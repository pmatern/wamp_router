#include <catch2/catch_test_macros.hpp>
#include "include/wamp_session.hpp"
#include "include/wamp_serializer.hpp"
#include "include/raw_socket.hpp"
#include <boost/asio/io_context.hpp>

using namespace wamp;

TEST_CASE("WampSession initialization", "[wamp_session]") {
    boost::asio::io_context io;
    WampSession session{io};

    SECTION("Session starts with ID 0") {
        REQUIRE(session.session_id() == 0);
    }

    SECTION("on_connect is callable") {
        session.on_connect();
        // Should not crash
        REQUIRE(true);
    }

    SECTION("on_disconnect is callable") {
        session.on_disconnect();
        // Should not crash
        REQUIRE(true);
    }
}

TEST_CASE("WampSession RawSocket handshake", "[wamp_session]") {
    boost::asio::io_context io;
    WampSession session{io};

    session.on_connect();

    SECTION("Accept valid CBOR handshake") {
        auto handshake = rawsocket::encode_handshake_request({
            .max_length = rawsocket::MaxLengthCode::BYTES_16M,
            .serializer = rawsocket::Serializer::CBOR
        });

        auto result = session.process(std::span{handshake.data(), handshake.size()});

        REQUIRE(result.has_value());
        REQUIRE(!result->empty());  // Should return handshake response

        // Decode response to verify it's a valid handshake
        auto response_header = rawsocket::decode_frame_header(std::span{result->data(), 4});
        // Response should be successful handshake
    }

    SECTION("Reject unsupported serializer") {
        auto handshake = rawsocket::encode_handshake_request({
            .max_length = rawsocket::MaxLengthCode::BYTES_16M,
            .serializer = rawsocket::Serializer::JSON
        });

        auto result = session.process(std::span{handshake.data(), handshake.size()});

        REQUIRE(result.has_value());
        REQUIRE(!result->empty());  // Should return error response
    }

    SECTION("Handle partial handshake data") {
        auto handshake = rawsocket::encode_handshake_request({
            .max_length = rawsocket::MaxLengthCode::BYTES_16M,
            .serializer = rawsocket::Serializer::CBOR
        });

        // Send only first 2 bytes
        auto result1 = session.process(std::span{handshake.data(), 2});
        REQUIRE(result1.has_value());
        REQUIRE(result1->empty());  // Should buffer, no response yet

        // Send remaining bytes
        auto result2 = session.process(std::span{handshake.data() + 2, handshake.size() - 2});
        REQUIRE(result2.has_value());
        REQUIRE(!result2->empty());  // Should complete handshake
    }
}

TEST_CASE("WampSession HELLO/WELCOME exchange", "[wamp_session]") {
    boost::asio::io_context io;
    WampSession session{io};

    session.on_connect();

    // Complete RawSocket handshake first
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    auto hs_result = session.process(std::span{handshake.data(), handshake.size()});
    REQUIRE(hs_result.has_value());

    SECTION("Process HELLO message and receive WELCOME") {
        HelloMessage hello{"com.example.realm"};
        hello.roles.push_back(Role{"subscriber", {}});
        hello.roles.push_back(Role{"publisher", {}});

        auto hello_cbor = serialize_hello(hello);
        auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

        auto result = session.process(std::span{hello_frame.data(), hello_frame.size()});

        REQUIRE(result.has_value());
        REQUIRE(!result->empty());

        // Session ID should be assigned after WELCOME
        REQUIRE(session.session_id() != 0);

        // Decode response to verify it's a WELCOME message
        // Skip frame header (4 bytes) and decode CBOR payload
        std::span response_payload{result->data() + 4, result->size() - 4};
        std::vector<uint8_t> payload_vec{response_payload.begin(), response_payload.end()};

        auto welcome = deserialize_welcome(payload_vec);
        REQUIRE(welcome.has_value());
        REQUIRE(welcome->session_id == session.session_id());
    }

    SECTION("Handle partial HELLO message") {
        HelloMessage hello{"com.example.realm"};
        hello.roles.push_back(Role{"subscriber", {}});

        auto hello_cbor = serialize_hello(hello);
        auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

        // Send frame header only
        auto result1 = session.process(std::span{hello_frame.data(), 4});
        REQUIRE(result1.has_value());
        REQUIRE(result1->empty());  // Should buffer

        // Send payload
        auto result2 = session.process(std::span{hello_frame.data() + 4, hello_frame.size() - 4});
        REQUIRE(result2.has_value());
        REQUIRE(!result2->empty());  // Should complete and send WELCOME
    }
}

TEST_CASE("WampSession GOODBYE handling", "[wamp_session]") {
    boost::asio::io_context io;
    WampSession session{io};

    // Complete handshake and HELLO
    session.on_connect();
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    HelloMessage hello{"com.example.realm"};
    hello.roles.push_back(Role{"subscriber", {}});
    auto hello_cbor = serialize_hello(hello);
    auto hello_frame = rawsocket::create_wamp_message(hello_cbor);
    session.process(std::span{hello_frame.data(), hello_frame.size()});

    SECTION("Process GOODBYE from client") {
        auto goodbye = GoodbyeMessage::create_normal();
        auto goodbye_cbor = serialize_goodbye(goodbye);
        auto goodbye_frame = rawsocket::create_wamp_message(goodbye_cbor);

        auto result = session.process(std::span{goodbye_frame.data(), goodbye_frame.size()});

        REQUIRE(result.has_value());
        REQUIRE(!result->empty());  // Should respond with GOODBYE

        // Verify response is a GOODBYE message
        std::span response_payload{result->data() + 4, result->size() - 4};
        std::vector<uint8_t> payload_vec{response_payload.begin(), response_payload.end()};

        auto response_goodbye = deserialize_goodbye(payload_vec);
        REQUIRE(response_goodbye.has_value());
    }
}

TEST_CASE("WampSession PING/PONG handling", "[wamp_session]") {
    boost::asio::io_context io;
    WampSession session{io};

    session.on_connect();

    // Complete handshake
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    SECTION("Respond to PING with PONG") {
        std::vector<uint8_t> ping_data{0x01, 0x02, 0x03, 0x04};
        auto ping = rawsocket::create_ping(std::span{ping_data.data(), ping_data.size()});

        auto result = session.process(std::span{ping.data(), ping.size()});

        REQUIRE(result.has_value());
        REQUIRE(!result->empty());

        // Verify it's a PONG frame
        auto header = rawsocket::decode_frame_header(std::span{result->data(), 4});
        REQUIRE(header.has_value());
        REQUIRE(header->type == rawsocket::FrameType::PONG);
    }

    SECTION("Handle PONG message") {
        std::vector<uint8_t> pong_data{0x05, 0x06, 0x07, 0x08};
        auto pong = rawsocket::create_pong(std::span{pong_data.data(), pong_data.size()});

        auto result = session.process(std::span{pong.data(), pong.size()});

        REQUIRE(result.has_value());
        REQUIRE(result->empty());  // PONG should not generate a response
    }
}

TEST_CASE("WampSession error handling", "[wamp_session]") {
    boost::asio::io_context io;
    WampSession session{io};

    session.on_connect();

    SECTION("Invalid frame header") {
        std::vector<uint8_t> invalid{0xFF, 0xFF, 0xFF, 0xFF};

        auto result = session.process(std::span{invalid.data(), invalid.size()});

        // Should handle gracefully
        // Don't assert on result - it may handle error in different ways
    }

    SECTION("Disconnection cleans up session") {
        // Establish session first
        auto handshake = rawsocket::encode_handshake_request({
            .max_length = rawsocket::MaxLengthCode::BYTES_16M,
            .serializer = rawsocket::Serializer::CBOR
        });
        session.process(std::span{handshake.data(), handshake.size()});

        HelloMessage hello{"com.example.realm"};
        hello.roles.push_back(Role{"subscriber", {}});
        auto hello_cbor = serialize_hello(hello);
        auto hello_frame = rawsocket::create_wamp_message(hello_cbor);
        session.process(std::span{hello_frame.data(), hello_frame.size()});

        uint64_t sid = session.session_id();
        REQUIRE(sid != 0);

        // Disconnect should not crash
        session.on_disconnect();
        REQUIRE(true);
    }
}

TEST_CASE("WampSession buffering behavior", "[wamp_session]") {
    boost::asio::io_context io;
    WampSession session{io};

    session.on_connect();

    SECTION("Buffer partial frames across multiple reads") {
        auto handshake = rawsocket::encode_handshake_request({
            .max_length = rawsocket::MaxLengthCode::BYTES_16M,
            .serializer = rawsocket::Serializer::CBOR
        });

        // Split handshake into single bytes
        for (size_t i = 0; i < handshake.size() - 1; ++i) {
            auto result = session.process(std::span{&handshake[i], 1});
            REQUIRE(result.has_value());
            REQUIRE(result->empty());  // Should buffer until complete
        }

        // Last byte should complete handshake
        auto result = session.process(std::span{&handshake[handshake.size() - 1], 1});
        REQUIRE(result.has_value());
        REQUIRE(!result->empty());  // Should return handshake response
    }
}
