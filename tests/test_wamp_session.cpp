// Copyright 2026 Pete Matern
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include <catch2/catch_test_macros.hpp>
#include "include/wamp_session.hpp"
#include "include/wamp_serializer.hpp"
#include "include/raw_socket.hpp"
#include "include/crypto_utils.hpp"
#include <boost/asio/io_context.hpp>
#include <fstream>

using namespace wamp;

// Helper function to create test ServerConfig for unit tests
static ServerConfig create_test_config() {
    ServerConfig config;
    config.port = 8080;
    config.tls.cert_path = "test_certs/cert.pem";
    config.tls.key_path = "test_certs/key.pem";
    config.max_pending_invocations = 1000;
    config.log_level = spdlog::level::debug;
    // No auth keys - allow unauthenticated connections for basic tests
    return config;
}

TEST_CASE("WampSession initialization", "[wamp_session]") {
    boost::asio::io_context io;
    auto config = create_test_config();
    WampSession session{io, config};

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
    auto config = create_test_config();
    WampSession session{io, config};

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
    auto config = create_test_config();
    WampSession session{io, config};

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
    auto config = create_test_config();
    WampSession session{io, config};

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
    auto config = create_test_config();
    WampSession session{io, config};

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
    auto config = create_test_config();
    WampSession session{io, config};

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
    auto config = create_test_config();
    WampSession session{io, config};

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

// ============================================================================
// Authentication Tests
// ============================================================================

// Helper to create a test key pair and return (priv_path, public_key_hex)
static std::pair<std::string, std::string> create_auth_test_keypair() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate test key pair");
    }
    EVP_PKEY_CTX_free(ctx);

    // Extract public key hex
    size_t pub_len = 32;
    std::vector<uint8_t> pub_key(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len);
    std::string public_key_hex = bytes_to_hex(pub_key);

    // Write private key to temp file
    std::string priv_path = "/tmp/wamp_test_auth_key.pem";
    FILE* priv_file = fopen(priv_path.c_str(), "w");
    if (!priv_file) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create temp private key file");
    }

    PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(priv_file);
    EVP_PKEY_free(pkey);

    return {priv_path, public_key_hex};
}

// Helper function to create auth-enabled ServerConfig
static ServerConfig create_auth_test_config(const std::string& authid, const std::string& public_key_hex) {
    ServerConfig config;
    config.port = 8080;
    config.tls.cert_path = "test_certs/cert.pem";
    config.tls.key_path = "test_certs/key.pem";
    config.max_pending_invocations = 1000;
    config.log_level = spdlog::level::debug;
    config.auth_keys[authid] = public_key_hex;
    return config;
}

TEST_CASE("WampSession authentication - unknown authid rejected", "[wamp_session][auth]") {
    auto [priv_path, public_key_hex] = create_auth_test_keypair();

    boost::asio::io_context io;
    // Configure with auth key for "validuser"
    auto config = create_auth_test_config("validuser", public_key_hex);
    WampSession session{io, config};

    session.on_connect();

    // Complete RawSocket handshake
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    // Send HELLO with unknown authid
    HelloMessage hello{"com.example.realm"};
    hello.authid = "unknownuser";  // Not in auth_keys
    hello.authmethods = std::vector<std::string>{"cryptosign"};

    auto hello_cbor = serialize_hello(hello);
    auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

    auto result = session.process(std::span{hello_frame.data(), hello_frame.size()});

    REQUIRE(result.has_value());
    REQUIRE(!result->empty());

    // Should receive ABORT message
    std::span response_payload{result->data() + 4, result->size() - 4};
    std::vector<uint8_t> payload_vec{response_payload.begin(), response_payload.end()};

    auto msg_type = get_message_type_from_cbor(payload_vec);
    REQUIRE(msg_type.has_value());
    REQUIRE(*msg_type == MessageType::ABORT);

    auto abort = deserialize_abort(payload_vec);
    REQUIRE(abort.has_value());
    REQUIRE(abort->reason == "wamp.error.not_authorized");

    std::remove(priv_path.c_str());
}

TEST_CASE("WampSession authentication - missing authid rejected", "[wamp_session][auth]") {
    auto [priv_path, public_key_hex] = create_auth_test_keypair();

    boost::asio::io_context io;
    auto config = create_auth_test_config("testuser", public_key_hex);
    WampSession session{io, config};

    session.on_connect();

    // Complete RawSocket handshake
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    // Send HELLO with cryptosign but no authid
    HelloMessage hello{"com.example.realm"};
    hello.authmethods = std::vector<std::string>{"cryptosign"};
    // Note: authid is not set

    auto hello_cbor = serialize_hello(hello);
    auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

    auto result = session.process(std::span{hello_frame.data(), hello_frame.size()});

    REQUIRE(result.has_value());
    REQUIRE(!result->empty());

    // Should receive ABORT message
    std::span response_payload{result->data() + 4, result->size() - 4};
    std::vector<uint8_t> payload_vec{response_payload.begin(), response_payload.end()};

    auto msg_type = get_message_type_from_cbor(payload_vec);
    REQUIRE(msg_type.has_value());
    REQUIRE(*msg_type == MessageType::ABORT);

    std::remove(priv_path.c_str());
}

TEST_CASE("WampSession authentication - sends CHALLENGE for valid authid", "[wamp_session][auth]") {
    auto [priv_path, public_key_hex] = create_auth_test_keypair();

    boost::asio::io_context io;
    auto config = create_auth_test_config("testuser", public_key_hex);
    WampSession session{io, config};

    session.on_connect();

    // Complete RawSocket handshake
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    // Send HELLO with valid authid
    HelloMessage hello{"com.example.realm"};
    hello.authid = "testuser";
    hello.authmethods = std::vector<std::string>{"cryptosign"};

    auto hello_cbor = serialize_hello(hello);
    auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

    auto result = session.process(std::span{hello_frame.data(), hello_frame.size()});

    REQUIRE(result.has_value());
    REQUIRE(!result->empty());

    // Should receive CHALLENGE message
    std::span response_payload{result->data() + 4, result->size() - 4};
    std::vector<uint8_t> payload_vec{response_payload.begin(), response_payload.end()};

    auto msg_type = get_message_type_from_cbor(payload_vec);
    REQUIRE(msg_type.has_value());
    REQUIRE(*msg_type == MessageType::CHALLENGE);

    auto challenge = deserialize_challenge(payload_vec);
    REQUIRE(challenge.has_value());
    REQUIRE(challenge->authmethod == "cryptosign");
    REQUIRE(challenge->extra.contains("challenge"));
    REQUIRE(challenge->extra.at("challenge").length() == 64);  // 32 bytes hex

    std::remove(priv_path.c_str());
}

TEST_CASE("WampSession authentication - full flow success", "[wamp_session][auth]") {
    auto [priv_path, public_key_hex] = create_auth_test_keypair();

    boost::asio::io_context io;
    auto config = create_auth_test_config("testuser", public_key_hex);
    WampSession session{io, config};

    session.on_connect();

    // Complete RawSocket handshake
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    // Send HELLO with valid authid
    HelloMessage hello{"com.example.realm"};
    hello.authid = "testuser";
    hello.authmethods = std::vector<std::string>{"cryptosign"};

    auto hello_cbor = serialize_hello(hello);
    auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

    auto hello_result = session.process(std::span{hello_frame.data(), hello_frame.size()});

    REQUIRE(hello_result.has_value());
    REQUIRE(!hello_result->empty());

    // Extract CHALLENGE
    std::span challenge_payload{hello_result->data() + 4, hello_result->size() - 4};
    std::vector<uint8_t> challenge_vec{challenge_payload.begin(), challenge_payload.end()};

    auto challenge = deserialize_challenge(challenge_vec);
    REQUIRE(challenge.has_value());

    // Load private key and sign challenge
    auto key_result = load_ed25519_private_key_pem(priv_path);
    REQUIRE(key_result.has_value());

    std::string challenge_nonce = challenge->extra.at("challenge");
    std::string message_to_sign = challenge_nonce + "|0|testuser|user";

    auto sig_result = sign_ed25519(message_to_sign, key_result->get());
    REQUIRE(sig_result.has_value());

    // Send AUTHENTICATE
    AuthenticateMessage auth{*sig_result};
    auto auth_cbor = serialize_authenticate(auth);
    auto auth_frame = rawsocket::create_wamp_message(auth_cbor);

    auto auth_result = session.process(std::span{auth_frame.data(), auth_frame.size()});

    REQUIRE(auth_result.has_value());
    REQUIRE(!auth_result->empty());

    // Should receive WELCOME
    std::span welcome_payload{auth_result->data() + 4, auth_result->size() - 4};
    std::vector<uint8_t> welcome_vec{welcome_payload.begin(), welcome_payload.end()};

    auto msg_type = get_message_type_from_cbor(welcome_vec);
    REQUIRE(msg_type.has_value());
    REQUIRE(*msg_type == MessageType::WELCOME);

    auto welcome = deserialize_welcome(welcome_vec);
    REQUIRE(welcome.has_value());
    REQUIRE(welcome->session_id != 0);
    REQUIRE(welcome->authid == "testuser");
    REQUIRE(welcome->authmethod == "cryptosign");

    // Session should be established
    REQUIRE(session.is_established());
    REQUIRE(session.session_id() != 0);

    std::remove(priv_path.c_str());
}

TEST_CASE("WampSession authentication - invalid signature rejected", "[wamp_session][auth]") {
    auto [priv_path, public_key_hex] = create_auth_test_keypair();

    boost::asio::io_context io;
    auto config = create_auth_test_config("testuser", public_key_hex);
    WampSession session{io, config};

    session.on_connect();

    // Complete RawSocket handshake
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    // Send HELLO
    HelloMessage hello{"com.example.realm"};
    hello.authid = "testuser";
    hello.authmethods = std::vector<std::string>{"cryptosign"};

    auto hello_cbor = serialize_hello(hello);
    auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

    auto hello_result = session.process(std::span{hello_frame.data(), hello_frame.size()});

    REQUIRE(hello_result.has_value());

    // Send AUTHENTICATE with invalid signature (all zeros)
    std::string fake_sig(128, '0');  // 64 bytes of zeros in hex
    AuthenticateMessage auth{fake_sig};
    auto auth_cbor = serialize_authenticate(auth);
    auto auth_frame = rawsocket::create_wamp_message(auth_cbor);

    auto auth_result = session.process(std::span{auth_frame.data(), auth_frame.size()});

    REQUIRE(auth_result.has_value());
    REQUIRE(!auth_result->empty());

    // Should receive ABORT
    std::span abort_payload{auth_result->data() + 4, auth_result->size() - 4};
    std::vector<uint8_t> abort_vec{abort_payload.begin(), abort_payload.end()};

    auto msg_type = get_message_type_from_cbor(abort_vec);
    REQUIRE(msg_type.has_value());
    REQUIRE(*msg_type == MessageType::ABORT);

    auto abort = deserialize_abort(abort_vec);
    REQUIRE(abort.has_value());
    REQUIRE(abort->reason == "wamp.error.not_authorized");

    std::remove(priv_path.c_str());
}

TEST_CASE("WampSession authentication - no auth required when auth_keys empty", "[wamp_session][auth]") {
    boost::asio::io_context io;
    auto config = create_test_config();  // No auth_keys configured
    WampSession session{io, config};

    session.on_connect();

    // Complete RawSocket handshake
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR
    });
    session.process(std::span{handshake.data(), handshake.size()});

    // Send HELLO without any auth info
    HelloMessage hello{"com.example.realm"};
    hello.roles.push_back(Role{"subscriber", {}});

    auto hello_cbor = serialize_hello(hello);
    auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

    auto result = session.process(std::span{hello_frame.data(), hello_frame.size()});

    REQUIRE(result.has_value());
    REQUIRE(!result->empty());

    // Should receive WELCOME directly (no CHALLENGE)
    std::span response_payload{result->data() + 4, result->size() - 4};
    std::vector<uint8_t> payload_vec{response_payload.begin(), response_payload.end()};

    auto msg_type = get_message_type_from_cbor(payload_vec);
    REQUIRE(msg_type.has_value());
    REQUIRE(*msg_type == MessageType::WELCOME);

    REQUIRE(session.is_established());
}
