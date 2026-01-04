// Copyright 2026 Patrick Matern
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
#include "include/raw_socket.hpp"
#include <vector>

using namespace wamp::rawsocket;

TEST_CASE("RawSocket handshake encoding/decoding", "[raw_socket]") {
    SECTION("Encode and decode handshake request") {
        HandshakeRequest req{
            .max_length = MaxLengthCode::BYTES_16M,
            .serializer = Serializer::CBOR
        };

        auto encoded = encode_handshake_request(req);
        REQUIRE(encoded.size() == HANDSHAKE_SIZE);

        auto decoded = decode_handshake_request(encoded);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->max_length == MaxLengthCode::BYTES_16M);
        REQUIRE(decoded->serializer == Serializer::CBOR);
    }

    SECTION("Encode handshake success") {
        HandshakeSuccess success{
            .max_length = MaxLengthCode::BYTES_16M,
            .serializer = Serializer::CBOR
        };

        auto encoded = encode_handshake_success(success);
        REQUIRE(encoded.size() == HANDSHAKE_SIZE);
        REQUIRE((encoded[0] & 0x7F) == 0x7F);  // Success bit set
    }

    SECTION("Encode handshake error") {
        auto encoded = encode_handshake_error(HandshakeError::SERIALIZER_UNSUPPORTED);
        REQUIRE(encoded.size() == HANDSHAKE_SIZE);
        REQUIRE(encoded[0] == 0x7F);  // Magic byte
        REQUIRE((encoded[1] >> 4) == static_cast<uint8_t>(HandshakeError::SERIALIZER_UNSUPPORTED));
    }

    SECTION("Invalid handshake size") {
        std::vector<uint8_t> short_data{0x7F};
        auto result = decode_handshake_request(short_data);
        REQUIRE(!result.has_value());
    }
}

TEST_CASE("RawSocket frame encoding/decoding", "[raw_socket]") {
    SECTION("Encode and decode frame header") {
        FrameHeader header{
            .type = FrameType::REGULAR,
            .payload_length = 1024
        };

        auto encoded = encode_frame_header(header);
        REQUIRE(encoded.size() == FRAME_HEADER_SIZE);

        auto decoded = decode_frame_header(encoded);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->type == FrameType::REGULAR);
        REQUIRE(decoded->payload_length == 1024);
    }

    SECTION("Encode PING frame") {
        FrameHeader header{
            .type = FrameType::PING,
            .payload_length = 16
        };

        auto encoded = encode_frame_header(header);
        auto decoded = decode_frame_header(encoded);

        REQUIRE(decoded.has_value());
        REQUIRE(decoded->type == FrameType::PING);
    }

    SECTION("Encode PONG frame") {
        FrameHeader header{
            .type = FrameType::PONG,
            .payload_length = 16
        };

        auto encoded = encode_frame_header(header);
        auto decoded = decode_frame_header(encoded);

        REQUIRE(decoded.has_value());
        REQUIRE(decoded->type == FrameType::PONG);
    }

    SECTION("Invalid frame header size") {
        std::vector<uint8_t> short_data{0x00, 0x01};
        auto result = decode_frame_header(short_data);
        REQUIRE(!result.has_value());
    }
}

TEST_CASE("RawSocket WAMP message creation", "[raw_socket]") {
    SECTION("Create WAMP message with small payload") {
        std::vector<uint8_t> payload{0x01, 0x02, 0x03, 0x04};
        auto message = create_wamp_message(payload);

        // Should have frame header (4 bytes) + payload
        REQUIRE(message.size() == FRAME_HEADER_SIZE + payload.size());

        // Decode header
        auto header = decode_frame_header(std::span{message.data(), FRAME_HEADER_SIZE});
        REQUIRE(header.has_value());
        REQUIRE(header->type == FrameType::REGULAR);
        REQUIRE(header->payload_length == payload.size());

        // Verify payload
        std::span payload_span{message.data() + FRAME_HEADER_SIZE, payload.size()};
        REQUIRE(std::equal(payload.begin(), payload.end(), payload_span.begin()));
    }
}

TEST_CASE("RawSocket PING/PONG messages", "[raw_socket]") {
    SECTION("Create PING message") {
        std::vector<uint8_t> data{0x01, 0x02, 0x03, 0x04};
        auto ping = create_ping(std::span{data.data(), data.size()});

        // Should have frame header + data
        REQUIRE(ping.size() == FRAME_HEADER_SIZE + data.size());

        auto header = decode_frame_header(std::span{ping.data(), FRAME_HEADER_SIZE});
        REQUIRE(header.has_value());
        REQUIRE(header->type == FrameType::PING);
    }

    SECTION("Create PONG message") {
        std::vector<uint8_t> data{0x01, 0x02, 0x03, 0x04};
        auto pong = create_pong(std::span{data.data(), data.size()});

        // Should have frame header + data
        REQUIRE(pong.size() == FRAME_HEADER_SIZE + data.size());

        auto header = decode_frame_header(std::span{pong.data(), FRAME_HEADER_SIZE});
        REQUIRE(header.has_value());
        REQUIRE(header->type == FrameType::PONG);
    }
}

TEST_CASE("RawSocket payload length validation", "[raw_socket]") {
    SECTION("Valid payload lengths") {
        REQUIRE(validate_payload_length(0, MaxLengthCode::BYTES_16M));
        REQUIRE(validate_payload_length(1024, MaxLengthCode::BYTES_16M));
        REQUIRE(validate_payload_length(16 * 1024 * 1024, MaxLengthCode::BYTES_16M));
    }

    SECTION("Invalid payload lengths") {
        REQUIRE(!validate_payload_length(16 * 1024 * 1024 + 1, MaxLengthCode::BYTES_16M));
        REQUIRE(!validate_payload_length(UINT32_MAX, MaxLengthCode::BYTES_16M));
    }

    SECTION("Different max length codes") {
        REQUIRE(validate_payload_length(512 * 1024, MaxLengthCode::BYTES_512K));
        REQUIRE(!validate_payload_length(512 * 1024 + 1, MaxLengthCode::BYTES_512K));
    }
}

TEST_CASE("RawSocket max length code conversions", "[raw_socket]") {
    SECTION("Convert max length codes to bytes") {
        REQUIRE(max_length_to_bytes(MaxLengthCode::BYTES_512K) == 512 * 1024);
        REQUIRE(max_length_to_bytes(MaxLengthCode::BYTES_1M) == 1024 * 1024);
        REQUIRE(max_length_to_bytes(MaxLengthCode::BYTES_2M) == 2 * 1024 * 1024);
        REQUIRE(max_length_to_bytes(MaxLengthCode::BYTES_4M) == 4 * 1024 * 1024);
        REQUIRE(max_length_to_bytes(MaxLengthCode::BYTES_8M) == 8 * 1024 * 1024);
        REQUIRE(max_length_to_bytes(MaxLengthCode::BYTES_16M) == 16 * 1024 * 1024);
    }
}
