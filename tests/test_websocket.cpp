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

#include "include/websocket.hpp"
#include <catch2/catch_test_macros.hpp>
#include <random>

using namespace wamp::ws;

namespace {

std::vector<uint8_t> bytes(std::string_view s) { return {s.begin(), s.end()}; }

// A masked client frame
std::vector<uint8_t> client_frame(uint8_t opcode, std::span<const uint8_t> payload, bool fin = true, bool mask = true,
                                  uint8_t rsv = 0) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>((fin ? 0x80 : 0) | rsv | opcode));
    const uint8_t mask_bit = mask ? 0x80 : 0;
    if (payload.size() < 126) {
        out.push_back(static_cast<uint8_t>(mask_bit | payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        out.push_back(static_cast<uint8_t>(mask_bit | 126));
        out.push_back(static_cast<uint8_t>(payload.size() >> 8));
        out.push_back(static_cast<uint8_t>(payload.size()));
    } else {
        out.push_back(static_cast<uint8_t>(mask_bit | 127));
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(uint64_t{payload.size()} >> (56 - 8 * i)));
    }
    const uint8_t key[4] = {0x37, 0xFA, 0x21, 0x3D};
    if (mask) out.insert(out.end(), key, key + 4);
    for (size_t i = 0; i < payload.size(); ++i) out.push_back(mask ? payload[i] ^ key[i % 4] : payload[i]);
    return out;
}

std::vector<uint8_t> pattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i * 31 + 7);
    return v;
}

const std::string kRequest =
    "GET /ws HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: keep-alive, Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: wamp.2.json, wamp.2.cbor\r\n"
    "\r\n";

UpgradeRequest parse(const std::string& text, const std::vector<std::string>& origins = {}) {
    return parse_upgrade({reinterpret_cast<const uint8_t*>(text.data()), text.size()}, origins);
}

std::string replace(std::string text, const std::string& from, const std::string& to) {
    const auto at = text.find(from);
    REQUIRE(at != std::string::npos);
    return text.replace(at, from.size(), to);
}

} // namespace

TEST_CASE("WebSocket accept key matches the RFC 6455 example", "[websocket]") {
    CHECK(accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    CHECK(base64_encode(bytes("")) == "");
    CHECK(base64_encode(bytes("f")) == "Zg==");
    CHECK(base64_encode(bytes("fo")) == "Zm8=");
    CHECK(base64_encode(bytes("foo")) == "Zm9v");
    CHECK(base64_encode(bytes("foobar")) == "Zm9vYmFy");
}

TEST_CASE("WebSocket upgrade request parsing", "[websocket]") {
    SECTION("a good request") {
        auto r = parse(kRequest);
        CHECK(r.status == UpgradeStatus::OK);
        CHECK(r.consumed == kRequest.size());
        CHECK(r.key == "dGhlIHNhbXBsZSBub25jZQ==");
        CHECK(upgrade_response(r.key).find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != std::string::npos);
        CHECK(upgrade_response(r.key).find("Sec-WebSocket-Protocol: wamp.2.cbor\r\n") != std::string::npos);
    }
    SECTION("header names and tokens are case-insensitive, any path") {
        auto text = replace(replace(kRequest, "Upgrade: websocket", "UPGRADE: WebSocket"), "/ws", "/anything/else?x=1");
        CHECK(parse(text).status == UpgradeStatus::OK);
    }
    SECTION("incomplete until the blank line") {
        CHECK(parse(kRequest.substr(0, kRequest.size() - 2)).status == UpgradeStatus::INCOMPLETE);
        CHECK(parse("").status == UpgradeStatus::INCOMPLETE);
    }
    SECTION("bytes after the request are left alone") {
        auto r = parse(kRequest + "\x82\x80");
        CHECK(r.status == UpgradeStatus::OK);
        CHECK(r.consumed == kRequest.size());
    }
    SECTION("malformed or missing pieces are 400") {
        CHECK(parse(replace(kRequest, "GET ", "POST ")).status == UpgradeStatus::BAD_REQUEST);
        CHECK(parse(replace(kRequest, "HTTP/1.1", "HTTP/1.0")).status == UpgradeStatus::BAD_REQUEST);
        CHECK(parse(replace(kRequest, "Upgrade: websocket\r\n", "")).status == UpgradeStatus::BAD_REQUEST);
        CHECK(parse(replace(kRequest, "Connection: keep-alive, Upgrade\r\n", "")).status == UpgradeStatus::BAD_REQUEST);
        CHECK(parse(replace(kRequest, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "")).status == UpgradeStatus::BAD_REQUEST);
        CHECK(parse(replace(kRequest, "dGhlIHNhbXBsZSBub25jZQ==", "short")).status == UpgradeStatus::BAD_REQUEST);
        CHECK(parse(replace(kRequest, "Host: example.com", "no colon here")).status == UpgradeStatus::BAD_REQUEST);
    }
    SECTION("the wamp.2.cbor subprotocol must be offered") {
        CHECK(parse(replace(kRequest, "wamp.2.json, wamp.2.cbor", "wamp.2.json")).status == UpgradeStatus::BAD_REQUEST);
        CHECK(parse(replace(kRequest, "Sec-WebSocket-Protocol: wamp.2.json, wamp.2.cbor\r\n", "")).status == UpgradeStatus::BAD_REQUEST);
    }
    SECTION("only version 13") {
        CHECK(parse(replace(kRequest, "Version: 13", "Version: 8")).status == UpgradeStatus::UPGRADE_REQUIRED);
        CHECK(parse(replace(kRequest, "Sec-WebSocket-Version: 13\r\n", "")).status == UpgradeStatus::UPGRADE_REQUIRED);
        CHECK(error_response(UpgradeStatus::UPGRADE_REQUIRED).find("Sec-WebSocket-Version: 13") != std::string::npos);
    }
    SECTION("origin allow-list") {
        const auto with_origin = replace(kRequest, "Host:", "Origin: https://app.example.com\r\nHost:");
        CHECK(parse(with_origin).status == UpgradeStatus::OK);                                        // no list: anyone
        CHECK(parse(with_origin, {"https://app.example.com"}).status == UpgradeStatus::OK);
        CHECK(parse(with_origin, {"https://other.example.com", "https://app.example.com"}).status == UpgradeStatus::OK);
        CHECK(parse(with_origin, {"https://evil.example.com"}).status == UpgradeStatus::FORBIDDEN);
        CHECK(parse(with_origin, {"https://app.example.com:8443"}).status == UpgradeStatus::FORBIDDEN);   // exact match
        CHECK(parse(kRequest, {"https://app.example.com"}).status == UpgradeStatus::OK);              // no Origin header: not a browser
        CHECK(error_response(UpgradeStatus::FORBIDDEN).starts_with("HTTP/1.1 403"));
    }
    SECTION("oversized header block") {
        CHECK(parse(std::string(kMaxUpgradeRequest + 10, 'G')).status == UpgradeStatus::HEADER_TOO_LARGE);
        CHECK(parse(replace(kRequest, "Host: example.com", "X: " + std::string(kMaxUpgradeRequest, 'a'))).status ==
              UpgradeStatus::HEADER_TOO_LARGE);
        CHECK(error_response(UpgradeStatus::HEADER_TOO_LARGE).starts_with("HTTP/1.1 431"));
    }
}

TEST_CASE("WebSocket server frame encoding", "[websocket]") {
    CHECK(encode_header(Opcode::BINARY, 5).view().size() == 2);
    CHECK(encode_header(Opcode::BINARY, 125).view().size() == 2);
    auto h126 = encode_header(Opcode::BINARY, 126);
    CHECK(h126.size == 4);
    CHECK(h126.bytes[0] == 0x82);
    CHECK(h126.bytes[1] == 126);
    CHECK(h126.bytes[2] == 0);
    CHECK(h126.bytes[3] == 126);
    auto h64k = encode_header(Opcode::BINARY, 0x10000);
    CHECK(h64k.size == 10);
    CHECK(h64k.bytes[1] == 127);
    CHECK(h64k.bytes[7] == 0x01);
    CHECK(encode_header(Opcode::PONG, 0).bytes[0] == 0x8A);
    CHECK(encode_header(Opcode::BINARY, 3, /*fin=*/false).bytes[0] == 0x02);

    std::vector<uint8_t> out;
    append_close(out, kCloseNormal);
    CHECK(out == std::vector<uint8_t>{0x88, 0x02, 0x03, 0xE8});
}

TEST_CASE("WebSocket frame parser: messages", "[websocket]") {
    FrameParser parser{1 << 20};

    SECTION("lengths in all three encodings") {
        for (size_t n : {size_t{0}, size_t{1}, size_t{125}, size_t{126}, size_t{127}, size_t{65535}, size_t{65536}, size_t{300000}}) {
            const auto payload = pattern(n);
            const auto frame = client_frame(0x2, payload);
            auto parsed = parser.next(frame);
            REQUIRE(parsed.kind == Parsed::Kind::MESSAGE);
            CHECK(parsed.consumed == frame.size());
            CHECK(parsed.payload == payload);
        }
    }
    SECTION("only the bytes of one frame are consumed") {
        auto two = client_frame(0x2, bytes("abc"));
        const auto second = client_frame(0x2, bytes("defg"));
        const auto first_size = two.size();
        two.insert(two.end(), second.begin(), second.end());
        auto a = parser.next(two);
        REQUIRE(a.kind == Parsed::Kind::MESSAGE);
        CHECK(a.consumed == first_size);
        CHECK(a.payload == bytes("abc"));
        auto b = parser.next(std::span<const uint8_t>{two}.subspan(a.consumed));
        REQUIRE(b.kind == Parsed::Kind::MESSAGE);
        CHECK(b.payload == bytes("defg"));
    }
    SECTION("a frame arriving one byte at a time") {
        const auto frame = client_frame(0x2, pattern(200));
        for (size_t have = 0; have < frame.size(); ++have) {
            auto parsed = parser.next(std::span<const uint8_t>{frame}.first(have));
            REQUIRE(parsed.kind == Parsed::Kind::NEED_MORE);
            REQUIRE(parsed.consumed == 0);
        }
        CHECK(parser.next(frame).kind == Parsed::Kind::MESSAGE);
    }
    SECTION("fragmented message, with a ping in the middle") {
        const auto part1 = client_frame(0x2, bytes("hello "), /*fin=*/false);
        const auto ping = client_frame(0x9, bytes("p"));
        const auto part2 = client_frame(0x0, bytes("wor"), /*fin=*/false);
        const auto part3 = client_frame(0x0, bytes("ld"), /*fin=*/true);
        std::vector<uint8_t> all;
        for (const auto* part : {&part1, &ping, &part2, &part3}) all.insert(all.end(), part->begin(), part->end());

        std::span<const uint8_t> in{all};
        auto first = parser.next(in);
        REQUIRE(first.kind == Parsed::Kind::PING);        // fragment 1 consumed silently, then the ping
        CHECK(first.payload == bytes("p"));
        in = in.subspan(first.consumed);
        auto second = parser.next(in);
        REQUIRE(second.kind == Parsed::Kind::MESSAGE);
        CHECK(second.payload == bytes("hello world"));
        CHECK(second.consumed == in.size());
    }
    SECTION("a fragment that is not complete yet reports what it consumed") {
        const auto part1 = client_frame(0x2, bytes("abc"), /*fin=*/false);
        auto part2 = client_frame(0x0, bytes("def"), /*fin=*/true);
        std::vector<uint8_t> all = part1;
        all.insert(all.end(), part2.begin(), part2.end() - 2);   // second frame truncated
        auto parsed = parser.next(all);
        REQUIRE(parsed.kind == Parsed::Kind::NEED_MORE);
        CHECK(parsed.consumed == part1.size());
        part2 = client_frame(0x0, bytes("def"), true);
        auto done = parser.next(part2);                           // the caller advanced by `consumed`
        REQUIRE(done.kind == Parsed::Kind::MESSAGE);
        CHECK(done.payload == bytes("abcdef"));
    }
    SECTION("pong and close") {
        CHECK(parser.next(client_frame(0xA, bytes("x"))).kind == Parsed::Kind::PONG);
        auto empty_close = parser.next(client_frame(0x8, {}));
        CHECK(empty_close.kind == Parsed::Kind::CLOSE);
        CHECK(empty_close.code == 1005);
        const std::vector<uint8_t> with_reason{0x03, 0xE8, 'b', 'y', 'e'};
        auto close = parser.next(client_frame(0x8, with_reason));
        CHECK(close.kind == Parsed::Kind::CLOSE);
        CHECK(close.code == 1000);
        CHECK(close.payload == with_reason);
    }
}

TEST_CASE("WebSocket frame parser: protocol violations", "[websocket]") {
    FrameParser parser{1000};
    auto kind_and_code = [&](std::vector<uint8_t> frame) {
        FrameParser fresh{1000};
        auto parsed = fresh.next(frame);
        return std::pair{parsed.kind, parsed.code};
    };
    using K = Parsed::Kind;

    CHECK(kind_and_code(client_frame(0x2, bytes("x"), true, /*mask=*/false)) == std::pair{K::FAIL, kCloseProtocolError});
    CHECK(kind_and_code(client_frame(0x2, bytes("x"), true, true, /*rsv=*/0x40)) == std::pair{K::FAIL, kCloseProtocolError});
    CHECK(kind_and_code(client_frame(0x3, bytes("x"))) == std::pair{K::FAIL, kCloseProtocolError});    // reserved data opcode
    CHECK(kind_and_code(client_frame(0xB, bytes("x"))) == std::pair{K::FAIL, kCloseProtocolError});    // reserved control opcode
    CHECK(kind_and_code(client_frame(0x9, pattern(126))) == std::pair{K::FAIL, kCloseProtocolError});   // control frame too long
    CHECK(kind_and_code(client_frame(0x9, bytes("x"), /*fin=*/false)) == std::pair{K::FAIL, kCloseProtocolError});   // fragmented control
    CHECK(kind_and_code(client_frame(0x0, bytes("x"))) == std::pair{K::FAIL, kCloseProtocolError});     // continuation with nothing to continue
    CHECK(kind_and_code(client_frame(0x1, bytes("{}"))) == std::pair{K::FAIL, kCloseUnsupportedData});  // text frame
    CHECK(kind_and_code(client_frame(0x8, bytes("x"))) == std::pair{K::FAIL, kCloseProtocolError});     // 1-byte close payload
    CHECK(kind_and_code(client_frame(0x8, std::vector<uint8_t>{0x03, 0xED})) == std::pair{K::FAIL, kCloseProtocolError});   // 1005 on the wire
    CHECK(kind_and_code(client_frame(0x8, std::vector<uint8_t>{0x00, 0x05})) == std::pair{K::FAIL, kCloseProtocolError});   // below 1000

    SECTION("a new message inside a fragmented one") {
        FrameParser fresh{1000};
        REQUIRE(fresh.next(client_frame(0x2, bytes("a"), false)).kind == K::NEED_MORE);
        auto parsed = fresh.next(client_frame(0x2, bytes("b")));
        CHECK(parsed.kind == K::FAIL);
        CHECK(parsed.code == kCloseProtocolError);
    }
    SECTION("length checked before the payload arrives") {
        auto frame = client_frame(0x2, pattern(2000));
        auto parsed = parser.next(std::span<const uint8_t>{frame}.first(14));   // header only
        CHECK(parsed.kind == K::FAIL);
        CHECK(parsed.code == kCloseTooBig);
    }
    SECTION("reassembled size is limited too") {
        FrameParser fresh{1000};
        REQUIRE(fresh.next(client_frame(0x2, pattern(600), false)).kind == K::NEED_MORE);
        auto parsed = fresh.next(client_frame(0x0, pattern(600)));
        CHECK(parsed.kind == K::FAIL);
        CHECK(parsed.code == kCloseTooBig);
    }
    SECTION("64-bit length with the top bit set") {
        std::vector<uint8_t> frame{0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4};
        CHECK(parser.next(frame).kind == K::FAIL);
    }
}

TEST_CASE("WebSocket parser survives random input", "[websocket]") {
    std::mt19937 rng{12345};
    for (int round = 0; round < 2000; ++round) {
        std::vector<uint8_t> noise(rng() % 64);
        for (auto& b : noise) b = static_cast<uint8_t>(rng());
        if (round % 2 == 0 && !noise.empty()) noise[0] = static_cast<uint8_t>(0x80 | (rng() % 16));   // plausible first byte
        FrameParser parser{4096};
        std::span<const uint8_t> in{noise};
        for (int steps = 0; steps < 8; ++steps) {
            auto parsed = parser.next(in);
            REQUIRE(parsed.consumed <= in.size());
            if (parsed.kind == Parsed::Kind::NEED_MORE || parsed.kind == Parsed::Kind::FAIL) break;
            in = in.subspan(parsed.consumed);
        }
        const std::string text(noise.begin(), noise.end());
        (void)parse(text);   // the upgrade parser must not crash either
    }
}
