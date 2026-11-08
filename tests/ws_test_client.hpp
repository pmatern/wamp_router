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


#pragma once

// A small blocking WebSocket client for tests: upgrade, masked frames, frame reading with a timeout.
// It is deliberately independent of include/websocket.hpp's parser so the tests do not check the
// implementation against itself (the accept key is the one shared helper).

#include "include/websocket.hpp"
#include <asio.hpp>
#include <poll.h>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace wamp::test {

struct WsFrame {
    uint8_t opcode{};
    bool fin{};
    std::vector<uint8_t> payload;
};

class WsTestClient {
public:
    WsTestClient() : socket_(io_) {}

    // How long connect() waits for the response head
    std::chrono::milliseconds head_timeout{5000};

    // Opens the connection and sends the upgrade request; returns the response head ("" if none came)
    std::string connect(unsigned short port, const std::string& extra_headers = "",
                        const std::string& subprotocols = "wamp.2.json, wamp.2.cbor",
                        const std::string& version = "13") {
        socket_.connect({asio::ip::address_v4::loopback(), port});
        const std::string request =
            "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: " + version + "\r\n" +
            (subprotocols.empty() ? "" : "Sec-WebSocket-Protocol: " + subprotocols + "\r\n") + extra_headers + "\r\n";
        send_raw({reinterpret_cast<const uint8_t*>(request.data()), request.size()});

        std::string head;
        while (head.find("\r\n\r\n") == std::string::npos) {
            uint8_t byte;
            if (!read_exact(&byte, 1, head_timeout)) return head;
            head += static_cast<char>(byte);
        }
        return head;
    }

    void send_raw(std::span<const uint8_t> data) { asio::write(socket_, asio::buffer(data.data(), data.size())); }

    // A masked client frame
    static std::vector<uint8_t> frame(uint8_t opcode, std::span<const uint8_t> payload, bool fin = true) {
        std::vector<uint8_t> out;
        out.push_back(static_cast<uint8_t>((fin ? 0x80 : 0) | opcode));
        if (payload.size() < 126) {
            out.push_back(static_cast<uint8_t>(0x80 | payload.size()));
        } else if (payload.size() <= 0xFFFF) {
            out.push_back(0x80 | 126);
            out.push_back(static_cast<uint8_t>(payload.size() >> 8));
            out.push_back(static_cast<uint8_t>(payload.size()));
        } else {
            out.push_back(0x80 | 127);
            for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(uint64_t{payload.size()} >> (56 - 8 * i)));
        }
        const uint8_t key[4] = {0x12, 0x34, 0x56, 0x78};
        out.insert(out.end(), key, key + 4);
        for (size_t i = 0; i < payload.size(); ++i) out.push_back(payload[i] ^ key[i % 4]);
        return out;
    }

    void send(uint8_t opcode, std::span<const uint8_t> payload, bool fin = true) {
        const auto bytes = frame(opcode, payload, fin);
        send_raw(bytes);
    }
    void send_binary(std::span<const uint8_t> payload) { send(0x2, payload); }

    // Next server frame; nullopt on timeout or when the peer closed the connection
    std::optional<WsFrame> read_frame(std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
        uint8_t head[2];
        if (!read_exact(head, 2, timeout)) return std::nullopt;
        WsFrame f;
        f.fin = head[0] & 0x80;
        f.opcode = head[0] & 0x0F;
        if (head[1] & 0x80) return std::nullopt;   // servers never mask
        uint64_t length = head[1] & 0x7F;
        if (length == 126) {
            uint8_t b[2];
            if (!read_exact(b, 2, timeout)) return std::nullopt;
            length = (uint64_t{b[0]} << 8) | b[1];
        } else if (length == 127) {
            uint8_t b[8];
            if (!read_exact(b, 8, timeout)) return std::nullopt;
            length = 0;
            for (uint8_t x : b) length = (length << 8) | x;
        }
        f.payload.resize(length);
        if (length && !read_exact(f.payload.data(), length, timeout)) return std::nullopt;
        return f;
    }

    // True if the server closed the connection (EOF) within the timeout
    bool closed_by_peer(std::chrono::milliseconds timeout = std::chrono::milliseconds{3000}) {
        uint8_t byte;
        return !read_exact(&byte, 1, timeout) && eof_;
    }

private:
    bool read_exact(uint8_t* out, size_t n, std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
        size_t have = 0;
        while (have < n) {
            pollfd p{socket_.native_handle(), POLLIN, 0};
            if (::poll(&p, 1, static_cast<int>(timeout.count())) <= 0) return false;
            std::error_code ec;
            const size_t got = socket_.read_some(asio::buffer(out + have, n - have), ec);
            if (ec) {
                eof_ = (ec == asio::error::eof);
                return false;
            }
            have += got;
        }
        return true;
    }

    asio::io_context io_;
    asio::ip::tcp::socket socket_;
    bool eof_{false};
};

} // namespace wamp::test
