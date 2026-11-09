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

#include "base64.hpp"
#include "utf8.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace wamp::ws {

// ============================================================================
// WebSocket (RFC 6455), server side, for the "wamp.2.cbor" subprotocol
// ============================================================================
// Pure functions and one incremental frame parser; no I/O. WampSession drives them. Only what a WAMP
// router needs: the HTTP upgrade, binary data frames (with fragmentation), ping/pong and close.
// Not implemented: extensions (permessage-deflate), text frames (they belong to wamp.2.json).

inline constexpr std::string_view kSubprotocol = "wamp.2.cbor";        // the default and first choice
inline constexpr std::string_view kSubprotocolJson = "wamp.2.json";
inline constexpr size_t kMaxUpgradeRequest = 8 * 1024;   // request line + headers

enum class Opcode : uint8_t {
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0xA,
};

// Close status codes (RFC 6455 section 7.4.1) used by the router
inline constexpr uint16_t kCloseNormal = 1000;
inline constexpr uint16_t kCloseProtocolError = 1002;
inline constexpr uint16_t kCloseUnsupportedData = 1003;
inline constexpr uint16_t kCloseInvalidData = 1007;   // a text message that is not valid UTF-8
inline constexpr uint16_t kCloseTooBig = 1009;

// ----------------------------------------------------------------------------
// Handshake helpers
// ----------------------------------------------------------------------------

using wamp::base64_encode;   // (include/base64.hpp)

// SHA-1 of the client key plus the protocol GUID, base64 encoded (RFC 6455 section 4.2.2). SHA-1 is part
// of the handshake definition, not used for any security property here.
inline std::string accept_key(std::string_view client_key) {
    static constexpr std::string_view kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string input;
    input.reserve(client_key.size() + kGuid.size());
    input.append(client_key).append(kGuid);

    std::array<uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    EVP_Digest(input.data(), input.size(), digest.data(), &length, EVP_sha1(), nullptr);
    return base64_encode({digest.data(), length});
}

// A client key is the base64 of 16 random bytes: 24 characters ending in "=="
inline bool valid_client_key(std::string_view key) {
    if (key.size() != 24 || key.substr(22) != "==") return false;
    return std::ranges::all_of(key.substr(0, 22), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/';
    });
}

enum class UpgradeStatus {
    OK,
    INCOMPLETE,          // the request is not complete yet
    BAD_REQUEST,         // 400: malformed, missing header, or no wamp.2.cbor offered
    FORBIDDEN,           // 403: Origin not allowed
    UPGRADE_REQUIRED,    // 426: Sec-WebSocket-Version is not 13
    HEADER_TOO_LARGE,    // 431
};

struct UpgradeRequest {
    UpgradeStatus status{UpgradeStatus::INCOMPLETE};
    size_t consumed{0};     // bytes of the request including the blank line (OK only)
    std::string key;        // Sec-WebSocket-Key (OK only)
    std::string subprotocol;   // the subprotocol chosen: the first one the client offers that is enabled (OK only)
    std::string origin;     // Origin header, empty if absent
};

namespace detail {

inline std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

inline std::string lower(std::string_view s) {
    std::string out{s};
    std::ranges::transform(out, out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// True if the comma separated list contains `token` (case-insensitive)
inline bool has_token(std::string_view list, std::string_view token) {
    while (!list.empty()) {
        const auto comma = list.find(',');
        if (lower(trim(list.substr(0, comma))) == token) return true;
        if (comma == std::string_view::npos) break;
        list.remove_prefix(comma + 1);
    }
    return false;
}

} // namespace detail

// Parses the client's HTTP upgrade request. `allowed_origins` empty = any origin; otherwise a request
// that carries an Origin header must match one entry exactly (requests without one, i.e. non-browser
// clients, are allowed).
inline constexpr std::array<std::string_view, 1> kCborOnly{kSubprotocol};

// `enabled` lists the subprotocols the router speaks; the first one the client offers that is on the list is
// chosen (the client's order is its preference), and a client that offers none gets 400.
inline UpgradeRequest parse_upgrade(std::span<const uint8_t> data, const std::vector<std::string>& allowed_origins,
                                    std::span<const std::string_view> enabled = kCborOnly) {
    UpgradeRequest request;
    const std::string_view text{reinterpret_cast<const char*>(data.data()), data.size()};

    const auto end = text.find("\r\n\r\n");
    if (end == std::string_view::npos) {
        request.status = data.size() > kMaxUpgradeRequest ? UpgradeStatus::HEADER_TOO_LARGE : UpgradeStatus::INCOMPLETE;
        return request;
    }
    if (end + 4 > kMaxUpgradeRequest) {
        request.status = UpgradeStatus::HEADER_TOO_LARGE;
        return request;
    }
    request.consumed = end + 4;

    auto head = text.substr(0, end);
    const auto request_line_end = head.find("\r\n");
    const auto request_line = head.substr(0, request_line_end);
    head = request_line_end == std::string_view::npos ? std::string_view{} : head.substr(request_line_end + 2);

    request.status = UpgradeStatus::BAD_REQUEST;
    if (!request_line.starts_with("GET ") || !request_line.ends_with(" HTTP/1.1")) return request;

    bool upgrade = false, connection = false, version_13 = false, have_version = false;
    std::vector<std::string> offered;   // subprotocols in the client's order
    std::string key;
    while (!head.empty()) {
        const auto eol = head.find("\r\n");
        const auto line = head.substr(0, eol);
        head = eol == std::string_view::npos ? std::string_view{} : head.substr(eol + 2);

        const auto colon = line.find(':');
        if (colon == std::string_view::npos) return request;
        const auto name = detail::lower(detail::trim(line.substr(0, colon)));
        const auto value = detail::trim(line.substr(colon + 1));

        if (name == "upgrade") upgrade = upgrade || detail::has_token(value, "websocket");
        else if (name == "connection") connection = connection || detail::has_token(value, "upgrade");
        else if (name == "sec-websocket-key") key = std::string{value};
        else if (name == "sec-websocket-version") { have_version = true; version_13 = version_13 || value == "13"; }
        else if (name == "sec-websocket-protocol") {
            for (auto rest = value; !rest.empty();) {
                const auto comma = rest.find(',');
                offered.push_back(detail::lower(detail::trim(rest.substr(0, comma))));
                if (comma == std::string_view::npos) break;
                rest.remove_prefix(comma + 1);
            }
        }
        else if (name == "origin") request.origin = std::string{value};
    }

    if (!upgrade || !connection || !valid_client_key(key)) return request;
    if (!have_version || !version_13) { request.status = UpgradeStatus::UPGRADE_REQUIRED; return request; }
    for (const auto& name : offered) {
        if (std::ranges::find(enabled, std::string_view{name}) != enabled.end()) { request.subprotocol = name; break; }
    }
    if (request.subprotocol.empty()) return request;   // 400: nothing in common
    if (!allowed_origins.empty() && !request.origin.empty() &&
        std::ranges::find(allowed_origins, request.origin) == allowed_origins.end()) {
        request.status = UpgradeStatus::FORBIDDEN;
        return request;
    }

    request.status = UpgradeStatus::OK;
    request.key = std::move(key);
    return request;
}

inline std::string upgrade_response(std::string_view client_key, std::string_view subprotocol = kSubprotocol) {
    std::string out = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: ";
    out += accept_key(client_key);
    out += "\r\nSec-WebSocket-Protocol: ";
    out += subprotocol;
    out += "\r\n\r\n";
    return out;
}

inline std::string error_response(UpgradeStatus status) {
    const char* line = "400 Bad Request";
    switch (status) {
        case UpgradeStatus::FORBIDDEN: line = "403 Forbidden"; break;
        case UpgradeStatus::UPGRADE_REQUIRED: line = "426 Upgrade Required"; break;
        case UpgradeStatus::HEADER_TOO_LARGE: line = "431 Request Header Fields Too Large"; break;
        default: break;
    }
    std::string out = "HTTP/1.1 ";
    out += line;
    out += "\r\nConnection: close\r\nContent-Length: 0\r\n";
    if (status == UpgradeStatus::UPGRADE_REQUIRED) out += "Sec-WebSocket-Version: 13\r\n";
    out += "\r\n";
    return out;
}

// ----------------------------------------------------------------------------
// Frames
// ----------------------------------------------------------------------------

// A server-to-client frame header (never masked)
struct FrameHeaderBytes {
    std::array<uint8_t, 10> bytes{};
    size_t size{0};
    [[nodiscard]] std::span<const uint8_t> view() const { return {bytes.data(), size}; }
};

inline FrameHeaderBytes encode_header(Opcode opcode, uint64_t length, bool fin = true) {
    FrameHeaderBytes h;
    h.bytes[0] = static_cast<uint8_t>((fin ? 0x80 : 0x00) | static_cast<uint8_t>(opcode));
    if (length < 126) {
        h.bytes[1] = static_cast<uint8_t>(length);
        h.size = 2;
    } else if (length <= 0xFFFF) {
        h.bytes[1] = 126;
        h.bytes[2] = static_cast<uint8_t>(length >> 8);
        h.bytes[3] = static_cast<uint8_t>(length);
        h.size = 4;
    } else {
        h.bytes[1] = 127;
        for (int i = 0; i < 8; ++i) h.bytes[2 + i] = static_cast<uint8_t>(length >> (56 - 8 * i));
        h.size = 10;
    }
    return h;
}

// Appends a complete unmasked frame
inline void append_frame(std::vector<uint8_t>& out, Opcode opcode, std::span<const uint8_t> payload) {
    const auto header = encode_header(opcode, payload.size());
    out.insert(out.end(), header.bytes.begin(), header.bytes.begin() + static_cast<std::ptrdiff_t>(header.size));
    out.insert(out.end(), payload.begin(), payload.end());
}

inline void append_close(std::vector<uint8_t>& out, uint16_t code) {
    const std::array<uint8_t, 2> payload{static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code)};
    append_frame(out, Opcode::CLOSE, payload);
}

// XOR with the 4-byte mask, eight bytes at a time
inline void unmask(uint8_t* data, size_t length, const uint8_t key[4]) {
    uint8_t doubled[8] = {key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3]};
    uint64_t wide_key;
    std::memcpy(&wide_key, doubled, 8);   // same byte order as the words loaded below, on any endianness
    size_t i = 0;
    for (; i + 8 <= length; i += 8) {
        uint64_t word;
        std::memcpy(&word, data + i, 8);
        word ^= wide_key;
        std::memcpy(data + i, &word, 8);
    }
    for (; i < length; ++i) data[i] ^= key[i % 4];
}

// Result of FrameParser::next
struct Parsed {
    enum class Kind {
        NEED_MORE,   // not enough bytes for the next frame
        MESSAGE,     // a complete binary message (payload)
        PING,        // payload to echo in a PONG
        PONG,
        CLOSE,       // the peer's close frame: `code` (1005 if it carried none) and payload
        FAIL,        // protocol violation: close with `code`
    };
    Kind kind{Kind::NEED_MORE};
    size_t consumed{0};              // bytes of the input used, also for NEED_MORE after skipped fragments
    std::vector<uint8_t> payload;
    uint16_t code{0};
};

// Incremental server-side frame parser. The caller keeps the unread bytes and calls next() until it
// returns NEED_MORE, advancing by `consumed` each time. A frame is parsed only once it is complete in the
// input, so the header is cheap to re-examine as more bytes arrive; its length is checked against
// `max_message` before anything is allocated.
class FrameParser {
public:
    // text_mode: the connection speaks wamp.2.json, so data messages must be text frames of valid UTF-8 (and binary
    // frames are refused); otherwise (wamp.2.cbor) they must be binary frames
    explicit FrameParser(size_t max_message, bool text_mode = false) : max_message_(max_message), text_mode_(text_mode) {}

    Parsed next(std::span<const uint8_t> in) {
        Parsed out;
        while (true) {
            if (in.size() < 2) return out;
            const uint8_t b0 = in[0], b1 = in[1];
            const bool fin = b0 & 0x80;
            const auto opcode = static_cast<uint8_t>(b0 & 0x0F);
            const bool masked = b1 & 0x80;

            if (b0 & 0x70) return fail(out, kCloseProtocolError);                 // reserved bits, no extensions
            if (!masked) return fail(out, kCloseProtocolError);                   // clients must mask
            const bool control = opcode & 0x8;
            if (!control && opcode > 0x2) return fail(out, kCloseProtocolError);  // reserved data opcodes
            if (control && opcode > 0xA) return fail(out, kCloseProtocolError);   // reserved control opcodes

            uint64_t length = b1 & 0x7F;
            size_t header = 2;
            if (length == 126) {
                if (in.size() < 4) return out;
                length = (uint64_t{in[2]} << 8) | in[3];
                header = 4;
            } else if (length == 127) {
                if (in.size() < 10) return out;
                length = 0;
                for (int i = 0; i < 8; ++i) length = (length << 8) | in[2 + i];
                header = 10;
                if (length >> 63) return fail(out, kCloseProtocolError);          // top bit must be 0
            }
            if (control && (length > 125 || !fin)) return fail(out, kCloseProtocolError);
            if (!control && message_.size() + length > max_message_) return fail(out, kCloseTooBig);

            if (in.size() < header + 4 + length) return out;                      // frame not complete yet
            uint8_t key[4];
            std::memcpy(key, in.data() + header, 4);
            const uint8_t* payload = in.data() + header + 4;
            const size_t frame_size = header + 4 + static_cast<size_t>(length);

            if (control) {
                std::vector<uint8_t> body(payload, payload + length);
                unmask(body.data(), body.size(), key);
                out.consumed += frame_size;
                out.payload = std::move(body);
                switch (static_cast<Opcode>(opcode)) {
                    case Opcode::PING: out.kind = Parsed::Kind::PING; return out;
                    case Opcode::PONG: out.kind = Parsed::Kind::PONG; return out;
                    default: break;
                }
                // CLOSE: empty, or a 2-byte status code plus an optional reason
                out.kind = Parsed::Kind::CLOSE;
                out.code = 1005;
                if (out.payload.size() == 1) return fail(out, kCloseProtocolError);
                if (out.payload.size() >= 2) {
                    out.code = static_cast<uint16_t>((out.payload[0] << 8) | out.payload[1]);
                    if (!valid_close_code(out.code)) return fail(out, kCloseProtocolError);
                }
                return out;
            }

            // Data frame
            if (opcode == 0x0) {
                if (!in_message_) return fail(out, kCloseProtocolError);          // continuation with nothing to continue
            } else {
                if (in_message_) return fail(out, kCloseProtocolError);          // new message inside a fragmented one
                if ((opcode == 0x1) != text_mode_) return fail(out, kCloseUnsupportedData);   // wrong frame kind for the subprotocol
                in_message_ = true;
            }
            const auto old_size = message_.size();
            message_.insert(message_.end(), payload, payload + length);
            unmask(message_.data() + old_size, static_cast<size_t>(length), key);
            in = in.subspan(frame_size);
            out.consumed += frame_size;

            if (fin) {
                in_message_ = false;
                if (text_mode_ && !valid_utf8({reinterpret_cast<const char*>(message_.data()), message_.size()})) {
                    out.kind = Parsed::Kind::FAIL;
                    out.code = kCloseInvalidData;
                    message_.clear();
                    return out;
                }
                out.kind = Parsed::Kind::MESSAGE;
                out.payload = std::exchange(message_, {});
                return out;
            }
            // else keep reading: the rest of the message may already be in the input
        }
    }

private:
    static bool valid_close_code(uint16_t code) {
        if (code >= 3000 && code <= 4999) return true;
        return code >= 1000 && code <= 1011 && code != 1004 && code != 1005 && code != 1006;
    }

    static Parsed fail(Parsed& out, uint16_t code) {
        out.kind = Parsed::Kind::FAIL;
        out.code = code;
        return std::move(out);
    }

    size_t max_message_;
    bool text_mode_;
    std::vector<uint8_t> message_;
    bool in_message_{false};
};

} // namespace wamp::ws
