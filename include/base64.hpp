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

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wamp {

// Standard base64 (RFC 4648 section 4) with padding
inline std::string base64_encode(std::span<const uint8_t> in) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const uint32_t v = (uint32_t{in[i]} << 16) | (uint32_t{in[i + 1]} << 8) | in[i + 2];
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += kAlphabet[v & 63];
    }
    if (const size_t rest = in.size() - i; rest == 1) {
        const uint32_t v = uint32_t{in[i]} << 16;
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += "==";
    } else if (rest == 2) {
        const uint32_t v = (uint32_t{in[i]} << 16) | (uint32_t{in[i + 1]} << 8);
        out += kAlphabet[(v >> 18) & 63];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

// Decodes standard base64; padding is optional, whitespace and other characters are errors
inline std::optional<std::vector<uint8_t>> base64_decode(std::string_view in) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    size_t padding = 0;
    while (!in.empty() && in.back() == '=') {
        in.remove_suffix(1);
        ++padding;
    }
    if (padding > 2 || (padding != 0 && (in.size() + padding) % 4 != 0)) return std::nullopt;
    if (in.size() % 4 == 1) return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(in.size() / 4 * 3 + 2);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        const int v = value(c);
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>(acc >> bits));
            acc &= (1u << bits) - 1;
        }
    }
    if (acc != 0) return std::nullopt;   // leftover bits must be zero
    return out;
}

} // namespace wamp
