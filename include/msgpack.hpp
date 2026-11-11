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

#pragma once

#include "cbor.hpp"
#include "utf8.hpp"
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace wamp::msgpackcodec {

// ============================================================================
// MessagePack <-> CBOR transcoding for wamp.2.msgpack
// ============================================================================
// Like the JSON adapter (json.hpp): a WAMP message is an array with the same layout in every serializer, so a
// MessagePack session converts whole messages at its edge, streaming, and the router core keeps working on CBOR.
//
// Mapping: nil, booleans, integers, floats (float32 is widened), str (must be valid UTF-8), bin (a CBOR byte
// string), arrays and maps (keys must be strings, as everywhere in WAMP) map directly. Extension types are
// refused. A uint64 above INT64_MAX becomes a double on the way in, as in the JSON adapter. In the other
// direction CBOR tags are dropped, every float is written as a float64, and indefinite-length containers (which
// the JSON adapter produces) are counted and written with a definite length.

enum class Error {
    SYNTAX = 1,   // truncated, or a byte that is not MessagePack (0xc1)
    UTF8,         // a str that is not valid UTF-8
    DEPTH,        // nested deeper than kMaxDepth
    UNSUPPORTED,  // an extension type, or a map key that is not a string
    TRAILING,     // data after the value
    CBOR,         // the CBOR input is invalid, truncated or has a non-text map key
};

inline const std::error_category& error_category() {
    static const struct : std::error_category {
        const char* name() const noexcept override { return "wamp.msgpack"; }
        std::string message(int ev) const override {
            switch (static_cast<Error>(ev)) {
                case Error::SYNTAX: return "invalid or truncated MessagePack";
                case Error::UTF8: return "invalid UTF-8 in a MessagePack str";
                case Error::DEPTH: return "MessagePack nested too deeply";
                case Error::UNSUPPORTED: return "unsupported MessagePack (extension type or non-string map key)";
                case Error::TRAILING: return "data after the MessagePack value";
                case Error::CBOR: return "invalid CBOR";
            }
            return "unknown MessagePack error";
        }
    } category;
    return category;
}

inline std::error_code make_error_code(Error e) { return {static_cast<int>(e), error_category()}; }

inline constexpr int kMaxDepth = 64;

namespace detail {

class ToCbor {
public:
    ToCbor(std::span<const uint8_t> in, std::vector<uint8_t>& out) : p_(in.data()), end_(in.data() + in.size()), w_(out) {}

    Error run() {
        if (const Error e = value(0); e != Error{}) return e;
        return p_ == end_ ? Error{} : Error::TRAILING;
    }

private:
    [[nodiscard]] size_t left() const { return static_cast<size_t>(end_ - p_); }

    // Big-endian unsigned integer of `bytes` bytes; false if the input is too short
    bool be(size_t bytes, uint64_t& v) {
        if (left() < bytes) return false;
        v = 0;
        for (size_t i = 0; i < bytes; ++i) v = (v << 8) | *p_++;
        return true;
    }

    Error text(uint64_t length) {
        if (left() < length) return Error::SYNTAX;
        const std::string_view s{reinterpret_cast<const char*>(p_), static_cast<size_t>(length)};
        if (!valid_utf8(s)) return Error::UTF8;
        w_.write_text(s);
        p_ += length;
        return {};
    }

    Error bytes(uint64_t length) {
        if (left() < length) return Error::SYNTAX;
        w_.write_bytes({p_, static_cast<size_t>(length)});
        p_ += length;
        return {};
    }

    Error array(uint64_t count, int depth) {
        if (count > left()) return Error::SYNTAX;   // every element takes at least one byte
        w_.write_array(count);
        for (uint64_t i = 0; i < count; ++i) {
            if (const Error e = value(depth + 1); e != Error{}) return e;
        }
        return {};
    }

    Error map(uint64_t count, int depth) {
        if (count > left() / 2) return Error::SYNTAX;   // a key and a value take at least two bytes
        w_.write_map(count);
        for (uint64_t i = 0; i < count; ++i) {
            if (left() == 0) return Error::SYNTAX;
            const uint8_t k = *p_;
            const bool is_str = (k >= 0xa0 && k <= 0xbf) || (k >= 0xd9 && k <= 0xdb);
            if (!is_str) return Error::UNSUPPORTED;
            if (const Error e = value(depth + 1); e != Error{}) return e;   // the key
            if (const Error e = value(depth + 1); e != Error{}) return e;   // the value
        }
        return {};
    }

    Error value(int depth) {
        if (depth > kMaxDepth) return Error::DEPTH;
        if (left() == 0) return Error::SYNTAX;
        const uint8_t b = *p_++;
        uint64_t n = 0;
        if (b <= 0x7f) { w_.write_uint(b); return {}; }                                 // positive fixint
        if (b >= 0xe0) { w_.write_int(static_cast<int8_t>(b)); return {}; }             // negative fixint
        if (b >= 0xa0 && b <= 0xbf) return text(b & 0x1f);                              // fixstr
        if (b >= 0x90 && b <= 0x9f) return array(b & 0x0f, depth);                      // fixarray
        if (b >= 0x80 && b <= 0x8f) return map(b & 0x0f, depth);                        // fixmap
        switch (b) {
            case 0xc0: w_.write_null(); return {};
            case 0xc2: w_.write_bool(false); return {};
            case 0xc3: w_.write_bool(true); return {};
            case 0xc4: return be(1, n) ? bytes(n) : Error::SYNTAX;
            case 0xc5: return be(2, n) ? bytes(n) : Error::SYNTAX;
            case 0xc6: return be(4, n) ? bytes(n) : Error::SYNTAX;
            case 0xca: {
                if (!be(4, n)) return Error::SYNTAX;
                w_.write_double(static_cast<double>(std::bit_cast<float>(static_cast<uint32_t>(n))));
                return {};
            }
            case 0xcb: {
                if (!be(8, n)) return Error::SYNTAX;
                w_.write_double(std::bit_cast<double>(n));
                return {};
            }
            case 0xcc: if (!be(1, n)) return Error::SYNTAX; w_.write_uint(n); return {};
            case 0xcd: if (!be(2, n)) return Error::SYNTAX; w_.write_uint(n); return {};
            case 0xce: if (!be(4, n)) return Error::SYNTAX; w_.write_uint(n); return {};
            case 0xcf:
                if (!be(8, n)) return Error::SYNTAX;
                if (n > static_cast<uint64_t>(INT64_MAX)) w_.write_double(static_cast<double>(n));   // as the JSON adapter
                else w_.write_uint(n);
                return {};
            case 0xd0: if (!be(1, n)) return Error::SYNTAX; w_.write_int(static_cast<int8_t>(n)); return {};
            case 0xd1: if (!be(2, n)) return Error::SYNTAX; w_.write_int(static_cast<int16_t>(n)); return {};
            case 0xd2: if (!be(4, n)) return Error::SYNTAX; w_.write_int(static_cast<int32_t>(n)); return {};
            case 0xd3: if (!be(8, n)) return Error::SYNTAX; w_.write_int(static_cast<int64_t>(n)); return {};
            case 0xd9: return be(1, n) ? text(n) : Error::SYNTAX;
            case 0xda: return be(2, n) ? text(n) : Error::SYNTAX;
            case 0xdb: return be(4, n) ? text(n) : Error::SYNTAX;
            case 0xdc: return be(2, n) ? array(n, depth) : Error::SYNTAX;
            case 0xdd: return be(4, n) ? array(n, depth) : Error::SYNTAX;
            case 0xde: return be(2, n) ? map(n, depth) : Error::SYNTAX;
            case 0xdf: return be(4, n) ? map(n, depth) : Error::SYNTAX;
            case 0xc7: case 0xc8: case 0xc9:                                    // ext 8/16/32
            case 0xd4: case 0xd5: case 0xd6: case 0xd7: case 0xd8:              // fixext 1/2/4/8/16
                return Error::UNSUPPORTED;
            default: return Error::SYNTAX;                                      // 0xc1 is never used
        }
    }

    const uint8_t* p_;
    const uint8_t* end_;
    cbor::Writer w_;
};

class FromCbor {
public:
    FromCbor(cbor::Reader& r, std::string& out) : r_(r), out_(out) {}

    Error value(int depth) {
        if (depth > kMaxDepth) return Error::DEPTH;
        switch (r_.peek_major()) {
            case cbor::Major::UNSIGNED: uint_(r_.read_uint()); return {};
            case cbor::Major::NEGATIVE: int_(r_.read_int()); return {};
            case cbor::Major::BYTES: {
                const auto b = r_.read_bytes_view();
                length(b.size(), 0xc4, 0xc5, 0xc6);
                out_.append(reinterpret_cast<const char*>(b.data()), b.size());
                return {};
            }
            case cbor::Major::TEXT: {
                const auto s = r_.read_text_view();
                if (!valid_utf8(s)) return Error::UTF8;
                text(s);
                return {};
            }
            case cbor::Major::ARRAY: return container(depth, false);
            case cbor::Major::MAP: return container(depth, true);
            default: break;
        }
        if (r_.peek_is_bool()) { out_.push_back(static_cast<char>(r_.read_bool() ? 0xc3 : 0xc2)); return {}; }
        if (r_.peek_is_null()) { r_.read_null(); out_.push_back(static_cast<char>(0xc0)); return {}; }
        if (r_.peek_is_float()) {
            const uint64_t bits = std::bit_cast<uint64_t>(r_.read_double());
            out_.push_back(static_cast<char>(0xcb));
            for (int shift = 56; shift >= 0; shift -= 8) out_.push_back(static_cast<char>(bits >> shift));
            return {};
        }
        return Error::CBOR;
    }

private:
    void be(uint64_t v, int bytes) {
        for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) out_.push_back(static_cast<char>(v >> shift));
    }

    // Header for a str/bin: `b8`, `b16`, `b32` are the type bytes for 1/2/4-byte lengths
    void length(size_t n, uint8_t b8, uint8_t b16, uint8_t b32) {
        if (n <= 0xff) { out_.push_back(static_cast<char>(b8)); be(n, 1); }
        else if (n <= 0xffff) { out_.push_back(static_cast<char>(b16)); be(n, 2); }
        else { out_.push_back(static_cast<char>(b32)); be(n, 4); }
    }

    void text(std::string_view s) {
        if (s.size() < 32) out_.push_back(static_cast<char>(0xa0 | s.size()));
        else length(s.size(), 0xd9, 0xda, 0xdb);
        out_.append(s);
    }

    void uint_(uint64_t v) {
        if (v <= 0x7f) out_.push_back(static_cast<char>(v));
        else if (v <= 0xff) { out_.push_back(static_cast<char>(0xcc)); be(v, 1); }
        else if (v <= 0xffff) { out_.push_back(static_cast<char>(0xcd)); be(v, 2); }
        else if (v <= 0xffffffff) { out_.push_back(static_cast<char>(0xce)); be(v, 4); }
        else { out_.push_back(static_cast<char>(0xcf)); be(v, 8); }
    }

    void int_(int64_t v) {   // v < 0 (CBOR negative)
        if (v >= -32) out_.push_back(static_cast<char>(v));
        else if (v >= INT8_MIN) { out_.push_back(static_cast<char>(0xd0)); be(static_cast<uint64_t>(v), 1); }
        else if (v >= INT16_MIN) { out_.push_back(static_cast<char>(0xd1)); be(static_cast<uint64_t>(v), 2); }
        else if (v >= INT32_MIN) { out_.push_back(static_cast<char>(0xd2)); be(static_cast<uint64_t>(v), 4); }
        else { out_.push_back(static_cast<char>(0xd3)); be(static_cast<uint64_t>(v), 8); }
    }

    void container_header(size_t count, bool is_map) {
        if (count < 16) out_.push_back(static_cast<char>((is_map ? 0x80 : 0x90) | count));
        else if (count <= 0xffff) { out_.push_back(static_cast<char>(is_map ? 0xde : 0xdc)); be(count, 2); }
        else { out_.push_back(static_cast<char>(is_map ? 0xdf : 0xdd)); be(count, 4); }
    }

    Error element(int depth, bool is_map_key, bool& had_error) {
        if (is_map_key && r_.peek_major() != cbor::Major::TEXT) { had_error = true; return Error::CBOR; }
        return value(depth + 1);
    }

    Error container(int depth, bool is_map) {
        auto c = is_map ? r_.read_map() : r_.read_array();
        const uint64_t items = is_map ? 2 : 1;   // CBOR elements per entry
        bool bad = false;
        if (!c.indefinite) {
            if (c.remaining > 0xffffffffull) return Error::CBOR;
            container_header(static_cast<size_t>(c.remaining), is_map);
            while (r_.next(c)) {
                for (uint64_t i = 0; i < items; ++i) {
                    if (const Error e = element(depth, is_map && i == 0, bad); e != Error{}) return e;
                }
            }
            return {};
        }
        // Indefinite length: count the entries while writing them aside, then put the header in front
        std::string inner;
        FromCbor sub{r_, inner};
        size_t count = 0;
        while (r_.next(c)) {
            for (uint64_t i = 0; i < items; ++i) {
                if (const Error e = sub.element(depth, is_map && i == 0, bad); e != Error{}) return e;
            }
            ++count;
        }
        container_header(count, is_map);
        out_ += inner;
        return {};
    }

    cbor::Reader& r_;
    std::string& out_;
};

} // namespace detail

// Appends the CBOR for the MessagePack value in `data` to `out` (nothing may follow the value). On failure `out`
// may hold a partial encoding.
[[nodiscard]] inline std::expected<void, std::error_code> to_cbor(std::span<const uint8_t> data, std::vector<uint8_t>& out) {
    if (const Error e = detail::ToCbor{data, out}.run(); e != Error{}) return std::unexpected{make_error_code(e)};
    return {};
}

// Appends the MessagePack for the single CBOR value in `cbor_data` to `out` (nothing may follow the value).
[[nodiscard]] inline std::expected<void, std::error_code> from_cbor(std::span<const uint8_t> cbor_data, std::string& out) {
    try {
        cbor::Reader r{cbor_data.data(), cbor_data.size()};
        if (const Error e = detail::FromCbor{r, out}.value(0); e != Error{}) return std::unexpected{make_error_code(e)};
        if (!r.at_end()) return std::unexpected{make_error_code(Error::TRAILING)};
        return {};
    } catch (const cbor::DecodeError&) {
        return std::unexpected{make_error_code(Error::CBOR)};
    }
}

} // namespace wamp::msgpackcodec
