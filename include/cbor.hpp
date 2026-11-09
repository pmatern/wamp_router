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

// Minimal CBOR (RFC 8949) reader and writer for WAMP messages.
//
// Messages are read straight into the WAMP structs and written straight into the output buffer: no
// intermediate tree, no per-node allocation (a JSON-tree library used to sit here and cost a third of the
// CPU). It covers what WAMP needs (unsigned/negative integers, text strings, arrays, maps, booleans, null,
// floats, tags, indefinite-length containers) and writes the shortest-form encoding with map keys in
// order, so the bytes are deterministic.

#include <cmath>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace wamp::cbor {

// ----------------------------------------------------------------------------
// Writer
// ----------------------------------------------------------------------------
class Writer {
public:
    explicit Writer(std::vector<uint8_t>& out) : out_(out) {}

    void write_uint(uint64_t v) { head(0, v); }

    void write_int(int64_t v) {
        if (v >= 0) {
            head(0, static_cast<uint64_t>(v));
        } else {
            head(1, ~static_cast<uint64_t>(v));  // -1 - v
        }
    }

    void write_text(std::string_view s) {
        head(3, s.size());
        out_.insert(out_.end(), s.begin(), s.end());
    }

    void write_bool(bool b) { out_.push_back(b ? 0xF5 : 0xF4); }
    void write_null() { out_.push_back(0xF6); }

    // A byte string
    void write_bytes(std::span<const uint8_t> bytes) {
        head(2, bytes.size());
        out_.insert(out_.end(), bytes.begin(), bytes.end());
    }

    // A double in the shortest form that keeps its value: single precision when that is exact, else double
    // (NaN and infinities too; this matches what the nlohmann test oracle writes)
    void write_double(double v) {
        const float f = static_cast<float>(v);
        if (static_cast<double>(f) == v || std::isnan(v)) {
            uint32_t bits;
            std::memcpy(&bits, &f, 4);
            out_.push_back(0xFA);
            put_be(bits, 4);
        } else {
            uint64_t bits;
            std::memcpy(&bits, &v, 8);
            out_.push_back(0xFB);
            put_be(bits, 8);
        }
    }

    // Indefinite-length containers: items follow, then write_break(). Used when the item count is not known yet.
    void begin_indefinite_array() { out_.push_back(0x9F); }
    void begin_indefinite_map() { out_.push_back(0xBF); }
    void write_break() { out_.push_back(0xFF); }

    // Appends bytes that are already encoded CBOR
    void write_raw(std::span<const uint8_t> encoded) { out_.insert(out_.end(), encoded.begin(), encoded.end()); }

    void write_array(uint64_t count) { head(4, count); }
    void write_map(uint64_t count) { head(5, count); }

    // A definite-length empty map (0xA0), the usual WAMP Details/Options value
    void write_empty_map() { out_.push_back(0xA0); }

private:
    void head(uint8_t major, uint64_t v) {
        const uint8_t m = static_cast<uint8_t>(major << 5);
        if (v < 24) {
            out_.push_back(m | static_cast<uint8_t>(v));
        } else if (v <= 0xFF) {
            out_.push_back(m | 24);
            out_.push_back(static_cast<uint8_t>(v));
        } else if (v <= 0xFFFF) {
            out_.push_back(m | 25);
            put_be(v, 2);
        } else if (v <= 0xFFFFFFFF) {
            out_.push_back(m | 26);
            put_be(v, 4);
        } else {
            out_.push_back(m | 27);
            put_be(v, 8);
        }
    }

    void put_be(uint64_t v, int bytes) {
        for (int i = bytes - 1; i >= 0; --i) out_.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }

    std::vector<uint8_t>& out_;
};

// ----------------------------------------------------------------------------
// Reader
// ----------------------------------------------------------------------------

// Thrown for bytes that are not valid CBOR, truncated input, or an unexpected value type
struct DecodeError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// An array or map being read. Definite containers count down; indefinite ones end at a break byte.
struct Container {
    uint64_t remaining = 0;
    bool indefinite = false;
};

enum class Major : uint8_t { UNSIGNED = 0, NEGATIVE = 1, BYTES = 2, TEXT = 3, ARRAY = 4, MAP = 5, TAG = 6, SIMPLE = 7 };

class Reader {
public:
    explicit Reader(const std::vector<uint8_t>& data) : p_(data.data()), end_(data.data() + data.size()) {}
    Reader(const uint8_t* data, size_t size) : p_(data), end_(data + size) {}

    [[nodiscard]] bool at_end() const { return p_ == end_; }

    // Major type of the next item, tags transparently skipped
    [[nodiscard]] Major peek_major() {
        skip_tags();
        return static_cast<Major>(need(1)[0] >> 5);
    }

    [[nodiscard]] bool peek_is_null() {
        skip_tags();
        const uint8_t b = need(1)[0];
        return b == 0xF6 || b == 0xF7;   // null or undefined
    }

    [[nodiscard]] bool peek_is_bool() {
        skip_tags();
        const uint8_t b = need(1)[0];
        return b == 0xF4 || b == 0xF5;
    }

    [[nodiscard]] bool peek_is_number() {
        skip_tags();
        const auto b = need(1)[0];
        const auto major = static_cast<Major>(b >> 5);
        return major == Major::UNSIGNED || major == Major::NEGATIVE ||
               (major == Major::SIMPLE && b >= 0xF9 && b <= 0xFB);
    }

    // --- containers ---------------------------------------------------------
    Container read_array() { return container(Major::ARRAY); }
    Container read_map() { return container(Major::MAP); }

    // True if the container has another element (consumes the break byte of an indefinite one at its end)
    bool next(Container& c) {
        if (c.indefinite) {
            if (need(1)[0] == 0xFF) {
                ++p_;
                return false;
            }
            return true;
        }
        if (c.remaining == 0) return false;
        --c.remaining;
        return true;
    }

    // --- scalars ------------------------------------------------------------
    uint64_t read_uint() {
        skip_tags();
        const uint8_t b = need(1)[0];
        if ((b >> 5) != 0) throw DecodeError("expected unsigned integer");
        ++p_;
        return argument(b & 0x1F);
    }

    // Any integer that fits int64; floats are truncated like the previous JSON-based reader did
    int64_t read_int() {
        skip_tags();
        const uint8_t b = need(1)[0];
        const auto major = static_cast<Major>(b >> 5);
        if (major == Major::UNSIGNED) {
            ++p_;
            const uint64_t v = argument(b & 0x1F);
            if (v > static_cast<uint64_t>(INT64_MAX)) throw DecodeError("integer out of int64 range");
            return static_cast<int64_t>(v);
        }
        if (major == Major::NEGATIVE) {
            ++p_;
            const uint64_t v = argument(b & 0x1F);
            if (v > static_cast<uint64_t>(INT64_MAX)) throw DecodeError("integer out of int64 range");
            return -1 - static_cast<int64_t>(v);
        }
        if (major == Major::SIMPLE && b >= 0xF9 && b <= 0xFB) {
            const double d = read_float();
            if (!std::isfinite(d) || d < -9.2e18 || d > 9.2e18) throw DecodeError("float out of int64 range");
            return static_cast<int64_t>(d);
        }
        throw DecodeError("expected integer");
    }

    bool read_bool() {
        skip_tags();
        const uint8_t b = need(1)[0];
        if (b != 0xF4 && b != 0xF5) throw DecodeError("expected boolean");
        ++p_;
        return b == 0xF5;
    }

    // Text string, valid for as long as the underlying buffer
    std::string_view read_text_view() {
        skip_tags();
        const uint8_t b = need(1)[0];
        if ((b >> 5) != 3) throw DecodeError("expected text string");
        if ((b & 0x1F) == 31) throw DecodeError("indefinite-length strings are not supported");
        ++p_;
        const uint64_t len = argument(b & 0x1F);
        const uint8_t* s = need(len);
        p_ += len;
        return {reinterpret_cast<const char*>(s), static_cast<size_t>(len)};
    }

    std::string read_text() { return std::string{read_text_view()}; }

    // Byte string, valid for as long as the underlying buffer
    std::span<const uint8_t> read_bytes_view() {
        skip_tags();
        const uint8_t b = need(1)[0];
        if ((b >> 5) != 2) throw DecodeError("expected byte string");
        if ((b & 0x1F) == 31) throw DecodeError("indefinite-length strings are not supported");
        ++p_;
        const uint64_t len = argument(b & 0x1F);
        const uint8_t* s = need(len);
        p_ += len;
        return {s, static_cast<size_t>(len)};
    }

    // Half, single or double precision float (an integer item is not accepted here; use read_int)
    double read_double() {
        skip_tags();
        const uint8_t b = need(1)[0];
        if (!(static_cast<Major>(b >> 5) == Major::SIMPLE && b >= 0xF9 && b <= 0xFB)) {
            throw DecodeError("expected float");
        }
        return read_float();
    }

    // True for a float item (half, single or double precision)
    [[nodiscard]] bool peek_is_float() {
        skip_tags();
        const uint8_t b = need(1)[0];
        return static_cast<Major>(b >> 5) == Major::SIMPLE && b >= 0xF9 && b <= 0xFB;
    }

    // Consumes a null (or undefined) item
    void read_null() {
        skip_tags();
        const uint8_t b = need(1)[0];
        if (b != 0xF6 && b != 0xF7) throw DecodeError("expected null");
        ++p_;
    }

    // Nesting limit for recursive readers
    static constexpr int kMaxNesting = 64;

    // Skips one whole item of any type
    void skip(int depth = 0) {
        if (depth > kMaxDepth) throw DecodeError("nesting too deep");
        skip_tags();
        const uint8_t b = need(1)[0];
        const auto major = static_cast<Major>(b >> 5);
        switch (major) {
            case Major::UNSIGNED:
            case Major::NEGATIVE:
                ++p_;
                (void)argument(b & 0x1F);
                return;
            case Major::BYTES:
            case Major::TEXT: {
                ++p_;
                if ((b & 0x1F) == 31) {  // indefinite: definite chunks until break
                    while (need(1)[0] != 0xFF) skip(depth + 1);
                    ++p_;
                    return;
                }
                const uint64_t len = argument(b & 0x1F);
                (void)need(len);
                p_ += len;
                return;
            }
            case Major::ARRAY:
            case Major::MAP: {
                auto c = container(major);
                const int per_entry = major == Major::MAP ? 2 : 1;
                while (next(c)) {
                    for (int i = 0; i < per_entry; ++i) skip(depth + 1);
                }
                return;
            }
            case Major::TAG:
                return;  // unreachable: skip_tags() consumed them
            case Major::SIMPLE:
                ++p_;
                if ((b & 0x1F) == 24) (void)need(1), ++p_;
                else if ((b & 0x1F) == 25) (void)need(2), p_ += 2;
                else if ((b & 0x1F) == 26) (void)need(4), p_ += 4;
                else if ((b & 0x1F) == 27) (void)need(8), p_ += 8;
                else if ((b & 0x1F) >= 28) throw DecodeError("reserved simple value");
                return;
        }
    }

private:
    static constexpr int kMaxDepth = 64;

    const uint8_t* need(uint64_t n) const {
        if (static_cast<uint64_t>(end_ - p_) < n) throw DecodeError("truncated CBOR");
        return p_;
    }

    void skip_tags() {
        while (p_ != end_ && (*p_ >> 5) == 6) {
            const uint8_t b = *p_++;
            (void)argument(b & 0x1F);
        }
    }

    // Value of an item's "additional information" (after the initial byte was consumed)
    uint64_t argument(uint8_t info) {
        if (info < 24) return info;
        int bytes;
        switch (info) {
            case 24: bytes = 1; break;
            case 25: bytes = 2; break;
            case 26: bytes = 4; break;
            case 27: bytes = 8; break;
            default: throw DecodeError("invalid additional information");
        }
        const uint8_t* s = need(bytes);
        uint64_t v = 0;
        for (int i = 0; i < bytes; ++i) v = (v << 8) | s[i];
        p_ += bytes;
        return v;
    }

    Container container(Major major) {
        skip_tags();
        const uint8_t b = need(1)[0];
        if (static_cast<Major>(b >> 5) != major) {
            throw DecodeError(major == Major::ARRAY ? "expected array" : "expected map");
        }
        ++p_;
        if ((b & 0x1F) == 31) return {0, true};
        const uint64_t count = argument(b & 0x1F);
        // Every element takes at least one byte (two for a map entry), so a count larger than the rest of
        // the input is malformed; rejecting it up front keeps a hostile header from driving huge loops
        if (count > static_cast<uint64_t>(end_ - p_)) throw DecodeError("container larger than input");
        return {count, false};
    }

    double read_float() {
        const uint8_t b = *p_++;
        if (b == 0xF9) {  // half precision
            const uint8_t* s = need(2);
            p_ += 2;
            const int half = (s[0] << 8) | s[1];
            const int exp = (half >> 10) & 0x1F;
            const int mant = half & 0x3FF;
            double val;
            if (exp == 0) val = std::ldexp(mant, -24);
            else if (exp != 31) val = std::ldexp(mant + 1024, exp - 25);
            else val = mant == 0 ? INFINITY : NAN;
            return (half & 0x8000) ? -val : val;
        }
        if (b == 0xFA) {
            const uint8_t* s = need(4);
            uint32_t bits = 0;
            for (int i = 0; i < 4; ++i) bits = (bits << 8) | s[i];
            p_ += 4;
            float f;
            std::memcpy(&f, &bits, 4);
            return f;
        }
        const uint8_t* s = need(8);
        uint64_t bits = 0;
        for (int i = 0; i < 8; ++i) bits = (bits << 8) | s[i];
        p_ += 8;
        double d;
        std::memcpy(&d, &bits, 8);
        return d;
    }

    const uint8_t* p_;
    const uint8_t* end_;
};

}  // namespace wamp::cbor
