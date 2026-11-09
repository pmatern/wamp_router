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
#include "cbor.hpp"
#include "utf8.hpp"
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace wamp::jsoncodec {

// ============================================================================
// JSON <-> CBOR transcoding for wamp.2.json
// ============================================================================
// A WAMP message is an array whose layout is the same in every serializer, so a JSON session needs no
// per-message code: the whole message is converted between JSON text and CBOR, streaming, without a
// tree. The router core keeps working on CBOR; this is the adapter at the edge of a JSON session.
//
// Mapping (WAMP spec, section "JSON"): null, true/false, integers and floats, strings, arrays and objects map
// directly. Binary data is a string that starts with a NUL character followed by standard base64
// ("\u0000" + base64), and corresponds to a CBOR byte string. In the other direction CBOR NaN and
// infinities become null (as JavaScript's JSON.stringify does), CBOR tags are dropped, and integers
// that do not fit int64 become doubles on the way in.

enum class Error {
    SYNTAX = 1,       // not valid JSON (or truncated)
    UTF8,             // invalid UTF-8, or a lone surrogate escape
    DEPTH,            // nested deeper than kMaxDepth
    NUMBER,           // number out of range (e.g. 1e999)
    TRAILING,         // data after the value
    BASE64,           // binary string that is not valid base64
    CBOR,             // the CBOR input is invalid, truncated or has a non-text map key
};

inline const std::error_category& error_category() {
    static const struct : std::error_category {
        const char* name() const noexcept override { return "wamp.json"; }
        std::string message(int ev) const override {
            switch (static_cast<Error>(ev)) {
                case Error::SYNTAX: return "invalid JSON";
                case Error::UTF8: return "invalid UTF-8";
                case Error::DEPTH: return "nested too deeply";
                case Error::NUMBER: return "number out of range";
                case Error::TRAILING: return "data after the JSON value";
                case Error::BASE64: return "invalid base64 in binary string";
                case Error::CBOR: return "invalid CBOR";
            }
            return "unknown JSON error";
        }
    } category;
    return category;
}

inline std::error_code make_error_code(Error e) { return {static_cast<int>(e), error_category()}; }

inline constexpr int kMaxDepth = cbor::Reader::kMaxNesting;

namespace detail {

// ---------------------------------------------------------------------------------------------------
// JSON text -> CBOR
// ---------------------------------------------------------------------------------------------------
class ToCbor {
public:
    ToCbor(std::string_view text, std::vector<uint8_t>& out) : p_(text.data()), end_(text.data() + text.size()), w_(out) {}

    Error run() {
        skip_ws();
        if (Error e = value(0); e != Error{}) return e;
        skip_ws();
        return p_ == end_ ? Error{} : Error::TRAILING;
    }

private:
    void skip_ws() {
        while (p_ != end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) ++p_;
    }

    bool literal(std::string_view word) {
        if (static_cast<size_t>(end_ - p_) < word.size() || std::string_view{p_, word.size()} != word) return false;
        p_ += word.size();
        return true;
    }

    Error value(int depth) {
        if (p_ == end_) return Error::SYNTAX;
        switch (*p_) {
            case 'n': return literal("null") ? (w_.write_null(), Error{}) : Error::SYNTAX;
            case 't': return literal("true") ? (w_.write_bool(true), Error{}) : Error::SYNTAX;
            case 'f': return literal("false") ? (w_.write_bool(false), Error{}) : Error::SYNTAX;
            case '"': return string(/*binary_allowed=*/true);
            case '[': return array(depth);
            case '{': return object(depth);
            default: return number();
        }
    }

    Error array(int depth) {
        if (depth >= kMaxDepth) return Error::DEPTH;
        ++p_;
        w_.begin_indefinite_array();
        skip_ws();
        if (p_ != end_ && *p_ == ']') { ++p_; w_.write_break(); return {}; }
        while (true) {
            skip_ws();
            if (Error e = value(depth + 1); e != Error{}) return e;
            skip_ws();
            if (p_ == end_) return Error::SYNTAX;
            if (*p_ == ',') { ++p_; continue; }
            if (*p_ == ']') { ++p_; w_.write_break(); return {}; }
            return Error::SYNTAX;
        }
    }

    Error object(int depth) {
        if (depth >= kMaxDepth) return Error::DEPTH;
        ++p_;
        w_.begin_indefinite_map();
        skip_ws();
        if (p_ != end_ && *p_ == '}') { ++p_; w_.write_break(); return {}; }
        while (true) {
            skip_ws();
            if (p_ == end_ || *p_ != '"') return Error::SYNTAX;
            if (Error e = string(/*binary_allowed=*/false); e != Error{}) return e;
            skip_ws();
            if (p_ == end_ || *p_ != ':') return Error::SYNTAX;
            ++p_;
            skip_ws();
            if (Error e = value(depth + 1); e != Error{}) return e;
            skip_ws();
            if (p_ == end_) return Error::SYNTAX;
            if (*p_ == ',') { ++p_; continue; }
            if (*p_ == '}') { ++p_; w_.write_break(); return {}; }
            return Error::SYNTAX;
        }
    }

    static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    bool hex4(uint32_t& out) {
        if (end_ - p_ < 4) return false;
        out = 0;
        for (int i = 0; i < 4; ++i) {
            const int h = hex(p_[i]);
            if (h < 0) return false;
            out = (out << 4) | static_cast<uint32_t>(h);
        }
        p_ += 4;
        return true;
    }

    static void append_utf8(std::string& s, uint32_t cp) {
        if (cp < 0x80) {
            s += static_cast<char>(cp);
        } else if (cp < 0x800) {
            s += static_cast<char>(0xC0 | (cp >> 6));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            s += static_cast<char>(0xE0 | (cp >> 12));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            s += static_cast<char>(0xF0 | (cp >> 18));
            s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    Error string(bool binary_allowed) {
        ++p_;   // opening quote
        scratch_.clear();
        while (true) {
            if (p_ == end_) return Error::SYNTAX;
            const auto c = static_cast<uint8_t>(*p_);
            if (c == '"') { ++p_; break; }
            if (c < 0x20) return Error::SYNTAX;   // raw control characters are not allowed
            if (c != '\\') { scratch_ += static_cast<char>(c); ++p_; continue; }
            if (++p_ == end_) return Error::SYNTAX;
            switch (*p_++) {
                case '"': scratch_ += '"'; break;
                case '\\': scratch_ += '\\'; break;
                case '/': scratch_ += '/'; break;
                case 'b': scratch_ += '\b'; break;
                case 'f': scratch_ += '\f'; break;
                case 'n': scratch_ += '\n'; break;
                case 'r': scratch_ += '\r'; break;
                case 't': scratch_ += '\t'; break;
                case 'u': {
                    uint32_t cp;
                    if (!hex4(cp)) return Error::SYNTAX;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {   // high surrogate: a low one must follow
                        uint32_t low;
                        if (end_ - p_ < 2 || p_[0] != '\\' || p_[1] != 'u') return Error::UTF8;
                        p_ += 2;
                        if (!hex4(low) || low < 0xDC00 || low > 0xDFFF) return Error::UTF8;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return Error::UTF8;               // lone low surrogate
                    }
                    append_utf8(scratch_, cp);
                    break;
                }
                default: return Error::SYNTAX;
            }
        }
        if (binary_allowed && !scratch_.empty() && scratch_[0] == '\0') {   // WAMP binary: NUL + base64
            auto bytes = base64_decode(std::string_view{scratch_}.substr(1));
            if (!bytes) return Error::BASE64;
            w_.write_bytes(*bytes);
            return {};
        }
        if (!valid_utf8(scratch_)) return Error::UTF8;
        w_.write_text(scratch_);
        return {};
    }

    Error number() {
        const char* start = p_;
        const char* q = p_;
        const bool negative = q != end_ && *q == '-';
        if (negative) ++q;
        if (q == end_) return Error::SYNTAX;
        if (*q == '0') {
            ++q;
        } else if (*q >= '1' && *q <= '9') {
            while (q != end_ && *q >= '0' && *q <= '9') ++q;
        } else {
            return Error::SYNTAX;
        }
        bool integral = true;
        if (q != end_ && *q == '.') {
            integral = false;
            ++q;
            if (q == end_ || *q < '0' || *q > '9') return Error::SYNTAX;
            while (q != end_ && *q >= '0' && *q <= '9') ++q;
        }
        if (q != end_ && (*q == 'e' || *q == 'E')) {
            integral = false;
            ++q;
            if (q != end_ && (*q == '+' || *q == '-')) ++q;
            if (q == end_ || *q < '0' || *q > '9') return Error::SYNTAX;
            while (q != end_ && *q >= '0' && *q <= '9') ++q;
        }
        p_ = q;
        const std::string_view token{start, static_cast<size_t>(q - start)};
        if (integral && token != "-0") {   // "-0" stays a float, like JavaScript's -0
            int64_t v;
            if (auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), v);
                ec == std::errc{} && ptr == token.data() + token.size()) {
                w_.write_int(v);
                return {};
            }
        }
        // a float, or an integer beyond int64 (kept as a double; the precision loss is the sender's)
        scratch_.assign(token);
        const double d = std::strtod(scratch_.c_str(), nullptr);   // the process never changes the C locale
        if (!std::isfinite(d)) return Error::NUMBER;
        w_.write_double(d);
        return {};
    }

    const char* p_;
    const char* end_;
    cbor::Writer w_;
    std::string scratch_;
};

// ---------------------------------------------------------------------------------------------------
// CBOR -> JSON text
// ---------------------------------------------------------------------------------------------------
inline void append_json_string(std::string& out, std::string_view s) {
    static constexpr char kHex[] = "0123456789abcdef";
    out += '"';
    for (const char ch : s) {
        const auto c = static_cast<uint8_t>(ch);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += kHex[c >> 4];
                    out += kHex[c & 15];
                } else {
                    out += ch;
                }
        }
    }
    out += '"';
}

// Shortest decimal that reads back as the same double; always looks like a float ("2.0", not "2")
inline void append_json_double(std::string& out, double v) {
    if (!std::isfinite(v)) { out += "null"; return; }
    char buf[40];
    for (int precision = 15; precision <= 17; ++precision) {
        std::snprintf(buf, sizeof buf, "%.*g", precision, v);
        if (std::strtod(buf, nullptr) == v) break;
    }
    out += buf;
    if (!std::string_view{buf}.contains('.') && !std::string_view{buf}.contains('e')) out += ".0";
}

class FromCbor {
public:
    FromCbor(cbor::Reader& r, std::string& out) : r_(r), out_(out) {}

    Error value(int depth) {
        if (depth > kMaxDepth) return Error::DEPTH;
        switch (r_.peek_major()) {
            case cbor::Major::UNSIGNED: {
                char buf[24];
                const auto [ptr, ec] = std::to_chars(buf, buf + sizeof buf, r_.read_uint());
                out_.append(buf, ptr);
                return {};
            }
            case cbor::Major::NEGATIVE: {
                char buf[24];
                const auto [ptr, ec] = std::to_chars(buf, buf + sizeof buf, r_.read_int());
                out_.append(buf, ptr);
                return {};
            }
            case cbor::Major::BYTES: {
                const auto bytes = r_.read_bytes_view();
                out_ += "\"\\u0000";
                out_ += base64_encode(bytes);
                out_ += '"';
                return {};
            }
            case cbor::Major::TEXT: {
                const auto text = r_.read_text_view();
                if (!valid_utf8(text)) return Error::UTF8;
                append_json_string(out_, text);
                return {};
            }
            case cbor::Major::ARRAY: {
                if (depth >= kMaxDepth) return Error::DEPTH;
                auto c = r_.read_array();
                out_ += '[';
                bool first = true;
                while (r_.next(c)) {
                    if (!first) out_ += ',';
                    first = false;
                    if (Error e = value(depth + 1); e != Error{}) return e;
                }
                out_ += ']';
                return {};
            }
            case cbor::Major::MAP: {
                if (depth >= kMaxDepth) return Error::DEPTH;
                auto c = r_.read_map();
                out_ += '{';
                bool first = true;
                while (r_.next(c)) {
                    if (!first) out_ += ',';
                    first = false;
                    if (r_.peek_major() != cbor::Major::TEXT) return Error::CBOR;   // JSON keys are strings
                    const auto key = r_.read_text_view();
                    if (!valid_utf8(key)) return Error::UTF8;
                    append_json_string(out_, key);
                    out_ += ':';
                    if (Error e = value(depth + 1); e != Error{}) return e;
                }
                out_ += '}';
                return {};
            }
            default:
                if (r_.peek_is_bool()) { out_ += r_.read_bool() ? "true" : "false"; return {}; }
                if (r_.peek_is_float()) { append_json_double(out_, r_.read_double()); return {}; }
                r_.read_null();   // null / undefined; anything else throws
                out_ += "null";
                return {};
        }
    }

private:
    cbor::Reader& r_;
    std::string& out_;
};

} // namespace detail

// Appends the CBOR for the JSON value in `text` to `out`. Containers are written with indefinite length,
// which every reader in this router accepts. On failure `out` may hold a partial encoding.
[[nodiscard]] inline std::expected<void, std::error_code> to_cbor(std::string_view text, std::vector<uint8_t>& out) {
    if (const Error e = detail::ToCbor{text, out}.run(); e != Error{}) return std::unexpected{make_error_code(e)};
    return {};
}

// Appends the JSON text for the single CBOR value in `cbor_data` to `out` (nothing may follow the value).
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

} // namespace wamp::jsoncodec

template<>
struct std::is_error_code_enum<wamp::jsoncodec::Error> : std::true_type {};
