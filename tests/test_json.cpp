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

#include "include/json.hpp"
#include "include/wamp_serializer.hpp"
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <random>

using namespace wamp;
using nlohmann::json;

namespace {

std::string to_text(const std::vector<uint8_t>& cbor_bytes) {
    std::string text;
    auto r = jsoncodec::from_cbor(cbor_bytes, text);
    REQUIRE(r.has_value());
    return text;
}

// JSON text -> CBOR -> WampValue (type exact: 2 and 2.0 differ)
std::expected<WampValue, std::error_code> parse(std::string_view text) {
    std::vector<uint8_t> out;
    if (auto r = jsoncodec::to_cbor(text, out); !r) return std::unexpected{r.error()};
    cbor::Reader reader{out};
    return fast::read_value(reader);
}

std::vector<uint8_t> cbor_of(const WampValue& v) {
    std::vector<uint8_t> out;
    cbor::Writer w{out};
    fast::write_value(w, v);
    return out;
}

// The nlohmann view of a tree (bytes as the WAMP "\0"+base64 string)
json to_oracle(const WampValue& v) {
    return std::visit([]<typename T>(const T& x) -> json {
        if constexpr (std::is_same_v<T, std::nullptr_t>) return nullptr;
        else if constexpr (std::is_same_v<T, WampBytes>) return std::string{"\0", 1} + base64_encode(x);
        else if constexpr (std::is_same_v<T, WampList>) {
            json a = json::array();
            for (const auto& item : x) a.push_back(to_oracle(item));
            return a;
        } else if constexpr (std::is_same_v<T, WampDict>) {
            json o = json::object();
            for (const auto& [key, item] : x) o[key] = to_oracle(item);
            return o;
        } else return x;
    }, v);
}

WampValue random_value(std::mt19937_64& rng, int depth) {
    switch (rng() % (depth >= 3 ? 8 : 10)) {
        case 0: return WampValue{};
        case 1: return WampValue{rng() % 2 == 0};
        case 2: return WampValue{static_cast<int64_t>(rng()) >> (rng() % 60)};
        case 3: {
            static const double specials[] = {0.0, -0.0, 0.5, 1.5, 2.0, 2.9, 1e300, -1e-300, 0.1, 3.14159265358979, 1e22, 123456789.125, 5e-324};
            return WampValue{specials[rng() % 13]};
        }
        case 4: {
            std::string s(rng() % 20, 'x');
            for (auto& c : s) c = static_cast<char>(' ' + rng() % 90);   // includes quote and backslash
            return WampValue{s};
        }
        case 5: {
            WampBytes b(rng() % 20);
            for (auto& x : b) x = static_cast<uint8_t>(rng());
            return WampValue{b};
        }
        case 6: return WampValue{std::string("tab\there \"quoted\" back\\slash \x01\x1f \xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80")};
        case 7: return WampValue{std::string{}};
        case 8: {
            WampList l;
            for (size_t n = rng() % 5; n > 0; --n) l.push_back(random_value(rng, depth + 1));
            return WampValue{l};
        }
        default: {
            WampDict d;
            for (size_t n = rng() % 5; n > 0; --n) d[std::string(1 + rng() % 3, static_cast<char>('a' + rng() % 8))] = random_value(rng, depth + 1);
            return WampValue{d};
        }
    }
}

}  // namespace

TEST_CASE("JSON text parses to the expected CBOR values", "[json]") {
    SECTION("scalars") {
        CHECK(std::holds_alternative<std::nullptr_t>(*parse("null")));
        CHECK(std::get<bool>(*parse("true")) == true);
        CHECK(std::get<bool>(*parse(" false ")) == false);
        CHECK(std::get<int64_t>(*parse("0")) == 0);
        CHECK(std::get<int64_t>(*parse("-17")) == -17);
        CHECK(std::get<int64_t>(*parse("9223372036854775807")) == INT64_MAX);
        CHECK(std::get<int64_t>(*parse("-9223372036854775808")) == INT64_MIN);
        CHECK(std::get<double>(*parse("9223372036854775808")) == 9223372036854775808.0);   // beyond int64: a double
        CHECK(std::get<double>(*parse("2.0")) == 2.0);
        CHECK(std::get<double>(*parse("-1.5e3")) == -1500.0);
        CHECK(std::get<double>(*parse("1E2")) == 100.0);
        CHECK(std::signbit(std::get<double>(*parse("-0"))));
        CHECK(std::get<double>(*parse("0.1")) == 0.1);
    }
    SECTION("strings and escapes") {
        CHECK(std::get<std::string>(*parse(R"("")")) == "");
        CHECK(std::get<std::string>(*parse(R"("a\"b\\c\/d\b\f\n\r\t")")) == "a\"b\\c/d\b\f\n\r\t");
        CHECK(std::get<std::string>(*parse(R"("\u00e9\u20ac")")) == "\xC3\xA9\xE2\x82\xAC");
        CHECK(std::get<std::string>(*parse(R"("\ud83d\ude00")")) == "\xF0\x9F\x98\x80");   // surrogate pair
        CHECK(std::get<std::string>(*parse("\"\xC3\xA9 raw utf-8\"")) == "\xC3\xA9 raw utf-8");
    }
    SECTION("binary: a string starting with NUL is base64 bytes") {
        CHECK(std::get<WampBytes>(*parse(R"("\u0000AQID")")) == WampBytes{1, 2, 3});
        CHECK(std::get<WampBytes>(*parse(R"("\u0000AQI=")")) == WampBytes{1, 2});
        CHECK(std::get<WampBytes>(*parse(R"("\u0000")")).empty());
        auto keyed = parse(R"({"\u0000x":"y"})");   // object keys are always strings, never binary
        REQUIRE(keyed);
        CHECK(std::get<WampDict>(*keyed).contains(std::string{"\0x", 2}));
    }
    SECTION("containers") {
        auto v = parse(R"( {"a":[1,2.5,null,{"b":true}],"c":{}, "d":[]} )");
        REQUIRE(v);
        const auto& d = std::get<WampDict>(*v);
        CHECK(std::get<WampList>(d.at("a")).size() == 4);
        CHECK(std::get<WampDict>(d.at("c")).empty());
        CHECK(std::get<WampList>(d.at("d")).empty());
        CHECK(std::get<WampDict>(std::get<WampList>(d.at("a"))[3]).at("b") == WampValue{true});
    }
    SECTION("a whole WAMP message") {
        std::vector<uint8_t> out;
        REQUIRE(jsoncodec::to_cbor(R"([48,7,{"timeout":250},"com.example.add",[2,3],{"unit":"ms","pi":3.5}])", out));
        auto call = deserialize_call(out);
        REQUIRE(call);
        CHECK(call->request_id == 7);
        CHECK(call->procedure == "com.example.add");
        CHECK(std::get<int64_t>(call->options.at("timeout")) == 250);
        CHECK(call->arguments == WampList{int64_t{2}, int64_t{3}});
        CHECK(std::get<double>(call->arguments_kw.at("pi")) == 3.5);
        CHECK(get_message_type_from_cbor(out).value() == MessageType::CALL);
    }
}

TEST_CASE("Invalid JSON is rejected with a specific error", "[json]") {
    auto code = [](std::string_view text) {
        auto r = parse(text);
        REQUIRE_FALSE(r.has_value());
        return r.error();
    };
    using E = jsoncodec::Error;
    const char* syntax[] = {"", " ", "nul", "tru", "falsey", "[", "[1,", "[1 2]", "[1,]", "{", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "{a:1}", "{1:2}",
                            "'x'", "\"abc", "\"a\nb\"", "\"\\x\"", "\"\\u12\"", "\"\\u12zz\"", "01", "-", "+1", ".5", "1.", "1e", "1e+", "--1",
                            "[1]]", "0x10", "NaN", "Infinity", "-Infinity", "\x01", "[\"a\" \"b\"]"};
    for (const char* text : syntax) {
        INFO(text);
        const auto ec = code(text);
        CHECK((ec == E::SYNTAX || ec == E::TRAILING));
    }
    CHECK(code("[1] x") == E::TRAILING);
    CHECK(code("1 2") == E::TRAILING);
    CHECK(code("\"\\ud800\"") == E::UTF8);          // lone high surrogate
    CHECK(code("\"\\udc00\"") == E::UTF8);          // lone low surrogate
    CHECK(code("\"\\ud800\\u0041\"") == E::UTF8);  // high surrogate followed by a non-surrogate
    CHECK(code("\"\xC3\"") == E::UTF8);              // truncated sequence
    CHECK(code("\"\xC0\x80\"") == E::UTF8);         // overlong
    CHECK(code("\"\xED\xA0\x80\"") == E::UTF8);    // encoded surrogate
    CHECK(code("\"\xF4\x90\x80\x80\"") == E::UTF8);  // above U+10FFFF
    CHECK(code("\"\xFF\"") == E::UTF8);
    CHECK(code("1e999") == E::NUMBER);
    CHECK(code("-1e999") == E::NUMBER);
    CHECK(code(R"("\u0000!!!")") == E::BASE64);
    CHECK(code(R"("\u0000A")") == E::BASE64);
    CHECK(code(R"("\u0000AQ=I")") == E::BASE64);
}

TEST_CASE("Nesting is limited in both directions", "[json]") {
    const std::string deep_arrays(100000, '[');
    CHECK(parse(deep_arrays).error() == jsoncodec::Error::DEPTH);
    std::string deep_objects;
    for (int i = 0; i < 100000; ++i) deep_objects += "{\"a\":";
    CHECK(parse(deep_objects).error() == jsoncodec::Error::DEPTH);

    std::string ok = std::string(60, '[') + "1" + std::string(60, ']');
    CHECK(parse(ok).has_value());
    std::string too_deep = std::string(70, '[') + "1" + std::string(70, ']');
    CHECK(parse(too_deep).error() == jsoncodec::Error::DEPTH);

    // CBOR nested deeper than the limit cannot be turned into JSON (a stack-overflow guard)
    std::vector<uint8_t> bomb(100000, 0x81);
    bomb.push_back(0x00);
    std::string text;
    CHECK_FALSE(jsoncodec::from_cbor(bomb, text).has_value());
}

TEST_CASE("CBOR converts to compact JSON", "[json]") {
    SECTION("scalars") {
        CHECK(to_text(cbor_of(WampValue{})) == "null");
        CHECK(to_text(cbor_of(WampValue{true})) == "true");
        CHECK(to_text(cbor_of(WampValue{int64_t{-5}})) == "-5");
        CHECK(to_text(cbor_of(WampValue{INT64_MIN})) == "-9223372036854775808");
        CHECK(to_text(cbor_of(WampValue{2.0})) == "2.0");
        CHECK(to_text(cbor_of(WampValue{2.5})) == "2.5");
        CHECK(to_text(cbor_of(WampValue{0.1})) == "0.1");
        CHECK(to_text(cbor_of(WampValue{1e300})) == "1e+300");
        CHECK(to_text(cbor_of(WampValue{-0.0})) == "-0.0");
        CHECK(to_text(cbor_of(WampValue{std::nan("")})) == "null");
        CHECK(to_text(cbor_of(WampValue{INFINITY})) == "null");
        CHECK(to_text(cbor_of(WampValue{-INFINITY})) == "null");
    }
    SECTION("strings are escaped") {
        CHECK(to_text(cbor_of(WampValue{std::string{"a\"b\\c\n\t\x01\x1f"}})) == R"("a\"b\\c\n\t\u0001\u001f")");
        CHECK(to_text(cbor_of(WampValue{std::string{"\xC3\xA9\xF0\x9F\x98\x80"}})) == "\"\xC3\xA9\xF0\x9F\x98\x80\"");   // UTF-8 stays UTF-8
        CHECK(to_text(cbor_of(WampValue{WampBytes{1, 2, 3}})) == R"("\u0000AQID")");
    }
    SECTION("containers keep order, empty ones are [] and {}") {
        CHECK(to_text(cbor_of(WampValue{WampList{}})) == "[]");
        CHECK(to_text(cbor_of(WampValue{WampDict{}})) == "{}");
        CHECK(to_text(cbor_of(WampValue{WampList{int64_t{1}, std::string{"b"}, WampList{}}})) == R"([1,"b",[]])");
        CHECK(to_text(cbor_of(WampValue{WampDict{{"b", int64_t{2}}, {"a", int64_t{1}}}})) == R"({"a":1,"b":2})");   // keys are written sorted
    }
    SECTION("invalid CBOR") {
        std::string text;
        CHECK(jsoncodec::from_cbor(std::vector<uint8_t>{0x82, 0x01}, text).error() == jsoncodec::Error::CBOR);          // truncated array
        CHECK(jsoncodec::from_cbor(std::vector<uint8_t>{0xA1, 0x01, 0x02}, text).error() == jsoncodec::Error::CBOR);    // non-text map key
        CHECK(jsoncodec::from_cbor(std::vector<uint8_t>{0x62, 0xC3, 0x28}, text).error() == jsoncodec::Error::UTF8);    // invalid UTF-8 text
        CHECK(jsoncodec::from_cbor(std::vector<uint8_t>{0x01, 0x02}, text).error() == jsoncodec::Error::TRAILING);
        CHECK(jsoncodec::from_cbor(std::vector<uint8_t>{}, text).error() == jsoncodec::Error::CBOR);
    }
    SECTION("indefinite-length containers (what the JSON parser writes) are read") {
        const std::vector<uint8_t> indefinite{0x9F, 0x01, 0xBF, 0x61, 'k', 0x02, 0xFF, 0xFF};
        CHECK(to_text(indefinite) == R"([1,{"k":2}])");
    }
}

TEST_CASE("JSON and CBOR agree with nlohmann on random payloads", "[json][oracle]") {
    std::mt19937_64 rng(2024);
    for (int i = 0; i < 2000; ++i) {
        const WampValue tree = random_value(rng, 0);

        // our JSON for the tree parses (in nlohmann) to the oracle's view of the same tree
        const std::string text = to_text(cbor_of(tree));
        REQUIRE(json::parse(text) == to_oracle(tree));

        // and reading our own JSON back gives the exact same tree, types included
        auto back = parse(text);
        REQUIRE(back.has_value());
        REQUIRE(*back == tree);

        // nlohmann's JSON text for the tree reads as the same tree too (its integral doubles print as 2.0)
        auto from_oracle = parse(to_oracle(tree).dump());
        REQUIRE(from_oracle.has_value());
        REQUIRE(*from_oracle == tree);
    }
}

TEST_CASE("The JSON transcoder survives garbage and mutated input", "[json][fuzz]") {
    std::mt19937_64 rng(31337);
    const std::string seed_text = R"([48,7,{"timeout":250},"com.example.add",[2,3.5,null,"\u00e9\ud83d\ude00",{"x":[true,false]}],{"k":"\u0000AQID"}])";
    std::vector<uint8_t> seed_cbor;
    REQUIRE(jsoncodec::to_cbor(seed_text, seed_cbor));

    for (int i = 0; i < 20000; ++i) {
        std::string text = seed_text;
        for (size_t n = 1 + rng() % 4; n > 0; --n) {
            switch (rng() % 3) {
                case 0: text[rng() % text.size()] = static_cast<char>(rng()); break;
                case 1: text.erase(rng() % text.size(), 1 + rng() % 3); break;
                default: text.insert(rng() % text.size(), 1, static_cast<char>(rng())); break;
            }
            if (text.empty()) text = "x";
        }
        std::vector<uint8_t> out;
        (void)jsoncodec::to_cbor(text, out);   // must not crash, hang or overrun

        auto data = seed_cbor;
        for (size_t n = 1 + rng() % 4; n > 0; --n) data[rng() % data.size()] = static_cast<uint8_t>(rng());
        data.resize(1 + rng() % data.size());
        std::string json_out;
        (void)jsoncodec::from_cbor(data, json_out);
    }
    for (int i = 0; i < 2000; ++i) {
        std::string noise(rng() % 64, 'x');
        for (auto& c : noise) c = static_cast<char>(rng());
        std::vector<uint8_t> out;
        (void)jsoncodec::to_cbor(noise, out);
    }
}

TEST_CASE("UTF-8 validation", "[json]") {
    CHECK(jsoncodec::valid_utf8(""));
    CHECK(jsoncodec::valid_utf8("plain ascii"));
    CHECK(jsoncodec::valid_utf8("\xC2\x80"));
    CHECK(jsoncodec::valid_utf8("\xDF\xBF"));
    CHECK(jsoncodec::valid_utf8("\xE0\xA0\x80"));
    CHECK(jsoncodec::valid_utf8("\xEF\xBF\xBF"));
    CHECK(jsoncodec::valid_utf8("\xF0\x90\x80\x80"));
    CHECK(jsoncodec::valid_utf8("\xF4\x8F\xBF\xBF"));
    CHECK_FALSE(jsoncodec::valid_utf8("\x80"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xC0\xAF"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xC1\xBF"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xE0\x80\x80"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xED\xA0\x80"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xF0\x80\x80\x80"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xF4\x90\x80\x80"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xF5\x80\x80\x80"));
    CHECK_FALSE(jsoncodec::valid_utf8("\xE2\x82"));
    CHECK_FALSE(jsoncodec::valid_utf8("a\xFFz"));
}

TEST_CASE("base64", "[json]") {
    for (const char* plain : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
        const std::string text{plain};
        const std::vector<uint8_t> bytes(text.begin(), text.end());
        const auto encoded = base64_encode(bytes);
        CHECK(base64_decode(encoded) == bytes);
        std::string unpadded = encoded;
        while (!unpadded.empty() && unpadded.back() == '=') unpadded.pop_back();
        CHECK(base64_decode(unpadded) == bytes);   // padding is optional on input
    }
    CHECK_FALSE(base64_decode("Zm9v!").has_value());
    CHECK_FALSE(base64_decode("Z").has_value());
    CHECK_FALSE(base64_decode("Zg=a").has_value());
    CHECK_FALSE(base64_decode("Zh==").has_value());   // non-zero leftover bits
    CHECK_FALSE(base64_decode("Zg===").has_value());
    CHECK_FALSE(base64_decode("Zm 9v").has_value());
}
