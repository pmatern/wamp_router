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
#include "include/msgpack.hpp"
#include "include/wamp_serializer.hpp"
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <random>

using namespace wamp;
using nlohmann::json;
using Bytes = std::vector<uint8_t>;

namespace {

std::expected<Bytes, std::error_code> to_cbor(const Bytes& msgpack) {
    Bytes out;
    if (auto r = msgpackcodec::to_cbor(msgpack, out); !r) return std::unexpected{r.error()};
    return out;
}

std::expected<Bytes, std::error_code> from_cbor(const Bytes& cbor) {
    std::string out;
    if (auto r = msgpackcodec::from_cbor(cbor, out); !r) return std::unexpected{r.error()};
    return Bytes(out.begin(), out.end());
}

msgpackcodec::Error error_of(const Bytes& msgpack) {
    auto r = to_cbor(msgpack);
    REQUIRE_FALSE(r.has_value());
    return static_cast<msgpackcodec::Error>(r.error().value());
}

Bytes cbor_of(const WampValue& v) {
    Bytes out;
    cbor::Writer w{out};
    fast::write_value(w, v);
    return out;
}

WampValue random_value(std::mt19937_64& rng, int depth) {
    switch (rng() % (depth >= 3 ? 8 : 10)) {
        case 0: return WampValue{};
        case 1: return WampValue{rng() % 2 == 0};
        case 2: return WampValue{static_cast<int64_t>(rng()) >> (rng() % 60)};
        case 3: {
            static const double specials[] = {0.0, -0.0, 0.5, 1.5, 2.0, 1e300, -1e-300, 0.1, 3.14159265358979, 5e-324};
            return WampValue{specials[rng() % 10]};
        }
        case 4: {
            std::string s(rng() % 40, 'x');
            for (auto& c : s) c = static_cast<char>(' ' + rng() % 90);
            return WampValue{s};
        }
        case 5: {
            WampBytes b(rng() % 300);
            for (auto& x : b) x = static_cast<uint8_t>(rng());
            return WampValue{b};
        }
        case 6: return WampValue{static_cast<int64_t>(rng() % 200) - 100};
        case 7: return WampValue{std::string{"\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80"}};
        case 8: {
            WampList list;
            for (size_t n = rng() % 20; n > 0; --n) list.push_back(random_value(rng, depth + 1));
            return WampValue{list};
        }
        default: {
            WampDict dict;
            for (size_t n = rng() % 20; n > 0; --n) dict["k" + std::to_string(rng() % 100)] = random_value(rng, depth + 1);
            return WampValue{dict};
        }
    }
}

}  // namespace

TEST_CASE("MessagePack values convert to the expected CBOR", "[msgpack]") {
    auto check = [](const Bytes& msgpack, const Bytes& expected) {
        auto cbor = to_cbor(msgpack);
        REQUIRE(cbor.has_value());
        CHECK(*cbor == expected);
    };
    check({0xc0}, {0xf6});                         // nil
    check({0xc2}, {0xf4});                         // false
    check({0xc3}, {0xf5});                         // true
    check({0x00}, {0x00});                         // positive fixint
    check({0x7f}, {0x18, 0x7f});
    check({0xff}, {0x20});                         // negative fixint -1
    check({0xe0}, {0x38, 0x1f});                   // -32
    check({0xcc, 0xff}, {0x18, 0xff});             // uint8
    check({0xcd, 0x01, 0x00}, {0x19, 0x01, 0x00}); // uint16
    check({0xce, 0x00, 0x01, 0x00, 0x00}, {0x1a, 0x00, 0x01, 0x00, 0x00});
    check({0xcf, 0, 0, 0, 1, 0, 0, 0, 0}, {0x1b, 0, 0, 0, 1, 0, 0, 0, 0});
    check({0xd0, 0x80}, {0x38, 0x7f});             // int8 -128
    check({0xd1, 0xff, 0x7f}, {0x38, 0x80});       // int16 -129 (CBOR uses the shortest form)
    check({0xd2, 0xff, 0xff, 0x7f, 0xff}, {0x39, 0x80, 0x00});   // int32 -32769
    check({0xd3, 0x80, 0, 0, 0, 0, 0, 0, 0}, {0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});   // INT64_MIN
    check({0xa3, 'a', 'b', 'c'}, {0x63, 'a', 'b', 'c'});                 // fixstr
    check({0xd9, 0x01, 'x'}, {0x61, 'x'});                                // str8 (non-minimal is fine)
    check({0xc4, 0x02, 0x01, 0x02}, {0x42, 0x01, 0x02});                  // bin8
    check({0x92, 0x01, 0xc0}, {0x82, 0x01, 0xf6});                        // fixarray [1, nil]
    check({0x81, 0xa1, 'k', 0xc3}, {0xa1, 0x61, 'k', 0xf5});              // fixmap {"k": true}
    check({0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0}, {0xfa, 0x3f, 0xc0, 0, 0});   // float64 1.5 (the CBOR writer uses float32 when exact)
    check({0xca, 0x3f, 0xc0, 0, 0}, {0xfa, 0x3f, 0xc0, 0, 0});                           // float32 1.5 widened
    check({0xdc, 0x00, 0x01, 0x05}, {0x81, 0x05});                        // array16
    check({0xde, 0x00, 0x01, 0xa1, 'a', 0x01}, {0xa1, 0x61, 'a', 0x01});  // map16

    // uint64 above INT64_MAX has no CBOR int in this router's value model: a double, as in the JSON adapter
    auto big = to_cbor({0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    REQUIRE(big.has_value());
    CHECK((*big)[0] >= 0xf9);   // a float (2^64 is exact in float32)
}

TEST_CASE("Invalid MessagePack is rejected with a specific error", "[msgpack]") {
    using E = msgpackcodec::Error;
    CHECK(error_of({}) == E::SYNTAX);
    CHECK(error_of({0xc1}) == E::SYNTAX);                       // never used
    CHECK(error_of({0xcd, 0x01}) == E::SYNTAX);                 // truncated uint16
    CHECK(error_of({0xa5, 'a', 'b'}) == E::SYNTAX);             // str shorter than declared
    CHECK(error_of({0x92, 0x01}) == E::SYNTAX);                 // array missing an element
    CHECK(error_of({0xdd, 0xff, 0xff, 0xff, 0xff}) == E::SYNTAX);   // declared 4G elements, no data: no big allocation
    CHECK(error_of({0xdf, 0xff, 0xff, 0xff, 0xff}) == E::SYNTAX);
    CHECK(error_of({0xdb, 0xff, 0xff, 0xff, 0xff}) == E::SYNTAX);
    CHECK(error_of({0xa2, 0xc3, 0x28}) == E::UTF8);             // invalid UTF-8
    CHECK(error_of({0xd4, 0x01, 0x02}) == E::UNSUPPORTED);      // fixext
    CHECK(error_of({0xc7, 0x01, 0x05, 0x00}) == E::UNSUPPORTED);// ext 8
    CHECK(error_of({0x81, 0x01, 0x02}) == E::UNSUPPORTED);      // integer map key
    CHECK(error_of({0x01, 0x02}) == E::TRAILING);

    Bytes deep(200, 0x91);   // 200 nested one-element arrays
    deep.push_back(0x00);
    CHECK(error_of(deep) == E::DEPTH);
}

TEST_CASE("CBOR converts to MessagePack", "[msgpack]") {
    auto check = [](const Bytes& cbor, const Bytes& expected) {
        auto mp = from_cbor(cbor);
        REQUIRE(mp.has_value());
        CHECK(*mp == expected);
    };
    check({0xf6}, {0xc0});
    check({0xf7}, {0xc0});                                // undefined -> nil
    check({0xf5}, {0xc3});
    check({0x17}, {0x17});
    check({0x18, 0x80}, {0xcc, 0x80});
    check({0x19, 0x01, 0x00}, {0xcd, 0x01, 0x00});
    check({0x1a, 0x00, 0x01, 0x00, 0x00}, {0xce, 0x00, 0x01, 0x00, 0x00});
    check({0x1b, 0, 0, 0, 1, 0, 0, 0, 0}, {0xcf, 0, 0, 0, 1, 0, 0, 0, 0});
    check({0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    check({0x20}, {0xff});                                // -1
    check({0x38, 0x1f}, {0xe0});                          // -32
    check({0x38, 0x20}, {0xd0, 0xdf});                    // -33
    check({0x39, 0x00, 0x80}, {0xd1, 0xff, 0x7f});        // -129
    check({0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xd3, 0x80, 0, 0, 0, 0, 0, 0, 0});
    check({0x41, 0xaa}, {0xc4, 0x01, 0xaa});              // byte string -> bin8
    check({0x61, 'x'}, {0xa1, 'x'});
    check({0xf9, 0x3e, 0x00}, {0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0});   // half-precision 1.5 -> float64
    check({0xc1, 0x1a, 0x00, 0x00, 0x00, 0x05}, {0x05});                // a tag is dropped
    check({0x82, 0x01, 0xf6}, {0x92, 0x01, 0xc0});
    check({0xa1, 0x61, 'k', 0xf5}, {0x81, 0xa1, 'k', 0xc3});

    // NaN and infinity are representable in MessagePack (unlike JSON)
    auto nan = from_cbor({0xf9, 0x7e, 0x00});
    REQUIRE(nan.has_value());
    CHECK((*nan)[0] == 0xcb);

    // long strings and big arrays use the wider headers
    Bytes long_text{0x78, 40};
    long_text.insert(long_text.end(), 40, 'a');
    auto mp = from_cbor(long_text);
    REQUIRE(mp.has_value());
    CHECK(((*mp)[0] == 0xd9 && (*mp)[1] == 40));
    Bytes big_array{0x98, 20};
    big_array.insert(big_array.end(), 20, 0x01);
    mp = from_cbor(big_array);
    REQUIRE(mp.has_value());
    CHECK(((*mp)[0] == 0xdc && (*mp)[2] == 20));

    // invalid inputs
    CHECK_FALSE(from_cbor({0x18}).has_value());                    // truncated
    CHECK_FALSE(from_cbor({0xa1, 0x01, 0x02}).has_value());        // map key that is not text
    CHECK_FALSE(from_cbor({0x62, 0xc3, 0x28}).has_value());        // invalid UTF-8
    CHECK_FALSE(from_cbor({0x01, 0x02}).has_value());              // trailing data
}

TEST_CASE("Indefinite-length CBOR (as the JSON adapter writes it) becomes definite-length MessagePack", "[msgpack]") {
    Bytes cbor;
    REQUIRE(jsoncodec::to_cbor(R"([48,7,{"a":[1,2,{"b":null}]},"x"])", cbor));
    REQUIRE(cbor[0] == 0x9f);   // indefinite array
    auto mp = from_cbor(cbor);
    REQUIRE(mp.has_value());
    CHECK(json::from_msgpack(*mp) == json::parse(R"([48,7,{"a":[1,2,{"b":null}]},"x"])"));
    CHECK((*mp)[0] == 0x94);   // fixarray of four
}

TEST_CASE("MessagePack and CBOR agree with nlohmann on random payloads", "[msgpack][oracle]") {
    std::mt19937_64 rng(4242);
    for (int i = 0; i < 2000; ++i) {
        const WampValue tree = random_value(rng, 0);
        const Bytes cbor = cbor_of(tree);

        // our MessagePack for the tree reads in nlohmann as the same value as the tree's CBOR does
        auto mp = from_cbor(cbor);
        REQUIRE(mp.has_value());
        REQUIRE(json::from_msgpack(*mp) == json::from_cbor(cbor));

        // and our reading of it gives the original tree back, types included
        auto back = to_cbor(*mp);
        REQUIRE(back.has_value());
        Bytes round = *back;
        cbor::Reader r{round};
        REQUIRE(fast::read_value(r) == tree);

        // nlohmann's MessagePack for the same value reads as the same tree (it picks the smallest encodings)
        const Bytes theirs = json::to_msgpack(json::from_cbor(cbor));
        auto from_theirs = to_cbor(theirs);
        REQUIRE(from_theirs.has_value());
        Bytes theirs_cbor = *from_theirs;
        cbor::Reader r2{theirs_cbor};
        REQUIRE(fast::read_value(r2) == tree);
    }
}

TEST_CASE("WAMP messages survive CBOR -> MessagePack -> CBOR", "[msgpack]") {
    const WampList args{int64_t{2}, 3.5, nullptr, std::string{"\xC3\xA9"}, WampBytes{1, 2, 3}, WampList{true}};
    const WampDict kwargs{{"k", WampDict{{"n", int64_t{-70000}}}}};
    const auto publish = serialize_publish(PublishMessage{7, WampDict{{"acknowledge", true}}, "com.example.t", args, kwargs});
    auto mp = from_cbor(publish);
    REQUIRE(mp.has_value());
    auto back = to_cbor(*mp);
    REQUIRE(back.has_value());
    auto decoded = deserialize_publish(*back);
    REQUIRE(decoded.has_value());
    CHECK(decoded->request_id == 7);
    CHECK(decoded->topic == "com.example.t");
    CHECK(decoded->arguments == args);
    CHECK(decoded->arguments_kw == kwargs);
}

TEST_CASE("The MessagePack transcoder survives garbage and mutated input", "[msgpack][fuzz]") {
    std::mt19937_64 rng(777);
    const auto seed_cbor = serialize_publish(PublishMessage{
        1, {}, "com.example.t", WampList{int64_t{1}, 2.5, std::string{"text"}, WampBytes{9, 8}}, WampDict{{"a", int64_t{1}}}});
    auto seed = from_cbor(seed_cbor);
    REQUIRE(seed.has_value());

    for (int i = 0; i < 20000; ++i) {
        Bytes data = *seed;
        for (size_t n = 1 + rng() % 4; n > 0; --n) data[rng() % data.size()] = static_cast<uint8_t>(rng());
        data.resize(1 + rng() % data.size());
        Bytes out;
        (void)msgpackcodec::to_cbor(data, out);   // must not crash, hang or overrun

        Bytes cbor = seed_cbor;
        for (size_t n = 1 + rng() % 4; n > 0; --n) cbor[rng() % cbor.size()] = static_cast<uint8_t>(rng());
        cbor.resize(1 + rng() % cbor.size());
        std::string mp_out;
        (void)msgpackcodec::from_cbor(cbor, mp_out);
    }
    for (int i = 0; i < 2000; ++i) {
        Bytes noise(rng() % 64);
        for (auto& b : noise) b = static_cast<uint8_t>(rng());
        Bytes out;
        (void)msgpackcodec::to_cbor(noise, out);
    }
}
