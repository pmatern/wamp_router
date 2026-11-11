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

// The direct CBOR codec (include/cbor.hpp and the fast:: functions in wamp_serializer.hpp) is checked
// against nlohmann::json, which produced and consumed every message before it existed.

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <cstdint>
#include <random>
#include "include/cbor.hpp"
#include "include/wamp_serializer.hpp"

using namespace wamp;
using nlohmann::json;

namespace {

std::vector<uint8_t> bytes(std::initializer_list<int> values) {
    std::vector<uint8_t> out;
    for (int v : values) out.push_back(static_cast<uint8_t>(v));
    return out;
}

// Shortest-form CBOR of `value` as nlohmann writes it
std::vector<uint8_t> reference(const json& value) {
    return json::to_cbor(value);
}

const WampList kArgs{std::string{"hello"}, int64_t{42}, int64_t{-7}, true, std::string{}};
const WampDict kKw{{"count", int64_t{3}}, {"unit", std::string{"ms"}}, {"flag", false},
                   {"nested", std::unordered_map<std::string, std::string>{{"a", "b"}}}};

json list_json() { return json::array({"hello", 42, -7, true, ""}); }
json kw_json() {
    return json::object({{"count", 3}, {"unit", "ms"}, {"flag", false}, {"nested", json::object({{"a", "b"}})}});
}

}  // namespace

TEST_CASE("cbor::Writer writes shortest-form integers like nlohmann", "[cbor]") {
    const uint64_t values[] = {0, 1, 23, 24, 25, 255, 256, 65535, 65536, 4294967295ULL, 4294967296ULL,
                               9007199254740993ULL, UINT64_MAX};
    for (uint64_t v : values) {
        std::vector<uint8_t> out;
        cbor::Writer{out}.write_uint(v);
        REQUIRE(out == reference(json(v)));
    }
    const int64_t signed_values[] = {0, -1, -24, -25, -256, -257, -65536, -65537, INT64_MIN, INT64_MAX, 1000000};
    for (int64_t v : signed_values) {
        std::vector<uint8_t> out;
        cbor::Writer{out}.write_int(v);
        REQUIRE(out == reference(json(v)));
    }
}

TEST_CASE("cbor::Reader reads integers, strings and containers", "[cbor]") {
    SECTION("integers round trip over the full range") {
        for (int64_t v : {int64_t{0}, int64_t{23}, int64_t{24}, int64_t{-1}, int64_t{-25}, int64_t{70000},
                          INT64_MAX, INT64_MIN}) {
            std::vector<uint8_t> out;
            cbor::Writer{out}.write_int(v);
            cbor::Reader r{out};
            REQUIRE(r.read_int() == v);
            REQUIRE(r.at_end());
        }
        std::vector<uint8_t> out;
        cbor::Writer{out}.write_uint(UINT64_MAX);
        cbor::Reader r{out};
        REQUIRE(r.read_uint() == UINT64_MAX);
    }

    SECTION("type mismatches throw") {
        auto text = reference(json("x"));
        REQUIRE_THROWS_AS(cbor::Reader{text}.read_uint(), cbor::DecodeError);
        auto number = reference(json(5));
        REQUIRE_THROWS_AS(cbor::Reader{number}.read_text(), cbor::DecodeError);
        auto negative = reference(json(-5));
        REQUIRE_THROWS_AS(cbor::Reader{negative}.read_uint(), cbor::DecodeError);
        REQUIRE_THROWS_AS(cbor::Reader{number}.read_array(), cbor::DecodeError);
    }

    SECTION("floats are read as truncated integers, as the JSON reader did") {
        REQUIRE(cbor::Reader{reference(json(3.75))}.read_int() == 3);
        REQUIRE(cbor::Reader{bytes({0xF9, 0x3C, 0x00})}.read_int() == 1);        // half precision 1.0
        REQUIRE(cbor::Reader{bytes({0xFA, 0x40, 0x49, 0x0F, 0xDB})}.read_int() == 3);  // float 3.14159
        REQUIRE_THROWS_AS(cbor::Reader{bytes({0xF9, 0x7C, 0x00})}.read_int(), cbor::DecodeError);  // infinity
    }

    SECTION("tags are transparent") {
        // tag 1 (epoch time) around the integer 5
        REQUIRE(cbor::Reader{bytes({0xC1, 0x05})}.read_int() == 5);
    }

    SECTION("indefinite-length arrays and maps") {
        auto data = bytes({0x9F, 0x01, 0x02, 0xFF});  // [_ 1, 2]
        cbor::Reader r{data};
        auto c = r.read_array();
        int sum = 0;
        while (r.next(c)) sum += static_cast<int>(r.read_int());
        REQUIRE(sum == 3);
        REQUIRE(r.at_end());

        auto map = bytes({0xBF, 0x61, 'a', 0x01, 0xFF});  // {_ "a": 1}
        cbor::Reader mr{map};
        auto mc = mr.read_map();
        REQUIRE(mr.next(mc));
        REQUIRE(mr.read_text() == "a");
        REQUIRE(mr.read_int() == 1);
        REQUIRE_FALSE(mr.next(mc));
    }

    SECTION("skip steps over nested values") {
        auto data = reference(json::array({json::object({{"k", json::array({1, 2, json::object()})}}), "after"}));
        cbor::Reader r{data};
        auto c = r.read_array();
        REQUIRE(r.next(c));
        r.skip();
        REQUIRE(r.next(c));
        REQUIRE(r.read_text() == "after");
    }

    SECTION("hostile headers are rejected without large allocations or loops") {
        // array claiming 2^32 elements in a 5 byte message
        REQUIRE_THROWS_AS(cbor::Reader{bytes({0x9A, 0xFF, 0xFF, 0xFF, 0xFF})}.read_array(), cbor::DecodeError);
        // string longer than the input
        REQUIRE_THROWS_AS(cbor::Reader{bytes({0x79, 0xFF, 0xFF, 'a'})}.read_text(), cbor::DecodeError);
        // deeply nested arrays
        std::vector<uint8_t> deep(1000, 0x81);
        deep.push_back(0x00);
        REQUIRE_THROWS_AS(cbor::Reader{deep}.skip(), cbor::DecodeError);
    }
}

TEST_CASE("Hot-path serializers produce the bytes nlohmann produced", "[cbor][serializer]") {
    SECTION("SUBSCRIBE / SUBSCRIBED / UNSUBSCRIBE(D)") {
        REQUIRE(serialize_subscribe(SubscribeMessage{300, {}, "com.example.topic"}) ==
                reference(json::array({32, 300, json::object(), "com.example.topic"})));
        REQUIRE(serialize_subscribed(SubscribedMessage{7, 1ULL << 40}) ==
                reference(json::array({33, 7, 1ULL << 40})));
        REQUIRE(serialize_unsubscribe(UnsubscribeMessage{8, 9}) == reference(json::array({34, 8, 9})));
        REQUIRE(serialize_unsubscribed(UnsubscribedMessage{8}) == reference(json::array({35, 8})));
    }

    SECTION("PUBLISH / PUBLISHED / EVENT, with and without payload") {
        REQUIRE(serialize_publish(PublishMessage{1, {{"acknowledge", true}}, "t"}) ==
                reference(json::array({16, 1, json::object({{"acknowledge", true}}), "t"})));
        REQUIRE(serialize_publish(PublishMessage{1, {}, "t", kArgs, {}}) ==
                reference(json::array({16, 1, json::object(), "t", list_json()})));
        REQUIRE(serialize_publish(PublishMessage{1, {}, "t", kArgs, kKw}) ==
                reference(json::array({16, 1, json::object(), "t", list_json(), kw_json()})));
        // kwargs without positional args still need the (empty) list in front
        REQUIRE(serialize_publish(PublishMessage{1, {}, "t", {}, kKw}) ==
                reference(json::array({16, 1, json::object(), "t", json::array(), kw_json()})));
        REQUIRE(serialize_published(PublishedMessage{5, 99}) == reference(json::array({17, 5, 99})));
        REQUIRE(serialize_event(EventMessage{4, 5, {}}) == reference(json::array({36, 4, 5, json::object()})));
        REQUIRE(serialize_event(EventMessage{4, 5, {}, kArgs, kKw}) ==
                reference(json::array({36, 4, 5, json::object(), list_json(), kw_json()})));
    }

    SECTION("REGISTER / REGISTERED / UNREGISTER(ED)") {
        REQUIRE(serialize_register(RegisterMessage{2, {}, "p"}) ==
                reference(json::array({64, 2, json::object(), "p"})));
        REQUIRE(serialize_registered(RegisteredMessage{2, 3}) == reference(json::array({65, 2, 3})));
        REQUIRE(serialize_unregister(UnregisterMessage{2, 3}) == reference(json::array({66, 2, 3})));
        REQUIRE(serialize_unregistered(UnregisteredMessage{2}) == reference(json::array({67, 2})));
    }

    SECTION("CALL / INVOCATION / YIELD / RESULT / INTERRUPT") {
        REQUIRE(serialize_call(CallMessage{1, {{"timeout", int64_t{500}}}, "p", kArgs, kKw}) ==
                reference(json::array({48, 1, json::object({{"timeout", 500}}), "p", list_json(), kw_json()})));
        REQUIRE(serialize_invocation(InvocationMessage{6, 7, {}, kArgs, {}}) ==
                reference(json::array({68, 6, 7, json::object(), list_json()})));
        REQUIRE(serialize_yield(YieldMessage{6, {}}) == reference(json::array({70, 6, json::object(), json::array()})));
        REQUIRE(serialize_yield(YieldMessage{6, {}, kArgs, kKw}) ==
                reference(json::array({70, 6, json::object(), list_json(), kw_json()})));
        REQUIRE(serialize_result(ResultMessage{1, {}, kArgs, {}}) ==
                reference(json::array({50, 1, json::object(), list_json()})));
        REQUIRE(serialize_result(ResultMessage{1, {}}) == reference(json::array({50, 1, json::object(), json::array()})));
        REQUIRE(serialize_interrupt(InterruptMessage{6, {{"mode", std::string{"killnowait"}}}}) ==
                reference(json::array({69, 6, json::object({{"mode", "killnowait"}})})));
    }

    SECTION("ERROR") {
        auto err = ErrorMessage::create_no_such_procedure(5, "p.q");
        REQUIRE(serialize_error(err) ==
                reference(json::array({8, 48, 5, json::object({{"message", "No such procedure: p.q"}}),
                                       "wamp.error.no_such_procedure"})));
        REQUIRE(serialize_error(ErrorMessage{MessageType::CALL, 5, {}, "e.x"}) ==
                reference(json::array({8, 48, 5, json::object(), "e.x"})));
        ErrorMessage with_payload{MessageType::CALL, 5, {{"k", int64_t{1}}}, "my.error", kArgs, kKw};
        REQUIRE(serialize_error(with_payload) ==
                reference(json::array({8, 48, 5, json::object({{"k", 1}}), "my.error", list_json(), kw_json()})));
    }
}

TEST_CASE("Session handshake messages produce the bytes nlohmann produced", "[cbor][serializer]") {
    SECTION("HELLO") {
        HelloMessage hello = HelloMessage::create_client("realm1");
        hello.authid = "alice";
        hello.authmethods = std::vector<std::string>{"cryptosign", "ticket"};
        const auto ppt_role = json::object({{"features", json::object({{"payload_passthru_mode", true}})}});
        REQUIRE(serialize_hello(hello) ==
                reference(json::array({1, "realm1",
                                       json::object({{"authid", "alice"},
                                                     {"authmethods", json::array({"cryptosign", "ticket"})},
                                                     {"roles", json::object({{"caller", json::object({{"features", json::object({{"call_canceling", true}, {"payload_passthru_mode", true}})}})},
                                                                             {"callee", json::object({{"features", json::object({{"pattern_based_registration", true}, {"payload_passthru_mode", true}})}})},
                                                                             {"publisher", ppt_role},
                                                                             {"subscriber", json::object({{"features", json::object({{"pattern_based_subscription", true}, {"payload_passthru_mode", true}})}})}})}})})));
        // minimal HELLO: no authid / authmethods, no roles
        REQUIRE(serialize_hello(HelloMessage{"r"}) ==
                reference(json::array({1, "r", json::object({{"roles", json::object()}})})));
    }

    SECTION("WELCOME") {
        auto welcome = WelcomeMessage::create_router(4242, "realm1");
        welcome.authid = "alice";
        welcome.authrole = "user";
        welcome.authmethod = "cryptosign";
        REQUIRE(serialize_welcome(welcome) ==
                reference(json::array({2, 4242,
                                       json::object({{"authid", "alice"}, {"authrole", "user"},
                                                     {"authmethod", "cryptosign"},
                                                     {"roles", json::object({{"broker", json::object({{"features", {{"payload_passthru_mode", true}, {"pattern_based_subscription", true}}}})},
                                                                             {"dealer", json::object({{"features", {{"call_canceling", true}, {"pattern_based_registration", true}, {"payload_passthru_mode", true}}}})}})}})})));
    }

    SECTION("GOODBYE / ABORT / CHALLENGE / AUTHENTICATE") {
        REQUIRE(serialize_goodbye(GoodbyeMessage{{}, "wamp.close.normal"}) ==
                reference(json::array({6, json::object(), "wamp.close.normal"})));
        REQUIRE(serialize_abort(AbortMessage{{}, "wamp.error.not_authorized"}) ==
                reference(json::array({3, json::object(), "wamp.error.not_authorized"})));
        REQUIRE(serialize_challenge(ChallengeMessage{"cryptosign", {{"challenge", "ab12"}, {"channel_binding", "x"}}}) ==
                reference(json::array({4, "cryptosign", json::object({{"challenge", "ab12"}, {"channel_binding", "x"}})})));
        REQUIRE(serialize_authenticate(AuthenticateMessage{"sig", {}}) ==
                reference(json::array({5, "sig", json::object()})));
    }
}

TEST_CASE("Session handshake deserializers read nlohmann-produced CBOR", "[cbor][serializer]") {
    auto hello = deserialize_hello(reference(json::array({1, "realm1",
        json::object({{"authid", "alice"}, {"authmethods", json::array({"cryptosign", 7, "ticket"})},
                      {"roles", json::object({{"caller", json::object({{"features", json::object()}})}})},
                      {"agent", "ignored"}, {"transport", json::object({{"a", 1}})}})})));
    REQUIRE(hello.has_value());
    REQUIRE(hello->realm == "realm1");
    REQUIRE(hello->authid == std::optional<std::string>{"alice"});
    REQUIRE(hello->authmethods == std::optional<std::vector<std::string>>{{"cryptosign", "ticket"}});
    REQUIRE(hello->roles.size() == 1);
    REQUIRE(hello->roles[0].name == "caller");

    // details that are not a map, or a wrongly typed authid, are ignored as before
    auto odd = deserialize_hello(reference(json::array({1, "r", json::array()})));
    REQUIRE(odd.has_value());
    REQUIRE_FALSE(odd->authid.has_value());
    auto wrong = deserialize_hello(reference(json::array({1, "r", json::object({{"authid", 5}, {"authmethods", json::array()}})})));
    REQUIRE(wrong.has_value());
    REQUIRE_FALSE(wrong->authid.has_value());
    REQUIRE_FALSE(wrong->authmethods.has_value());

    auto welcome = deserialize_welcome(reference(json::array({2, 99,
        json::object({{"authid", "bob"}, {"authrole", "admin"}, {"authmethod", "cryptosign"},
                      {"roles", json::object({{"broker", json::object()}})}})})));
    REQUIRE(welcome.has_value());
    REQUIRE(welcome->session_id == 99);
    REQUIRE(welcome->authrole == std::optional<std::string>{"admin"});
    REQUIRE(welcome->roles.size() == 1);

    REQUIRE(deserialize_goodbye(reference(json::array({6, json::object(), "bye"})))->reason == "bye");
    REQUIRE(deserialize_abort(reference(json::array({3, json::object({{"message", "x"}}), "why"})))->reason == "why");

    auto challenge = deserialize_challenge(reference(json::array({4, "cryptosign",
        json::object({{"challenge", "ab"}, {"n", 5}})})));
    REQUIRE(challenge.has_value());
    REQUIRE(challenge->extra == std::map<std::string, std::string>{{"challenge", "ab"}});  // non-text values dropped

    auto auth = deserialize_authenticate(reference(json::array({5, "sig", json::object()})));
    REQUIRE(auth.has_value());
    REQUIRE(auth->signature == "sig");

    // too short / wrong type
    REQUIRE(deserialize_hello(reference(json::array({1, "r"}))).error() == SerializationError::MALFORMED_MESSAGE);
    REQUIRE(deserialize_welcome(reference(json::array({2, "x", json::object()}))).error() ==
            SerializationError::CBOR_DECODE_ERROR);
}

TEST_CASE("Hot-path deserializers read nlohmann-produced CBOR", "[cbor][serializer]") {
    SECTION("integers of every width in id fields") {
        for (uint64_t id : {0ULL, 23ULL, 24ULL, 255ULL, 256ULL, 65536ULL, 4294967296ULL, (1ULL << 53) - 1}) {
            auto data = reference(json::array({33, id, id}));
            auto msg = deserialize_subscribed(data);
            REQUIRE(msg.has_value());
            REQUIRE(msg->request_id == id);
            REQUIRE(msg->subscription_id == id);
        }
    }

    SECTION("CALL with arguments, kwargs and options") {
        auto data = reference(json::array({48, 9, json::object({{"timeout", 250}}), "p", list_json(), kw_json()}));
        auto msg = deserialize_call(data);
        REQUIRE(msg.has_value());
        REQUIRE(msg->request_id == 9);
        REQUIRE(msg->procedure == "p");
        REQUIRE(std::get<int64_t>(msg->options.at("timeout")) == 250);
        REQUIRE(msg->arguments == kArgs);
        REQUIRE(msg->arguments_kw == kKw);
    }

    SECTION("every kind of value in the payload is kept, in place") {
        // null, a nested array, a float and bytes inside Arguments; a null and nested containers inside ArgumentsKw
        auto data = reference(json::array({48, 1, json::object(), "p",
                                           json::array({"a", nullptr, json::array({1}), 2.9, true}),
                                           json::object({{"x", nullptr}, {"y", json::array()}, {"z", 1}})}));
        auto msg = deserialize_call(data);
        REQUIRE(msg.has_value());
        REQUIRE(msg->arguments.size() == 5);
        CHECK(std::get<std::string>(msg->arguments[0]) == "a");
        CHECK(std::holds_alternative<std::nullptr_t>(msg->arguments[1]));
        CHECK(std::get<WampList>(msg->arguments[2]) == WampList{int64_t{1}});
        CHECK(std::get<double>(msg->arguments[3]) == 2.9);
        CHECK(std::get<bool>(msg->arguments[4]) == true);
        REQUIRE(msg->arguments_kw.size() == 3);
        CHECK(std::holds_alternative<std::nullptr_t>(msg->arguments_kw.at("x")));
        CHECK(std::get<WampList>(msg->arguments_kw.at("y")).empty());
        CHECK(std::get<int64_t>(msg->arguments_kw.at("z")) == 1);
    }

    SECTION("PUBLISH keeps only the boolean options it understands") {
        auto data = reference(json::array({16, 1,
                                           json::object({{"acknowledge", true}, {"exclude_me", false},
                                                         {"retain", true}, {"acknowledge2", 1}}),
                                           "t"}));
        auto msg = deserialize_publish(data);
        REQUIRE(msg.has_value());
        REQUIRE(msg->options.size() == 2);
        REQUIRE(std::get<bool>(msg->options.at("acknowledge")) == true);
        REQUIRE(std::get<bool>(msg->options.at("exclude_me")) == false);
    }

    SECTION("YIELD / RESULT / EVENT / INVOCATION / ERROR payloads") {
        auto yield = deserialize_yield(reference(json::array({70, 4, json::object(), list_json(), kw_json()})));
        REQUIRE(yield.has_value());
        REQUIRE(yield->invocation_id == 4);
        REQUIRE(yield->arguments == kArgs);
        REQUIRE(yield->arguments_kw == kKw);

        auto bare_yield = deserialize_yield(reference(json::array({70, 4, json::object()})));
        REQUIRE(bare_yield.has_value());
        REQUIRE(bare_yield->arguments.empty());

        auto result = deserialize_result(reference(json::array({50, 4, json::object(), list_json()})));
        REQUIRE(result.has_value());
        REQUIRE(result->arguments == kArgs);

        auto event = deserialize_event(reference(json::array({36, 1, 2, json::object({{"topic", "t"}}), list_json()})));
        REQUIRE(event.has_value());
        REQUIRE(event->arguments == kArgs);
        REQUIRE(std::get<std::string>(event->details.at("topic")) == "t");

        auto inv = deserialize_invocation(reference(json::array({68, 1, 2, json::object(), list_json(), kw_json()})));
        REQUIRE(inv.has_value());
        REQUIRE(inv->arguments_kw == kKw);

        auto err = deserialize_error(reference(json::array({8, 48, 3, json::object(), "e.x", list_json()})));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->error_uri == "e.x");
        REQUIRE(err->arguments == kArgs);
    }

    SECTION("indefinite-length framing from other CBOR libraries") {
        // [_ 32, 1, {}, "t"]
        auto data = bytes({0x9F, 0x18, 0x20, 0x01, 0xA0, 0x61, 't', 0xFF});
        auto msg = deserialize_subscribe(data);
        REQUIRE(msg.has_value());
        REQUIRE(msg->topic == "t");
        REQUIRE(get_message_type_from_cbor(data) == MessageType::SUBSCRIBE);
    }

    SECTION("errors map to the same codes as before") {
        auto code = [](const auto& result) { return result.error(); };
        // not an array
        REQUIRE(code(deserialize_call(reference(json::object()))) == SerializationError::MALFORMED_MESSAGE);
        // too short
        REQUIRE(code(deserialize_call(reference(json::array({48, 1})))) == SerializationError::MALFORMED_MESSAGE);
        REQUIRE(code(deserialize_call(reference(json::array()))) == SerializationError::MALFORMED_MESSAGE);
        // wrong message type
        REQUIRE(code(deserialize_call(reference(json::array({49, 1, json::object(), "p"})))) ==
                SerializationError::INVALID_MESSAGE_TYPE);
        // wrong field type
        REQUIRE(code(deserialize_call(reference(json::array({48, "x", json::object(), "p"})))) ==
                SerializationError::CBOR_DECODE_ERROR);
        REQUIRE(code(deserialize_call(reference(json::array({48, 1, json::object(), 5})))) ==
                SerializationError::CBOR_DECODE_ERROR);
        // truncated
        auto cut = reference(json::array({48, 1, json::object(), "procedure"}));
        cut.resize(cut.size() - 3);
        REQUIRE(code(deserialize_call(cut)) == SerializationError::CBOR_DECODE_ERROR);
        // empty input
        REQUIRE_FALSE(get_message_type_from_cbor({}).has_value());
    }
}

TEST_CASE("Serialize/deserialize round-trips random payloads", "[cbor][serializer]") {
    std::mt19937_64 rng(12345);
    auto random_text = [&] {
        std::string s(rng() % 40, 'a');
        for (auto& c : s) c = static_cast<char>('a' + rng() % 26);
        return s;
    };
    auto random_int = [&]() -> int64_t {
        switch (rng() % 4) {
            case 0: return static_cast<int64_t>(rng() % 30);
            case 1: return static_cast<int64_t>(rng() % 70000) - 100;
            case 2: return static_cast<int64_t>(rng());
            default: return -static_cast<int64_t>(rng() >> 2);
        }
    };

    for (int i = 0; i < 500; ++i) {
        WampList args;
        for (size_t n = rng() % 12; n > 0; --n) {
            switch (rng() % 3) {
                case 0: args.emplace_back(random_text()); break;
                case 1: args.emplace_back(random_int()); break;
                default: args.emplace_back(rng() % 2 == 0); break;
            }
        }
        WampDict kw;
        for (size_t n = rng() % 5; n > 0; --n) {
            switch (rng() % 3) {
                case 0: kw[random_text()] = random_text(); break;
                case 1: kw[random_text()] = random_int(); break;
                default: kw[random_text()] = (rng() % 2 == 0); break;
            }
        }
        const uint64_t id = rng();

        auto call = deserialize_call(serialize_call(CallMessage{id, {}, random_text(), args, kw}));
        REQUIRE(call.has_value());
        // an empty Arguments list with non-empty kwargs is written and read back as empty
        REQUIRE(call->request_id == id);
        REQUIRE(call->arguments == args);
        REQUIRE(call->arguments_kw == kw);

        auto result = deserialize_result(serialize_result(ResultMessage{id, {}, args, kw}));
        REQUIRE(result.has_value());
        REQUIRE(result->arguments == args);
        REQUIRE(result->arguments_kw == kw);

        // the previous implementation must read what the new one writes, and vice versa
        auto via_json = json::from_cbor(serialize_event(EventMessage{id, id + 1, {}, args, kw}));
        REQUIRE(via_json[1].get<uint64_t>() == id);
    }
}

TEST_CASE("Deserializers survive truncated and corrupted input", "[cbor][serializer][fuzz]") {
    const std::vector<std::vector<uint8_t>> corpus = {
        serialize_subscribe(SubscribeMessage{1, {}, "com.example.topic"}),
        serialize_publish(PublishMessage{2, {{"acknowledge", true}}, "t", kArgs, kKw}),
        serialize_event(EventMessage{3, 4, {}, kArgs, kKw}),
        serialize_register(RegisterMessage{5, {}, "p"}),
        serialize_call(CallMessage{6, {{"timeout", int64_t{9}}}, "p", kArgs, kKw}),
        serialize_invocation(InvocationMessage{7, 8, {}, kArgs, kKw}),
        serialize_yield(YieldMessage{9, {}, kArgs, kKw}),
        serialize_result(ResultMessage{10, {}, kArgs, kKw}),
        serialize_error(ErrorMessage{MessageType::CALL, 11, {{"k", int64_t{1}}}, "e", kArgs, kKw}),
        serialize_interrupt(InterruptMessage{12, {{"mode", std::string{"kill"}}}}),
        serialize_unsubscribe(UnsubscribeMessage{13, 14}),
        serialize_hello(HelloMessage::create_client("realm")),
        serialize_welcome(WelcomeMessage::create_router(5, "realm")),
        serialize_challenge(ChallengeMessage{"cryptosign", {{"challenge", "ab"}}}),
        serialize_authenticate(AuthenticateMessage{"sig", {}}),
    };

    auto run_all = [](const std::vector<uint8_t>& data) {
        (void)get_message_type_from_cbor(data);
        (void)deserialize_subscribe(data);
        (void)deserialize_subscribed(data);
        (void)deserialize_publish(data);
        (void)deserialize_published(data);
        (void)deserialize_event(data);
        (void)deserialize_register(data);
        (void)deserialize_registered(data);
        (void)deserialize_call(data);
        (void)deserialize_invocation(data);
        (void)deserialize_yield(data);
        (void)deserialize_result(data);
        (void)deserialize_error(data);
        (void)deserialize_interrupt(data);
        (void)deserialize_unsubscribe(data);
        (void)deserialize_hello(data);
        (void)deserialize_welcome(data);
        (void)deserialize_challenge(data);
        (void)deserialize_authenticate(data);
        (void)deserialize_goodbye(data);
        (void)deserialize_abort(data);
        (void)deserialize_unregister(data);
    };

    spdlog::set_level(spdlog::level::off);  // decode errors are expected here

    // every prefix of every message: either parses or reports an error, never reads out of bounds
    for (const auto& message : corpus) {
        for (size_t len = 0; len <= message.size(); ++len) {
            run_all(std::vector<uint8_t>(message.begin(), message.begin() + static_cast<std::ptrdiff_t>(len)));
        }
    }

    // random byte flips and random garbage
    std::mt19937 rng(777);
    for (int i = 0; i < 20000; ++i) {
        auto data = corpus[rng() % corpus.size()];
        for (int flips = 1 + static_cast<int>(rng() % 3); flips > 0; --flips) {
            data[rng() % data.size()] = static_cast<uint8_t>(rng());
        }
        run_all(data);
    }
    for (int i = 0; i < 2000; ++i) {
        std::vector<uint8_t> garbage(rng() % 64);
        for (auto& b : garbage) b = static_cast<uint8_t>(rng());
        run_all(garbage);
    }
    SUCCEED();
}

// ----------------------------------------------------------------------------
// The value model carries any payload without loss
// ----------------------------------------------------------------------------
namespace {

json to_oracle(const WampValue& v) {
    return std::visit([]<typename T>(const T& x) -> json {
        if constexpr (std::is_same_v<T, std::nullptr_t>) return nullptr;
        else if constexpr (std::is_same_v<T, WampBytes>) return json::binary(std::vector<uint8_t>(x.begin(), x.end()));
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
    switch (rng() % (depth >= 3 ? 7 : 9)) {
        case 0: return WampValue{};
        case 1: return WampValue{rng() % 2 == 0};
        case 2: return WampValue{static_cast<int64_t>(rng()) >> (rng() % 60)};
        case 3: {
            static const double specials[] = {0.0, -0.0, 0.5, 1.5, 2.9, 1e300, -1e-300, 0.1, 3.14159265358979, 65504.0, 5.960464477539063e-8};
            return WampValue{specials[rng() % 11]};
        }
        case 4: {
            std::string s(rng() % 20, 'x');
            for (auto& c : s) c = static_cast<char>('a' + rng() % 26);
            return WampValue{s};
        }
        case 5: {
            WampBytes b(rng() % 20);
            for (auto& x : b) x = static_cast<uint8_t>(rng());
            return WampValue{b};
        }
        case 6: return WampValue{std::string("\xC3\xA9\xE2\x82\xAC")};   // multi-byte UTF-8
        case 7: {
            WampList l;
            for (size_t n = rng() % 5; n > 0; --n) l.push_back(random_value(rng, depth + 1));
            return WampValue{l};
        }
        default: {
            WampDict d;
            for (size_t n = rng() % 5; n > 0; --n) d[std::string(1, static_cast<char>('a' + rng() % 8))] = random_value(rng, depth + 1);
            return WampValue{d};
        }
    }
}

}  // namespace

TEST_CASE("WampValue payloads round-trip through CBOR without loss and match the oracle bytes", "[cbor][value]") {
    std::mt19937_64 rng(777);
    for (int i = 0; i < 1000; ++i) {
        WampList args;
        for (size_t n = 1 + rng() % 6; n > 0; --n) args.push_back(random_value(rng, 0));
        WampDict kw;
        for (size_t n = 1 + rng() % 4; n > 0; --n) kw[std::string(1, static_cast<char>('a' + rng() % 8))] = random_value(rng, 0);
        const uint64_t id = rng() >> 12;

        const auto wire = serialize_call(CallMessage{id, {}, "p", args, kw});
        // same bytes as the independent oracle writes for the same tree
        json expected = json::array({48, id, json::object(), "p", to_oracle(WampValue{args}), to_oracle(WampValue{kw})});
        REQUIRE(wire == json::to_cbor(expected));

        auto back = deserialize_call(wire);
        REQUIRE(back.has_value());
        REQUIRE(back->arguments == args);
        REQUIRE(back->arguments_kw == kw);
    }
}

TEST_CASE("WampValue edge cases", "[cbor][value]") {
    SECTION("floats: NaN and infinities survive") {
        std::vector<uint8_t> out;
        cbor::Writer w{out};
        w.write_array(3);
        w.write_double(std::nan(""));
        w.write_double(INFINITY);
        w.write_double(-INFINITY);
        cbor::Reader r{out};
        auto list = fast::read_list(r);
        REQUIRE(list.size() == 3);
        CHECK(std::isnan(std::get<double>(list[0])));
        CHECK(std::get<double>(list[1]) == INFINITY);
        CHECK(std::get<double>(list[2]) == -INFINITY);
    }
    SECTION("half-precision floats from other encoders are read") {
        const std::vector<uint8_t> half{0xF9, 0x3C, 0x00};   // 1.0
        cbor::Reader r{half};
        CHECK(std::get<double>(fast::read_value(r)) == 1.0);
    }
    SECTION("integers at the int64 limits, and one past them") {
        for (int64_t v : {INT64_MIN, INT64_MAX}) {
            std::vector<uint8_t> out;
            cbor::Writer{out}.write_int(v);
            cbor::Reader r{out};
            CHECK(std::get<int64_t>(fast::read_value(r)) == v);
        }
        const std::vector<uint8_t> two_pow_63{0x1B, 0x80, 0, 0, 0, 0, 0, 0, 0};
        cbor::Reader too_big{two_pow_63};
        CHECK_THROWS_AS(fast::read_value(too_big), cbor::DecodeError);
    }
    SECTION("tags are transparent, undefined reads as null") {
        const std::vector<uint8_t> tagged_bytes{0xC1, 0x18, 0x2A};   // tag 1 around 42
        cbor::Reader tagged{tagged_bytes};
        CHECK(std::get<int64_t>(fast::read_value(tagged)) == 42);
        const std::vector<uint8_t> undefined_bytes{0xF7};
        cbor::Reader undef{undefined_bytes};
        CHECK(std::holds_alternative<std::nullptr_t>(fast::read_value(undef)));
    }
    SECTION("nesting deeper than the limit is an error, not a stack overflow") {
        std::vector<uint8_t> deep(10000, 0x81);   // [[[[...
        deep.push_back(0x00);
        cbor::Reader r{deep};
        CHECK_THROWS_AS(fast::read_value(r), cbor::DecodeError);
        std::vector<uint8_t> deep_map;
        for (int i = 0; i < 5000; ++i) { deep_map.push_back(0xA1); deep_map.push_back(0x61); deep_map.push_back('k'); }
        deep_map.push_back(0x00);
        cbor::Reader rm{deep_map};
        CHECK_THROWS_AS(fast::read_value(rm), cbor::DecodeError);
        // within the limit is fine
        std::vector<uint8_t> ok(60, 0x81);
        ok.push_back(0x00);
        cbor::Reader r_ok{ok};
        CHECK_NOTHROW(fast::read_value(r_ok));
    }
    SECTION("literals build the types one expects") {
        WampList args{"text", 5, 5U, 5L, int64_t{5}, true, 1.5, nullptr, WampBytes{1, 2}};
        CHECK(std::holds_alternative<std::string>(args[0]));
        for (int i = 1; i <= 4; ++i) CHECK(std::get<int64_t>(args[i]) == 5);
        CHECK(std::holds_alternative<bool>(args[5]));
        CHECK(std::holds_alternative<double>(args[6]));
        CHECK(std::holds_alternative<std::nullptr_t>(args[7]));
        CHECK(std::holds_alternative<WampBytes>(args[8]));
    }
}
