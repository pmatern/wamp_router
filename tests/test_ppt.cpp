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


#include "include/ppt.hpp"
#include "include/wamp_serializer.hpp"
#include <catch2/catch_test_macros.hpp>

using namespace wamp;

namespace {
const WampBytes kBlob{0x00, 0xFF, 0x10, 0x80};
WampDict scheme_options() {
    return WampDict{{"ppt_scheme", std::string{"x_protobuf"}}, {"ppt_serializer", std::string{"native"}}};
}
}  // namespace

TEST_CASE("ppt::extract keeps only ppt_* entries", "[ppt]") {
    const WampDict options{{"acknowledge", true}, {"ppt_scheme", std::string{"s"}}, {"ppt_keyid", std::string{"k"}}};
    const auto ppt = ppt::extract(options);
    CHECK(ppt.size() == 2);
    CHECK(ppt.contains("ppt_scheme"));
    CHECK(ppt::extract(WampDict{{"acknowledge", true}}).empty());
}

TEST_CASE("ppt::valid requires a scheme, string options and one binary argument", "[ppt]") {
    const WampList payload{kBlob};
    CHECK(ppt::valid(scheme_options(), payload, {}));
    CHECK_FALSE(ppt::valid(WampDict{{"ppt_serializer", std::string{"native"}}}, payload, {}));        // no scheme
    CHECK_FALSE(ppt::valid(WampDict{{"ppt_scheme", std::string{}}}, payload, {}));                    // empty scheme
    CHECK_FALSE(ppt::valid(WampDict{{"ppt_scheme", int64_t{1}}}, payload, {}));                       // not a string
    CHECK_FALSE(ppt::valid(WampDict{{"ppt_scheme", std::string{"s"}}, {"ppt_cipher", true}}, payload, {}));
    CHECK_FALSE(ppt::valid(scheme_options(), WampList{}, {}));                                        // no payload
    CHECK_FALSE(ppt::valid(scheme_options(), WampList{std::string{"text"}}, {}));                     // not binary
    CHECK_FALSE(ppt::valid(scheme_options(), WampList{kBlob, kBlob}, {}));                            // two arguments
    CHECK_FALSE(ppt::valid(scheme_options(), payload, WampDict{{"k", true}}));                        // kwargs
}

TEST_CASE("ppt feature announcement", "[ppt]") {
    CHECK(ppt::announced(WampDict{{"payload_passthru_mode", true}}));
    CHECK_FALSE(ppt::announced(WampDict{{"payload_passthru_mode", false}}));
    CHECK_FALSE(ppt::announced(WampDict{}));
}

TEST_CASE("ppt options survive PUBLISH, YIELD, EVENT, INVOCATION and RESULT serialization", "[ppt][serializer]") {
    const WampList payload{kBlob};

    auto publish = deserialize_publish(serialize_publish(
        PublishMessage{1, WampDict{{"acknowledge", true}, {"ppt_scheme", std::string{"s"}}, {"other", int64_t{3}}},
                       "topic", payload}));
    REQUIRE(publish);
    CHECK(publish->options.size() == 2);  // acknowledge and ppt_scheme; unknown options are dropped
    CHECK(std::get<std::string>(publish->options.at("ppt_scheme")) == "s");

    auto yield = deserialize_yield(serialize_yield(YieldMessage{7, scheme_options(), payload}));
    REQUIRE(yield);
    CHECK(yield->options == scheme_options());
    CHECK(yield->arguments == payload);

    auto event = deserialize_event(serialize_event(EventMessage{3, 4, scheme_options(), payload}));
    REQUIRE(event);
    CHECK(event->details == scheme_options());

    auto invocation = deserialize_invocation(serialize_invocation(InvocationMessage{5, 6, scheme_options(), payload}));
    REQUIRE(invocation);
    CHECK(invocation->details == scheme_options());

    auto result = deserialize_result(serialize_result(ResultMessage{8, scheme_options(), payload}));
    REQUIRE(result);
    CHECK(result->details == scheme_options());
    CHECK(result->arguments == payload);
}

TEST_CASE("EventTemplate stamps subscription ids into an event that has details", "[ppt][serializer]") {
    const EventTemplate event_template{EventMessage{0, 99, scheme_options(), WampList{kBlob}}};
    for (const uint64_t id : {uint64_t{1}, uint64_t{300}, uint64_t{70000}, uint64_t{1} << 40}) {
        const auto frame = event_template.frame_for(id);
        auto event = deserialize_event(std::vector<uint8_t>(frame.begin() + rawsocket::FRAME_HEADER_SIZE, frame.end()));
        REQUIRE(event);
        CHECK(event->subscription_id == id);
        CHECK(event->publication_id == 99);
        CHECK(event->details == scheme_options());
        CHECK(event->arguments == WampList{kBlob});
    }
}

TEST_CASE("Role features are written to and read from HELLO and WELCOME", "[ppt][serializer]") {
    auto hello = deserialize_hello(serialize_hello(HelloMessage::create_client("realm1")));
    REQUIRE(hello);
    REQUIRE(hello->roles.size() == 4);
    for (const auto& role : hello->roles) CHECK(ppt::announced(role.features));

    auto without = deserialize_hello(serialize_hello(HelloMessage::create_client("realm1", false)));
    REQUIRE(without);
    for (const auto& role : without->roles) CHECK_FALSE(ppt::announced(role.features));

    auto welcome = deserialize_welcome(serialize_welcome(WelcomeMessage::create_router(1, "realm1")));
    REQUIRE(welcome);
    REQUIRE(welcome->roles.size() == 2);
    for (const auto& role : welcome->roles) CHECK(ppt::announced(role.features));
}
