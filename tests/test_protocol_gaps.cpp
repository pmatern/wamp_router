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


#include <catch2/catch_test_macros.hpp>
#include <boost/asio/io_context.hpp>
#include "include/pubsub_handler.hpp"
#include "include/procedure_handler.hpp"
#include "include/wamp_serializer.hpp"
#include "include/wamp_session.hpp"

using namespace wamp;

namespace {

constexpr size_t kFrameHeader = 4;

std::vector<uint8_t> payload_of(const std::vector<uint8_t>& frame) {
    REQUIRE(frame.size() > kFrameHeader);
    return {frame.begin() + kFrameHeader, frame.end()};
}

// Pop one frame from a session's event channel (empty if none queued)
std::vector<uint8_t> pop_frame(EventChannel& channel) {
    std::vector<uint8_t> out;
    channel.try_receive([&](boost::system::error_code ec, EventToSend ev) {
        if (!ec && ev.event_data) {
            out = *ev.event_data;
        }
    });
    return out;
}

// Registers a channel for each session id and removes them on destruction
struct Sessions {
    boost::asio::io_context io;
    std::vector<uint64_t> ids;

    std::shared_ptr<EventChannel> add(uint64_t id) {
        ids.push_back(id);
        return EventChannelRegistry::get_or_create(id, io);
    }
    ~Sessions() {
        for (auto id : ids) {
            PubSubHandler::cleanup_session(id);
            ProcedureHandler::cleanup_session(id);
            EventChannelRegistry::remove(id);
        }
    }
};

}  // namespace

TEST_CASE("Serializer round-trips payloads", "[protocol][serializer]") {
    const WampList args{std::string{"a"}, int64_t{7}, true};
    const WampDict kw{{"k", std::string{"v"}}};

    SECTION("CALL") {
        auto msg = deserialize_call(serialize_call(CallMessage{1, {}, "p.q", args, kw}));
        REQUIRE(msg.has_value());
        REQUIRE(msg->procedure == "p.q");
        REQUIRE(msg->arguments == args);
        REQUIRE(msg->arguments_kw.at("k") == WampDict::mapped_type{std::string{"v"}});
    }
    SECTION("INVOCATION") {
        auto msg = deserialize_invocation(serialize_invocation(InvocationMessage{2, 3, {}, args, kw}));
        REQUIRE(msg.has_value());
        REQUIRE(msg->arguments == args);
        REQUIRE(msg->arguments_kw.size() == 1);
    }
    SECTION("PUBLISH") {
        auto msg = deserialize_publish(serialize_publish(PublishMessage{4, {}, "t.x", args, {}}));
        REQUIRE(msg.has_value());
        REQUIRE(msg->arguments == args);
        REQUIRE(msg->arguments_kw.empty());
    }
    SECTION("EVENT") {
        auto msg = deserialize_event(serialize_event(EventMessage{5, 6, {}, args, kw}));
        REQUIRE(msg.has_value());
        REQUIRE(msg->arguments == args);
        REQUIRE(msg->arguments_kw.size() == 1);
    }
    SECTION("ERROR") {
        auto msg = deserialize_error(serialize_error(
            ErrorMessage{MessageType::INVOCATION, 8, {{"message", std::string{"boom"}}}, "my.error", args, kw}));
        REQUIRE(msg.has_value());
        REQUIRE(msg->request_type == MessageType::INVOCATION);
        REQUIRE(msg->error_uri == "my.error");
        REQUIRE(msg->details.contains("message"));
        REQUIRE(msg->arguments == args);
    }
    SECTION("Empty payload stays minimal") {
        auto j = nlohmann::json::from_cbor(serialize_event(EventMessage{1, 2, {}}));
        REQUIRE(j.size() == 4);
    }
    SECTION("PUBLISH keeps exclude_me") {
        auto msg = deserialize_publish(serialize_publish(PublishMessage{1, {{"exclude_me", false}}, "t"}));
        REQUIRE(msg.has_value());
        REQUIRE(std::get<bool>(msg->options.at("exclude_me")) == false);
    }
}

TEST_CASE("Serializer round-trips unsubscribe/unregister", "[protocol][serializer]") {
    auto unsub = deserialize_unsubscribe(serialize_unsubscribe(UnsubscribeMessage{1, 2}));
    REQUIRE(unsub.has_value());
    REQUIRE(unsub->request_id == 1);
    REQUIRE(unsub->subscription_id == 2);

    auto unsubd = deserialize_unsubscribed(serialize_unsubscribed(UnsubscribedMessage{3}));
    REQUIRE(unsubd.has_value());
    REQUIRE(unsubd->request_id == 3);

    auto unreg = deserialize_unregister(serialize_unregister(UnregisterMessage{4, 5}));
    REQUIRE(unreg.has_value());
    REQUIRE(unreg->registration_id == 5);

    auto unregd = deserialize_unregistered(serialize_unregistered(UnregisteredMessage{6}));
    REQUIRE(unregd.has_value());
    REQUIRE(unregd->request_id == 6);

    REQUIRE(!deserialize_unsubscribe(serialize_unsubscribed(UnsubscribedMessage{1})).has_value());
}

TEST_CASE("UNSUBSCRIBE handling", "[protocol][pubsub]") {
    Sessions s;
    auto ch_sub = s.add(910001);
    s.add(910002);

    auto subscribed = deserialize_subscribed(payload_of(
        PubSubHandler::handle_subscribe(SubscribeMessage{1, {}, "proto.topic"}, 910001)));
    REQUIRE(subscribed.has_value());
    auto sub_id = subscribed->subscription_id;

    SECTION("Owner can unsubscribe and no longer receives events") {
        auto resp = PubSubHandler::handle_unsubscribe(UnsubscribeMessage{2, sub_id}, 910001);
        auto unsubscribed = deserialize_unsubscribed(payload_of(resp));
        REQUIRE(unsubscribed.has_value());
        REQUIRE(unsubscribed->request_id == 2);

        (void)PubSubHandler::handle_publish(PublishMessage{3, {}, "proto.topic"}, 910002);
        REQUIRE(pop_frame(*ch_sub).empty());
    }

    SECTION("Unknown subscription yields no_such_subscription") {
        auto resp = PubSubHandler::handle_unsubscribe(UnsubscribeMessage{4, 123456789}, 910001);
        auto err = deserialize_error(payload_of(resp));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::UNSUBSCRIBE);
        REQUIRE(err->error_uri == "wamp.error.no_such_subscription");
    }

    SECTION("Another session cannot remove the subscription") {
        auto resp = PubSubHandler::handle_unsubscribe(UnsubscribeMessage{5, sub_id}, 910002);
        auto err = deserialize_error(payload_of(resp));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.no_such_subscription");

        (void)PubSubHandler::handle_publish(PublishMessage{6, {}, "proto.topic"}, 910002);
        REQUIRE(!pop_frame(*ch_sub).empty());
    }
}

TEST_CASE("PUBLISH forwards payload and honors exclude_me", "[protocol][pubsub]") {
    Sessions s;
    auto ch_pub = s.add(910011);
    auto ch_sub = s.add(910012);

    (void)PubSubHandler::handle_subscribe(SubscribeMessage{1, {}, "proto.events"}, 910011);
    (void)PubSubHandler::handle_subscribe(SubscribeMessage{2, {}, "proto.events"}, 910012);

    const WampList args{std::string{"hello"}, int64_t{42}};
    const WampDict kw{{"flag", true}};

    SECTION("Subscriber gets args, publisher excluded by default") {
        (void)PubSubHandler::handle_publish(PublishMessage{3, {}, "proto.events", args, kw}, 910011);

        auto event = deserialize_event(payload_of(pop_frame(*ch_sub)));
        REQUIRE(event.has_value());
        REQUIRE(event->arguments == args);
        REQUIRE(event->arguments_kw.size() == 1);
        REQUIRE(pop_frame(*ch_pub).empty());
    }

    SECTION("exclude_me=false delivers to the publisher too") {
        (void)PubSubHandler::handle_publish(
            PublishMessage{4, {{"exclude_me", false}}, "proto.events", args, {}}, 910011);

        REQUIRE(!pop_frame(*ch_pub).empty());
        REQUIRE(!pop_frame(*ch_sub).empty());
    }
}

TEST_CASE("UNREGISTER handling", "[protocol][rpc]") {
    Sessions s;
    s.add(910021);
    s.add(910022);

    auto registered = deserialize_registered(payload_of(*ProcedureHandler::handle_register(
        RegisterMessage{1, {}, "proto.add"}, 910021)));
    REQUIRE(registered.has_value());
    auto reg_id = registered->registration_id;

    SECTION("Another session cannot unregister it") {
        auto resp = ProcedureHandler::handle_unregister(UnregisterMessage{2, reg_id}, 910022);
        REQUIRE(resp.has_value());
        auto err = deserialize_error(payload_of(*resp));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.no_such_registration");
        REQUIRE(ProcedureHandler::get_registration_manager().find_callee("proto.add").has_value());
    }

    SECTION("Owner unregisters; later CALL gets no_such_procedure") {
        auto resp = ProcedureHandler::handle_unregister(UnregisterMessage{3, reg_id}, 910021);
        REQUIRE(resp.has_value());
        REQUIRE(deserialize_unregistered(payload_of(*resp)).has_value());

        auto call = ProcedureHandler::handle_call(CallMessage{4, {}, "proto.add"}, 910022);
        REQUIRE(call.has_value());
        auto err = deserialize_error(payload_of(*call));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.no_such_procedure");
    }
}

TEST_CASE("RPC forwards args and callee errors", "[protocol][rpc]") {
    Sessions s;
    auto ch_callee = s.add(910031);
    auto ch_caller = s.add(910032);

    REQUIRE(ProcedureHandler::handle_register(RegisterMessage{1, {}, "proto.echo"}, 910031).has_value());

    const WampList args{std::string{"x"}, int64_t{1}};
    const WampDict kw{{"k", std::string{"v"}}};

    auto call = ProcedureHandler::handle_call(CallMessage{50, {}, "proto.echo", args, kw}, 910032);
    REQUIRE(call.has_value());
    REQUIRE(call->empty());

    auto invocation = deserialize_invocation(payload_of(pop_frame(*ch_callee)));
    REQUIRE(invocation.has_value());
    REQUIRE(invocation->arguments == args);
    REQUIRE(invocation->arguments_kw.size() == 1);

    SECTION("Callee ERROR is forwarded to the caller as ERROR for CALL") {
        ErrorMessage callee_error{MessageType::INVOCATION, invocation->request_id,
                                  {{"message", std::string{"bad"}}}, "app.error.bad", args, kw};
        auto resp = ProcedureHandler::handle_invocation_error(callee_error, 910031);
        REQUIRE(resp.has_value());
        REQUIRE(resp->empty());

        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->request_id == 50);
        REQUIRE(err->error_uri == "app.error.bad");
        REQUIRE(err->arguments == args);

        // Invocation is consumed; a late YIELD is ignored
        (void)ProcedureHandler::handle_yield(YieldMessage{invocation->request_id, {}}, 910031);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("Callee disconnect fails pending calls with callee_failure") {
        ProcedureHandler::cleanup_session(910031);

        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->request_id == 50);
        REQUIRE(err->error_uri == "wamp.error.callee_failure");
    }

    SECTION("ERROR for unknown invocation is ignored") {
        ErrorMessage stray{MessageType::INVOCATION, 987654321, {}, "app.error.x"};
        auto resp = ProcedureHandler::handle_invocation_error(stray, 910031);
        REQUIRE(resp.has_value());
        REQUIRE(pop_frame(*ch_caller).empty());
    }
}

// ============================================================================
// Pipelined frames: one socket read can carry many messages
// ============================================================================

namespace {

void append(std::vector<uint8_t>& out, const std::vector<uint8_t>& more) {
    out.insert(out.end(), more.begin(), more.end());
}

std::vector<uint8_t> handshake_bytes() {
    auto hs = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR});
    return {hs.begin(), hs.end()};
}

std::vector<uint8_t> frame_of(const std::vector<uint8_t>& cbor) {
    return rawsocket::create_wamp_message(cbor);
}

// Split concatenated RawSocket frames (after the 4-byte handshake reply) into WAMP message types
std::vector<MessageType> message_types(std::span<const uint8_t> bytes) {
    std::vector<MessageType> types;
    size_t pos = rawsocket::HANDSHAKE_SIZE;
    while (pos + kFrameHeader <= bytes.size()) {
        auto header = rawsocket::decode_frame_header(bytes.subspan(pos, kFrameHeader));
        REQUIRE(header.has_value());
        pos += kFrameHeader;
        REQUIRE(pos + header->payload_length <= bytes.size());
        std::vector<uint8_t> payload{bytes.begin() + pos, bytes.begin() + pos + header->payload_length};
        auto type = get_message_type_from_cbor(payload);
        REQUIRE(type.has_value());
        types.push_back(*type);
        pos += header->payload_length;
    }
    REQUIRE(pos == bytes.size());
    return types;
}

}  // namespace

TEST_CASE("WampSession processes pipelined frames in one read", "[protocol][session]") {
    boost::asio::io_context io;
    ServerConfig config;
    WampSession session{io, config};
    session.on_connect();

    std::vector<uint8_t> input = handshake_bytes();
    append(input, frame_of(serialize_hello(HelloMessage::create_client("pipeline.realm"))));
    append(input, frame_of(serialize_subscribe(SubscribeMessage{1, {}, "proto.pipeline"})));
    append(input, frame_of(serialize_publish(PublishMessage{2, {{"acknowledge", true}}, "proto.pipeline"})));

    auto result = session.process(std::span{input.data(), input.size()});
    REQUIRE(result.has_value());

    auto types = message_types(*result);
    REQUIRE(types == std::vector<MessageType>{MessageType::WELCOME, MessageType::SUBSCRIBED, MessageType::PUBLISHED});
    REQUIRE(session.is_established());
}

TEST_CASE("WampSession delivers every fire-and-forget PUBLISH in a burst", "[protocol][session]") {
    Sessions s;
    auto subscriber = s.add(910041);
    (void)PubSubHandler::handle_subscribe(SubscribeMessage{1, {}, "proto.burst"}, 910041);

    boost::asio::io_context io;
    ServerConfig config;
    WampSession publisher{io, config};

    std::vector<uint8_t> input = handshake_bytes();
    append(input, frame_of(serialize_hello(HelloMessage::create_client("burst.realm"))));
    constexpr int kBurst = 50;
    for (int i = 0; i < kBurst; ++i) {
        append(input, frame_of(serialize_publish(PublishMessage{static_cast<uint64_t>(i + 1), {}, "proto.burst"})));
    }

    auto result = publisher.process(std::span{input.data(), input.size()});
    REQUIRE(result.has_value());

    int events = 0;
    while (!pop_frame(*subscriber).empty()) {
        ++events;
    }
    REQUIRE(events == kBurst);
}

TEST_CASE("WampSession handles frames split across reads", "[protocol][session]") {
    boost::asio::io_context io;
    ServerConfig config;
    WampSession session{io, config};

    auto handshake = handshake_bytes();
    REQUIRE(session.process(std::span{handshake.data(), handshake.size()}).has_value());

    auto hello = frame_of(serialize_hello(HelloMessage::create_client("split.realm")));

    // Header split mid-way must neither hang nor produce output
    auto first = session.process(std::span{hello.data(), 2});
    REQUIRE(first.has_value());
    REQUIRE(first->empty());

    auto second = session.process(std::span{hello.data() + 2, hello.size() - 2});
    REQUIRE(second.has_value());
    REQUIRE(!second->empty());
    REQUIRE(session.is_established());
}

// ============================================================================
// Call timeouts
// ============================================================================

TEST_CASE("Unanswered calls time out", "[protocol][rpc][timeout]") {
    using namespace std::chrono;
    Sessions s;
    auto ch_callee = s.add(910041);
    auto ch_caller = s.add(910042);
    REQUIRE(ProcedureHandler::handle_register(RegisterMessage{1, {}, "proto.slow"}, 910041).has_value());

    const auto saved = ProcedureHandler::get_default_call_timeout();
    struct Restore {
        milliseconds t;
        ~Restore() { ProcedureHandler::set_default_call_timeout(t); }
    } restore{saved};

    SECTION("CALL timeout option expires the call with wamp.error.timeout") {
        ProcedureHandler::set_default_call_timeout(0ms);
        WampDict opts{{"timeout", int64_t{100}}};
        REQUIRE(ProcedureHandler::handle_call(CallMessage{60, opts, "proto.slow"}, 910042).has_value());
        auto invocation = deserialize_invocation(payload_of(pop_frame(*ch_callee)));
        REQUIRE(invocation.has_value());

        REQUIRE(ProcedureHandler::expire_calls(steady_clock::now()) == 0);
        REQUIRE(pop_frame(*ch_caller).empty());

        REQUIRE(ProcedureHandler::expire_calls(steady_clock::now() + 1s) == 1);
        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->request_id == 60);
        REQUIRE(err->error_uri == "wamp.error.timeout");

        // A late YIELD is ignored
        (void)ProcedureHandler::handle_yield(YieldMessage{invocation->request_id, {}}, 910041);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("Default timeout applies when the CALL has no option") {
        ProcedureHandler::set_default_call_timeout(200ms);
        REQUIRE(ProcedureHandler::handle_call(CallMessage{61, {}, "proto.slow"}, 910042).has_value());
        REQUIRE(ProcedureHandler::expire_calls(steady_clock::now() + 1s) == 1);
        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.timeout");
    }

    SECTION("No timeout configured: call never expires") {
        ProcedureHandler::set_default_call_timeout(0ms);
        REQUIRE(ProcedureHandler::handle_call(CallMessage{62, {}, "proto.slow"}, 910042).has_value());
        REQUIRE(ProcedureHandler::expire_calls(steady_clock::now() + hours(24)) == 0);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("Answered calls do not time out") {
        ProcedureHandler::set_default_call_timeout(100ms);
        REQUIRE(ProcedureHandler::handle_call(CallMessage{63, {}, "proto.slow"}, 910042).has_value());
        auto invocation = deserialize_invocation(payload_of(pop_frame(*ch_callee)));
        REQUIRE(invocation.has_value());
        (void)ProcedureHandler::handle_yield(YieldMessage{invocation->request_id, {}}, 910041);
        REQUIRE(ProcedureHandler::expire_calls(steady_clock::now() + 1s) == 0);
    }
}
