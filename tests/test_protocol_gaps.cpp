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
#include <nlohmann/json.hpp>
#include <asio/io_context.hpp>
#include "include/pubsub_handler.hpp"
#include "include/procedure_handler.hpp"
#include "include/wamp_serializer.hpp"
#include "include/wamp_session.hpp"

using namespace wamp;

namespace {

// Routing state shared by the sessions and handlers a test builds by hand (one per test file)
static Shard& test_shard() {
    static Shard shard;
    return shard;
}

constexpr size_t kFrameHeader = 4;

// Handlers are called directly in a single realm; sessions in these tests join it too
Realm& kRealm() {
    return test_shard().realms.get("test.realm");
}

std::vector<uint8_t> payload_of(const std::vector<uint8_t>& frame) {
    REQUIRE(frame.size() > kFrameHeader);
    return {frame.begin() + kFrameHeader, frame.end()};
}

// Pop one frame from a session's event channel (empty if none queued)
std::vector<uint8_t> pop_frame(EventChannel& channel) {
    std::vector<uint8_t> out;
    channel.try_receive([&](std::error_code ec, EventToSend ev) {
        if (!ec && ev.event_data) {
            out = *ev.event_data;
        }
    });
    return out;
}

// Registers a channel for each session id and removes them on destruction
struct Sessions {
    asio::io_context io;
    std::vector<uint64_t> ids;

    std::shared_ptr<EventChannel> add(uint64_t id) {
        ids.push_back(id);
        return test_shard().channels.get_or_create(id, io);
    }
    ~Sessions() {
        for (auto id : ids) {
            PubSubHandler::cleanup_session(kRealm(), id);
            ProcedureHandler::cleanup_session(kRealm(), id);
            test_shard().channels.remove(id);
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
        PubSubHandler::handle_subscribe(kRealm(), SubscribeMessage{1, {}, "proto.topic"}, 910001)));
    REQUIRE(subscribed.has_value());
    auto sub_id = subscribed->subscription_id;

    SECTION("Owner can unsubscribe and no longer receives events") {
        auto resp = PubSubHandler::handle_unsubscribe(kRealm(), UnsubscribeMessage{2, sub_id}, 910001);
        auto unsubscribed = deserialize_unsubscribed(payload_of(resp));
        REQUIRE(unsubscribed.has_value());
        REQUIRE(unsubscribed->request_id == 2);

        (void)PubSubHandler::handle_publish(kRealm(), PublishMessage{3, {}, "proto.topic"}, 910002);
        REQUIRE(pop_frame(*ch_sub).empty());
    }

    SECTION("Unknown subscription yields no_such_subscription") {
        auto resp = PubSubHandler::handle_unsubscribe(kRealm(), UnsubscribeMessage{4, 123456789}, 910001);
        auto err = deserialize_error(payload_of(resp));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::UNSUBSCRIBE);
        REQUIRE(err->error_uri == "wamp.error.no_such_subscription");
    }

    SECTION("Another session cannot remove the subscription") {
        auto resp = PubSubHandler::handle_unsubscribe(kRealm(), UnsubscribeMessage{5, sub_id}, 910002);
        auto err = deserialize_error(payload_of(resp));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.no_such_subscription");

        (void)PubSubHandler::handle_publish(kRealm(), PublishMessage{6, {}, "proto.topic"}, 910002);
        REQUIRE(!pop_frame(*ch_sub).empty());
    }
}

TEST_CASE("PUBLISH forwards payload and honors exclude_me", "[protocol][pubsub]") {
    Sessions s;
    auto ch_pub = s.add(910011);
    auto ch_sub = s.add(910012);

    (void)PubSubHandler::handle_subscribe(kRealm(), SubscribeMessage{1, {}, "proto.events"}, 910011);
    (void)PubSubHandler::handle_subscribe(kRealm(), SubscribeMessage{2, {}, "proto.events"}, 910012);

    const WampList args{std::string{"hello"}, int64_t{42}};
    const WampDict kw{{"flag", true}};

    SECTION("Subscriber gets args, publisher excluded by default") {
        (void)PubSubHandler::handle_publish(kRealm(), PublishMessage{3, {}, "proto.events", args, kw}, 910011);

        auto event = deserialize_event(payload_of(pop_frame(*ch_sub)));
        REQUIRE(event.has_value());
        REQUIRE(event->arguments == args);
        REQUIRE(event->arguments_kw.size() == 1);
        REQUIRE(pop_frame(*ch_pub).empty());
    }

    SECTION("exclude_me=false delivers to the publisher too") {
        (void)PubSubHandler::handle_publish(kRealm(),
            PublishMessage{4, {{"exclude_me", false}}, "proto.events", args, {}}, 910011);

        REQUIRE(!pop_frame(*ch_pub).empty());
        REQUIRE(!pop_frame(*ch_sub).empty());
    }
}

TEST_CASE("UNREGISTER handling", "[protocol][rpc]") {
    Sessions s;
    s.add(910021);
    s.add(910022);

    auto registered = deserialize_registered(payload_of(*ProcedureHandler::handle_register(kRealm(),
        RegisterMessage{1, {}, "proto.add"}, 910021)));
    REQUIRE(registered.has_value());
    auto reg_id = registered->registration_id;

    SECTION("Another session cannot unregister it") {
        auto resp = ProcedureHandler::handle_unregister(kRealm(), UnregisterMessage{2, reg_id}, 910022);
        REQUIRE(resp.has_value());
        auto err = deserialize_error(payload_of(*resp));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.no_such_registration");
        REQUIRE(kRealm().registrations.find_callee("proto.add").has_value());
    }

    SECTION("Owner unregisters; later CALL gets no_such_procedure") {
        auto resp = ProcedureHandler::handle_unregister(kRealm(), UnregisterMessage{3, reg_id}, 910021);
        REQUIRE(resp.has_value());
        REQUIRE(deserialize_unregistered(payload_of(*resp)).has_value());

        auto call = ProcedureHandler::handle_call(kRealm(), CallMessage{4, {}, "proto.add"}, 910022);
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

    REQUIRE(ProcedureHandler::handle_register(kRealm(), RegisterMessage{1, {}, "proto.echo"}, 910031).has_value());

    const WampList args{std::string{"x"}, int64_t{1}};
    const WampDict kw{{"k", std::string{"v"}}};

    auto call = ProcedureHandler::handle_call(kRealm(), CallMessage{50, {}, "proto.echo", args, kw}, 910032);
    REQUIRE(call.has_value());
    REQUIRE(call->empty());

    auto invocation = deserialize_invocation(payload_of(pop_frame(*ch_callee)));
    REQUIRE(invocation.has_value());
    REQUIRE(invocation->arguments == args);
    REQUIRE(invocation->arguments_kw.size() == 1);

    SECTION("Callee ERROR is forwarded to the caller as ERROR for CALL") {
        ErrorMessage callee_error{MessageType::INVOCATION, invocation->request_id,
                                  {{"message", std::string{"bad"}}}, "app.error.bad", args, kw};
        auto resp = ProcedureHandler::handle_invocation_error(test_shard(), callee_error, 910031);
        REQUIRE(resp.has_value());
        REQUIRE(resp->empty());

        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->request_id == 50);
        REQUIRE(err->error_uri == "app.error.bad");
        REQUIRE(err->arguments == args);

        // Invocation is consumed; a late YIELD is ignored
        (void)ProcedureHandler::handle_yield(test_shard(), YieldMessage{invocation->request_id, {}}, 910031);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("Callee disconnect fails pending calls with callee_failure") {
        ProcedureHandler::cleanup_session(kRealm(), 910031);

        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->request_id == 50);
        REQUIRE(err->error_uri == "wamp.error.callee_failure");
    }

    SECTION("ERROR for unknown invocation is ignored") {
        ErrorMessage stray{MessageType::INVOCATION, 987654321, {}, "app.error.x"};
        auto resp = ProcedureHandler::handle_invocation_error(test_shard(), stray, 910031);
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
    asio::io_context io;
    ServerConfig config;
    WampSession session{io, config, test_shard()};
    session.on_connect();

    std::vector<uint8_t> input = handshake_bytes();
    append(input, frame_of(serialize_hello(HelloMessage::create_client("test.realm"))));
    append(input, frame_of(serialize_subscribe(SubscribeMessage{1, {}, "proto.pipeline"})));
    append(input, frame_of(serialize_publish(PublishMessage{2, {{"acknowledge", true}}, "proto.pipeline"})));

    auto result = session.process(std::span{input.data(), input.size()});
    REQUIRE(result.has_value());

    auto types = message_types(*result);
    REQUIRE(types == std::vector<MessageType>{MessageType::WELCOME, MessageType::SUBSCRIBED, MessageType::PUBLISHED});
    REQUIRE(session.is_established());
}

TEST_CASE("WampSession handles thousands of pipelined frames split at arbitrary points", "[protocol][session]") {
    // A 64 KiB read can carry hundreds of small frames; consuming them must not shift the buffer per frame.
    asio::io_context io;
    ServerConfig config;
    WampSession session{io, config, test_shard()};
    session.on_connect();

    std::vector<uint8_t> input = handshake_bytes();
    append(input, frame_of(serialize_hello(HelloMessage::create_client("test.realm"))));
    constexpr int kFrames = 5000;
    for (int i = 0; i < kFrames; ++i) {
        append(input, frame_of(serialize_subscribe(SubscribeMessage{static_cast<uint64_t>(i + 1), {}, "proto.many"})));
    }

    // feed it in uneven chunks so frames straddle read boundaries
    std::vector<uint8_t> all_output;  // handshake reply first, then the frames
    size_t pos = 0;
    size_t chunk = 7;
    while (pos < input.size()) {
        const size_t n = std::min(chunk, input.size() - pos);
        auto result = session.process(std::span{input.data() + pos, n});
        REQUIRE(result.has_value());
        all_output.insert(all_output.end(), result->begin(), result->end());
        pos += n;
        chunk = chunk * 3 % 9973 + 5;
    }
    auto types = message_types(all_output);
    REQUIRE(types.size() == static_cast<size_t>(kFrames) + 1);  // WELCOME + a SUBSCRIBED per frame
    REQUIRE(types.front() == MessageType::WELCOME);
    REQUIRE(std::all_of(types.begin() + 1, types.end(), [](auto t) { return t == MessageType::SUBSCRIBED; }));

    // and all in one read
    WampSession whole{io, config, test_shard()};
    whole.on_connect();
    auto result = whole.process(std::span{input.data(), input.size()});
    REQUIRE(result.has_value());
    REQUIRE(message_types(*result).size() == static_cast<size_t>(kFrames) + 1);
}

TEST_CASE("WampSession delivers every fire-and-forget PUBLISH in a burst", "[protocol][session]") {
    Sessions s;
    auto subscriber = s.add(910041);
    (void)PubSubHandler::handle_subscribe(kRealm(), SubscribeMessage{1, {}, "proto.burst"}, 910041);

    asio::io_context io;
    ServerConfig config;
    WampSession publisher{io, config, test_shard()};

    std::vector<uint8_t> input = handshake_bytes();
    append(input, frame_of(serialize_hello(HelloMessage::create_client("test.realm"))));
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
    asio::io_context io;
    ServerConfig config;
    WampSession session{io, config, test_shard()};

    auto handshake = handshake_bytes();
    REQUIRE(session.process(std::span{handshake.data(), handshake.size()}).has_value());

    auto hello = frame_of(serialize_hello(HelloMessage::create_client("test.realm")));

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

TEST_CASE("INTERRUPT round-trips", "[protocol][serializer]") {
    auto msg = deserialize_interrupt(serialize_interrupt(
        InterruptMessage{77, {{"mode", std::string{"killnowait"}}}}));
    REQUIRE(msg.has_value());
    REQUIRE(msg->request_id == 77);
    REQUIRE(msg->options.at("mode") == WampDict::mapped_type{std::string{"killnowait"}});
}

TEST_CASE("Unanswered calls time out", "[protocol][rpc][timeout]") {
    using namespace std::chrono;
    Sessions s;
    auto ch_callee = s.add(910041);
    auto ch_caller = s.add(910042);
    REQUIRE(ProcedureHandler::handle_register(kRealm(), RegisterMessage{1, {}, "proto.slow"}, 910041).has_value());

    const auto saved = test_shard().call_timeout;
    struct Restore {
        milliseconds t;
        ~Restore() { test_shard().call_timeout = t; }
    } restore{saved};

    SECTION("CALL timeout option expires the call with wamp.error.timeout") {
        test_shard().call_timeout = 0ms;
        WampDict opts{{"timeout", int64_t{100}}};
        REQUIRE(ProcedureHandler::handle_call(kRealm(), CallMessage{60, opts, "proto.slow"}, 910042).has_value());
        auto invocation = deserialize_invocation(payload_of(pop_frame(*ch_callee)));
        REQUIRE(invocation.has_value());

        REQUIRE(ProcedureHandler::expire_calls(test_shard(), steady_clock::now()) == 0);
        REQUIRE(pop_frame(*ch_caller).empty());

        REQUIRE(ProcedureHandler::expire_calls(test_shard(), steady_clock::now() + 1s) == 1);

        // The callee is told to stop
        auto interrupt = deserialize_interrupt(payload_of(pop_frame(*ch_callee)));
        REQUIRE(interrupt.has_value());
        REQUIRE(interrupt->request_id == invocation->request_id);

        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->request_id == 60);
        REQUIRE(err->error_uri == "wamp.error.timeout");

        // A late YIELD is ignored
        (void)ProcedureHandler::handle_yield(test_shard(), YieldMessage{invocation->request_id, {}}, 910041);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("Default timeout applies when the CALL has no option") {
        test_shard().call_timeout = 200ms;
        REQUIRE(ProcedureHandler::handle_call(kRealm(), CallMessage{61, {}, "proto.slow"}, 910042).has_value());
        REQUIRE(ProcedureHandler::expire_calls(test_shard(), steady_clock::now() + 1s) == 1);
        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.timeout");
    }

    SECTION("No timeout configured: call never expires") {
        test_shard().call_timeout = 0ms;
        REQUIRE(ProcedureHandler::handle_call(kRealm(), CallMessage{62, {}, "proto.slow"}, 910042).has_value());
        REQUIRE(ProcedureHandler::expire_calls(test_shard(), steady_clock::now() + hours(24)) == 0);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("Answered calls do not time out") {
        test_shard().call_timeout = 100ms;
        REQUIRE(ProcedureHandler::handle_call(kRealm(), CallMessage{63, {}, "proto.slow"}, 910042).has_value());
        auto invocation = deserialize_invocation(payload_of(pop_frame(*ch_callee)));
        REQUIRE(invocation.has_value());
        (void)ProcedureHandler::handle_yield(test_shard(), YieldMessage{invocation->request_id, {}}, 910041);
        REQUIRE(ProcedureHandler::expire_calls(test_shard(), steady_clock::now() + 1s) == 0);
    }
}

TEST_CASE("CANCEL stops a pending call in the three modes", "[protocol][rpc][cancel]") {
    Sessions s;
    auto ch_callee = s.add(910051);
    auto ch_caller = s.add(910052);
    REQUIRE(ProcedureHandler::handle_register(kRealm(), RegisterMessage{1, {}, "proto.cancel"}, 910051).has_value());
    auto cancel = [](uint64_t request_id, const char* mode) {
        WampDict options;
        if (mode != nullptr) options["mode"] = std::string{mode};
        return CancelMessage{request_id, options};
    };
    auto start = [&](uint64_t request_id) {
        REQUIRE(ProcedureHandler::handle_call(kRealm(), CallMessage{request_id, {}, "proto.cancel"}, 910052).has_value());
        auto invocation = deserialize_invocation(payload_of(pop_frame(*ch_callee)));
        REQUIRE(invocation.has_value());
        return invocation->request_id;
    };
    auto expect_canceled = [&](uint64_t request_id) {
        auto err = deserialize_error(payload_of(pop_frame(*ch_caller)));
        REQUIRE(err.has_value());
        REQUIRE(err->request_type == MessageType::CALL);
        REQUIRE(err->request_id == request_id);
        REQUIRE(err->error_uri == "wamp.error.canceled");
    };

    SECTION("skip (the default): the caller gets the error, the callee is not told, its answer is dropped") {
        const auto invocation_id = start(70);
        ProcedureHandler::handle_cancel(test_shard(), cancel(70, nullptr), 910052);
        expect_canceled(70);
        REQUIRE(pop_frame(*ch_callee).empty());
        (void)ProcedureHandler::handle_yield(test_shard(), YieldMessage{invocation_id, {}}, 910051);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("killnowait: the caller gets the error and the callee is interrupted") {
        const auto invocation_id = start(71);
        ProcedureHandler::handle_cancel(test_shard(), cancel(71, "killnowait"), 910052);
        expect_canceled(71);
        auto interrupt = deserialize_interrupt(payload_of(pop_frame(*ch_callee)));
        REQUIRE(interrupt.has_value());
        REQUIRE(interrupt->request_id == invocation_id);
        REQUIRE(std::get<std::string>(interrupt->options.at("mode")) == "killnowait");
        (void)ProcedureHandler::handle_yield(test_shard(), YieldMessage{invocation_id, {}}, 910051);
        REQUIRE(pop_frame(*ch_caller).empty());
    }

    SECTION("kill: the callee is interrupted and its answer reaches the caller") {
        const auto invocation_id = start(72);
        ProcedureHandler::handle_cancel(test_shard(), cancel(72, "kill"), 910052);
        REQUIRE(pop_frame(*ch_caller).empty());   // nothing yet
        auto interrupt = deserialize_interrupt(payload_of(pop_frame(*ch_callee)));
        REQUIRE(interrupt.has_value());
        REQUIRE(std::get<std::string>(interrupt->options.at("mode")) == "kill");

        auto error = ErrorMessage::create_canceled(invocation_id, "stopped");
        REQUIRE(ProcedureHandler::handle_invocation_error(test_shard(), error, 910051).has_value());
        expect_canceled(72);
    }

    SECTION("unknown modes mean skip; unknown, finished and foreign calls are ignored") {
        const auto invocation_id = start(73);
        ProcedureHandler::handle_cancel(test_shard(), cancel(999, "kill"), 910052);   // never existed
        ProcedureHandler::handle_cancel(test_shard(), cancel(73, "kill"), 910099);    // someone else's session
        REQUIRE(pop_frame(*ch_callee).empty());
        REQUIRE(pop_frame(*ch_caller).empty());

        ProcedureHandler::handle_cancel(test_shard(), cancel(73, "bogus"), 910052);
        expect_canceled(73);
        REQUIRE(pop_frame(*ch_callee).empty());

        ProcedureHandler::handle_cancel(test_shard(), cancel(73, nullptr), 910052);   // already canceled
        REQUIRE(pop_frame(*ch_caller).empty());
        (void)invocation_id;
    }

    SECTION("a call that was answered cannot be canceled") {
        const auto invocation_id = start(74);
        (void)ProcedureHandler::handle_yield(test_shard(), YieldMessage{invocation_id, {}}, 910051);
        REQUIRE(deserialize_result(payload_of(pop_frame(*ch_caller))).has_value());
        ProcedureHandler::handle_cancel(test_shard(), cancel(74, "kill"), 910052);
        REQUIRE(pop_frame(*ch_callee).empty());
        REQUIRE(pop_frame(*ch_caller).empty());
    }
}

TEST_CASE("CANCEL round-trips", "[protocol][serializer]") {
    auto msg = deserialize_cancel(serialize_cancel(CancelMessage{12, {{"mode", std::string{"kill"}}}}));
    REQUIRE(msg.has_value());
    REQUIRE(msg->request_id == 12);
    REQUIRE(std::get<std::string>(msg->options.at("mode")) == "kill");
    auto no_options = deserialize_cancel(serialize_cancel(CancelMessage{13}));
    REQUIRE(no_options.has_value());
    REQUIRE(no_options->options.empty());
}

TEST_CASE("InvocationTracker finds calls by caller session and request id, through every removal path", "[protocol][rpc][cancel]") {
    InvocationTracker tracker{3};
    tracker.track(PendingCall{1, 100, 10, 200});
    tracker.track(PendingCall{2, 100, 11, 200});
    tracker.track(PendingCall{3, 101, 10, 201});
    REQUIRE(tracker.find_by_call(100, 10)->invocation_id == 1);
    REQUIRE(tracker.find_by_call(101, 10)->invocation_id == 3);   // same request id, other session
    REQUIRE_FALSE(tracker.find_by_call(100, 12).has_value());

    tracker.track(PendingCall{4, 102, 10, 200});                   // evicts the oldest (invocation 1)
    REQUIRE_FALSE(tracker.find_by_call(100, 10).has_value());

    REQUIRE(tracker.retrieve(2).has_value());
    REQUIRE_FALSE(tracker.find_by_call(100, 11).has_value());

    (void)tracker.remove_caller_session(101);
    REQUIRE_FALSE(tracker.find_by_call(101, 10).has_value());
    (void)tracker.remove_callee_session(200);
    REQUIRE_FALSE(tracker.find_by_call(102, 10).has_value());
    REQUIRE(tracker.pending_count() == 0);

    tracker.track(PendingCall{5, 103, 10, 200, std::chrono::steady_clock::now()});
    REQUIRE(tracker.find_by_call(103, 10).has_value());
    REQUIRE(tracker.remove_expired(std::chrono::steady_clock::now() + std::chrono::seconds{1}).size() == 1);
    REQUIRE_FALSE(tracker.find_by_call(103, 10).has_value());
}
