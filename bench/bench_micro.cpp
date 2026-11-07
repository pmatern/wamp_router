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


// Micro-benchmarks for the router's hot paths (Catch2 BENCHMARK).
//
//   cmake --preset local-release && cmake --build build-local-release --target wamp_bench
//   ./build-local-release/wamp_bench
//
// Run a Release build; Debug numbers are not meaningful.

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <boost/asio/io_context.hpp>
#include <spdlog/spdlog.h>
#include "include/authorizer.hpp"
#include "include/invocation_tracker.hpp"
#include "include/procedure_handler.hpp"
#include "include/pubsub_handler.hpp"
#include "include/raw_socket.hpp"
#include "include/registration_manager.hpp"
#include "include/subscription_manager.hpp"
#include "include/wamp_serializer.hpp"

using namespace wamp;

namespace {

// Router handlers log at info level; keep logging out of the measurements.
const bool kQuiet = (spdlog::set_level(spdlog::level::off), true);

constexpr const char* kTopic = "com.bench.topic";
constexpr const char* kProcedure = "com.bench.procedure";

WampList make_args(size_t n) {
    WampList args;
    for (size_t i = 0; i < n; ++i) {
        switch (i % 3) {
            case 0: args.emplace_back(std::string{"argument-value-"} + std::to_string(i)); break;
            case 1: args.emplace_back(static_cast<int64_t>(i * 1000)); break;
            default: args.emplace_back(i % 2 == 0); break;
        }
    }
    return args;
}

WampDict make_kw() {
    return {{"unit", std::string{"ms"}}, {"count", int64_t{42}}, {"flag", true}};
}

}  // namespace

// ============================================================================
// Serialization: empty payload vs. 10 positional + keyword arguments
// ============================================================================

TEST_CASE("bench: serialize", "[bench][serializer]") {
    const WampList args = make_args(10);
    const WampDict kw = make_kw();

    const CallMessage call_empty{1, {}, kProcedure};
    const CallMessage call_args{1, {}, kProcedure, args, kw};
    const PublishMessage publish_args{1, {}, kTopic, args, kw};
    const EventMessage event_empty{10, 20, {}};
    const EventMessage event_args{10, 20, {}, args, kw};
    const InvocationMessage invocation_args{5, 6, {}, args, kw};
    const ResultMessage result_args{1, {}, args, kw};
    const ErrorMessage error_args{MessageType::CALL, 1, {{"message", std::string{"boom"}}},
                                  "wamp.error.callee_failure", args, kw};

    BENCHMARK("CALL (no args)") { return serialize_call(call_empty); };
    BENCHMARK("CALL (10 args + kw)") { return serialize_call(call_args); };
    BENCHMARK("PUBLISH (10 args + kw)") { return serialize_publish(publish_args); };
    BENCHMARK("EVENT (no args)") { return serialize_event(event_empty); };
    BENCHMARK("EVENT (10 args + kw)") { return serialize_event(event_args); };
    BENCHMARK("INVOCATION (10 args + kw)") { return serialize_invocation(invocation_args); };
    BENCHMARK("RESULT (10 args + kw)") { return serialize_result(result_args); };
    BENCHMARK("ERROR (10 args + kw)") { return serialize_error(error_args); };
}

TEST_CASE("bench: authorization check", "[bench][authz]") {
    Permissions role;
    for (int i = 0; i < 50; ++i) {
        role.add_rule(Action::PUBLISH, "com.example.topic" + std::to_string(i), false);
    }
    for (int i = 0; i < 5; ++i) {
        role.add_rule(Action::PUBLISH, "org.prefix" + std::to_string(i) + ".", true);
    }

    BENCHMARK("exact hit (50 exact + 5 prefix rules)") { return role.allows(Action::PUBLISH, "com.example.topic37"); };
    BENCHMARK("prefix hit (5th prefix)") { return role.allows(Action::PUBLISH, "org.prefix4.a.b.c"); };
    BENCHMARK("miss (scans all prefixes)") { return role.allows(Action::PUBLISH, "net.nothing.here.at.all"); };
}

TEST_CASE("bench: EVENT per subscriber", "[bench][serializer]") {
    const WampList args = make_args(10);
    const WampDict kw = make_kw();
    const EventMessage event{10, 20, {}, args, kw};
    const EventTemplate tmpl{event};

    // What the router did per subscriber before EventTemplate, and what it does now
    BENCHMARK("serialize_event + frame (per subscriber, old)") {
        return rawsocket::create_wamp_message(serialize_event(event));
    };
    BENCHMARK("EventTemplate::frame_for (per subscriber, new)") { return tmpl.frame_for(12345); };
    BENCHMARK("EventTemplate build (once per publish)") { return EventTemplate{event}; };
}

TEST_CASE("bench: deserialize", "[bench][serializer]") {
    const WampList args = make_args(10);
    const WampDict kw = make_kw();

    const auto call_empty = serialize_call(CallMessage{1, {}, kProcedure});
    const auto call_args = serialize_call(CallMessage{1, {}, kProcedure, args, kw});
    const auto publish_args = serialize_publish(PublishMessage{1, {}, kTopic, args, kw});
    const auto event_args = serialize_event(EventMessage{10, 20, {}, args, kw});
    const auto invocation_args = serialize_invocation(InvocationMessage{5, 6, {}, args, kw});
    const auto result_args = serialize_result(ResultMessage{1, {}, args, kw});
    const auto yield_args = serialize_yield(YieldMessage{5, {}, args, kw});

    BENCHMARK("CALL (no args)") { return deserialize_call(call_empty); };
    BENCHMARK("CALL (10 args + kw)") { return deserialize_call(call_args); };
    BENCHMARK("PUBLISH (10 args + kw)") { return deserialize_publish(publish_args); };
    BENCHMARK("EVENT (10 args + kw)") { return deserialize_event(event_args); };
    BENCHMARK("INVOCATION (10 args + kw)") { return deserialize_invocation(invocation_args); };
    BENCHMARK("RESULT (10 args + kw)") { return deserialize_result(result_args); };
    BENCHMARK("YIELD (10 args + kw)") { return deserialize_yield(yield_args); };
    BENCHMARK("get_message_type_from_cbor") { return get_message_type_from_cbor(call_args); };
}

// ============================================================================
// RawSocket framing
// ============================================================================

TEST_CASE("bench: rawsocket framing", "[bench][rawsocket]") {
    const std::vector<uint8_t> small(128, 0xAB);
    const std::vector<uint8_t> large(16 * 1024, 0xAB);
    const auto frame = rawsocket::create_wamp_message(small);
    const auto header = std::span<const uint8_t>{frame.data(), rawsocket::FRAME_HEADER_SIZE};

    BENCHMARK("create_wamp_message 128 B") { return rawsocket::create_wamp_message(small); };
    BENCHMARK("create_wamp_message 16 KiB") { return rawsocket::create_wamp_message(large); };
    BENCHMARK("decode_frame_header") { return rawsocket::decode_frame_header(header); };
}

// ============================================================================
// Routing tables
// ============================================================================

TEST_CASE("bench: subscription manager", "[bench][routing]") {
    for (uint64_t n : {1u, 100u, 10000u}) {
        SubscriptionManager manager;
        for (uint64_t i = 0; i < n; ++i) {
            manager.subscribe(i + 1, kTopic, 1000 + i);
        }
        // Unrelated topics, so lookups don't hit a lone bucket
        for (uint64_t i = 0; i < 1000; ++i) {
            manager.subscribe(1'000'000 + i, "com.bench.other." + std::to_string(i), 1);
        }

        BENCHMARK("get_subscribers, " + std::to_string(n) + " subscribers") {
            return manager.get_subscribers(kTopic);
        };
        BENCHMARK("get_subscription (by id), " + std::to_string(n) + " subscribers") {
            return manager.get_subscription(n);
        };
        BENCHMARK("for_each_subscriber, " + std::to_string(n) + " subscribers") {
            uint64_t sum = 0;
            manager.for_each_subscriber(kTopic, [&](uint64_t sub, uint64_t session) { sum += sub ^ session; });
            return sum;
        };
    }

    BENCHMARK_ADVANCED("subscribe + unsubscribe")(Catch::Benchmark::Chronometer meter) {
        SubscriptionManager manager;
        uint64_t id = 0;
        meter.measure([&] {
            ++id;
            manager.subscribe(id, kTopic, 1);
            return manager.unsubscribe(id);
        });
    };
}

TEST_CASE("bench: registration manager and invocation tracker", "[bench][routing]") {
    RegistrationManager registrations;
    for (uint64_t i = 0; i < 1000; ++i) {
        registrations.register_procedure(i + 1, "com.bench.proc." + std::to_string(i), 1);
    }
    registrations.register_procedure(5000, kProcedure, 2);

    BENCHMARK("find_callee (1000 registrations)") { return registrations.find_callee(kProcedure); };

    InvocationTracker tracker{10000};
    BENCHMARK_ADVANCED("track + retrieve")(Catch::Benchmark::Chronometer meter) {
        uint64_t id = 0;
        meter.measure([&] {
            ++id;
            tracker.track(id, PendingCall{1, id, 2});
            return tracker.retrieve(id);
        });
    };
}

// ============================================================================
// Handler paths (include message (de)serialization and channel delivery)
// ============================================================================

TEST_CASE("bench: publish fan-out", "[bench][handlers]") {
    boost::asio::io_context io;
    const WampList args = make_args(10);
    const WampDict kw = make_kw();

    for (uint64_t n : {1u, 10u, 100u}) {
        const uint64_t publisher = 9'000'000;
        std::vector<std::shared_ptr<EventChannel>> channels;
        std::vector<uint64_t> sessions;
        for (uint64_t i = 0; i < n; ++i) {
            const uint64_t session = 9'100'000 + i;
            sessions.push_back(session);
            channels.push_back(EventChannelRegistry::get_or_create(session, io));
            (void)PubSubHandler::handle_subscribe(SubscribeMessage{i + 1, {}, kTopic}, session);
        }

        // Channels hold 100 events; drain them after every publish so none overflow.
        // The drain cost (n try_receive calls) is included in the number.
        const PublishMessage publish{1, {}, kTopic, args, kw};
        BENCHMARK("PUBLISH + drain, " + std::to_string(n) + " subscribers") {
            auto response = PubSubHandler::handle_publish(publish, publisher);
            for (auto& channel : channels) {
                channel->try_receive([](boost::system::error_code, EventToSend) {});
            }
            return response;
        };

        for (auto session : sessions) {
            PubSubHandler::cleanup_session(session);
            EventChannelRegistry::remove(session);
        }
    }
}

TEST_CASE("bench: RPC round trip through the router", "[bench][handlers]") {
    boost::asio::io_context io;
    const uint64_t callee = 9'200'001;
    const uint64_t caller = 9'200'002;
    auto callee_channel = EventChannelRegistry::get_or_create(callee, io);
    auto caller_channel = EventChannelRegistry::get_or_create(caller, io);
    REQUIRE(ProcedureHandler::handle_register(RegisterMessage{1, {}, kProcedure}, callee).has_value());

    const WampList args = make_args(10);
    const WampDict kw = make_kw();
    const CallMessage call{1, {}, kProcedure, args, kw};

    // CALL -> INVOCATION (callee) -> deserialize + YIELD -> RESULT (caller), minus socket I/O
    BENCHMARK("CALL + INVOCATION + YIELD + RESULT (10 args + kw)") {
        (void)ProcedureHandler::handle_call(call, caller);

        uint64_t invocation_id = 0;
        callee_channel->try_receive([&](boost::system::error_code, EventToSend ev) {
            std::vector<uint8_t> payload{ev.event_data->begin() + rawsocket::FRAME_HEADER_SIZE,
                                         ev.event_data->end()};
            if (auto inv = deserialize_invocation(payload)) {
                invocation_id = inv->request_id;
            }
        });

        (void)ProcedureHandler::handle_yield(YieldMessage{invocation_id, {}, args, kw}, callee);

        bool delivered = false;
        caller_channel->try_receive([&](boost::system::error_code, EventToSend) { delivered = true; });
        return delivered;
    };

    ProcedureHandler::cleanup_session(callee);
    ProcedureHandler::cleanup_session(caller);
    EventChannelRegistry::remove(callee);
    EventChannelRegistry::remove(caller);
}
