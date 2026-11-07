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
#include "include/wamp_client.hpp"
#include "include/wamp_server.hpp"
#include <boost/asio.hpp>
#include <chrono>

using namespace wamp;
using namespace boost::asio;

// Test helper: Find available port
uint16_t find_available_port() {
    io_context io;
    ip::tcp::acceptor acceptor{io, ip::tcp::endpoint(ip::tcp::v4(), 0)};
    uint16_t port = acceptor.local_endpoint().port();
    acceptor.close();
    return port;
}

TEST_CASE("WampClient - Connect and disconnect", "[wamp_client]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();

    // Start server
    WampServer server{io, port, config};
    server.start();

    // Create client
    WampClient client{io};

    bool connected = false;
    bool disconnected = false;

    co_spawn(io, [&]() -> awaitable<void> {
        // Connect
        co_await client.connect("127.0.0.1", port, "test.realm");
        connected = true;
        REQUIRE(client.is_connected());
        REQUIRE(client.session_id() != 0);

        // Disconnect
        co_await client.disconnect();
        disconnected = true;
    }, detached);

    // Run for a bit
    io.run_for(std::chrono::seconds(2));

    REQUIRE(connected);
    REQUIRE(disconnected);
}

TEST_CASE("WampClient - Subscribe and receive event", "[wamp_client]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();

    // Start server
    WampServer server{io, port, config};
    server.start();

    // Create two clients: subscriber and publisher
    WampClient subscriber{io};
    WampClient publisher{io};

    bool event_received = false;
    uint64_t received_publication_id = 0;

    co_spawn(io, [&]() -> awaitable<void> {
        // Connect both clients
        co_await subscriber.connect("127.0.0.1", port, "test.realm");
        co_await publisher.connect("127.0.0.1", port, "test.realm");

        // Subscribe
        co_await subscriber.subscribe("com.example.topic", [&](const EventMessage& event) {
            event_received = true;
            received_publication_id = event.publication_id;
            spdlog::info("Event received: publication_id={}", event.publication_id);
        });

        // Small delay to ensure subscription is processed
        boost::asio::steady_timer timer{io};
        timer.expires_after(std::chrono::milliseconds(100));
        co_await timer.async_wait(use_awaitable);

        // Publish
        uint64_t pub_id = co_await publisher.publish("com.example.topic", true);
        spdlog::info("Published: publication_id={}", pub_id);

        // Wait for event
        timer.expires_after(std::chrono::milliseconds(500));
        co_await timer.async_wait(use_awaitable);

        // Cleanup
        co_await subscriber.disconnect();
        co_await publisher.disconnect();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(event_received);
    REQUIRE(received_publication_id != 0);
}

TEST_CASE("WampClient - Register procedure and handle call", "[wamp_client]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();

    // Start server
    WampServer server{io, port, config};
    server.start();

    // Create two clients: callee and caller
    WampClient callee{io};
    WampClient caller{io};

    bool procedure_invoked = false;
    bool result_received = false;

    co_spawn(io, [&]() -> awaitable<void> {
        // Connect both clients
        co_await callee.connect("127.0.0.1", port, "test.realm");
        co_await caller.connect("127.0.0.1", port, "test.realm");

        // Register procedure
        co_await callee.register_procedure(
            "com.example.add",
            [&](const InvocationMessage& invocation) -> awaitable<YieldMessage> {
                procedure_invoked = true;
                spdlog::info("Procedure invoked: request_id={}", invocation.request_id);

                // Return result (YieldMessage uses invocation_id which is the request_id from INVOCATION)
                YieldMessage yield{invocation.request_id, {}};
                co_return yield;
            }
        );

        // Small delay
        boost::asio::steady_timer timer{io};
        timer.expires_after(std::chrono::milliseconds(100));
        co_await timer.async_wait(use_awaitable);

        // Call procedure
        auto result = co_await caller.call("com.example.add");
        result_received = true;

        // Cleanup
        co_await callee.disconnect();
        co_await caller.disconnect();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(procedure_invoked);
    REQUIRE(result_received);
}

TEST_CASE("WampClient - Multiple subscribers receive same event", "[wamp_client]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();

    // Start server
    WampServer server{io, port, config};
    server.start();

    WampClient sub1{io};
    WampClient sub2{io};
    WampClient pub{io};

    int events_received = 0;

    co_spawn(io, [&]() -> awaitable<void> {
        // Connect all clients
        co_await sub1.connect("127.0.0.1", port, "test.realm");
        co_await sub2.connect("127.0.0.1", port, "test.realm");
        co_await pub.connect("127.0.0.1", port, "test.realm");

        // Subscribe both
        co_await sub1.subscribe("com.test.multi", [&](const EventMessage&) {
            events_received++;
        });

        co_await sub2.subscribe("com.test.multi", [&](const EventMessage&) {
            events_received++;
        });

        // Small delay
        boost::asio::steady_timer timer{io};
        timer.expires_after(std::chrono::milliseconds(100));
        co_await timer.async_wait(use_awaitable);

        // Publish
        co_await pub.publish("com.test.multi", false);

        // Wait for events
        timer.expires_after(std::chrono::milliseconds(500));
        co_await timer.async_wait(use_awaitable);

        // Cleanup
        co_await sub1.disconnect();
        co_await sub2.disconnect();
        co_await pub.disconnect();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(events_received == 2);
}

TEST_CASE("WampClient - Error handling for non-existent procedure", "[wamp_client]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();

    // Start server
    WampServer server{io, port, config};
    server.start();

    WampClient client{io};

    bool error_caught = false;

    co_spawn(io, [&]() -> awaitable<void> {
        // Connect
        co_await client.connect("127.0.0.1", port, "test.realm");

        // Try to call a non-existent procedure - should get ERROR
        try {
            co_await client.call("com.example.nonexistent");
        } catch (const std::runtime_error& e) {
            error_caught = true;
            spdlog::info("Caught expected error: {}", e.what());
        }

        // Cleanup
        co_await client.disconnect();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(error_caught);
}

// ============================================================================
// Payloads, unsubscribe/unregister and error propagation
// ============================================================================

namespace {
awaitable<void> sleep_ms(io_context& io, int ms) {
    boost::asio::steady_timer timer{io};
    timer.expires_after(std::chrono::milliseconds(ms));
    co_await timer.async_wait(use_awaitable);
}
}  // namespace

TEST_CASE("WampClient - RPC arguments round trip", "[wamp_client][payload]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();
    WampServer server{io, port, config};
    server.start();

    WampClient callee{io};
    WampClient caller{io};

    const WampList sent{std::string{"abc"}, int64_t{7}, true};
    const WampDict sent_kw{{"unit", std::string{"ms"}}};

    WampList seen_args;
    WampDict seen_kw;
    ResultMessage result{0, {}};
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await callee.connect("127.0.0.1", port, "test.realm");
        co_await caller.connect("127.0.0.1", port, "test.realm");

        co_await callee.register_procedure(
            "proto.client.echo",
            [&](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                seen_args = inv.arguments;
                seen_kw = inv.arguments_kw;
                co_return YieldMessage{inv.request_id, {}, inv.arguments, inv.arguments_kw};
            });

        result = co_await caller.call_result("proto.client.echo", sent, sent_kw);
        done = true;

        co_await callee.disconnect();
        co_await caller.disconnect();
        io.stop();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(done);
    REQUIRE(seen_args == sent);
    REQUIRE(seen_kw.size() == 1);
    REQUIRE(result.arguments == sent);
    REQUIRE(result.arguments_kw.size() == 1);
}

TEST_CASE("WampClient - PubSub payload, unsubscribe and exclude_me", "[wamp_client][payload]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();
    WampServer server{io, port, config};
    server.start();

    WampClient sub{io};
    WampClient pub{io};

    const WampList sent{std::string{"hello"}, int64_t{42}};
    int sub_events = 0;
    int pub_events = 0;
    WampList last_args;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await sub.connect("127.0.0.1", port, "test.realm");
        co_await pub.connect("127.0.0.1", port, "test.realm");

        auto sub_id = co_await sub.subscribe("proto.client.topic", [&](const EventMessage& ev) {
            sub_events++;
            last_args = ev.arguments;
        });
        co_await pub.subscribe("proto.client.topic", [&](const EventMessage&) { pub_events++; });
        co_await sleep_ms(io, 50);

        // Default: publisher doesn't get its own event; subscriber gets the payload
        co_await pub.publish("proto.client.topic", sent);
        co_await sleep_ms(io, 100);
        // exclude_me=false: publisher receives it too
        co_await pub.publish("proto.client.topic", sent, {}, false, false);
        co_await sleep_ms(io, 100);

        co_await sub.unsubscribe(sub_id);
        co_await pub.publish("proto.client.topic", sent, {}, false, false);
        co_await sleep_ms(io, 100);
        done = true;

        co_await sub.disconnect();
        co_await pub.disconnect();
        io.stop();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(done);
    REQUIRE(last_args == sent);
    REQUIRE(sub_events == 2);   // third publish came after unsubscribe
    REQUIRE(pub_events == 2);   // second and third (exclude_me=false) publishes
}

TEST_CASE("WampClient - unregister removes the procedure", "[wamp_client][payload]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();
    WampServer server{io, port, config};
    server.start();

    WampClient callee{io};
    WampClient caller{io};

    std::string error_uri;
    bool first_call_ok = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await callee.connect("127.0.0.1", port, "test.realm");
        co_await caller.connect("127.0.0.1", port, "test.realm");

        auto reg_id = co_await callee.register_procedure(
            "proto.client.gone",
            [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                co_return YieldMessage{inv.request_id, {}};
            });

        (void)co_await caller.call("proto.client.gone");
        first_call_ok = true;

        co_await callee.unregister(reg_id);

        try {
            (void)co_await caller.call("proto.client.gone");
        } catch (const WampException& e) {
            error_uri = e.error_uri;
        }

        co_await callee.disconnect();
        co_await caller.disconnect();
        io.stop();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(first_call_ok);
    REQUIRE(error_uri == "wamp.error.no_such_procedure");
}

TEST_CASE("WampClient - callee errors reach the caller", "[wamp_client][payload]") {
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();
    WampServer server{io, port, config};
    server.start();

    WampClient callee{io};
    WampClient caller{io};

    std::string custom_uri;
    WampList custom_args;
    std::string generic_uri;
    std::string bad_unsubscribe_uri;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await callee.connect("127.0.0.1", port, "test.realm");
        co_await caller.connect("127.0.0.1", port, "test.realm");

        co_await callee.register_procedure(
            "proto.client.custom_error",
            [](const InvocationMessage&) -> awaitable<YieldMessage> {
                throw WampException{"app.error.nope", {{"message", std::string{"denied"}}},
                                    WampList{std::string{"detail"}}};
                co_return YieldMessage{0, {}};
            });
        co_await callee.register_procedure(
            "proto.client.generic_error",
            [](const InvocationMessage&) -> awaitable<YieldMessage> {
                throw std::runtime_error("kaboom");
                co_return YieldMessage{0, {}};
            });

        try {
            (void)co_await caller.call("proto.client.custom_error");
        } catch (const WampException& e) {
            custom_uri = e.error_uri;
            custom_args = e.arguments;
        }

        try {
            (void)co_await caller.call("proto.client.generic_error");
        } catch (const WampException& e) {
            generic_uri = e.error_uri;
        }

        try {
            co_await caller.unsubscribe(123456789);
        } catch (const WampException& e) {
            bad_unsubscribe_uri = e.error_uri;
        }
        done = true;

        co_await callee.disconnect();
        co_await caller.disconnect();
        io.stop();
    }, detached);

    io.run_for(std::chrono::seconds(3));

    REQUIRE(done);
    REQUIRE(custom_uri == "app.error.nope");
    REQUIRE(custom_args == WampList{std::string{"detail"}});
    REQUIRE(generic_uri == "wamp.error.callee_failure");
    REQUIRE(bad_unsubscribe_uri == "wamp.error.no_such_subscription");
}

TEST_CASE("WampClient - many concurrent callers share one callee", "[wamp_client][payload]") {
    // Regression: concurrent invocation handlers used to interleave socket writes, and the router
    // could drop an INVOCATION when a read and a channel event completed together.
    io_context io;
    ServerConfig config;
    uint16_t port = find_available_port();
    WampServer server{io, port, config};
    server.start();

    constexpr size_t kCallers = 8;
    constexpr size_t kCallsEach = 40;

    WampClient callee{io};
    std::vector<std::unique_ptr<WampClient>> callers;
    for (size_t i = 0; i < kCallers; ++i) {
        callers.push_back(std::make_unique<WampClient>(io));
    }

    size_t ok = 0;
    size_t failed = 0;
    size_t running = kCallers;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await callee.connect("127.0.0.1", port, "test.realm");
        co_await callee.register_procedure(
            "proto.client.concurrent",
            [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                co_return YieldMessage{inv.request_id, {}, inv.arguments};
            });

        for (auto& caller : callers) {
            co_await caller->connect("127.0.0.1", port, "test.realm");
        }
        for (auto& caller : callers) {
            co_spawn(io, [&, c = caller.get()]() -> awaitable<void> {
                for (size_t i = 0; i < kCallsEach; ++i) {
                    try {
                        (void)co_await c->call("proto.client.concurrent", WampList{int64_t(i)});
                        ++ok;
                    } catch (const std::exception&) {
                        ++failed;
                    }
                }
                --running;
            }, detached);
        }

        while (running > 0) {
            co_await sleep_ms(io, 5);
        }
        co_await callee.disconnect();
        for (auto& caller : callers) {
            co_await caller->disconnect();
        }
        io.stop();
    }, detached);

    io.run_for(std::chrono::seconds(10));

    REQUIRE(running == 0);
    REQUIRE(failed == 0);
    REQUIRE(ok == kCallers * kCallsEach);
}

namespace {

// Unpaced burst of fire-and-forget PUBLISHes into a tiny subscriber queue.
// Returns {delivered, dropped}.
std::pair<size_t, uint64_t> run_burst(OverflowPolicy policy, size_t queue_size, size_t burst) {
    io_context io;
    ServerConfig config;
    config.events.size = queue_size;
    config.events.overflow = policy;
    config.events.backpressure_timeout = std::chrono::milliseconds{3000};
    uint16_t port = find_available_port();
    WampServer server{io, port, config};   // applies config.events to the channel registry
    server.start();
    EventChannelRegistry::reset_dropped_count();

    WampClient sub{io};
    WampClient pub{io};
    size_t delivered = 0;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await sub.connect("127.0.0.1", port, "test.realm");
        co_await pub.connect("127.0.0.1", port, "test.realm");
        co_await sub.subscribe("proto.client.burst", [&](const EventMessage&) { ++delivered; });
        co_await sleep_ms(io, 50);

        for (size_t i = 0; i < burst; ++i) {
            (void)co_await pub.publish("proto.client.burst", WampList{int64_t(i)});
        }

        // Every event ends up either delivered or counted as dropped
        for (int i = 0; i < 300 && delivered + EventChannelRegistry::dropped_count() < burst; ++i) {
            co_await sleep_ms(io, 10);
        }
        co_await pub.disconnect();
        co_await sub.disconnect();
        io.stop();
    }, detached);

    io.run_for(std::chrono::seconds(8));
    auto result = std::make_pair(delivered, EventChannelRegistry::dropped_count());
    EventChannelRegistry::configure({});
    return result;
}

}  // namespace

TEST_CASE("Backpressure delivers every event through a tiny queue", "[wamp_client][events]") {
    constexpr size_t kBurst = 2000;
    auto [delivered, dropped] = run_burst(OverflowPolicy::BACKPRESSURE, 4, kBurst);

    REQUIRE(dropped == 0);
    REQUIRE(delivered == kBurst);
}

TEST_CASE("DROP policy accounts for every event", "[wamp_client][events]") {
    constexpr size_t kBurst = 2000;
    auto [delivered, dropped] = run_burst(OverflowPolicy::DROP, 4, kBurst);

    REQUIRE(delivered + dropped == kBurst);
}

TEST_CASE("WampClient - Call to an unresponsive callee times out", "[wamp_client][timeout]") {
    io_context io;
    ServerConfig config;
    config.call_timeout = std::chrono::milliseconds{200};
    uint16_t port = find_available_port();

    WampServer server{io, port, config};
    server.start();

    WampClient callee{io};
    WampClient caller{io};
    std::string error_uri;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await callee.connect("127.0.0.1", port, "test.realm");
        co_await caller.connect("127.0.0.1", port, "test.realm");

        co_await callee.register_procedure(
            "com.example.hang",
            [&](const InvocationMessage& invocation) -> awaitable<YieldMessage> {
                boost::asio::steady_timer t{io};
                t.expires_after(std::chrono::seconds(5));
                co_await t.async_wait(use_awaitable);
                co_return YieldMessage{invocation.request_id, {}};
            });

        try {
            co_await caller.call("com.example.hang");
        } catch (const WampException& e) {
            error_uri = e.error_uri;
        }
        io.stop();
    }, detached);

    io.run_for(std::chrono::seconds(3));
    REQUIRE(error_uri == "wamp.error.timeout");
}
