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
#include <numeric>
#include "include/router.hpp"
#include "include/wamp_client.hpp"

using namespace wamp;
using namespace std::chrono_literals;
using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;

namespace {

ServerConfig plain_config() {
    ServerConfig config;
    config.port = 0;  // any free port
    config.max_pending_invocations = 1000;
    return config;
}

awaitable<void> pause(asio::io_context& io, std::chrono::milliseconds d) {
    asio::steady_timer timer{io};
    timer.expires_after(d);
    co_await timer.async_wait(use_awaitable);
}

// Create the default logger before any router thread can log (spdlog creates it lazily on first use)
[[maybe_unused]] const bool kLoggerReady = (wamp::logging::init({spdlog::level::off, false, 8192, ""}), true);

}  // namespace

TEST_CASE("Router spreads connections over its shards", "[router]") {
    Router router{plain_config(), Router::Transport::PLAIN, 3};
    router.start();
    REQUIRE(router.shard_count() == 3);

    asio::io_context io;
    constexpr size_t kClients = 12;
    std::vector<std::unique_ptr<WampClient>> clients;
    for (size_t i = 0; i < kClients; ++i) clients.push_back(std::make_unique<WampClient>(io));

    size_t connected = 0;
    std::vector<size_t> during;
    co_spawn(io, [&]() -> awaitable<void> {
        for (auto& client : clients) {
            co_await client->connect("127.0.0.1", router.port(), "test.realm");
            ++connected;
        }
        during = router.sessions_per_shard();
        for (auto& client : clients) co_await client->disconnect();
    }, detached);
    io.run_for(5s);

    REQUIRE(connected == kClients);
    REQUIRE(during == std::vector<size_t>{4, 4, 4});  // least-loaded assignment is exact for a sequential burst

    auto accepted = router.accepted_per_shard();
    REQUIRE(std::accumulate(accepted.begin(), accepted.end(), uint64_t{0}) == kClients);

    // sessions end when the clients disconnect
    for (int i = 0; i < 100; ++i) {
        auto counts = router.sessions_per_shard();
        if (std::accumulate(counts.begin(), counts.end(), size_t{0}) == 0) break;
        std::this_thread::sleep_for(20ms);
    }
    auto counts = router.sessions_per_shard();
    REQUIRE(std::accumulate(counts.begin(), counts.end(), size_t{0}) == 0);
}

TEST_CASE("Self-contained sessions work on every shard", "[router]") {
    // Each client registers a procedure and subscribes to a topic of its own and uses them itself, so it
    // never needs a session on another shard.
    Router router{plain_config(), Router::Transport::PLAIN, 4};
    router.start();

    asio::io_context io;
    constexpr size_t kClients = 16;
    std::vector<std::unique_ptr<WampClient>> clients;
    for (size_t i = 0; i < kClients; ++i) clients.push_back(std::make_unique<WampClient>(io));

    std::vector<int> results(kClients, 0);
    std::vector<int> events(kClients, 0);
    size_t finished = 0;

    for (size_t i = 0; i < kClients; ++i) {
        co_spawn(io, [&, i]() -> awaitable<void> {
            auto& c = *clients[i];
            const std::string name = "self." + std::to_string(i);
            co_await c.connect("127.0.0.1", router.port(), "test.realm");
            co_await c.register_procedure(name,
                [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                    co_return YieldMessage{inv.request_id, {}, inv.arguments, inv.arguments_kw};
                });
            co_await c.subscribe(name, [&events, i](const EventMessage&) { ++events[i]; });

            for (int n = 0; n < 20; ++n) {
                auto result = co_await c.call_result(name, WampList{int64_t{n}});
                if (!result.arguments.empty() && std::get<int64_t>(result.arguments[0]) == n) ++results[i];
                (void)co_await c.publish(name, WampList{int64_t{n}}, {}, /*acknowledge=*/true, /*exclude_me=*/false);
            }
            co_await pause(io, 100ms);
            co_await c.disconnect();
            ++finished;
        }, detached);
    }
    io.run_for(10s);

    REQUIRE(finished == kClients);
    for (size_t i = 0; i < kClients; ++i) {
        REQUIRE(results[i] == 20);
        REQUIRE(events[i] == 20);
    }

    // all four shards did work
    auto accepted = router.accepted_per_shard();
    REQUIRE(accepted == std::vector<uint64_t>{4, 4, 4, 4});
}

TEST_CASE("One thread routes between sessions like WampServer", "[router]") {
    Router router{plain_config(), Router::Transport::PLAIN, 1};
    router.start();

    asio::io_context io;
    WampClient callee{io};
    WampClient caller{io};
    WampClient subscriber{io};
    WampClient publisher{io};
    int events = 0;
    int64_t answer = 0;

    co_spawn(io, [&]() -> awaitable<void> {
        for (auto* c : {&callee, &caller, &subscriber, &publisher}) {
            co_await c->connect("127.0.0.1", router.port(), "test.realm");
        }
        co_await callee.register_procedure("com.example.double",
            [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                co_return YieldMessage{inv.request_id, {}, WampList{std::get<int64_t>(inv.arguments.at(0)) * 2}};
            });
        co_await subscriber.subscribe("com.example.topic", [&](const EventMessage&) { ++events; });

        auto result = co_await caller.call("com.example.double", WampList{int64_t{21}});
        answer = std::get<int64_t>(result.at(0));
        (void)co_await publisher.publish("com.example.topic", true);
        co_await pause(io, 100ms);

        for (auto* c : {&callee, &caller, &subscriber, &publisher}) co_await c->disconnect();
    }, detached);
    io.run_for(5s);

    REQUIRE(answer == 42);
    REQUIRE(events == 1);
}

TEST_CASE("Router stops cleanly with sessions still open", "[router]") {
    auto router = std::make_unique<Router>(plain_config(), Router::Transport::PLAIN, 2);
    router->start();

    asio::io_context io;
    std::vector<std::unique_ptr<WampClient>> clients;
    for (int i = 0; i < 6; ++i) clients.push_back(std::make_unique<WampClient>(io));
    size_t connected = 0;
    co_spawn(io, [&]() -> awaitable<void> {
        for (auto& client : clients) {
            co_await client->connect("127.0.0.1", router->port(), "test.realm");
            ++connected;
        }
    }, detached);
    io.run_for(2s);
    REQUIRE(connected == 6);

    router->stop();
    router->stop();   // idempotent
    router.reset();   // and destroying it afterwards is fine
    SUCCEED();
}

TEST_CASE("threads = 0 means one shard per available CPU", "[router][cpu_limits]") {
    Router router{plain_config(), Router::Transport::PLAIN, 0};
    REQUIRE(router.shard_count() == detect_cpu_limits().available);
}

TEST_CASE("Pub/sub reaches subscribers on every shard, in order", "[router][crossshard]") {
    Router router{plain_config(), Router::Transport::PLAIN, 4};
    router.start();

    asio::io_context io;
    constexpr size_t kClients = 8;  // sequential connects spread two per shard; client 0 (the publisher) is on shard 0
    std::vector<std::unique_ptr<WampClient>> clients;
    for (size_t i = 0; i < kClients; ++i) clients.push_back(std::make_unique<WampClient>(io));
    std::vector<std::vector<int64_t>> received(kClients);
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        for (auto& c : clients) co_await c->connect("127.0.0.1", router.port(), "test.realm");
        for (size_t i = 1; i < kClients; ++i) {
            co_await clients[i]->subscribe("cross.topic", [&received, i](const EventMessage& e) {
                received[i].push_back(std::get<int64_t>(e.arguments.at(0)));
            });
        }
        for (int64_t n = 0; n < 50; ++n) {
            (void)co_await clients[0]->publish("cross.topic", WampList{n}, {}, /*acknowledge=*/true);
        }
        co_await pause(io, 300ms);
        for (auto& c : clients) co_await c->disconnect();
        done = true;
    }, detached);
    io.run_for(10s);

    REQUIRE(done);
    REQUIRE(router.accepted_per_shard() == std::vector<uint64_t>{2, 2, 2, 2});
    std::vector<int64_t> expected(50);
    std::iota(expected.begin(), expected.end(), 0);
    for (size_t i = 1; i < kClients; ++i) {
        REQUIRE(received[i] == expected);  // every event, none duplicated, publisher's order kept
    }
    REQUIRE(router.dropped_events() == 0);
}

TEST_CASE("Cross-shard interest follows subscribe, unsubscribe and disconnect", "[router][crossshard]") {
    Router router{plain_config(), Router::Transport::PLAIN, 2};
    router.start();

    asio::io_context io;
    WampClient publisher{io};   // shard 0
    WampClient subscriber{io};  // shard 1
    WampClient other_realm{io}; // shard 0
    int events = 0;
    int other = 0;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await publisher.connect("127.0.0.1", router.port(), "test.realm");
        co_await subscriber.connect("127.0.0.1", router.port(), "test.realm");
        co_await other_realm.connect("127.0.0.1", router.port(), "another.realm");
        REQUIRE(router.accepted_per_shard() == std::vector<uint64_t>{2, 1});

        co_await other_realm.subscribe("cross.t", [&](const EventMessage&) { ++other; });  // same topic name, other realm

        (void)co_await publisher.publish("cross.t", true);     // nobody listening on the other shard yet
        co_await pause(io, 50ms);
        REQUIRE(events == 0);

        auto sub = co_await subscriber.subscribe("cross.t", [&](const EventMessage&) { ++events; });
        (void)co_await publisher.publish("cross.t", true);     // SUBSCRIBED came back, so this one must arrive
        co_await pause(io, 50ms);
        REQUIRE(events == 1);

        co_await subscriber.unsubscribe(sub);
        (void)co_await publisher.publish("cross.t", true);
        co_await pause(io, 50ms);
        REQUIRE(events == 1);

        (void)co_await subscriber.subscribe("cross.t", [&](const EventMessage&) { ++events; });
        (void)co_await publisher.publish("cross.t", true);
        co_await pause(io, 50ms);
        REQUIRE(events == 2);

        co_await subscriber.disconnect();                      // interest must be withdrawn on disconnect too
        co_await pause(io, 50ms);
        (void)co_await publisher.publish("cross.t", true);
        co_await pause(io, 50ms);
        REQUIRE(events == 2);

        REQUIRE(other == 0);                                   // realms stay isolated across shards
        co_await publisher.disconnect();
        co_await other_realm.disconnect();
        done = true;
    }, detached);
    io.run_for(10s);
    REQUIRE(done);
}

TEST_CASE("A fast publisher is slowed by a subscriber on another shard instead of losing events", "[router][crossshard]") {
    Router router{plain_config(), Router::Transport::PLAIN, 2};
    router.start();

    asio::io_context io;
    WampClient publisher{io};   // shard 0
    WampClient subscriber{io};  // shard 1
    constexpr int kEvents = 30000;
    int received = 0;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await publisher.connect("127.0.0.1", router.port(), "test.realm");
        co_await subscriber.connect("127.0.0.1", router.port(), "test.realm");
        co_await subscriber.subscribe("flood", [&](const EventMessage&) { ++received; });
        for (int n = 0; n < kEvents; ++n) {
            (void)co_await publisher.publish("flood", WampList{int64_t{n}}, {}, /*acknowledge=*/false);
        }
        for (int i = 0; i < 100 && received < kEvents; ++i) co_await pause(io, 50ms);
        co_await publisher.disconnect();
        co_await subscriber.disconnect();
        done = true;
    }, detached);
    io.run_for(30s);

    REQUIRE(done);
    REQUIRE(router.dropped_events() == 0);
    REQUIRE(received == kEvents);
}

TEST_CASE("RPC works between sessions on different shards", "[router][crossshard][rpc]") {
    Router router{plain_config(), Router::Transport::PLAIN, 4};
    router.start();

    asio::io_context io;
    constexpr size_t kClients = 8;  // two per shard; client 0 is the callee (shard 0)
    std::vector<std::unique_ptr<WampClient>> clients;
    for (size_t i = 0; i < kClients; ++i) clients.push_back(std::make_unique<WampClient>(io));
    std::vector<int> ok(kClients, 0);
    std::string error_uri;
    std::string duplicate_uri;
    std::string missing_uri;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        for (auto& c : clients) co_await c->connect("127.0.0.1", router.port(), "test.realm");
        auto reg = co_await clients[0]->register_procedure("cross.double",
            [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                co_return YieldMessage{inv.request_id, {}, WampList{std::get<int64_t>(inv.arguments.at(0)) * 2}};
            });
        (void)co_await clients[0]->register_procedure("cross.fail",
            [](const InvocationMessage&) -> awaitable<YieldMessage> {
                throw WampException{"com.example.error.bad"};
                co_return YieldMessage{0, {}};
            });

        // every other client calls it, from all shards
        for (size_t i = 1; i < kClients; ++i) {
            for (int64_t n = 0; n < 20; ++n) {
                auto result = co_await clients[i]->call("cross.double", WampList{n});
                if (std::get<int64_t>(result.at(0)) == n * 2) ++ok[i];
            }
        }

        try { (void)co_await clients[3]->call("cross.fail"); } catch (const WampException& e) { error_uri = e.error_uri; }
        try {   // one procedure, one callee, across all shards
            (void)co_await clients[5]->register_procedure("cross.double",
                [](const InvocationMessage& inv) -> awaitable<YieldMessage> { co_return YieldMessage{inv.request_id, {}}; });
        } catch (const WampException& e) { duplicate_uri = e.error_uri; }

        co_await clients[0]->unregister(reg);
        try { (void)co_await clients[2]->call("cross.double", WampList{int64_t{1}}); }
        catch (const WampException& e) { missing_uri = e.error_uri; }

        for (auto& c : clients) co_await c->disconnect();
        done = true;
    }, detached);
    io.run_for(15s);

    REQUIRE(done);
    for (size_t i = 1; i < kClients; ++i) REQUIRE(ok[i] == 20);
    REQUIRE(error_uri == "com.example.error.bad");
    REQUIRE(duplicate_uri == "wamp.error.procedure_already_exists");
    REQUIRE(missing_uri == "wamp.error.no_such_procedure");
}

TEST_CASE("Cross-shard calls fail cleanly when the callee disconnects or is too slow", "[router][crossshard][rpc]") {
    Router router{plain_config(), Router::Transport::PLAIN, 2};
    router.start();

    asio::io_context io;
    WampClient callee{io};   // shard 0
    WampClient caller{io};   // shard 1
    std::string disconnect_uri;
    std::string timeout_uri;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await callee.connect("127.0.0.1", router.port(), "test.realm");
        co_await caller.connect("127.0.0.1", router.port(), "test.realm");
        REQUIRE(router.accepted_per_shard() == std::vector<uint64_t>{1, 1});

        (void)co_await callee.register_procedure("cross.slow",
            [&io](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                co_await pause(io, 60s);   // never answers within the test
                co_return YieldMessage{inv.request_id, {}};
            });

        try { (void)co_await caller.call("cross.slow", {}, {}, 300ms); }
        catch (const WampException& e) { timeout_uri = e.error_uri; }

        // a call in flight when the callee goes away
        co_spawn(io, [&]() -> awaitable<void> {
            co_await pause(io, 200ms);
            co_await callee.disconnect();
        }, detached);
        try { (void)co_await caller.call("cross.slow"); }
        catch (const WampException& e) { disconnect_uri = e.error_uri; }

        co_await caller.disconnect();
        done = true;
    }, detached);
    io.run_for(15s);

    REQUIRE(done);
    REQUIRE(timeout_uri == "wamp.error.timeout");
    REQUIRE(disconnect_uri == "wamp.error.callee_failure");
}

TEST_CASE("A caller that disconnects cancels its call on the callee's shard", "[router][crossshard][rpc]") {
    Router router{plain_config(), Router::Transport::PLAIN, 2};
    router.start();

    asio::io_context io;
    WampClient callee{io};   // shard 0
    WampClient caller{io};   // shard 1
    bool started = false;
    bool interrupted = false;
    bool cancelled = false;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await callee.connect("127.0.0.1", router.port(), "test.realm");
        co_await caller.connect("127.0.0.1", router.port(), "test.realm");
        REQUIRE(router.accepted_per_shard() == std::vector<uint64_t>{1, 1});

        (void)co_await callee.register_procedure("cross.hang",
            [&](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                struct Guard { bool& flag; ~Guard() { flag = true; } } guard{interrupted};
                started = true;
                co_await pause(io, 60s);   // only an INTERRUPT ends this early
                co_return YieldMessage{inv.request_id, {}};
            });

        co_spawn(io, [&]() -> awaitable<void> {
            try { (void)co_await caller.call("cross.hang"); } catch (const std::exception&) {}
        }, detached);
        for (int i = 0; i < 100 && !started; ++i) co_await pause(io, 20ms);
        co_await caller.disconnect();
        for (int i = 0; i < 100 && !interrupted; ++i) co_await pause(io, 20ms);
        cancelled = interrupted;   // before the callee's own disconnect can end the handler

        co_await callee.disconnect();
        done = true;
    }, detached);
    io.run_for(15s);

    REQUIRE(done);
    REQUIRE(started);
    REQUIRE(cancelled);
}

TEST_CASE("Router::stats() counts work per shard and stop() leaves the inboxes empty", "[router][crossshard]") {
    Router router{plain_config(), Router::Transport::PLAIN, 2};
    router.start();

    asio::io_context io;
    WampClient publisher{io};   // shard 0
    WampClient subscriber{io};  // shard 1
    constexpr int kEvents = 500;
    int received = 0;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await publisher.connect("127.0.0.1", router.port(), "test.realm");
        co_await subscriber.connect("127.0.0.1", router.port(), "test.realm");
        co_await subscriber.subscribe("stats.t", [&](const EventMessage&) { ++received; });
        for (int n = 0; n < kEvents; ++n) {
            (void)co_await publisher.publish("stats.t", WampList{int64_t{n}}, {}, /*acknowledge=*/false);
        }
        try { (void)co_await publisher.call("no.such.procedure"); } catch (const WampException&) {}
        for (int i = 0; i < 100 && received < kEvents; ++i) co_await pause(io, 20ms);
        done = true;
    }, detached);
    io.run_for(10s);
    REQUIRE(done);

    const auto stats = router.stats();
    REQUIRE(stats.size() == 2);
    REQUIRE(stats[0].accepted == 1);
    REQUIRE(stats[1].accepted == 1);
    REQUIRE(stats[0].publishes == kEvents);
    REQUIRE(stats[1].publishes == 0);
    REQUIRE(stats[0].calls == 1);
    REQUIRE(stats[1].inbox_received == kEvents);
    REQUIRE(stats[1].inbox_dropped == 0);
    router.stop();
    REQUIRE(router.stats()[1].inbox_depth == 0);
}

TEST_CASE("stop() delivers cross-shard messages that are still queued", "[router][crossshard]") {
    Router router{plain_config(), Router::Transport::PLAIN, 2};
    router.start();

    asio::io_context io;
    WampClient publisher{io};   // shard 0
    WampClient subscriber{io};  // shard 1
    constexpr int kEvents = 2000;   // below the high-water mark, so the publisher is never slowed
    bool published = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await publisher.connect("127.0.0.1", router.port(), "test.realm");
        co_await subscriber.connect("127.0.0.1", router.port(), "test.realm");
        co_await subscriber.subscribe("drain.t", [](const EventMessage&) {});

        router.post_to_shard(1, [] { std::this_thread::sleep_for(1s); });   // shard 1 cannot drain its inbox
        for (int n = 0; n < kEvents; ++n) {
            (void)co_await publisher.publish("drain.t", WampList{int64_t{n}}, {}, /*acknowledge=*/false);
        }
        published = true;
        io.stop();
    }, detached);
    io.run_for(10s);
    REQUIRE(published);
    for (int i = 0; i < 20 && router.stats()[0].publishes < kEvents; ++i) std::this_thread::sleep_for(10ms);

    const auto before = router.stats();
    REQUIRE(before[0].publishes == kEvents);
    REQUIRE(before[1].inbox_depth > 0);   // still queued behind the stalled shard

    router.stop();                        // must wait for them
    const auto after = router.stats();
    CHECK(after[1].inbox_received == kEvents);
    CHECK(after[1].inbox_depth == 0);
    CHECK(after[1].inbox_dropped == 0);
}

// ---------------------------------------------------------------------------------------------------
// WebSocket (wamp.2.cbor) on the same port
// ---------------------------------------------------------------------------------------------------
#include "tests/ws_test_client.hpp"
#include <filesystem>

namespace {

using wamp::test::WsTestClient;
using wamp::test::WsFrame;

// Upgrade, HELLO, WELCOME; returns false on any deviation
bool ws_join(WsTestClient& ws, unsigned short port, const std::string& realm = "test.realm") {
    if (ws.connect(port).find("101 Switching Protocols") == std::string::npos) return false;
    ws.send_binary(serialize_hello(HelloMessage{realm}));
    auto reply = ws.read_frame();
    if (!reply || reply->opcode != 0x2) return false;
    auto type = get_message_type_from_cbor(reply->payload);
    return type.has_value() && *type == MessageType::WELCOME;
}

// Next binary WAMP message of a given type, skipping nothing: the frame must be exactly that
std::optional<std::vector<uint8_t>> ws_expect(WsTestClient& ws, MessageType expected) {
    auto frame = ws.read_frame();
    if (!frame || frame->opcode != 0x2) return std::nullopt;
    auto type = get_message_type_from_cbor(frame->payload);
    if (!type || *type != expected) return std::nullopt;
    return std::move(frame->payload);
}

}  // namespace

TEST_CASE("WebSocket upgrade negotiates wamp.2.cbor and the session works", "[router][websocket]") {
    Router router{plain_config(), Router::Transport::PLAIN, 1};
    router.start();

    WsTestClient ws;
    const auto head = ws.connect(router.port());
    CHECK(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    CHECK(head.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != std::string::npos);
    CHECK(head.find("Sec-WebSocket-Protocol: wamp.2.cbor\r\n") != std::string::npos);

    ws.send_binary(serialize_hello(HelloMessage{"test.realm"}));
    REQUIRE(ws_expect(ws, MessageType::WELCOME));

    ws.send_binary(serialize_subscribe(SubscribeMessage{7, {}, "ws.topic"}));
    auto subscribed = ws_expect(ws, MessageType::SUBSCRIBED);
    REQUIRE(subscribed);
    CHECK(deserialize_subscribed(*subscribed)->request_id == 7);

    // acknowledged publish from the same session, excluded from its own events by default
    ws.send_binary(serialize_publish(PublishMessage{8, {{"acknowledge", true}}, "ws.topic", {std::string{"x"}}}));
    REQUIRE(ws_expect(ws, MessageType::PUBLISHED));
}

TEST_CASE("WebSocket and RawSocket sessions exchange pub/sub and RPC, across shards", "[router][websocket][crossshard]") {
    Router router{plain_config(), Router::Transport::PLAIN, 2};
    router.start();

    WsTestClient ws;                 // first connection: shard 0
    REQUIRE(ws_join(ws, router.port()));
    ws.send_binary(serialize_subscribe(SubscribeMessage{1, {}, "mixed.topic"}));
    REQUIRE(ws_expect(ws, MessageType::SUBSCRIBED));

    asio::io_context io;
    WampClient raw{io};              // second connection: shard 1
    std::vector<std::string> raw_events;
    std::string rpc_result;
    bool done = false;

    co_spawn(io, [&]() -> awaitable<void> {
        co_await raw.connect("127.0.0.1", router.port(), "test.realm");
        REQUIRE(router.accepted_per_shard() == std::vector<uint64_t>{1, 1});

        co_await raw.subscribe("mixed.raw", [&](const EventMessage& e) { raw_events.push_back(std::get<std::string>(e.arguments.at(0))); });
        (void)co_await raw.register_procedure("mixed.echo",
            [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
                co_return YieldMessage{inv.request_id, {}, inv.arguments};
            });

        // RawSocket -> WebSocket event
        (void)co_await raw.publish("mixed.topic", WampList{std::string{"from raw"}});

        // WebSocket -> RawSocket event, and a WebSocket CALL answered by the RawSocket callee
        ws.send_binary(serialize_publish(PublishMessage{2, {}, "mixed.raw", {std::string{"from ws"}}}));
        ws.send_binary(serialize_call(CallMessage{3, {}, "mixed.echo", {std::string{"ping"}}}));
        co_await pause(io, 300ms);
        done = true;
    }, detached);
    io.run_for(10s);
    REQUIRE(done);

    auto event = ws_expect(ws, MessageType::EVENT);
    REQUIRE(event);
    CHECK(std::get<std::string>(deserialize_event(*event)->arguments.at(0)) == "from raw");
    auto result = ws_expect(ws, MessageType::RESULT);
    REQUIRE(result);
    CHECK(std::get<std::string>(deserialize_result(*result)->arguments.at(0)) == "ping");
    REQUIRE(raw_events.size() == 1);
    CHECK(raw_events[0] == "from ws");
}

TEST_CASE("WebSocket control frames, fragmentation and the close handshake", "[router][websocket]") {
    Router router{plain_config(), Router::Transport::PLAIN, 1};
    router.start();

    SECTION("ping is answered with a pong carrying the same payload") {
        WsTestClient ws;
        REQUIRE(ws_join(ws, router.port()));
        const std::vector<uint8_t> payload{1, 2, 3};
        ws.send(0x9, payload);
        auto pong = ws.read_frame();
        REQUIRE(pong);
        CHECK(pong->opcode == 0xA);
        CHECK(pong->payload == payload);
    }
    SECTION("a message split into fragments, with a ping in between") {
        WsTestClient ws;
        REQUIRE(ws.connect(router.port()).find("101") != std::string::npos);
        const auto hello = serialize_hello(HelloMessage{"test.realm"});
        const auto half = hello.size() / 2;
        ws.send(0x2, std::span{hello}.first(half), /*fin=*/false);
        ws.send(0x9, {});
        ws.send(0x0, std::span{hello}.subspan(half), /*fin=*/true);
        auto pong = ws.read_frame();
        REQUIRE(pong);
        CHECK(pong->opcode == 0xA);
        REQUIRE(ws_expect(ws, MessageType::WELCOME));
    }
    SECTION("frames split across TCP writes") {
        WsTestClient ws;
        REQUIRE(ws.connect(router.port()).find("101") != std::string::npos);
        const auto bytes = WsTestClient::frame(0x2, serialize_hello(HelloMessage{"test.realm"}));
        for (uint8_t b : bytes) {
            ws.send_raw({&b, 1});
            std::this_thread::sleep_for(1ms);
        }
        REQUIRE(ws_expect(ws, MessageType::WELCOME));
    }
    SECTION("the client's close frame is echoed and the connection closed") {
        WsTestClient ws;
        REQUIRE(ws_join(ws, router.port()));
        ws.send(0x8, std::vector<uint8_t>{0x03, 0xE8});
        auto close = ws.read_frame();
        REQUIRE(close);
        CHECK(close->opcode == 0x8);
        CHECK(close->payload == std::vector<uint8_t>{0x03, 0xE8});
        CHECK(ws.closed_by_peer());
    }
    SECTION("WAMP GOODBYE is answered, then the router closes the WebSocket") {
        WsTestClient ws;
        REQUIRE(ws_join(ws, router.port()));
        ws.send_binary(serialize_goodbye(GoodbyeMessage::create_normal()));
        REQUIRE(ws_expect(ws, MessageType::GOODBYE));
        auto close = ws.read_frame();
        REQUIRE(close);
        CHECK(close->opcode == 0x8);
        CHECK(ws.closed_by_peer());
    }
    SECTION("a large message in both directions (1 MiB)") {
        asio::io_context io;
        WampClient raw{io};
        WsTestClient ws;
        REQUIRE(ws_join(ws, router.port()));
        ws.send_binary(serialize_subscribe(SubscribeMessage{1, {}, "big.topic"}));
        REQUIRE(ws_expect(ws, MessageType::SUBSCRIBED));

        const std::string big(1 << 20, 'z');
        std::string received;
        bool done = false;
        co_spawn(io, [&]() -> awaitable<void> {
            co_await raw.connect("127.0.0.1", router.port(), "test.realm");
            co_await raw.subscribe("big.back", [&](const EventMessage& e) { received = std::get<std::string>(e.arguments.at(0)); });
            (void)co_await raw.publish("big.topic", WampList{big});
            ws.send_binary(serialize_publish(PublishMessage{2, {}, "big.back", {big}}));
            for (int i = 0; i < 100 && received.empty(); ++i) co_await pause(io, 20ms);
            done = true;
        }, detached);
        io.run_for(15s);
        REQUIRE(done);
        CHECK(received == big);
        auto event = ws_expect(ws, MessageType::EVENT);
        REQUIRE(event);
        CHECK(std::get<std::string>(deserialize_event(*event)->arguments.at(0)) == big);
    }
}

TEST_CASE("WebSocket protocol violations and rejected upgrades", "[router][websocket]") {
    auto config = plain_config();
    config.websocket.allowed_origins = {"https://app.example.com"};
    Router router{config, Router::Transport::PLAIN, 1};
    router.start();

    SECTION("origin not on the allow-list: 403, then closed") {
        WsTestClient ws;
        CHECK(ws.connect(router.port(), "Origin: https://evil.example.com\r\n").starts_with("HTTP/1.1 403"));
        CHECK(ws.closed_by_peer());
    }
    SECTION("allowed origin and no origin both work") {
        WsTestClient allowed;
        CHECK(allowed.connect(router.port(), "Origin: https://app.example.com\r\n").starts_with("HTTP/1.1 101"));
        WsTestClient none;
        CHECK(none.connect(router.port()).starts_with("HTTP/1.1 101"));
    }
    SECTION("no wamp.2.cbor offered: 400") {
        WsTestClient ws;
        CHECK(ws.connect(router.port(), "", "wamp.2.json").starts_with("HTTP/1.1 400"));
        CHECK(ws.closed_by_peer());
    }
    SECTION("wrong version: 426 advertising 13") {
        WsTestClient ws;
        const auto head = ws.connect(router.port(), "", "wamp.2.cbor", "8");
        CHECK(head.starts_with("HTTP/1.1 426"));
        CHECK(head.find("Sec-WebSocket-Version: 13") != std::string::npos);
    }
    SECTION("an unmasked client frame closes with 1002") {
        WsTestClient ws;
        REQUIRE(ws_join(ws, router.port()));
        const std::vector<uint8_t> unmasked{0x82, 0x01, 0x00};
        ws.send_raw(unmasked);
        auto close = ws.read_frame();
        REQUIRE(close);
        CHECK(close->opcode == 0x8);
        CHECK(close->payload == std::vector<uint8_t>{0x03, 0xEA});
        CHECK(ws.closed_by_peer());
    }
    SECTION("a text frame closes with 1003") {
        WsTestClient ws;
        REQUIRE(ws_join(ws, router.port()));
        ws.send(0x1, std::vector<uint8_t>{'{', '}'});
        auto close = ws.read_frame();
        REQUIRE(close);
        CHECK(close->payload == std::vector<uint8_t>{0x03, 0xEB});
    }
    SECTION("garbage instead of WAMP is dropped without taking the router down") {
        WsTestClient ws;
        REQUIRE(ws.connect(router.port()).starts_with("HTTP/1.1 101"));
        ws.send_binary(std::vector<uint8_t>{0xFF, 0xFF, 0xFF});
        (void)ws.read_frame(500ms);
        WsTestClient healthy;
        CHECK(ws_join(healthy, router.port()));
    }
}

TEST_CASE("WebSocket can be switched off", "[router][websocket]") {
    auto config = plain_config();
    config.websocket.enabled = false;
    Router router{config, Router::Transport::PLAIN, 1};
    router.start();

    WsTestClient ws;
    ws.head_timeout = 500ms;
    const auto head = ws.connect(router.port());
    CHECK(head.find("101") == std::string::npos);   // treated as a (bad) RawSocket handshake
}

// ---------------------------------------------------------------------------------------------------
// Connections that open and stall
// ---------------------------------------------------------------------------------------------------
namespace {

// A bare blocking TCP connection; reports whether the router closes it within a time
struct BareConnection {
    asio::io_context io;
    asio::ip::tcp::socket socket{io};

    explicit BareConnection(unsigned short port) { socket.connect({asio::ip::address_v4::loopback(), port}); }

    void send(std::span<const uint8_t> data) { asio::write(socket, asio::buffer(data.data(), data.size())); }

    bool closed_within(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd p{socket.native_handle(), POLLIN, 0};
            if (::poll(&p, 1, 50) <= 0) continue;
            uint8_t buf[256];
            std::error_code ec;
            const auto n = socket.read_some(asio::buffer(buf), ec);
            if (ec == asio::error::eof || ec == asio::error::connection_reset) return true;
            if (!ec && n == 0) return true;
        }
        return false;
    }
};

ServerConfig impatient_config(std::chrono::milliseconds limit) {
    auto config = plain_config();
    config.handshake_timeout = limit;
    return config;
}

}  // namespace

TEST_CASE("Connections that stall before a session is established are closed", "[router][timeout]") {
    Router router{impatient_config(300ms), Router::Transport::PLAIN, 1};
    router.start();

    SECTION("a silent connection") {
        BareConnection c{router.port()};
        CHECK_FALSE(c.closed_within(100ms));    // not closed early
        CHECK(c.closed_within(2s));
    }
    SECTION("a connection that sent only the first byte of a RawSocket handshake") {
        BareConnection c{router.port()};
        c.send(std::vector<uint8_t>{0x7F});
        CHECK(c.closed_within(2s));
    }
    SECTION("a half-finished HTTP upgrade request") {
        BareConnection c{router.port()};
        const std::string partial = "GET /ws HTTP/1.1\r\nHost: localhost\r\n";
        c.send({reinterpret_cast<const uint8_t*>(partial.data()), partial.size()});
        CHECK(c.closed_within(2s));
    }
    SECTION("trickling bytes does not extend the deadline") {
        BareConnection c{router.port()};
        const std::string request = "GET /ws HTTP/1.1\r\nHost: localhost\r\nX-Slow: ";
        const auto start = std::chrono::steady_clock::now();
        bool closed = false;
        for (char ch : request + std::string(200, 'a')) {
            std::error_code ec;
            asio::write(c.socket, asio::buffer(&ch, 1), ec);
            if (ec || c.closed_within(20ms)) { closed = true; break; }
        }
        CHECK(closed);
        CHECK(std::chrono::steady_clock::now() - start < 2s);
    }
    SECTION("a RawSocket client that handshakes but never sends HELLO") {
        BareConnection c{router.port()};
        const auto handshake = rawsocket::encode_handshake_request({.max_length = rawsocket::MaxLengthCode::BYTES_16M,
                                                                    .serializer = rawsocket::Serializer::CBOR});
        c.send(handshake);
        CHECK(c.closed_within(2s));
    }

    // the timeouts were counted (one per section that ran)
    CHECK(router.stats()[0].handshake_timeouts == 1);
}

TEST_CASE("Established sessions are not subject to the handshake timeout", "[router][timeout]") {
    Router router{impatient_config(300ms), Router::Transport::PLAIN, 1};
    router.start();

    SECTION("WebSocket") {
        WsTestClient ws;
        REQUIRE(ws_join(ws, router.port()));
        std::this_thread::sleep_for(900ms);                   // three times the limit
        ws.send(0x9, std::vector<uint8_t>{1});
        auto pong = ws.read_frame();
        REQUIRE(pong);
        CHECK(pong->opcode == 0xA);
    }
    SECTION("RawSocket") {
        asio::io_context io;
        WampClient client{io};
        bool ok = false;
        co_spawn(io, [&]() -> awaitable<void> {
            co_await client.connect("127.0.0.1", router.port(), "test.realm");
            co_await pause(io, 900ms);
            (void)co_await client.publish("still.alive", WampList{std::string{"yes"}});
            auto sub_ok = co_await client.subscribe("still.alive", [](const EventMessage&) {});
            ok = sub_ok != 0;
            co_await client.disconnect();
        }, detached);
        io.run_for(10s);
        CHECK(ok);
    }
    CHECK(router.stats()[0].handshake_timeouts == 0);
}

TEST_CASE("handshake_timeout_ms = 0 disables the limit", "[router][timeout]") {
    Router router{impatient_config(0ms), Router::Transport::PLAIN, 1};
    router.start();
    BareConnection c{router.port()};
    CHECK_FALSE(c.closed_within(800ms));
}

TEST_CASE("A client that never completes the TLS handshake is closed", "[router][timeout][tls]") {
    if (!std::filesystem::exists("test_certs/cert.pem") || !std::filesystem::exists("test_certs/key.pem")) {
        SKIP("test_certs/ missing (run scripts/gen-test-certs.sh)");
    }
    auto config = impatient_config(300ms);
    config.tls.cert_path = "test_certs/cert.pem";
    config.tls.key_path = "test_certs/key.pem";
    Router router{config, Router::Transport::TLS, 1};
    router.start();

    BareConnection silent{router.port()};
    CHECK(silent.closed_within(2s));

    BareConnection hello_fragment{router.port()};
    hello_fragment.send(std::vector<uint8_t>{0x16, 0x03, 0x01, 0x02, 0x00, 0x01});   // the start of a TLS record, then nothing
    CHECK(hello_fragment.closed_within(2s));
    CHECK(router.stats()[0].handshake_timeouts == 2);
}

// ---------------------------------------------------------------------------------------------------
// Connection limits
// ---------------------------------------------------------------------------------------------------
TEST_CASE("ConnectionLimiter counts total and per-address connections", "[limits]") {
    const auto a = asio::ip::make_address("10.0.0.1");
    const auto b = asio::ip::make_address("10.0.0.2");

    SECTION("total cap") {
        ConnectionLimiter limiter{2, 0};
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::ADMITTED);
        CHECK(limiter.admit(b) == ConnectionLimiter::Result::ADMITTED);
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::TOTAL_LIMIT);
        limiter.release(a);
        CHECK(limiter.open() == 1);
        CHECK(limiter.admit(b) == ConnectionLimiter::Result::ADMITTED);
    }
    SECTION("per-address cap leaves other addresses alone") {
        ConnectionLimiter limiter{0, 2};
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::ADMITTED);
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::ADMITTED);
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::ADDRESS_LIMIT);
        CHECK(limiter.admit(b) == ConnectionLimiter::Result::ADMITTED);
        limiter.release(a);
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::ADMITTED);
        CHECK(limiter.open() == 3);
    }
    SECTION("0 means unlimited") {
        ConnectionLimiter limiter{0, 0};
        for (int i = 0; i < 1000; ++i) REQUIRE(limiter.admit(a) == ConnectionLimiter::Result::ADMITTED);
    }
    SECTION("a rejected connection does not use up the per-address count") {
        ConnectionLimiter limiter{1, 1};
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::ADMITTED);
        CHECK(limiter.admit(b) == ConnectionLimiter::Result::TOTAL_LIMIT);
        limiter.release(a);
        CHECK(limiter.admit(b) == ConnectionLimiter::Result::ADMITTED);
        CHECK(limiter.admit(a) == ConnectionLimiter::Result::TOTAL_LIMIT);
    }
}

TEST_CASE("The router closes connections beyond max_connections and admits again after one ends", "[router][limits]") {
    auto config = plain_config();
    config.max_connections = 3;
    Router router{config, Router::Transport::PLAIN, 2};
    router.start();

    std::vector<std::unique_ptr<BareConnection>> open;
    for (int i = 0; i < 3; ++i) open.push_back(std::make_unique<BareConnection>(router.port()));
    for (auto& c : open) CHECK_FALSE(c->closed_within(100ms));     // admitted: idle but open
    CHECK(router.open_connections() == 3);

    BareConnection rejected{router.port()};
    CHECK(rejected.closed_within(2s));
    CHECK(router.rejected_connections().total_limit == 1);
    CHECK(router.open_connections() == 3);

    open.pop_back();                                                // one client leaves
    for (int i = 0; i < 100 && router.open_connections() > 2; ++i) std::this_thread::sleep_for(20ms);
    CHECK(router.open_connections() == 2);

    BareConnection admitted{router.port()};
    CHECK_FALSE(admitted.closed_within(300ms));
    CHECK(router.open_connections() == 3);
    CHECK(router.rejected_connections().total_limit == 1);
}

TEST_CASE("The router caps connections per client address", "[router][limits]") {
    auto config = plain_config();
    config.max_connections_per_ip = 2;
    config.max_connections = 0;
    Router router{config, Router::Transport::PLAIN, 1};
    router.start();

    BareConnection first{router.port()};
    BareConnection second{router.port()};
    CHECK_FALSE(first.closed_within(100ms));
    CHECK_FALSE(second.closed_within(100ms));
    BareConnection third{router.port()};                             // same address (loopback)
    CHECK(third.closed_within(2s));
    CHECK(router.rejected_connections().address_limit == 1);
    CHECK(router.rejected_connections().total_limit == 0);
}

TEST_CASE("Established sessions count against the limit and free it when they end", "[router][limits]") {
    auto config = plain_config();
    config.max_connections = 2;
    Router router{config, Router::Transport::PLAIN, 1};
    router.start();

    {
        WsTestClient one, two;
        REQUIRE(ws_join(one, router.port()));
        REQUIRE(ws_join(two, router.port()));
        BareConnection third{router.port()};
        CHECK(third.closed_within(2s));
    }
    for (int i = 0; i < 100 && router.open_connections() > 0; ++i) std::this_thread::sleep_for(20ms);
    CHECK(router.open_connections() == 0);
    WsTestClient again;
    CHECK(ws_join(again, router.port()));
}
