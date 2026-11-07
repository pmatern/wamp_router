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
