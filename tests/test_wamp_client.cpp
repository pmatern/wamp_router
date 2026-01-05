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
