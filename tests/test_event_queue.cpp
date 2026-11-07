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
#include <asio.hpp>
#include "include/shard.hpp"

using namespace wamp;

// Routing state shared by the sessions and handlers a test builds by hand (one per test file)
static Shard& test_shard() {
    static Shard shard;
    return shard;
}
using namespace std::chrono_literals;

namespace {

// Applies an event-queue config for one test and restores the defaults afterwards
struct QueueConfigGuard {
    QueueConfigGuard(size_t size, OverflowPolicy policy, std::chrono::milliseconds timeout = 1000ms) {
        test_shard().channels.configure({size, policy, timeout});
        test_shard().channels.clear_blocked();
        test_shard().channels.reset_dropped_count();
    }
    ~QueueConfigGuard() {
        test_shard().channels.configure({});
        test_shard().channels.clear_blocked();
    }
};

constexpr uint64_t kSession = 920001;

EventToSend make_event(uint8_t tag) {
    return EventToSend{kSession, std::make_shared<std::vector<uint8_t>>(1, tag)};
}

std::optional<uint8_t> receive_tag(EventChannel& channel) {
    std::optional<uint8_t> tag;
    channel.try_receive([&](std::error_code ec, EventToSend ev) {
        if (!ec) {
            tag = (*ev.event_data)[0];
        }
    });
    return tag;
}

struct ChannelFixture {
    asio::io_context io;
    std::shared_ptr<EventChannel> channel;

    ChannelFixture() : channel(test_shard().channels.get_or_create(kSession, io)) {}
    ~ChannelFixture() { test_shard().channels.remove(kSession); }
};

}  // namespace

TEST_CASE("Event queue size comes from configuration", "[event_queue]") {
    QueueConfigGuard guard{3, OverflowPolicy::DROP};
    ChannelFixture fx;

    for (uint8_t i = 0; i < 3; ++i) {
        REQUIRE(test_shard().channels.deliver(kSession, make_event(i)) == DeliveryResult::QUEUED);
    }
    REQUIRE(test_shard().channels.deliver(kSession, make_event(3)) == DeliveryResult::DROPPED_FULL);
}

TEST_CASE("DROP policy counts dropped events", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::DROP};
    ChannelFixture fx;

    REQUIRE(test_shard().channels.deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(1)) == DeliveryResult::DROPPED_FULL);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(2)) == DeliveryResult::DROPPED_FULL);
    REQUIRE(test_shard().channels.dropped_count() == 2);
    REQUIRE(test_shard().channels.take_blocked().empty());
}

TEST_CASE("Delivery to a missing session is a counted drop", "[event_queue]") {
    QueueConfigGuard guard{4, OverflowPolicy::BACKPRESSURE};

    REQUIRE(test_shard().channels.deliver(999999, make_event(0)) == DeliveryResult::DROPPED_NO_SESSION);
    REQUIRE(test_shard().channels.dropped_count() == 1);
}

TEST_CASE("BACKPRESSURE parks sends for a full queue", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE};
    ChannelFixture fx;

    REQUIRE(test_shard().channels.deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);

    auto blocked = test_shard().channels.take_blocked();
    REQUIRE(blocked.size() == 2);
    REQUIRE((*blocked[0].event.event_data)[0] == 1);  // order preserved
    REQUIRE((*blocked[1].event.event_data)[0] == 2);
    REQUIRE(test_shard().channels.take_blocked().empty());
    REQUIRE(test_shard().channels.dropped_count() == 0);

    SECTION("may_defer=false drops instead of parking") {
        REQUIRE(test_shard().channels.deliver(kSession, make_event(3), false) == DeliveryResult::DROPPED_FULL);
        REQUIRE(test_shard().channels.take_blocked().empty());
        REQUIRE(test_shard().channels.dropped_count() == 1);
    }
}

TEST_CASE("deliver_blocked waits for the subscriber to drain", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 2000ms};
    ChannelFixture fx;

    REQUIRE(test_shard().channels.deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);

    std::vector<uint8_t> received;
    bool flushed = false;
    const auto start = std::chrono::steady_clock::now();
    std::chrono::milliseconds flush_time{0};

    // Sender: waits for room
    asio::co_spawn(fx.io, [&]() -> asio::awaitable<void> {
        co_await test_shard().channels.deliver_blocked(test_shard().channels.take_blocked());
        flush_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        flushed = true;
    }, asio::detached);

    // Slow subscriber: drains one event every 30 ms
    asio::co_spawn(fx.io, [&]() -> asio::awaitable<void> {
        asio::steady_timer timer{fx.io};
        for (int i = 0; i < 3; ++i) {
            timer.expires_after(30ms);
            co_await timer.async_wait(asio::use_awaitable);
            if (auto tag = receive_tag(*fx.channel)) {
                received.push_back(*tag);
            }
        }
    }, asio::detached);

    fx.io.run_for(3s);

    REQUIRE(flushed);
    REQUIRE(flush_time >= 25ms);          // the sender really waited for the subscriber
    REQUIRE(flush_time < 1500ms);
    REQUIRE(received == std::vector<uint8_t>{0, 1, 2});  // nothing lost, order kept
    REQUIRE(test_shard().channels.dropped_count() == 0);
}

TEST_CASE("deliver_blocked drops after the backpressure timeout", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 80ms};
    ChannelFixture fx;

    REQUIRE(test_shard().channels.deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);

    bool flushed = false;
    const auto start = std::chrono::steady_clock::now();
    std::chrono::milliseconds flush_time{0};

    asio::co_spawn(fx.io, [&]() -> asio::awaitable<void> {
        co_await test_shard().channels.deliver_blocked(test_shard().channels.take_blocked());
        flush_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        flushed = true;
    }, asio::detached);

    fx.io.run_for(2s);

    REQUIRE(flushed);
    REQUIRE(flush_time >= 70ms);
    REQUIRE(flush_time < 1000ms);   // one shared deadline, not 80 ms per event
    REQUIRE(test_shard().channels.dropped_count() == 2);
    REQUIRE(receive_tag(*fx.channel) == 0);   // the queued event is still there
    REQUIRE(!receive_tag(*fx.channel).has_value());
}

TEST_CASE("Stalled subscribers are skipped after repeated timeouts", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 40ms};
    test_shard().channels.configure({1, OverflowPolicy::BACKPRESSURE, 40ms, 2});
    ChannelFixture fx;

    REQUIRE(test_shard().channels.deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);

    auto flush = [&] {
        bool done = false;
        asio::co_spawn(fx.io, [&]() -> asio::awaitable<void> {
            co_await test_shard().channels.deliver_blocked(test_shard().channels.take_blocked());
            done = true;
        }, asio::detached);
        fx.io.restart();
        fx.io.run_for(2s);
        REQUIRE(done);
    };

    // Two timeouts in a row mark the subscriber slow
    REQUIRE(test_shard().channels.deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    flush();
    REQUIRE(!test_shard().channels.is_slow(kSession));
    REQUIRE(test_shard().channels.deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);
    flush();
    REQUIRE(test_shard().channels.is_slow(kSession));

    // Now publishers no longer wait on it
    REQUIRE(test_shard().channels.deliver(kSession, make_event(3)) == DeliveryResult::DROPPED_FULL);
    REQUIRE(test_shard().channels.take_blocked().empty());

    // Once it drains, delivery works again and the mark clears
    REQUIRE(receive_tag(*fx.channel) == 0);
    REQUIRE(test_shard().channels.deliver(kSession, make_event(4)) == DeliveryResult::QUEUED);
    REQUIRE(!test_shard().channels.is_slow(kSession));
    REQUIRE(test_shard().channels.deliver(kSession, make_event(5)) == DeliveryResult::DEFERRED);
    test_shard().channels.clear_blocked();
}

TEST_CASE("slow_subscriber_limit 0 never skips", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 30ms};
    test_shard().channels.configure({1, OverflowPolicy::BACKPRESSURE, 30ms, 0});
    ChannelFixture fx;

    REQUIRE(test_shard().channels.deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    for (int i = 0; i < 3; ++i) {
        REQUIRE(test_shard().channels.deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
        bool done = false;
        asio::co_spawn(fx.io, [&]() -> asio::awaitable<void> {
            co_await test_shard().channels.deliver_blocked(test_shard().channels.take_blocked());
            done = true;
        }, asio::detached);
        fx.io.restart();
        fx.io.run_for(2s);
        REQUIRE(done);
    }
    REQUIRE(!test_shard().channels.is_slow(kSession));
}
