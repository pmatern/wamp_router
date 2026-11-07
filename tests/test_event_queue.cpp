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
#include <boost/asio.hpp>
#include "include/event_channel.hpp"

using namespace wamp;
using namespace std::chrono_literals;

namespace {

// Applies an event-queue config for one test and restores the defaults afterwards
struct QueueConfigGuard {
    QueueConfigGuard(size_t size, OverflowPolicy policy, std::chrono::milliseconds timeout = 1000ms) {
        EventChannelRegistry::configure({size, policy, timeout});
        EventChannelRegistry::clear_blocked();
        EventChannelRegistry::reset_dropped_count();
    }
    ~QueueConfigGuard() {
        EventChannelRegistry::configure({});
        EventChannelRegistry::clear_blocked();
    }
};

constexpr uint64_t kSession = 920001;

EventToSend make_event(uint8_t tag) {
    return EventToSend{kSession, std::make_shared<std::vector<uint8_t>>(1, tag)};
}

std::optional<uint8_t> receive_tag(EventChannel& channel) {
    std::optional<uint8_t> tag;
    channel.try_receive([&](boost::system::error_code ec, EventToSend ev) {
        if (!ec) {
            tag = (*ev.event_data)[0];
        }
    });
    return tag;
}

struct ChannelFixture {
    boost::asio::io_context io;
    std::shared_ptr<EventChannel> channel;

    ChannelFixture() : channel(EventChannelRegistry::get_or_create(kSession, io)) {}
    ~ChannelFixture() { EventChannelRegistry::remove(kSession); }
};

}  // namespace

TEST_CASE("Event queue size comes from configuration", "[event_queue]") {
    QueueConfigGuard guard{3, OverflowPolicy::DROP};
    ChannelFixture fx;

    for (uint8_t i = 0; i < 3; ++i) {
        REQUIRE(EventChannelRegistry::deliver(kSession, make_event(i)) == DeliveryResult::QUEUED);
    }
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(3)) == DeliveryResult::DROPPED_FULL);
}

TEST_CASE("DROP policy counts dropped events", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::DROP};
    ChannelFixture fx;

    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(1)) == DeliveryResult::DROPPED_FULL);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(2)) == DeliveryResult::DROPPED_FULL);
    REQUIRE(EventChannelRegistry::dropped_count() == 2);
    REQUIRE(EventChannelRegistry::take_blocked().empty());
}

TEST_CASE("Delivery to a missing session is a counted drop", "[event_queue]") {
    QueueConfigGuard guard{4, OverflowPolicy::BACKPRESSURE};

    REQUIRE(EventChannelRegistry::deliver(999999, make_event(0)) == DeliveryResult::DROPPED_NO_SESSION);
    REQUIRE(EventChannelRegistry::dropped_count() == 1);
}

TEST_CASE("BACKPRESSURE parks sends for a full queue", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE};
    ChannelFixture fx;

    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);

    auto blocked = EventChannelRegistry::take_blocked();
    REQUIRE(blocked.size() == 2);
    REQUIRE((*blocked[0].event.event_data)[0] == 1);  // order preserved
    REQUIRE((*blocked[1].event.event_data)[0] == 2);
    REQUIRE(EventChannelRegistry::take_blocked().empty());
    REQUIRE(EventChannelRegistry::dropped_count() == 0);

    SECTION("may_defer=false drops instead of parking") {
        REQUIRE(EventChannelRegistry::deliver(kSession, make_event(3), false) == DeliveryResult::DROPPED_FULL);
        REQUIRE(EventChannelRegistry::take_blocked().empty());
        REQUIRE(EventChannelRegistry::dropped_count() == 1);
    }
}

TEST_CASE("deliver_blocked waits for the subscriber to drain", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 2000ms};
    ChannelFixture fx;

    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);

    std::vector<uint8_t> received;
    bool flushed = false;
    const auto start = std::chrono::steady_clock::now();
    std::chrono::milliseconds flush_time{0};

    // Sender: waits for room
    boost::asio::co_spawn(fx.io, [&]() -> boost::asio::awaitable<void> {
        co_await EventChannelRegistry::deliver_blocked(EventChannelRegistry::take_blocked());
        flush_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        flushed = true;
    }, boost::asio::detached);

    // Slow subscriber: drains one event every 30 ms
    boost::asio::co_spawn(fx.io, [&]() -> boost::asio::awaitable<void> {
        boost::asio::steady_timer timer{fx.io};
        for (int i = 0; i < 3; ++i) {
            timer.expires_after(30ms);
            co_await timer.async_wait(boost::asio::use_awaitable);
            if (auto tag = receive_tag(*fx.channel)) {
                received.push_back(*tag);
            }
        }
    }, boost::asio::detached);

    fx.io.run_for(3s);

    REQUIRE(flushed);
    REQUIRE(flush_time >= 25ms);          // the sender really waited for the subscriber
    REQUIRE(flush_time < 1500ms);
    REQUIRE(received == std::vector<uint8_t>{0, 1, 2});  // nothing lost, order kept
    REQUIRE(EventChannelRegistry::dropped_count() == 0);
}

TEST_CASE("deliver_blocked drops after the backpressure timeout", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 80ms};
    ChannelFixture fx;

    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);

    bool flushed = false;
    const auto start = std::chrono::steady_clock::now();
    std::chrono::milliseconds flush_time{0};

    boost::asio::co_spawn(fx.io, [&]() -> boost::asio::awaitable<void> {
        co_await EventChannelRegistry::deliver_blocked(EventChannelRegistry::take_blocked());
        flush_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        flushed = true;
    }, boost::asio::detached);

    fx.io.run_for(2s);

    REQUIRE(flushed);
    REQUIRE(flush_time >= 70ms);
    REQUIRE(flush_time < 1000ms);   // one shared deadline, not 80 ms per event
    REQUIRE(EventChannelRegistry::dropped_count() == 2);
    REQUIRE(receive_tag(*fx.channel) == 0);   // the queued event is still there
    REQUIRE(!receive_tag(*fx.channel).has_value());
}

TEST_CASE("Stalled subscribers are skipped after repeated timeouts", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 40ms};
    EventChannelRegistry::configure({1, OverflowPolicy::BACKPRESSURE, 40ms, 2});
    ChannelFixture fx;

    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);

    auto flush = [&] {
        bool done = false;
        boost::asio::co_spawn(fx.io, [&]() -> boost::asio::awaitable<void> {
            co_await EventChannelRegistry::deliver_blocked(EventChannelRegistry::take_blocked());
            done = true;
        }, boost::asio::detached);
        fx.io.restart();
        fx.io.run_for(2s);
        REQUIRE(done);
    };

    // Two timeouts in a row mark the subscriber slow
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
    flush();
    REQUIRE(!EventChannelRegistry::is_slow(kSession));
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(2)) == DeliveryResult::DEFERRED);
    flush();
    REQUIRE(EventChannelRegistry::is_slow(kSession));

    // Now publishers no longer wait on it
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(3)) == DeliveryResult::DROPPED_FULL);
    REQUIRE(EventChannelRegistry::take_blocked().empty());

    // Once it drains, delivery works again and the mark clears
    REQUIRE(receive_tag(*fx.channel) == 0);
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(4)) == DeliveryResult::QUEUED);
    REQUIRE(!EventChannelRegistry::is_slow(kSession));
    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(5)) == DeliveryResult::DEFERRED);
    EventChannelRegistry::clear_blocked();
}

TEST_CASE("slow_subscriber_limit 0 never skips", "[event_queue]") {
    QueueConfigGuard guard{1, OverflowPolicy::BACKPRESSURE, 30ms};
    EventChannelRegistry::configure({1, OverflowPolicy::BACKPRESSURE, 30ms, 0});
    ChannelFixture fx;

    REQUIRE(EventChannelRegistry::deliver(kSession, make_event(0)) == DeliveryResult::QUEUED);
    for (int i = 0; i < 3; ++i) {
        REQUIRE(EventChannelRegistry::deliver(kSession, make_event(1)) == DeliveryResult::DEFERRED);
        bool done = false;
        boost::asio::co_spawn(fx.io, [&]() -> boost::asio::awaitable<void> {
            co_await EventChannelRegistry::deliver_blocked(EventChannelRegistry::take_blocked());
            done = true;
        }, boost::asio::detached);
        fx.io.restart();
        fx.io.run_for(2s);
        REQUIRE(done);
    }
    REQUIRE(!EventChannelRegistry::is_slow(kSession));
}
