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


#pragma once

#include "config.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <cstdint>
#include <utility>
#include <vector>

namespace wamp {

// ============================================================================
// EventToSend - Flyweight pattern for distributing events to multiple subscribers
// ============================================================================
// Uses shared_ptr to avoid copying event data for each subscriber
struct EventToSend {
    uint64_t target_session_id{};
    std::shared_ptr<const std::vector<uint8_t>> event_data;  // Shared between all recipients

    EventToSend() = default;

    EventToSend(uint64_t session_id, std::shared_ptr<const std::vector<uint8_t>> data)
        : target_session_id(session_id)
        , event_data(std::move(data))
    {}
};

using EventChannel = boost::asio::experimental::channel<void(boost::system::error_code, EventToSend)>;

// ============================================================================
// EventChannelRegistry - Manages event channels for active sessions
// ============================================================================
// Each session has one bounded queue (router -> client). When a queue is full the configured
// OverflowPolicy applies:
//   DROP          - the event is discarded and counted.
//   BACKPRESSURE  - the send is parked in a per-thread "blocked" list. The session coroutine that
//                   triggered it takes the list right after processing its input and awaits
//                   deliver_blocked(), so it stops reading its socket until the subscriber
//                   catches up (TCP then pushes back on the sender). The wait is bounded by
//                   backpressure_timeout, after which the event is dropped and counted; this also
//                   breaks wait cycles between sessions that publish to each other.
// A subscriber whose waits time out slow_subscriber_limit times in a row is marked slow: while its
// queue is full, further events for it are dropped immediately instead of making publishers wait.
// Any successful delivery to it (it made room again) clears the mark.

// Result of EventChannelRegistry::deliver
enum class DeliveryResult {
    QUEUED,              // In the recipient's queue
    DEFERRED,            // Queue full; parked for deliver_blocked() (BACKPRESSURE only)
    DROPPED_NO_SESSION,  // Recipient has no open channel
    DROPPED_FULL         // Queue full and policy is DROP
};

// True if the event is (or will be) in the recipient's queue
[[nodiscard]] constexpr bool accepted(DeliveryResult result) {
    return result == DeliveryResult::QUEUED || result == DeliveryResult::DEFERRED;
}

// A send waiting for queue space
struct BlockedSend {
    uint64_t session_id{};
    EventToSend event;
};

class EventChannelRegistry {
public:
    static void configure(const EventQueueConfig& config) {
        settings() = config;
    }

    [[nodiscard]] static const EventQueueConfig& config() {
        return settings();
    }

    static std::shared_ptr<EventChannel> get_or_create(
        uint64_t session_id,
        boost::asio::io_context& io
    ) {
        auto& channels = get_channels();

        auto it = channels.find(session_id);
        if (it != channels.end()) {
            return it->second;
        }

        auto channel = std::make_shared<EventChannel>(io, settings().size);
        channels[session_id] = channel;

        spdlog::debug("Created event channel for session {} (capacity {})", session_id, settings().size);
        return channel;
    }

    static std::shared_ptr<EventChannel> find(uint64_t session_id) {
        auto& channels = get_channels();
        auto it = channels.find(session_id);
        return it != channels.end() ? it->second : nullptr;
    }

    static void remove(uint64_t session_id) {
        auto& channels = get_channels();
        auto it = channels.find(session_id);
        if (it != channels.end()) {
            it->second->close();
            channels.erase(it);
            strikes().erase(session_id);
            spdlog::debug("Removed event channel for session {}", session_id);
        }
    }

    // Non-blocking send; false if the session has no channel or its queue is full
    static bool try_send(uint64_t session_id, EventToSend event) {
        auto& channels = get_channels();
        auto it = channels.find(session_id);
        if (it != channels.end()) {
            return it->second->try_send(boost::system::error_code{}, std::move(event));
        }
        return false;
    }

    // Queue an event for a session, applying the overflow policy if its queue is full.
    // may_defer=false forces DROP behaviour (for callers that cannot wait, e.g. disconnect cleanup).
    static DeliveryResult deliver(uint64_t session_id, EventToSend event, bool may_defer = true) {
        auto channel = find(session_id);
        if (!channel || !channel->is_open()) {
            note_drop(session_id, "no open channel");
            return DeliveryResult::DROPPED_NO_SESSION;
        }

        if (channel->try_send(boost::system::error_code{}, event)) {
            clear_strikes(session_id);
            return DeliveryResult::QUEUED;
        }

        if (is_slow(session_id)) {
            note_drop(session_id, "slow subscriber");
            return DeliveryResult::DROPPED_FULL;
        }

        if (may_defer && settings().overflow == OverflowPolicy::BACKPRESSURE) {
            blocked_sends().push_back(BlockedSend{session_id, std::move(event)});
            return DeliveryResult::DEFERRED;
        }

        note_drop(session_id, "queue full");
        return DeliveryResult::DROPPED_FULL;
    }

    // Hand over (and clear) the sends this thread parked since the last call
    [[nodiscard]] static std::vector<BlockedSend> take_blocked() {
        return std::exchange(blocked_sends(), {});
    }

    static void clear_blocked() {
        blocked_sends().clear();
    }

    // Wait for room in each recipient's queue, in order. One deadline covers the whole batch;
    // sends still blocked when it expires are dropped and counted.
    static boost::asio::awaitable<void> deliver_blocked(std::vector<BlockedSend> blocked) {
        if (blocked.empty()) {
            co_return;
        }

        auto executor = co_await boost::asio::this_coro::executor;
        boost::asio::steady_timer deadline{executor, settings().backpressure_timeout};
        bool expired = false;

        for (auto& send : blocked) {
            auto channel = find(send.session_id);
            if (expired || !channel || !channel->is_open()) {
                note_drop(send.session_id, expired ? "backpressure timeout" : "no open channel");
                continue;
            }

            // The loser of wait_for_one may still have completed; check the send's own result
            auto [order, ec_send, ec_timer] = co_await boost::asio::experimental::make_parallel_group(
                channel->async_send(boost::system::error_code{}, std::move(send.event), boost::asio::deferred),
                deadline.async_wait(boost::asio::deferred)
            ).async_wait(
                boost::asio::experimental::wait_for_one(),
                boost::asio::use_awaitable
            );
            (void)ec_timer;

            if (ec_send) {
                expired = expired || order[0] == 1;
                note_drop(send.session_id, order[0] == 1 ? "backpressure timeout" : "channel closed");
                if (order[0] == 1) {
                    add_strike(send.session_id);
                }
            } else {
                clear_strikes(send.session_id);
            }
        }
    }

    // True if the session has timed out slow_subscriber_limit waits in a row
    [[nodiscard]] static bool is_slow(uint64_t session_id) {
        const auto limit = settings().slow_subscriber_limit;
        if (limit == 0) return false;
        auto it = strikes().find(session_id);
        return it != strikes().end() && it->second >= limit;
    }

    // Events dropped since startup (full queue under DROP, backpressure timeout, missing session)
    [[nodiscard]] static uint64_t dropped_count() {
        return dropped().load(std::memory_order_relaxed);
    }

    static void reset_dropped_count() {
        dropped().store(0, std::memory_order_relaxed);
    }

private:
    static void add_strike(uint64_t session_id) {
        const auto limit = settings().slow_subscriber_limit;
        if (limit == 0) return;
        if (++strikes()[session_id] == limit) {
            spdlog::warn("Session {} is a slow subscriber ({} backpressure timeouts in a row); "
                         "dropping its events while its queue is full", session_id, limit);
        }
    }

    static void clear_strikes(uint64_t session_id) {
        auto& s = strikes();
        if (!s.empty()) s.erase(session_id);
    }

    static std::unordered_map<uint64_t, size_t>& strikes() {
        static std::unordered_map<uint64_t, size_t> map;
        return map;
    }

    // Logs the first drop and then every 1000th so a stalled subscriber can't flood the log
    static void note_drop(uint64_t session_id, const char* reason) {
        const auto total = dropped().fetch_add(1, std::memory_order_relaxed) + 1;
        if (total == 1 || total % 1000 == 0) {
            spdlog::warn("Dropped event for session {} ({}); {} events dropped in total", session_id, reason, total);
        }
    }

    static EventQueueConfig& settings() {
        static EventQueueConfig config;
        return config;
    }

    static std::atomic<uint64_t>& dropped() {
        static std::atomic<uint64_t> count{0};
        return count;
    }

    static std::vector<BlockedSend>& blocked_sends() {
        static thread_local std::vector<BlockedSend> list;
        return list;
    }

    static std::unordered_map<uint64_t, std::shared_ptr<EventChannel>>& get_channels() {
        static std::unordered_map<uint64_t, std::shared_ptr<EventChannel>> channels;
        return channels;
    }
};

} // namespace wamp
