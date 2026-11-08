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

#include "shard.hpp"
#include "wamp_serializer.hpp"
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace wamp {

// One PUBLISH travelling to the other shards: the EVENT is serialized once (on the publishing shard) and
// the same immutable template is shared by every interested shard, which stamps in its own subscribers'
// subscription ids.
struct CrossPublish {
    std::string realm;
    std::string topic;
    EventTemplate event;
};
using CrossPublishPtr = std::shared_ptr<const CrossPublish>;

// A CALL travelling to the shard that holds the callee's registration. That shard owns the pending call:
// its YIELD arrives there, and it sends the RESULT/ERROR back as a CrossFrame.
struct CrossCall {
    std::string realm;
    std::string procedure;
    uint32_t caller_shard{};
    uint64_t caller_session{};
    uint64_t request_id{};   // the caller's CALL request id
    int64_t timeout_ms{0};   // CALL timeout option, 0 = shard default
    WampList arguments;
    WampDict arguments_kw;
};

// A complete frame (RESULT, ERROR) for a session that lives on the receiving shard
struct CrossFrame {
    uint64_t session_id{};
    std::shared_ptr<const std::vector<uint8_t>> frame;
};

using CrossMessage = std::variant<CrossPublishPtr, CrossCall, CrossFrame>;

// ============================================================================
// ShardGroup - how shards of one Router reach each other
// ============================================================================
// Shards share no routing state. They exchange two things:
//
//  * Interest: each shard keeps a replica of "which OTHER shards have a subscriber for (realm, topic)".
//    The shard that gains its first / loses its last local subscriber to a topic updates every other
//    shard's replica directly, before its own SUBSCRIBED/UNSUBSCRIBED reply goes out, so "subscribed
//    means every later publish is seen" holds without acknowledgements. A replica has its own mutex, but
//    it is taken by its owner on every publish and by another shard only on those rare changes, so in
//    steady state it is an uncontended lock on a cache line only that shard touches. Only one such
//    lock is ever held at a time.
//  * Mailboxes: one inbox per shard for cross-shard PUBLISHes. The sender appends under the inbox's
//    mutex and, only when the inbox was idle, schedules a drain on the destination's io_context, so a
//    burst costs one wake-up. Messages from one shard to another stay in order, which preserves
//    per-publisher, per-topic ordering. The inbox is bounded; beyond the cap the event is dropped and
//    counted (the destination is behind by definition).
class ShardGroup {
public:
    // Called on the destination shard's thread with a batch of messages; may suspend (backpressure)
    using Handler = std::function<asio::awaitable<void>(Shard&, std::vector<CrossMessage>)>;

    static constexpr size_t kMailboxCap = 1 << 16;   // hard limit: beyond this events are dropped
    static constexpr size_t kHighWater = 1 << 12;    // publishers are told to wait above this ...
    static constexpr size_t kLowWater = 1 << 11;     // ... until the inbox is back under this

    explicit ShardGroup(unsigned shards, Handler handler)
        : handler_(std::move(handler))
    {
        members_.reserve(shards);
        for (unsigned i = 0; i < shards; ++i) members_.push_back(std::make_unique<Member>());
    }

    ShardGroup(const ShardGroup&) = delete;
    ShardGroup& operator=(const ShardGroup&) = delete;

    [[nodiscard]] size_t size() const { return members_.size(); }

    // Registers shard `index` (run by `io`) and points the shard back at this group
    void attach(unsigned index, Shard& shard, asio::io_context& io) {
        members_.at(index)->shard = &shard;
        members_[index]->io = &io;
        shard.group = this;
        shard.index = index;
    }

    // Shard `from` now has a subscriber for the topic where it had none
    void add_interest(unsigned from, const std::string& realm, const std::string& topic) {
        for (unsigned j = 0; j < members_.size(); ++j) {
            if (j == from) continue;
            Member& m = *members_[j];
            std::lock_guard lock{m.interest_mutex};
            auto realm_it = m.interest.find(realm);
            if (realm_it == m.interest.end()) {
                realm_it = m.interest.emplace(realm, TopicMap{}).first;
            }
            auto topic_it = realm_it->second.find(topic);
            if (topic_it == realm_it->second.end()) {
                topic_it = realm_it->second.emplace(topic, std::vector<uint32_t>{}).first;
            }
            auto& shards = topic_it->second;
            if (std::ranges::find(shards, from) == shards.end()) shards.push_back(from);
        }
    }

    // Shard `from` no longer has any subscriber for the topic
    void remove_interest(unsigned from, const std::string& realm, const std::string& topic) {
        for (unsigned j = 0; j < members_.size(); ++j) {
            if (j == from) continue;
            Member& m = *members_[j];
            std::lock_guard lock{m.interest_mutex};
            auto realm_it = m.interest.find(realm);
            if (realm_it == m.interest.end()) continue;
            auto topic_it = realm_it->second.find(topic);
            if (topic_it == realm_it->second.end()) continue;
            std::erase(topic_it->second, from);
            if (topic_it->second.empty()) realm_it->second.erase(topic_it);
            if (realm_it->second.empty()) m.interest.erase(realm_it);
        }
    }

    // The other shards that have a subscriber for (realm, topic), as seen by shard `self`
    [[nodiscard]] std::vector<uint32_t> interested(unsigned self, std::string_view realm, std::string_view topic) {
        Member& m = *members_[self];
        std::lock_guard lock{m.interest_mutex};
        if (m.interest.empty()) return {};
        auto realm_it = m.interest.find(realm);
        if (realm_it == m.interest.end()) return {};
        auto topic_it = realm_it->second.find(topic);
        if (topic_it == realm_it->second.end()) return {};
        return topic_it->second;
    }

    // Queue `message` for each shard in `targets`. Shards whose inbox is now above the high-water mark are
    // appended to `congested`: the publishing session should wait_for_room() on them before reading more.
    void send(const std::vector<uint32_t>& targets, const CrossPublishPtr& message,
              std::vector<uint32_t>& congested) {
        for (uint32_t to : targets) {
            (void)push(to, CrossMessage{message}, congested);
        }
    }

    // Queue one message for one shard; false if it was dropped (only events are, when the inbox is full)
    bool send_to(uint32_t to, CrossMessage message, std::vector<uint32_t>& congested) {
        return push(to, std::move(message), congested);
    }

    // --- procedure registrations, one per (realm, procedure) across all shards -------------------------------
    // Same scheme as topic interest: a global table (guarded by one mutex, touched only when registering)
    // is the arbiter for uniqueness, and every other shard gets a replica entry "procedure -> shard" before
    // REGISTERED is sent, so a CALL after REGISTERED always finds the callee. The hot path (a CALL looking
    // up a remote procedure) takes only the caller's own replica lock.

    // Claims (realm, procedure) for shard `from`; false if it is registered anywhere already
    bool try_register(unsigned from, const std::string& realm, const std::string& procedure) {
        std::lock_guard lock{registration_mutex_};
        auto& owners = registrations_[realm];
        if (!owners.emplace(procedure, from).second) return false;
        for (unsigned j = 0; j < members_.size(); ++j) {
            if (j == from) continue;
            Member& m = *members_[j];
            std::lock_guard replica_lock{m.procedure_mutex};
            m.procedures[realm][procedure] = from;
        }
        return true;
    }

    void drop_registration(unsigned from, const std::string& realm, const std::string& procedure) {
        std::lock_guard lock{registration_mutex_};
        auto realm_it = registrations_.find(realm);
        if (realm_it == registrations_.end()) return;
        auto it = realm_it->second.find(procedure);
        if (it == realm_it->second.end() || it->second != from) return;
        realm_it->second.erase(it);
        if (realm_it->second.empty()) registrations_.erase(realm_it);
        for (unsigned j = 0; j < members_.size(); ++j) {
            if (j == from) continue;
            Member& m = *members_[j];
            std::lock_guard replica_lock{m.procedure_mutex};
            auto r = m.procedures.find(realm);
            if (r == m.procedures.end()) continue;
            r->second.erase(procedure);
            if (r->second.empty()) m.procedures.erase(r);
        }
    }

    // The other shard that holds the registration for (realm, procedure), as seen by shard `self`
    [[nodiscard]] std::optional<uint32_t> find_registration(unsigned self, std::string_view realm,
                                                             std::string_view procedure) {
        Member& m = *members_[self];
        std::lock_guard lock{m.procedure_mutex};
        if (m.procedures.empty()) return std::nullopt;
        auto r = m.procedures.find(realm);
        if (r == m.procedures.end()) return std::nullopt;
        auto it = r->second.find(procedure);
        if (it == r->second.end()) return std::nullopt;
        return it->second;
    }

    // Suspends the calling session until each of `shards` has worked its inbox back under the low-water
    // mark (or `timeout` passes). This is how a publisher on one shard is slowed down by a subscriber on
    // another, as it already is by one on its own shard.
    asio::awaitable<void> wait_for_room(std::vector<uint32_t> shards, std::chrono::milliseconds timeout) {
        auto executor = co_await asio::this_coro::executor;
        asio::steady_timer timer{executor};
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            bool congested = false;
            for (uint32_t s : shards) {
                if (members_[s]->depth.load(std::memory_order_relaxed) >= kLowWater) congested = true;
            }
            if (!congested) co_return;
            timer.expires_after(std::chrono::microseconds(100));
            co_await timer.async_wait(asio::use_awaitable);
        }
    }

    // Cross-shard events discarded because the destination's inbox was full
    [[nodiscard]] uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }

private:
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
    };

    using TopicMap = std::unordered_map<std::string, std::vector<uint32_t>, StringHash, std::equal_to<>>;

    struct alignas(64) Member {
        Shard* shard{nullptr};
        asio::io_context* io{nullptr};

        std::mutex interest_mutex;
        std::unordered_map<std::string, TopicMap, StringHash, std::equal_to<>> interest;  // realm -> topic -> shards

        std::mutex mailbox_mutex;
        std::vector<CrossMessage> mailbox;
        std::atomic<size_t> depth{0};  // queued plus being delivered; read by publishers waiting for room
        bool draining{false};  // a drain coroutine is scheduled or running

        std::mutex procedure_mutex;
        std::unordered_map<std::string, std::unordered_map<std::string, uint32_t, StringHash, std::equal_to<>>,
                           StringHash, std::equal_to<>> procedures;  // realm -> procedure -> shard (other shards only)
    };

    bool push(uint32_t to, CrossMessage message, std::vector<uint32_t>& congested) {
        Member& m = *members_[to];
        bool schedule = false;
        {
            std::lock_guard lock{m.mailbox_mutex};
            // Only events are shed at the cap. Calls and their results must not vanish (the caller would wait
            // forever); they are bounded by the sessions that issue them, which wait_for_room() slows down.
            if (m.mailbox.size() >= kMailboxCap && std::holds_alternative<CrossPublishPtr>(message)) {
                dropped_.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            m.mailbox.push_back(std::move(message));
            const auto depth = m.depth.fetch_add(1, std::memory_order_relaxed) + 1;
            if (depth >= kHighWater && std::ranges::find(congested, to) == congested.end()) {
                congested.push_back(to);
            }
            if (!m.draining) {
                m.draining = true;
                schedule = true;
            }
        }
        if (schedule) asio::co_spawn(*m.io, drain(to), asio::detached);
        return true;
    }

    asio::awaitable<void> drain(unsigned index) {
        Member& m = *members_[index];
        while (true) {
            std::vector<CrossMessage> batch;
            {
                std::lock_guard lock{m.mailbox_mutex};
                if (m.mailbox.empty()) {
                    m.draining = false;
                    co_return;
                }
                batch.swap(m.mailbox);
            }
            const auto count = batch.size();
            co_await handler_(*m.shard, std::move(batch));
            m.depth.fetch_sub(count, std::memory_order_relaxed);
        }
    }

    Handler handler_;
    std::vector<std::unique_ptr<Member>> members_;
    std::mutex registration_mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, uint32_t>> registrations_;  // realm -> procedure -> shard
    std::atomic<uint64_t> dropped_{0};
};

} // namespace wamp
