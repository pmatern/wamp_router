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
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
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
    using Handler = std::function<asio::awaitable<void>(Shard&, std::vector<CrossPublishPtr>)>;

    static constexpr size_t kMailboxCap = 1 << 16;

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

    // Queue `message` for each shard in `targets`
    void send(const std::vector<uint32_t>& targets, const CrossPublishPtr& message) {
        for (uint32_t to : targets) {
            Member& m = *members_[to];
            bool schedule = false;
            {
                std::lock_guard lock{m.mailbox_mutex};
                if (m.mailbox.size() >= kMailboxCap) {
                    dropped_.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                m.mailbox.push_back(message);
                if (!m.draining) {
                    m.draining = true;
                    schedule = true;
                }
            }
            if (schedule) asio::co_spawn(*m.io, drain(to), asio::detached);
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
        std::vector<CrossPublishPtr> mailbox;
        bool draining{false};  // a drain coroutine is scheduled or running
    };

    asio::awaitable<void> drain(unsigned index) {
        Member& m = *members_[index];
        while (true) {
            std::vector<CrossPublishPtr> batch;
            {
                std::lock_guard lock{m.mailbox_mutex};
                if (m.mailbox.empty()) {
                    m.draining = false;
                    co_return;
                }
                batch.swap(m.mailbox);
            }
            co_await handler_(*m.shard, std::move(batch));
        }
    }

    Handler handler_;
    std::vector<std::unique_ptr<Member>> members_;
    std::atomic<uint64_t> dropped_{0};
};

} // namespace wamp
