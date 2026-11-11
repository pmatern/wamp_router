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
#include "uri_match.hpp"
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
#include <map>
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
    bool ppt{false};  // a passthru event: only subscribers that announced the feature get it
    // The same EVENT with details.topic, for prefix/wildcard subscribers; set when any pattern subscription exists
    std::optional<EventTemplate> pattern_event;
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
    WampDict ppt;            // the CALL's ppt_* options, forwarded as INVOCATION details
    WampList arguments;
    WampDict arguments_kw;
};

// A complete frame (RESULT, ERROR) for a session that lives on the receiving shard
struct CrossFrame {
    uint64_t session_id{};
    std::shared_ptr<const std::vector<uint8_t>> frame;
};

// A caller on the sending shard disconnected: drop its pending calls on the receiving shard and interrupt the callees
struct CrossCancel {
    uint64_t caller_session{};
};

// A caller sent CANCEL for a call that is not pending on its own shard: the shard that holds the pending call
// applies the cancellation mode and answers the caller with a CrossFrame
struct CrossCancelCall {
    uint32_t caller_shard{};
    uint64_t caller_session{};
    uint64_t request_id{};  // the caller's CALL request id
    std::string mode;       // "skip", "kill" or "killnowait"
};

using CrossMessage = std::variant<CrossPublishPtr, CrossCall, CrossFrame, CrossCancel, CrossCancelCall>;

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
        std::vector<uint32_t> shards;
        if (!m.interest.empty()) {
            if (auto realm_it = m.interest.find(realm); realm_it != m.interest.end()) {
                if (auto topic_it = realm_it->second.find(topic); topic_it != realm_it->second.end()) {
                    shards = topic_it->second;
                }
            }
        }
        if (!m.pattern_interest.empty()) {
            if (auto realm_it = m.pattern_interest.find(realm); realm_it != m.pattern_interest.end()) {
                for (const auto& entry : realm_it->second) {
                    if (uri::matches(entry.match, entry.uri, topic) && std::ranges::find(shards, entry.shard) == shards.end()) {
                        shards.push_back(entry.shard);
                    }
                }
            }
        }
        return shards;
    }

    // Shard `from` now has a prefix or wildcard subscription to `uri` where it had none. Pattern interest is a short
    // list per realm that a publish scans; it is updated only when a shard gains its first or loses its last
    // subscription for a (match, uri).
    void add_pattern_interest(unsigned from, const std::string& realm, Match match, const std::string& uri) {
        pattern_keys_.fetch_add(1);   // before the replicas change: a publisher that sees an entry sees the count
        for (unsigned j = 0; j < members_.size(); ++j) {
            if (j == from) continue;
            Member& m = *members_[j];
            std::lock_guard lock{m.interest_mutex};
            auto& entries = m.pattern_interest[realm];
            const PatternEntry entry{match, uri, from};
            if (std::ranges::find(entries, entry) == entries.end()) entries.push_back(entry);
        }
    }

    void remove_pattern_interest(unsigned from, const std::string& realm, Match match, const std::string& uri) {
        for (unsigned j = 0; j < members_.size(); ++j) {
            if (j == from) continue;
            Member& m = *members_[j];
            std::lock_guard lock{m.interest_mutex};
            auto realm_it = m.pattern_interest.find(realm);
            if (realm_it == m.pattern_interest.end()) continue;
            std::erase(realm_it->second, PatternEntry{match, uri, from});
            if (realm_it->second.empty()) m.pattern_interest.erase(realm_it);
        }
        pattern_keys_.fetch_sub(1);
    }

    // True while any shard has a prefix or wildcard subscription: publishers then build the pattern EVENT template
    [[nodiscard]] bool has_pattern_interest() const { return pattern_keys_.load() > 0; }

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

    // Claims (realm, match, procedure) for shard `from`; false if it is registered anywhere already
    bool try_register(unsigned from, const std::string& realm, const std::string& procedure,
                      Match match = Match::EXACT) {
        std::lock_guard lock{registration_mutex_};
        if (match != Match::EXACT) {
            if (!pattern_registrations_[realm].emplace(PatternKey{match, procedure}, from).second) return false;
            for (unsigned j = 0; j < members_.size(); ++j) {
                if (j == from) continue;
                Member& m = *members_[j];
                std::lock_guard replica_lock{m.procedure_mutex};
                m.procedure_patterns[realm].push_back(PatternEntry{match, procedure, from});
            }
            return true;
        }
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

    void drop_registration(unsigned from, const std::string& realm, const std::string& procedure,
                           Match match = Match::EXACT) {
        std::lock_guard lock{registration_mutex_};
        if (match != Match::EXACT) {
            auto owners = pattern_registrations_.find(realm);
            if (owners == pattern_registrations_.end()) return;
            auto it = owners->second.find(PatternKey{match, procedure});
            if (it == owners->second.end() || it->second != from) return;
            owners->second.erase(it);
            if (owners->second.empty()) pattern_registrations_.erase(owners);
            for (unsigned j = 0; j < members_.size(); ++j) {
                if (j == from) continue;
                Member& m = *members_[j];
                std::lock_guard replica_lock{m.procedure_mutex};
                auto r = m.procedure_patterns.find(realm);
                if (r == m.procedure_patterns.end()) continue;
                std::erase(r->second, PatternEntry{match, procedure, from});
                if (r->second.empty()) m.procedure_patterns.erase(r);
            }
            return;
        }
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

    // A registration on another shard that matches a called procedure
    struct RemoteRegistration {
        uint32_t shard;
        Match match;
        std::string uri;
    };

    // The best registration on another shard for a call to (realm, procedure), as seen by shard `self`: the exact
    // one if there is one, else the most specific pattern (uri::more_specific)
    [[nodiscard]] std::optional<RemoteRegistration> find_registration(unsigned self, std::string_view realm,
                                                                      std::string_view procedure) {
        Member& m = *members_[self];
        std::lock_guard lock{m.procedure_mutex};
        if (m.procedures.empty() && m.procedure_patterns.empty()) return std::nullopt;
        if (auto r = m.procedures.find(realm); r != m.procedures.end()) {
            if (auto it = r->second.find(procedure); it != r->second.end()) {
                return RemoteRegistration{it->second, Match::EXACT, std::string{procedure}};
            }
        }
        std::optional<RemoteRegistration> best;
        if (auto r = m.procedure_patterns.find(realm); r != m.procedure_patterns.end()) {
            for (const auto& entry : r->second) {
                if (!uri::matches(entry.match, entry.uri, procedure)) continue;
                if (!best || uri::more_specific(entry.match, entry.uri, best->match, best->uri)) {
                    best = RemoteRegistration{entry.shard, entry.match, entry.uri};
                }
            }
        }
        return best;
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
    [[nodiscard]] uint64_t dropped() const {
        uint64_t total = 0;
        for (const auto& m : members_) total += m->dropped.load(std::memory_order_relaxed);
        return total;
    }

    // Messages queued for, or being delivered on, one shard
    [[nodiscard]] size_t depth(unsigned index) const { return members_[index]->depth.load(std::memory_order_relaxed); }
    // Messages shard `index` has taken from its inbox since startup
    [[nodiscard]] uint64_t received(unsigned index) const {
        return members_[index]->received.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t dropped(unsigned index) const {
        return members_[index]->dropped.load(std::memory_order_relaxed);
    }
    // Messages in flight across all shards (shutdown waits for this to reach zero)
    [[nodiscard]] size_t pending() const {
        size_t total = 0;
        for (const auto& m : members_) total += m->depth.load(std::memory_order_relaxed);
        return total;
    }

private:
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
    };

    using TopicMap = std::unordered_map<std::string, std::vector<uint32_t>, StringHash, std::equal_to<>>;

    // A prefix or wildcard (match, uri) that `shard` has a subscription or registration for
    struct PatternEntry {
        Match match;
        std::string uri;
        uint32_t shard;
        bool operator==(const PatternEntry&) const = default;
    };
    using PatternKey = std::pair<Match, std::string>;
    using PatternList = std::unordered_map<std::string, std::vector<PatternEntry>, StringHash, std::equal_to<>>;

    struct alignas(64) Member {
        Shard* shard{nullptr};
        asio::io_context* io{nullptr};

        std::mutex interest_mutex;
        std::unordered_map<std::string, TopicMap, StringHash, std::equal_to<>> interest;  // realm -> topic -> shards
        PatternList pattern_interest;  // realm -> prefix/wildcard subscriptions of the other shards (interest_mutex)

        std::mutex mailbox_mutex;
        std::vector<CrossMessage> mailbox;
        std::atomic<uint64_t> received{0};  // messages taken from the mailbox
        std::atomic<uint64_t> dropped{0};   // events discarded because the mailbox was full
        std::atomic<size_t> depth{0};  // queued plus being delivered; read by publishers waiting for room
        bool draining{false};  // a drain coroutine is scheduled or running

        std::mutex procedure_mutex;
        std::unordered_map<std::string, std::unordered_map<std::string, uint32_t, StringHash, std::equal_to<>>,
                           StringHash, std::equal_to<>> procedures;  // realm -> procedure -> shard (other shards only)
        PatternList procedure_patterns;  // realm -> prefix/wildcard registrations of the other shards (procedure_mutex)
    };

    bool push(uint32_t to, CrossMessage message, std::vector<uint32_t>& congested) {
        Member& m = *members_[to];
        bool schedule = false;
        {
            std::lock_guard lock{m.mailbox_mutex};
            // Only events are shed at the cap. Calls and their results must not vanish (the caller would wait
            // forever); they are bounded by the sessions that issue them, which wait_for_room() slows down.
            if (m.mailbox.size() >= kMailboxCap && std::holds_alternative<CrossPublishPtr>(message)) {
                m.dropped.fetch_add(1, std::memory_order_relaxed);
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
            m.received.fetch_add(count, std::memory_order_relaxed);
            co_await handler_(*m.shard, std::move(batch));
            m.depth.fetch_sub(count, std::memory_order_relaxed);
        }
    }

    Handler handler_;
    std::vector<std::unique_ptr<Member>> members_;
    std::mutex registration_mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, uint32_t>> registrations_;  // realm -> procedure -> shard
    std::unordered_map<std::string, std::map<PatternKey, uint32_t>> pattern_registrations_;     // realm -> (match, uri) -> shard
    std::atomic<size_t> pattern_keys_{0};   // (shard, match, uri) prefix/wildcard subscriptions that exist
};

} // namespace wamp
