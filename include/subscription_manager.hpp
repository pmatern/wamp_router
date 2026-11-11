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

#include "uri_match.hpp"
#include <algorithm>
#include <concepts>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <optional>

namespace wamp {

// Information about a single subscription
struct SubscriptionInfo {
    uint64_t subscription_id;
    std::string topic;    // the URI the client subscribed with: an exact topic or, for prefix/wildcard, the pattern
    uint64_t session_id;  // Which session owns this subscription
    Match match;

    SubscriptionInfo(uint64_t sub_id, std::string topic_uri, uint64_t sess_id, Match match_policy = Match::EXACT)
        : subscription_id(sub_id)
        , topic(std::move(topic_uri))
        , session_id(sess_id)
        , match(match_policy)
    {}
};

// A (match policy, URI) pair: what shards register interest in, and what "no subscriber left" refers to
struct SubscriptionKey {
    Match match;
    std::string uri;
    bool operator==(const SubscriptionKey&) const = default;
};

// ============================================================================
// SubscriptionManager - Manages topic subscriptions: exact, prefix and wildcard
// ============================================================================
// Exact topics are an O(1) hash lookup. Prefix and wildcard patterns are kept in separate tables that a publish only
// consults when some exist (has_patterns()): prefixes by one hash lookup per distinct prefix length, wildcards by a scan of
// the patterns with the topic's number of components.
class SubscriptionManager {
public:
    SubscriptionManager() = default;

    // subscription_id comes from the caller's ID generator
    void subscribe(uint64_t subscription_id, const std::string& topic, uint64_t session_id, Match match = Match::EXACT) {
        table(match, topic).emplace(subscription_id, session_id);
        if (match == Match::PREFIX && prefix_.at(topic).size() == 1) ++prefix_lengths_[topic.size()];
        subscriptions_.emplace(subscription_id, SubscriptionInfo{subscription_id, topic, session_id, match});
    }

    // Returns true if subscription existed and was removed
    bool unsubscribe(uint64_t subscription_id) {
        auto it = subscriptions_.find(subscription_id);
        if (it == subscriptions_.end()) {
            return false;
        }

        const auto& info = it->second;
        auto& subs = info.match == Match::EXACT ? exact_
                   : info.match == Match::PREFIX ? prefix_
                   : wildcard_[uri::component_count(info.topic)];
        if (auto topic_it = subs.find(info.topic); topic_it != subs.end()) {
            topic_it->second.erase(subscription_id);
            // Clean up empty topic entries
            if (topic_it->second.empty()) {
                if (info.match == Match::PREFIX) {
                    if (--prefix_lengths_[info.topic.size()] == 0) prefix_lengths_.erase(info.topic.size());
                }
                subs.erase(topic_it);
                if (info.match == Match::WILDCARD && subs.empty()) wildcard_.erase(uri::component_count(info.topic));
            }
        }

        subscriptions_.erase(it);
        return true;
    }

    // Unsubscribe all subscriptions for a session (for cleanup on disconnect).
    // Returns the (match, uri) keys that no longer have any subscriber.
    std::vector<SubscriptionKey> unsubscribe_session(uint64_t session_id) {
        // Collect subscription IDs to remove (can't modify during iteration)
        std::vector<uint64_t> to_remove;
        for (const auto& [sub_id, info] : subscriptions_) {
            if (info.session_id == session_id) {
                to_remove.push_back(sub_id);
            }
        }

        std::vector<SubscriptionKey> emptied;
        for (uint64_t sub_id : to_remove) {
            SubscriptionKey key{subscriptions_.at(sub_id).match, subscriptions_.at(sub_id).topic};
            unsubscribe(sub_id);
            if (subscriber_count(key.match, key.uri) == 0 && std::ranges::find(emptied, key) == emptied.end()) {
                emptied.push_back(std::move(key));
            }
        }
        return emptied;
    }

    // Subscriptions to exactly this topic (not counting patterns that would match it)
    [[nodiscard]] size_t subscriber_count(const std::string& topic) const {
        return subscriber_count(Match::EXACT, topic);
    }

    [[nodiscard]] size_t subscriber_count(Match match, const std::string& uri) const {
        const auto& subs = match == Match::EXACT ? exact_ : match == Match::PREFIX ? prefix_ : wildcard_view(uri);
        auto it = subs.find(uri);
        return it == subs.end() ? 0 : it->second.size();
    }

    // True if any prefix or wildcard subscription exists
    [[nodiscard]] bool has_patterns() const { return !prefix_.empty() || !wildcard_.empty(); }

    // Ids of the subscriptions a publish to `topic` reaches (copies; use for_each_subscriber on hot paths)
    [[nodiscard]] std::vector<uint64_t> get_subscribers(const std::string& topic) const {
        std::vector<uint64_t> ids;
        for_each_subscriber(topic, [&](uint64_t subscription_id, uint64_t) { ids.push_back(subscription_id); });
        return ids;
    }

    // Calls fn(subscription_id, session_id) or fn(subscription_id, session_id, Match) for each subscription a publish
    // to `topic` reaches: the exact ones, then the prefix and wildcard patterns that match. In place: no copy of the
    // subscriber sets. fn must not modify this manager.
    template<typename Fn>
        requires (std::invocable<Fn&, uint64_t, uint64_t> || std::invocable<Fn&, uint64_t, uint64_t, Match>)
    void for_each_subscriber(const std::string& topic, Fn&& fn) const {
        auto call = [&](uint64_t subscription_id, uint64_t session_id, Match match) {
            if constexpr (std::invocable<Fn&, uint64_t, uint64_t, Match>) fn(subscription_id, session_id, match);
            else fn(subscription_id, session_id);
        };
        if (auto it = exact_.find(topic); it != exact_.end()) {
            for (const auto& [subscription_id, session_id] : it->second) call(subscription_id, session_id, Match::EXACT);
        }
        if (!has_patterns()) return;

        for (const auto& [length, count] : prefix_lengths_) {
            if (length > topic.size()) break;  // lengths are ascending
            if (auto it = prefix_.find(std::string_view{topic}.substr(0, length)); it != prefix_.end()) {
                for (const auto& [subscription_id, session_id] : it->second) call(subscription_id, session_id, Match::PREFIX);
            }
        }
        if (auto group = wildcard_.find(uri::component_count(topic)); group != wildcard_.end()) {
            for (const auto& [pattern, subs] : group->second) {
                if (!uri::wildcard_matches(pattern, topic)) continue;
                for (const auto& [subscription_id, session_id] : subs) call(subscription_id, session_id, Match::WILDCARD);
            }
        }
    }

    [[nodiscard]] std::optional<SubscriptionInfo> get_subscription(uint64_t subscription_id) const {
        auto it = subscriptions_.find(subscription_id);
        if (it == subscriptions_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

private:
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
    };
    using Subscribers = std::unordered_map<uint64_t, uint64_t>;  // subscription ID -> owning session ID
    using ByUri = std::unordered_map<std::string, Subscribers, StringHash, std::equal_to<>>;

    Subscribers& table(Match match, const std::string& uri) {
        switch (match) {
            case Match::EXACT:  return exact_[uri];
            case Match::PREFIX: return prefix_[uri];
            default:            return wildcard_[uri::component_count(uri)][uri];
        }
    }

    const ByUri& wildcard_view(const std::string& pattern) const {
        static const ByUri none;
        auto it = wildcard_.find(uri::component_count(pattern));
        return it == wildcard_.end() ? none : it->second;
    }

    // topic -> (subscription ID -> owning session ID); O(1) lookup by topic, and iterating yields
    // everything needed to deliver an event without a second lookup
    ByUri exact_;
    ByUri prefix_;
    std::map<size_t, size_t> prefix_lengths_;      // distinct prefix lengths (ascending) -> number of prefixes of that length
    std::map<size_t, ByUri> wildcard_;             // number of components -> patterns

    // subscription_id -> subscription info (O(1) reverse lookup)
    std::unordered_map<uint64_t, SubscriptionInfo> subscriptions_;
};

} // namespace wamp
