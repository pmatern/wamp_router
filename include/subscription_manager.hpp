// Copyright 2026 Patrick Matern
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
    std::string topic;
    uint64_t session_id;  // Which session owns this subscription

    SubscriptionInfo(uint64_t sub_id, std::string topic_uri, uint64_t sess_id)
        : subscription_id(sub_id)
        , topic(std::move(topic_uri))
        , session_id(sess_id)
    {}
};

// ============================================================================
// SubscriptionManager - Manages topic subscriptions with exact matching
// ============================================================================
// Simple O(1) implementation for exact topic matching
// Future: Can be extended to support prefix/wildcard matching with trie
class SubscriptionManager {
public:
    SubscriptionManager() = default;

    // Returns subscription_id (caller provides this from ID generator)
    void subscribe(uint64_t subscription_id, const std::string& topic, uint64_t session_id) {
        topic_subscriptions_[topic].insert(subscription_id);

        // Store reverse lookup: subscription_id -> info
        subscriptions_.emplace(subscription_id, SubscriptionInfo{subscription_id, topic, session_id});
    }

    // Returns true if subscription existed and was removed
    bool unsubscribe(uint64_t subscription_id) {
        auto it = subscriptions_.find(subscription_id);
        if (it == subscriptions_.end()) {
            return false;
        }

        const auto& info = it->second;
        const std::string& topic = info.topic;

        auto topic_it = topic_subscriptions_.find(topic);
        if (topic_it != topic_subscriptions_.end()) {
            topic_it->second.erase(subscription_id);

            // Clean up empty topic entries
            if (topic_it->second.empty()) {
                topic_subscriptions_.erase(topic_it);
            }
        }

        subscriptions_.erase(it);

        return true;
    }

    // Unsubscribe all subscriptions for a session (for cleanup on disconnect)
    void unsubscribe_session(uint64_t session_id) {
        // Collect subscription IDs to remove (can't modify during iteration)
        std::vector<uint64_t> to_remove;
        for (const auto& [sub_id, info] : subscriptions_) {
            if (info.session_id == session_id) {
                to_remove.push_back(sub_id);
            }
        }

        for (uint64_t sub_id : to_remove) {
            unsubscribe(sub_id);
        }
    }

    // Returns empty vector if no subscribers
    [[nodiscard]] std::vector<uint64_t> get_subscribers(const std::string& topic) const {
        auto it = topic_subscriptions_.find(topic);
        if (it == topic_subscriptions_.end()) {
            return {};
        }

        return std::vector<uint64_t>{it->second.begin(), it->second.end()};
    }

    [[nodiscard]] std::optional<SubscriptionInfo> get_subscription(uint64_t subscription_id) const {
        auto it = subscriptions_.find(subscription_id);
        if (it == subscriptions_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

private:
    // topic -> set of subscription IDs (O(1) lookup by topic)
    std::unordered_map<std::string, std::unordered_set<uint64_t>> topic_subscriptions_;

    // subscription_id -> subscription info (O(1) reverse lookup)
    std::unordered_map<uint64_t, SubscriptionInfo> subscriptions_;
};

} // namespace wamp
