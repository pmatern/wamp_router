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

#include <chrono>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <list>
#include <utility>
#include <vector>

namespace wamp {

// Information about a pending RPC call awaiting YIELD from callee
struct PendingCall {
    uint64_t invocation_id;       // The INVOCATION request id sent to the callee; the tracker's key
    uint64_t caller_session_id;  // Who made the CALL
    uint64_t call_request_id;     // Original request_id from CALL message
    uint64_t callee_session_id;   // Who was sent the INVOCATION (0 if unknown)
    std::chrono::steady_clock::time_point deadline;  // time_point::max() = no timeout
    int32_t caller_shard;         // shard the caller's session lives on, -1 = this shard (see ShardGroup)

    PendingCall(uint64_t inv_id, uint64_t caller_id, uint64_t request_id, uint64_t callee_id = 0,
                std::chrono::steady_clock::time_point call_deadline =
                    std::chrono::steady_clock::time_point::max(),
                int32_t caller_shard_index = -1)
        : invocation_id(inv_id)
        , caller_session_id(caller_id)
        , call_request_id(request_id)
        , callee_session_id(callee_id)
        , deadline(call_deadline)
        , caller_shard(caller_shard_index)
    {}
};

// ============================================================================
// InvocationTracker - LRU cache for tracking pending RPC invocations
// ============================================================================
// Maps invocation_id -> PendingCall info
// Size-limited with LRU eviction to prevent unbounded growth under load
class InvocationTracker {
public:
    explicit InvocationTracker(size_t max_pending = 10000)
        : max_pending_calls_(max_pending)
    {}

    void track(const PendingCall& call_info) {
        const uint64_t invocation_id = call_info.invocation_id;
        auto map_it = invocation_map_.find(invocation_id);
        if (map_it != invocation_map_.end()) {
            // Already exists - move to front (most recent)
            lru_list_.splice(lru_list_.begin(), lru_list_, map_it->second);
            map_it->second->second = call_info;
            return;
        }

        if (lru_list_.size() >= max_pending_calls_) {
            // Evict oldest (back of list)
            auto& oldest = lru_list_.back();
            invocation_map_.erase(oldest.first);
            lru_list_.pop_back();
        }

        lru_list_.emplace_front(invocation_id, call_info);
        invocation_map_[invocation_id] = lru_list_.begin();
    }

    // Retrieve and remove invocation info (called when YIELD received)
    // Returns nullopt if invocation_id not found (timeout, eviction, or invalid)
    [[nodiscard]] std::optional<PendingCall> retrieve(uint64_t invocation_id) {
        auto map_it = invocation_map_.find(invocation_id);
        if (map_it == invocation_map_.end()) {
            return std::nullopt;
        }

        auto list_it = map_it->second;
        PendingCall info = list_it->second;

        lru_list_.erase(list_it);
        invocation_map_.erase(map_it);

        return info;
    }

    // Remove all pending invocations for a session (called on disconnect)
    void remove_caller_session(uint64_t caller_session_id) {
        auto it = lru_list_.begin();
        while (it != lru_list_.end()) {
            if (it->second.caller_session_id == caller_session_id) {
                invocation_map_.erase(it->first);
                it = lru_list_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Remove and return all pending invocations routed to a callee (called when the callee disconnects)
    [[nodiscard]] std::vector<PendingCall> remove_callee_session(uint64_t callee_session_id) {
        std::vector<PendingCall> removed;
        auto it = lru_list_.begin();
        while (it != lru_list_.end()) {
            if (it->second.callee_session_id == callee_session_id) {
                removed.push_back(it->second);
                invocation_map_.erase(it->first);
                it = lru_list_.erase(it);
            } else {
                ++it;
            }
        }
        return removed;
    }

    // Remove and return all pending invocations whose deadline has passed
    [[nodiscard]] std::vector<PendingCall> remove_expired(std::chrono::steady_clock::time_point now) {
        std::vector<PendingCall> removed;
        auto it = lru_list_.begin();
        while (it != lru_list_.end()) {
            if (it->second.deadline <= now) {
                removed.push_back(it->second);
                invocation_map_.erase(it->first);
                it = lru_list_.erase(it);
            } else {
                ++it;
            }
        }
        return removed;
    }

    [[nodiscard]] size_t pending_count() const {
        return lru_list_.size();
    }

    [[nodiscard]] size_t max_capacity() const {
        return max_pending_calls_;
    }

private:
    size_t max_pending_calls_;

    // LRU list: front = most recent, back = oldest
    // Each entry is (invocation_id, PendingCall)
    std::list<std::pair<uint64_t, PendingCall>> lru_list_;

    std::unordered_map<uint64_t, decltype(lru_list_)::iterator> invocation_map_;
};

} // namespace wamp
