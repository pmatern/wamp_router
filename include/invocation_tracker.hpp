#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <list>
#include <utility>

namespace wamp {

// Information about a pending RPC call awaiting YIELD from callee
struct PendingCall {
    uint64_t caller_session_id;  // Who made the CALL
    uint64_t call_request_id;     // Original request_id from CALL message

    PendingCall(uint64_t caller_id, uint64_t request_id)
        : caller_session_id(caller_id)
        , call_request_id(request_id)
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

    void track(uint64_t invocation_id, const PendingCall& call_info) {
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

    [[nodiscard]] std::optional<PendingCall> peek(uint64_t invocation_id) const {
        auto map_it = invocation_map_.find(invocation_id);
        if (map_it == invocation_map_.end()) {
            return std::nullopt;
        }
        return map_it->second->second;
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

    [[nodiscard]] size_t pending_count() const {
        return lru_list_.size();
    }

    [[nodiscard]] size_t max_capacity() const {
        return max_pending_calls_;
    }

    [[nodiscard]] bool is_full() const {
        return lru_list_.size() >= max_pending_calls_;
    }

private:
    size_t max_pending_calls_;

    // LRU list: front = most recent, back = oldest
    // Each entry is (invocation_id, PendingCall)
    std::list<std::pair<uint64_t, PendingCall>> lru_list_;

    std::unordered_map<uint64_t, decltype(lru_list_)::iterator> invocation_map_;
};

} // namespace wamp
