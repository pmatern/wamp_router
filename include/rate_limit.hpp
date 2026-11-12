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

#include <algorithm>
#include <asio/ip/address.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>

namespace wamp {

// ============================================================================
// TokenBucket - a rate limit with a burst allowance
// ============================================================================
// Holds up to `burst` tokens and gains `rate` tokens per second. Time is passed in (steady_clock) so a test can drive
// it. Not synchronized: each bucket belongs to one thread.
class TokenBucket {
public:
    using Clock = std::chrono::steady_clock;

    TokenBucket(double rate_per_second, double burst, Clock::time_point now)
        : rate_(rate_per_second), burst_(burst), tokens_(burst), last_(now) {}

    // Takes one token if there is one (a connection either passes or it does not)
    [[nodiscard]] bool try_consume(Clock::time_point now) {
        refill(now);
        if (tokens_ < 1.0) return false;
        tokens_ -= 1.0;
        return true;
    }

    // Takes `n` tokens even if that puts the bucket in debt, and returns how long the caller should wait for the debt to
    // be paid off (0 = it was within the limit). The debt is carried, not forgiven: a caller that handles a whole read's
    // worth of messages at once and then waits (as a session does) still averages out to the rate. (Capped at a billion
    // tokens only so the arithmetic cannot overflow.)
    [[nodiscard]] std::chrono::nanoseconds consume(uint64_t n, Clock::time_point now) {
        refill(now);
        tokens_ -= static_cast<double>(n);
        tokens_ = std::max(tokens_, -1e9);
        if (tokens_ >= 0.0) return std::chrono::nanoseconds{0};
        return std::chrono::nanoseconds{static_cast<int64_t>(-tokens_ / rate_ * 1e9)};
    }

    // True if the bucket is back to its full burst (nothing to remember about this client)
    [[nodiscard]] bool full(Clock::time_point now) const {
        return tokens_ + std::chrono::duration<double>(now - last_).count() * rate_ >= burst_;
    }

    [[nodiscard]] double tokens() const { return tokens_; }

private:
    void refill(Clock::time_point now) {
        if (now <= last_) return;
        tokens_ = std::min(burst_, tokens_ + std::chrono::duration<double>(now - last_).count() * rate_);
        last_ = now;
    }

    double rate_;
    double burst_;
    double tokens_;
    Clock::time_point last_;
};

// ============================================================================
// ConnectionRateLimiter - new connections per second, per client address
// ============================================================================
// Used by the acceptor thread only, so there is no lock. Each address has a token bucket; entries whose bucket is full
// again are pruned every kPruneEvery admissions, and no more than kMaxEntries addresses are tracked at once: an attacker
// that sprays more addresses than that cannot be limited per address anyway, and the map must not grow without bound.
// 0 = off.
class ConnectionRateLimiter {
public:
    using Clock = TokenBucket::Clock;
    static constexpr size_t kPruneEvery = 4096;
    static constexpr size_t kMaxEntries = 100'000;

    ConnectionRateLimiter(double rate_per_second, double burst) : rate_(rate_per_second), burst_(std::max(burst, 1.0)) {}

    [[nodiscard]] bool enabled() const { return rate_ > 0.0; }

    // False if `address` has used up its allowance of new connections
    [[nodiscard]] bool admit(const asio::ip::address& address, Clock::time_point now = Clock::now()) {
        if (!enabled()) return true;
        if (++admissions_ % kPruneEvery == 0) prune(now);
        auto it = buckets_.find(address);
        if (it == buckets_.end()) {
            if (buckets_.size() >= kMaxEntries) return true;   // untracked: see above
            it = buckets_.emplace(address, TokenBucket{rate_, burst_, now}).first;
        }
        return it->second.try_consume(now);
    }

    [[nodiscard]] size_t tracked() const { return buckets_.size(); }

private:
    void prune(Clock::time_point now) {
        for (auto it = buckets_.begin(); it != buckets_.end();) {
            it = it->second.full(now) ? buckets_.erase(it) : std::next(it);
        }
    }

    double rate_;
    double burst_;
    uint64_t admissions_{0};
    std::unordered_map<asio::ip::address, TokenBucket> buckets_;
};

} // namespace wamp
