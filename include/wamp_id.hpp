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

#include <cstdint>
#include <random>

namespace wamp {

// WAMP ID generation according to spec section 2.1.2
// https://wamp-proto.org/wamp_latest_ietf.txt
//
// ID range: [1, 2^53]
// - Lower bound 1: because 0 is falsy in many languages
// - Upper bound 2^53: largest integer representable exactly in IEEE-754 double

constexpr uint64_t WAMP_ID_MIN = 1;
constexpr uint64_t WAMP_ID_MAX = 9007199254740992ULL; // 2^53

// ============================================================================
// Global Scope ID Generator
// ============================================================================
// Used for: Session IDs, Publication IDs
// Requirement: "IDs in the global scope MUST be drawn randomly from a uniform
//              distribution over the complete range [1, 2^53]"
class GlobalIdGenerator {
public:
    GlobalIdGenerator()
        : rng_(std::random_device{}())
        , distribution_(WAMP_ID_MIN, WAMP_ID_MAX)
    {
    }

    uint64_t generate() {
        return distribution_(rng_);
    }

private:
    std::mt19937_64 rng_;
    std::uniform_int_distribution<uint64_t> distribution_;
};

// ============================================================================
// Router Scope ID Generator
// ============================================================================
// Used for: Subscription IDs, Registration IDs
// Requirement: "CAN be chosen freely by the specific router implementation"
// Implementation choice: use sequential IDs for simplicity and debugging
class RouterScopeIdGenerator {
public:
    RouterScopeIdGenerator()
        : next_id_(WAMP_ID_MIN)
    {
    }

    uint64_t generate() {
        uint64_t id = next_id_;

        if (next_id_ == WAMP_ID_MAX) {
            next_id_ = WAMP_ID_MIN;
        } else {
            ++next_id_;
        }

        return id;
    }

private:
    uint64_t next_id_;
};

// ============================================================================
// Session Scope ID Generator
// ============================================================================
// Used for: Request IDs (within a single session)
// Requirement: "IDs in the session scope MUST be incremented by 1 beginning
//              with 1 and wrapping to 1 after it reached 2^53"
class SessionScopeIdGenerator {
public:
    SessionScopeIdGenerator()
        : next_id_(WAMP_ID_MIN)
    {
    }

    uint64_t generate() {
        uint64_t id = next_id_;

        if (next_id_ == WAMP_ID_MAX) {
            next_id_ = WAMP_ID_MIN;
        } else {
            ++next_id_;
        }

        return id;
    }

    void reset() {
        next_id_ = WAMP_ID_MIN;
    }

private:
    uint64_t next_id_;
};

} // namespace wamp
