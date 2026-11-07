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
#include "event_channel.hpp"
#include "invocation_tracker.hpp"
#include "realm.hpp"
#include "wamp_id.hpp"
#include <chrono>

namespace wamp {

// What a Shard needs from the server configuration
struct ShardConfig {
    EventQueueConfig events{};
    size_t max_pending_invocations{10000};
    std::chrono::milliseconds call_timeout{30000};  // default time a callee has to answer a CALL, 0 = none

    [[nodiscard]] static ShardConfig from(const ServerConfig& config) {
        return {config.events, config.max_pending_invocations > 0 ? config.max_pending_invocations : 10000,
                config.call_timeout};
    }
};

// ============================================================================
// Shard - everything one router thread mutates
// ============================================================================
// All routing state that used to be process-wide statics lives here: the per-session event channels,
// the pending-call tracker, the realms (subscriptions and registrations), and the id generators.
// A shard is owned by exactly one thread (one io_context) and is not synchronized, so the router
// can run several shards side by side, each with its own sessions, without sharing mutable state.
// Sessions, handlers and servers receive the shard they belong to by reference.
class Shard {
public:
    explicit Shard(ShardConfig config = {})
        : call_timeout(config.call_timeout)
        , invocations(config.max_pending_invocations)
        , realms(*this)
    {
        channels.configure(config.events);
    }

    Shard(const Shard&) = delete;
    Shard& operator=(const Shard&) = delete;

    EventChannelRegistry channels;
    InvocationTracker invocations;
    RealmRegistry realms;
    std::chrono::milliseconds call_timeout;

    // Session and publication ids are drawn randomly from the global scope; subscription, registration
    // and invocation ids are sequential router-scope ids
    struct IdGenerators {
        GlobalIdGenerator session;
        GlobalIdGenerator publication;
        RouterScopeIdGenerator subscription;
        RouterScopeIdGenerator registration;
        RouterScopeIdGenerator invocation;
    } ids;
};

} // namespace wamp
