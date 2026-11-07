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

#include "registration_manager.hpp"
#include "subscription_manager.hpp"
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

namespace wamp {

class Shard;

// ============================================================================
// Realm - the routing state of one WAMP realm (within one Shard)
// ============================================================================
// Topics and procedures are only visible inside their realm: the same URI in two realms refers to
// two unrelated topics/procedures. Sessions are bound to one realm for their lifetime.
struct Realm {
    explicit Realm(Shard& owner) : shard(owner) {}

    Shard& shard;  // the shard that owns this realm: channels, invocations and id generators live there
    SubscriptionManager subscriptions;
    RegistrationManager registrations;
};

// The realms of one Shard, created on first use. Not synchronized: a shard is owned by one thread.
class RealmRegistry {
public:
    explicit RealmRegistry(Shard& owner) : owner_(owner) {}
    RealmRegistry(const RealmRegistry&) = delete;
    RealmRegistry& operator=(const RealmRegistry&) = delete;

    // The returned reference stays valid for the life of the registry
    [[nodiscard]] Realm& get(std::string_view name) {
        if (auto it = realms_.find(name); it != realms_.end()) {
            return *it->second;
        }
        return *realms_.emplace(std::string{name}, std::make_unique<Realm>(owner_)).first->second;
    }

    [[nodiscard]] size_t count() const {
        return realms_.size();
    }

private:
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
    };

    Shard& owner_;
    std::unordered_map<std::string, std::unique_ptr<Realm>, StringHash, std::equal_to<>> realms_;
};

} // namespace wamp
