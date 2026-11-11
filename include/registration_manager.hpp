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
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <optional>

namespace wamp {

// Information about a single procedure registration
struct RegistrationInfo {
    uint64_t registration_id;
    std::string procedure;  // the URI registered: an exact procedure or, for prefix/wildcard, the pattern
    uint64_t session_id;    // Which session registered this procedure (the callee)
    Match match;

    RegistrationInfo(uint64_t reg_id, std::string proc_uri, uint64_t sess_id, Match match_policy = Match::EXACT)
        : registration_id(reg_id)
        , procedure(std::move(proc_uri))
        , session_id(sess_id)
        , match(match_policy)
    {}
};

// A (match policy, URI) pair, the unit of registration uniqueness across shards
struct RegistrationKey {
    Match match;
    std::string uri;
    bool operator==(const RegistrationKey&) const = default;
};

// ============================================================================
// RegistrationManager - Manages procedure registrations for RPC: exact, prefix and wildcard
// ============================================================================
// At most one registration per (match, URI), first come first served (WAMP also has invocation policies for
// several callees; not supported). A call resolves to exactly one registration: exact first, then the longest
// matching prefix, then the wildcard with the most literal components (uri::more_specific).
class RegistrationManager {
public:
    RegistrationManager() = default;

    // Returns true if registration succeeded, false if (match, procedure) is already registered
    bool register_procedure(uint64_t registration_id, const std::string& procedure, uint64_t session_id,
                            Match match = Match::EXACT) {
        auto& slot = table(match, procedure);
        if (slot.contains(procedure)) {
            return false;
        }

        slot[procedure] = registration_id;
        if (match == Match::PREFIX) ++prefix_lengths_[procedure.size()];
        registrations_.emplace(registration_id, RegistrationInfo{registration_id, procedure, session_id, match});
        session_registrations_[session_id].insert(registration_id);

        return true;
    }

    // Returns true if registration existed and was removed
    bool unregister(uint64_t registration_id) {
        auto it = registrations_.find(registration_id);
        if (it == registrations_.end()) {
            return false;
        }

        const auto& info = it->second;
        const uint64_t session_id = info.session_id;

        auto& slot = table(info.match, info.procedure);
        slot.erase(info.procedure);
        if (info.match == Match::PREFIX && --prefix_lengths_[info.procedure.size()] == 0) {
            prefix_lengths_.erase(info.procedure.size());
        }
        if (info.match == Match::WILDCARD && slot.empty()) wildcard_.erase(uri::component_count(info.procedure));

        auto session_it = session_registrations_.find(session_id);
        if (session_it != session_registrations_.end()) {
            session_it->second.erase(registration_id);

            if (session_it->second.empty()) {
                session_registrations_.erase(session_it);
            }
        }

        registrations_.erase(it);

        return true;
    }

    // Unregister all procedures for a session (for cleanup on disconnect); returns the (match, URI) keys removed
    std::vector<RegistrationKey> unregister_session(uint64_t session_id) {
        std::vector<RegistrationKey> removed;
        auto it = session_registrations_.find(session_id);
        if (it == session_registrations_.end()) {
            return removed;  // No registrations for this session
        }

        // Collect registration IDs to remove (can't modify during iteration)
        std::vector<uint64_t> to_remove{it->second.begin(), it->second.end()};
        for (uint64_t reg_id : to_remove) {
            if (auto info = get_registration(reg_id)) removed.push_back({info->match, info->procedure});
            unregister(reg_id);
        }
        return removed;
    }

    // The registration a call to `procedure` goes to, nullopt if none matches
    [[nodiscard]] std::optional<RegistrationInfo> find_callee(const std::string& procedure) const {
        if (auto it = exact_.find(procedure); it != exact_.end()) {
            return get_registration(it->second);
        }
        if (prefix_.empty() && wildcard_.empty()) {
            return std::nullopt;  // Procedure not registered
        }

        // Longest matching prefix: lengths are visited from the longest down
        for (auto length = prefix_lengths_.rbegin(); length != prefix_lengths_.rend(); ++length) {
            if (length->first > procedure.size()) continue;
            if (auto it = prefix_.find(std::string_view{procedure}.substr(0, length->first)); it != prefix_.end()) {
                return get_registration(it->second);
            }
        }

        const std::string* best = nullptr;
        uint64_t best_id = 0;
        if (auto group = wildcard_.find(uri::component_count(procedure)); group != wildcard_.end()) {
            for (const auto& [pattern, registration_id] : group->second) {
                if (!uri::wildcard_matches(pattern, procedure)) continue;
                if (best == nullptr || uri::more_specific(Match::WILDCARD, pattern, Match::WILDCARD, *best)) {
                    best = &pattern;
                    best_id = registration_id;
                }
            }
        }
        return best != nullptr ? get_registration(best_id) : std::nullopt;
    }

    [[nodiscard]] std::optional<RegistrationInfo> get_registration(uint64_t registration_id) const {
        auto it = registrations_.find(registration_id);
        if (it == registrations_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    // True if any prefix or wildcard registration exists
    [[nodiscard]] bool has_patterns() const { return !prefix_.empty() || !wildcard_.empty(); }

private:
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
    };
    using ByUri = std::unordered_map<std::string, uint64_t, StringHash, std::equal_to<>>;

    ByUri& table(Match match, const std::string& procedure) {
        switch (match) {
            case Match::EXACT:  return exact_;
            case Match::PREFIX: return prefix_;
            default:            return wildcard_[uri::component_count(procedure)];
        }
    }

    // procedure URI -> registration_id (O(1) lookup by procedure); one registration per (match, URI)
    ByUri exact_;
    ByUri prefix_;
    std::map<size_t, size_t> prefix_lengths_;   // distinct prefix lengths -> number of prefixes of that length
    std::map<size_t, ByUri> wildcard_;          // number of components -> patterns

    // registration_id -> registration info (O(1) reverse lookup)
    std::unordered_map<uint64_t, RegistrationInfo> registrations_;

    // session_id -> set of registration_ids (for cleanup on disconnect)
    std::unordered_map<uint64_t, std::unordered_set<uint64_t>> session_registrations_;
};

} // namespace wamp
