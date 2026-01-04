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

// Information about a single procedure registration
struct RegistrationInfo {
    uint64_t registration_id;
    std::string procedure;
    uint64_t session_id;  // Which session registered this procedure (the callee)

    RegistrationInfo(uint64_t reg_id, std::string proc_uri, uint64_t sess_id)
        : registration_id(reg_id)
        , procedure(std::move(proc_uri))
        , session_id(sess_id)
    {}
};

// ============================================================================
// RegistrationManager - Manages procedure registrations for RPC
// ============================================================================
// Tracks which sessions have registered which procedures
// For simplicity, only one registration per procedure (first-come-first-served)
// Real WAMP supports multiple registrations with invocation policies
class RegistrationManager {
public:
    RegistrationManager() = default;

    // Returns true if registration succeeded, false if procedure already registered
    bool register_procedure(uint64_t registration_id, const std::string& procedure, uint64_t session_id) {
        if (procedure_to_registration_.contains(procedure)) {
            return false;
        }

        procedure_to_registration_[procedure] = registration_id;
        registrations_.emplace(registration_id, RegistrationInfo{registration_id, procedure, session_id});
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
        const std::string& procedure = info.procedure;
        const uint64_t session_id = info.session_id;

        procedure_to_registration_.erase(procedure);

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

    // Unregister all procedures for a session (for cleanup on disconnect)
    void unregister_session(uint64_t session_id) {
        auto it = session_registrations_.find(session_id);
        if (it == session_registrations_.end()) {
            return;  // No registrations for this session
        }

        // Collect registration IDs to remove (can't modify during iteration)
        std::vector<uint64_t> to_remove{it->second.begin(), it->second.end()};
        for (uint64_t reg_id : to_remove) {
            unregister(reg_id);
        }
    }

    // Returns registration info if procedure is registered, nullopt otherwise
    [[nodiscard]] std::optional<RegistrationInfo> find_callee(const std::string& procedure) const {
        auto proc_it = procedure_to_registration_.find(procedure);
        if (proc_it == procedure_to_registration_.end()) {
            return std::nullopt;  // Procedure not registered
        }

        uint64_t registration_id = proc_it->second;
        return get_registration(registration_id);
    }

    [[nodiscard]] std::optional<RegistrationInfo> get_registration(uint64_t registration_id) const {
        auto it = registrations_.find(registration_id);
        if (it == registrations_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] bool is_registered(const std::string& procedure) const {
        return procedure_to_registration_.contains(procedure);
    }

private:
    // procedure URI -> registration_id (O(1) lookup by procedure)
    // Only one registration per procedure for simplicity
    std::unordered_map<std::string, uint64_t> procedure_to_registration_;

    // registration_id -> registration info (O(1) reverse lookup)
    std::unordered_map<uint64_t, RegistrationInfo> registrations_;

    // session_id -> set of registration_ids (for cleanup on disconnect)
    std::unordered_map<uint64_t, std::unordered_set<uint64_t>> session_registrations_;
};

} // namespace wamp
