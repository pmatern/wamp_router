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
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace wamp {

// What a session asks to do with a URI
enum class Action : uint8_t { CALL, REGISTER, PUBLISH, SUBSCRIBE };

[[nodiscard]] constexpr const char* to_string(Action action) {
    switch (action) {
        case Action::CALL:      return "call";
        case Action::REGISTER:  return "register";
        case Action::PUBLISH:   return "publish";
        case Action::SUBSCRIBE: return "subscribe";
    }
    return "?";
}

[[nodiscard]] inline std::optional<Action> parse_action(std::string_view name) {
    for (auto action : {Action::CALL, Action::REGISTER, Action::PUBLISH, Action::SUBSCRIBE}) {
        if (name == to_string(action)) return action;
    }
    return std::nullopt;
}

// ============================================================================
// Permissions - the URIs a class of sessions may use, per action. Default-deny: only what a rule
// allows is permitted. A rule is an exact URI or a prefix (which also matches itself).
// ============================================================================
class Permissions {
public:
    void add_rule(Action action, std::string uri, bool prefix) {
        auto& rules = rules_[static_cast<size_t>(action)];
        if (prefix) {
            rules.prefixes.push_back(std::move(uri));
        } else {
            rules.exact.insert(std::move(uri));
        }
    }

    // Restrict the payload passthru schemes (ppt_scheme) this class of sessions may use; none set = any
    void set_ppt_schemes(std::vector<std::string> schemes) { ppt_schemes_ = std::move(schemes); }

    [[nodiscard]] bool allows_ppt_scheme(std::string_view scheme) const {
        return ppt_schemes_.empty() || std::ranges::find(ppt_schemes_, scheme) != ppt_schemes_.end();
    }

    // A prefix or wildcard subscription/registration is allowed only if everything it can match is: it needs a prefix
    // rule that is a prefix of the pattern (of its literal head for a wildcard). Exact rules never allow patterns.
    [[nodiscard]] bool allows_pattern(Action action, std::string_view uri, Match match) const {
        if (match == Match::EXACT) return allows(action, uri);
        const std::string_view head = match == Match::PREFIX ? uri : uri::literal_head(uri);
        for (const auto& prefix : rules_[static_cast<size_t>(action)].prefixes) {
            if (head.starts_with(prefix)) return true;
        }
        return false;
    }

    [[nodiscard]] bool allows(Action action, std::string_view uri) const {
        const auto& rules = rules_[static_cast<size_t>(action)];
        if (rules.exact.find(uri) != rules.exact.end()) return true;
        for (const auto& prefix : rules.prefixes) {
            if (uri.starts_with(prefix)) return true;
        }
        return false;
    }

private:
    struct StringHash {
        using is_transparent = void;
        size_t operator()(std::string_view s) const { return std::hash<std::string_view>{}(s); }
    };
    struct Rules {
        std::unordered_set<std::string, StringHash, std::equal_to<>> exact;
        std::vector<std::string> prefixes;
    };
    std::array<Rules, 4> rules_;
    std::vector<std::string> ppt_schemes_;
};

} // namespace wamp
