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

#pragma once

#include "wamp_messages.hpp"

#include <optional>
#include <string>

// WAMP Payload Passthru Mode: a PUBLISH or CALL (and the YIELD answering it) may carry ppt_* options
// (ppt_scheme, ppt_serializer, ppt_cipher, ppt_keyid) and a payload that is one binary argument in an
// application-defined format. The router never looks inside the payload; it checks the shape, forwards the
// ppt_* entries as EVENT/INVOCATION/RESULT details and delivers only to peers that announced the feature.
namespace wamp::ppt {

inline constexpr const char* kFeature = "payload_passthru_mode";

[[nodiscard]] inline bool is_ppt_key(const std::string& key) {
    return key.starts_with("ppt_");
}

// The ppt_* entries of an options/details dict (empty if there are none)
[[nodiscard]] inline WampDict extract(const WampDict& source) {
    WampDict result;
    for (const auto& [key, value] : source) {
        if (is_ppt_key(key)) result.emplace(key, value);
    }
    return result;
}

// True if `ppt` (as returned by extract) and the payload form a well-formed passthru message: ppt_scheme is a
// non-empty string, the other ppt_* entries are strings, the payload is exactly one binary argument.
[[nodiscard]] inline bool valid(const WampDict& ppt, const WampList& arguments, const WampDict& arguments_kw) {
    const auto scheme = ppt.find("ppt_scheme");
    if (scheme == ppt.end()) return false;
    for (const auto& [key, value] : ppt) {
        if (!std::holds_alternative<std::string>(value)) return false;
    }
    if (std::get<std::string>(scheme->second).empty()) return false;
    return arguments.size() == 1 && std::holds_alternative<WampBytes>(arguments.front()) && arguments_kw.empty();
}

// Whether a role's announced features (the "features" dict of a HELLO/WELCOME role) include passthru
[[nodiscard]] inline bool announced(const WampDict& features) {
    const auto it = features.find(kFeature);
    if (it == features.end()) return false;
    const auto* flag = std::get_if<bool>(&it->second);
    return flag != nullptr && *flag;
}

} // namespace wamp::ppt
