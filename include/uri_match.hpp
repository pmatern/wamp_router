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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

// WAMP pattern-based subscriptions and registrations (advanced profile): how a SUBSCRIBE/REGISTER URI is
// matched against a published topic or called procedure.
//   exact     the URIs are equal
//   prefix    the pattern is a string prefix of the URI
//   wildcard  the same number of dot-separated components, an empty pattern component matches any component
namespace wamp {

enum class Match : uint8_t { EXACT, PREFIX, WILDCARD };

[[nodiscard]] constexpr const char* to_string(Match match) {
    switch (match) {
        case Match::EXACT:    return "exact";
        case Match::PREFIX:   return "prefix";
        case Match::WILDCARD: return "wildcard";
    }
    return "?";
}

[[nodiscard]] inline std::optional<Match> parse_match(std::string_view name) {
    if (name == "exact") return Match::EXACT;
    if (name == "prefix") return Match::PREFIX;
    if (name == "wildcard") return Match::WILDCARD;
    return std::nullopt;
}

namespace uri {

// Number of dot-separated components ("a.b" is 2, "a..b" is 3, "" is 1)
[[nodiscard]] inline size_t component_count(std::string_view uri) {
    size_t count = 1;
    for (const char c : uri) count += c == '.';
    return count;
}

// Number of non-empty components of a wildcard pattern: how specific it is
[[nodiscard]] inline size_t literal_components(std::string_view pattern) {
    size_t literal = 0;
    size_t start = 0;
    while (start <= pattern.size()) {
        size_t end = pattern.find('.', start);
        if (end == std::string_view::npos) end = pattern.size();
        if (end > start) ++literal;
        start = end + 1;
    }
    return literal;
}

// A wildcard pattern needs at least one empty component (else it is an exact URI) and one literal one
[[nodiscard]] inline bool valid_wildcard(std::string_view pattern) {
    const size_t components = component_count(pattern);
    const size_t literal = literal_components(pattern);
    return literal > 0 && literal < components;
}

// The pattern's components up to the first empty one, with the dot before it ("a.b..c" -> "a.b."); empty if
// the first component is empty. Every URI a wildcard pattern matches starts with this.
[[nodiscard]] inline std::string_view literal_head(std::string_view pattern) {
    size_t start = 0;
    while (start <= pattern.size()) {
        size_t end = pattern.find('.', start);
        if (end == std::string_view::npos) end = pattern.size();
        if (end == start) return pattern.substr(0, start);
        start = end + 1;
    }
    return pattern;  // no empty component
}

[[nodiscard]] inline bool wildcard_matches(std::string_view pattern, std::string_view uri) {
    size_t p = 0;
    size_t u = 0;
    while (true) {
        size_t p_end = pattern.find('.', p);
        size_t u_end = uri.find('.', u);
        const bool p_last = p_end == std::string_view::npos;
        const bool u_last = u_end == std::string_view::npos;
        if (p_last != u_last) return false;  // different number of components
        if (p_last) p_end = pattern.size();
        if (u_last) u_end = uri.size();
        if (p_end != p && pattern.substr(p, p_end - p) != uri.substr(u, u_end - u)) return false;
        if (p_last) return true;
        p = p_end + 1;
        u = u_end + 1;
    }
}

[[nodiscard]] inline bool matches(Match match, std::string_view pattern, std::string_view uri) {
    switch (match) {
        case Match::EXACT:    return pattern == uri;
        case Match::PREFIX:   return uri.starts_with(pattern);
        case Match::WILDCARD: return wildcard_matches(pattern, uri);
    }
    return false;
}

// Which of two registrations that both match a call wins: exact over prefix over wildcard; the longer prefix;
// the wildcard with more literal components; then the smaller pattern string, so that every shard decides alike.
[[nodiscard]] inline bool more_specific(Match a, std::string_view a_uri, Match b, std::string_view b_uri) {
    if (a != b) return static_cast<uint8_t>(a) < static_cast<uint8_t>(b);   // EXACT < PREFIX < WILDCARD
    if (a == Match::PREFIX && a_uri.size() != b_uri.size()) return a_uri.size() > b_uri.size();
    if (a == Match::WILDCARD) {
        const auto a_literal = literal_components(a_uri);
        const auto b_literal = literal_components(b_uri);
        if (a_literal != b_literal) return a_literal > b_literal;
    }
    return a_uri < b_uri;
}

} // namespace uri
} // namespace wamp
