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


#include "include/authorizer.hpp"
#include "include/registration_manager.hpp"
#include "include/subscription_manager.hpp"
#include "include/uri_match.hpp"
#include <catch2/catch_test_macros.hpp>
#include <algorithm>
#include <set>

using namespace wamp;

TEST_CASE("URI matching: exact, prefix and wildcard", "[patterns]") {
    SECTION("exact") {
        CHECK(uri::matches(Match::EXACT, "a.b", "a.b"));
        CHECK_FALSE(uri::matches(Match::EXACT, "a.b", "a.b.c"));
    }
    SECTION("prefix is a string prefix, equal included") {
        CHECK(uri::matches(Match::PREFIX, "com.shop.", "com.shop.orders"));
        CHECK(uri::matches(Match::PREFIX, "com.shop", "com.shop"));
        CHECK(uri::matches(Match::PREFIX, "com.shop", "com.shop2.x"));   // not component-bounded
        CHECK_FALSE(uri::matches(Match::PREFIX, "com.shop.orders", "com.shop"));
    }
    SECTION("wildcard: same component count, empty pattern components match any component") {
        CHECK(uri::matches(Match::WILDCARD, "com..created", "com.orders.created"));
        CHECK(uri::matches(Match::WILDCARD, "com..created", "com..created"));   // an empty topic component too
        CHECK(uri::matches(Match::WILDCARD, "a..c.", "a.b.c.d"));
        CHECK(uri::matches(Match::WILDCARD, ".b", "a.b"));
        CHECK_FALSE(uri::matches(Match::WILDCARD, "com..created", "com.orders.x.created"));   // more components
        CHECK_FALSE(uri::matches(Match::WILDCARD, "com..created", "com.created"));            // fewer
        CHECK_FALSE(uri::matches(Match::WILDCARD, "com..created", "com.orders.deleted"));
        CHECK_FALSE(uri::matches(Match::WILDCARD, "a..c", "x.b.c"));
    }
}

TEST_CASE("URI pattern helpers", "[patterns]") {
    CHECK(uri::component_count("") == 1);
    CHECK(uri::component_count("a.b.c") == 3);
    CHECK(uri::component_count("a..c") == 3);
    CHECK(uri::literal_components("a..c") == 2);
    CHECK(uri::literal_components("..") == 0);

    CHECK(uri::valid_wildcard("a..c"));
    CHECK(uri::valid_wildcard(".b"));
    CHECK_FALSE(uri::valid_wildcard("a.b"));    // no empty component: that is an exact URI
    CHECK_FALSE(uri::valid_wildcard(".."));     // nothing literal
    CHECK_FALSE(uri::valid_wildcard(""));

    CHECK(uri::literal_head("a.b..c") == "a.b.");
    CHECK(uri::literal_head("a.b.") == "a.b.");
    CHECK(uri::literal_head(".b") == "");
    CHECK(uri::literal_head("a.b") == "a.b");

    CHECK(parse_match("exact") == Match::EXACT);
    CHECK(parse_match("prefix") == Match::PREFIX);
    CHECK(parse_match("wildcard") == Match::WILDCARD);
    CHECK_FALSE(parse_match("regex").has_value());
}

TEST_CASE("Precedence between matching registrations", "[patterns]") {
    CHECK(uri::more_specific(Match::EXACT, "a.b", Match::PREFIX, "a."));
    CHECK(uri::more_specific(Match::PREFIX, "a.b", Match::WILDCARD, "a..c"));
    CHECK(uri::more_specific(Match::PREFIX, "a.bc", Match::PREFIX, "a."));        // longer prefix
    CHECK_FALSE(uri::more_specific(Match::PREFIX, "a.", Match::PREFIX, "a.bc"));
    CHECK(uri::more_specific(Match::WILDCARD, "a.b.", Match::WILDCARD, "a.."));   // more literal components
    CHECK(uri::more_specific(Match::WILDCARD, "a..c", Match::WILDCARD, "a.b."));  // tie: smaller string wins
    CHECK_FALSE(uri::more_specific(Match::WILDCARD, "a.b.", Match::WILDCARD, "a..c"));
}

namespace {
std::vector<std::pair<uint64_t, Match>> reached(const SubscriptionManager& manager, const std::string& topic) {
    std::vector<std::pair<uint64_t, Match>> result;
    manager.for_each_subscriber(topic, [&](uint64_t subscription_id, uint64_t, Match match) {
        result.emplace_back(subscription_id, match);
    });
    std::ranges::sort(result);
    return result;
}
using Hits = std::vector<std::pair<uint64_t, Match>>;
}  // namespace

TEST_CASE("SubscriptionManager delivers to exact, prefix and wildcard subscriptions", "[patterns][subscriptions]") {
    SubscriptionManager manager;
    manager.subscribe(1, "com.shop.orders", 10);
    manager.subscribe(2, "com.shop.", 10, Match::PREFIX);          // same session: one event per subscription
    manager.subscribe(3, "com.", 11, Match::PREFIX);
    manager.subscribe(4, "com.shop.", 12, Match::WILDCARD);   // three components, the last one free
    manager.subscribe(5, "com..orders", 13, Match::WILDCARD);
    manager.subscribe(6, "com.shop.orders", 11, Match::PREFIX);    // prefix equal to the topic: matches it

    CHECK(manager.has_patterns());
    CHECK(reached(manager, "com.shop.orders") ==
          Hits{{1, Match::EXACT}, {2, Match::PREFIX}, {3, Match::PREFIX}, {4, Match::WILDCARD},
               {5, Match::WILDCARD}, {6, Match::PREFIX}});
    CHECK(reached(manager, "com.shop.carts") == Hits{{2, Match::PREFIX}, {3, Match::PREFIX}, {4, Match::WILDCARD}});
    CHECK(reached(manager, "com.other") == Hits{{3, Match::PREFIX}});
    CHECK(reached(manager, "org.shop.orders").empty());
    CHECK(reached(manager, "com.shop.orders.x") == Hits{{2, Match::PREFIX}, {3, Match::PREFIX}, {6, Match::PREFIX}});

    // get_subscribers and the two-argument form see all of them
    auto ids = manager.get_subscribers("com.shop.orders");
    std::ranges::sort(ids);
    CHECK(ids == std::vector<uint64_t>{1, 2, 3, 4, 5, 6});

    // exact count does not include patterns; the keyed count does
    CHECK(manager.subscriber_count("com.shop.orders") == 1);
    CHECK(manager.subscriber_count(Match::PREFIX, "com.shop.orders") == 1);
    CHECK(manager.subscriber_count(Match::WILDCARD, "com.shop.") == 1);
    CHECK(manager.subscriber_count(Match::WILDCARD, "com.shop.orders") == 0);
}

TEST_CASE("SubscriptionManager cleans up patterns", "[patterns][subscriptions]") {
    SubscriptionManager manager;
    manager.subscribe(1, "a.", 10, Match::PREFIX);
    manager.subscribe(2, "a.", 11, Match::PREFIX);
    manager.subscribe(3, "a..c", 10, Match::WILDCARD);
    manager.subscribe(4, "a.b", 10);
    REQUIRE(manager.get_subscription(1)->match == Match::PREFIX);

    CHECK(manager.unsubscribe(1));
    CHECK(reached(manager, "a.b") == Hits{{2, Match::PREFIX}, {4, Match::EXACT}});
    CHECK(manager.subscriber_count(Match::PREFIX, "a.") == 1);

    // Session cleanup reports the keys that lost their last subscriber
    const auto emptied = manager.unsubscribe_session(10);
    CHECK(emptied.size() == 2);   // the wildcard and the exact topic; the prefix still has session 11
    CHECK(std::ranges::find(emptied, SubscriptionKey{Match::WILDCARD, "a..c"}) != emptied.end());
    CHECK(std::ranges::find(emptied, SubscriptionKey{Match::EXACT, "a.b"}) != emptied.end());
    CHECK(reached(manager, "a.x.c") == Hits{{2, Match::PREFIX}});

    CHECK(manager.unsubscribe(2));
    CHECK_FALSE(manager.has_patterns());
    CHECK(reached(manager, "a.b").empty());
    CHECK_FALSE(manager.unsubscribe(2));
}

TEST_CASE("Prefix lookups use only the distinct prefix lengths that exist", "[patterns][subscriptions]") {
    SubscriptionManager manager;
    manager.subscribe(1, "x", 1, Match::PREFIX);
    manager.subscribe(2, "x.y.z", 1, Match::PREFIX);
    CHECK(reached(manager, "x.y.z.w") == Hits{{1, Match::PREFIX}, {2, Match::PREFIX}});
    CHECK(reached(manager, "x.y") == Hits{{1, Match::PREFIX}});   // the long prefix is longer than the topic
    CHECK(reached(manager, "") .empty());
    manager.unsubscribe(2);
    CHECK(reached(manager, "x.y.z.w") == Hits{{1, Match::PREFIX}});
}

TEST_CASE("RegistrationManager resolves a call to exactly one registration", "[patterns][registrations]") {
    RegistrationManager manager;
    REQUIRE(manager.register_procedure(1, "com.shop.orders.get", 10));
    REQUIRE(manager.register_procedure(2, "com.shop.", 11, Match::PREFIX));
    REQUIRE(manager.register_procedure(3, "com.shop.orders.", 12, Match::PREFIX));
    REQUIRE(manager.register_procedure(4, "com..get", 13, Match::WILDCARD));
    REQUIRE(manager.register_procedure(5, "com.shop..get", 14, Match::WILDCARD));
    REQUIRE(manager.register_procedure(6, "org..", 15, Match::WILDCARD));

    auto session_of = [&](const std::string& procedure) {
        const auto info = manager.find_callee(procedure);
        return info ? info->session_id : 0;
    };
    CHECK(session_of("com.shop.orders.get") == 10);    // exact beats prefix and wildcard
    CHECK(session_of("com.shop.orders.list") == 12);   // the longest matching prefix
    CHECK(session_of("com.shop.carts.get") == 11);     // a prefix beats a wildcard that also matches
    CHECK(session_of("com.misc.get") == 13);           // only the wildcard matches
    CHECK(session_of("org.x.y") == 15);
    CHECK(session_of("net.x") == 0);

    const auto info = manager.find_callee("com.shop.carts.get");
    REQUIRE(info.has_value());
    CHECK(info->match == Match::PREFIX);
    CHECK(info->procedure == "com.shop.");
}

TEST_CASE("Wildcard registrations: the most literal components win, ties go to the smaller pattern", "[patterns][registrations]") {
    RegistrationManager manager;
    REQUIRE(manager.register_procedure(1, "a..", 10, Match::WILDCARD));
    REQUIRE(manager.register_procedure(2, "a.b.", 11, Match::WILDCARD));
    REQUIRE(manager.register_procedure(3, "a..c", 12, Match::WILDCARD));
    CHECK(manager.find_callee("a.b.c")->session_id == 12);   // "a..c" and "a.b." both have 2 literals: "a..c" < "a.b."
    CHECK(manager.find_callee("a.b.x")->session_id == 11);   // "a.b." (2 literals) beats "a.." (1)
    CHECK(manager.find_callee("a.x.y")->session_id == 10);
}

TEST_CASE("Registrations are unique per (match, uri) and cleaned up", "[patterns][registrations]") {
    RegistrationManager manager;
    REQUIRE(manager.register_procedure(1, "a.", 10, Match::PREFIX));
    CHECK_FALSE(manager.register_procedure(2, "a.", 11, Match::PREFIX));       // same pattern
    CHECK(manager.register_procedure(3, "a.", 11));                              // the exact procedure "a." is another key
    CHECK(manager.register_procedure(4, "a..", 11, Match::WILDCARD));
    CHECK_FALSE(manager.register_procedure(5, "a..", 12, Match::WILDCARD));

    CHECK(manager.find_callee("a.")->session_id == 11);        // exact
    CHECK(manager.find_callee("a.x")->session_id == 10);

    CHECK(manager.unregister(1));
    CHECK_FALSE(manager.find_callee("a.x").has_value());                      // "a.." needs three components
    CHECK(manager.find_callee("a.x.y")->match == Match::WILDCARD);
    CHECK(manager.register_procedure(6, "a.", 12, Match::PREFIX));             // free again

    const auto removed = manager.unregister_session(11);
    CHECK(removed.size() == 2);
    CHECK(std::ranges::find(removed, RegistrationKey{Match::EXACT, "a."}) != removed.end());
    CHECK(std::ranges::find(removed, RegistrationKey{Match::WILDCARD, "a.."}) != removed.end());
    CHECK(manager.find_callee("a.x")->session_id == 12);
    CHECK_FALSE(manager.find_callee("a.x.y")->session_id == 11);               // the wildcard is gone, the prefix takes it
    CHECK(manager.unregister(6));
    CHECK_FALSE(manager.has_patterns());
    CHECK_FALSE(manager.find_callee("a.x").has_value());
}

TEST_CASE("Permissions::allows_pattern needs a prefix rule that covers everything the pattern can match", "[patterns][authz]") {
    Permissions role;
    role.add_rule(Action::SUBSCRIBE, "com.shop.", true);            // prefix rule
    role.add_rule(Action::SUBSCRIBE, "com.news.today", false);      // exact rule
    role.add_rule(Action::REGISTER, "com.shop.orders.", true);

    // exact: as before
    CHECK(role.allows_pattern(Action::SUBSCRIBE, "com.news.today", Match::EXACT));
    CHECK(role.allows_pattern(Action::SUBSCRIBE, "com.shop.carts", Match::EXACT));
    // prefix patterns
    CHECK(role.allows_pattern(Action::SUBSCRIBE, "com.shop.", Match::PREFIX));
    CHECK(role.allows_pattern(Action::SUBSCRIBE, "com.shop.orders.", Match::PREFIX));
    CHECK_FALSE(role.allows_pattern(Action::SUBSCRIBE, "com.", Match::PREFIX));                // wider than the rule
    CHECK_FALSE(role.allows_pattern(Action::SUBSCRIBE, "com.news.today", Match::PREFIX));      // an exact rule is not enough
    // wildcard patterns: the literal head must be covered
    CHECK(role.allows_pattern(Action::SUBSCRIBE, "com.shop..created", Match::WILDCARD));
    CHECK_FALSE(role.allows_pattern(Action::SUBSCRIBE, "com..created", Match::WILDCARD));
    CHECK_FALSE(role.allows_pattern(Action::SUBSCRIBE, ".shop.created", Match::WILDCARD));
    // rules are per action
    CHECK_FALSE(role.allows_pattern(Action::REGISTER, "com.shop.", Match::PREFIX));
    CHECK(role.allows_pattern(Action::REGISTER, "com.shop.orders.get", Match::PREFIX));
}
