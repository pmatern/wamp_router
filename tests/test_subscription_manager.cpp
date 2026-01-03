#include <catch2/catch_test_macros.hpp>
#include "include/subscription_manager.hpp"
#include <algorithm>

using namespace wamp;

TEST_CASE("SubscriptionManager basic operations", "[subscription_manager]") {
    SubscriptionManager manager;

    SECTION("Subscribe to a topic") {
        manager.subscribe(1, "com.example.topic", 100);

        REQUIRE(manager.has_subscribers("com.example.topic"));

        auto subscribers = manager.get_subscribers("com.example.topic");
        REQUIRE(subscribers.size() == 1);
        REQUIRE(std::count(subscribers.begin(), subscribers.end(), 1) == 1);
    }

    SECTION("Multiple subscriptions to same topic") {
        manager.subscribe(1, "com.example.topic", 100);
        manager.subscribe(2, "com.example.topic", 101);
        manager.subscribe(3, "com.example.topic", 102);

        auto subscribers = manager.get_subscribers("com.example.topic");
        REQUIRE(subscribers.size() == 3);
        REQUIRE(std::count(subscribers.begin(), subscribers.end(), 1) == 1);
        REQUIRE(std::count(subscribers.begin(), subscribers.end(), 2) == 1);
        REQUIRE(std::count(subscribers.begin(), subscribers.end(), 3) == 1);
    }

    SECTION("Subscriptions to different topics") {
        manager.subscribe(1, "com.example.topic1", 100);
        manager.subscribe(2, "com.example.topic2", 101);

        REQUIRE(manager.has_subscribers("com.example.topic1"));
        REQUIRE(manager.has_subscribers("com.example.topic2"));

        auto sub1 = manager.get_subscribers("com.example.topic1");
        auto sub2 = manager.get_subscribers("com.example.topic2");

        REQUIRE(sub1.size() == 1);
        REQUIRE(sub2.size() == 1);
        REQUIRE(std::count(sub1.begin(), sub1.end(), 1) == 1);
        REQUIRE(std::count(sub2.begin(), sub2.end(), 2) == 1);
    }

    SECTION("Get subscription info") {
        manager.subscribe(123, "com.example.topic", 999);

        auto info = manager.get_subscription(123);
        REQUIRE(info.has_value());
        REQUIRE(info->subscription_id == 123);
        REQUIRE(info->topic == "com.example.topic");
        REQUIRE(info->session_id == 999);
    }

    SECTION("Get non-existent subscription") {
        auto info = manager.get_subscription(999);
        REQUIRE(!info.has_value());
    }
}

TEST_CASE("SubscriptionManager unsubscribe operations", "[subscription_manager]") {
    SubscriptionManager manager;

    SECTION("Unsubscribe from topic") {
        manager.subscribe(1, "com.example.topic", 100);
        REQUIRE(manager.has_subscribers("com.example.topic"));

        manager.unsubscribe(1);
        REQUIRE(!manager.has_subscribers("com.example.topic"));
    }

    SECTION("Unsubscribe one of multiple subscribers") {
        manager.subscribe(1, "com.example.topic", 100);
        manager.subscribe(2, "com.example.topic", 101);
        manager.subscribe(3, "com.example.topic", 102);

        manager.unsubscribe(2);

        auto subscribers = manager.get_subscribers("com.example.topic");
        REQUIRE(subscribers.size() == 2);
        REQUIRE(std::count(subscribers.begin(), subscribers.end(), 1) == 1);
        REQUIRE(std::count(subscribers.begin(), subscribers.end(), 2) == 0);
        REQUIRE(std::count(subscribers.begin(), subscribers.end(), 3) == 1);
    }

    SECTION("Unsubscribe from non-existent subscription") {
        // Should not crash
        manager.unsubscribe(999);
        REQUIRE(true);
    }
}

TEST_CASE("SubscriptionManager session cleanup", "[subscription_manager]") {
    SubscriptionManager manager;

    SECTION("Unsubscribe all subscriptions for a session") {
        manager.subscribe(1, "com.example.topic1", 100);
        manager.subscribe(2, "com.example.topic2", 100);
        manager.subscribe(3, "com.example.topic3", 100);
        manager.subscribe(4, "com.example.topic1", 101);  // Different session

        manager.unsubscribe_session(100);

        // Session 100's subscriptions should be gone
        REQUIRE(!manager.get_subscription(1).has_value());
        REQUIRE(!manager.get_subscription(2).has_value());
        REQUIRE(!manager.get_subscription(3).has_value());

        // Session 101's subscription should remain
        REQUIRE(manager.get_subscription(4).has_value());
        REQUIRE(manager.has_subscribers("com.example.topic1"));
    }

    SECTION("Cleanup non-existent session") {
        manager.subscribe(1, "com.example.topic", 100);

        // Should not affect existing subscriptions
        manager.unsubscribe_session(999);

        REQUIRE(manager.has_subscribers("com.example.topic"));
    }
}

TEST_CASE("SubscriptionManager edge cases", "[subscription_manager]") {
    SubscriptionManager manager;

    SECTION("Empty topic") {
        manager.subscribe(1, "", 100);

        REQUIRE(manager.has_subscribers(""));
        auto subscribers = manager.get_subscribers("");
        REQUIRE(subscribers.size() == 1);
    }

    SECTION("Topic with special characters") {
        std::string complex_topic = "com.example.topic.with.many.parts.ąćę中文";
        manager.subscribe(1, complex_topic, 100);

        REQUIRE(manager.has_subscribers(complex_topic));
    }

    SECTION("Same session subscribing to same topic twice with different subscription IDs") {
        manager.subscribe(1, "com.example.topic", 100);
        manager.subscribe(2, "com.example.topic", 100);

        auto subscribers = manager.get_subscribers("com.example.topic");
        REQUIRE(subscribers.size() == 2);
    }

    SECTION("Query non-existent topic") {
        REQUIRE(!manager.has_subscribers("com.nonexistent.topic"));

        auto subscribers = manager.get_subscribers("com.nonexistent.topic");
        REQUIRE(subscribers.empty());
    }
}

TEST_CASE("SubscriptionManager topic isolation", "[subscription_manager]") {
    SubscriptionManager manager;

    SECTION("Topics are isolated") {
        manager.subscribe(1, "com.example.topic1", 100);
        manager.subscribe(2, "com.example.topic2", 101);

        auto sub1 = manager.get_subscribers("com.example.topic1");
        auto sub2 = manager.get_subscribers("com.example.topic2");

        REQUIRE(sub1.size() == 1);
        REQUIRE(sub2.size() == 1);
        REQUIRE(sub1 != sub2);
    }

    SECTION("Prefix matching does not occur") {
        manager.subscribe(1, "com.example", 100);
        manager.subscribe(2, "com.example.topic", 101);

        auto sub1 = manager.get_subscribers("com.example");
        auto sub2 = manager.get_subscribers("com.example.topic");

        REQUIRE(sub1.size() == 1);
        REQUIRE(sub2.size() == 1);
        REQUIRE(std::count(sub1.begin(), sub1.end(), 1) == 1);
        REQUIRE(std::count(sub2.begin(), sub2.end(), 2) == 1);
    }
}
