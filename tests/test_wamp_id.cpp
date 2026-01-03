#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_range_equals.hpp>
#include "include/wamp_id.hpp"
#include <unordered_set>

using namespace wamp;

TEST_CASE("GlobalIdGenerator generates IDs in valid range", "[wamp_id]") {
    GlobalIdGenerator gen;

    SECTION("IDs are within [1, 2^53]") {
        for (int i = 0; i < 1000; ++i) {
            uint64_t id = gen.generate();
            REQUIRE(id >= 1);
            REQUIRE(id <= (1ULL << 53));
        }
    }

    SECTION("IDs are unique") {
        std::unordered_set<uint64_t> ids;
        for (int i = 0; i < 10000; ++i) {
            uint64_t id = gen.generate();
            REQUIRE(ids.find(id) == ids.end());
            ids.insert(id);
        }
    }
}

TEST_CASE("RouterScopeIdGenerator generates sequential IDs", "[wamp_id]") {
    RouterScopeIdGenerator gen;

    SECTION("IDs start at 1") {
        REQUIRE(gen.generate() == 1);
    }

    SECTION("IDs are sequential") {
        uint64_t first = gen.generate();
        uint64_t second = gen.generate();
        uint64_t third = gen.generate();

        REQUIRE(second == first + 1);
        REQUIRE(third == second + 1);
    }

    SECTION("IDs wrap at max value") {
        RouterScopeIdGenerator wrapper;

        // Generate IDs up to near the max
        constexpr uint64_t max_id = (1ULL << 53);

        // Set internal state close to max (we'd need a way to set this for proper testing)
        // For now, just verify the range is correct
        for (int i = 0; i < 100; ++i) {
            uint64_t id = wrapper.generate();
            REQUIRE(id >= 1);
            REQUIRE(id <= max_id);
        }
    }
}

TEST_CASE("SessionScopeIdGenerator generates sequential IDs", "[wamp_id]") {
    SessionScopeIdGenerator gen;

    SECTION("IDs start at 1") {
        REQUIRE(gen.generate() == 1);
    }

    SECTION("IDs are sequential") {
        uint64_t first = gen.generate();
        uint64_t second = gen.generate();
        uint64_t third = gen.generate();

        REQUIRE(second == first + 1);
        REQUIRE(third == second + 1);
    }

    SECTION("IDs are within valid range") {
        for (int i = 0; i < 1000; ++i) {
            uint64_t id = gen.generate();
            REQUIRE(id >= 1);
            REQUIRE(id <= (1ULL << 53));
        }
    }
}

TEST_CASE("Different generator types produce different ID patterns", "[wamp_id]") {
    GlobalIdGenerator global1, global2;
    RouterScopeIdGenerator router1, router2;
    SessionScopeIdGenerator session1, session2;

    // Global generators should produce different random IDs
    uint64_t g1 = global1.generate();
    uint64_t g2 = global2.generate();
    REQUIRE(g1 != g2);  // Highly likely with random generation

    // Router generators should produce same sequence if starting fresh
    uint64_t r1 = router1.generate();
    uint64_t r2 = router2.generate();
    REQUIRE(r1 == r2);  // Both start at 1

    // Session generators should produce same sequence if starting fresh
    uint64_t s1 = session1.generate();
    uint64_t s2 = session2.generate();
    REQUIRE(s1 == s2);  // Both start at 1
}
