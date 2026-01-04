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


#include <catch2/catch_test_macros.hpp>
#include "include/registration_manager.hpp"
#include "include/procedure_handler.hpp"
#include "include/invocation_tracker.hpp"

using namespace wamp;

TEST_CASE("RegistrationManager basic operations", "[procedure_handler][registration]") {
    RegistrationManager manager;

    SECTION("Register a procedure") {
        bool success = manager.register_procedure(100, "com.example.add", 1);
        REQUIRE(success);

        auto reg = manager.find_callee("com.example.add");
        REQUIRE(reg.has_value());
        REQUIRE(reg->registration_id == 100);
        REQUIRE(reg->procedure == "com.example.add");
        REQUIRE(reg->session_id == 1);
    }

    SECTION("Cannot register same procedure twice") {
        manager.register_procedure(100, "com.example.multiply", 1);
        bool success = manager.register_procedure(101, "com.example.multiply", 2);
        REQUIRE(!success);

        // First registration should still be valid
        auto reg = manager.find_callee("com.example.multiply");
        REQUIRE(reg.has_value());
        REQUIRE(reg->registration_id == 100);
        REQUIRE(reg->session_id == 1);
    }

    SECTION("Unregister by registration ID") {
        manager.register_procedure(200, "com.example.divide", 1);
        REQUIRE(manager.is_registered("com.example.divide"));

        bool success = manager.unregister(200);
        REQUIRE(success);
        REQUIRE(!manager.is_registered("com.example.divide"));
    }

    SECTION("Unregister invalid registration ID") {
        bool success = manager.unregister(999);
        REQUIRE(!success);
    }

    SECTION("Get registration info") {
        manager.register_procedure(300, "com.example.subtract", 5);

        auto reg = manager.get_registration(300);
        REQUIRE(reg.has_value());
        REQUIRE(reg->procedure == "com.example.subtract");
        REQUIRE(reg->session_id == 5);

        auto missing = manager.get_registration(999);
        REQUIRE(!missing.has_value());
    }
}

TEST_CASE("RegistrationManager session cleanup", "[procedure_handler][registration]") {
    RegistrationManager manager;

    SECTION("Unregister all procedures for a session") {
        // Session 1 registers multiple procedures
        manager.register_procedure(100, "com.example.proc1", 1);
        manager.register_procedure(101, "com.example.proc2", 1);
        manager.register_procedure(102, "com.example.proc3", 1);

        // Session 2 registers a procedure
        manager.register_procedure(200, "com.example.proc4", 2);

        // Cleanup session 1
        manager.unregister_session(1);

        // Session 1's procedures should be gone
        REQUIRE(!manager.is_registered("com.example.proc1"));
        REQUIRE(!manager.is_registered("com.example.proc2"));
        REQUIRE(!manager.is_registered("com.example.proc3"));

        // Session 2's procedure should still exist
        REQUIRE(manager.is_registered("com.example.proc4"));
        auto reg = manager.find_callee("com.example.proc4");
        REQUIRE(reg.has_value());
        REQUIRE(reg->session_id == 2);
    }

    SECTION("Cleanup session with no registrations") {
        manager.register_procedure(100, "com.example.test", 1);

        // Cleanup session that has no registrations
        manager.unregister_session(999);

        // Original registration should be unaffected
        REQUIRE(manager.is_registered("com.example.test"));
    }
}

TEST_CASE("RegistrationManager edge cases", "[procedure_handler][registration]") {
    RegistrationManager manager;

    SECTION("Empty procedure name") {
        bool success = manager.register_procedure(100, "", 1);
        REQUIRE(success);  // Empty names are allowed (protocol doesn't forbid)

        auto reg = manager.find_callee("");
        REQUIRE(reg.has_value());
    }

    SECTION("Very long procedure name") {
        std::string long_name(1000, 'x');
        bool success = manager.register_procedure(100, long_name, 1);
        REQUIRE(success);

        auto reg = manager.find_callee(long_name);
        REQUIRE(reg.has_value());
    }

    SECTION("Multiple sessions, same procedures") {
        // First registration wins
        manager.register_procedure(100, "com.example.echo", 1);
        manager.register_procedure(101, "com.example.echo", 2);

        auto reg = manager.find_callee("com.example.echo");
        REQUIRE(reg.has_value());
        REQUIRE(reg->session_id == 1);  // First one wins
    }
}

TEST_CASE("InvocationTracker basic operations", "[procedure_handler][invocation]") {
    InvocationTracker tracker(100);  // Small capacity for testing

    SECTION("Track and retrieve invocation") {
        PendingCall call{1, 999};
        tracker.track(12345, call);

        auto retrieved = tracker.retrieve(12345);
        REQUIRE(retrieved.has_value());
        REQUIRE(retrieved->caller_session_id == 1);
        REQUIRE(retrieved->call_request_id == 999);
        REQUIRE(tracker.pending_count() == 0);  // Retrieved = removed
    }

    SECTION("Retrieve non-existent invocation") {
        auto result = tracker.retrieve(99999);
        REQUIRE(!result.has_value());
    }

    SECTION("Peek without removing") {
        PendingCall call{5, 777};
        tracker.track(54321, call);

        auto peeked = tracker.peek(54321);
        REQUIRE(peeked.has_value());
        REQUIRE(peeked->caller_session_id == 5);
        REQUIRE(tracker.pending_count() == 1);  // Still there

        auto retrieved = tracker.retrieve(54321);
        REQUIRE(retrieved.has_value());
        REQUIRE(tracker.pending_count() == 0);  // Now removed
    }

    SECTION("Track multiple invocations") {
        tracker.track(1, PendingCall{1, 100});
        tracker.track(2, PendingCall{2, 200});
        tracker.track(3, PendingCall{3, 300});

        REQUIRE(tracker.pending_count() == 3);

        auto call2 = tracker.retrieve(2);
        REQUIRE(call2.has_value());
        REQUIRE(call2->call_request_id == 200);
        REQUIRE(tracker.pending_count() == 2);
    }
}

TEST_CASE("InvocationTracker LRU eviction", "[procedure_handler][invocation]") {
    InvocationTracker tracker(3);  // Capacity of 3

    SECTION("LRU eviction when at capacity") {
        tracker.track(1, PendingCall{1, 100});
        tracker.track(2, PendingCall{2, 200});
        tracker.track(3, PendingCall{3, 300});

        REQUIRE(tracker.pending_count() == 3);
        REQUIRE(tracker.is_full());

        // Adding 4th entry should evict oldest (1)
        tracker.track(4, PendingCall{4, 400});

        REQUIRE(tracker.pending_count() == 3);
        REQUIRE(!tracker.retrieve(1).has_value());  // Evicted
        REQUIRE(tracker.retrieve(2).has_value());   // Still there
    }

    SECTION("Re-tracking updates entry") {
        tracker.track(1, PendingCall{1, 100});
        tracker.track(2, PendingCall{2, 200});

        // Update entry 1 with new data
        tracker.track(1, PendingCall{1, 999});

        auto call = tracker.retrieve(1);
        REQUIRE(call.has_value());
        REQUIRE(call->call_request_id == 999);
    }
}

TEST_CASE("InvocationTracker session cleanup", "[procedure_handler][invocation]") {
    InvocationTracker tracker(100);

    SECTION("Remove all invocations for a caller session") {
        // Multiple callers
        tracker.track(1, PendingCall{10, 100});
        tracker.track(2, PendingCall{10, 200});
        tracker.track(3, PendingCall{20, 300});
        tracker.track(4, PendingCall{10, 400});

        REQUIRE(tracker.pending_count() == 4);

        // Remove all from session 10
        tracker.remove_caller_session(10);

        REQUIRE(tracker.pending_count() == 1);  // Only session 20's call remains
        REQUIRE(!tracker.retrieve(1).has_value());
        REQUIRE(!tracker.retrieve(2).has_value());
        REQUIRE(tracker.retrieve(3).has_value());  // Session 20
        REQUIRE(!tracker.retrieve(4).has_value());
    }

    SECTION("Remove non-existent session") {
        tracker.track(1, PendingCall{5, 100});
        tracker.remove_caller_session(999);
        REQUIRE(tracker.pending_count() == 1);  // Unchanged
    }
}

TEST_CASE("ProcedureHandler configuration", "[procedure_handler]") {
    SECTION("Set and get max pending invocations") {
        ProcedureHandler::set_max_pending_invocations(5000);
        REQUIRE(ProcedureHandler::get_max_pending_invocations() == 5000);

        ProcedureHandler::set_max_pending_invocations(10000);
        REQUIRE(ProcedureHandler::get_max_pending_invocations() == 10000);
    }
}
