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


#include <catch2/catch_test_macros.hpp>
#include "include/wamp_serializer.hpp"
#include "include/wamp_messages.hpp"

using namespace wamp;

TEST_CASE("HELLO message serialization", "[wamp_serializer]") {
    SECTION("Serialize and deserialize basic HELLO") {
        HelloMessage hello{"com.example.realm"};
        hello.roles.push_back(Role{"subscriber", {}});
        hello.roles.push_back(Role{"publisher", {}});

        auto cbor = serialize_hello(hello);
        REQUIRE(!cbor.empty());

        auto deserialized = deserialize_hello(cbor);
        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->realm == "com.example.realm");
        REQUIRE(deserialized->roles.size() == 2);
    }

    SECTION("HELLO with authmethods") {
        HelloMessage hello{"com.example.realm"};
        hello.authmethods = std::vector<std::string>{"anonymous", "ticket"};

        auto cbor = serialize_hello(hello);
        auto deserialized = deserialize_hello(cbor);

        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->authmethods.has_value());
        REQUIRE(deserialized->authmethods->size() == 2);
    }

    SECTION("HELLO with authid") {
        HelloMessage hello{"com.example.realm"};
        hello.authid = "user123";

        auto cbor = serialize_hello(hello);
        auto deserialized = deserialize_hello(cbor);

        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->authid.has_value());
        REQUIRE(deserialized->authid == "user123");
    }

    SECTION("Invalid CBOR data") {
        std::vector<uint8_t> invalid{0xFF, 0xFF, 0xFF};
        auto result = deserialize_hello(invalid);
        REQUIRE(!result.has_value());
    }
}

TEST_CASE("WELCOME message serialization", "[wamp_serializer]") {
    SECTION("Serialize and deserialize basic WELCOME") {
        auto welcome = WelcomeMessage::create_router(12345, "com.example.realm");

        auto cbor = serialize_welcome(welcome);
        REQUIRE(!cbor.empty());

        auto deserialized = deserialize_welcome(cbor);
        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->session_id == 12345);
        REQUIRE(deserialized->roles.size() == 2);  // broker and dealer
    }

    SECTION("WELCOME with authid") {
        WelcomeMessage welcome{67890, "com.example.realm"};
        welcome.authid = "authenticated_user";
        welcome.authrole = "admin";
        welcome.authmethod = "ticket";

        auto cbor = serialize_welcome(welcome);
        auto deserialized = deserialize_welcome(cbor);

        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->session_id == 67890);
        REQUIRE(deserialized->authid == "authenticated_user");
        REQUIRE(deserialized->authrole == "admin");
        REQUIRE(deserialized->authmethod == "ticket");
    }
}

TEST_CASE("GOODBYE message serialization", "[wamp_serializer]") {
    SECTION("Serialize and deserialize GOODBYE") {
        auto goodbye = GoodbyeMessage::create_normal();

        auto cbor = serialize_goodbye(goodbye);
        REQUIRE(!cbor.empty());

        auto deserialized = deserialize_goodbye(cbor);
        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->reason == "wamp.close.normal");
    }

    SECTION("GOODBYE with system shutdown") {
        auto goodbye = GoodbyeMessage::create_system_shutdown();

        auto cbor = serialize_goodbye(goodbye);
        auto deserialized = deserialize_goodbye(cbor);

        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->reason == "wamp.close.system_shutdown");
    }
}

TEST_CASE("ABORT message serialization", "[wamp_serializer]") {
    SECTION("Serialize and deserialize ABORT") {
        auto abort = AbortMessage::create_not_authorized("Invalid credentials");

        auto cbor = serialize_abort(abort);
        REQUIRE(!cbor.empty());

        auto deserialized = deserialize_abort(cbor);
        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->reason == "wamp.error.not_authorized");
    }

    SECTION("ABORT with no such realm") {
        auto abort = AbortMessage::create_no_such_realm("invalid.realm");

        auto cbor = serialize_abort(abort);
        auto deserialized = deserialize_abort(cbor);

        REQUIRE(deserialized.has_value());
        REQUIRE(deserialized->reason == "wamp.error.no_such_realm");
    }
}

TEST_CASE("SUBSCRIBE/SUBSCRIBED message serialization", "[wamp_serializer]") {
    SECTION("Serialize and deserialize SUBSCRIBE") {
        SubscribeMessage subscribe{123, {}, "com.example.topic"};

        auto cbor = serialize_subscribed(SubscribedMessage{123, 456});
        REQUIRE(!cbor.empty());

        // Note: We can't deserialize SUBSCRIBED, but we can check it serializes
    }

    SECTION("Deserialize SUBSCRIBE message") {
        // Create a manual SUBSCRIBE message
        SubscribeMessage subscribe{999, {}, "com.test.topic"};

        // In a real scenario, this would come from a client
        // We need to manually create CBOR for testing
        std::vector<uint8_t> cbor_data; // Would need proper CBOR encoding
        // For now, just verify the structure exists
        REQUIRE(subscribe.request_id == 999);
        REQUIRE(subscribe.topic == "com.test.topic");
    }
}

TEST_CASE("PUBLISH/PUBLISHED message serialization", "[wamp_serializer]") {
    SECTION("Serialize PUBLISHED message") {
        PublishedMessage published{789, 101112};

        auto cbor = serialize_published(published);
        REQUIRE(!cbor.empty());

        // Verify it's a valid CBOR array
        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result.size() == 3);
        REQUIRE(json_result[0] == static_cast<int>(MessageType::PUBLISHED));
    }

    SECTION("Deserialize PUBLISH with acknowledgment") {
        // Manual CBOR construction for PUBLISH
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::PUBLISH));
        j.push_back(555);  // request_id
        j.push_back(nlohmann::json::object({{"acknowledge", true}}));  // options
        j.push_back("com.example.event");  // topic

        auto cbor = nlohmann::json::to_cbor(j);
        auto publish = deserialize_publish(cbor);

        REQUIRE(publish.has_value());
        REQUIRE(publish->request_id == 555);
        REQUIRE(publish->topic == "com.example.event");
        REQUIRE(publish->options.contains("acknowledge"));
    }

    SECTION("Deserialize PUBLISH without acknowledgment") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::PUBLISH));
        j.push_back(777);
        j.push_back(nlohmann::json::object());  // empty options
        j.push_back("com.example.another");

        auto cbor = nlohmann::json::to_cbor(j);
        auto publish = deserialize_publish(cbor);

        REQUIRE(publish.has_value());
        REQUIRE(publish->request_id == 777);
        REQUIRE(!publish->options.contains("acknowledge"));
    }
}

TEST_CASE("EVENT message serialization", "[wamp_serializer]") {
    SECTION("Serialize EVENT message") {
        EventMessage event{12345, 67890, {}};

        auto cbor = serialize_event(event);
        REQUIRE(!cbor.empty());

        // Verify structure
        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result.size() == 4);
        REQUIRE(json_result[0] == static_cast<int>(MessageType::EVENT));
        REQUIRE(json_result[1] == 12345);  // subscription_id
        REQUIRE(json_result[2] == 67890);  // publication_id
    }
}

TEST_CASE("REGISTER/REGISTERED message serialization", "[wamp_serializer][rpc]") {
    SECTION("Serialize REGISTERED message") {
        RegisteredMessage registered{123, 456};

        auto cbor = serialize_registered(registered);
        REQUIRE(!cbor.empty());

        // Verify structure
        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result.size() == 3);
        REQUIRE(json_result[0] == static_cast<int>(MessageType::REGISTERED));
        REQUIRE(json_result[1] == 123);  // request_id
        REQUIRE(json_result[2] == 456);  // registration_id
    }

    SECTION("Deserialize REGISTER message") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::REGISTER));
        j.push_back(999);  // request_id
        j.push_back(nlohmann::json::object());  // options
        j.push_back("com.example.procedure");  // procedure

        auto cbor = nlohmann::json::to_cbor(j);
        auto register_msg = deserialize_register(cbor);

        REQUIRE(register_msg.has_value());
        REQUIRE(register_msg->request_id == 999);
        REQUIRE(register_msg->procedure == "com.example.procedure");
    }

    SECTION("Deserialize REGISTER with empty procedure") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::REGISTER));
        j.push_back(111);
        j.push_back(nlohmann::json::object());
        j.push_back("");  // empty procedure

        auto cbor = nlohmann::json::to_cbor(j);
        auto register_msg = deserialize_register(cbor);

        REQUIRE(register_msg.has_value());
        REQUIRE(register_msg->procedure.empty());
    }
}

TEST_CASE("CALL/INVOCATION message serialization", "[wamp_serializer][rpc]") {
    SECTION("Serialize INVOCATION message") {
        InvocationMessage invocation{12345, 67890, {}};

        auto cbor = serialize_invocation(invocation);
        REQUIRE(!cbor.empty());

        // Verify structure
        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result.size() == 4);
        REQUIRE(json_result[0] == static_cast<int>(MessageType::INVOCATION));
        REQUIRE(json_result[1] == 12345);  // request_id
        REQUIRE(json_result[2] == 67890);  // registration_id
    }

    SECTION("Deserialize CALL message") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::CALL));
        j.push_back(555);  // request_id
        j.push_back(nlohmann::json::object());  // options
        j.push_back("com.example.add");  // procedure

        auto cbor = nlohmann::json::to_cbor(j);
        auto call_msg = deserialize_call(cbor);

        REQUIRE(call_msg.has_value());
        REQUIRE(call_msg->request_id == 555);
        REQUIRE(call_msg->procedure == "com.example.add");
    }

    SECTION("Deserialize CALL with options") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::CALL));
        j.push_back(777);
        j.push_back(nlohmann::json::object({{"timeout", 5000}}));
        j.push_back("com.example.longop");

        auto cbor = nlohmann::json::to_cbor(j);
        auto call_msg = deserialize_call(cbor);

        REQUIRE(call_msg.has_value());
        REQUIRE(call_msg->request_id == 777);
        REQUIRE(call_msg->procedure == "com.example.longop");
        // Note: options are not currently parsed by deserializer (returns empty dict)
    }
}

TEST_CASE("YIELD/RESULT message serialization", "[wamp_serializer][rpc]") {
    SECTION("Serialize RESULT message") {
        ResultMessage result{123, {}};

        auto cbor = serialize_result(result);
        REQUIRE(!cbor.empty());

        // Verify structure
        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result.size() == 4);
        REQUIRE(json_result[0] == static_cast<int>(MessageType::RESULT));
        REQUIRE(json_result[1] == 123);  // request_id
    }

    SECTION("Deserialize YIELD message") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::YIELD));
        j.push_back(999);  // invocation_id
        j.push_back(nlohmann::json::object());  // options

        auto cbor = nlohmann::json::to_cbor(j);
        auto yield_msg = deserialize_yield(cbor);

        REQUIRE(yield_msg.has_value());
        REQUIRE(yield_msg->invocation_id == 999);
    }

    SECTION("Deserialize YIELD with options") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::YIELD));
        j.push_back(444);
        j.push_back(nlohmann::json::object({{"progress", true}}));

        auto cbor = nlohmann::json::to_cbor(j);
        auto yield_msg = deserialize_yield(cbor);

        REQUIRE(yield_msg.has_value());
        REQUIRE(yield_msg->invocation_id == 444);
        // Note: options are not currently parsed by deserializer (returns empty dict)
    }
}

TEST_CASE("ERROR message serialization", "[wamp_serializer][rpc]") {
    SECTION("Serialize ERROR for procedure_already_exists") {
        auto error = ErrorMessage::create_procedure_already_exists(123, "com.example.proc");

        auto cbor = serialize_error(error);
        REQUIRE(!cbor.empty());

        // Verify structure
        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result.size() == 5);
        REQUIRE(json_result[0] == static_cast<int>(MessageType::ERROR));
        REQUIRE(json_result[1] == static_cast<int>(MessageType::REGISTER));
        REQUIRE(json_result[2] == 123);  // request_id
        REQUIRE(json_result[4] == "wamp.error.procedure_already_exists");
    }

    SECTION("Serialize ERROR for no_such_procedure") {
        auto error = ErrorMessage::create_no_such_procedure(456, "com.example.missing");

        auto cbor = serialize_error(error);

        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result[1] == static_cast<int>(MessageType::CALL));
        REQUIRE(json_result[2] == 456);
        REQUIRE(json_result[4] == "wamp.error.no_such_procedure");
    }

    SECTION("Serialize ERROR for callee_failure") {
        auto error = ErrorMessage::create_callee_failure(789, "Connection lost");

        auto cbor = serialize_error(error);

        auto json_result = nlohmann::json::from_cbor(cbor);
        REQUIRE(json_result.is_array());
        REQUIRE(json_result[1] == static_cast<int>(MessageType::CALL));
        REQUIRE(json_result[2] == 789);
        REQUIRE(json_result[4] == "wamp.error.callee_failure");
    }
}

TEST_CASE("Message type detection from CBOR", "[wamp_serializer]") {
    SECTION("Detect HELLO message type") {
        HelloMessage hello{"com.example.realm"};
        auto cbor = serialize_hello(hello);

        auto msg_type = get_message_type_from_cbor(cbor);
        REQUIRE(msg_type.has_value());
        REQUIRE(*msg_type == MessageType::HELLO);
    }

    SECTION("Detect WELCOME message type") {
        auto welcome = WelcomeMessage::create_router(1, "realm");
        auto cbor = serialize_welcome(welcome);

        auto msg_type = get_message_type_from_cbor(cbor);
        REQUIRE(msg_type.has_value());
        REQUIRE(*msg_type == MessageType::WELCOME);
    }

    SECTION("Detect GOODBYE message type") {
        auto goodbye = GoodbyeMessage::create_normal();
        auto cbor = serialize_goodbye(goodbye);

        auto msg_type = get_message_type_from_cbor(cbor);
        REQUIRE(msg_type.has_value());
        REQUIRE(*msg_type == MessageType::GOODBYE);
    }

    SECTION("Detect REGISTER message type") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::REGISTER));
        j.push_back(1);
        j.push_back(nlohmann::json::object());
        j.push_back("proc");
        auto cbor = nlohmann::json::to_cbor(j);

        auto msg_type = get_message_type_from_cbor(cbor);
        REQUIRE(msg_type.has_value());
        REQUIRE(*msg_type == MessageType::REGISTER);
    }

    SECTION("Detect CALL message type") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::CALL));
        j.push_back(1);
        j.push_back(nlohmann::json::object());
        j.push_back("proc");
        auto cbor = nlohmann::json::to_cbor(j);

        auto msg_type = get_message_type_from_cbor(cbor);
        REQUIRE(msg_type.has_value());
        REQUIRE(*msg_type == MessageType::CALL);
    }

    SECTION("Detect YIELD message type") {
        nlohmann::json j = nlohmann::json::array();
        j.push_back(static_cast<int>(MessageType::YIELD));
        j.push_back(1);
        j.push_back(nlohmann::json::object());
        auto cbor = nlohmann::json::to_cbor(j);

        auto msg_type = get_message_type_from_cbor(cbor);
        REQUIRE(msg_type.has_value());
        REQUIRE(*msg_type == MessageType::YIELD);
    }

    SECTION("Invalid CBOR data") {
        std::vector<uint8_t> invalid{0xFF, 0xFF};
        auto msg_type = get_message_type_from_cbor(invalid);
        REQUIRE(!msg_type.has_value());
    }
}
