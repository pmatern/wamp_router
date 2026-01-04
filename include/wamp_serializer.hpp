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

#include "wamp_messages.hpp"
#include <nlohmann/json.hpp>
#include <vector>
#include <cstdint>
#include <expected>
#include <system_error>
#include <spdlog/spdlog.h>

namespace wamp {

// Serialization errors
enum class SerializationError {
    INVALID_MESSAGE_TYPE = 200,
    MALFORMED_MESSAGE = 201,
    MISSING_REQUIRED_FIELD = 202,
    TYPE_MISMATCH = 203,
    CBOR_DECODE_ERROR = 204
};

// Error category for serialization errors
class SerializationErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override {
        return "wamp_serialization";
    }

    [[nodiscard]] std::string message(int ev) const override {
        switch (static_cast<SerializationError>(ev)) {
            case SerializationError::INVALID_MESSAGE_TYPE:
                return "Invalid WAMP message type";
            case SerializationError::MALFORMED_MESSAGE:
                return "Malformed WAMP message structure";
            case SerializationError::MISSING_REQUIRED_FIELD:
                return "Missing required field in message";
            case SerializationError::TYPE_MISMATCH:
                return "Type mismatch in message field";
            case SerializationError::CBOR_DECODE_ERROR:
                return "Failed to decode CBOR data";
            default:
                return "Unknown serialization error";
        }
    }
};

inline const SerializationErrorCategory& serialization_error_category() {
    static SerializationErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(SerializationError e) {
    return {static_cast<int>(e), serialization_error_category()};
}

} // namespace wamp

// Register SerializationError as error code enum
template<>
struct std::is_error_code_enum<wamp::SerializationError> : std::true_type {};

namespace wamp {

using json = nlohmann::json;

// ============================================================================
// CBOR Serialization Functions
// ============================================================================

// Serialize HELLO message to CBOR
// Format: [1, realm, details]
inline std::vector<uint8_t> serialize_hello(const HelloMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::HELLO));

    // Realm (string)
    j.push_back(msg.realm);

    // Details (dictionary)
    json details = json::object();

    // Add roles
    json roles = json::object();
    for (const auto& role : msg.roles) {
        roles[role.name] = json::object();  // Empty features for now
    }
    details["roles"] = roles;

    // Add optional authmethods
    if (msg.authmethods.has_value() && !msg.authmethods->empty()) {
        json authmethods_array = json::array();
        for (const auto& method : *msg.authmethods) {
            authmethods_array.push_back(method);
        }
        details["authmethods"] = authmethods_array;
    }

    // Add optional authid
    if (msg.authid.has_value()) {
        details["authid"] = *msg.authid;
    }

    j.push_back(details);

    return json::to_cbor(j);
}

// Serialize WELCOME message to CBOR
// Format: [2, session_id, details]
inline std::vector<uint8_t> serialize_welcome(const WelcomeMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::WELCOME));

    // Session ID (integer)
    j.push_back(msg.session_id);

    // Details (dictionary)
    json details = json::object();

    // Add roles
    json roles = json::object();
    for (const auto& role : msg.roles) {
        roles[role.name] = json::object();  // Empty features for now
    }
    details["roles"] = roles;

    // Add optional fields
    if (msg.authid.has_value()) {
        details["authid"] = *msg.authid;
    }
    if (msg.authrole.has_value()) {
        details["authrole"] = *msg.authrole;
    }
    if (msg.authmethod.has_value()) {
        details["authmethod"] = *msg.authmethod;
    }

    j.push_back(details);

    return json::to_cbor(j);
}

// Serialize GOODBYE message to CBOR
// Format: [6, details, reason]
inline std::vector<uint8_t> serialize_goodbye(const GoodbyeMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::GOODBYE));

    // Details (empty object for now)
    j.push_back(json::object());

    // Reason (URI string)
    j.push_back(msg.reason);

    return json::to_cbor(j);
}

// Serialize ABORT message to CBOR
// Format: [3, details, reason]
inline std::vector<uint8_t> serialize_abort(const AbortMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::ABORT));

    // Details (can contain message field)
    json details = json::object();
    // Note: WampDict conversion simplified here
    j.push_back(details);

    // Reason (URI string)
    j.push_back(msg.reason);

    return json::to_cbor(j);
}

// Serialize CHALLENGE message to CBOR
// Format: [4, authmethod, extra]
inline std::vector<uint8_t> serialize_challenge(const ChallengeMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::CHALLENGE));

    // AuthMethod (string)
    j.push_back(msg.authmethod);

    // Extra (dictionary)
    json extra = json::object();
    for (const auto& [key, value] : msg.extra) {
        extra[key] = value;
    }
    j.push_back(extra);

    return json::to_cbor(j);
}

// Serialize AUTHENTICATE message to CBOR
// Format: [5, signature, extra]
inline std::vector<uint8_t> serialize_authenticate(const AuthenticateMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::AUTHENTICATE));

    // Signature (string)
    j.push_back(msg.signature);

    // Extra (dictionary)
    json extra = json::object();
    for (const auto& [key, value] : msg.extra) {
        extra[key] = value;
    }
    j.push_back(extra);

    return json::to_cbor(j);
}

// ============================================================================
// CBOR Deserialization Functions
// ============================================================================

// Deserialize CBOR to determine message type
inline std::expected<MessageType, std::error_code>
get_message_type_from_cbor(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.empty()) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type_code = j[0].get<int>();
        return static_cast<MessageType>(type_code);

    } catch (const json::exception& e) {
        spdlog::error("CBOR decode error: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize HELLO message from CBOR
// Format: [1, realm, details]
inline std::expected<HelloMessage, std::error_code>
deserialize_hello(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() != 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::HELLO)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        std::string realm = j[1].get<std::string>();
        HelloMessage msg{realm};

        if (j[2].is_object()) {
            const auto& details = j[2];

            // Extract roles
            if (details.contains("roles") && details["roles"].is_object()) {
                for (const auto& [role_name, features] : details["roles"].items()) {
                    msg.roles.push_back(Role{role_name, {}});
                }
            }

            // Extract authmethods
            if (details.contains("authmethods") && details["authmethods"].is_array()) {
                std::vector<std::string> methods;
                for (const auto& method : details["authmethods"]) {
                    if (method.is_string()) {
                        methods.push_back(method.get<std::string>());
                    }
                }
                if (!methods.empty()) {
                    msg.authmethods = methods;
                }
            }

            // Extract authid
            if (details.contains("authid") && details["authid"].is_string()) {
                msg.authid = details["authid"].get<std::string>();
            }
        }

        return msg;

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize HELLO: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize WELCOME message from CBOR
// Format: [2, session_id, details]
inline std::expected<WelcomeMessage, std::error_code>
deserialize_welcome(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() != 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::WELCOME)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract session ID
        uint64_t session_id = j[1].get<uint64_t>();

        // Create message (realm is in details, but we'll use a placeholder)
        WelcomeMessage msg{session_id, ""};

        // Parse details
        if (j[2].is_object()) {
            const auto& details = j[2];

            // Extract roles
            if (details.contains("roles") && details["roles"].is_object()) {
                for (const auto& [role_name, features] : details["roles"].items()) {
                    msg.roles.push_back(Role{role_name, {}});
                }
            }

            // Extract optional fields
            if (details.contains("authid") && details["authid"].is_string()) {
                msg.authid = details["authid"].get<std::string>();
            }
            if (details.contains("authrole") && details["authrole"].is_string()) {
                msg.authrole = details["authrole"].get<std::string>();
            }
            if (details.contains("authmethod") && details["authmethod"].is_string()) {
                msg.authmethod = details["authmethod"].get<std::string>();
            }
        }

        return msg;

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize WELCOME: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize GOODBYE message from CBOR
// Format: [6, details, reason]
inline std::expected<GoodbyeMessage, std::error_code>
deserialize_goodbye(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() != 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::GOODBYE)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract details (currently ignored)
        WampDict details;

        // Extract reason
        std::string reason = j[2].get<std::string>();

        return GoodbyeMessage{details, reason};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize GOODBYE: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize ABORT message from CBOR
// Format: [3, details, reason]
inline std::expected<AbortMessage, std::error_code>
deserialize_abort(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() != 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::ABORT)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract details (currently simplified)
        WampDict details;

        // Extract reason
        std::string reason = j[2].get<std::string>();

        return AbortMessage{details, reason};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize ABORT: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize CHALLENGE message from CBOR
// Format: [4, authmethod, extra]
inline std::expected<ChallengeMessage, std::error_code>
deserialize_challenge(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() != 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::CHALLENGE)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract authmethod
        std::string authmethod = j[1].get<std::string>();

        // Extract extra dictionary
        std::map<std::string, std::string> extra;
        if (j[2].is_object()) {
            for (auto it = j[2].begin(); it != j[2].end(); ++it) {
                if (it.value().is_string()) {
                    extra[it.key()] = it.value().get<std::string>();
                }
            }
        }

        return ChallengeMessage{authmethod, extra};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize CHALLENGE: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize AUTHENTICATE message from CBOR
// Format: [5, signature, extra]
inline std::expected<AuthenticateMessage, std::error_code>
deserialize_authenticate(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() != 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::AUTHENTICATE)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract signature
        std::string signature = j[1].get<std::string>();

        // Extract extra dictionary
        std::map<std::string, std::string> extra;
        if (j[2].is_object()) {
            for (auto it = j[2].begin(); it != j[2].end(); ++it) {
                if (it.value().is_string()) {
                    extra[it.key()] = it.value().get<std::string>();
                }
            }
        }

        return AuthenticateMessage{signature, extra};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize AUTHENTICATE: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Serialize SUBSCRIBE message to CBOR
// Format: [32, Request|id, Options|dict, Topic|uri]
inline std::vector<uint8_t> serialize_subscribe(const SubscribeMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::SUBSCRIBE));

    // Request ID
    j.push_back(msg.request_id);

    // Options (empty dict for now)
    j.push_back(json::object());

    // Topic URI
    j.push_back(msg.topic);

    return json::to_cbor(j);
}

// Serialize SUBSCRIBED message to CBOR
// Format: [33, SUBSCRIBE.Request|id, Subscription|id]
inline std::vector<uint8_t> serialize_subscribed(const SubscribedMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::SUBSCRIBED));

    // Request ID
    j.push_back(msg.request_id);

    // Subscription ID
    j.push_back(msg.subscription_id);

    return json::to_cbor(j);
}

// Deserialize SUBSCRIBE message from CBOR
// Format: [32, Request|id, Options|dict, Topic|uri]
inline std::expected<SubscribeMessage, std::error_code>
deserialize_subscribe(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() != 4) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::SUBSCRIBE)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract request ID
        uint64_t request_id = j[1].get<uint64_t>();

        // Extract options (simplified - just store as empty dict for now)
        WampDict options{};

        // Extract topic URI
        std::string topic = j[3].get<std::string>();

        return SubscribeMessage{request_id, options, topic};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize SUBSCRIBE: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Serialize PUBLISHED message to CBOR
// Format: [17, PUBLISH.Request|id, Publication|id]
inline std::vector<uint8_t> serialize_published(const PublishedMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::PUBLISHED));

    // Request ID
    j.push_back(msg.request_id);

    // Publication ID
    j.push_back(msg.publication_id);

    return json::to_cbor(j);
}

// Serialize EVENT message to CBOR
// Format: [36, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict]
inline std::vector<uint8_t> serialize_event(const EventMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::EVENT));

    // Subscription ID
    j.push_back(msg.subscription_id);

    // Publication ID
    j.push_back(msg.publication_id);

    // Details (empty object for now)
    j.push_back(json::object());

    // Note: Can optionally include Arguments|list and ArgumentsKw|dict but we ignore for now
    return json::to_cbor(j);
}

// Deserialize PUBLISH message from CBOR
// Format: [16, Request|id, Options|dict, Topic|uri]
// Note: Can optionally have Arguments|list and ArgumentsKw|dict but we ignore those for now
inline std::expected<PublishMessage, std::error_code>
deserialize_publish(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 4) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::PUBLISH)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract request ID
        uint64_t request_id = j[1].get<uint64_t>();

        // Extract options
        WampDict options{};
        if (j[2].is_object()) {
            // Parse acknowledge option if present
            if (j[2].contains("acknowledge") && j[2]["acknowledge"].is_boolean()) {
                options["acknowledge"] = j[2]["acknowledge"].get<bool>();
            }
            // Can add other options here as needed
        }

        // Extract topic URI
        std::string topic = j[3].get<std::string>();

        // Note: j[4] and j[5] may contain Arguments and ArgumentsKw but we ignore for now

        return PublishMessage{request_id, options, topic};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize PUBLISH: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Serialize REGISTER message to CBOR
// Format: [64, Request|id, Options|dict, Procedure|uri]
inline std::vector<uint8_t> serialize_register(const RegisterMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::REGISTER));

    // Request ID
    j.push_back(msg.request_id);

    // Options (empty dict for now)
    j.push_back(json::object());

    // Procedure URI
    j.push_back(msg.procedure);

    return json::to_cbor(j);
}

// Serialize REGISTERED message to CBOR
// Format: [65, REGISTER.Request|id, Registration|id]
inline std::vector<uint8_t> serialize_registered(const RegisteredMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::REGISTERED));

    // Request ID
    j.push_back(msg.request_id);

    // Registration ID
    j.push_back(msg.registration_id);

    return json::to_cbor(j);
}

// Deserialize REGISTER message from CBOR
// Format: [64, Request|id, Options|dict, Procedure|uri]
inline std::expected<RegisterMessage, std::error_code>
deserialize_register(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 4) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::REGISTER)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract request ID
        uint64_t request_id = j[1].get<uint64_t>();

        // Extract options (empty dict for now)
        WampDict options{};
        // Could parse options from j[2] if needed

        // Extract procedure URI
        std::string procedure = j[3].get<std::string>();

        return RegisterMessage{request_id, options, procedure};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize REGISTER: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Serialize INVOCATION message to CBOR
// Format: [68, Request|id, Registration|id, Details|dict]
inline std::vector<uint8_t> serialize_invocation(const InvocationMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::INVOCATION));

    // Request ID
    j.push_back(msg.request_id);

    // Registration ID
    j.push_back(msg.registration_id);

    // Details (empty object for now)
    j.push_back(json::object());

    // Note: Could add Arguments|list and ArgumentsKw|dict but we ignore for now

    return json::to_cbor(j);
}

// Deserialize CALL message from CBOR
// Format: [48, Request|id, Options|dict, Procedure|uri]
// Note: Can optionally have Arguments|list and ArgumentsKw|dict but we ignore those for now
inline std::expected<CallMessage, std::error_code>
deserialize_call(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 4) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::CALL)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract request ID
        uint64_t request_id = j[1].get<uint64_t>();

        // Extract options (empty dict for now)
        WampDict options{};
        // Could parse options from j[2] if needed

        // Extract procedure URI
        std::string procedure = j[3].get<std::string>();

        // Note: j[4] and j[5] may contain Arguments and ArgumentsKw but we ignore for now

        return CallMessage{request_id, options, procedure};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize CALL: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Serialize RESULT message to CBOR
// Format: [50, CALL.Request|id, Details|dict]
inline std::vector<uint8_t> serialize_result(const ResultMessage& msg) {
    json j = json::array();

    // Message type
    j.push_back(static_cast<int>(MessageType::RESULT));

    // Request ID from the original CALL
    j.push_back(msg.request_id);

    // Details (empty object for now)
    j.push_back(json::object());

    // Note: Can optionally include Arguments|list and ArgumentsKw|dict but we ignore for now
    return json::to_cbor(j);
}

// Deserialize YIELD message from CBOR
// Format: [70, INVOCATION.Request|id, Options|dict]
// Note: Can optionally have Arguments|list and ArgumentsKw|dict but we ignore those for now
inline std::expected<YieldMessage, std::error_code>
deserialize_yield(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        // Verify message type
        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::YIELD)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        // Extract invocation ID (from INVOCATION message)
        uint64_t invocation_id = j[1].get<uint64_t>();

        // Extract options (empty dict for now)
        WampDict options{};
        // Could parse options from j[2] if needed

        // Note: j[3] and j[4] may contain Arguments and ArgumentsKw but we ignore for now

        return YieldMessage{invocation_id, options};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize YIELD: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Serialize ERROR message to CBOR
// Format: [8, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri]
inline std::vector<uint8_t> serialize_error(const ErrorMessage& msg) {
    json j = json::array();

    // Message type (always 8 for ERROR)
    j.push_back(static_cast<int>(MessageType::ERROR));

    // Request type that caused the error
    j.push_back(static_cast<int>(msg.request_type));

    // Request ID from the failed request
    j.push_back(msg.request_id);

    // Details dictionary
    json details = json::object();
    for (const auto& [key, value] : msg.details) {
        if (auto* str = std::get_if<std::string>(&value)) {
            details[key] = *str;
        } else if (auto* num = std::get_if<int64_t>(&value)) {
            details[key] = *num;
        } else if (auto* b = std::get_if<bool>(&value)) {
            details[key] = *b;
        }
    }
    j.push_back(details);

    // Error URI
    j.push_back(msg.error_uri);

    // Note: Can optionally include Arguments|list and ArgumentsKw|dict but we ignore for now
    return json::to_cbor(j);
}

// Serialize PUBLISH message to CBOR
// Format: [16, Request|id, Options|dict, Topic|uri]
inline std::vector<uint8_t> serialize_publish(const PublishMessage& msg) {
    json j = json::array();
    j.push_back(static_cast<int>(MessageType::PUBLISH));
    j.push_back(msg.request_id);

    json options_obj = json::object();
    for (const auto& [key, value] : msg.options) {
        if (auto* b = std::get_if<bool>(&value)) {
            options_obj[key] = *b;
        }
    }
    j.push_back(options_obj);
    j.push_back(msg.topic);
    return json::to_cbor(j);
}

// Serialize CALL message to CBOR
// Format: [48, Request|id, Options|dict, Procedure|uri]
inline std::vector<uint8_t> serialize_call(const CallMessage& msg) {
    json j = json::array();
    j.push_back(static_cast<int>(MessageType::CALL));
    j.push_back(msg.request_id);
    j.push_back(json::object());  // options (empty for now)
    j.push_back(msg.procedure);
    return json::to_cbor(j);
}

// Serialize YIELD message to CBOR
// Format: [70, INVOCATION.Request|id, Options|dict]
inline std::vector<uint8_t> serialize_yield(const YieldMessage& msg) {
    json j = json::array();
    j.push_back(static_cast<int>(MessageType::YIELD));
    j.push_back(msg.invocation_id);
    j.push_back(json::object());  // options (empty for now)
    return json::to_cbor(j);
}

// Deserialize SUBSCRIBED message from CBOR
// Format: [33, SUBSCRIBE.Request|id, Subscription|id]
inline std::expected<SubscribedMessage, std::error_code>
deserialize_subscribed(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::SUBSCRIBED)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        uint64_t request_id = j[1].get<uint64_t>();
        uint64_t subscription_id = j[2].get<uint64_t>();

        return SubscribedMessage{request_id, subscription_id};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize SUBSCRIBED: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize PUBLISHED message from CBOR
// Format: [17, PUBLISH.Request|id, Publication|id]
inline std::expected<PublishedMessage, std::error_code>
deserialize_published(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::PUBLISHED)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        uint64_t request_id = j[1].get<uint64_t>();
        uint64_t publication_id = j[2].get<uint64_t>();

        return PublishedMessage{request_id, publication_id};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize PUBLISHED: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize EVENT message from CBOR
// Format: [36, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict]
inline std::expected<EventMessage, std::error_code>
deserialize_event(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 4) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::EVENT)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        uint64_t subscription_id = j[1].get<uint64_t>();
        uint64_t publication_id = j[2].get<uint64_t>();
        WampDict details{};  // Simplified - not parsing details for now

        return EventMessage{subscription_id, publication_id, details};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize EVENT: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize REGISTERED message from CBOR
// Format: [65, REGISTER.Request|id, Registration|id]
inline std::expected<RegisteredMessage, std::error_code>
deserialize_registered(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::REGISTERED)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        uint64_t request_id = j[1].get<uint64_t>();
        uint64_t registration_id = j[2].get<uint64_t>();

        return RegisteredMessage{request_id, registration_id};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize REGISTERED: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize INVOCATION message from CBOR
// Format: [68, Request|id, REGISTERED.Registration|id, Details|dict]
inline std::expected<InvocationMessage, std::error_code>
deserialize_invocation(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 4) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::INVOCATION)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        uint64_t request_id = j[1].get<uint64_t>();
        uint64_t registration_id = j[2].get<uint64_t>();
        WampDict details{};  // Simplified - not parsing details for now

        return InvocationMessage{request_id, registration_id, details};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize INVOCATION: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize RESULT message from CBOR
// Format: [50, CALL.Request|id, Details|dict]
inline std::expected<ResultMessage, std::error_code>
deserialize_result(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 3) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::RESULT)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        uint64_t request_id = j[1].get<uint64_t>();
        WampDict details{};  // Simplified - not parsing details for now

        return ResultMessage{request_id, details};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize RESULT: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Deserialize ERROR message from CBOR
// Format: [8, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri]
inline std::expected<ErrorMessage, std::error_code>
deserialize_error(const std::vector<uint8_t>& cbor_data) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < 5) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(MessageType::ERROR)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        auto request_type = static_cast<MessageType>(j[1].get<int>());
        uint64_t request_id = j[2].get<uint64_t>();
        WampDict details{};  // Simplified - not parsing details for now
        std::string error_uri = j[4].get<std::string>();

        return ErrorMessage{request_type, request_id, details, error_uri};

    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize ERROR: {}", e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

} // namespace wamp
