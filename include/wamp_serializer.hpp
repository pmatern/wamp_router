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
// Variant-JSON Conversion Helpers
// ============================================================================

// Convert WampList element variant to JSON
inline json variant_to_json(const std::variant<std::string, int64_t, bool>& v) {
    return std::visit([](const auto& val) -> json { return val; }, v);
}

// Convert WampDict element variant to JSON (includes nested dict support)
inline json variant_to_json(const WampDict::mapped_type& v) {
    return std::visit(
        []<typename T0>(const T0& val) -> json {
            using T = std::decay_t<T0>;
            if constexpr (std::is_same_v<T, std::unordered_map<std::string, std::string>>) {
                return json(val);
            } else {
                return val;
            }
        },
        v);
}

// Convert JSON to WampList element variant
inline std::optional<std::variant<std::string, int64_t, bool>> json_to_list_variant(const json& j) {
    if (j.is_string()) {
        return j.get<std::string>();
    } else if (j.is_boolean()) {
        return j.get<bool>();
    } else if (j.is_number()) {
        return j.get<int64_t>();
    }
    return std::nullopt;
}

// Convert JSON to WampDict element variant
inline std::optional<WampDict::mapped_type> json_to_dict_variant(const json& j) {
    if (j.is_string()) {
        return j.get<std::string>();
    } else if (j.is_boolean()) {
        return j.get<bool>();
    } else if (j.is_number()) {
        return j.get<int64_t>();
    } else if (j.is_object()) {
        std::unordered_map<std::string, std::string> nested;
        for (const auto& [k, v] : j.items()) {
            if (v.is_string()) {
                nested[k] = v.get<std::string>();
            }
        }
        return nested;
    }
    return std::nullopt;
}

// ============================================================================
// Deserialization Helper
// ============================================================================

// Helper template to reduce boilerplate in deserialize_* functions.
// Handles CBOR decoding, array validation, message type checking, and error handling.
// The extractor lambda receives the parsed JSON array and returns the message struct.
template<typename T, typename Extractor>
std::expected<T, std::error_code>
deserialize_message(const std::vector<uint8_t>& cbor_data,
                    size_t min_size,
                    MessageType expected_type,
                    std::string_view msg_name,
                    Extractor&& extract) {
    try {
        json j = json::from_cbor(cbor_data);

        if (!j.is_array() || j.size() < min_size) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }

        int type = j[0].get<int>();
        if (type != static_cast<int>(expected_type)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }

        return extract(j);
    } catch (const json::exception& e) {
        spdlog::error("Failed to deserialize {}: {}", msg_name, e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// ============================================================================
// CBOR Serialization Functions
// ============================================================================

inline json serialize_list(const WampList& list) {
    auto arr = json::array();
    for (const auto& item : list) {
        arr.push_back(variant_to_json(item));
    }
    return arr;
}

inline json serialize_dict(const WampDict& dict) {
    auto obj = json::object();
    for (const auto& [key, value] : dict) {
        obj[key] = variant_to_json(value);
    }
    return obj;
}

inline WampList deserialize_list(const json::array_t& j) {
    WampList list;
    for (const auto& item : j) {
        if (auto val = json_to_list_variant(item)) {
            list.push_back(*val);
        }
    }
    return list;
}

inline WampDict deserialize_dict(const json::object_t& j) {
    WampDict dict;
    for (const auto& [key, value] : j) {
        if (auto val = json_to_dict_variant(value)) {
            dict[key] = *val;
        }
    }
    return dict;
}


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
    return deserialize_message<HelloMessage>(
        cbor_data, 3, MessageType::HELLO, "HELLO",
        [](const json& j) {
            HelloMessage msg{j[1].get<std::string>()};

            if (j[2].is_object()) {
                const auto& details = j[2];

                if (details.contains("roles") && details["roles"].is_object()) {
                    for (const auto& [role_name, features] : details["roles"].items()) {
                        msg.roles.push_back(Role{role_name, {}});
                    }
                }

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

                if (details.contains("authid") && details["authid"].is_string()) {
                    msg.authid = details["authid"].get<std::string>();
                }
            }

            return msg;
        });
}

// Deserialize WELCOME message from CBOR
// Format: [2, session_id, details]
inline std::expected<WelcomeMessage, std::error_code>
deserialize_welcome(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<WelcomeMessage>(
        cbor_data, 3, MessageType::WELCOME, "WELCOME",
        [](const json& j) {
            WelcomeMessage msg{j[1].get<uint64_t>(), ""};

            if (j[2].is_object()) {
                const auto& details = j[2];

                if (details.contains("roles") && details["roles"].is_object()) {
                    for (const auto& [role_name, features] : details["roles"].items()) {
                        msg.roles.push_back(Role{role_name, {}});
                    }
                }

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
        });
}

// Deserialize GOODBYE message from CBOR
// Format: [6, details, reason]
inline std::expected<GoodbyeMessage, std::error_code>
deserialize_goodbye(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<GoodbyeMessage>(
        cbor_data, 3, MessageType::GOODBYE, "GOODBYE",
        [](const json& j) {
            return GoodbyeMessage{WampDict{}, j[2].get<std::string>()};
        });
}

// Deserialize ABORT message from CBOR
// Format: [3, details, reason]
inline std::expected<AbortMessage, std::error_code>
deserialize_abort(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<AbortMessage>(
        cbor_data, 3, MessageType::ABORT, "ABORT",
        [](const json& j) {
            return AbortMessage{WampDict{}, j[2].get<std::string>()};
        });
}

// Helper to extract string map from JSON object
inline std::map<std::string, std::string> extract_string_map(const json& obj) {
    std::map<std::string, std::string> result;
    if (obj.is_object()) {
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            if (it.value().is_string()) {
                result[it.key()] = it.value().get<std::string>();
            }
        }
    }
    return result;
}

// Deserialize CHALLENGE message from CBOR
// Format: [4, authmethod, extra]
inline std::expected<ChallengeMessage, std::error_code>
deserialize_challenge(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<ChallengeMessage>(
        cbor_data, 3, MessageType::CHALLENGE, "CHALLENGE",
        [](const json& j) {
            return ChallengeMessage{j[1].get<std::string>(), extract_string_map(j[2])};
        });
}

// Deserialize AUTHENTICATE message from CBOR
// Format: [5, signature, extra]
inline std::expected<AuthenticateMessage, std::error_code>
deserialize_authenticate(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<AuthenticateMessage>(
        cbor_data, 3, MessageType::AUTHENTICATE, "AUTHENTICATE",
        [](const json& j) {
            return AuthenticateMessage{j[1].get<std::string>(), extract_string_map(j[2])};
        });
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
    return deserialize_message<SubscribeMessage>(
        cbor_data, 4, MessageType::SUBSCRIBE, "SUBSCRIBE",
        [](const json& j) {
            return SubscribeMessage{j[1].get<uint64_t>(), WampDict{}, j[3].get<std::string>()};
        });
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
    return deserialize_message<PublishMessage>(
        cbor_data, 4, MessageType::PUBLISH, "PUBLISH",
        [](const json& j) {
            WampDict options{};
            if (j[2].is_object() && j[2].contains("acknowledge") && j[2]["acknowledge"].is_boolean()) {
                options["acknowledge"] = j[2]["acknowledge"].get<bool>();
            }
            return PublishMessage{j[1].get<uint64_t>(), options, j[3].get<std::string>()};
        });
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
    return deserialize_message<RegisterMessage>(
        cbor_data, 4, MessageType::REGISTER, "REGISTER",
        [](const json& j) {
            return RegisterMessage{j[1].get<uint64_t>(), WampDict{}, j[3].get<std::string>()};
        });
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

    // TODO: Add Arguments|list and ArgumentsKw|dict but we ignore for now

    return json::to_cbor(j);
}

// Deserialize CALL message from CBOR
// Format: [48, Request|id, Options|dict, Procedure|uri]
// Note: Can optionally have Arguments|list and ArgumentsKw|dict but we ignore those for now
inline std::expected<CallMessage, std::error_code>
deserialize_call(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<CallMessage>(
        cbor_data, 4, MessageType::CALL, "CALL",
        [](const json& j) {
            return CallMessage{j[1].get<uint64_t>(), WampDict{}, j[3].get<std::string>()};
        });
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

    // Arguments (positional)
    if (!msg.arguments.empty()) {
        auto l = serialize_list(msg.arguments);
        j.push_back(l);
    } else {
        j.push_back(json::array());
    }

    // ArgumentsKw (keyword)
    if (!msg.arguments_kw.empty()) {
        auto d = serialize_dict(msg.arguments_kw);
        j.push_back(d);
    }

    return json::to_cbor(j);
}

// Deserialize YIELD message from CBOR
// Format: [70, INVOCATION.Request|id, Options|dict]
// Note: Can optionally have Arguments|list and ArgumentsKw|dict
inline std::expected<YieldMessage, std::error_code>
deserialize_yield(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<YieldMessage>(
        cbor_data, 3, MessageType::YIELD, "YIELD",
        [](const json& j) {
            WampList arguments;
            WampDict arguments_kw;
            if (j.size() >= 4 && j[3].is_array()) {
                arguments = deserialize_list(j[3]);
            }
            if (j.size() >= 5 && j[4].is_object()) {
                arguments_kw = deserialize_dict(j[4]);
            }
            return YieldMessage{j[1].get<uint64_t>(), WampDict{}, arguments, arguments_kw};
        });
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
    json details = serialize_dict(msg.details);
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
    j.push_back(serialize_dict(msg.options));
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
    auto j = json::array();
    j.push_back(static_cast<int>(MessageType::YIELD));
    j.push_back(msg.invocation_id);
    j.push_back(json::object());  // options (empty for now)

    // Arguments (positional)
    if (!msg.arguments.empty()) {
        const auto l = serialize_list(msg.arguments);
        j.push_back(l);
    } else {
        j.push_back(json::array());
    }

    // ArgumentsKw (keyword)
    if (!msg.arguments_kw.empty()) {
        const auto d = serialize_dict(msg.arguments_kw);
        j.push_back(d);
    }

    return json::to_cbor(j);
}

// Deserialize SUBSCRIBED message from CBOR
// Format: [33, SUBSCRIBE.Request|id, Subscription|id]
inline std::expected<SubscribedMessage, std::error_code>
deserialize_subscribed(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<SubscribedMessage>(
        cbor_data, 3, MessageType::SUBSCRIBED, "SUBSCRIBED",
        [](const json& j) {
            return SubscribedMessage{j[1].get<uint64_t>(), j[2].get<uint64_t>()};
        });
}

// Deserialize PUBLISHED message from CBOR
// Format: [17, PUBLISH.Request|id, Publication|id]
inline std::expected<PublishedMessage, std::error_code>
deserialize_published(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<PublishedMessage>(
        cbor_data, 3, MessageType::PUBLISHED, "PUBLISHED",
        [](const json& j) {
            return PublishedMessage{j[1].get<uint64_t>(), j[2].get<uint64_t>()};
        });
}

// Deserialize EVENT message from CBOR
// Format: [36, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict]
inline std::expected<EventMessage, std::error_code>
deserialize_event(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<EventMessage>(
        cbor_data, 4, MessageType::EVENT, "EVENT",
        [](const json& j) {
            return EventMessage{j[1].get<uint64_t>(), j[2].get<uint64_t>(), WampDict{}};
        });
}

// Deserialize REGISTERED message from CBOR
// Format: [65, REGISTER.Request|id, Registration|id]
inline std::expected<RegisteredMessage, std::error_code>
deserialize_registered(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<RegisteredMessage>(
        cbor_data, 3, MessageType::REGISTERED, "REGISTERED",
        [](const json& j) {
            return RegisteredMessage{j[1].get<uint64_t>(), j[2].get<uint64_t>()};
        });
}

// Deserialize INVOCATION message from CBOR
// Format: [68, Request|id, REGISTERED.Registration|id, Details|dict]
inline std::expected<InvocationMessage, std::error_code>
deserialize_invocation(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<InvocationMessage>(
        cbor_data, 4, MessageType::INVOCATION, "INVOCATION",
        [](const json& j) {
            return InvocationMessage{j[1].get<uint64_t>(), j[2].get<uint64_t>(), WampDict{}};
        });
}

// Deserialize RESULT message from CBOR
// Format: [50, CALL.Request|id, Details|dict, YIELD.Arguments|list, YIELD.ArgumentsKw|dict]
inline std::expected<ResultMessage, std::error_code>
deserialize_result(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<ResultMessage>(
        cbor_data, 3, MessageType::RESULT, "RESULT",
        [](const json& j) {
            WampList arguments;
            WampDict arguments_kw;
            if (j.size() >= 4 && j[3].is_array()) {
                arguments = deserialize_list(j[3]);
            }
            if (j.size() >= 5 && j[4].is_object()) {
                arguments_kw = deserialize_dict(j[4]);
            }
            return ResultMessage{j[1].get<uint64_t>(), WampDict{}, arguments, arguments_kw};
        });
}

// Deserialize ERROR message from CBOR
// Format: [8, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri]
inline std::expected<ErrorMessage, std::error_code>
deserialize_error(const std::vector<uint8_t>& cbor_data) {
    return deserialize_message<ErrorMessage>(
        cbor_data, 5, MessageType::ERROR, "ERROR",
        [](const json& j) {
            return ErrorMessage{
                static_cast<MessageType>(j[1].get<int>()),
                j[2].get<uint64_t>(),
                WampDict{},
                j[4].get<std::string>()
            };
        });
}

} // namespace wamp
