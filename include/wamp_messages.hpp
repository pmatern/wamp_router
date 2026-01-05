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

#include <string>
#include <unordered_map>
#include <map>
#include <cstdint>
#include <vector>
#include <variant>
#include <optional>
#include <system_error>

namespace wamp {

// WAMP message type codes (from WAMP spec)
enum class MessageType : uint8_t {
    HELLO = 1,
    WELCOME = 2,
    ABORT = 3,
    CHALLENGE = 4,
    AUTHENTICATE = 5,
    GOODBYE = 6,
    ERROR = 8,
    PUBLISH = 16,
    PUBLISHED = 17,
    SUBSCRIBE = 32,
    SUBSCRIBED = 33,
    UNSUBSCRIBE = 34,
    UNSUBSCRIBED = 35,
    EVENT = 36,
    CALL = 48,
    RESULT = 50,
    REGISTER = 64,
    REGISTERED = 65,
    UNREGISTER = 66,
    UNREGISTERED = 67,
    INVOCATION = 68,
    YIELD = 70
};

// WAMP protocol error codes
enum class WampError {
    INVALID_MESSAGE = 1,
    PROTOCOL_VIOLATION = 2,
    NOT_AUTHORIZED = 3,
    INVALID_STATE = 4,
    SERIALIZATION_ERROR = 5
};

// Error category for WAMP errors
class WampErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override {
        return "wamp";
    }

    [[nodiscard]] std::string message(int ev) const override {
        switch (static_cast<WampError>(ev)) {
            case WampError::INVALID_MESSAGE:
                return "Invalid WAMP message";
            case WampError::PROTOCOL_VIOLATION:
                return "WAMP protocol violation";
            case WampError::NOT_AUTHORIZED:
                return "Not authorized";
            case WampError::INVALID_STATE:
                return "Invalid state for operation";
            case WampError::SERIALIZATION_ERROR:
                return "Serialization error";
            default:
                return "Unknown WAMP error";
        }
    }
};

inline const WampErrorCategory& wamp_error_category() {
    static WampErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(WampError e) {
    return {static_cast<int>(e), wamp_error_category()};
}

} // namespace wamp

// Register wamp::WampError as an error code
template<>
struct std::is_error_code_enum<wamp::WampError> : std::true_type {};

namespace wamp {

// Type aliases for WAMP data structures
using WampDict = std::unordered_map<std::string, std::variant<
    std::string,
    int64_t,
    bool,
    std::unordered_map<std::string, std::string>  // Nested dict for roles
>>;

using WampList = std::vector<std::variant<std::string, int64_t, bool>>;

// Role types
struct Role {
    std::string name;  // "caller", "callee", "publisher", "subscriber"
    WampDict features; // Optional features for this role
};

// ============================================================================
// HELLO Message: [1, Realm, Details]
// ============================================================================
// Sent by client to initiate WAMP session
struct HelloMessage {
    static constexpr MessageType TYPE = MessageType::HELLO;

    std::string realm;                          // URI of realm to join
    std::vector<Role> roles;                    // Client roles
    std::optional<std::vector<std::string>> authmethods;  // Supported auth methods
    std::optional<std::string> authid;          // Authentication ID

    explicit HelloMessage(std::string realm_uri)
        : realm(std::move(realm_uri))
    {}

    static HelloMessage create_client(const std::string& realm_uri) {
        HelloMessage msg{realm_uri};

        // Add basic client roles
        msg.roles.push_back(Role{"caller", {}});
        msg.roles.push_back(Role{"callee", {}});
        msg.roles.push_back(Role{"publisher", {}});
        msg.roles.push_back(Role{"subscriber", {}});

        return msg;
    }

    [[nodiscard]] WampDict to_details() const {
        WampDict details;

        std::unordered_map<std::string, std::string> roles_dict;
        for (const auto& role : roles) {
            roles_dict[role.name] = "{}";  // Empty features for now
        }
        details["roles"] = roles_dict;

        if (authmethods.has_value() && !authmethods->empty()) {
            // Note: This is simplified - real implementation needs proper variant handling
            details["authmethods"] = authmethods->front();
        }

        if (authid.has_value()) {
            details["authid"] = *authid;
        }

        return details;
    }
};

// ============================================================================
// WELCOME Message: [2, Session, Details]
// ============================================================================
// Sent by router in response to HELLO
struct WelcomeMessage {
    static constexpr MessageType TYPE = MessageType::WELCOME;

    uint64_t session_id;                        // Assigned session ID
    std::string realm;                          // Realm joined
    std::vector<Role> roles;                    // Router roles
    std::optional<std::string> authid;          // Authenticated identity
    std::optional<std::string> authrole;        // Authenticated role
    std::optional<std::string> authmethod;      // Auth method used

    explicit WelcomeMessage(uint64_t sid, std::string realm_name)
        : session_id(sid)
        , realm(std::move(realm_name))
    {}

    static WelcomeMessage create_router(uint64_t session_id, const std::string& realm_uri) {
        WelcomeMessage msg{session_id, realm_uri};

        // Add basic router roles
        msg.roles.push_back(Role{"broker", {}});
        msg.roles.push_back(Role{"dealer", {}});

        return msg;
    }

    [[nodiscard]] WampDict to_details() const {
        WampDict details;

        std::unordered_map<std::string, std::string> roles_dict;
        for (const auto& role : roles) {
            roles_dict[role.name] = "{}";  // Empty features for now
        }
        details["roles"] = roles_dict;

        if (authid.has_value()) {
            details["authid"] = *authid;
        }

        if (authrole.has_value()) {
            details["authrole"] = *authrole;
        }

        if (authmethod.has_value()) {
            details["authmethod"] = *authmethod;
        }

        return details;
    }
};

// ============================================================================
// GOODBYE Message: [6, Details, Reason]
// ============================================================================
// Sent by either peer to close session gracefully
struct GoodbyeMessage {
    static constexpr MessageType TYPE = MessageType::GOODBYE;

    WampDict details{};
    std::string reason{};  // URI like "wamp.close.normal"

    GoodbyeMessage(WampDict details_dict, std::string reason_uri)
        : details(std::move(details_dict))
        , reason(std::move(reason_uri))
    {}

    static GoodbyeMessage create_normal() {
        WampDict details{};
        return GoodbyeMessage{details, "wamp.close.normal"};
    }

    static GoodbyeMessage create_system_shutdown() {
        WampDict details{};
        return GoodbyeMessage{details, "wamp.close.system_shutdown"};
    }
};

// ============================================================================
// ABORT Message: [3, Details, Reason]
// ============================================================================
// Sent during session establishment to abort connection
struct AbortMessage {
    static constexpr MessageType TYPE = MessageType::ABORT;

    WampDict details{};
    std::string reason{};  // URI like "wamp.error.not_authorized"

    AbortMessage(WampDict details_dict, std::string reason_uri)
        : details(std::move(details_dict))
        , reason(std::move(reason_uri))
    {}

    static AbortMessage create_not_authorized(const std::string& message = "") {
        WampDict details{};
        if (!message.empty()) {
            details["message"] = message;
        }
        return AbortMessage{details, "wamp.error.not_authorized"};
    }

    static AbortMessage create_no_such_realm(const std::string& realm) {
        WampDict details{};
        details["message"] = "Realm does not exist: " + realm;
        return AbortMessage{details, "wamp.error.no_such_realm"};
    }
};

// ============================================================================
// CHALLENGE Message: [4, AuthMethod, Extra]
// ============================================================================
// Sent by router during authentication to challenge the client
struct ChallengeMessage {
    static constexpr MessageType TYPE = MessageType::CHALLENGE;

    std::string authmethod{};  // e.g., "cryptosign"
    std::map<std::string, std::string> extra{};  // Challenge data

    ChallengeMessage(std::string auth_method, std::map<std::string, std::string> extra_data)
        : authmethod(std::move(auth_method))
        , extra(std::move(extra_data))
    {}

    static ChallengeMessage create_cryptosign(const std::string& challenge_hex) {
        std::map<std::string, std::string> extra;
        extra["challenge"] = challenge_hex;
        return ChallengeMessage{"cryptosign", extra};
    }
};

// ============================================================================
// AUTHENTICATE Message: [5, Signature, Extra]
// ============================================================================
// Sent by client in response to CHALLENGE
struct AuthenticateMessage {
    static constexpr MessageType TYPE = MessageType::AUTHENTICATE;

    std::string signature;  // Signature/response to challenge
    std::map<std::string, std::string> extra;  // Optional extra data

    AuthenticateMessage(std::string sig, std::map<std::string, std::string> extra_data)
        : signature(std::move(sig))
        , extra(std::move(extra_data))
    {}

    explicit AuthenticateMessage(std::string sig)
        : signature(std::move(sig))
        , extra{}
    {}
};

// ============================================================================
// SUBSCRIBE Message: [32, Request|id, Options|dict, Topic|uri]
// ============================================================================
// Client subscribes to a topic
struct SubscribeMessage {
    static constexpr MessageType TYPE = MessageType::SUBSCRIBE;

    uint64_t request_id{};
    WampDict options{};
    std::string topic{};  // URI

    SubscribeMessage(uint64_t req_id, WampDict opts, std::string topic_uri)
        : request_id(req_id)
        , options(std::move(opts))
        , topic(std::move(topic_uri))
    {}
};

// ============================================================================
// SUBSCRIBED Message: [33, SUBSCRIBE.Request|id, Subscription|id]
// ============================================================================
// Router confirms subscription
struct SubscribedMessage {
    static constexpr MessageType TYPE = MessageType::SUBSCRIBED;

    uint64_t request_id{};
    uint64_t subscription_id{};

    SubscribedMessage(uint64_t req_id, uint64_t sub_id)
        : request_id(req_id)
        , subscription_id(sub_id)
    {}
};

// ============================================================================
// PUBLISH Message: [16, Request|id, Options|dict, Topic|uri]
// ============================================================================
// Client publishes an event to a topic
struct PublishMessage {
    static constexpr MessageType TYPE = MessageType::PUBLISH;

    uint64_t request_id{};
    WampDict options{};
    std::string topic{};  // URI

    PublishMessage(uint64_t req_id, WampDict opts, std::string topic_uri)
        : request_id(req_id)
        , options(std::move(opts))
        , topic(std::move(topic_uri))
    {}
};

// ============================================================================
// PUBLISHED Message: [17, PUBLISH.Request|id, Publication|id]
// ============================================================================
// Router confirms publication
struct PublishedMessage {
    static constexpr MessageType TYPE = MessageType::PUBLISHED;

    uint64_t request_id{};
    uint64_t publication_id{};

    PublishedMessage(uint64_t req_id, uint64_t pub_id)
        : request_id(req_id)
        , publication_id(pub_id)
    {}
};

// ============================================================================
// EVENT Message: [36, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict]
// ============================================================================
// Router sends event to subscriber
struct EventMessage {
    static constexpr MessageType TYPE = MessageType::EVENT;

    uint64_t subscription_id{};
    uint64_t publication_id{};
    WampDict details{};

    EventMessage(uint64_t sub_id, uint64_t pub_id, WampDict details_dict)
        : subscription_id(sub_id)
        , publication_id(pub_id)
        , details(std::move(details_dict))
    {}
};

// ============================================================================
// REGISTER Message: [64, Request|id, Options|dict, Procedure|uri]
// ============================================================================
// Client registers a procedure that can be called by other clients
struct RegisterMessage {
    static constexpr MessageType TYPE = MessageType::REGISTER;

    uint64_t request_id{};
    WampDict options{};
    std::string procedure{};  // URI

    RegisterMessage(uint64_t req_id, WampDict opts, std::string procedure_uri)
        : request_id(req_id)
        , options(std::move(opts))
        , procedure(std::move(procedure_uri))
    {}
};

// ============================================================================
// REGISTERED Message: [65, REGISTER.Request|id, Registration|id]
// ============================================================================
// Router confirms registration
struct RegisteredMessage {
    static constexpr MessageType TYPE = MessageType::REGISTERED;

    uint64_t request_id{};
    uint64_t registration_id{};

    RegisteredMessage(uint64_t req_id, uint64_t reg_id)
        : request_id(req_id)
        , registration_id(reg_id)
    {}
};

// ============================================================================
// CALL Message: [48, Request|id, Options|dict, Procedure|uri]
// ============================================================================
// Client calls a remote procedure
struct CallMessage {
    static constexpr MessageType TYPE = MessageType::CALL;

    uint64_t request_id{};
    WampDict options{};
    std::string procedure{};  // URI

    CallMessage(uint64_t req_id, WampDict opts, std::string procedure_uri)
        : request_id(req_id)
        , options(std::move(opts))
        , procedure(std::move(procedure_uri))
    {}
};

// ============================================================================
// INVOCATION Message: [68, Request|id, Registration|id, Details|dict]
// ============================================================================
// Router invokes a procedure on the callee
struct InvocationMessage {
    static constexpr MessageType TYPE = MessageType::INVOCATION;

    uint64_t request_id{};      // Generated by router for this invocation
    uint64_t registration_id{}; // Which registration to invoke
    WampDict details{};

    InvocationMessage(uint64_t req_id, uint64_t reg_id, WampDict details_dict)
        : request_id(req_id)
        , registration_id(reg_id)
        , details(std::move(details_dict))
    {}
};

// ============================================================================
// YIELD Message: [70, INVOCATION.Request|id, Options|dict]
// ============================================================================
// Callee sends result back to router (in response to INVOCATION)
struct YieldMessage {
    static constexpr MessageType TYPE = MessageType::YIELD;

    uint64_t invocation_id{};  // Request ID from the INVOCATION message
    WampDict options{};
    WampList arguments{};       // Positional result arguments (optional)
    WampDict arguments_kw{};    // Keyword result arguments (optional)

    YieldMessage(uint64_t inv_id, WampDict opts, WampList args = {}, WampDict args_kw = {})
        : invocation_id(inv_id)
        , options(std::move(opts))
        , arguments(std::move(args))
        , arguments_kw(std::move(args_kw))
    {}
};

// ============================================================================
// RESULT Message: [50, CALL.Request|id, Details|dict]
// ============================================================================
// Router sends call result back to caller
struct ResultMessage {
    static constexpr MessageType TYPE = MessageType::RESULT;

    uint64_t request_id{};  // Request ID from the original CALL message
    WampDict details{};
    WampList arguments{};       // Positional result arguments (optional)
    WampDict arguments_kw{};    // Keyword result arguments (optional)

    ResultMessage(uint64_t req_id, WampDict details_dict, WampList args = {}, WampDict args_kw = {})
        : request_id(req_id)
        , details(std::move(details_dict))
        , arguments(std::move(args))
        , arguments_kw(std::move(args_kw))
    {}
};

// ============================================================================
// ERROR Message: [8, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri]
// ============================================================================
// Generic error response for failed requests
struct ErrorMessage {
    static constexpr MessageType TYPE = MessageType::ERROR;

    MessageType request_type{};  // Type of message that caused the error (e.g., CALL, REGISTER)
    uint64_t request_id{};       // Request ID from the failed request
    WampDict details{};
    std::string error_uri{};     // Error URI like "wamp.error.procedure_already_exists"

    ErrorMessage(MessageType req_type, uint64_t req_id, WampDict details_dict, std::string error)
        : request_type(req_type)
        , request_id(req_id)
        , details(std::move(details_dict))
        , error_uri(std::move(error))
    {}

    static ErrorMessage create_procedure_already_exists(uint64_t request_id, const std::string& procedure) {
        WampDict details;
        details["message"] = "Procedure already registered: " + procedure;
        return ErrorMessage{MessageType::REGISTER, request_id, details, "wamp.error.procedure_already_exists"};
    }

    static ErrorMessage create_no_such_procedure(uint64_t request_id, const std::string& procedure) {
        WampDict details;
        details["message"] = "No such procedure: " + procedure;
        return ErrorMessage{MessageType::CALL, request_id, details, "wamp.error.no_such_procedure"};
    }

    static ErrorMessage create_callee_failure(uint64_t request_id, const std::string& reason) {
        WampDict details;
        details["message"] = reason;
        return ErrorMessage{MessageType::CALL, request_id, details, "wamp.error.callee_failure"};
    }
};

// ============================================================================
// Message Union Type
// ============================================================================
using WampMessage = std::variant<
    HelloMessage,
    WelcomeMessage,
    GoodbyeMessage,
    AbortMessage,
    SubscribeMessage,
    SubscribedMessage,
    PublishMessage,
    PublishedMessage,
    EventMessage,
    RegisterMessage,
    RegisteredMessage,
    CallMessage,
    InvocationMessage,
    YieldMessage,
    ResultMessage,
    ErrorMessage
>;

inline MessageType get_message_type(const WampMessage& msg) {
    return std::visit([](const auto& m) { return m.TYPE; }, msg);
}

} // namespace wamp
