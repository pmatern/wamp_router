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
#include "raw_socket.hpp"
#include "cbor.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <stdexcept>
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
// Direct CBOR codec for the hot-path messages
// ============================================================================
// Everything between a socket and a handler (SUBSCRIBE ... INTERRUPT) is read into and written from the WAMP
// structs by cbor::Reader / cbor::Writer, with no nlohmann::json tree. HELLO, WELCOME, GOODBYE, ABORT,
// CHALLENGE and AUTHENTICATE (once per session) still use the JSON-based code below.

namespace fast {

inline void write_list(cbor::Writer& w, const WampList& list) {
    w.write_array(list.size());
    for (const auto& item : list) {
        std::visit([&w]<typename T>(const T& v) {
            if constexpr (std::is_same_v<T, std::string>) w.write_text(v);
            else if constexpr (std::is_same_v<T, bool>) w.write_bool(v);
            else w.write_int(v);
        }, item);
    }
}

inline void write_dict_value(cbor::Writer& w, const WampDict::mapped_type& value) {
    std::visit([&w]<typename T>(const T& v) {
        if constexpr (std::is_same_v<T, std::string>) {
            w.write_text(v);
        } else if constexpr (std::is_same_v<T, bool>) {
            w.write_bool(v);
        } else if constexpr (std::is_same_v<T, int64_t>) {
            w.write_int(v);
        } else {  // nested string map
            w.write_map(v.size());
            for (const auto& [k, nested] : v) {
                w.write_text(k);
                w.write_text(nested);
            }
        }
    }, value);
}

// Entries are written in key order, so the bytes do not depend on unordered_map's iteration order
inline void write_dict(cbor::Writer& w, const WampDict& dict) {
    w.write_map(dict.size());
    if (dict.size() <= 1) {
        for (const auto& [key, value] : dict) {
            w.write_text(key);
            write_dict_value(w, value);
        }
        return;
    }
    std::vector<const WampDict::value_type*> entries;
    entries.reserve(dict.size());
    for (const auto& entry : dict) entries.push_back(&entry);
    std::sort(entries.begin(), entries.end(), [](const auto* a, const auto* b) { return a->first < b->first; });
    for (const auto* entry : entries) {
        w.write_text(entry->first);
        write_dict_value(w, entry->second);
    }
}

// Number of elements append_payload would add: nothing, [args], or [args, kw]
inline uint64_t payload_elements(const WampList& args, const WampDict& args_kw) {
    if (args.empty() && args_kw.empty()) return 0;
    return args_kw.empty() ? 1 : 2;
}

inline void write_payload(cbor::Writer& w, const WampList& args, const WampDict& args_kw) {
    if (args.empty() && args_kw.empty()) return;
    write_list(w, args);
    if (!args_kw.empty()) write_dict(w, args_kw);
}

// Elements that are not string/integer/boolean (null, nested containers) are dropped, as before
inline WampList read_list(cbor::Reader& r) {
    WampList list;
    auto c = r.read_array();
    while (r.next(c)) {
        switch (r.peek_major()) {
            case cbor::Major::TEXT: list.emplace_back(r.read_text()); break;
            case cbor::Major::UNSIGNED:
            case cbor::Major::NEGATIVE: list.emplace_back(r.read_int()); break;
            default:
                if (r.peek_is_bool()) list.emplace_back(r.read_bool());
                else if (r.peek_is_number()) list.emplace_back(r.read_int());
                else r.skip();
        }
    }
    return list;
}

// Values that are not string/integer/boolean/map are dropped; nested maps keep their string values
inline WampDict read_dict(cbor::Reader& r) {
    WampDict dict;
    auto c = r.read_map();
    while (r.next(c)) {
        std::string key = r.read_text();
        switch (r.peek_major()) {
            case cbor::Major::TEXT: dict.insert_or_assign(std::move(key), r.read_text()); break;
            case cbor::Major::UNSIGNED:
            case cbor::Major::NEGATIVE: dict.insert_or_assign(std::move(key), r.read_int()); break;
            case cbor::Major::MAP: {
                std::unordered_map<std::string, std::string> nested;
                auto nc = r.read_map();
                while (r.next(nc)) {
                    std::string nk = r.read_text();
                    if (r.peek_major() == cbor::Major::TEXT) nested[std::move(nk)] = r.read_text();
                    else r.skip();
                }
                dict.insert_or_assign(std::move(key), std::move(nested));
                break;
            }
            default:
                if (r.peek_is_bool()) dict.insert_or_assign(std::move(key), r.read_bool());
                else if (r.peek_is_number()) dict.insert_or_assign(std::move(key), r.read_int());
                else r.skip();
        }
    }
    return dict;
}

// Thrown when a message has fewer elements than its type requires
struct MalformedMessage {};

// Sequential access to the elements after the message type
class Fields {
public:
    Fields(cbor::Reader& r, cbor::Container& c) : r_(r), c_(c) {}

    [[nodiscard]] bool more() { return r_.next(c_); }

    uint64_t uint64() { require(); return r_.read_uint(); }
    int64_t int64() { require(); return r_.read_int(); }
    std::string text() { require(); return r_.read_text(); }
    void skip() { require(); r_.skip(); }

    // A Details/Options dict; empty if the element is absent or not a map
    WampDict dict() {
        if (!more()) return {};
        return r_.peek_major() == cbor::Major::MAP ? read_dict(r_) : (r_.skip(), WampDict{});
    }

    // Optional Arguments|list and ArgumentsKw|dict
    void payload(WampList& args, WampDict& args_kw) {
        if (more()) {
            if (r_.peek_major() == cbor::Major::ARRAY) args = read_list(r_); else r_.skip();
        } else {
            return;
        }
        if (more()) {
            if (r_.peek_major() == cbor::Major::MAP) args_kw = read_dict(r_); else r_.skip();
        }
    }

    cbor::Reader& reader() { return r_; }

private:
    void require() {
        if (!r_.next(c_)) throw MalformedMessage{};
    }

    cbor::Reader& r_;
    cbor::Container& c_;
};

// Decodes [type, ...fields] into T. `extract` reads the fields in wire order from a Fields.
template<typename T, typename Extractor>
std::expected<T, std::error_code>
decode(const std::vector<uint8_t>& data, MessageType expected_type, size_t min_size,
       std::string_view msg_name, Extractor&& extract) {
    try {
        cbor::Reader r{data};
        if (r.at_end() || r.peek_major() != cbor::Major::ARRAY) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }
        auto c = r.read_array();
        if (!c.indefinite && c.remaining < min_size) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }
        if (!r.next(c)) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }
        if (r.read_int() != static_cast<int64_t>(expected_type)) {
            return std::unexpected(make_error_code(SerializationError::INVALID_MESSAGE_TYPE));
        }
        Fields fields{r, c};
        return extract(fields);
    } catch (const MalformedMessage&) {
        return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
    } catch (const cbor::DecodeError& e) {
        spdlog::error("Failed to deserialize {}: {}", msg_name, e.what());
        return std::unexpected{make_error_code(SerializationError::CBOR_DECODE_ERROR)};
    }
}

// Starts a message: array header for `elements` items, then the type
inline cbor::Writer begin(std::vector<uint8_t>& out, MessageType type, uint64_t elements) {
    cbor::Writer w{out};
    w.write_array(elements);
    w.write_uint(static_cast<uint64_t>(type));
    return w;
}

}  // namespace fast

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

// Append optional Arguments|list / ArgumentsKw|dict to a message array.
// Per spec, ArgumentsKw requires an Arguments list (possibly empty) before it.
inline void append_payload(json& j, const WampList& args, const WampDict& args_kw) {
    if (args.empty() && args_kw.empty()) {
        return;
    }
    j.push_back(serialize_list(args));
    if (!args_kw.empty()) {
        j.push_back(serialize_dict(args_kw));
    }
}

// Read optional Arguments|list / ArgumentsKw|dict starting at index `pos`.
inline void extract_payload(const json& j, size_t pos, WampList& args, WampDict& args_kw) {
    if (j.size() > pos && j[pos].is_array()) {
        args = deserialize_list(j[pos]);
    }
    if (j.size() > pos + 1 && j[pos + 1].is_object()) {
        args_kw = deserialize_dict(j[pos + 1]);
    }
}

// Read a Details/Options dict at index `pos` (empty if absent or not an object).
inline WampDict extract_dict(const json& j, size_t pos) {
    if (j.size() > pos && j[pos].is_object()) {
        return deserialize_dict(j[pos]);
    }
    return {};
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
        cbor::Reader r{cbor_data};
        if (r.at_end() || r.peek_major() != cbor::Major::ARRAY) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }
        auto c = r.read_array();
        if (!r.next(c)) {
            return std::unexpected(make_error_code(SerializationError::MALFORMED_MESSAGE));
        }
        return static_cast<MessageType>(r.read_int());
    } catch (const cbor::DecodeError& e) {
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
    std::vector<uint8_t> out;
    out.reserve(16 + msg.topic.size());
    auto w = fast::begin(out, MessageType::SUBSCRIBE, 4);
    w.write_uint(msg.request_id);
    w.write_empty_map();  // options
    w.write_text(msg.topic);
    return out;
}

// Serialize SUBSCRIBED message to CBOR
// Format: [33, SUBSCRIBE.Request|id, Subscription|id]
inline std::vector<uint8_t> serialize_subscribed(const SubscribedMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::SUBSCRIBED, 3);
    w.write_uint(msg.request_id);
    w.write_uint(msg.subscription_id);
    return out;
}

// Deserialize SUBSCRIBE message from CBOR
// Format: [32, Request|id, Options|dict, Topic|uri]
inline std::expected<SubscribeMessage, std::error_code>
deserialize_subscribe(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<SubscribeMessage>(cbor_data, MessageType::SUBSCRIBE, 4, "SUBSCRIBE", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        f.skip();  // options
        return SubscribeMessage{request_id, WampDict{}, f.text()};
    });
}

// Serialize PUBLISHED message to CBOR
// Format: [17, PUBLISH.Request|id, Publication|id]
inline std::vector<uint8_t> serialize_published(const PublishedMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::PUBLISHED, 3);
    w.write_uint(msg.request_id);
    w.write_uint(msg.publication_id);
    return out;
}

// Serialize EVENT message to CBOR
// Format: [36, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict]
inline std::vector<uint8_t> serialize_event(const EventMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(64);
    auto w = fast::begin(out, MessageType::EVENT, 4 + fast::payload_elements(msg.arguments, msg.arguments_kw));
    w.write_uint(msg.subscription_id);
    w.write_uint(msg.publication_id);
    w.write_empty_map();  // details
    fast::write_payload(w, msg.arguments, msg.arguments_kw);
    return out;
}

// Deserialize PUBLISH message from CBOR
// Format: [16, Request|id, Options|dict, Topic|uri, Arguments|list, ArgumentsKw|dict]
inline std::expected<PublishMessage, std::error_code>
deserialize_publish(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<PublishMessage>(cbor_data, MessageType::PUBLISH, 4, "PUBLISH", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        // Only the boolean options the router acts on are kept
        WampDict options;
        if (!f.more()) throw fast::MalformedMessage{};
        auto& r = f.reader();
        if (r.peek_major() == cbor::Major::MAP) {
            auto c = r.read_map();
            while (r.next(c)) {
                const std::string key = r.read_text();
                if ((key == "acknowledge" || key == "exclude_me") && r.peek_is_bool()) {
                    options[key] = r.read_bool();
                } else {
                    r.skip();
                }
            }
        } else {
            r.skip();
        }
        std::string topic = f.text();
        WampList args;
        WampDict args_kw;
        f.payload(args, args_kw);
        return PublishMessage{request_id, std::move(options), std::move(topic), std::move(args), std::move(args_kw)};
    });
}

// Serialize REGISTER message to CBOR
// Format: [64, Request|id, Options|dict, Procedure|uri]
inline std::vector<uint8_t> serialize_register(const RegisterMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(16 + msg.procedure.size());
    auto w = fast::begin(out, MessageType::REGISTER, 4);
    w.write_uint(msg.request_id);
    w.write_empty_map();  // options
    w.write_text(msg.procedure);
    return out;
}

// Serialize REGISTERED message to CBOR
// Format: [65, REGISTER.Request|id, Registration|id]
inline std::vector<uint8_t> serialize_registered(const RegisteredMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::REGISTERED, 3);
    w.write_uint(msg.request_id);
    w.write_uint(msg.registration_id);
    return out;
}

// Deserialize REGISTER message from CBOR
// Format: [64, Request|id, Options|dict, Procedure|uri]
inline std::expected<RegisterMessage, std::error_code>
deserialize_register(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<RegisterMessage>(cbor_data, MessageType::REGISTER, 4, "REGISTER", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        f.skip();  // options
        return RegisterMessage{request_id, WampDict{}, f.text()};
    });
}

// Serialize INVOCATION message to CBOR
// Format: [68, Request|id, Registration|id, Details|dict]
inline std::vector<uint8_t> serialize_invocation(const InvocationMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(64);
    auto w = fast::begin(out, MessageType::INVOCATION, 4 + fast::payload_elements(msg.arguments, msg.arguments_kw));
    w.write_uint(msg.request_id);
    w.write_uint(msg.registration_id);
    w.write_empty_map();  // details
    fast::write_payload(w, msg.arguments, msg.arguments_kw);
    return out;
}

// Deserialize CALL message from CBOR
// Format: [48, Request|id, Options|dict, Procedure|uri, Arguments|list, ArgumentsKw|dict]
inline std::expected<CallMessage, std::error_code>
deserialize_call(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<CallMessage>(cbor_data, MessageType::CALL, 4, "CALL", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        auto options = f.dict();
        auto procedure = f.text();
        WampList args;
        WampDict args_kw;
        f.payload(args, args_kw);
        return CallMessage{request_id, std::move(options), std::move(procedure), std::move(args), std::move(args_kw)};
    });
}

// Serialize RESULT message to CBOR
// Format: [50, CALL.Request|id, Details|dict]
inline std::vector<uint8_t> serialize_result(const ResultMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(64);
    // Arguments are always present (possibly empty); ArgumentsKw only when non-empty
    auto w = fast::begin(out, MessageType::RESULT, 4 + (msg.arguments_kw.empty() ? 0 : 1));
    w.write_uint(msg.request_id);
    w.write_empty_map();  // details
    fast::write_list(w, msg.arguments);
    if (!msg.arguments_kw.empty()) fast::write_dict(w, msg.arguments_kw);
    return out;
}

// Deserialize YIELD message from CBOR
// Format: [70, INVOCATION.Request|id, Options|dict]
// Note: Can optionally have Arguments|list and ArgumentsKw|dict
inline std::expected<YieldMessage, std::error_code>
deserialize_yield(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<YieldMessage>(cbor_data, MessageType::YIELD, 3, "YIELD", [](fast::Fields& f) {
        const auto invocation_id = f.uint64();
        if (f.more()) f.reader().skip();  // options
        WampList arguments;
        WampDict arguments_kw;
        f.payload(arguments, arguments_kw);
        return YieldMessage{invocation_id, WampDict{}, std::move(arguments), std::move(arguments_kw)};
    });
}

// Serialize ERROR message to CBOR
// Format: [8, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri]
inline std::vector<uint8_t> serialize_error(const ErrorMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(64);
    auto w = fast::begin(out, MessageType::ERROR, 5 + fast::payload_elements(msg.arguments, msg.arguments_kw));
    w.write_uint(static_cast<uint64_t>(msg.request_type));
    w.write_uint(msg.request_id);
    fast::write_dict(w, msg.details);
    w.write_text(msg.error_uri);
    fast::write_payload(w, msg.arguments, msg.arguments_kw);
    return out;
}

// Serialize PUBLISH message to CBOR
// Format: [16, Request|id, Options|dict, Topic|uri, Arguments|list, ArgumentsKw|dict]
inline std::vector<uint8_t> serialize_publish(const PublishMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(64 + msg.topic.size());
    auto w = fast::begin(out, MessageType::PUBLISH, 4 + fast::payload_elements(msg.arguments, msg.arguments_kw));
    w.write_uint(msg.request_id);
    fast::write_dict(w, msg.options);
    w.write_text(msg.topic);
    fast::write_payload(w, msg.arguments, msg.arguments_kw);
    return out;
}

// Serialize CALL message to CBOR
// Format: [48, Request|id, Options|dict, Procedure|uri]
inline std::vector<uint8_t> serialize_call(const CallMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(64 + msg.procedure.size());
    auto w = fast::begin(out, MessageType::CALL, 4 + fast::payload_elements(msg.arguments, msg.arguments_kw));
    w.write_uint(msg.request_id);
    fast::write_dict(w, msg.options);
    w.write_text(msg.procedure);
    fast::write_payload(w, msg.arguments, msg.arguments_kw);
    return out;
}

// Serialize YIELD message to CBOR
// Format: [70, INVOCATION.Request|id, Options|dict]
inline std::vector<uint8_t> serialize_yield(const YieldMessage& msg) {
    std::vector<uint8_t> out;
    out.reserve(64);
    auto w = fast::begin(out, MessageType::YIELD, 4 + (msg.arguments_kw.empty() ? 0 : 1));
    w.write_uint(msg.invocation_id);
    w.write_empty_map();  // options
    fast::write_list(w, msg.arguments);
    if (!msg.arguments_kw.empty()) fast::write_dict(w, msg.arguments_kw);
    return out;
}

// Deserialize SUBSCRIBED message from CBOR
// Format: [33, SUBSCRIBE.Request|id, Subscription|id]
inline std::expected<SubscribedMessage, std::error_code>
deserialize_subscribed(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<SubscribedMessage>(cbor_data, MessageType::SUBSCRIBED, 3, "SUBSCRIBED", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        return SubscribedMessage{request_id, f.uint64()};
    });
}

// Deserialize PUBLISHED message from CBOR
// Format: [17, PUBLISH.Request|id, Publication|id]
inline std::expected<PublishedMessage, std::error_code>
deserialize_published(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<PublishedMessage>(cbor_data, MessageType::PUBLISHED, 3, "PUBLISHED", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        return PublishedMessage{request_id, f.uint64()};
    });
}

// Deserialize EVENT message from CBOR
// Format: [36, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict]
inline std::expected<EventMessage, std::error_code>
deserialize_event(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<EventMessage>(cbor_data, MessageType::EVENT, 4, "EVENT", [](fast::Fields& f) {
        const auto subscription_id = f.uint64();
        const auto publication_id = f.uint64();
        auto details = f.dict();
        WampList args;
        WampDict args_kw;
        f.payload(args, args_kw);
        return EventMessage{subscription_id, publication_id, std::move(details), std::move(args), std::move(args_kw)};
    });
}

// Deserialize REGISTERED message from CBOR
// Format: [65, REGISTER.Request|id, Registration|id]
inline std::expected<RegisteredMessage, std::error_code>
deserialize_registered(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<RegisteredMessage>(cbor_data, MessageType::REGISTERED, 3, "REGISTERED", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        return RegisteredMessage{request_id, f.uint64()};
    });
}

// Deserialize INVOCATION message from CBOR
// Format: [68, Request|id, REGISTERED.Registration|id, Details|dict]
inline std::expected<InvocationMessage, std::error_code>
deserialize_invocation(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<InvocationMessage>(cbor_data, MessageType::INVOCATION, 4, "INVOCATION", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        const auto registration_id = f.uint64();
        auto details = f.dict();
        WampList args;
        WampDict args_kw;
        f.payload(args, args_kw);
        return InvocationMessage{request_id, registration_id, std::move(details), std::move(args), std::move(args_kw)};
    });
}

// Deserialize RESULT message from CBOR
// Format: [50, CALL.Request|id, Details|dict, YIELD.Arguments|list, YIELD.ArgumentsKw|dict]
inline std::expected<ResultMessage, std::error_code>
deserialize_result(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<ResultMessage>(cbor_data, MessageType::RESULT, 3, "RESULT", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        if (f.more()) f.reader().skip();  // details
        WampList arguments;
        WampDict arguments_kw;
        f.payload(arguments, arguments_kw);
        return ResultMessage{request_id, WampDict{}, std::move(arguments), std::move(arguments_kw)};
    });
}

// Deserialize ERROR message from CBOR
// Format: [8, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri]
inline std::expected<ErrorMessage, std::error_code>
deserialize_error(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<ErrorMessage>(cbor_data, MessageType::ERROR, 5, "ERROR", [](fast::Fields& f) {
        const auto request_type = static_cast<MessageType>(f.int64());
        const auto request_id = f.uint64();
        auto details = f.dict();
        auto error_uri = f.text();
        WampList args;
        WampDict args_kw;
        f.payload(args, args_kw);
        return ErrorMessage{request_type, request_id, std::move(details), std::move(error_uri),
                            std::move(args), std::move(args_kw)};
    });
}

// ============================================================================
// UNSUBSCRIBE / UNSUBSCRIBED / UNREGISTER / UNREGISTERED
// ============================================================================

// Format: [34, Request|id, SUBSCRIBED.Subscription|id]
inline std::vector<uint8_t> serialize_unsubscribe(const UnsubscribeMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::UNSUBSCRIBE, 3);
    w.write_uint(msg.request_id);
    w.write_uint(msg.subscription_id);
    return out;
}

inline std::expected<UnsubscribeMessage, std::error_code>
deserialize_unsubscribe(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<UnsubscribeMessage>(cbor_data, MessageType::UNSUBSCRIBE, 3, "UNSUBSCRIBE", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        return UnsubscribeMessage{request_id, f.uint64()};
    });
}

// Format: [35, UNSUBSCRIBE.Request|id]
inline std::vector<uint8_t> serialize_unsubscribed(const UnsubscribedMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::UNSUBSCRIBED, 2);
    w.write_uint(msg.request_id);
    return out;
}

inline std::expected<UnsubscribedMessage, std::error_code>
deserialize_unsubscribed(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<UnsubscribedMessage>(cbor_data, MessageType::UNSUBSCRIBED, 2, "UNSUBSCRIBED", [](fast::Fields& f) {
        return UnsubscribedMessage{f.uint64()};
    });
}

// Format: [66, Request|id, REGISTERED.Registration|id]
inline std::vector<uint8_t> serialize_unregister(const UnregisterMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::UNREGISTER, 3);
    w.write_uint(msg.request_id);
    w.write_uint(msg.registration_id);
    return out;
}

inline std::expected<UnregisterMessage, std::error_code>
deserialize_unregister(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<UnregisterMessage>(cbor_data, MessageType::UNREGISTER, 3, "UNREGISTER", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        return UnregisterMessage{request_id, f.uint64()};
    });
}

// Format: [67, UNREGISTER.Request|id]
inline std::vector<uint8_t> serialize_unregistered(const UnregisteredMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::UNREGISTERED, 2);
    w.write_uint(msg.request_id);
    return out;
}

inline std::expected<UnregisteredMessage, std::error_code>
deserialize_unregistered(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<UnregisteredMessage>(cbor_data, MessageType::UNREGISTERED, 2, "UNREGISTERED", [](fast::Fields& f) {
        return UnregisteredMessage{f.uint64()};
    });
}

// Format: [69, INVOCATION.Request|id, Options|dict]
inline std::vector<uint8_t> serialize_interrupt(const InterruptMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::INTERRUPT, 3);
    w.write_uint(msg.request_id);
    fast::write_dict(w, msg.options);
    return out;
}

inline std::expected<InterruptMessage, std::error_code>
deserialize_interrupt(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<InterruptMessage>(cbor_data, MessageType::INTERRUPT, 2, "INTERRUPT", [](fast::Fields& f) {
        const auto request_id = f.uint64();
        return InterruptMessage{request_id, f.dict()};
    });
}

// ============================================================================
// EventTemplate - serialize an EVENT once, stamp the subscription id per subscriber
// ============================================================================
// Only Subscription|id differs between the EVENTs of one publication. The CBOR array
//   [36, Subscription|id, Publication|id, Details|dict, Arguments|list?, ArgumentsKw|dict?]
// is encoded once with a placeholder subscription id (0, a single CBOR byte); frame_for() then
// splices the real id into the shared prefix/suffix and adds the RawSocket header, avoiding a
// full JSON build and CBOR encode per subscriber.
class EventTemplate {
public:
    // msg.subscription_id is ignored
    explicit EventTemplate(const EventMessage& msg) {
        const auto bytes = serialize_event(EventMessage{0, msg.publication_id, msg.details,
                                                         msg.arguments, msg.arguments_kw});
        // [array header][0x18 0x24 = 36][0x00 = placeholder id][rest...]
        constexpr size_t kPrefix = 3;
        if (bytes.size() < kPrefix + 1 || bytes[1] != 0x18 || bytes[2] != static_cast<uint8_t>(MessageType::EVENT) ||
            bytes[kPrefix] != 0x00) {
            throw std::logic_error("unexpected CBOR layout for EVENT template");
        }
        prefix_.assign(bytes.begin(), bytes.begin() + kPrefix);
        suffix_.assign(bytes.begin() + kPrefix + 1, bytes.end());
    }

    // Complete RawSocket frame for one subscriber
    [[nodiscard]] std::vector<uint8_t> frame_for(uint64_t subscription_id) const {
        uint8_t id_bytes[9];
        const size_t id_len = encode_cbor_uint(subscription_id, id_bytes);
        const auto payload_len = static_cast<uint32_t>(prefix_.size() + id_len + suffix_.size());

        std::vector<uint8_t> frame;
        frame.reserve(rawsocket::FRAME_HEADER_SIZE + payload_len);
        const auto header = rawsocket::encode_frame_header(
            {.type = rawsocket::FrameType::REGULAR, .payload_length = payload_len});
        frame.insert(frame.end(), header.begin(), header.end());
        frame.insert(frame.end(), prefix_.begin(), prefix_.end());
        frame.insert(frame.end(), id_bytes, id_bytes + id_len);
        frame.insert(frame.end(), suffix_.begin(), suffix_.end());
        return frame;
    }

private:
    // Shortest-form CBOR unsigned integer (RFC 8949 major type 0); returns bytes written
    static size_t encode_cbor_uint(uint64_t v, uint8_t* out) {
        if (v < 24) {
            out[0] = static_cast<uint8_t>(v);
            return 1;
        }
        const int extra = v <= 0xFF ? 1 : v <= 0xFFFF ? 2 : v <= 0xFFFFFFFF ? 4 : 8;
        out[0] = static_cast<uint8_t>(0x18 + (extra == 1 ? 0 : extra == 2 ? 1 : extra == 4 ? 2 : 3));
        for (int i = 0; i < extra; ++i) {
            out[1 + i] = static_cast<uint8_t>(v >> (8 * (extra - 1 - i)));
        }
        return 1 + static_cast<size_t>(extra);
    }

    std::vector<uint8_t> prefix_;
    std::vector<uint8_t> suffix_;
};

} // namespace wamp
