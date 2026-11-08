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
#include <algorithm>
#include <concepts>
#include <map>
#include <set>
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

// ============================================================================
// Direct CBOR codec
// ============================================================================
// Every message is read into and written from the WAMP structs by cbor::Reader / cbor::Writer, with no
// intermediate tree.

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

// Details "roles": {name: {}} with names in sorted order
inline void write_roles(cbor::Writer& w, const std::vector<Role>& roles) {
    w.write_text("roles");
    std::set<std::string> names;
    for (const auto& role : roles) names.insert(role.name);
    w.write_map(names.size());
    for (const auto& name : names) {
        w.write_text(name);
        w.write_empty_map();  // features
    }
}

inline std::vector<Role> read_roles(cbor::Reader& r) {
    std::vector<Role> roles;
    auto c = r.read_map();
    while (r.next(c)) {
        roles.push_back(Role{r.read_text(), {}});
        r.skip();  // features
    }
    return roles;
}

inline void write_string_map(cbor::Writer& w, const std::map<std::string, std::string>& map) {
    w.write_map(map.size());
    for (const auto& [key, value] : map) {  // std::map is already key-ordered
        w.write_text(key);
        w.write_text(value);
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

    // A required map element of text values (other values are dropped)
    std::map<std::string, std::string> string_map() {
        std::map<std::string, std::string> result;
        map([&result](const std::string& key, cbor::Reader& r) {
            if (r.peek_major() == cbor::Major::TEXT) result[key] = r.read_text();
            else r.skip();
        });
        return result;
    }

    // A required map element: calls fn(key, reader) for each entry, fn must consume the value.
    // A non-map element is skipped.
    template<std::invocable<std::string&, cbor::Reader&> Fn>
    void map(Fn&& fn) {
        require();
        if (r_.peek_major() != cbor::Major::MAP) {
            r_.skip();
            return;
        }
        auto c = r_.read_map();
        while (r_.next(c)) {
            std::string key = r_.read_text();
            fn(key, r_);
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

// Reads the fields of one message type in wire order and builds the message
template<typename E, typename T>
concept FieldExtractor = requires(E&& extract, Fields& fields) {
    { std::forward<E>(extract)(fields) } -> std::convertible_to<T>;
};

// Decodes [type, ...fields] into T. `extract` reads the fields in wire order from a Fields.
template<typename T, FieldExtractor<T> Extractor>
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

// Serialize HELLO message to CBOR
// Format: [1, realm, details]
inline std::vector<uint8_t> serialize_hello(const HelloMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::HELLO, 3);
    w.write_text(msg.realm);

    // Details, keys in order: authid, authmethods, roles
    const bool has_methods = msg.authmethods.has_value() && !msg.authmethods->empty();
    w.write_map(1 + (msg.authid ? 1 : 0) + (has_methods ? 1 : 0));
    if (msg.authid) {
        w.write_text("authid");
        w.write_text(*msg.authid);
    }
    if (has_methods) {
        w.write_text("authmethods");
        w.write_array(msg.authmethods->size());
        for (const auto& method : *msg.authmethods) w.write_text(method);
    }
    fast::write_roles(w, msg.roles);
    return out;
}

// Serialize WELCOME message to CBOR
// Format: [2, session_id, details]
inline std::vector<uint8_t> serialize_welcome(const WelcomeMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::WELCOME, 3);
    w.write_uint(msg.session_id);

    // Details, keys in order: authid, authmethod, authrole, roles
    w.write_map(1 + (msg.authid ? 1 : 0) + (msg.authmethod ? 1 : 0) + (msg.authrole ? 1 : 0));
    if (msg.authid) {
        w.write_text("authid");
        w.write_text(*msg.authid);
    }
    if (msg.authmethod) {
        w.write_text("authmethod");
        w.write_text(*msg.authmethod);
    }
    if (msg.authrole) {
        w.write_text("authrole");
        w.write_text(*msg.authrole);
    }
    fast::write_roles(w, msg.roles);
    return out;
}

// Serialize GOODBYE message to CBOR
// Format: [6, details, reason]
inline std::vector<uint8_t> serialize_goodbye(const GoodbyeMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::GOODBYE, 3);
    w.write_empty_map();  // details
    w.write_text(msg.reason);
    return out;
}

// Serialize ABORT message to CBOR
// Format: [3, details, reason]
inline std::vector<uint8_t> serialize_abort(const AbortMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::ABORT, 3);
    w.write_empty_map();  // details
    w.write_text(msg.reason);
    return out;
}

// Serialize CHALLENGE message to CBOR
// Format: [4, authmethod, extra]
inline std::vector<uint8_t> serialize_challenge(const ChallengeMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::CHALLENGE, 3);
    w.write_text(msg.authmethod);
    fast::write_string_map(w, msg.extra);
    return out;
}

// Serialize AUTHENTICATE message to CBOR
// Format: [5, signature, extra]
inline std::vector<uint8_t> serialize_authenticate(const AuthenticateMessage& msg) {
    std::vector<uint8_t> out;
    auto w = fast::begin(out, MessageType::AUTHENTICATE, 3);
    w.write_text(msg.signature);
    fast::write_string_map(w, msg.extra);
    return out;
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
    return fast::decode<HelloMessage>(cbor_data, MessageType::HELLO, 3, "HELLO", [](fast::Fields& f) {
        HelloMessage msg{f.text()};
        f.map([&msg](const std::string& key, cbor::Reader& r) {
            if (key == "roles" && r.peek_major() == cbor::Major::MAP) {
                msg.roles = fast::read_roles(r);
            } else if (key == "authmethods" && r.peek_major() == cbor::Major::ARRAY) {
                std::vector<std::string> methods;
                auto c = r.read_array();
                while (r.next(c)) {
                    if (r.peek_major() == cbor::Major::TEXT) methods.push_back(r.read_text());
                    else r.skip();
                }
                if (!methods.empty()) msg.authmethods = std::move(methods);
            } else if (key == "authid" && r.peek_major() == cbor::Major::TEXT) {
                msg.authid = r.read_text();
            } else {
                r.skip();
            }
        });
        return msg;
    });
}

// Deserialize WELCOME message from CBOR
// Format: [2, session_id, details]
inline std::expected<WelcomeMessage, std::error_code>
deserialize_welcome(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<WelcomeMessage>(cbor_data, MessageType::WELCOME, 3, "WELCOME", [](fast::Fields& f) {
        WelcomeMessage msg{f.uint64(), ""};
        f.map([&msg](const std::string& key, cbor::Reader& r) {
            const bool is_text = r.peek_major() == cbor::Major::TEXT;
            if (key == "roles" && r.peek_major() == cbor::Major::MAP) {
                msg.roles = fast::read_roles(r);
            } else if (key == "authid" && is_text) {
                msg.authid = r.read_text();
            } else if (key == "authrole" && is_text) {
                msg.authrole = r.read_text();
            } else if (key == "authmethod" && is_text) {
                msg.authmethod = r.read_text();
            } else {
                r.skip();
            }
        });
        return msg;
    });
}

// Deserialize GOODBYE message from CBOR
// Format: [6, details, reason]
inline std::expected<GoodbyeMessage, std::error_code>
deserialize_goodbye(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<GoodbyeMessage>(cbor_data, MessageType::GOODBYE, 3, "GOODBYE", [](fast::Fields& f) {
        f.skip();  // details
        return GoodbyeMessage{WampDict{}, f.text()};
    });
}

// Deserialize ABORT message from CBOR
// Format: [3, details, reason]
inline std::expected<AbortMessage, std::error_code>
deserialize_abort(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<AbortMessage>(cbor_data, MessageType::ABORT, 3, "ABORT", [](fast::Fields& f) {
        f.skip();  // details
        return AbortMessage{WampDict{}, f.text()};
    });
}

// Deserialize CHALLENGE message from CBOR
// Format: [4, authmethod, extra]
inline std::expected<ChallengeMessage, std::error_code>
deserialize_challenge(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<ChallengeMessage>(cbor_data, MessageType::CHALLENGE, 3, "CHALLENGE", [](fast::Fields& f) {
        auto authmethod = f.text();
        return ChallengeMessage{std::move(authmethod), f.string_map()};
    });
}

// Deserialize AUTHENTICATE message from CBOR
// Format: [5, signature, extra]
inline std::expected<AuthenticateMessage, std::error_code>
deserialize_authenticate(const std::vector<uint8_t>& cbor_data) {
    return fast::decode<AuthenticateMessage>(cbor_data, MessageType::AUTHENTICATE, 3, "AUTHENTICATE", [](fast::Fields& f) {
        auto signature = f.text();
        return AuthenticateMessage{std::move(signature), f.string_map()};
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
