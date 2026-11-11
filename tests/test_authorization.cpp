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
#include <asio/io_context.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "include/authorizer.hpp"
#include "include/wamp_session.hpp"

using namespace wamp;

// Routing state shared by the sessions and handlers a test builds by hand (one per test file)
static Shard& test_shard() {
    static Shard shard;
    return shard;
}

TEST_CASE("Permissions: exact and prefix rules", "[authz]") {
    Permissions p;
    p.add_rule(Action::PUBLISH, "com.example.events", false);
    p.add_rule(Action::SUBSCRIBE, "com.example.", true);

    SECTION("exact matches only the exact URI") {
        REQUIRE(p.allows(Action::PUBLISH, "com.example.events"));
        REQUIRE_FALSE(p.allows(Action::PUBLISH, "com.example.events.more"));
        REQUIRE_FALSE(p.allows(Action::PUBLISH, "com.example.event"));
    }
    SECTION("prefix matches itself and anything below it") {
        REQUIRE(p.allows(Action::SUBSCRIBE, "com.example."));
        REQUIRE(p.allows(Action::SUBSCRIBE, "com.example.a.b.c"));
        REQUIRE_FALSE(p.allows(Action::SUBSCRIBE, "com.exampl"));
        REQUIRE_FALSE(p.allows(Action::SUBSCRIBE, "org.example.x"));
    }
    SECTION("actions are independent and default is deny") {
        REQUIRE_FALSE(p.allows(Action::CALL, "com.example.events"));
        REQUIRE_FALSE(p.allows(Action::REGISTER, "com.example.x"));
        REQUIRE(p.allows(Action::SUBSCRIBE, "com.example.events"));  // via prefix
        REQUIRE_FALSE(Permissions{}.allows(Action::PUBLISH, "anything"));
    }
}

TEST_CASE("Action names parse", "[authz]") {
    REQUIRE(parse_action("call") == Action::CALL);
    REQUIRE(parse_action("register") == Action::REGISTER);
    REQUIRE(parse_action("publish") == Action::PUBLISH);
    REQUIRE(parse_action("subscribe") == Action::SUBSCRIBE);
    REQUIRE_FALSE(parse_action("Call").has_value());
    REQUIRE_FALSE(parse_action("").has_value());
}

namespace {

struct KeyPair {
    std::string priv_path;
    std::string public_hex;
};

KeyPair make_keypair() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    REQUIRE(ctx != nullptr);
    REQUIRE(EVP_PKEY_keygen_init(ctx) > 0);
    REQUIRE(EVP_PKEY_keygen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);

    size_t len = 32;
    std::vector<uint8_t> pub(len);
    EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len);

    KeyPair kp{"/tmp/wamp_authz_test_key.pem", bytes_to_hex(pub)};
    FILE* f = fopen(kp.priv_path.c_str(), "w");
    REQUIRE(f != nullptr);
    PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    EVP_PKEY_free(pkey);
    return kp;
}

std::vector<uint8_t> payload_of(std::span<const uint8_t> frame) {
    REQUIRE(frame.size() > 4);
    return {frame.begin() + 4, frame.end()};
}

// Authorization config: "alice" is a publisher/subscriber under com.example., may call
// com.example.add and register com.example.add only; "bob" has no role.
ServerConfig authz_config(const std::string& public_hex) {
    ServerConfig config;
    config.port = 8080;
    config.max_pending_invocations = 1000;
    config.auth_keys["alice"] = public_hex;
    config.auth_keys["bob"] = public_hex;
    config.auth_realms["alice"] = {"com.example.realm"};
    config.auth_realms["bob"] = {"com.example.realm"};

    Permissions user;
    user.add_rule(Action::PUBLISH, "com.example.", true);
    user.add_rule(Action::SUBSCRIBE, "com.example.", true);
    user.add_rule(Action::CALL, "com.example.add", false);
    user.add_rule(Action::REGISTER, "com.example.add", false);
    config.roles.emplace("user", std::move(user));
    config.auth_roles["alice"] = "user";
    return config;
}

// Runs the RawSocket handshake and Cryptosign flow; returns the WELCOME
WelcomeMessage establish(WampSession& session, const KeyPair& kp, const std::string& authid,
                         const std::string& realm = "com.example.realm", bool passthru = false) {
    session.on_connect();

    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR});
    REQUIRE(session.process(std::span{handshake.data(), handshake.size()}).has_value());

    HelloMessage hello{realm};
    if (passthru) hello.roles = HelloMessage::create_client(realm).roles;
    hello.authid = authid;
    hello.authmethods = std::vector<std::string>{"cryptosign"};
    auto hello_frame = rawsocket::create_wamp_message(serialize_hello(hello));
    auto challenge_frame = session.process(std::span{hello_frame.data(), hello_frame.size()});
    REQUIRE(challenge_frame.has_value());
    auto challenge = deserialize_challenge(payload_of(*challenge_frame));
    REQUIRE(challenge.has_value());

    auto key = load_ed25519_private_key_pem(kp.priv_path);
    REQUIRE(key.has_value());
    auto sig = sign_challenge(challenge->extra.at("challenge"), key->get());
    REQUIRE(sig.has_value());

    auto auth_frame = rawsocket::create_wamp_message(serialize_authenticate(AuthenticateMessage{*sig}));
    auto welcome_frame = session.process(std::span{auth_frame.data(), auth_frame.size()});
    REQUIRE(welcome_frame.has_value());
    auto welcome = deserialize_welcome(payload_of(*welcome_frame));
    REQUIRE(welcome.has_value());
    return *welcome;
}

// Send a message and return the router's reply payload (empty if none)
std::vector<uint8_t> send(WampSession& session, const std::vector<uint8_t>& cbor) {
    auto frame = rawsocket::create_wamp_message(cbor);
    auto reply = session.process(std::span{frame.data(), frame.size()});
    REQUIRE(reply.has_value());
    if (reply->empty()) return {};
    return payload_of(*reply);
}

void require_not_authorized(const std::vector<uint8_t>& reply, MessageType request_type, uint64_t request_id) {
    auto error = deserialize_error(reply);
    REQUIRE(error.has_value());
    REQUIRE(error->error_uri == "wamp.error.not_authorized");
    REQUIRE(error->request_type == request_type);
    REQUIRE(error->request_id == request_id);
}

}  // namespace

TEST_CASE("Session enforces role permissions", "[authz][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);
    WampSession session{io, config, test_shard()};

    auto welcome = establish(session, kp, "alice");
    REQUIRE(welcome.authrole == "user");

    SECTION("subscribe") {
        auto ok = send(session, serialize_subscribe(SubscribeMessage{1, {}, "com.example.news"}));
        REQUIRE(get_message_type_from_cbor(ok) == MessageType::SUBSCRIBED);
        require_not_authorized(send(session, serialize_subscribe(SubscribeMessage{2, {}, "org.other.news"})),
                               MessageType::SUBSCRIBE, 2);
    }

    SECTION("publish: acknowledged denial gets an error, unacknowledged is silent") {
        WampDict ack{{"acknowledge", true}};
        auto ok = send(session, serialize_publish(PublishMessage{3, ack, "com.example.news"}));
        REQUIRE(get_message_type_from_cbor(ok) == MessageType::PUBLISHED);

        require_not_authorized(send(session, serialize_publish(PublishMessage{4, ack, "org.other.news"})),
                               MessageType::PUBLISH, 4);
        REQUIRE(send(session, serialize_publish(PublishMessage{5, {}, "org.other.news"})).empty());
    }

    SECTION("register") {
        auto ok = send(session, serialize_register(RegisterMessage{6, {}, "com.example.add"}));
        REQUIRE(get_message_type_from_cbor(ok) == MessageType::REGISTERED);
        require_not_authorized(send(session, serialize_register(RegisterMessage{7, {}, "com.example.mul"})),
                               MessageType::REGISTER, 7);
    }

    SECTION("call: allowed procedure reaches the dealer, others are denied first") {
        auto passed = send(session, serialize_call(CallMessage{8, {}, "com.example.add"}));
        auto err = deserialize_error(passed);
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.no_such_procedure");  // authorized, but nobody registered it

        require_not_authorized(send(session, serialize_call(CallMessage{9, {}, "com.example.mul"})),
                               MessageType::CALL, 9);
    }
}

TEST_CASE("A role can be limited to certain payload passthru schemes", "[authz][ppt][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);
    config.roles.at("user").set_ppt_schemes({"x_protobuf"});
    WampSession session{io, config, test_shard()};
    (void)establish(session, kp, "alice", "com.example.realm", true);

    const WampList blob{WampBytes{1, 2, 3}};
    auto options = [](const std::string& scheme) {
        return WampDict{{"acknowledge", true}, {"ppt_scheme", scheme}};
    };

    auto ok = send(session, serialize_publish(PublishMessage{1, options("x_protobuf"), "com.example.news", blob}));
    REQUIRE(get_message_type_from_cbor(ok) == MessageType::PUBLISHED);
    require_not_authorized(
        send(session, serialize_publish(PublishMessage{2, options("x_other"), "com.example.news", blob})),
        MessageType::PUBLISH, 2);
    require_not_authorized(
        send(session, serialize_call(CallMessage{3, WampDict{{"ppt_scheme", std::string{"x_other"}}},
                                                 "com.example.add", blob})),
        MessageType::CALL, 3);
    // without ppt_* the scheme list does not matter
    auto plain = send(session, serialize_publish(PublishMessage{4, WampDict{{"acknowledge", true}}, "com.example.news"}));
    REQUIRE(get_message_type_from_cbor(plain) == MessageType::PUBLISHED);
}

TEST_CASE("Permissions: ppt schemes", "[authz][ppt]") {
    Permissions any;
    CHECK(any.allows_ppt_scheme("whatever"));
    Permissions limited;
    limited.set_ppt_schemes({"a", "b"});
    CHECK(limited.allows_ppt_scheme("a"));
    CHECK_FALSE(limited.allows_ppt_scheme("c"));
}

TEST_CASE("Pattern subscriptions and registrations are authorized by what they can match", "[authz][patterns][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);   // prefix rules for publish/subscribe under com.example., exact rules for call/register
    WampSession session{io, config, test_shard()};
    (void)establish(session, kp, "alice");

    auto subscribe = [&](uint64_t id, const std::string& topic, const std::string& match) {
        return send(session, serialize_subscribe(SubscribeMessage{id, WampDict{{"match", match}}, topic}));
    };
    auto error_of = [](const std::vector<uint8_t>& reply) {
        auto error = deserialize_error(reply);
        REQUIRE(error.has_value());
        return error->error_uri;
    };

    CHECK(get_message_type_from_cbor(subscribe(1, "com.example.n", "prefix")) == MessageType::SUBSCRIBED);
    CHECK(get_message_type_from_cbor(subscribe(2, "com.example..x", "wildcard")) == MessageType::SUBSCRIBED);
    CHECK(error_of(subscribe(3, "com.", "prefix")) == "wamp.error.not_authorized");           // wider than the rule
    CHECK(error_of(subscribe(4, "com..x", "wildcard")) == "wamp.error.not_authorized");
    CHECK(error_of(subscribe(5, "", "prefix")) == "wamp.error.invalid_uri");
    CHECK(error_of(subscribe(6, "com.example.x", "wildcard")) == "wamp.error.invalid_uri");   // no empty component
    CHECK(error_of(subscribe(7, "com.example.x", "regex")) == "wamp.error.invalid_argument");

    // REGISTER is allowed for the exact procedure only: an exact rule never authorizes a pattern
    auto reg = [&](uint64_t id, const std::string& uri, const std::string& match) {
        return send(session, serialize_register(RegisterMessage{id, WampDict{{"match", match}}, uri}));
    };
    CHECK(error_of(reg(8, "com.example.add", "prefix")) == "wamp.error.not_authorized");
    CHECK(get_message_type_from_cbor(reg(9, "com.example.add", "exact")) == MessageType::REGISTERED);
}

TEST_CASE("Authid without a role can connect but do nothing", "[authz][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);
    WampSession session{io, config, test_shard()};

    auto welcome = establish(session, kp, "bob");
    REQUIRE(welcome.authrole == "none");

    require_not_authorized(send(session, serialize_subscribe(SubscribeMessage{1, {}, "com.example.news"})),
                           MessageType::SUBSCRIBE, 1);
    require_not_authorized(send(session, serialize_call(CallMessage{2, {}, "com.example.add"})),
                           MessageType::CALL, 2);
}

TEST_CASE("Without auth keys nothing is restricted", "[authz][wamp_session]") {
    asio::io_context io;
    ServerConfig config;
    config.max_pending_invocations = 1000;
    WampSession session{io, config, test_shard()};
    session.on_connect();

    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR});
    REQUIRE(session.process(std::span{handshake.data(), handshake.size()}).has_value());
    auto hello_frame = rawsocket::create_wamp_message(serialize_hello(HelloMessage{"com.example.realm"}));
    REQUIRE(session.process(std::span{hello_frame.data(), hello_frame.size()}).has_value());

    auto ok = send(session, serialize_subscribe(SubscribeMessage{1, {}, "any.topic.at.all"}));
    REQUIRE(get_message_type_from_cbor(ok) == MessageType::SUBSCRIBED);
}

TEST_CASE("Session only admits authids to their allowed realms", "[authz][realm][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);
    config.auth_realms["alice"] = {"com.example.realm", "second.realm"};
    WampSession session{io, config, test_shard()};

    session.on_connect();
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR});
    REQUIRE(session.process(std::span{handshake.data(), handshake.size()}).has_value());

    auto join = [&](const std::string& realm) {
        HelloMessage hello{realm};
        hello.authid = "alice";
        hello.authmethods = std::vector<std::string>{"cryptosign"};
        return send(session, serialize_hello(hello));
    };

    SECTION("a realm outside the authid's list is aborted before any CHALLENGE") {
        auto reply = join("third.realm");
        REQUIRE(get_message_type_from_cbor(reply) == MessageType::ABORT);
    }

    SECTION("a realm in the list gets a CHALLENGE") {
        REQUIRE(get_message_type_from_cbor(join("second.realm")) == MessageType::CHALLENGE);
    }
}

TEST_CASE("An authid with no realm list cannot join anywhere", "[authz][realm][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);
    config.auth_realms.erase("bob");
    WampSession session{io, config, test_shard()};

    session.on_connect();
    auto handshake = rawsocket::encode_handshake_request({
        .max_length = rawsocket::MaxLengthCode::BYTES_16M,
        .serializer = rawsocket::Serializer::CBOR});
    REQUIRE(session.process(std::span{handshake.data(), handshake.size()}).has_value());

    HelloMessage hello{"com.example.realm"};
    hello.authid = "bob";
    hello.authmethods = std::vector<std::string>{"cryptosign"};
    REQUIRE(get_message_type_from_cbor(send(session, serialize_hello(hello))) == MessageType::ABORT);
}

TEST_CASE("Roles can differ per realm", "[authz][realm][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);

    Permissions readonly;
    readonly.add_rule(Action::SUBSCRIBE, "com.example.", true);
    config.roles.emplace("readonly", std::move(readonly));

    config.auth_realms["alice"] = {"com.example.realm", "second.realm"};
    AuthRole alice;
    alice.by_realm["com.example.realm"] = "user";
    alice.by_realm["second.realm"] = "readonly";
    config.auth_roles["alice"] = alice;

    WampSession first{io, config, test_shard()};
    auto welcome1 = establish(first, kp, "alice", "com.example.realm");
    REQUIRE(welcome1.authrole == "user");
    REQUIRE(get_message_type_from_cbor(send(first, serialize_publish(
        PublishMessage{1, {{"acknowledge", true}}, "com.example.news"}))) == MessageType::PUBLISHED);

    WampSession second{io, config, test_shard()};
    auto welcome2 = establish(second, kp, "alice", "second.realm");
    REQUIRE(welcome2.authrole == "readonly");
    require_not_authorized(send(second, serialize_publish(
        PublishMessage{1, {{"acknowledge", true}}, "com.example.news"})), MessageType::PUBLISH, 1);
    REQUIRE(get_message_type_from_cbor(send(second, serialize_subscribe(
        SubscribeMessage{2, {}, "com.example.news"}))) == MessageType::SUBSCRIBED);
}

TEST_CASE("Authenticated sessions in different realms are isolated", "[authz][realm][wamp_session]") {
    auto kp = make_keypair();
    asio::io_context io;
    auto config = authz_config(kp.public_hex);
    config.auth_realms["alice"] = {"com.example.realm", "second.realm"};

    WampSession in_first{io, config, test_shard()};
    WampSession in_second{io, config, test_shard()};
    auto w1 = establish(in_first, kp, "alice", "com.example.realm");
    auto w2 = establish(in_second, kp, "alice", "second.realm");
    REQUIRE(w1.session_id != w2.session_id);

    REQUIRE(get_message_type_from_cbor(send(in_first, serialize_subscribe(
        SubscribeMessage{1, {}, "com.example.news"}))) == MessageType::SUBSCRIBED);

    // Publishing the same topic from the other realm must not produce an EVENT for the first
    (void)send(in_second, serialize_publish(PublishMessage{1, {}, "com.example.news"}));
    auto channel = test_shard().channels.find(w1.session_id);
    REQUIRE(channel != nullptr);
    bool got_event = false;
    channel->try_receive([&](std::error_code, EventToSend) { got_event = true; });
    REQUIRE_FALSE(got_event);

    // ...while a publish in its own realm does (alice is publisher-capable; use a second session)
    WampSession publisher{io, config, test_shard()};
    (void)establish(publisher, kp, "alice", "com.example.realm");
    (void)send(publisher, serialize_publish(PublishMessage{2, {}, "com.example.news"}));
    channel->try_receive([&](std::error_code, EventToSend) { got_event = true; });
    REQUIRE(got_event);
}
