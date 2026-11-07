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
#include "include/wamp_server.hpp"
#include "include/wamp_serializer.hpp"
#include "include/raw_socket.hpp"
#include "include/crypto_utils.hpp"
#include <asio.hpp>
#include <thread>
#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <fstream>
#include <poll.h>
#include <cerrno>

using namespace wamp;
using namespace std::chrono_literals;
using tcp = asio::ip::tcp;

// Helper function to create test ServerConfig for integration tests
static ServerConfig create_test_config() {
    ServerConfig config;
    config.port = 0;  // Let OS assign port
    config.tls.cert_path = "test_certs/cert.pem";
    config.tls.key_path = "test_certs/key.pem";
    config.max_pending_invocations = 1000;
    config.log_level = spdlog::level::warn;  // Less verbose for tests
    // No auth keys - allow unauthenticated connections for basic tests
    return config;
}

// Read exactly buf.size() bytes, giving up at `deadline`. The test clients are purely blocking;
// without this a missing reply would hang the test instead of failing it.
static bool read_exact(tcp::socket& socket, std::span<uint8_t> buf,
                       std::chrono::steady_clock::time_point deadline) {
    size_t got = 0;
    while (got < buf.size()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

        pollfd pfd{socket.native_handle(), POLLIN, 0};
        const int ready = ::poll(&pfd, 1, static_cast<int>(std::max<int64_t>(1, remaining.count())));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;

        std::error_code ec;
        const size_t n = socket.read_some(asio::buffer(buf.data() + got, buf.size() - got), ec);
        if (ec) return false;
        got += n;
    }
    return true;
}

// ============================================================================
// WampTestClient - Synchronous blocking client for integration tests
// ============================================================================
class WampTestClient {
public:
    explicit WampTestClient(asio::io_context& io, const ServerConfig& config)
        : io_(io)
        , socket_(io)
        , session_id_(0)
    {
        (void)config;
    }

    ~WampTestClient() {
        disconnect();
    }

    // Connect to server and establish WAMP session
    bool connect(unsigned short port, std::chrono::milliseconds timeout = 5s) {
        try {
            // Connect TCP socket synchronously
            tcp::resolver resolver(io_);
            auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));

            std::error_code ec;
            asio::connect(socket_, endpoints, ec);
            if (ec) {
                spdlog::error("Client TCP connect failed: {}", ec.message());
                return false;
            }

            // Send RawSocket handshake
            auto handshake = rawsocket::encode_handshake_request({
                .max_length = rawsocket::MaxLengthCode::BYTES_16K,
                .serializer = rawsocket::Serializer::CBOR
            });
            asio::write(socket_, asio::buffer(handshake));

            // Receive handshake response (4 bytes)
            std::vector<uint8_t> handshake_response(4);
            asio::read(socket_, asio::buffer(handshake_response));

            // Send HELLO message
            auto hello = HelloMessage::create_client("com.example.realm");
            auto hello_cbor = serialize_hello(hello);
            auto hello_frame = rawsocket::create_wamp_message(hello_cbor);
            asio::write(socket_, asio::buffer(hello_frame));

            // Wait for WELCOME message
            auto welcome_msg = wait_for_message<WelcomeMessage>(timeout);
            if (!welcome_msg.has_value()) {
                return false;
            }

            session_id_ = welcome_msg->session_id;
            return true;

        } catch (const std::exception& e) {
            spdlog::error("Client connect failed: {}", e.what());
            return false;
        }
    }

    void disconnect() {
        if (socket_.is_open()) {
            std::error_code ec;
            socket_.close(ec);
        }
    }

    uint64_t session_id() const { return session_id_; }

    // Send raw CBOR message (for testing edge cases)
    void send_raw_message(const std::vector<uint8_t>& cbor_data) {
        auto frame = rawsocket::create_wamp_message(cbor_data);
        asio::write(socket_, asio::buffer(frame));
    }

    // Subscribe to topic, returns subscription_id
    std::optional<uint64_t> subscribe(const std::string& topic, std::chrono::milliseconds timeout = 1s) {
        static uint64_t request_id = 1000;
        uint64_t req_id = request_id++;

        SubscribeMessage sub{req_id, {}, topic};
        auto sub_cbor = serialize_subscribe(sub);
        auto sub_frame = rawsocket::create_wamp_message(sub_cbor);

        asio::write(socket_, asio::buffer(sub_frame));

        auto subscribed = wait_for_message<SubscribedMessage>(timeout);
        if (subscribed.has_value() && subscribed->request_id == req_id) {
            return subscribed->subscription_id;
        }
        return std::nullopt;
    }

    // Publish to topic
    bool publish(const std::string& topic, std::chrono::milliseconds timeout = 1s) {
        static uint64_t request_id = 2000;
        uint64_t req_id = request_id++;

        WampDict options;
        options["acknowledge"] = true;
        PublishMessage pub{req_id, options, topic};
        auto pub_cbor = serialize_publish(pub);
        auto pub_frame = rawsocket::create_wamp_message(pub_cbor);

        asio::write(socket_, asio::buffer(pub_frame));

        auto published = wait_for_message<PublishedMessage>(timeout);
        return published.has_value() && published->request_id == req_id;
    }

    // Wait for EVENT message
    std::optional<EventMessage> wait_for_event(std::chrono::milliseconds timeout = 1s) {
        return wait_for_message<EventMessage>(timeout);
    }

    // Register a procedure, returns registration_id
    std::optional<uint64_t> register_procedure(const std::string& procedure, std::chrono::milliseconds timeout = 1s) {
        static uint64_t request_id = 3000;
        uint64_t req_id = request_id++;

        RegisterMessage reg{req_id, {}, procedure};
        auto reg_cbor = serialize_register(reg);
        auto reg_frame = rawsocket::create_wamp_message(reg_cbor);

        asio::write(socket_, asio::buffer(reg_frame));

        auto registered = wait_for_message<RegisteredMessage>(timeout);
        if (registered.has_value() && registered->request_id == req_id) {
            return registered->registration_id;
        }
        return std::nullopt;
    }

    // Call a procedure, returns request_id
    std::optional<uint64_t> call_procedure(const std::string& procedure, [[maybe_unused]] std::chrono::milliseconds timeout = 1s) {
        static uint64_t request_id = 4000;
        uint64_t req_id = request_id++;

        CallMessage call{req_id, {}, procedure};
        auto call_cbor = serialize_call(call);
        auto call_frame = rawsocket::create_wamp_message(call_cbor);

        asio::write(socket_, asio::buffer(call_frame));

        return req_id;
    }

    // Wait for INVOCATION message (callee side)
    std::optional<InvocationMessage> wait_for_invocation(std::chrono::milliseconds timeout = 1s) {
        return wait_for_message<InvocationMessage>(timeout);
    }

    // Send YIELD message (callee side)
    bool yield_result(uint64_t invocation_id) {
        YieldMessage yield{invocation_id, {}};
        auto yield_cbor = serialize_yield(yield);
        auto yield_frame = rawsocket::create_wamp_message(yield_cbor);

        asio::write(socket_, asio::buffer(yield_frame));
        return true;
    }

    // Wait for RESULT message (caller side)
    std::optional<ResultMessage> wait_for_result(std::chrono::milliseconds timeout = 1s) {
        return wait_for_message<ResultMessage>(timeout);
    }

    // Wait for ERROR message
    std::optional<ErrorMessage> wait_for_error(std::chrono::milliseconds timeout = 1s) {
        return wait_for_message<ErrorMessage>(timeout);
    }

private:
    template<typename T>
    std::optional<T> wait_for_message(std::chrono::milliseconds timeout) {
        // This is simplified - we're doing blocking reads instead of proper async
        // In a real implementation, we'd have a message queue and condition variable

        auto deadline = std::chrono::steady_clock::now() + timeout;

        while (std::chrono::steady_clock::now() < deadline) {
            // Read frame header (4 bytes)
            std::vector<uint8_t> header_buf(4);
            if (!read_exact(socket_, header_buf, deadline)) break;

            auto header = rawsocket::decode_frame_header(header_buf);
            if (!header.has_value()) break;

            // Read payload
            std::vector<uint8_t> payload(header->payload_length);
            if (!read_exact(socket_, payload, deadline)) break;

            // Get message type
            auto msg_type = get_message_type_from_cbor(payload);
            if (!msg_type.has_value()) continue;

            // Try to deserialize as requested type
            if constexpr (std::is_same_v<T, WelcomeMessage>) {
                if (*msg_type == MessageType::WELCOME) {
                    auto msg = deserialize_welcome(payload);
                    if (msg.has_value()) return *msg;
                }
            } else if constexpr (std::is_same_v<T, SubscribedMessage>) {
                if (*msg_type == MessageType::SUBSCRIBED) {
                    auto msg = deserialize_subscribed(payload);
                    if (msg.has_value()) return *msg;
                }
            } else if constexpr (std::is_same_v<T, PublishedMessage>) {
                if (*msg_type == MessageType::PUBLISHED) {
                    auto msg = deserialize_published(payload);
                    if (msg.has_value()) return *msg;
                }
            } else if constexpr (std::is_same_v<T, EventMessage>) {
                if (*msg_type == MessageType::EVENT) {
                    auto msg = deserialize_event(payload);
                    if (msg.has_value()) return *msg;
                }
            } else if constexpr (std::is_same_v<T, RegisteredMessage>) {
                if (*msg_type == MessageType::REGISTERED) {
                    auto msg = deserialize_registered(payload);
                    if (msg.has_value()) return *msg;
                }
            } else if constexpr (std::is_same_v<T, InvocationMessage>) {
                if (*msg_type == MessageType::INVOCATION) {
                    auto msg = deserialize_invocation(payload);
                    if (msg.has_value()) return *msg;
                }
            } else if constexpr (std::is_same_v<T, ResultMessage>) {
                if (*msg_type == MessageType::RESULT) {
                    auto msg = deserialize_result(payload);
                    if (msg.has_value()) return *msg;
                }
            } else if constexpr (std::is_same_v<T, ErrorMessage>) {
                if (*msg_type == MessageType::ERROR) {
                    auto msg = deserialize_error(payload);
                    if (msg.has_value()) return *msg;
                }
            }
        }

        return std::nullopt;
    }

    asio::io_context& io_;
    tcp::socket socket_;
    uint64_t session_id_;
};

// ============================================================================
// Test Fixture - Manages server lifecycle
// ============================================================================
class RouterFixture {
public:
    explicit RouterFixture(const ServerConfig& config)
        : config_(config)
        , server_(server_io_, 0, config_)
    {
        // The acceptor is already bound and listening, so connections queue until the loop runs
        port_ = server_.port();
        server_.start();
        server_thread_ = std::thread([this] { server_io_.run(); });
        spdlog::debug("Test router listening on port {}", port_);
    }

    ~RouterFixture() {
        // io_context::stop() is thread-safe; the io_context and server outlive the thread
        server_io_.stop();
        if (server_thread_.joinable()) server_thread_.join();
    }

    RouterFixture(const RouterFixture&) = delete;
    RouterFixture& operator=(const RouterFixture&) = delete;

    unsigned short port() const { return port_; }
    asio::io_context& io_context() { return client_io_; }

private:
    ServerConfig config_;  // WampServer keeps a reference to its config
    asio::io_context server_io_;
    asio::io_context client_io_;  // only used by the blocking test clients (resolver, sockets)
    WampServer server_;
    unsigned short port_{0};
    std::thread server_thread_;
};

// Router with the default test configuration
class WampServerFixture : public RouterFixture {
public:
    WampServerFixture() : RouterFixture(create_test_config()) {}
};

// ============================================================================
// Integration Tests
// ============================================================================

TEST_CASE("Integration: Client connects and establishes session", "[integration]") {
    WampServerFixture fixture;
    auto config = create_test_config();
    WampTestClient client(fixture.io_context(), config);

    bool connected = client.connect(fixture.port(), 2s);
    REQUIRE(connected);
    REQUIRE(client.session_id() > 0);
}

TEST_CASE("Integration: Pub/Sub - Single subscriber receives event", "[integration]") {
    WampServerFixture fixture;

    // Create subscriber
    auto config = create_test_config();
    WampTestClient subscriber(fixture.io_context(), config);
    REQUIRE(subscriber.connect(fixture.port()));

    // Subscribe to topic
    auto sub_id = subscriber.subscribe("com.example.test");
    REQUIRE(sub_id.has_value());

    // Create publisher
    WampTestClient publisher(fixture.io_context(), config);
    REQUIRE(publisher.connect(fixture.port()));

    // Publish event
    bool published = publisher.publish("com.example.test");
    REQUIRE(published);

    // Subscriber should receive event
    auto event = subscriber.wait_for_event(2s);
    REQUIRE(event.has_value());
    REQUIRE(event->subscription_id == *sub_id);
}

TEST_CASE("Integration: Pub/Sub - Multiple subscribers receive event", "[integration]") {
    WampServerFixture fixture;

    // Create multiple subscribers
    auto config = create_test_config();
    WampTestClient sub1(fixture.io_context(), config);
    WampTestClient sub2(fixture.io_context(), config);
    WampTestClient sub3(fixture.io_context(), config);

    REQUIRE(sub1.connect(fixture.port()));
    REQUIRE(sub2.connect(fixture.port()));
    REQUIRE(sub3.connect(fixture.port()));

    // All subscribe to same topic
    auto sub_id1 = sub1.subscribe("com.example.broadcast");
    auto sub_id2 = sub2.subscribe("com.example.broadcast");
    auto sub_id3 = sub3.subscribe("com.example.broadcast");

    REQUIRE(sub_id1.has_value());
    REQUIRE(sub_id2.has_value());
    REQUIRE(sub_id3.has_value());

    // Publisher sends event
    WampTestClient publisher(fixture.io_context(), config);
    REQUIRE(publisher.connect(fixture.port()));
    REQUIRE(publisher.publish("com.example.broadcast"));

    // All subscribers should receive event
    auto event1 = sub1.wait_for_event(2s);
    auto event2 = sub2.wait_for_event(2s);
    auto event3 = sub3.wait_for_event(2s);

    REQUIRE(event1.has_value());
    REQUIRE(event2.has_value());
    REQUIRE(event3.has_value());
}

TEST_CASE("Integration: RPC - Call and result flow", "[integration]") {
    WampServerFixture fixture;

    // Callee registers procedure
    auto config = create_test_config();
    WampTestClient callee(fixture.io_context(), config);
    REQUIRE(callee.connect(fixture.port()));

    auto reg_id = callee.register_procedure("com.example.add");
    REQUIRE(reg_id.has_value());

    // Caller invokes procedure
    WampTestClient caller(fixture.io_context(), config);
    REQUIRE(caller.connect(fixture.port()));

    auto call_req_id = caller.call_procedure("com.example.add");
    REQUIRE(call_req_id.has_value());

    // Callee receives invocation
    auto invocation = callee.wait_for_invocation(2s);
    REQUIRE(invocation.has_value());
    REQUIRE(invocation->registration_id == *reg_id);

    // Callee sends yield
    REQUIRE(callee.yield_result(invocation->request_id));

    // Caller receives result
    auto result = caller.wait_for_result(2s);
    REQUIRE(result.has_value());
    REQUIRE(result->request_id == *call_req_id);
}

TEST_CASE("Integration: RPC - Call to unregistered procedure returns error", "[integration]") {
    WampServerFixture fixture;

    auto config = create_test_config();
    WampTestClient caller(fixture.io_context(), config);
    REQUIRE(caller.connect(fixture.port()));

    auto call_req_id = caller.call_procedure("com.example.nonexistent");
    REQUIRE(call_req_id.has_value());

    // Should receive ERROR message
    auto error = caller.wait_for_error(2s);
    REQUIRE(error.has_value());
    REQUIRE(error->request_id == *call_req_id);
    REQUIRE(error->error_uri == "wamp.error.no_such_procedure");
}

TEST_CASE("Integration: RPC - Duplicate registration returns error", "[integration]") {
    WampServerFixture fixture;
    auto config = create_test_config();

    // First client registers
    WampTestClient callee1(fixture.io_context(), config);
    REQUIRE(callee1.connect(fixture.port()));
    auto reg_id1 = callee1.register_procedure("com.example.exclusive");
    REQUIRE(reg_id1.has_value());

    // Second client tries to register same procedure
    WampTestClient callee2(fixture.io_context(), config);
    REQUIRE(callee2.connect(fixture.port()));

    // Send REGISTER
    static uint64_t request_id = 5000;
    RegisterMessage reg{request_id++, {}, "com.example.exclusive"};
    auto reg_cbor = serialize_register(reg);
    callee2.send_raw_message(reg_cbor);

    // Should receive ERROR
    auto error = callee2.wait_for_error(2s);
    REQUIRE(error.has_value());
    REQUIRE(error->error_uri == "wamp.error.procedure_already_exists");
}

TEST_CASE("Integration: Multiple clients with mixed operations", "[integration]") {
    WampServerFixture fixture;
    auto config = create_test_config();

    // Client 1: Subscriber and Callee
    WampTestClient client1(fixture.io_context(), config);
    REQUIRE(client1.connect(fixture.port()));
    auto sub_id = client1.subscribe("com.example.events");
    auto reg_id = client1.register_procedure("com.example.compute");
    REQUIRE(sub_id.has_value());
    REQUIRE(reg_id.has_value());

    // Client 2: Publisher and Caller
    WampTestClient client2(fixture.io_context(), config);
    REQUIRE(client2.connect(fixture.port()));

    // Test pub/sub
    REQUIRE(client2.publish("com.example.events"));
    auto event = client1.wait_for_event(2s);
    REQUIRE(event.has_value());

    // Test RPC
    auto call_req = client2.call_procedure("com.example.compute");
    REQUIRE(call_req.has_value());

    auto invocation = client1.wait_for_invocation(2s);
    REQUIRE(invocation.has_value());

    REQUIRE(client1.yield_result(invocation->request_id));

    auto result = client2.wait_for_result(2s);
    REQUIRE(result.has_value());
}

// ============================================================================
// Authentication Integration Tests
// ============================================================================

// Helper to create Ed25519 key pair for auth tests
static std::pair<std::string, std::string> create_integration_test_keypair() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate test key pair");
    }
    EVP_PKEY_CTX_free(ctx);

    // Extract public key hex
    size_t pub_len = 32;
    std::vector<uint8_t> pub_key(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len);
    std::string public_key_hex = bytes_to_hex(pub_key);

    // Write private key to temp file
    std::string priv_path = "/tmp/wamp_integration_test_key.pem";
    FILE* priv_file = fopen(priv_path.c_str(), "w");
    if (!priv_file) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create temp private key file");
    }

    PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(priv_file);
    EVP_PKEY_free(pkey);

    return {priv_path, public_key_hex};
}

// Helper to create auth-enabled ServerConfig
static ServerConfig create_auth_server_config(const std::string& authid, const std::string& public_key_hex) {
    ServerConfig config;
    config.port = 0;  // Let OS assign port
    config.tls.cert_path = "test_certs/cert.pem";
    config.tls.key_path = "test_certs/key.pem";
    config.max_pending_invocations = 1000;
    config.log_level = spdlog::level::warn;
    config.auth_keys[authid] = public_key_hex;
    config.auth_realms[authid] = {"com.example.realm"};

    // The authenticated user may only subscribe below "allowed."
    Permissions limited;
    limited.add_rule(Action::SUBSCRIBE, "allowed.", true);
    config.roles.emplace("limited", std::move(limited));
    config.auth_roles[authid] = "limited";
    return config;
}

// Router that requires Cryptosign for the given authid
class WampAuthServerFixture : public RouterFixture {
public:
    WampAuthServerFixture(const std::string& authid, const std::string& public_key_hex)
        : RouterFixture(create_auth_server_config(authid, public_key_hex)) {}
};

// Auth-aware test client that can perform cryptosign authentication
class WampAuthTestClient {
public:
    WampAuthTestClient(asio::io_context& io, const std::string& priv_key_path, const std::string& authid,
                       std::string realm = "com.example.realm")
        : io_(io)
        , socket_(io)
        , realm_(std::move(realm))
        , priv_key_path_(priv_key_path)
        , authid_(authid)
        , session_id_(0)
    {}

    ~WampAuthTestClient() {
        disconnect();
    }

    bool connect(unsigned short port, std::chrono::milliseconds timeout = 5s) {
        try {
            // Connect TCP socket
            tcp::resolver resolver(io_);
            auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));

            std::error_code ec;
            asio::connect(socket_, endpoints, ec);
            if (ec) return false;

            // RawSocket handshake
            auto handshake = rawsocket::encode_handshake_request({
                .max_length = rawsocket::MaxLengthCode::BYTES_16K,
                .serializer = rawsocket::Serializer::CBOR
            });
            asio::write(socket_, asio::buffer(handshake));

            std::vector<uint8_t> handshake_response(4);
            asio::read(socket_, asio::buffer(handshake_response));

            // Send HELLO with auth info
            HelloMessage hello = HelloMessage::create_client(realm_);
            hello.authid = authid_;
            hello.authmethods = std::vector<std::string>{"cryptosign"};

            auto hello_cbor = serialize_hello(hello);
            auto hello_frame = rawsocket::create_wamp_message(hello_cbor);
            asio::write(socket_, asio::buffer(hello_frame));

            // Wait for CHALLENGE
            auto challenge_msg = read_wamp_message(timeout);
            if (!challenge_msg.has_value()) return false;

            auto msg_type = get_message_type_from_cbor(*challenge_msg);
            if (!msg_type.has_value() || *msg_type != MessageType::CHALLENGE) {
                // Check if it's an ABORT
                if (msg_type.has_value() && *msg_type == MessageType::ABORT) {
                    spdlog::warn("Received ABORT instead of CHALLENGE");
                    return false;
                }
                return false;
            }

            auto challenge = deserialize_challenge(*challenge_msg);
            if (!challenge.has_value()) return false;

            // Load private key and sign
            auto key_result = load_ed25519_private_key_pem(priv_key_path_);
            if (!key_result.has_value()) return false;

            std::string challenge_nonce = challenge->extra.at("challenge");

            auto sig_result = sign_challenge(challenge_nonce, key_result->get());
            if (!sig_result.has_value()) return false;

            // Send AUTHENTICATE
            AuthenticateMessage auth{*sig_result};
            auto auth_cbor = serialize_authenticate(auth);
            auto auth_frame = rawsocket::create_wamp_message(auth_cbor);
            asio::write(socket_, asio::buffer(auth_frame));

            // Wait for WELCOME
            auto welcome_msg = read_wamp_message(timeout);
            if (!welcome_msg.has_value()) return false;

            auto welcome_type = get_message_type_from_cbor(*welcome_msg);
            if (!welcome_type.has_value() || *welcome_type != MessageType::WELCOME) {
                return false;
            }

            auto welcome = deserialize_welcome(*welcome_msg);
            if (!welcome.has_value()) return false;

            session_id_ = welcome->session_id;
            return true;

        } catch (const std::exception& e) {
            spdlog::error("Auth client connect failed: {}", e.what());
            return false;
        }
    }

    void disconnect() {
        if (socket_.is_open()) {
            std::error_code ec;
            socket_.close(ec);
        }
    }

    uint64_t session_id() const { return session_id_; }

    // Send one WAMP message and return the router's reply payload
    std::optional<std::vector<uint8_t>> request(const std::vector<uint8_t>& cbor,
                                                std::chrono::milliseconds timeout = 2s) {
        asio::write(socket_, asio::buffer(rawsocket::create_wamp_message(cbor)));
        return read_wamp_message(timeout);
    }

private:
    std::optional<std::vector<uint8_t>> read_wamp_message(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;

        try {
            // Read frame header
            std::vector<uint8_t> header_buf(4);
            if (!read_exact(socket_, header_buf, deadline)) return std::nullopt;

            auto header = rawsocket::decode_frame_header(header_buf);
            if (!header.has_value()) return std::nullopt;

            // Read payload
            std::vector<uint8_t> payload(header->payload_length);
            if (!read_exact(socket_, payload, deadline)) return std::nullopt;

            return payload;
        } catch (...) {
            return std::nullopt;
        }
    }

    asio::io_context& io_;
    tcp::socket socket_;
    std::string realm_;
    std::string priv_key_path_;
    std::string authid_;
    uint64_t session_id_;
};

TEST_CASE("Integration: Authenticated client connects successfully", "[integration][auth]") {
    auto [priv_path, public_key_hex] = create_integration_test_keypair();

    WampAuthServerFixture fixture("testuser", public_key_hex);
    WampAuthTestClient client(fixture.io_context(), priv_path, "testuser");

    bool connected = client.connect(fixture.port(), 5s);
    REQUIRE(connected);
    REQUIRE(client.session_id() > 0);

    std::remove(priv_path.c_str());
}

TEST_CASE("Integration: Unknown authid rejected", "[integration][auth]") {
    auto [priv_path, public_key_hex] = create_integration_test_keypair();

    // Server configured for "validuser" but client uses "wronguser"
    WampAuthServerFixture fixture("validuser", public_key_hex);
    WampAuthTestClient client(fixture.io_context(), priv_path, "wronguser");

    bool connected = client.connect(fixture.port(), 5s);
    REQUIRE(!connected);

    std::remove(priv_path.c_str());
}

TEST_CASE("Integration: Invalid signature rejected", "[integration][auth]") {
    // Create two different key pairs
    auto [priv_path1, public_key_hex1] = create_integration_test_keypair();
    auto [priv_path2, public_key_hex2] = create_integration_test_keypair();

    // Server expects public_key_hex1, but client uses private key from pair 2
    WampAuthServerFixture fixture("testuser", public_key_hex1);
    WampAuthTestClient client(fixture.io_context(), priv_path2, "testuser");

    bool connected = client.connect(fixture.port(), 5s);
    REQUIRE(!connected);

    std::remove(priv_path1.c_str());
    std::remove(priv_path2.c_str());
}

TEST_CASE("Integration: Role permissions are enforced end to end", "[integration][auth][authz]") {
    auto [priv_path, public_key_hex] = create_integration_test_keypair();

    WampAuthServerFixture fixture("testuser", public_key_hex);
    WampAuthTestClient client(fixture.io_context(), priv_path, "testuser");
    REQUIRE(client.connect(fixture.port(), 5s));

    auto allowed = client.request(serialize_subscribe(SubscribeMessage{1, {}, "allowed.topic"}));
    REQUIRE(allowed.has_value());
    REQUIRE(get_message_type_from_cbor(*allowed) == MessageType::SUBSCRIBED);

    auto denied = client.request(serialize_subscribe(SubscribeMessage{2, {}, "secret.topic"}));
    REQUIRE(denied.has_value());
    auto error = deserialize_error(*denied);
    REQUIRE(error.has_value());
    REQUIRE(error->error_uri == "wamp.error.not_authorized");
    REQUIRE(error->request_id == 2);

    // Publishing was never granted
    auto publish = client.request(serialize_publish(PublishMessage{3, {{"acknowledge", true}}, "allowed.topic"}));
    REQUIRE(publish.has_value());
    REQUIRE(deserialize_error(*publish)->error_uri == "wamp.error.not_authorized");

    std::remove(priv_path.c_str());
}

TEST_CASE("Integration: Cryptosign login is refused for a realm the authid may not join",
          "[integration][auth][realm]") {
    auto [priv_path, public_key_hex] = create_integration_test_keypair();

    WampAuthServerFixture fixture("testuser", public_key_hex);

    WampAuthTestClient wrong_realm(fixture.io_context(), priv_path, "testuser", "other.realm");
    REQUIRE_FALSE(wrong_realm.connect(fixture.port(), 5s));

    WampAuthTestClient right_realm(fixture.io_context(), priv_path, "testuser");
    REQUIRE(right_realm.connect(fixture.port(), 5s));

    std::remove(priv_path.c_str());
}
