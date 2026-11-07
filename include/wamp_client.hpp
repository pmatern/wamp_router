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
#include "wamp_serializer.hpp"
#include "raw_socket.hpp"
#include "crypto_utils.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <spdlog/spdlog.h>
#include <deque>
#include <functional>
#include <unordered_map>
#include <vector>
#include <string>
#include <optional>
#include <expected>
#include <memory>
#include <stdexcept>

namespace wamp {

using boost::asio::awaitable;
using boost::asio::use_awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::ip::tcp;

// Thrown by WampClient when the router answers a request with an ERROR, and
// throwable from an InvocationHandler to make the router send an ERROR to the caller.
class WampException : public std::runtime_error {
public:
    explicit WampException(std::string uri, WampDict details_dict = {},
                           WampList args = {}, WampDict args_kw = {})
        : std::runtime_error(make_what(uri, details_dict))
        , error_uri(std::move(uri))
        , details(std::move(details_dict))
        , arguments(std::move(args))
        , arguments_kw(std::move(args_kw))
    {}

    std::string error_uri;
    WampDict details;
    WampList arguments;
    WampDict arguments_kw;

private:
    static std::string make_what(const std::string& uri, const WampDict& details_dict) {
        if (auto it = details_dict.find("message"); it != details_dict.end()) {
            if (const auto* msg = std::get_if<std::string>(&it->second)) {
                return uri + ": " + *msg;
            }
        }
        return uri;
    }
};

// Callback types for client
using EventCallback = std::function<void(const EventMessage&)>;
using InvocationHandler = std::function<awaitable<YieldMessage>(const InvocationMessage&)>;

// ============================================================================
// WampClient - Coroutine-based WAMP client
// ============================================================================
class WampClient {
public:
    explicit WampClient(boost::asio::io_context& io)
        : io_(io)
        , socket_(io)
        , state_(State::DISCONNECTED)
        , framing_state_(FramingState::AWAITING_FRAME_HEADER)
        , expected_payload_length_(0)
        , session_id_(0)
        , read_loop_running_(false)
        , welcome_channel_(io, 1)
        , goodbye_channel_(io, 1)
        , challenge_channel_(io, 1)
    {
        spdlog::debug("WampClient created");
    }

    // No copy/move
    WampClient(const WampClient&) = delete;
    WampClient& operator=(const WampClient&) = delete;

    ~WampClient() {
        if (state_ != State::DISCONNECTED && state_ != State::CLOSED) {
            spdlog::warn("WampClient destroyed while still connected");
        }
    }

    // ========================================================================
    // Connection Management
    // ========================================================================

    // Connect to WAMP router (unauthenticated)
    awaitable<void> connect(std::string host, uint16_t port, std::string realm) {
        co_await connect_with_auth(std::move(host), port, std::move(realm), std::nullopt, std::nullopt);
    }

    // Connect to WAMP router with authentication
    awaitable<void> connect_with_auth(
        std::string host,
        uint16_t port,
        std::string realm,
        std::optional<std::string> authid,
        std::optional<std::string> private_key_pem_path
    ) {
        if (state_ != State::DISCONNECTED) {
            throw std::runtime_error("Client already connected or connecting");
        }

        // Load private key if authentication is requested
        if (authid.has_value() && private_key_pem_path.has_value()) {
            authid_ = *authid;
            auto key_result = load_ed25519_private_key_pem(*private_key_pem_path);
            if (!key_result.has_value()) {
                throw std::runtime_error("Failed to load private key: " + key_result.error());
            }
            private_key_ = std::move(*key_result);
            spdlog::info("Connecting to {}:{} for realm '{}' with authid='{}'", host, port, realm, *authid);
        } else {
            spdlog::info("Connecting to {}:{} for realm '{}'", host, port, realm);
        }

        realm_ = realm;
        state_ = State::CONNECTING;

        tcp::resolver resolver{io_};
        auto endpoints = co_await resolver.async_resolve(host, std::to_string(port), use_awaitable);
        co_await boost::asio::async_connect(socket_, endpoints, use_awaitable);

        co_await send_rawsocket_handshake();

        // Start read loop AFTER handshake completes
        read_loop_running_ = true;
        co_spawn(io_, read_loop(), detached);

        co_await send_hello();

        // If authenticating, we expect CHALLENGE then WELCOME
        // If not authenticating, we expect WELCOME directly
        if (authid_.has_value()) {
            // Wait for CHALLENGE
            auto challenge_opt = co_await challenge_channel_.async_receive(use_awaitable);
            if (!challenge_opt.has_value()) {
                throw std::runtime_error("Failed to receive CHALLENGE");
            }

            // Handle the challenge and send AUTHENTICATE
            co_await handle_challenge_and_authenticate(*challenge_opt);
        }

        auto welcome_opt = co_await welcome_channel_.async_receive(use_awaitable);
        if (!welcome_opt.has_value()) {
            throw std::runtime_error("Failed to receive WELCOME");
        }
        session_id_ = welcome_opt->session_id;
        state_ = State::ESTABLISHED;

        spdlog::info("Session established: session_id={}", session_id_);
    }

    awaitable<void> disconnect() {
        if (state_ != State::ESTABLISHED && state_ != State::CLOSING) {
            co_return;
        }

        spdlog::info("Disconnecting from router");
        state_ = State::CLOSING;

        auto goodbye = GoodbyeMessage::create_normal();
        try {
            co_await send_wamp_message(goodbye);
        } catch (const std::exception& e) {
            spdlog::error("Failed to send GOODBYE: {}", e.what());
            state_ = State::CLOSED;
            co_return;
        }

        using namespace boost::asio::experimental::awaitable_operators;

        boost::asio::steady_timer timer{io_};
        timer.expires_after(std::chrono::milliseconds(500));

        // Coroutine lambdas must stay alive while their coroutines run (the frame refers to the
        // closure), so they are named locals rather than immediately-invoked temporaries.
        auto timeout = [&]() -> awaitable<bool> {
            co_await timer.async_wait(use_awaitable);
            co_return false; // timeout occurred
        };

        auto receive_goodbye = [&]() -> awaitable<bool> {
            auto [ec, msg] = co_await goodbye_channel_.async_receive(boost::asio::as_tuple(use_awaitable));
            if (!ec && msg.has_value()) {
                spdlog::debug("Received GOODBYE response from server");
                co_return true; // got goodbye
            }
            co_return false;
        };

        // Race the timeout and the goodbye receive
        auto result = co_await (timeout() || receive_goodbye());

        // Visit the variant to determine which completed first
        bool got_goodbye = std::visit([](auto&& value) { return value; }, result);

        if (!got_goodbye) {
            spdlog::debug("Timeout waiting for GOODBYE response");
        }

        if (socket_.is_open()) {
            socket_.close();
        }
        state_ = State::CLOSED;
        read_loop_running_ = false;

        spdlog::info("Disconnected");
    }

    [[nodiscard]] bool is_connected() const {
        return state_ == State::ESTABLISHED;
    }

    [[nodiscard]] uint64_t session_id() const {
        return session_id_;
    }

    // ========================================================================
    // PubSub API
    // ========================================================================

    awaitable<uint64_t> subscribe(std::string topic, EventCallback callback) {
        if (state_ != State::ESTABLISHED) {
            throw std::runtime_error("Not connected");
        }

        uint64_t request_id = next_request_id();
        SubscribeMessage msg{request_id, {}, topic};

        auto channel = std::make_shared<SubscribedChannel>(io_, 1);
        pending_subscribes_[request_id] = channel;

        co_await send_wamp_message(msg);

        auto subscribed = co_await await_reply<SubscribedMessage>(channel, request_id, "SUBSCRIBED");

        event_handlers_[subscribed.subscription_id] = std::move(callback);
        topic_to_subscription_id_[topic] = subscribed.subscription_id;

        spdlog::debug("Subscribed to '{}': subscription_id={}", topic, subscribed.subscription_id);
        co_return subscribed.subscription_id;
    }

    awaitable<void> unsubscribe(uint64_t subscription_id) {
        if (state_ != State::ESTABLISHED) {
            throw std::runtime_error("Not connected");
        }

        uint64_t request_id = next_request_id();
        auto channel = std::make_shared<UnsubscribedChannel>(io_, 1);
        pending_unsubscribes_[request_id] = channel;

        co_await send_wamp_message(UnsubscribeMessage{request_id, subscription_id});
        co_await await_reply<UnsubscribedMessage>(channel, request_id, "UNSUBSCRIBED");

        event_handlers_.erase(subscription_id);
        std::erase_if(topic_to_subscription_id_,
                      [subscription_id](const auto& kv) { return kv.second == subscription_id; });

        spdlog::debug("Unsubscribed: subscription_id={}", subscription_id);
    }

    awaitable<uint64_t> publish(std::string topic, bool acknowledge = false) {
        co_return co_await publish(std::move(topic), WampList{}, WampDict{}, acknowledge);
    }

    // Publish with payload. exclude_me=false delivers the event to this client's own subscriptions too.
    awaitable<uint64_t> publish(std::string topic, WampList args, WampDict args_kw = {},
                                bool acknowledge = false, bool exclude_me = true) {
        if (state_ != State::ESTABLISHED) {
            throw std::runtime_error("Not connected");
        }

        uint64_t request_id = next_request_id();
        WampDict options;
        if (acknowledge) {
            options["acknowledge"] = acknowledge;
        }
        if (!exclude_me) {
            options["exclude_me"] = exclude_me;
        }

        PublishMessage msg{request_id, options, topic, std::move(args), std::move(args_kw)};

        if (acknowledge) {
            auto channel = std::make_shared<PublishedChannel>(io_, 1);
            pending_publishes_[request_id] = channel;

            co_await send_wamp_message(msg);

            auto published = co_await await_reply<PublishedMessage>(channel, request_id, "PUBLISHED");
            spdlog::debug("Published to '{}': publication_id={}", topic, published.publication_id);
            co_return published.publication_id;
        } else {
            // Fire and forget
            co_await send_wamp_message(msg);
            spdlog::debug("Published to '{}' (no ack)", topic);
            co_return 0;
        }
    }

    // ========================================================================
    // RPC API
    // ========================================================================

    awaitable<uint64_t> register_procedure(std::string uri, InvocationHandler handler) {
        if (state_ != State::ESTABLISHED) {
            throw std::runtime_error("Not connected");
        }

        uint64_t request_id = next_request_id();
        RegisterMessage msg{request_id, {}, uri};

        auto channel = std::make_shared<RegisteredChannel>(io_, 1);
        pending_registers_[request_id] = channel;

        co_await send_wamp_message(msg);

        auto registered = co_await await_reply<RegisteredMessage>(channel, request_id, "REGISTERED");

        invocation_handlers_[registered.registration_id] = std::move(handler);
        uri_to_registration_id_[uri] = registered.registration_id;

        spdlog::debug("Registered procedure '{}': registration_id={}", uri, registered.registration_id);
        co_return registered.registration_id;
    }

    awaitable<void> unregister(uint64_t registration_id) {
        if (state_ != State::ESTABLISHED) {
            throw std::runtime_error("Not connected");
        }

        uint64_t request_id = next_request_id();
        auto channel = std::make_shared<UnregisteredChannel>(io_, 1);
        pending_unregisters_[request_id] = channel;

        co_await send_wamp_message(UnregisterMessage{request_id, registration_id});
        co_await await_reply<UnregisteredMessage>(channel, request_id, "UNREGISTERED");

        invocation_handlers_.erase(registration_id);
        std::erase_if(uri_to_registration_id_,
                      [registration_id](const auto& kv) { return kv.second == registration_id; });

        spdlog::debug("Unregistered: registration_id={}", registration_id);
    }

    // Call a procedure; returns the unwrapped result (see call_result for the full RESULT).
    // Throws WampException if the router or callee answers with an ERROR.
    awaitable<nlohmann::json> call(std::string procedure) {
        co_return co_await call(std::move(procedure), WampList{}, WampDict{});
    }

    // `timeout` (if non-zero) is sent as the CALL `timeout` option; the router fails the call with
    // wamp.error.timeout (thrown as WampException) if the callee has not answered in time.
    awaitable<nlohmann::json> call(std::string procedure, WampList args, WampDict args_kw = {},
                                   std::chrono::milliseconds timeout = std::chrono::milliseconds{0}) {
        const auto result = co_await call_result(std::move(procedure), std::move(args),
                                                 std::move(args_kw), timeout);

        // Extract result: prefer keyword arguments, then positional arguments
        if (!result.arguments_kw.empty()) {
            co_return serialize_dict(result.arguments_kw);
        } else if (!result.arguments.empty()) {
            // If single positional argument, unwrap it; otherwise return array
            if (result.arguments.size() == 1) {
                co_return variant_to_json(result.arguments[0]);
            } else {
                co_return serialize_list(result.arguments);
            }
        } else {
            co_return nlohmann::json{};
        }
    }

    // Call a procedure and return the complete RESULT message (arguments and keyword arguments).
    awaitable<ResultMessage> call_result(std::string procedure, WampList args = {}, WampDict args_kw = {},
                                         std::chrono::milliseconds timeout = std::chrono::milliseconds{0}) {
        if (state_ != State::ESTABLISHED) {
            throw std::runtime_error("Not connected");
        }

        uint64_t request_id = next_request_id();
        WampDict options;
        if (timeout.count() > 0) {
            options["timeout"] = static_cast<int64_t>(timeout.count());
        }
        CallMessage msg{request_id, std::move(options), procedure, std::move(args), std::move(args_kw)};

        auto channel = std::make_shared<ResultChannel>(io_, 1);
        pending_calls_[request_id] = channel;

        co_await send_wamp_message(msg);

        auto result = co_await await_reply<ResultMessage>(channel, request_id, "RESULT");
        spdlog::debug("Received RESULT for call to '{}'", procedure);
        co_return result;
    }

private:
    // Wait for the reply to a pending request. If the router answered with an ERROR instead,
    // throw it as a WampException.
    template<typename Reply, typename Channel>
    awaitable<Reply> await_reply(std::shared_ptr<Channel> channel, uint64_t request_id, const char* what) {
        auto [ec, reply] = co_await channel->async_receive(boost::asio::as_tuple(use_awaitable));
        if (!ec && reply.has_value()) {
            co_return std::move(*reply);
        }

        if (auto it = failed_requests_.find(request_id); it != failed_requests_.end()) {
            ErrorMessage error = std::move(it->second);
            failed_requests_.erase(it);
            throw WampException{std::move(error.error_uri), std::move(error.details),
                                std::move(error.arguments), std::move(error.arguments_kw)};
        }
        throw std::runtime_error(std::string{"Failed to receive "} + what);
    }

    // ========================================================================
    // Read Loop and Message Processing
    // ========================================================================

    awaitable<void> read_loop() {
        try {
            std::array<uint8_t, 8192> buffer{};

            while (read_loop_running_ && socket_.is_open()) {
                size_t n = co_await socket_.async_read_some(
                    boost::asio::buffer(buffer),
                    use_awaitable
                );

                if (n == 0) {
                    break;
                }

                read_buffer_.insert(read_buffer_.end(), buffer.begin(), buffer.begin() + n);
                process_buffer();
            }

            spdlog::debug("Read loop terminated");
        } catch (const boost::system::system_error& e) {
            // Closing the socket (disconnect) or the peer going away ends the loop; not an error
            if (e.code() == boost::asio::error::operation_aborted || e.code() == boost::asio::error::eof) {
                spdlog::debug("Read loop ended: {}", e.what());
            } else {
                spdlog::error("Read loop error: {}", e.what());
            }
            socket_.close();
            state_ = State::CLOSED;
        } catch (const std::exception& e) {
            spdlog::error("Read loop error: {}", e.what());
            socket_.close();
            state_ = State::CLOSED;
        }
    }

    void process_buffer() {
        while (true) {
            switch (framing_state_) {
                case FramingState::AWAITING_FRAME_HEADER:
                    if (!process_frame_header()) {
                        return;
                    }
                    break;

                case FramingState::AWAITING_FRAME_PAYLOAD:
                    if (!process_frame_payload()) {
                        return;
                    }
                    break;
            }
        }
    }

    bool process_frame_header() {
        if (read_buffer_.size() < rawsocket::FRAME_HEADER_SIZE) {
            return false;  // Not enough data
        }

        auto header_result = rawsocket::decode_frame_header(read_buffer_);
        if (!header_result.has_value()) {
            spdlog::error("Invalid frame header: {}", header_result.error().message());
            socket_.close();
            return false;
        }

        current_frame_header_ = *header_result;
        expected_payload_length_ = current_frame_header_.payload_length;

        read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + rawsocket::FRAME_HEADER_SIZE);
        framing_state_ = FramingState::AWAITING_FRAME_PAYLOAD;

        return true;
    }

    bool process_frame_payload() {
        if (read_buffer_.size() < expected_payload_length_) {
            return false;  // Not enough data
        }

        std::vector<uint8_t> payload(
            read_buffer_.begin(),
            read_buffer_.begin() + expected_payload_length_
        );

        read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + expected_payload_length_);
        framing_state_ = FramingState::AWAITING_FRAME_HEADER;

        handle_frame(current_frame_header_.type, payload);

        return true;
    }

    void handle_frame(rawsocket::FrameType type, const std::vector<uint8_t>& payload) {
        switch (type) {
            case rawsocket::FrameType::REGULAR:
                handle_wamp_message(payload);
                break;

            case rawsocket::FrameType::PING:
                spdlog::debug("Received PING, sending PONG");
                {
                    auto pong = rawsocket::create_pong(payload);
                    co_spawn(io_, [this, pong = std::move(pong)]() -> awaitable<void> {
                        co_await write_frame(pong);
                    }, detached);
                }
                break;

            case rawsocket::FrameType::PONG:
                spdlog::debug("Received PONG");
                break;

            default:
                spdlog::warn("Unknown frame type: {}", static_cast<int>(type));
        }
    }

    void handle_wamp_message(const std::vector<uint8_t>& cbor_payload) {
        auto type_result = get_message_type_from_cbor(cbor_payload);
        if (!type_result.has_value()) {
            spdlog::error("Failed to get message type");
            return;
        }

        switch (*type_result) {
            case MessageType::WELCOME:
                handle_welcome(cbor_payload);
                break;

            case MessageType::CHALLENGE:
                handle_challenge(cbor_payload);
                break;

            case MessageType::SUBSCRIBED:
                handle_subscribed(cbor_payload);
                break;

            case MessageType::PUBLISHED:
                handle_published(cbor_payload);
                break;

            case MessageType::UNSUBSCRIBED:
                handle_unsubscribed(cbor_payload);
                break;

            case MessageType::UNREGISTERED:
                handle_unregistered(cbor_payload);
                break;

            case MessageType::EVENT:
                handle_event(cbor_payload);
                break;

            case MessageType::REGISTERED:
                handle_registered(cbor_payload);
                break;

            case MessageType::INVOCATION:
                handle_invocation(cbor_payload);
                break;

            case MessageType::INTERRUPT:
                handle_interrupt(cbor_payload);
                break;

            case MessageType::RESULT:
                handle_result(cbor_payload);
                break;

            case MessageType::ERROR:
                handle_error(cbor_payload);
                break;

            case MessageType::GOODBYE:
                handle_goodbye(cbor_payload);
                break;

            default:
                spdlog::warn("Unexpected message type: {}", static_cast<int>(*type_result));
        }
    }

    // ========================================================================
    // Message Handlers
    // ========================================================================

    void handle_welcome(const std::vector<uint8_t>& cbor_payload) {
        auto welcome_result = deserialize_welcome(cbor_payload);
        if (!welcome_result.has_value()) {
            spdlog::error("Failed to deserialize WELCOME");
            socket_.close();
            return;
        }

        spdlog::info("Received WELCOME: session_id={}", welcome_result->session_id);

        welcome_channel_.try_send(boost::system::error_code(), std::make_optional(*welcome_result));
    }

    void handle_challenge(const std::vector<uint8_t>& cbor_payload) {
        auto challenge_result = deserialize_challenge(cbor_payload);
        if (!challenge_result.has_value()) {
            spdlog::error("Failed to deserialize CHALLENGE");
            socket_.close();
            return;
        }

        spdlog::info("Received CHALLENGE: authmethod={}", challenge_result->authmethod);

        // Send challenge to channel for connect_with_auth() to process
        challenge_channel_.try_send(boost::system::error_code(), std::make_optional(*challenge_result));
    }

    void handle_subscribed(const std::vector<uint8_t>& cbor_payload) {
        auto subscribed_result = deserialize_subscribed(cbor_payload);
        if (!subscribed_result.has_value()) {
            spdlog::error("Failed to deserialize SUBSCRIBED");
            return;
        }

        const auto& subscribed = *subscribed_result;

        auto it = pending_subscribes_.find(subscribed.request_id);
        if (it != pending_subscribes_.end()) {
            it->second->try_send(boost::system::error_code(), std::make_optional(subscribed));
            pending_subscribes_.erase(it);
        } else {
            spdlog::warn("Received SUBSCRIBED for unknown request_id={}", subscribed.request_id);
        }
    }

    void handle_unsubscribed(const std::vector<uint8_t>& cbor_payload) {
        auto unsubscribed_result = deserialize_unsubscribed(cbor_payload);
        if (!unsubscribed_result.has_value()) {
            spdlog::error("Failed to deserialize UNSUBSCRIBED");
            return;
        }

        const auto& unsubscribed = *unsubscribed_result;

        auto it = pending_unsubscribes_.find(unsubscribed.request_id);
        if (it != pending_unsubscribes_.end()) {
            it->second->try_send(boost::system::error_code(), std::make_optional(unsubscribed));
            pending_unsubscribes_.erase(it);
        } else {
            spdlog::warn("Received UNSUBSCRIBED for unknown request_id={}", unsubscribed.request_id);
        }
    }

    void handle_unregistered(const std::vector<uint8_t>& cbor_payload) {
        auto unregistered_result = deserialize_unregistered(cbor_payload);
        if (!unregistered_result.has_value()) {
            spdlog::error("Failed to deserialize UNREGISTERED");
            return;
        }

        const auto& unregistered = *unregistered_result;

        auto it = pending_unregisters_.find(unregistered.request_id);
        if (it != pending_unregisters_.end()) {
            it->second->try_send(boost::system::error_code(), std::make_optional(unregistered));
            pending_unregisters_.erase(it);
        } else {
            spdlog::warn("Received UNREGISTERED for unknown request_id={}", unregistered.request_id);
        }
    }

    void handle_published(const std::vector<uint8_t>& cbor_payload) {
        auto published_result = deserialize_published(cbor_payload);
        if (!published_result.has_value()) {
            spdlog::error("Failed to deserialize PUBLISHED");
            return;
        }

        const auto& published = *published_result;

        auto it = pending_publishes_.find(published.request_id);
        if (it != pending_publishes_.end()) {
            it->second->try_send(boost::system::error_code(), std::make_optional(published));
            pending_publishes_.erase(it);
        } else {
            spdlog::warn("Received PUBLISHED for unknown request_id={}", published.request_id);
        }
    }

    void handle_event(const std::vector<uint8_t>& cbor_payload) {
        auto event_result = deserialize_event(cbor_payload);
        if (!event_result.has_value()) {
            spdlog::error("Failed to deserialize EVENT");
            return;
        }

        const auto& event = *event_result;

        auto it = event_handlers_.find(event.subscription_id);
        if (it != event_handlers_.end()) {
            spdlog::debug("Dispatching EVENT: subscription_id={}", event.subscription_id);
            it->second(event);
        } else {
            spdlog::warn("Received EVENT for unknown subscription_id={}", event.subscription_id);
        }
    }

    void handle_registered(const std::vector<uint8_t>& cbor_payload) {
        auto registered_result = deserialize_registered(cbor_payload);
        if (!registered_result.has_value()) {
            spdlog::error("Failed to deserialize REGISTERED");
            return;
        }

        const auto& registered = *registered_result;

        auto it = pending_registers_.find(registered.request_id);
        if (it != pending_registers_.end()) {
            it->second->try_send(boost::system::error_code(), std::make_optional(registered));
            pending_registers_.erase(it);
        } else {
            spdlog::warn("Received REGISTERED for unknown request_id={}", registered.request_id);
        }
    }

    void handle_invocation(const std::vector<uint8_t>& cbor_payload) {
        auto invocation_result = deserialize_invocation(cbor_payload);
        if (!invocation_result.has_value()) {
            spdlog::error("Failed to deserialize INVOCATION");
            return;
        }

        const auto& invocation = *invocation_result;

        auto it = invocation_handlers_.find(invocation.registration_id);
        if (it != invocation_handlers_.end()) {
            spdlog::debug("Dispatching INVOCATION: registration_id={}, request_id={}",
                         invocation.registration_id, invocation.request_id);

            // Spawn coroutine to handle invocation
            auto handler = it->second;
            auto signal = std::make_shared<boost::asio::cancellation_signal>();
            running_invocations_[invocation.request_id] = signal;
            co_spawn(io_, handle_invocation_async(handler, invocation, signal),
                     boost::asio::bind_cancellation_slot(signal->slot(), detached));
        } else {
            spdlog::warn("Received INVOCATION for unknown registration_id={}", invocation.registration_id);
        }
    }

    // INTERRUPT: cancel the handler's pending operation; it then answers with wamp.error.canceled
    void handle_interrupt(const std::vector<uint8_t>& cbor_payload) {
        auto interrupt = deserialize_interrupt(cbor_payload);
        if (!interrupt.has_value()) {
            spdlog::error("Failed to deserialize INTERRUPT");
            return;
        }
        auto it = running_invocations_.find(interrupt->request_id);
        if (it == running_invocations_.end()) {
            spdlog::debug("INTERRUPT for finished invocation {}", interrupt->request_id);
            return;
        }
        spdlog::debug("INTERRUPT: canceling invocation {}", interrupt->request_id);
        auto signal = it->second;  // the handler may finish and erase the entry while emitting
        signal->emit(boost::asio::cancellation_type::terminal);
    }

    // `signal` is a parameter so it outlives the coroutine, whose cancellation slot refers to it
    awaitable<void> handle_invocation_async(InvocationHandler handler, InvocationMessage invocation,
                                            std::shared_ptr<boost::asio::cancellation_signal> signal) {
        (void)signal;
        std::optional<ErrorMessage> error;
        bool canceled = false;

        try {
            auto yield = co_await handler(invocation);
            running_invocations_.erase(invocation.request_id);
            co_await send_wamp_message(yield);
        } catch (const boost::system::system_error& e) {
            if (e.code() != boost::asio::error::operation_aborted) {
                spdlog::error("Invocation handler error: {}", e.what());
                error = ErrorMessage{MessageType::INVOCATION, invocation.request_id,
                                     {{"message", std::string{e.what()}}}, "wamp.error.callee_failure"};
            } else {
                canceled = true;
            }
        } catch (const WampException& e) {
            // Handler chose the error URI/payload to send back to the caller
            spdlog::debug("Invocation handler raised {}", e.error_uri);
            error = ErrorMessage{MessageType::INVOCATION, invocation.request_id, e.details,
                                 e.error_uri, e.arguments, e.arguments_kw};
        } catch (const std::exception& e) {
            spdlog::error("Invocation handler error: {}", e.what());
            error = ErrorMessage{MessageType::INVOCATION, invocation.request_id,
                                 {{"message", std::string{e.what()}}}, "wamp.error.callee_failure"};
        }

        running_invocations_.erase(invocation.request_id);
        if (canceled) {
            // Awaiting again would throw while the cancellation state is set
            co_await boost::asio::this_coro::reset_cancellation_state();
            error = ErrorMessage::create_canceled(invocation.request_id, "Invocation interrupted");
        }
        if (error.has_value()) {
            co_await send_wamp_message(*error);
        }
    }

    void handle_result(const std::vector<uint8_t>& cbor_payload) {
        auto result_result = deserialize_result(cbor_payload);
        if (!result_result.has_value()) {
            spdlog::error("Failed to deserialize RESULT");
            return;
        }

        const auto& result = *result_result;

        auto it = pending_calls_.find(result.request_id);
        if (it != pending_calls_.end()) {
            it->second->try_send(boost::system::error_code(), std::make_optional(result));
            pending_calls_.erase(it);
        } else {
            spdlog::warn("Received RESULT for unknown request_id={}", result.request_id);
        }
    }

    void handle_error(const std::vector<uint8_t>& cbor_payload) {
        auto error_result = deserialize_error(cbor_payload);
        if (!error_result.has_value()) {
            spdlog::error("Failed to deserialize ERROR");
            return;
        }

        const auto& error = *error_result;
        spdlog::error("Received ERROR: uri={}, request_id={}, request_type={}",
                     error.error_uri, error.request_id, static_cast<int>(error.request_type));

        // Route error to the appropriate pending operation based on request_type.
        // The ERROR is stashed so the awaiting coroutine can rethrow it as a WampException.
        auto ec = boost::asio::error::operation_aborted;
        failed_requests_.insert_or_assign(error.request_id, error);

        switch (error.request_type) {
            case MessageType::SUBSCRIBE: {
                auto it = pending_subscribes_.find(error.request_id);
                if (it != pending_subscribes_.end()) {
                    it->second->try_send(ec, std::nullopt);
                    pending_subscribes_.erase(it);
                }
                break;
            }

            case MessageType::PUBLISH: {
                auto it = pending_publishes_.find(error.request_id);
                if (it != pending_publishes_.end()) {
                    it->second->try_send(ec, std::nullopt);
                    pending_publishes_.erase(it);
                }
                break;
            }

            case MessageType::UNSUBSCRIBE: {
                auto it = pending_unsubscribes_.find(error.request_id);
                if (it != pending_unsubscribes_.end()) {
                    it->second->try_send(ec, std::nullopt);
                    pending_unsubscribes_.erase(it);
                }
                break;
            }

            case MessageType::UNREGISTER: {
                auto it = pending_unregisters_.find(error.request_id);
                if (it != pending_unregisters_.end()) {
                    it->second->try_send(ec, std::nullopt);
                    pending_unregisters_.erase(it);
                }
                break;
            }

            case MessageType::REGISTER: {
                auto it = pending_registers_.find(error.request_id);
                if (it != pending_registers_.end()) {
                    it->second->try_send(ec, std::nullopt);
                    pending_registers_.erase(it);
                }
                break;
            }

            case MessageType::CALL: {
                auto it = pending_calls_.find(error.request_id);
                if (it != pending_calls_.end()) {
                    it->second->try_send(ec, std::nullopt);
                    pending_calls_.erase(it);
                }
                break;
            }

            default:
                failed_requests_.erase(error.request_id);
                spdlog::warn("Unhandled ERROR for request_type={}", static_cast<int>(error.request_type));
                break;
        }
    }

    void handle_goodbye(const std::vector<uint8_t>& cbor_payload) {
        auto goodbye_result = deserialize_goodbye(cbor_payload);
        if (!goodbye_result.has_value()) {
            spdlog::error("Failed to deserialize GOODBYE");
            return;
        }

        spdlog::info("Received GOODBYE: {}", goodbye_result->reason);

        // Signal disconnect() coroutine if it's waiting
        goodbye_channel_.try_send(boost::system::error_code(), std::make_optional(*goodbye_result));

        // Note: socket close and state change are handled by disconnect()
    }

    // ========================================================================
    // Sending Messages
    // ========================================================================

    awaitable<void> send_rawsocket_handshake() {
        state_ = State::AWAITING_RAWSOCKET_RESPONSE;

        rawsocket::HandshakeRequest request{
            .max_length = rawsocket::MaxLengthCode::BYTES_16M,
            .serializer = rawsocket::Serializer::CBOR
        };

        auto handshake_bytes = rawsocket::encode_handshake_request(request);
        co_await boost::asio::async_write(
            socket_,
            boost::asio::buffer(handshake_bytes),
            use_awaitable
        );

        spdlog::debug("Sent RawSocket handshake request");

        // Read handshake response (4 bytes)
        std::array<uint8_t, 4> response{};
        co_await boost::asio::async_read(
            socket_,
            boost::asio::buffer(response),
            use_awaitable
        );

        // Check if it's an error response
        if (rawsocket::is_handshake_error(response)) {
            throw std::runtime_error("RawSocket handshake failed");
        }

        // Decode success response
        auto success_result = rawsocket::decode_handshake_request(response);
        if (!success_result.has_value()) {
            throw std::runtime_error("Invalid RawSocket handshake response");
        }

        spdlog::debug("RawSocket handshake successful");
    }

    awaitable<void> send_hello() {
        spdlog::info("send_hello() called, preparing HELLO message");

        HelloMessage hello = HelloMessage::create_client(realm_);

        // Add authentication info if provided
        if (authid_.has_value()) {
            hello.authid = *authid_;
            hello.authmethods = std::vector<std::string>{"cryptosign"};
            state_ = State::AWAITING_CHALLENGE;
            spdlog::info("HELLO will include authid='{}', authmethods=['cryptosign']", *authid_);
        } else {
            state_ = State::AWAITING_WELCOME;
        }

        auto hello_cbor = serialize_hello(hello);
        auto hello_frame = rawsocket::create_wamp_message(hello_cbor);

        spdlog::info("Sending HELLO frame ({} bytes)", hello_frame.size());

        co_await boost::asio::async_write(
            socket_,
            boost::asio::buffer(hello_frame),
            use_awaitable
        );

        spdlog::info("Sent HELLO for realm '{}'", realm_);
    }

    awaitable<void> handle_challenge_and_authenticate(const ChallengeMessage& challenge) {
        spdlog::info("Handling CHALLENGE with authmethod='{}'", challenge.authmethod);

        if (challenge.authmethod != "cryptosign") {
            throw std::runtime_error("Unsupported auth method: " + challenge.authmethod);
        }

        // Extract challenge nonce from extra
        auto it = challenge.extra.find("challenge");
        if (it == challenge.extra.end()) {
            throw std::runtime_error("CHALLENGE missing 'challenge' field in extra");
        }
        const std::string& challenge_nonce = it->second;

        spdlog::debug("Challenge nonce: {}", challenge_nonce);

        // Cryptosign: sign the raw challenge bytes
        auto signature_result = sign_challenge(challenge_nonce, private_key_.get());
        if (!signature_result.has_value()) {
            throw std::runtime_error("Failed to sign challenge: " + signature_result.error());
        }

        spdlog::debug("Signature: {}", *signature_result);

        // Send AUTHENTICATE message
        state_ = State::AWAITING_WELCOME;

        AuthenticateMessage auth{*signature_result};
        auto auth_cbor = serialize_authenticate(auth);
        auto auth_frame = rawsocket::create_wamp_message(auth_cbor);

        co_await boost::asio::async_write(
            socket_,
            boost::asio::buffer(auth_frame),
            use_awaitable
        );

        spdlog::info("Sent AUTHENTICATE message");
    }

    template<typename MessageType>
    awaitable<void> send_wamp_message(const MessageType& msg) {
        std::vector<uint8_t> cbor_payload;

        if constexpr (std::is_same_v<MessageType, SubscribeMessage>) {
            cbor_payload = serialize_subscribe(msg);
        } else if constexpr (std::is_same_v<MessageType, UnsubscribeMessage>) {
            cbor_payload = serialize_unsubscribe(msg);
        } else if constexpr (std::is_same_v<MessageType, UnregisterMessage>) {
            cbor_payload = serialize_unregister(msg);
        } else if constexpr (std::is_same_v<MessageType, PublishMessage>) {
            cbor_payload = serialize_publish(msg);
        } else if constexpr (std::is_same_v<MessageType, RegisterMessage>) {
            cbor_payload = serialize_register(msg);
        } else if constexpr (std::is_same_v<MessageType, CallMessage>) {
            cbor_payload = serialize_call(msg);
        } else if constexpr (std::is_same_v<MessageType, YieldMessage>) {
            cbor_payload = serialize_yield(msg);
        } else if constexpr (std::is_same_v<MessageType, ErrorMessage>) {
            cbor_payload = serialize_error(msg);
        } else if constexpr (std::is_same_v<MessageType, GoodbyeMessage>) {
            cbor_payload = serialize_goodbye(msg);
        } else {
            static_assert(sizeof(MessageType) == 0, "Unsupported message type");
        }

        auto frame = rawsocket::create_wamp_message(cbor_payload);
        co_await write_frame(frame);
    }

    // Asio forbids overlapping async_write calls on one socket, and concurrent coroutines
    // (e.g. several invocation handlers answering at once) would interleave frames.
    // Writers take turns: later ones wait on a timer that the previous writer cancels.
    awaitable<void> write_frame(const std::vector<uint8_t>& frame) {
        while (write_in_progress_) {
            boost::asio::steady_timer gate{io_, boost::asio::steady_timer::time_point::max()};
            write_waiters_.push_back(&gate);
            co_await gate.async_wait(boost::asio::as_tuple(use_awaitable));
        }
        write_in_progress_ = true;

        auto [ec, written] = co_await boost::asio::async_write(
            socket_,
            boost::asio::buffer(frame),
            boost::asio::as_tuple(use_awaitable)
        );
        (void)written;

        write_in_progress_ = false;
        if (!write_waiters_.empty()) {
            auto* next = write_waiters_.front();
            write_waiters_.pop_front();
            next->cancel();
        }

        if (ec) {
            throw boost::system::system_error{ec};
        }
    }

    uint64_t next_request_id() {
        return next_request_id_++;
    }

    // ========================================================================
    // State
    // ========================================================================

    enum class State {
        DISCONNECTED,
        CONNECTING,
        AWAITING_RAWSOCKET_RESPONSE,
        AWAITING_WELCOME,
        AWAITING_CHALLENGE,
        AWAITING_AUTHENTICATE,
        ESTABLISHED,
        CLOSING,
        CLOSED
    };

    enum class FramingState {
        AWAITING_FRAME_HEADER,
        AWAITING_FRAME_PAYLOAD
    };

    boost::asio::io_context& io_;
    tcp::socket socket_;

    State state_;
    FramingState framing_state_;

    // Buffering
    std::vector<uint8_t> read_buffer_;
    rawsocket::FrameHeader current_frame_header_{};
    uint32_t expected_payload_length_;

    // Session info
    uint64_t session_id_;
    std::string realm_;

    // Read loop control
    std::atomic<bool> read_loop_running_;

    // Write serialization (see write_frame)
    bool write_in_progress_ = false;
    std::deque<boost::asio::steady_timer*> write_waiters_;

    // Request ID generation
    std::atomic<uint64_t> next_request_id_{1};

    // Connection establishment
    using WelcomeChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<WelcomeMessage>)>;
    WelcomeChannel welcome_channel_;

    // Disconnection
    using GoodbyeChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<GoodbyeMessage>)>;
    GoodbyeChannel goodbye_channel_;

    // Authentication
    using ChallengeChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<ChallengeMessage>)>;
    ChallengeChannel challenge_channel_;
    std::optional<std::string> authid_;
    std::unique_ptr<EVP_PKEY, PKEYDeleter> private_key_;

    // Pending requests (using channels for async awaiting with optional for default-constructibility)
    using SubscribedChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<SubscribedMessage>)>;
    using PublishedChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<PublishedMessage>)>;
    using RegisteredChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<RegisteredMessage>)>;
    using ResultChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<ResultMessage>)>;
    std::unordered_map<uint64_t, std::shared_ptr<SubscribedChannel>> pending_subscribes_;
    std::unordered_map<uint64_t, std::shared_ptr<PublishedChannel>> pending_publishes_;
    std::unordered_map<uint64_t, std::shared_ptr<RegisteredChannel>> pending_registers_;
    std::unordered_map<uint64_t, std::shared_ptr<ResultChannel>> pending_calls_;
    using UnsubscribedChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<UnsubscribedMessage>)>;
    using UnregisteredChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::optional<UnregisteredMessage>)>;
    std::unordered_map<uint64_t, std::shared_ptr<UnsubscribedChannel>> pending_unsubscribes_;
    std::unordered_map<uint64_t, std::shared_ptr<UnregisteredChannel>> pending_unregisters_;

    // ERRORs received for pending requests, keyed by request_id, until the waiter rethrows them
    std::unordered_map<uint64_t, ErrorMessage> failed_requests_;

    // Subscription and registration handlers
    std::unordered_map<uint64_t, EventCallback> event_handlers_;
    std::unordered_map<std::string, uint64_t> topic_to_subscription_id_;
    std::unordered_map<uint64_t, InvocationHandler> invocation_handlers_;
    std::unordered_map<uint64_t, std::shared_ptr<boost::asio::cancellation_signal>> running_invocations_;
    std::unordered_map<std::string, uint64_t> uri_to_registration_id_;
};

} // namespace wamp
