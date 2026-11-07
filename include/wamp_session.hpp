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

#include "raw_socket.hpp"
#include "wamp_messages.hpp"
#include "wamp_serializer.hpp"
#include "wamp_id.hpp"
#include "pubsub_handler.hpp"
#include "procedure_handler.hpp"
#include "event_channel.hpp"
#include "config.hpp"
#include "authorizer.hpp"
#include "crypto_utils.hpp"
#include <asio/io_context.hpp>
#include <spdlog/spdlog.h>
#include <vector>
#include <span>
#include <expected>
#include <system_error>
#include <cstdint>

namespace wamp {

// RawSocket framing states
enum class SessionProtocolState {
    AWAITING_RAWSOCKET_HANDSHAKE,  // Waiting for 4-byte handshake
    AWAITING_FRAME_HEADER,          // Waiting for 4-byte frame header
    AWAITING_FRAME_PAYLOAD,         // Waiting for N bytes of payload
    AWAITING_AUTHENTICATE,          // Waiting for AUTHENTICATE after CHALLENGE sent
    SHUTTING_DOWN,                  // GOODBYE initiated
    CLOSED                          // Session closed
};

// ============================================================================
// WampSession - Handles buffering and protocol state machine
// ============================================================================
class WampSession {
public:
    explicit WampSession(asio::io_context& io, const ServerConfig& config, Shard& shard)
        : io_(io)
        , config_(config)
        , shard_(shard)
        , state_(SessionProtocolState::AWAITING_RAWSOCKET_HANDSHAKE)
        , expected_payload_length_(0)
        , session_id_(0)
        , wamp_session_established_(false)
    {
        spdlog::debug("WAMP session created");
    }

    WampSession(const WampSession&) = delete;
    WampSession& operator=(const WampSession&) = delete;

    // The session coroutine can be destroyed without seeing EOF (e.g. io_context shutdown),
    // so make sure global subscriptions/registrations never outlive the session.
    ~WampSession() {
        if (!disconnected_) {
            on_disconnect();
        }
    }

    [[nodiscard]] Shard& shard() const {
        return shard_;
    }

    // Get session ID (0 if not yet established)
    [[nodiscard]] uint64_t session_id() const {
        return session_id_;
    }

    // Check if WAMP session is established (HELLO/WELCOME handshake complete)
    [[nodiscard]] bool is_established() const {
        return wamp_session_established_;
    }

    // Called when TCP connection is established
    void on_connect() {
        // Connection state is managed internally
    }

    // Called when TCP connection closes
    void on_disconnect() {
        state_ = SessionProtocolState::CLOSED;
        disconnected_ = true;

        // Clean up all subscriptions and registrations for this session
        if (session_id_ != 0) {
            if (realm_ptr_) {
                PubSubHandler::cleanup_session(*realm_ptr_, session_id_);
                ProcedureHandler::cleanup_session(*realm_ptr_, session_id_);
            }
            shard_.channels.remove(session_id_);
        }

        spdlog::info("WAMP session disconnected");
    }

    // Consumes all complete frames in the buffer (a single socket read can carry several
    // pipelined messages). Returns a view of the concatenated responses, valid until the next
    // call (empty span = no response).
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process(std::span<const uint8_t> data) {
        auto result = process_input(data);
        compact_buffer();
        return result;
    }

private:
    // Consumed bytes are skipped with read_pos_ instead of erased one frame at a time (each erase
    // moves everything behind it, which is quadratic when a read carries hundreds of small frames);
    // process() drops them once per call.
    void compact_buffer() {
        if (read_pos_ == buffer_.size()) {
            buffer_.clear();
        } else if (read_pos_ > 0) {
            buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(read_pos_));
        }
        read_pos_ = 0;
    }

    [[nodiscard]] size_t unread() const { return buffer_.size() - read_pos_; }

    [[nodiscard]] std::span<const uint8_t> unread_span() const {
        return std::span<const uint8_t>{buffer_}.subspan(read_pos_);
    }

    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_input(std::span<const uint8_t> data) {
        buffer_.insert(buffer_.end(), data.begin(), data.end());
        output_buffer_.clear();
        // Sends parked by earlier callers that never flushed them must not leak into this session's turn
        shard_.channels.clear_blocked();

        spdlog::debug("Received {} bytes, buffer now {} bytes in state {}",
                     data.size(), unread(), state_name());

        bool progressed = false;
        while (true) {
            const auto state_before = state_;
            const auto size_before = unread();

            std::expected<std::span<const uint8_t>, std::error_code> result{std::span<const uint8_t>{}};
            switch (state_) {
                case SessionProtocolState::AWAITING_RAWSOCKET_HANDSHAKE:
                    result = process_rawsocket_handshake();
                    break;

                case SessionProtocolState::AWAITING_FRAME_HEADER:
                    result = process_frame_header();
                    break;

                case SessionProtocolState::AWAITING_AUTHENTICATE:
                    // After CHALLENGE sent, client must send AUTHENTICATE
                    result = process_frame_payload_authenticate();
                    break;

                case SessionProtocolState::AWAITING_FRAME_PAYLOAD:
                    result = process_frame_payload();
                    break;

                case SessionProtocolState::SHUTTING_DOWN:
                case SessionProtocolState::CLOSED:
                default:
                    // Frames handled earlier in this call (e.g. the GOODBYE reply) still get sent
                    if (progressed) {
                        return std::span<const uint8_t>(output_buffer_);
                    }
                    return std::unexpected{make_error_code(WampError::INVALID_STATE)};
            }

            if (!result.has_value()) {
                return std::unexpected{result.error()};
            }
            output_buffer_.insert(output_buffer_.end(), result->begin(), result->end());

            const bool made_progress = state_ != state_before || unread() != size_before;
            progressed = progressed || made_progress;

            // Keep going only while input is being consumed and the session is ready for the
            // next frame; after an ABORT or other terminal reply, stop and let the caller act.
            const bool ready_for_more = result->empty() || state_ == SessionProtocolState::AWAITING_FRAME_HEADER;
            if (!made_progress || !ready_for_more) {
                return std::span<const uint8_t>(output_buffer_);
            }
        }
    }

private:
    // Process RawSocket handshake (expecting 4 bytes)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_rawsocket_handshake() {
        if (unread() < rawsocket::HANDSHAKE_SIZE) {
            // Not enough data yet
            return std::span<const uint8_t>{};
        }

        auto handshake_result = rawsocket::decode_handshake_request(unread_span());
        if (!handshake_result.has_value()) {
            spdlog::error("Invalid RawSocket handshake: {}",
                         handshake_result.error().message());

            auto error_response = rawsocket::encode_handshake_error(
                rawsocket::HandshakeError::SERIALIZER_UNSUPPORTED
            );

            response_buffer_.assign(error_response.begin(), error_response.end());
            return std::span<const uint8_t>(response_buffer_);
        }

        const auto& handshake = *handshake_result;

        spdlog::info("RawSocket handshake: serializer={}, max_length={}",
                    static_cast<int>(handshake.serializer),
                    static_cast<int>(handshake.max_length));

        // Validate serializer (we only support CBOR = 3)
        if (handshake.serializer != rawsocket::Serializer::CBOR) {
            spdlog::warn("Unsupported serializer requested: {}",
                        static_cast<int>(handshake.serializer));

            auto error_response = rawsocket::encode_handshake_error(
                rawsocket::HandshakeError::SERIALIZER_UNSUPPORTED
            );

            response_buffer_.assign(error_response.begin(), error_response.end());
            return std::span<const uint8_t>(response_buffer_);
        }

        serializer_ = handshake.serializer;
        max_length_ = handshake.max_length;

        auto success_response = rawsocket::encode_handshake_success({
            .max_length = handshake.max_length,
            .serializer = handshake.serializer
        });

        read_pos_ += rawsocket::HANDSHAKE_SIZE;

        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        spdlog::info("RawSocket handshake complete, awaiting WAMP HELLO");

        response_buffer_.assign(success_response.begin(), success_response.end());
        return std::span<const uint8_t>(response_buffer_);
    }

    // Process frame header (expecting 4 bytes)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_frame_header() {
        if (unread() < rawsocket::FRAME_HEADER_SIZE) {
            // Not enough data yet
            return std::span<const uint8_t>{};
        }

        // Decode frame header
        auto header_result = rawsocket::decode_frame_header(unread_span());
        if (!header_result.has_value()) {
            spdlog::error("Invalid frame header: {}", header_result.error().message());
            return std::unexpected{header_result.error()};
        }

        current_frame_header_ = *header_result;

        spdlog::debug("Frame header: type={}, payload_length={}",
                     static_cast<int>(current_frame_header_.type),
                     current_frame_header_.payload_length);

        // Validate payload length against negotiated max
        if (max_length_.has_value() &&
            !rawsocket::validate_payload_length(
                current_frame_header_.payload_length, *max_length_)) {
            spdlog::error("Payload length {} exceeds negotiated max",
                         current_frame_header_.payload_length);
            return std::unexpected{
                rawsocket::make_error_code(rawsocket::RawSocketError::PAYLOAD_TOO_LARGE)};
        }
        read_pos_ += rawsocket::FRAME_HEADER_SIZE;

        expected_payload_length_ = current_frame_header_.payload_length;

        // If we're expecting an AUTHENTICATE message (after CHALLENGE), go to that state
        if (expect_authenticate_) {
            state_ = SessionProtocolState::AWAITING_AUTHENTICATE;
        } else {
            state_ = SessionProtocolState::AWAITING_FRAME_PAYLOAD;
        }

        // Continue processing if payload is already in buffer
        return std::span<const uint8_t>{};
    }

    // Process frame payload (expecting expected_payload_length_ bytes)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_frame_payload() {
        if (unread() < expected_payload_length_) {
            // Not enough data yet
            spdlog::debug("Waiting for payload: have {} bytes, need {}",
                         unread(), expected_payload_length_);
            return std::span<const uint8_t>{};
        }
        std::vector<uint8_t> payload(
            buffer_.begin() + static_cast<std::ptrdiff_t>(read_pos_),
            buffer_.begin() + static_cast<std::ptrdiff_t>(read_pos_ + expected_payload_length_)
        );

        read_pos_ += expected_payload_length_;

        spdlog::debug("Received complete frame payload: {} bytes", payload.size());

        auto result = handle_frame(current_frame_header_.type, payload);

        // Return to frame header state for next message
        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        return result;
    }

    // Process frame payload during authentication (only AUTHENTICATE allowed)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_frame_payload_authenticate() {
        if (unread() < expected_payload_length_) {
            // Not enough data yet
            spdlog::debug("Waiting for payload: have {} bytes, need {}",
                         unread(), expected_payload_length_);
            return std::span<const uint8_t>{};
        }

        std::vector<uint8_t> payload(
            buffer_.begin() + static_cast<std::ptrdiff_t>(read_pos_),
            buffer_.begin() + static_cast<std::ptrdiff_t>(read_pos_ + expected_payload_length_)
        );

        read_pos_ += expected_payload_length_;

        spdlog::debug("Received complete frame payload during auth: {} bytes", payload.size());

        // Only handle REGULAR frames during authentication
        if (current_frame_header_.type != rawsocket::FrameType::REGULAR) {
            spdlog::error("Unexpected frame type during authentication");
            auto abort = AbortMessage::create_not_authorized("Protocol violation");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        // Verify it's an AUTHENTICATE message
        auto type_result = get_message_type_from_cbor(payload);
        if (!type_result.has_value() || *type_result != MessageType::AUTHENTICATE) {
            spdlog::error("Expected AUTHENTICATE message, got something else");
            auto abort = AbortMessage::create_not_authorized("Expected AUTHENTICATE message");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        // Handle AUTHENTICATE message
        expect_authenticate_ = false;  // Reset the flag
        auto result = handle_authenticate_message(payload);

        // Note: state transition happens in handle_authenticate_message()
        // Either to AWAITING_FRAME_HEADER (success) or stays in auth state (error returns ABORT)

        return result;
    }

    // Handle complete frame based on type
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> handle_frame(
        rawsocket::FrameType type,
        const std::vector<uint8_t>& payload
    ) {
        switch (type) {
            case rawsocket::FrameType::REGULAR:
                return handle_wamp_message(payload);

            case rawsocket::FrameType::PING:
                spdlog::debug("Received PING, sending PONG");
                response_buffer_ = rawsocket::create_pong(std::span{payload.data(), payload.size()});
                return std::span<const uint8_t>(response_buffer_);
            case rawsocket::FrameType::PONG:
                spdlog::debug("Received PONG");
                return std::span<const uint8_t>{};

            default:
                return std::unexpected{
                    rawsocket::make_error_code(rawsocket::RawSocketError::INVALID_FRAME_TYPE)};
        }
    }

    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> handle_wamp_message(
        const std::vector<uint8_t>& payload
    ) {
        if (!wamp_session_established_) {
            // First WAMP message after RawSocket handshake - should be HELLO
            return handle_hello_message(payload);
        } else {
            // Session is active, handle various message types
            return handle_established_message(payload);
        }
    }

    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> handle_hello_message(
        const std::vector<uint8_t>& cbor_payload
    ) {
        spdlog::info("Processing HELLO message");

        auto hello_result = deserialize_hello(cbor_payload);
        if (!hello_result.has_value()) {
            spdlog::error("Failed to deserialize HELLO: {}",
                         hello_result.error().message());

            auto abort = AbortMessage::create_not_authorized("Invalid HELLO message");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);

            return std::span<const uint8_t>(response_buffer_);
        }

        const auto& hello = *hello_result;
        realm_ = hello.realm;  // Store realm for later

        if (config_.auth_keys.empty()) {
            spdlog::info("No authentication configured, establishing session for realm '{}'", realm_);

            session_id_ = shard_.ids.session.generate();
            wamp_session_established_ = true;
            realm_ptr_ = &shard_.realms.get(realm_);

            WelcomeMessage welcome{session_id_, realm_};
            auto welcome_cbor = serialize_welcome(welcome);
            response_buffer_ = rawsocket::create_wamp_message(welcome_cbor);

            spdlog::info("Session {} established (no auth)", session_id_);
            return std::span<const uint8_t>(response_buffer_);
        }

        // Require cryptosign authentication
        if (!hello.authmethods.has_value() ||
            std::ranges::find(hello.authmethods->begin(), hello.authmethods->end(), "cryptosign") ==
                hello.authmethods->end()) {
            spdlog::warn("Client does not support cryptosign authentication");
            auto abort = AbortMessage::create_not_authorized(
                "Only cryptosign authentication is supported");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        // Require authid
        if (!hello.authid.has_value() || hello.authid->empty()) {
            spdlog::warn("Client did not provide authid");
            auto abort = AbortMessage::create_not_authorized("authid is required");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        // Verify authid exists in configuration
        if (!config_.auth_keys.contains(*hello.authid)) {
            spdlog::warn("Unknown authid: {}", *hello.authid);
            auto abort = AbortMessage::create_not_authorized("Unknown authid");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        // The authid must be allowed to join the requested realm. The same error covers unknown and
        // disallowed realms so a client cannot probe which realms exist.
        if (!config_.may_join(*hello.authid, realm_)) {
            spdlog::warn("authid '{}' is not allowed to join realm '{}'", *hello.authid, realm_);
            auto abort = AbortMessage::create_not_authorized("Not allowed to join this realm");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        // Generate cryptographic challenge
        pending_authid_ = *hello.authid;
        pending_challenge_ = generate_challenge();

        if (pending_challenge_.empty()) {
            spdlog::error("Failed to generate challenge");
            auto abort = AbortMessage::create_not_authorized("Internal error");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        spdlog::info("Sending CHALLENGE to authid={}", pending_authid_);

        auto challenge = ChallengeMessage::create_cryptosign(pending_challenge_);
        auto challenge_cbor = serialize_challenge(challenge);
        response_buffer_ = rawsocket::create_wamp_message(challenge_cbor);

        // Go to frame header state, and flag that we expect AUTHENTICATE
        expect_authenticate_ = true;
        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        return std::span<const uint8_t>(response_buffer_);
    }

    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> handle_authenticate_message(
        const std::vector<uint8_t>& cbor_payload
    ) {
        spdlog::info("Processing AUTHENTICATE message from authid={}", pending_authid_);

        auto authenticate_result = deserialize_authenticate(cbor_payload);
        if (!authenticate_result.has_value()) {
            spdlog::error("Failed to deserialize AUTHENTICATE: {}",
                         authenticate_result.error().message());

            auto abort = AbortMessage::create_not_authorized("Invalid AUTHENTICATE message");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);

            return std::span<const uint8_t>(response_buffer_);
        }

        const auto& authenticate = *authenticate_result;

        // Get public key from configuration
        auto it = config_.auth_keys.find(pending_authid_);
        if (it == config_.auth_keys.end()) {
            spdlog::error("Public key not found for authid={}", pending_authid_);
            auto abort = AbortMessage::create_not_authorized("Unknown authid");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        const std::string& public_key_hex = it->second;

        // Cryptosign: the client signs the raw challenge bytes
        bool signature_valid = verify_challenge_signature(
            authenticate.signature,
            pending_challenge_,
            public_key_hex
        );

        if (!signature_valid) {
            spdlog::warn("Invalid signature from authid={}", pending_authid_);
            auto abort = AbortMessage::create_not_authorized("Invalid signature");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        session_id_ = shard_.ids.session.generate();
        wamp_session_established_ = true;
        realm_ptr_ = &shard_.realms.get(realm_);
        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        spdlog::info("Authentication successful: session_id={}, authid={}, realm={}",
                    session_id_, pending_authid_, realm_);

        shard_.channels.get_or_create(session_id_, io_);

        // Resolve the authid's permissions; an authid without a role may connect but do nothing
        static const Permissions no_permissions;
        authid_ = pending_authid_;
        role_name_ = "none";
        role_ = &no_permissions;
        if (auto role_it = config_.auth_roles.find(authid_); role_it != config_.auth_roles.end()) {
            const std::string& role_name = role_it->second.role_for(realm_);
            if (auto def = config_.roles.find(role_name); def != config_.roles.end()) {
                role_name_ = role_name;
                role_ = &def->second;
            }
        }

        auto welcome = WelcomeMessage::create_router(session_id_, realm_);
        welcome.authid = pending_authid_;
        welcome.authrole = role_name_;
        welcome.authmethod = "cryptosign";

        auto welcome_cbor = serialize_welcome(welcome);
        response_buffer_ = rawsocket::create_wamp_message(welcome_cbor);

        pending_authid_.clear();
        pending_challenge_.clear();

        return std::span<const uint8_t>(response_buffer_);
    }

    // True if this session may perform `action` on `uri`; logs the denial otherwise
    [[nodiscard]] bool is_authorized(Action action, const std::string& uri) const {
        if (role_ == nullptr || role_->allows(action, uri)) {
            return true;
        }
        spdlog::warn("Denied {} on '{}' for authid={} role={}", to_string(action), uri, authid_, role_name_);
        return false;
    }

    // wamp.error.not_authorized for a denied request
    std::span<const uint8_t> deny(MessageType request_type, uint64_t request_id, Action action,
                                  const std::string& uri) {
        response_buffer_ = rawsocket::create_wamp_message(serialize_error(
            ErrorMessage::create_not_authorized(request_type, request_id, to_string(action), uri)));
        return std::span<const uint8_t>(response_buffer_);
    }

    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> handle_established_message(
        const std::vector<uint8_t>& cbor_payload
    ) {
        spdlog::debug("Processing message in ESTABLISHED state");

        auto type_result = get_message_type_from_cbor(cbor_payload);
        if (!type_result.has_value()) {
            spdlog::error("Failed to get message type: {}",
                         type_result.error().message());
            return std::unexpected{type_result.error()};
        }

        switch (auto msg_type = *type_result) {
            case MessageType::GOODBYE: {
                spdlog::info("Received GOODBYE from client");

                auto goodbye_result = deserialize_goodbye(cbor_payload);
                if (!goodbye_result.has_value()) {
                    spdlog::error("Failed to deserialize GOODBYE");
                    return std::span<const uint8_t>{};
                }

                const auto& goodbye = *goodbye_result;
                spdlog::debug("GOODBYE reason: {}", goodbye.reason);

                auto response_goodbye = GoodbyeMessage::create_normal();
                auto goodbye_cbor = serialize_goodbye(response_goodbye);
                response_buffer_ = rawsocket::create_wamp_message(goodbye_cbor);

                state_ = SessionProtocolState::SHUTTING_DOWN;

                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::SUBSCRIBE: {
                spdlog::info("Received SUBSCRIBE from client");

                auto subscribe_result = deserialize_subscribe(cbor_payload);
                if (!subscribe_result.has_value()) {
                    spdlog::error("Failed to deserialize SUBSCRIBE");
                    return std::span<const uint8_t>{};
                }

                if (!is_authorized(Action::SUBSCRIBE, subscribe_result->topic)) {
                    return deny(MessageType::SUBSCRIBE, subscribe_result->request_id,
                                Action::SUBSCRIBE, subscribe_result->topic);
                }

                response_buffer_ = PubSubHandler::handle_subscribe(
                    *realm_ptr_,
                    *subscribe_result,
                    session_id_
                );

                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::PUBLISH: {
                spdlog::info("Received PUBLISH from client");

                auto publish_result = deserialize_publish(cbor_payload);
                if (!publish_result.has_value()) {
                    spdlog::error("Failed to deserialize PUBLISH");
                    return std::span<const uint8_t>{};
                }

                if (!is_authorized(Action::PUBLISH, publish_result->topic)) {
                    // WAMP: an unacknowledged publish gets no response, not even an error
                    const auto ack = publish_result->options.find("acknowledge");
                    const auto* flag = ack != publish_result->options.end() ? std::get_if<bool>(&ack->second) : nullptr;
                    if (flag == nullptr || !*flag) {
                        return std::span<const uint8_t>{};
                    }
                    return deny(MessageType::PUBLISH, publish_result->request_id,
                                Action::PUBLISH, publish_result->topic);
                }

                response_buffer_ = PubSubHandler::handle_publish(
                    *realm_ptr_,
                    *publish_result,
                    session_id_
                );

                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::UNSUBSCRIBE: {
                spdlog::info("Received UNSUBSCRIBE from client");

                auto unsubscribe_result = deserialize_unsubscribe(cbor_payload);
                if (!unsubscribe_result.has_value()) {
                    spdlog::error("Failed to deserialize UNSUBSCRIBE");
                    return std::span<const uint8_t>{};
                }

                response_buffer_ = PubSubHandler::handle_unsubscribe(
                    *realm_ptr_,
                    *unsubscribe_result,
                    session_id_
                );

                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::UNREGISTER: {
                spdlog::info("Received UNREGISTER from client");

                auto unregister_result = deserialize_unregister(cbor_payload);
                if (!unregister_result.has_value()) {
                    spdlog::error("Failed to deserialize UNREGISTER");
                    return std::span<const uint8_t>{};
                }

                auto handle_result = ProcedureHandler::handle_unregister(
                    *realm_ptr_,
                    *unregister_result,
                    session_id_
                );

                if (!handle_result.has_value()) {
                    spdlog::error("Failed to handle UNREGISTER: {}", handle_result.error().message());
                    return std::span<const uint8_t>{};
                }

                response_buffer_ = *handle_result;
                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::ERROR: {
                spdlog::info("Received ERROR from callee");

                auto error_result = deserialize_error(cbor_payload);
                if (!error_result.has_value()) {
                    spdlog::error("Failed to deserialize ERROR");
                    return std::span<const uint8_t>{};
                }

                // Only ERROR replies to INVOCATION are meaningful for a router
                if (error_result->request_type != MessageType::INVOCATION) {
                    spdlog::warn("Ignoring client ERROR for request type {}",
                                static_cast<int>(error_result->request_type));
                    return std::span<const uint8_t>{};
                }

                auto handle_result = ProcedureHandler::handle_invocation_error(
                    shard_,
                    *error_result,
                    session_id_
                );

                if (!handle_result.has_value()) {
                    spdlog::error("Failed to handle ERROR: {}", handle_result.error().message());
                    return std::span<const uint8_t>{};
                }

                response_buffer_ = *handle_result;
                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::REGISTER: {
                spdlog::info("Received REGISTER from client");

                auto register_result = deserialize_register(cbor_payload);
                if (!register_result.has_value()) {
                    spdlog::error("Failed to deserialize REGISTER");
                    return std::span<const uint8_t>{};
                }

                if (!is_authorized(Action::REGISTER, register_result->procedure)) {
                    return deny(MessageType::REGISTER, register_result->request_id,
                                Action::REGISTER, register_result->procedure);
                }

                auto handle_result = ProcedureHandler::handle_register(
                    *realm_ptr_,
                    *register_result,
                    session_id_
                );

                if (!handle_result.has_value()) {
                    spdlog::error("Failed to handle REGISTER: {}", handle_result.error().message());
                    return std::span<const uint8_t>{};
                }

                response_buffer_ = *handle_result;
                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::CALL: {
                spdlog::info("Received CALL from client");

                auto call_result = deserialize_call(cbor_payload);
                if (!call_result.has_value()) {
                    spdlog::error("Failed to deserialize CALL");
                    return std::span<const uint8_t>{};
                }

                if (!is_authorized(Action::CALL, call_result->procedure)) {
                    return deny(MessageType::CALL, call_result->request_id,
                                Action::CALL, call_result->procedure);
                }

                auto handle_result = ProcedureHandler::handle_call(
                    *realm_ptr_,
                    *call_result,
                    session_id_
                );

                if (!handle_result.has_value()) {
                    spdlog::error("Failed to handle CALL: {}", handle_result.error().message());
                    return std::span<const uint8_t>{};
                }

                response_buffer_ = *handle_result;
                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::YIELD: {
                spdlog::info("Received YIELD from callee");

                auto yield_result = deserialize_yield(cbor_payload);
                if (!yield_result.has_value()) {
                    spdlog::error("Failed to deserialize YIELD");
                    return std::span<const uint8_t>{};
                }

                auto handle_result = ProcedureHandler::handle_yield(
                    shard_,
                    *yield_result,
                    session_id_
                );

                if (!handle_result.has_value()) {
                    spdlog::error("Failed to handle YIELD: {}", handle_result.error().message());
                    return std::span<const uint8_t>{};
                }

                response_buffer_ = *handle_result;
                return std::span<const uint8_t>(response_buffer_);
            }

            default:
                spdlog::warn("Unexpected message type in ESTABLISHED state: {}",
                            static_cast<int>(msg_type));
                return std::span<const uint8_t>{};
        }
    }

    [[nodiscard]] const char* state_name() const {
        switch (state_) {
            case SessionProtocolState::AWAITING_RAWSOCKET_HANDSHAKE:
                return "AWAITING_RAWSOCKET_HANDSHAKE";
            case SessionProtocolState::AWAITING_FRAME_HEADER:
                return "AWAITING_FRAME_HEADER";
            case SessionProtocolState::AWAITING_FRAME_PAYLOAD:
                return "AWAITING_FRAME_PAYLOAD";
            case SessionProtocolState::SHUTTING_DOWN:
                return "SHUTTING_DOWN";
            case SessionProtocolState::CLOSED:
                return "CLOSED";
            default:
                return "UNKNOWN";
        }
    }

private:
    asio::io_context& io_;
    const ServerConfig& config_;  // Server configuration (includes auth keys)
    Shard& shard_;                // The shard (channels, pending calls, realms, ids) this session runs on
    SessionProtocolState state_;
    bool disconnected_ = false;
    std::vector<uint8_t> output_buffer_;  // Responses accumulated during one process() call
    std::vector<uint8_t> buffer_;          // Accumulates partial reads
    size_t read_pos_{0};                   // Bytes of buffer_ already consumed (dropped at the end of process())
    std::vector<uint8_t> response_buffer_;  // Reusable buffer for responses

    // RawSocket parameters
    std::optional<rawsocket::Serializer> serializer_;
    std::optional<rawsocket::MaxLengthCode> max_length_;

    // Frame parsing state
    rawsocket::FrameHeader current_frame_header_{};
    uint32_t expected_payload_length_;

    // WAMP session state
    uint64_t session_id_;
    std::string realm_;
    Realm* realm_ptr_{nullptr};  // routing state of realm_, set when the session is established
    bool wamp_session_established_;  // True after HELLO/WELCOME handshake

    // Authentication state
    std::string pending_authid_;      // authid from HELLO message (during auth)
    std::string pending_challenge_;   // Challenge sent to client (hex-encoded)
    bool expect_authenticate_{false}; // True when expecting AUTHENTICATE message

    // Authorization state: role_ is null while authentication is off (everything allowed)
    std::string authid_;
    std::string role_name_;
    const Permissions* role_{nullptr};
};

} // namespace wamp
