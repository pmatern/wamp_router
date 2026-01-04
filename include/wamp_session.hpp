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

#include "raw_socket.hpp"
#include "wamp_messages.hpp"
#include "wamp_serializer.hpp"
#include "wamp_id.hpp"
#include "pubsub_handler.hpp"
#include "procedure_handler.hpp"
#include "event_channel.hpp"
#include "config.hpp"
#include "crypto_utils.hpp"
#include <boost/asio/io_context.hpp>
#include <spdlog/spdlog.h>
#include <vector>
#include <span>
#include <expected>
#include <system_error>
#include <cstdint>

// TODO - register local roles and associated functions, subscriptions, etc

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
    explicit WampSession(boost::asio::io_context& io, const ServerConfig& config)
        : io_(io)
        , config_(config)
        , state_(SessionProtocolState::AWAITING_RAWSOCKET_HANDSHAKE)
        , expected_payload_length_(0)
        , session_id_(0)
        , wamp_session_established_(false)
    {
        spdlog::debug("WAMP session created");
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

        // Clean up all subscriptions and registrations for this session
        if (session_id_ != 0) {
            PubSubHandler::cleanup_session(session_id_);
            ProcedureHandler::cleanup_session(session_id_);
            EventChannelRegistry::remove(session_id_);
        }

        spdlog::info("WAMP session disconnected");
    }

    // Returns span view into response_buffer_ (empty span = no response)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process(std::span<const uint8_t> data) {
        buffer_.insert(buffer_.end(), data.begin(), data.end());

        spdlog::debug("Received {} bytes, buffer now {} bytes in state {}",
                     data.size(), buffer_.size(), state_name());

        while (true) {
            switch (state_) {
                case SessionProtocolState::AWAITING_RAWSOCKET_HANDSHAKE:
                    return process_rawsocket_handshake();

                case SessionProtocolState::AWAITING_FRAME_HEADER: {
                    auto result = process_frame_header();
                    if (!result.has_value()) {
                        return std::unexpected{result.error()};
                    }
                    if (!result->empty()) {
                        return result;
                    }
                    break;
                }

                case SessionProtocolState::AWAITING_AUTHENTICATE: {
                    // After CHALLENGE sent, client must send AUTHENTICATE
                    auto result = process_frame_payload_authenticate();
                    if (!result.has_value()) {
                        return std::unexpected{result.error()};
                    }
                    if (!result->empty()) {
                        return result;
                    }
                    break;
                }

                case SessionProtocolState::AWAITING_FRAME_PAYLOAD:
                    return process_frame_payload();

                case SessionProtocolState::SHUTTING_DOWN:
                case SessionProtocolState::CLOSED:
                default:
                    return std::unexpected{make_error_code(WampError::INVALID_STATE)};
            }
        }
    }

private:
    // Process RawSocket handshake (expecting 4 bytes)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_rawsocket_handshake() {
        if (buffer_.size() < rawsocket::HANDSHAKE_SIZE) {
            // Not enough data yet
            return std::span<const uint8_t>{};
        }

        auto handshake_result = rawsocket::decode_handshake_request(buffer_);
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

        buffer_.erase(buffer_.begin(), buffer_.begin() + rawsocket::HANDSHAKE_SIZE);

        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        spdlog::info("RawSocket handshake complete, awaiting WAMP HELLO");

        response_buffer_.assign(success_response.begin(), success_response.end());
        return std::span<const uint8_t>(response_buffer_);
    }

    // Process frame header (expecting 4 bytes)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_frame_header() {
        if (buffer_.size() < rawsocket::FRAME_HEADER_SIZE) {
            // Not enough data yet
            return std::span<const uint8_t>{};
        }

        // Decode frame header
        auto header_result = rawsocket::decode_frame_header(buffer_);
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
        buffer_.erase(buffer_.begin(), buffer_.begin() + rawsocket::FRAME_HEADER_SIZE);

        expected_payload_length_ = current_frame_header_.payload_length;
        state_ = SessionProtocolState::AWAITING_FRAME_PAYLOAD;

        // Continue processing if payload is already in buffer
        return std::span<const uint8_t>{};
    }

    // Process frame payload (expecting expected_payload_length_ bytes)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_frame_payload() {
        if (buffer_.size() < expected_payload_length_) {
            // Not enough data yet
            spdlog::debug("Waiting for payload: have {} bytes, need {}",
                         buffer_.size(), expected_payload_length_);
            return std::span<const uint8_t>{};
        }
        std::vector<uint8_t> payload(
            buffer_.begin(),
            buffer_.begin() + expected_payload_length_
        );

        buffer_.erase(buffer_.begin(), buffer_.begin() + expected_payload_length_);

        spdlog::debug("Received complete frame payload: {} bytes", payload.size());

        auto result = handle_frame(current_frame_header_.type, payload);

        // Return to frame header state for next message
        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        return result;
    }

    // Process frame payload during authentication (only AUTHENTICATE allowed)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_frame_payload_authenticate() {
        if (buffer_.size() < expected_payload_length_) {
            // Not enough data yet
            spdlog::debug("Waiting for payload: have {} bytes, need {}",
                         buffer_.size(), expected_payload_length_);
            return std::span<const uint8_t>{};
        }

        std::vector<uint8_t> payload(
            buffer_.begin(),
            buffer_.begin() + expected_payload_length_
        );

        buffer_.erase(buffer_.begin(), buffer_.begin() + expected_payload_length_);

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

            session_id_ = generate_session_id();
            wamp_session_established_ = true;

            WelcomeMessage welcome{session_id_, realm_};
            auto welcome_cbor = serialize_welcome(welcome);
            response_buffer_ = rawsocket::create_wamp_message(welcome_cbor);

            spdlog::info("Session {} established (no auth)", session_id_);
            return std::span<const uint8_t>(response_buffer_);
        }

        // Require cryptosign authentication
        if (!hello.authmethods.has_value() ||
            std::find(hello.authmethods->begin(), hello.authmethods->end(), "cryptosign") ==
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
        if (config_.auth_keys.find(*hello.authid) == config_.auth_keys.end()) {
            spdlog::warn("Unknown authid: {}", *hello.authid);
            auto abort = AbortMessage::create_not_authorized("Unknown authid");
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

        state_ = SessionProtocolState::AWAITING_AUTHENTICATE;

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

        // Build message that should have been signed:
        // Format: challenge|session_id|authid|authrole
        // Note: session_id not yet assigned, use "0"
        std::string signed_message = pending_challenge_ + "|0|" + pending_authid_ + "|user";

        bool signature_valid = verify_ed25519_signature(
            authenticate.signature,
            signed_message,
            public_key_hex
        );

        if (!signature_valid) {
            spdlog::warn("Invalid signature from authid={}", pending_authid_);
            auto abort = AbortMessage::create_not_authorized("Invalid signature");
            auto abort_cbor = serialize_abort(abort);
            response_buffer_ = rawsocket::create_wamp_message(abort_cbor);
            return std::span<const uint8_t>(response_buffer_);
        }

        session_id_ = generate_session_id();
        wamp_session_established_ = true;
        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        spdlog::info("Authentication successful: session_id={}, authid={}, realm={}",
                    session_id_, pending_authid_, realm_);

        EventChannelRegistry::get_or_create(session_id_, io_);

        auto welcome = WelcomeMessage::create_router(session_id_, realm_);
        welcome.authid = pending_authid_;
        welcome.authrole = "user";
        welcome.authmethod = "cryptosign";

        auto welcome_cbor = serialize_welcome(welcome);
        response_buffer_ = rawsocket::create_wamp_message(welcome_cbor);

        pending_authid_.clear();
        pending_challenge_.clear();

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

                response_buffer_ = PubSubHandler::handle_subscribe(
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

                response_buffer_ = PubSubHandler::handle_publish(
                    *publish_result,
                    session_id_
                );

                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::REGISTER: {
                spdlog::info("Received REGISTER from client");

                auto register_result = deserialize_register(cbor_payload);
                if (!register_result.has_value()) {
                    spdlog::error("Failed to deserialize REGISTER");
                    return std::span<const uint8_t>{};
                }

                auto handle_result = ProcedureHandler::handle_register(
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

                auto handle_result = ProcedureHandler::handle_call(
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

    static uint64_t generate_session_id() {
        static GlobalIdGenerator id_gen;
        return id_gen.generate();
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
    boost::asio::io_context& io_;
    const ServerConfig& config_;  // Server configuration (includes auth keys)
    SessionProtocolState state_;
    std::vector<uint8_t> buffer_;          // Accumulates partial reads
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
    bool wamp_session_established_;  // True after HELLO/WELCOME handshake

    // Authentication state
    std::string pending_authid_;      // authid from HELLO message (during auth)
    std::string pending_challenge_;   // Challenge sent to client (hex-encoded)
};

} // namespace wamp
