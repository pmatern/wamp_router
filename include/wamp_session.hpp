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
#include "rate_limit.hpp"
#include "wire.hpp"
#include "websocket.hpp"
#include <asio/io_context.hpp>
#include <spdlog/spdlog.h>
#include <optional>
#include <algorithm>
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
        if (config.max_messages_per_second > 0) {
            const auto rate = static_cast<double>(config.max_messages_per_second);
            const auto burst = config.message_burst != 0 ? static_cast<double>(config.message_burst)
                                                         : std::max(10.0, 2.0 * rate);
            rate_bucket_ = std::make_unique<TokenBucket>(rate, burst, TokenBucket::Clock::now());
        }
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

    // True if the client connected with a WebSocket upgrade instead of the RawSocket handshake. All frames
    // the router builds are RawSocket frames (4-byte header + CBOR); a WebSocket session re-wraps them as
    // binary messages when writing (see ws_wrap and session_writer).
    [[nodiscard]] bool is_websocket() const {
        return transport_ == Transport::WEBSOCKET;
    }

    // True if the client chose JSON (wamp.2.json, or RawSocket serializer 1). The router works in CBOR
    // internally; a JSON session converts messages at its edge (see to_wire, core_payload, ws_wrap and
    // session_writer).
    [[nodiscard]] bool is_json() const {
        return wire_ == Wire::JSON;
    }

    // The serializer of the session; the router converts at its edge unless it is CBOR
    [[nodiscard]] Wire wire() const {
        return wire_;
    }

    // True when the last process() output (a close frame or an HTTP error) is the final thing to send:
    // the caller writes it and then closes the connection
    [[nodiscard]] bool should_close() const {
        return close_requested_;
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
            shard_.ppt_sessions.erase(session_id_);
        }

        spdlog::info("WAMP session disconnected");
    }

    // Consumes all complete frames in the buffer (a single socket read can carry several
    // pipelined messages). Returns a view of the concatenated responses, valid until the next
    // call (empty span = no response).
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process(std::span<const uint8_t> data) {
        auto result = process_input(data);
        compact_buffer();
        if (rate_bucket_ && messages_in_turn_ > 0) result = settle_rate(std::move(result));
        return result;
    }

    // How long the caller should wait before reading this session's socket again because it is over its message rate
    // (see [server] max_messages_per_second); zero if it is not. Reading and clearing.
    [[nodiscard]] std::chrono::nanoseconds take_throttle() {
        return std::exchange(throttle_delay_, std::chrono::nanoseconds{0});
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
        shard_.congested.clear();

        spdlog::debug("Received {} bytes, buffer now {} bytes in state {}",
                     data.size(), unread(), state_name());

        // The first byte tells the transports apart: RawSocket starts with 0x7F, an HTTP upgrade with "GET "
        if (transport_ == Transport::UNDECIDED && unread() > 0) {
            if (buffer_[read_pos_] == 'G' && config_.websocket.enabled) {
                transport_ = Transport::WEBSOCKET;
                ws_parser_.emplace(config_.websocket.max_message_size);
            } else {
                transport_ = Transport::RAWSOCKET;
            }
        }
        if (transport_ == Transport::WEBSOCKET) {
            return process_websocket();
        }

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
    // ------------------------------------------------------------------------
    // WebSocket (wamp.2.cbor)
    // ------------------------------------------------------------------------
    // Appends the RawSocket frames in `frames` to output_buffer_ as WebSocket messages: binary for CBOR, text
    // (the CBOR converted to JSON) for JSON
    void ws_wrap(std::span<const uint8_t> frames) {
        while (frames.size() >= rawsocket::FRAME_HEADER_SIZE) {
            auto header = rawsocket::decode_frame_header(frames);
            if (!header || frames.size() < rawsocket::FRAME_HEADER_SIZE + header->payload_length) break;
            const auto payload = frames.subspan(rawsocket::FRAME_HEADER_SIZE, header->payload_length);
            if (header->type == rawsocket::FrameType::REGULAR) {
                if (wire_ != Wire::CBOR) {
                    json_text_.clear();
                    if (auto converted = wirecodec::from_cbor(wire_, payload, json_text_)) {
                        ws::append_frame(output_buffer_, wire_ == Wire::JSON ? ws::Opcode::TEXT : ws::Opcode::BINARY,
                                         {reinterpret_cast<const uint8_t*>(json_text_.data()), json_text_.size()});
                    } else {
                        spdlog::warn("Dropped a reply that cannot be written as {}: {}", to_string(wire_),
                                     converted.error().message());
                    }
                } else {
                    ws::append_frame(output_buffer_, ws::Opcode::BINARY, payload);
                }
            }
            frames = frames.subspan(rawsocket::FRAME_HEADER_SIZE + header->payload_length);
        }
    }

    // The CBOR form of a client message payload (JSON and MessagePack are converted; CBOR passes through)
    [[nodiscard]] std::expected<std::vector<uint8_t>, std::error_code> core_payload(std::vector<uint8_t>&& payload) {
        if (wire_ == Wire::CBOR) return std::move(payload);
        std::vector<uint8_t> cbor;
        cbor.reserve(payload.size() + 16);
        if (auto r = wirecodec::to_cbor(wire_, payload, cbor); !r) {
            return std::unexpected{r.error()};
        }
        return cbor;
    }

    // RawSocket output: for a JSON or MessagePack session, converts each regular frame of `framed` (header + CBOR)
    // to a frame in the session's format; ping/pong frames and CBOR sessions are returned unchanged
    [[nodiscard]] std::span<const uint8_t> to_wire(std::span<const uint8_t> framed) {
        if (wire_ == Wire::CBOR || framed.empty()) return framed;
        json_frames_.clear();
        while (framed.size() >= rawsocket::FRAME_HEADER_SIZE) {
            auto header = rawsocket::decode_frame_header(framed);
            if (!header || framed.size() < rawsocket::FRAME_HEADER_SIZE + header->payload_length) break;
            const auto whole = framed.first(rawsocket::FRAME_HEADER_SIZE + header->payload_length);
            if (header->type == rawsocket::FrameType::REGULAR) {
                json_text_.clear();
                if (auto converted = wirecodec::from_cbor(wire_, whole.subspan(rawsocket::FRAME_HEADER_SIZE), json_text_)) {
                    const auto frame_header = rawsocket::encode_frame_header(
                        rawsocket::FrameHeader{rawsocket::FrameType::REGULAR, static_cast<uint32_t>(json_text_.size())});
                    json_frames_.insert(json_frames_.end(), frame_header.begin(), frame_header.end());
                    json_frames_.insert(json_frames_.end(), json_text_.begin(), json_text_.end());
                } else {
                    spdlog::warn("Dropped a reply that cannot be written as {}: {}", to_string(wire_),
                                 converted.error().message());
                }
            } else {
                json_frames_.insert(json_frames_.end(), whole.begin(), whole.end());
            }
            framed = framed.subspan(whole.size());
        }
        return json_frames_;
    }

    // Ends the connection after the pending output is written
    void ws_close(uint16_t code) {
        ws::append_close(output_buffer_, code);
        close_requested_ = true;
        state_ = SessionProtocolState::SHUTTING_DOWN;
    }

    // One complete binary message from the client: the same WAMP handling as a RawSocket frame payload
    [[nodiscard]] std::expected<void, std::error_code> ws_message(std::vector<uint8_t>&& raw_payload) {
        auto converted = core_payload(std::move(raw_payload));
        if (!converted) {
            spdlog::debug("Message is not valid {}: {}", to_string(wire_), converted.error().message());
            if (!wamp_session_established_) {   // nothing sensible can follow a bad first message
                ws_close(ws::kCloseProtocolError);
            } else {
                ws_wrap(malformed(to_string(wire_)));
                if (close_requested_ || state_ == SessionProtocolState::SHUTTING_DOWN) ws_close(ws::kCloseNormal);
            }
            return {};
        }
        const std::vector<uint8_t>& payload = *converted;
        std::expected<std::span<const uint8_t>, std::error_code> result{std::span<const uint8_t>{}};
        if (expect_authenticate_) {
            // After CHALLENGE only AUTHENTICATE is acceptable
            auto type = get_message_type_from_cbor(payload);
            if (!type.has_value() || *type != MessageType::AUTHENTICATE) {
                spdlog::error("Expected AUTHENTICATE message, got something else");
                response_buffer_ = rawsocket::create_wamp_message(serialize_abort(
                    AbortMessage::create_not_authorized("Expected AUTHENTICATE message")));
                ws_wrap(response_buffer_);
                ws_close(ws::kCloseNormal);
                return {};
            }
            expect_authenticate_ = false;
            result = handle_authenticate_message(payload);
        } else {
            result = handle_wamp_message(payload);
        }
        if (!result.has_value()) {
            return std::unexpected{result.error()};
        }
        ws_wrap(*result);
        if (state_ == SessionProtocolState::SHUTTING_DOWN) {   // GOODBYE was answered
            ws_close(ws::kCloseNormal);
        }
        return {};
    }

    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_websocket() {
        if (close_requested_) {   // already closing: ignore whatever else the client sends
            read_pos_ = buffer_.size();
            return std::span<const uint8_t>(output_buffer_);
        }

        if (!ws_upgraded_) {
            auto request = ws::parse_upgrade(unread_span(), config_.websocket.allowed_origins, enabled_subprotocols());
            if (request.status == ws::UpgradeStatus::INCOMPLETE) {
                return std::span<const uint8_t>{};
            }
            if (request.status != ws::UpgradeStatus::OK) {
                spdlog::warn("Rejected WebSocket upgrade (status {})", static_cast<int>(request.status));
                const auto response = ws::error_response(request.status);
                output_buffer_.assign(response.begin(), response.end());
                read_pos_ = buffer_.size();
                close_requested_ = true;
                state_ = SessionProtocolState::SHUTTING_DOWN;
                return std::span<const uint8_t>(output_buffer_);
            }
            read_pos_ += request.consumed;
            const auto response = ws::upgrade_response(request.key, request.subprotocol);
            output_buffer_.assign(response.begin(), response.end());
            ws_upgraded_ = true;
            if (request.subprotocol == ws::kSubprotocolJson) {
                wire_ = Wire::JSON;
                ws_parser_.emplace(config_.websocket.max_message_size, /*text_mode=*/true);   // text frames only
            } else if (request.subprotocol == ws::kSubprotocolMsgpack) {
                wire_ = Wire::MSGPACK;   // binary frames, like CBOR
            }
            state_ = SessionProtocolState::AWAITING_FRAME_HEADER;
            spdlog::info("WebSocket upgrade complete (origin '{}'), awaiting WAMP HELLO", request.origin);
        }

        while (!close_requested_) {
            auto parsed = ws_parser_->next(unread_span());
            read_pos_ += parsed.consumed;
            switch (parsed.kind) {
                case ws::Parsed::Kind::NEED_MORE:
                    return std::span<const uint8_t>(output_buffer_);
                case ws::Parsed::Kind::MESSAGE:
                    if (auto handled = ws_message(std::move(parsed.payload)); !handled) {
                        return std::unexpected{handled.error()};
                    }
                    break;
                case ws::Parsed::Kind::PING:
                    ws::append_frame(output_buffer_, ws::Opcode::PONG, parsed.payload);
                    break;
                case ws::Parsed::Kind::PONG:
                    break;
                case ws::Parsed::Kind::CLOSE:   // echo the peer's status code, then close
                    ws_close(parsed.code == 1005 ? ws::kCloseNormal : parsed.code);
                    break;
                case ws::Parsed::Kind::FAIL:
                    spdlog::warn("WebSocket protocol violation, closing with {}", parsed.code);
                    ws_close(parsed.code);
                    break;
            }
        }
        read_pos_ = buffer_.size();
        return std::span<const uint8_t>(output_buffer_);
    }

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

        // Validate serializer: CBOR, and JSON or MessagePack when [server.websocket] subprotocols enables them
        auto enabled = [this](std::string_view name) {
            return std::ranges::find(config_.websocket.subprotocols, std::string{name}) !=
                   config_.websocket.subprotocols.end();
        };
        const bool json_ok = handshake.serializer == rawsocket::Serializer::JSON && enabled(ws::kSubprotocolJson);
        const bool msgpack_ok = handshake.serializer == rawsocket::Serializer::MSGPACK && enabled(ws::kSubprotocolMsgpack);
        if (handshake.serializer != rawsocket::Serializer::CBOR && !json_ok && !msgpack_ok) {
            spdlog::warn("Unsupported serializer requested: {}",
                        static_cast<int>(handshake.serializer));

            auto error_response = rawsocket::encode_handshake_error(
                rawsocket::HandshakeError::SERIALIZER_UNSUPPORTED
            );

            response_buffer_.assign(error_response.begin(), error_response.end());
            return std::span<const uint8_t>(response_buffer_);
        }

        serializer_ = handshake.serializer;
        if (json_ok) wire_ = Wire::JSON;
        if (msgpack_ok) wire_ = Wire::MSGPACK;
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

        std::expected<std::span<const uint8_t>, std::error_code> result{std::span<const uint8_t>{}};
        if (current_frame_header_.type == rawsocket::FrameType::REGULAR && wire_ != Wire::CBOR) {
            auto converted = core_payload(std::move(payload));
            if (converted) {
                result = handle_frame(current_frame_header_.type, *converted);
            } else if (wamp_session_established_) {
                spdlog::debug("Message is not valid {}: {}", to_string(wire_), converted.error().message());
                result = malformed(to_string(wire_));
            } else {
                return std::unexpected{converted.error()};   // nothing sensible can follow a bad first message
            }
        } else {
            result = handle_frame(current_frame_header_.type, payload);
        }

        // Return to frame header state for next message
        state_ = SessionProtocolState::AWAITING_FRAME_HEADER;

        if (result) result = to_wire(*result);
        return result;
    }

    // Process frame payload during authentication (only AUTHENTICATE allowed)
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> process_frame_payload_authenticate() {
        auto result = authenticate_payload();
        if (result) result = to_wire(*result);
        return result;
    }

    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> authenticate_payload() {
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

        // A JSON or MessagePack message is converted first; one that does not convert is not an AUTHENTICATE
        if (wire_ != Wire::CBOR) {
            if (auto converted = core_payload(std::move(payload))) payload = std::move(*converted);
            else payload.clear();
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
        }
        // Session is active, handle various message types. Any message that decodes resets the count of
        // malformed ones in a row (see malformed()).
        malformed_this_message_ = false;
        ++messages_in_turn_;
        auto result = handle_established_message(payload);
        if (!malformed_this_message_) malformed_in_a_row_ = 0;
        return result;
    }

    // Charges the messages handled by this process() call to the session's rate bucket. Over the limit the session is
    // throttled (throttle_delay_: the caller stops reading for that long, TCP slows the client, nothing is lost); a
    // session that has been over it for longer than rate_limit_grace without a break is aborted and closed.
    [[nodiscard]] std::expected<std::span<const uint8_t>, std::error_code> settle_rate(
        std::expected<std::span<const uint8_t>, std::error_code> result) {
        const auto now = TokenBucket::Clock::now();
        const auto wait = rate_bucket_->consume(std::exchange(messages_in_turn_, 0), now);
        if (wait.count() <= 0) {
            throttled_since_.reset();
            return result;
        }
        if (!throttled_since_) throttled_since_ = now;
        shard_.counters.rate_throttles.fetch_add(1, std::memory_order_relaxed);
        if (!result || close_requested_) return result;
        // The wait that would follow is at most a second per read (the debt is carried to the next one)
        const auto pause = std::min<std::chrono::nanoseconds>(wait, std::chrono::seconds{1});
        if (now - *throttled_since_ + std::chrono::duration_cast<TokenBucket::Clock::duration>(pause) > config_.rate_limit_grace) {
            shard_.counters.rate_closes.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("Closing session {} (authid '{}'): over {} messages per second for {} ms", session_id_, authid_,
                         config_.max_messages_per_second,
                         std::chrono::duration_cast<std::chrono::milliseconds>(now - *throttled_since_ + pause).count());
            return rate_abort();
        }
        spdlog::debug("Session {} is over its message rate: waiting {} us", session_id_,
                      std::chrono::duration_cast<std::chrono::microseconds>(wait).count());
        throttle_delay_ = pause;
        return result;
    }

    // ABORT wamp.error.protocol_violation and close, in the session's transport and serializer
    [[nodiscard]] std::span<const uint8_t> rate_abort() {
        WampDict details{{"message", std::string{"Message rate limit exceeded"}}};
        const auto abort = rawsocket::create_wamp_message(
            serialize_abort(AbortMessage{std::move(details), "wamp.error.protocol_violation"}));
        if (transport_ == Transport::WEBSOCKET) {
            output_buffer_.clear();
            ws_wrap(abort);
            ws_close(ws::kCloseNormal);
            return std::span<const uint8_t>(output_buffer_);
        }
        state_ = SessionProtocolState::SHUTTING_DOWN;
        close_requested_ = true;
        response_buffer_ = abort;
        return to_wire(response_buffer_);
    }

    // A message of a known type that does not decode. The session carries on, but a client that keeps
    // sending them is broken or hostile (each costs a decode failure and a log line), so after
    // max_malformed_messages in a row it gets ABORT wamp.error.protocol_violation and is closed.
    [[nodiscard]] std::span<const uint8_t> malformed(const char* message_type) {
        malformed_this_message_ = true;
        ++malformed_in_a_row_;
        const auto limit = config_.max_malformed_messages;
        if (limit != 0 && malformed_in_a_row_ >= limit) {
            spdlog::warn("Closing session {}: {} malformed messages in a row (last: {})", session_id_,
                         malformed_in_a_row_, message_type);
            WampDict details{{"message", std::string{"Too many malformed messages"}}};
            response_buffer_ = rawsocket::create_wamp_message(
                serialize_abort(AbortMessage{std::move(details), "wamp.error.protocol_violation"}));
            state_ = SessionProtocolState::SHUTTING_DOWN;
            close_requested_ = true;
            return std::span<const uint8_t>(response_buffer_);
        }
        if (malformed_in_a_row_ == 1) {
            spdlog::warn("Malformed {} from session {}", message_type, session_id_);
        } else {
            spdlog::debug("Malformed {} from session {} ({} in a row)", message_type, session_id_, malformed_in_a_row_);
        }
        return std::span<const uint8_t>{};
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
        ppt_ = std::ranges::any_of(hello.roles, [](const Role& role) { return ppt::announced(role.features); });

        if (config_.auth_keys.empty()) {
            spdlog::info("No authentication configured, establishing session for realm '{}'", realm_);

            session_id_ = shard_.ids.session.generate();
            wamp_session_established_ = true;
            realm_ptr_ = &shard_.realms.get(realm_);

            if (ppt_) shard_.ppt_sessions.insert(session_id_);

            auto welcome = WelcomeMessage::create_router(session_id_, realm_);
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
        if (ppt_) shard_.ppt_sessions.insert(session_id_);

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

    // True if this session may subscribe/register the pattern `uri` with this match policy
    [[nodiscard]] bool is_authorized(Action action, const std::string& uri, Match match) const {
        if (role_ == nullptr || role_->allows_pattern(action, uri, match)) {
            return true;
        }
        spdlog::warn("Denied {} on '{}' ({} match) for authid={} role={}", to_string(action), uri, to_string(match),
                     authid_, role_name_);
        return false;
    }

    // The match policy a SUBSCRIBE/REGISTER asks for ("match" option, default exact). A policy the router does not
    // know, or a pattern that is not valid for it, is answered with an ERROR in response_buffer_ and nullopt.
    [[nodiscard]] std::optional<Match> pattern_match(MessageType request_type, uint64_t request_id,
                                                     const WampDict& options, const std::string& uri) {
        Match match = Match::EXACT;
        if (const auto it = options.find("match"); it != options.end()) {
            const auto* name = std::get_if<std::string>(&it->second);
            const auto parsed = name != nullptr ? parse_match(*name) : std::nullopt;
            if (!parsed) {
                response_buffer_ = rawsocket::create_wamp_message(serialize_error(ErrorMessage::create_invalid_argument(
                    request_type, request_id, "match must be exact, prefix or wildcard")));
                return std::nullopt;
            }
            match = *parsed;
        }
        const bool valid = match == Match::EXACT || (match == Match::PREFIX ? !uri.empty() : uri::valid_wildcard(uri));
        if (!valid) {
            response_buffer_ = rawsocket::create_wamp_message(serialize_error(ErrorMessage::create_invalid_uri(
                request_type, request_id,
                match == Match::PREFIX ? "A prefix must not be empty"
                                       : "A wildcard pattern needs at least one empty and one non-empty component")));
            return std::nullopt;
        }
        return match;
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
                spdlog::debug("Received GOODBYE from client");

                auto goodbye_result = deserialize_goodbye(cbor_payload);
                if (!goodbye_result.has_value()) {
                    return malformed("GOODBYE");
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
                spdlog::debug("Received SUBSCRIBE from client");

                auto subscribe_result = deserialize_subscribe(cbor_payload);
                if (!subscribe_result.has_value()) {
                    return malformed("SUBSCRIBE");
                }

                const auto match = pattern_match(MessageType::SUBSCRIBE, subscribe_result->request_id,
                                                 subscribe_result->options, subscribe_result->topic);
                if (!match) return std::span<const uint8_t>(response_buffer_);

                if (!is_authorized(Action::SUBSCRIBE, subscribe_result->topic, *match)) {
                    return deny(MessageType::SUBSCRIBE, subscribe_result->request_id,
                                Action::SUBSCRIBE, subscribe_result->topic);
                }

                response_buffer_ = PubSubHandler::handle_subscribe(
                    *realm_ptr_,
                    *subscribe_result,
                    session_id_,
                    *match
                );

                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::PUBLISH: {
                spdlog::debug("Received PUBLISH from client");

                auto publish_result = deserialize_publish(cbor_payload);
                if (!publish_result.has_value()) {
                    return malformed("PUBLISH");
                }

                const WampDict publish_ppt = ppt::extract(publish_result->options);
                if (!publish_ppt.empty()) {
                    const auto ack_it = publish_result->options.find("acknowledge");
                    const auto* ack_flag = ack_it != publish_result->options.end()
                                               ? std::get_if<bool>(&ack_it->second) : nullptr;
                    const bool ack = ack_flag != nullptr && *ack_flag;
                    std::optional<ErrorMessage> refusal;
                    if (!ppt_) {
                        refusal = ErrorMessage::create_feature_not_supported(
                            MessageType::PUBLISH, publish_result->request_id,
                            "The session did not announce payload passthru mode");
                    } else if (!ppt::valid(publish_ppt, publish_result->arguments, publish_result->arguments_kw)) {
                        refusal = ErrorMessage::create_invalid_argument(
                            MessageType::PUBLISH, publish_result->request_id,
                            "Malformed ppt_* options or payload (one binary argument required)");
                    }
                    if (!refusal && role_ != nullptr &&
                        !role_->allows_ppt_scheme(std::get<std::string>(publish_ppt.at("ppt_scheme")))) {
                        refusal = ErrorMessage::create_not_authorized(MessageType::PUBLISH, publish_result->request_id,
                                                                      "use payload passthru scheme", publish_result->topic);
                    }
                    if (refusal) {
                        if (!ack) return std::span<const uint8_t>{};
                        response_buffer_ = rawsocket::create_wamp_message(serialize_error(*refusal));
                        return std::span<const uint8_t>(response_buffer_);
                    }
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
                spdlog::debug("Received UNSUBSCRIBE from client");

                auto unsubscribe_result = deserialize_unsubscribe(cbor_payload);
                if (!unsubscribe_result.has_value()) {
                    return malformed("UNSUBSCRIBE");
                }

                response_buffer_ = PubSubHandler::handle_unsubscribe(
                    *realm_ptr_,
                    *unsubscribe_result,
                    session_id_
                );

                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::UNREGISTER: {
                spdlog::debug("Received UNREGISTER from client");

                auto unregister_result = deserialize_unregister(cbor_payload);
                if (!unregister_result.has_value()) {
                    return malformed("UNREGISTER");
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
                spdlog::debug("Received ERROR from callee");

                auto error_result = deserialize_error(cbor_payload);
                if (!error_result.has_value()) {
                    return malformed("ERROR");
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
                spdlog::debug("Received REGISTER from client");

                auto register_result = deserialize_register(cbor_payload);
                if (!register_result.has_value()) {
                    return malformed("REGISTER");
                }

                const auto match = pattern_match(MessageType::REGISTER, register_result->request_id,
                                                 register_result->options, register_result->procedure);
                if (!match) return std::span<const uint8_t>(response_buffer_);

                if (!is_authorized(Action::REGISTER, register_result->procedure, *match)) {
                    return deny(MessageType::REGISTER, register_result->request_id,
                                Action::REGISTER, register_result->procedure);
                }

                auto handle_result = ProcedureHandler::handle_register(
                    *realm_ptr_,
                    *register_result,
                    session_id_,
                    *match
                );

                if (!handle_result.has_value()) {
                    spdlog::error("Failed to handle REGISTER: {}", handle_result.error().message());
                    return std::span<const uint8_t>{};
                }

                response_buffer_ = *handle_result;
                return std::span<const uint8_t>(response_buffer_);
            }

            case MessageType::CALL: {
                spdlog::debug("Received CALL from client");

                auto call_result = deserialize_call(cbor_payload);
                if (!call_result.has_value()) {
                    return malformed("CALL");
                }

                if (const WampDict call_ppt = ppt::extract(call_result->options); !call_ppt.empty()) {
                    std::optional<ErrorMessage> refusal;
                    if (!ppt_) {
                        refusal = ErrorMessage::create_feature_not_supported(
                            MessageType::CALL, call_result->request_id,
                            "The session did not announce payload passthru mode");
                    } else if (!ppt::valid(call_ppt, call_result->arguments, call_result->arguments_kw)) {
                        refusal = ErrorMessage::create_invalid_argument(
                            MessageType::CALL, call_result->request_id,
                            "Malformed ppt_* options or payload (one binary argument required)");
                    }
                    if (!refusal && role_ != nullptr &&
                        !role_->allows_ppt_scheme(std::get<std::string>(call_ppt.at("ppt_scheme")))) {
                        refusal = ErrorMessage::create_not_authorized(MessageType::CALL, call_result->request_id,
                                                                      "use payload passthru scheme", call_result->procedure);
                    }
                    if (refusal) {
                        response_buffer_ = rawsocket::create_wamp_message(serialize_error(*refusal));
                        return std::span<const uint8_t>(response_buffer_);
                    }
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

            case MessageType::CANCEL: {
                spdlog::debug("Received CANCEL from caller");

                auto cancel_result = deserialize_cancel(cbor_payload);
                if (!cancel_result.has_value()) {
                    return malformed("CANCEL");
                }

                ProcedureHandler::handle_cancel(shard_, *cancel_result, session_id_);
                return std::span<const uint8_t>{};
            }

            case MessageType::YIELD: {
                spdlog::debug("Received YIELD from callee");

                auto yield_result = deserialize_yield(cbor_payload);
                if (!yield_result.has_value()) {
                    return malformed("YIELD");
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

    // Serialization the client chose; the router core always works on CBOR
    Wire wire_{Wire::CBOR};

    // [server] max_messages_per_second: the session's bucket (null when off), the messages handled by the current
    // process() call, when it first went over the limit without a break, and the wait the caller should honour
    std::unique_ptr<TokenBucket> rate_bucket_;
    uint64_t messages_in_turn_{0};
    std::optional<TokenBucket::Clock::time_point> throttled_since_;
    std::chrono::nanoseconds throttle_delay_{0};
    std::string json_text_;                 // scratch for CBOR -> JSON
    std::vector<uint8_t> json_frames_;      // converted RawSocket output of one call

    // Subprotocols the router accepts on the WebSocket upgrade, as views for ws::parse_upgrade
    [[nodiscard]] std::span<const std::string_view> enabled_subprotocols() {
        enabled_subprotocol_views_.clear();
        for (const auto& name : config_.websocket.subprotocols) enabled_subprotocol_views_.emplace_back(name);
        return enabled_subprotocol_views_;
    }
    std::vector<std::string_view> enabled_subprotocol_views_;

    // Which transport the client chose (decided by the first byte), and the WebSocket state
    enum class Transport { UNDECIDED, RAWSOCKET, WEBSOCKET };
    Transport transport_{Transport::UNDECIDED};
    std::optional<ws::FrameParser> ws_parser_;
    bool ws_upgraded_{false};
    bool close_requested_{false};

    // Malformed messages (known type, undecodable body) since the last good one, see malformed()
    size_t malformed_in_a_row_{0};
    bool malformed_this_message_{false};

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
    bool ppt_{false};                // the client announced Payload Passthru Mode in HELLO
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
