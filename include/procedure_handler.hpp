#pragma once

#include "wamp_messages.hpp"
#include "wamp_serializer.hpp"
#include "wamp_id.hpp"
#include "registration_manager.hpp"
#include "invocation_tracker.hpp"
#include "event_channel.hpp"
#include "raw_socket.hpp"
#include <spdlog/spdlog.h>
#include <vector>
#include <cstdint>
#include <span>
#include <memory>

namespace wamp {

// ============================================================================
// ProcedureHandler - Handles WAMP RPC operations (REGISTER/CALL/YIELD)
// ============================================================================
class ProcedureHandler {
public:
    static RegistrationManager& get_registration_manager() {
        static RegistrationManager manager;
        return manager;
    }

    static InvocationTracker& get_invocation_tracker() {
        static InvocationTracker tracker(get_max_pending_invocations());
        return tracker;
    }

    // Configure maximum pending invocations (must be called before first use)
    static void set_max_pending_invocations(size_t max_pending) {
        max_pending_invocations_ = max_pending;
    }

    static size_t get_max_pending_invocations() {
        return max_pending_invocations_;
    }

    // Clean up all registrations and pending invocations for a session (called on disconnect)
    static void cleanup_session(uint64_t session_id) {
        auto& reg_manager = get_registration_manager();
        auto& invocation_tracker = get_invocation_tracker();

        reg_manager.unregister_session(session_id);
        invocation_tracker.remove_caller_session(session_id);

        spdlog::debug("Cleaned up registrations and pending calls for session {}", session_id);
    }

    // Handle REGISTER message
    // Returns response bytes (REGISTERED or ERROR message wrapped in RawSocket frame)
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_register(
        const RegisterMessage& register_msg,
        uint64_t session_id
    ) {
        auto& reg_manager = get_registration_manager();
        spdlog::debug("REGISTER request_id={}, procedure={}, session={}",
                     register_msg.request_id, register_msg.procedure, session_id);

        static RouterScopeIdGenerator reg_id_gen;
        uint64_t registration_id = reg_id_gen.generate();

        bool success = reg_manager.register_procedure(
            registration_id,
            register_msg.procedure,
            session_id
        );

        if (!success) {
            spdlog::warn("Procedure '{}' already registered, sending ERROR to session {}",
                        register_msg.procedure, session_id);

            auto error = ErrorMessage::create_procedure_already_exists(
                register_msg.request_id,
                register_msg.procedure
            );
            auto error_cbor = serialize_error(error);

            spdlog::info("Sent ERROR: request_id={}, error=wamp.error.procedure_already_exists",
                        register_msg.request_id);

            return rawsocket::create_wamp_message(error_cbor);
        }

        auto registered = RegisteredMessage{register_msg.request_id, registration_id};
        auto registered_cbor = serialize_registered(registered);

        spdlog::info("Sent REGISTERED: request_id={}, registration_id={}, procedure={}",
                    register_msg.request_id, registration_id, register_msg.procedure);

        return rawsocket::create_wamp_message(registered_cbor);
    }

    // Handle CALL message
    // Routes call to registered callee by sending INVOCATION via event channel
    // Returns ERROR if procedure not found or callee unavailable, empty vector otherwise
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_call(
        const CallMessage& call,
        uint64_t caller_session_id
    ) {
        const auto& reg_manager = get_registration_manager();
        spdlog::debug("CALL request_id={}, procedure={}, caller_session={}",
                     call.request_id, call.procedure, caller_session_id);

        auto registration = reg_manager.find_callee(call.procedure);
        if (!registration.has_value()) {
            spdlog::warn("CALL to unregistered procedure '{}' from session {}",
                        call.procedure, caller_session_id);

            auto error = ErrorMessage::create_no_such_procedure(
                call.request_id,
                call.procedure
            );
            auto error_cbor = serialize_error(error);

            spdlog::info("Sent ERROR: request_id={}, error=wamp.error.no_such_procedure",
                        call.request_id);

            return rawsocket::create_wamp_message(error_cbor);
        }

        uint64_t callee_session_id = registration->session_id;
        uint64_t registration_id = registration->registration_id;

        spdlog::debug("Routing CALL to callee session {} (registration_id={})",
                     callee_session_id, registration_id);

        static RouterScopeIdGenerator invocation_id_gen;
        uint64_t invocation_id = invocation_id_gen.generate();

        auto invocation = InvocationMessage{invocation_id, registration_id, {}};
        auto invocation_cbor = serialize_invocation(invocation);
        auto invocation_frame = rawsocket::create_wamp_message(invocation_cbor);

        auto invocation_data = std::make_shared<std::vector<uint8_t>>(std::move(invocation_frame));

        if (!EventChannelRegistry::try_send(callee_session_id,
            EventToSend{callee_session_id, invocation_data})) {
            spdlog::error("Failed to send INVOCATION to callee session {} (channel full or closed)",
                         callee_session_id);

            auto error = ErrorMessage::create_callee_failure(
                call.request_id,
                "Callee session unavailable or channel full"
            );
            auto error_cbor = serialize_error(error);

            spdlog::info("Sent ERROR: request_id={}, error=wamp.error.callee_failure",
                        call.request_id);

            return rawsocket::create_wamp_message(error_cbor);
        }

        spdlog::info("Sent INVOCATION to callee session {} (invocation_id={}, procedure={})",
                    callee_session_id, invocation_id, call.procedure);

        // Track the invocation for routing YIELD back to caller as RESULT
        auto& invocation_tracker = get_invocation_tracker();
        invocation_tracker.track(invocation_id, PendingCall{caller_session_id, call.request_id});

        spdlog::debug("Tracking invocation_id={} -> caller_session={}, call_request_id={} ({} pending)",
                     invocation_id, caller_session_id, call.request_id,
                     invocation_tracker.pending_count());

        if (invocation_tracker.pending_count() * 10 > invocation_tracker.max_capacity() * 8) {
            spdlog::warn("Invocation tracker at {}% capacity ({}/{}), oldest entries being evicted",
                        (invocation_tracker.pending_count() * 100) / invocation_tracker.max_capacity(),
                        invocation_tracker.pending_count(), invocation_tracker.max_capacity());
        }

        // No direct response to caller - they will get RESULT when callee sends YIELD
        return std::vector<uint8_t>{};
    }

    // Handle YIELD message
    // Routes result back to original caller by sending RESULT via event channel
    // Returns empty vector (no direct response to callee)
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_yield(
        const YieldMessage& yield_msg,
        uint64_t callee_session_id
    ) {
        auto& invocation_tracker = get_invocation_tracker();
        spdlog::debug("YIELD invocation_id={}, callee_session={}",
                     yield_msg.invocation_id, callee_session_id);

        auto pending_call = invocation_tracker.retrieve(yield_msg.invocation_id);
        if (!pending_call.has_value()) {
            spdlog::warn("YIELD for unknown invocation_id={} from callee session {} (expired/evicted/invalid)",
                        yield_msg.invocation_id, callee_session_id);
            // Silently ignore - callee sent YIELD but we don't know about the invocation
            // Could be due to: LRU eviction, caller disconnected, or invalid invocation_id
            return std::vector<uint8_t>{};
        }

        uint64_t caller_session_id = pending_call->caller_session_id;
        uint64_t call_request_id = pending_call->call_request_id;

        spdlog::debug("Routing YIELD to caller session {} with original request_id={}",
                     caller_session_id, call_request_id);

        auto result = ResultMessage{call_request_id, {}};
        auto result_cbor = serialize_result(result);
        auto result_frame = rawsocket::create_wamp_message(result_cbor);

        auto result_data = std::make_shared<std::vector<uint8_t>>(std::move(result_frame));

        if (!EventChannelRegistry::try_send(caller_session_id,
            EventToSend{caller_session_id, result_data})) {
            spdlog::error("Failed to send RESULT to caller session {} (channel full or closed)",
                         caller_session_id);
            // Caller may have disconnected or channel is full
            // Nothing we can do - YIELD is lost
            return std::vector<uint8_t>{};
        }

        spdlog::info("Sent RESULT to caller session {} (request_id={}, invocation_id={})",
                    caller_session_id, call_request_id, yield_msg.invocation_id);

        spdlog::debug("Invocation completed and removed from tracker ({} pending)",
                     invocation_tracker.pending_count());

        // No direct response to callee - YIELD is fire-and-forget
        return std::vector<uint8_t>{};
    }

private:
    inline static size_t max_pending_invocations_ = 10000;  // Default: 10k pending calls
};

} // namespace wamp
