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
#include "wamp_id.hpp"
#include "shard.hpp"
#include "shard_group.hpp"
#include "invocation_tracker.hpp"
#include "event_channel.hpp"
#include "raw_socket.hpp"
#include <spdlog/spdlog.h>
#include <vector>
#include <cstdint>
#include <span>
#include <chrono>
#include <memory>
#include <optional>

namespace wamp {

// ============================================================================
// ProcedureHandler - Handles WAMP RPC operations (REGISTER/CALL/YIELD)
// ============================================================================
class ProcedureHandler {
public:
    // Send a frame to the caller of a pending call: through this shard's channels when the caller lives here,
    // otherwise as a CrossFrame to the caller's shard. Returns false if it was not accepted.
    static bool deliver_to_caller(Shard& shard, const PendingCall& pending, std::vector<uint8_t> frame,
                                  bool may_defer = true) {
        auto data = std::make_shared<std::vector<uint8_t>>(std::move(frame));
        if (pending.caller_shard < 0 || shard.group == nullptr) {
            return accepted(shard.channels.deliver(pending.caller_session_id,
                EventToSend{pending.caller_session_id, std::move(data)}, may_defer));
        }
        return shard.group->send_to(static_cast<uint32_t>(pending.caller_shard),
                                    CrossFrame{pending.caller_session_id, std::move(data)}, shard.congested);
    }

    // Fail every pending call whose deadline has passed with wamp.error.timeout.
    // Returns the number of calls expired. Called periodically by the server.
    static size_t expire_calls(Shard& shard, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) {
        auto expired = shard.invocations.remove_expired(now);
        for (const auto& pending : expired) {
            auto error = ErrorMessage::create_timeout(pending.call_request_id, "Call timed out");
            auto frame = rawsocket::create_wamp_message(serialize_error(error));
            spdlog::warn("Call timed out: caller_session={}, request_id={}, callee_session={}",
                        pending.caller_session_id, pending.call_request_id, pending.callee_session_id);
            // Runs from a timer, so it cannot wait for queue space
            (void)deliver_to_caller(shard, pending, std::move(frame), /*may_defer=*/false);

            interrupt_callee(shard, pending);
        }
        return expired.size();
    }

    // Tell the callee to stop working on a call nobody waits for any more
    static void interrupt_callee(Shard& shard, const PendingCall& pending) {
        if (pending.callee_session_id == 0) return;
        auto interrupt = InterruptMessage{pending.invocation_id, {{"mode", std::string{"killnowait"}}}};
        auto idata = std::make_shared<std::vector<uint8_t>>(
            rawsocket::create_wamp_message(serialize_interrupt(interrupt)));
        (void)shard.channels.deliver(pending.callee_session_id,
            EventToSend{pending.callee_session_id, idata}, /*may_defer=*/false);
    }

    // A caller disconnected: forget its pending calls and interrupt their callees
    static void cancel_caller(Shard& shard, uint64_t caller_session_id) {
        for (const auto& pending : shard.invocations.remove_caller_session(caller_session_id)) {
            interrupt_callee(shard, pending);
        }
    }

    // Clean up all registrations and pending invocations for a session (called on disconnect)
    static void cleanup_session(Realm& realm, uint64_t session_id) {
        auto& reg_manager = realm.registrations;
        auto& shard = realm.shard;
        auto& invocation_tracker = shard.invocations;

        for (const auto& procedure : reg_manager.unregister_session(session_id)) {
            if (shard.group && shard.group->size() > 1) shard.group->drop_registration(shard.index, realm.name, procedure);
        }
        cancel_caller(shard, session_id);
        // Calls this session forwarded to other shards are pending there
        if (shard.remote_callers.erase(session_id) > 0 && shard.group) {
            std::vector<uint32_t> ignored;
            for (uint32_t to = 0; to < shard.group->size(); ++to) {
                if (to != shard.index) (void)shard.group->send_to(to, CrossCancel{session_id}, ignored);
            }
        }

        // Callers waiting on this session as callee would otherwise hang forever
        for (const auto& pending : invocation_tracker.remove_callee_session(session_id)) {
            auto error = ErrorMessage::create_callee_failure(
                pending.call_request_id, "Callee session disconnected");
            auto frame = rawsocket::create_wamp_message(serialize_error(error));
            // Cleanup runs during disconnect and cannot wait for queue space
            if (!deliver_to_caller(shard, pending, std::move(frame), /*may_defer=*/false)) {
                spdlog::debug("Caller session {} gone; dropped callee_failure for request_id={}",
                             pending.caller_session_id, pending.call_request_id);
            }
        }

        spdlog::debug("Cleaned up registrations and pending calls for session {}", session_id);
    }

    // Handle REGISTER message
    // Returns response bytes (REGISTERED or ERROR message wrapped in RawSocket frame)
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_register(
        Realm& realm,
        const RegisterMessage& register_msg,
        uint64_t session_id
    ) {
        auto& reg_manager = realm.registrations;
        spdlog::debug("REGISTER request_id={}, procedure={}, session={}",
                     register_msg.request_id, register_msg.procedure, session_id);

        uint64_t registration_id = realm.shard.ids.registration.generate();

        // With several shards a procedure may be registered once across all of them
        auto* group = realm.shard.group;
        const bool multi = group && group->size() > 1;
        bool success = !multi || group->try_register(realm.shard.index, realm.name, register_msg.procedure);
        if (success) {
            success = reg_manager.register_procedure(registration_id, register_msg.procedure, session_id);
            if (!success && multi) group->drop_registration(realm.shard.index, realm.name, register_msg.procedure);
        }

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

    // Handle UNREGISTER message
    // Returns UNREGISTERED, or ERROR if the registration doesn't exist or belongs to another session
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_unregister(
        Realm& realm,
        const UnregisterMessage& unregister_msg,
        uint64_t session_id
    ) {
        auto& reg_manager = realm.registrations;
        spdlog::debug("UNREGISTER request_id={}, registration_id={}, session={}",
                     unregister_msg.request_id, unregister_msg.registration_id, session_id);

        auto info = reg_manager.get_registration(unregister_msg.registration_id);
        if (!info.has_value() || info->session_id != session_id) {
            spdlog::warn("UNREGISTER for unknown registration_id={} from session {}",
                        unregister_msg.registration_id, session_id);
            return rawsocket::create_wamp_message(serialize_error(
                ErrorMessage::create_no_such_registration(unregister_msg.request_id)));
        }

        reg_manager.unregister(unregister_msg.registration_id);
        if (auto* group = realm.shard.group; group && group->size() > 1) {
            group->drop_registration(realm.shard.index, realm.name, info->procedure);
        }

        spdlog::info("Sent UNREGISTERED: request_id={}, registration_id={}",
                    unregister_msg.request_id, unregister_msg.registration_id);

        return rawsocket::create_wamp_message(
            serialize_unregistered(UnregisteredMessage{unregister_msg.request_id}));
    }

    // Handle CALL message
    // Routes call to registered callee by sending INVOCATION via event channel
    // Returns ERROR if procedure not found or callee unavailable, empty vector otherwise
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_call(
        Realm& realm,
        const CallMessage& call,
        uint64_t caller_session_id
    ) {
        realm.shard.counters.calls.fetch_add(1, std::memory_order_relaxed);
        const auto& reg_manager = realm.registrations;
        spdlog::debug("CALL request_id={}, procedure={}, caller_session={}",
                     call.request_id, call.procedure, caller_session_id);

        auto registration = reg_manager.find_callee(call.procedure);
        if (!registration.has_value()) {
            // Not registered on this shard: maybe on another one
            if (auto* group = realm.shard.group; group && group->size() > 1) {
                if (auto owner = group->find_registration(realm.shard.index, realm.name, call.procedure)) {
                    return forward_call(realm, *owner, call, caller_session_id);
                }
            }

            spdlog::warn("CALL to unregistered procedure '{}' from session {}",
                        call.procedure, caller_session_id);
            spdlog::debug("Sent ERROR: request_id={}, error=wamp.error.no_such_procedure", call.request_id);
            return rawsocket::create_wamp_message(serialize_error(
                ErrorMessage::create_no_such_procedure(call.request_id, call.procedure)));
        }

        spdlog::debug("Routing CALL to callee session {} (registration_id={})",
                     registration->session_id, registration->registration_id);

        if (auto failure = start_call(realm.shard, *registration, caller_session_id, call.request_id,
                                      call.arguments, call.arguments_kw, ppt::extract(call.options),
                                      call_timeout(realm.shard, call), -1)) {
            return rawsocket::create_wamp_message(serialize_error(*failure));
        }

        // No direct response to caller - they will get RESULT when callee sends YIELD
        return std::vector<uint8_t>{};
    }

    // Runs on the callee's shard: a CALL forwarded from another shard
    static void accept_remote_call(Shard& shard, CrossCall&& call) {
        Realm& realm = shard.realms.get(call.realm);
        auto registration = realm.registrations.find_callee(call.procedure);
        std::optional<ErrorMessage> failure;
        if (!registration.has_value()) {
            failure = ErrorMessage::create_no_such_procedure(call.request_id, call.procedure);
        } else {
            auto timeout = call.timeout_ms > 0 ? std::chrono::milliseconds{call.timeout_ms} : shard.call_timeout;
            failure = start_call(shard, *registration, call.caller_session, call.request_id, call.arguments,
                                 call.arguments_kw, call.ppt, timeout, static_cast<int32_t>(call.caller_shard));
        }
        if (failure) {
            auto frame = std::make_shared<std::vector<uint8_t>>(
                rawsocket::create_wamp_message(serialize_error(*failure)));
            (void)shard.group->send_to(call.caller_shard, CrossFrame{call.caller_session, std::move(frame)},
                                       shard.congested);
        }
    }


    // Handle YIELD message
    // Routes result back to original caller by sending RESULT via event channel
    // Returns empty vector (no direct response to callee)
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_yield(
        Shard& shard,
        const YieldMessage& yield_msg,
        uint64_t callee_session_id
    ) {
        auto& invocation_tracker = shard.invocations;
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

        // Forward arguments from YIELD to RESULT; passthru options become RESULT details
        std::vector<uint8_t> result_frame;
        if (!yield_msg.options.empty() && !ppt::valid(yield_msg.options, yield_msg.arguments, yield_msg.arguments_kw)) {
            spdlog::warn("YIELD from callee session {} has malformed passthru options or payload", callee_session_id);
            result_frame = rawsocket::create_wamp_message(serialize_error(ErrorMessage::create_invalid_argument(
                MessageType::CALL, call_request_id, "The callee's passthru payload is malformed")));
        } else {
            auto result = ResultMessage{call_request_id, yield_msg.options, yield_msg.arguments, yield_msg.arguments_kw};
            result_frame = rawsocket::create_wamp_message(serialize_result(result));
        }

        if (!deliver_to_caller(shard, *pending_call, std::move(result_frame))) {
            spdlog::error("Failed to send RESULT to caller session {} (channel full or closed)",
                         caller_session_id);
            // Caller may have disconnected or channel is full
            // Nothing we can do - YIELD is lost
            return std::vector<uint8_t>{};
        }

        spdlog::debug("Sent RESULT to caller session {} (request_id={}, invocation_id={})",
                    caller_session_id, call_request_id, yield_msg.invocation_id);

        spdlog::debug("Invocation completed and removed from tracker ({} pending)",
                     invocation_tracker.pending_count());

        // No direct response to callee - YIELD is fire-and-forget
        return std::vector<uint8_t>{};
    }

    // Handle ERROR sent by a callee in response to an INVOCATION
    // Routes it back to the original caller as an ERROR for their CALL
    [[nodiscard]] static std::expected<std::vector<uint8_t>, std::error_code> handle_invocation_error(
        Shard& shard,
        const ErrorMessage& error_msg,
        uint64_t callee_session_id
    ) {
        auto& invocation_tracker = shard.invocations;
        spdlog::debug("ERROR for invocation_id={}, error={}, callee_session={}",
                     error_msg.request_id, error_msg.error_uri, callee_session_id);

        auto pending_call = invocation_tracker.retrieve(error_msg.request_id);
        if (!pending_call.has_value()) {
            spdlog::warn("ERROR for unknown invocation_id={} from callee session {}",
                        error_msg.request_id, callee_session_id);
            return std::vector<uint8_t>{};
        }

        auto forwarded = ErrorMessage{MessageType::CALL, pending_call->call_request_id,
                                      error_msg.details, error_msg.error_uri,
                                      error_msg.arguments, error_msg.arguments_kw};
        auto frame = rawsocket::create_wamp_message(serialize_error(forwarded));

        if (!deliver_to_caller(shard, *pending_call, std::move(frame))) {
            spdlog::error("Failed to send ERROR to caller session {} (channel full or closed)",
                         pending_call->caller_session_id);
            return std::vector<uint8_t>{};
        }

        spdlog::debug("Forwarded callee ERROR to caller session {} (request_id={}, error={})",
                    pending_call->caller_session_id, pending_call->call_request_id, error_msg.error_uri);

        return std::vector<uint8_t>{};
    }
private:
    // The CALL's "timeout" option in milliseconds, 0 if absent
    static int64_t timeout_option(const CallMessage& call) {
        if (auto it = call.options.find("timeout"); it != call.options.end()) {
            if (const auto* ms = std::get_if<int64_t>(&it->second); ms && *ms > 0) return *ms;
        }
        return 0;
    }

    static std::chrono::milliseconds call_timeout(const Shard& shard, const CallMessage& call) {
        const auto ms = timeout_option(call);
        return ms > 0 ? std::chrono::milliseconds{ms} : shard.call_timeout;
    }

    // Send the INVOCATION to the callee (on this shard) and track the call. Returns the ERROR to give the
    // caller if the callee cannot take it. caller_shard is -1 when the caller is on this shard too.
    static std::optional<ErrorMessage> start_call(Shard& shard, const RegistrationInfo& registration,
                                                  uint64_t caller_session_id, uint64_t call_request_id,
                                                  const WampList& arguments, const WampDict& arguments_kw,
                                                  const WampDict& ppt, std::chrono::milliseconds timeout,
                                                  int32_t caller_shard) {
        const uint64_t callee_session_id = registration.session_id;
        if (!ppt.empty() && !shard.ppt_sessions.contains(callee_session_id)) {
            return ErrorMessage::create_feature_not_supported(
                MessageType::CALL, call_request_id, "The callee does not support payload passthru mode");
        }
        const uint64_t invocation_id = shard.ids.invocation.generate();

        auto invocation = InvocationMessage{invocation_id, registration.registration_id, ppt, arguments, arguments_kw};
        auto invocation_data = std::make_shared<std::vector<uint8_t>>(
            rawsocket::create_wamp_message(serialize_invocation(invocation)));

        if (!accepted(shard.channels.deliver(callee_session_id, EventToSend{callee_session_id, invocation_data}))) {
            spdlog::error("Failed to send INVOCATION to callee session {} (channel full or closed)",
                         callee_session_id);
            spdlog::debug("Sent ERROR: request_id={}, error=wamp.error.callee_failure", call_request_id);
            return ErrorMessage::create_callee_failure(call_request_id, "Callee session unavailable or channel full");
        }

        spdlog::debug("Sent INVOCATION to callee session {} (invocation_id={}, procedure={})",
                    callee_session_id, invocation_id, registration.procedure);

        // Track the invocation for routing YIELD back to the caller as RESULT
        auto& invocation_tracker = shard.invocations;
        auto deadline = timeout.count() > 0 ? std::chrono::steady_clock::now() + timeout
                                            : std::chrono::steady_clock::time_point::max();
        invocation_tracker.track(PendingCall{invocation_id, caller_session_id, call_request_id, callee_session_id,
                                             deadline, caller_shard});

        spdlog::debug("Tracking invocation_id={} -> caller_session={}, call_request_id={} ({} pending)",
                     invocation_id, caller_session_id, call_request_id, invocation_tracker.pending_count());

        if (invocation_tracker.pending_count() * 10 > invocation_tracker.max_capacity() * 8) {
            spdlog::warn("Invocation tracker at {}% capacity ({}/{}), oldest entries being evicted",
                        (invocation_tracker.pending_count() * 100) / invocation_tracker.max_capacity(),
                        invocation_tracker.pending_count(), invocation_tracker.max_capacity());
        }
        return std::nullopt;
    }

    // The callee is registered on another shard: hand the CALL over; that shard owns the pending call
    static std::expected<std::vector<uint8_t>, std::error_code> forward_call(
        Realm& realm, uint32_t owner, const CallMessage& call, uint64_t caller_session_id) {
        auto& shard = realm.shard;
        spdlog::debug("Forwarding CALL '{}' to shard {}", call.procedure, owner);
        const bool sent = shard.group->send_to(owner,
            CrossCall{realm.name, call.procedure, shard.index, caller_session_id, call.request_id,
                      timeout_option(call), ppt::extract(call.options), call.arguments, call.arguments_kw},
            shard.congested);
        if (!sent) {
            return rawsocket::create_wamp_message(serialize_error(
                ErrorMessage::create_callee_failure(call.request_id, "Callee shard unavailable")));
        }
        shard.remote_callers.insert(caller_session_id);
        return std::vector<uint8_t>{};
    }
};

} // namespace wamp
