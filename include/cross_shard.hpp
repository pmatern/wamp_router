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

#include "procedure_handler.hpp"
#include "pubsub_handler.hpp"
#include "shard_group.hpp"
#include <variant>

namespace wamp {

// Runs on the destination shard's thread for each batch taken from its inbox: delivers cross-shard events,
// starts calls forwarded from other shards, and writes results/errors to sessions that live here. Sends
// that found a subscriber queue full were parked; wait (bounded) for room before taking the next batch.
inline asio::awaitable<void> dispatch_cross_messages(Shard& shard, std::vector<CrossMessage> batch) {
    for (auto& message : batch) {
        if (auto* publish = std::get_if<CrossPublishPtr>(&message)) {
            PubSubHandler::deliver_remote(shard, **publish);
        } else if (auto* call = std::get_if<CrossCall>(&message)) {
            ProcedureHandler::accept_remote_call(shard, std::move(*call));
        } else if (auto* cancel_call = std::get_if<CrossCancelCall>(&message)) {
            ProcedureHandler::accept_remote_cancel(shard, *cancel_call);
        } else if (auto* cancel = std::get_if<CrossCancel>(&message)) {
            ProcedureHandler::cancel_caller(shard, cancel->caller_session);
        } else if (auto* frame = std::get_if<CrossFrame>(&message)) {
            (void)shard.channels.deliver(frame->session_id, EventToSend{frame->session_id, std::move(frame->frame)});
        }
    }
    co_await shard.channels.deliver_blocked(shard.channels.take_blocked());
}

} // namespace wamp
