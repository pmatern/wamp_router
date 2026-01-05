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

#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <spdlog/spdlog.h>
#include <memory>
#include <unordered_map>
#include <cstdint>
#include <vector>

namespace wamp {

// ============================================================================
// EventToSend - Flyweight pattern for distributing events to multiple subscribers
// ============================================================================
// Uses shared_ptr to avoid copying event data for each subscriber
struct EventToSend {
    uint64_t target_session_id{};
    std::shared_ptr<const std::vector<uint8_t>> event_data;  // Shared between all recipients

    EventToSend() = default;

    EventToSend(uint64_t session_id, std::shared_ptr<const std::vector<uint8_t>> data)
        : target_session_id(session_id)
        , event_data(std::move(data))
    {}
};

using EventChannel = boost::asio::experimental::channel<void(boost::system::error_code, EventToSend)>;

// ============================================================================
// EventChannelRegistry - Manages event channels for active sessions
// ============================================================================
class EventChannelRegistry {
public:
    static std::shared_ptr<EventChannel> get_or_create(
        uint64_t session_id,
        boost::asio::io_context& io
    ) {
        auto& channels = get_channels();

        auto it = channels.find(session_id);
        if (it != channels.end()) {
            return it->second;
        }

        auto channel = std::make_shared<EventChannel>(io, 100);
        channels[session_id] = channel;

        spdlog::debug("Created event channel for session {}", session_id);
        return channel;
    }

    static void remove(uint64_t session_id) {
        auto& channels = get_channels();
        auto it = channels.find(session_id);
        if (it != channels.end()) {
            it->second->close();
            channels.erase(it);
            spdlog::debug("Removed event channel for session {}", session_id);
        }
    }

    static bool try_send(uint64_t session_id, EventToSend event) {
        auto& channels = get_channels();
        auto it = channels.find(session_id);
        if (it != channels.end()) {
            return it->second->try_send(boost::system::error_code{}, std::move(event));
        }
        return false;
    }

private:
    static std::unordered_map<uint64_t, std::shared_ptr<EventChannel>>& get_channels() {
        static std::unordered_map<uint64_t, std::shared_ptr<EventChannel>> channels;
        return channels;
    }
};

} // namespace wamp
