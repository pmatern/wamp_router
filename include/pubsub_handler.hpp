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
#include "realm.hpp"
#include "event_channel.hpp"
#include "raw_socket.hpp"
#include <spdlog/spdlog.h>
#include <vector>
#include <cstdint>
#include <span>
#include <memory>
#include <optional>

namespace wamp {

// ============================================================================
// PubSubHandler - Handles WAMP PubSub operations (SUBSCRIBE/PUBLISH)
// ============================================================================
class PubSubHandler {
public:
    static void cleanup_session(Realm& realm, uint64_t session_id) {
        auto& sub_manager = realm.subscriptions;
        sub_manager.unsubscribe_session(session_id);
        spdlog::debug("Cleaned up subscriptions for session {}", session_id);
    }

    // Handle SUBSCRIBE message
    // Returns response bytes (SUBSCRIBED message wrapped in RawSocket frame)
    [[nodiscard]] static std::vector<uint8_t> handle_subscribe(
        Realm& realm,
        const SubscribeMessage& subscribe,
        uint64_t session_id
    ) {
        auto& sub_manager = realm.subscriptions;
        spdlog::debug("SUBSCRIBE request_id={}, topic={}, session={}",
                     subscribe.request_id, subscribe.topic, session_id);

        static RouterScopeIdGenerator sub_id_gen;
        uint64_t subscription_id = sub_id_gen.generate();

        sub_manager.subscribe(subscription_id, subscribe.topic, session_id);

        auto subscribed = SubscribedMessage{subscribe.request_id, subscription_id};
        auto subscribed_cbor = serialize_subscribed(subscribed);

        spdlog::info("Sent SUBSCRIBED: request_id={}, subscription_id={}, topic={}",
                    subscribe.request_id, subscription_id, subscribe.topic);

        return rawsocket::create_wamp_message(subscribed_cbor);
    }

    // Handle UNSUBSCRIBE message
    // Returns UNSUBSCRIBED, or ERROR if the subscription doesn't exist or belongs to another session
    [[nodiscard]] static std::vector<uint8_t> handle_unsubscribe(
        Realm& realm,
        const UnsubscribeMessage& unsubscribe,
        uint64_t session_id
    ) {
        auto& sub_manager = realm.subscriptions;
        spdlog::debug("UNSUBSCRIBE request_id={}, subscription_id={}, session={}",
                     unsubscribe.request_id, unsubscribe.subscription_id, session_id);

        auto info = sub_manager.get_subscription(unsubscribe.subscription_id);
        if (!info.has_value() || info->session_id != session_id) {
            spdlog::warn("UNSUBSCRIBE for unknown subscription_id={} from session {}",
                        unsubscribe.subscription_id, session_id);
            return rawsocket::create_wamp_message(serialize_error(
                ErrorMessage::create_no_such_subscription(unsubscribe.request_id)));
        }

        sub_manager.unsubscribe(unsubscribe.subscription_id);

        spdlog::info("Sent UNSUBSCRIBED: request_id={}, subscription_id={}",
                    unsubscribe.request_id, unsubscribe.subscription_id);

        return rawsocket::create_wamp_message(
            serialize_unsubscribed(UnsubscribedMessage{unsubscribe.request_id}));
    }

    // Handle PUBLISH message
    // Sends events directly to subscriber channels, returns acknowledgment response if requested
    [[nodiscard]] static std::vector<uint8_t> handle_publish(
        Realm& realm,
        const PublishMessage& publish,
        uint64_t session_id
    ) {
        const auto& sub_manager = realm.subscriptions;
        spdlog::debug("PUBLISH request_id={}, topic={}, session={}",
                     publish.request_id, publish.topic, session_id);

        static GlobalIdGenerator pub_id_gen;
        uint64_t publication_id = pub_id_gen.generate();

        // exclude_me defaults to true per the WAMP spec: the publisher doesn't receive its own event
        bool exclude_me = true;
        if (auto it = publish.options.find("exclude_me"); it != publish.options.end()) {
            if (auto* val = std::get_if<bool>(&it->second)) {
                exclude_me = *val;
            }
        }

        // Serialize the EVENT once; each subscriber only needs its subscription id stamped in
        std::optional<EventTemplate> event_template;
        size_t subscriber_count = 0;
        size_t sent_count = 0;

        sub_manager.for_each_subscriber(publish.topic,
            [&](uint64_t subscription_id, uint64_t subscriber_session) {
                ++subscriber_count;

                if (exclude_me && subscriber_session == session_id) {
                    return;
                }

                if (!event_template) {
                    event_template.emplace(EventMessage{0, publication_id, {},
                                                        publish.arguments, publish.arguments_kw});
                }

                auto event_data = std::make_shared<std::vector<uint8_t>>(
                    event_template->frame_for(subscription_id));

                if (accepted(EventChannelRegistry::deliver(subscriber_session,
                    EventToSend{subscriber_session, std::move(event_data)}))) {
                    ++sent_count;
                    spdlog::debug("Sent EVENT to session {} via channel (subscription_id={})",
                                subscriber_session, subscription_id);
                } else {
                    spdlog::debug("EVENT for session {} not delivered (queue full or session gone)",
                                subscriber_session);
                }
            });

        spdlog::debug("Topic '{}' has {} subscribers", publish.topic, subscriber_count);
        if (subscriber_count > 0) {
            spdlog::info("Sent {}/{} EVENT messages for publication_id={}, topic={}",
                        sent_count, subscriber_count, publication_id, publish.topic);
        }

        bool acknowledge = false;
        auto ack_it = publish.options.find("acknowledge");
        if (ack_it != publish.options.end()) {
            if (auto* ack_val = std::get_if<bool>(&ack_it->second)) {
                acknowledge = *ack_val;
            }
        }

        if (acknowledge) {
            auto published = PublishedMessage{publish.request_id, publication_id};
            auto published_cbor = serialize_published(published);

            spdlog::info("Sent PUBLISHED: request_id={}, publication_id={}, topic={}",
                        publish.request_id, publication_id, publish.topic);

            return rawsocket::create_wamp_message(published_cbor);
        }

        spdlog::debug("No acknowledgment requested for publication_id={}, topic={}",
                     publication_id, publish.topic);

        return {};  // Empty response
    }
};

} // namespace wamp
