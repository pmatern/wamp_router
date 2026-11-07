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
#include <boost/asio/io_context.hpp>
#include "include/procedure_handler.hpp"
#include "include/pubsub_handler.hpp"
#include "include/realm.hpp"
#include "include/wamp_serializer.hpp"

using namespace wamp;

namespace {

std::vector<uint8_t> payload_of(const std::vector<uint8_t>& frame) {
    REQUIRE(frame.size() > 4);
    return {frame.begin() + 4, frame.end()};
}

std::vector<uint8_t> pop_frame(EventChannel& channel) {
    std::vector<uint8_t> out;
    channel.try_receive([&](boost::system::error_code ec, EventToSend ev) {
        if (!ec && ev.event_data) {
            out = *ev.event_data;
        }
    });
    return out;
}

// Two sessions in realm A and one in realm B, with their event channels
struct TwoRealms {
    boost::asio::io_context io;
    Shard shard;
    Realm& a = shard.realms.get("isolation.a");
    Realm& b = shard.realms.get("isolation.b");
    static constexpr uint64_t kA1 = 920001, kA2 = 920002, kB1 = 920003;
    std::shared_ptr<EventChannel> ch_a1 = shard.channels.get_or_create(kA1, io);
    std::shared_ptr<EventChannel> ch_a2 = shard.channels.get_or_create(kA2, io);
    std::shared_ptr<EventChannel> ch_b1 = shard.channels.get_or_create(kB1, io);

    ~TwoRealms() {
        for (auto id : {kA1, kA2}) {
            PubSubHandler::cleanup_session(a, id);
            ProcedureHandler::cleanup_session(a, id);
            shard.channels.remove(id);
        }
        PubSubHandler::cleanup_session(b, kB1);
        ProcedureHandler::cleanup_session(b, kB1);
        shard.channels.remove(kB1);
    }
};

}  // namespace

TEST_CASE("RealmRegistry returns one stable Realm per name", "[realm]") {
    Shard shard;
    Realm& first = shard.realms.get("realm.stable");
    Realm& again = shard.realms.get(std::string{"realm.stable"});
    REQUIRE(&first == &again);
    REQUIRE(&first != &shard.realms.get("realm.other"));
    REQUIRE(&first.shard == &shard);

    // another shard has its own, unrelated realm of the same name
    Shard other;
    REQUIRE(&other.realms.get("realm.stable") != &first);
}

TEST_CASE("PUBLISH only reaches subscribers in the publisher's realm", "[realm][pubsub]") {
    TwoRealms r;
    (void)PubSubHandler::handle_subscribe(r.a, SubscribeMessage{1, {}, "shared.topic"}, r.kA2);
    (void)PubSubHandler::handle_subscribe(r.b, SubscribeMessage{1, {}, "shared.topic"}, r.kB1);

    SECTION("publish in A") {
        (void)PubSubHandler::handle_publish(r.a, PublishMessage{2, {}, "shared.topic"}, r.kA1);
        REQUIRE(!pop_frame(*r.ch_a2).empty());
        REQUIRE(pop_frame(*r.ch_b1).empty());
    }

    SECTION("publish in B") {
        (void)PubSubHandler::handle_publish(r.b, PublishMessage{2, {}, "shared.topic"}, r.kB1);
        REQUIRE(pop_frame(*r.ch_a2).empty());
    }

    SECTION("a subscription from another realm cannot be unsubscribed") {
        const auto sub_id = r.a.subscriptions.get_subscribers("shared.topic").front();
        auto resp = PubSubHandler::handle_unsubscribe(r.b, UnsubscribeMessage{3, sub_id}, r.kA2);
        auto type = get_message_type_from_cbor(payload_of(resp));
        REQUIRE(type.has_value());
        REQUIRE(*type == MessageType::ERROR);
        REQUIRE(r.a.subscriptions.get_subscription(sub_id).has_value());
    }
}

TEST_CASE("Procedures are per realm", "[realm][rpc]") {
    TwoRealms r;

    SECTION("the same procedure can be registered in two realms") {
        REQUIRE(ProcedureHandler::handle_register(r.a, RegisterMessage{1, {}, "shared.proc"}, r.kA2).has_value());
        REQUIRE(ProcedureHandler::handle_register(r.b, RegisterMessage{1, {}, "shared.proc"}, r.kB1).has_value());
        REQUIRE(r.a.registrations.find_callee("shared.proc")->session_id == r.kA2);
        REQUIRE(r.b.registrations.find_callee("shared.proc")->session_id == r.kB1);
    }

    SECTION("a CALL resolves only inside the caller's realm") {
        REQUIRE(ProcedureHandler::handle_register(r.b, RegisterMessage{1, {}, "only.in.b"}, r.kB1).has_value());

        auto resp = ProcedureHandler::handle_call(r.a, CallMessage{2, {}, "only.in.b"}, r.kA1);
        REQUIRE(resp.has_value());
        auto err = deserialize_error(payload_of(*resp));
        REQUIRE(err.has_value());
        REQUIRE(err->error_uri == "wamp.error.no_such_procedure");
        REQUIRE(pop_frame(*r.ch_b1).empty());  // the callee in B never saw an INVOCATION
    }

    SECTION("cleaning up a session leaves the other realm's registrations") {
        REQUIRE(ProcedureHandler::handle_register(r.a, RegisterMessage{1, {}, "shared.proc"}, r.kA2).has_value());
        REQUIRE(ProcedureHandler::handle_register(r.b, RegisterMessage{1, {}, "shared.proc"}, r.kB1).has_value());
        ProcedureHandler::cleanup_session(r.a, r.kA2);
        REQUIRE_FALSE(r.a.registrations.find_callee("shared.proc").has_value());
        REQUIRE(r.b.registrations.find_callee("shared.proc").has_value());
    }
}
