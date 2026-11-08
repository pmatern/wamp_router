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

#include "include/router.hpp"
#include "include/subscription_manager.hpp"
#include "include/wamp_client.hpp"
#include "include/wamp_server.hpp"
#include <catch2/catch_test_macros.hpp>

// The template constraints are checked at compile time; the test case only gives the file a home in the suite.

using namespace wamp;
using asio::ip::tcp;
using TlsStream = asio::ssl::stream<tcp::socket>;

// Sockets
static_assert(WampSocket<tcp::socket>);
static_assert(WampSocket<TlsStream>);
static_assert(!WampSocket<int>);
static_assert(!WampSocket<std::string>);
static_assert(!WampSocket<asio::io_context>);
static_assert(TlsSocket<TlsStream>);
static_assert(!TlsSocket<tcp::socket>);
static_assert(!TlsSocket<int>);

// Field extractors read a message from a fast::Fields and produce it
using Extract = decltype([](fast::Fields&) { return GoodbyeMessage::create_normal(); });
static_assert(fast::FieldExtractor<Extract, GoodbyeMessage>);
static_assert(!fast::FieldExtractor<Extract, HelloMessage>);                     // wrong result type
static_assert(!fast::FieldExtractor<decltype([](int) { return 1; }), int>);      // wrong argument type
static_assert(!fast::FieldExtractor<int, GoodbyeMessage>);                       // not callable

// Callables handed to the router and the subscription manager
// (the helper concepts keep the failed constraint a substitution failure instead of a hard error)
template<typename F>
concept CanPost = requires(Router& r, F f) { r.post_to_shard(0, std::move(f)); };
template<typename F>
concept CanVisitSubscribers = requires(const SubscriptionManager& m, F f) { m.for_each_subscriber("t", std::move(f)); };

static_assert(CanPost<decltype([] {})>);
static_assert(!CanPost<int>);                                                    // not callable
static_assert(!CanPost<decltype([](int) {})>);                                   // needs an argument
static_assert(CanVisitSubscribers<decltype([](uint64_t, uint64_t) {})>);
static_assert(!CanVisitSubscribers<decltype([](const std::string&) {})>);

// The client's message types
static_assert(ClientMessage<CallMessage>);
static_assert(ClientMessage<GoodbyeMessage>);
static_assert(!ClientMessage<HelloMessage>);
static_assert(!ClientMessage<int>);
static_assert(std::same_as<ReplyChannel<ResultMessage>,
                           asio::experimental::channel<void(std::error_code, std::optional<ResultMessage>)>>);

TEST_CASE("Template constraints are in place", "[concepts]") {
    SUCCEED("checked by static_assert");
}
