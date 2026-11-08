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

#include "include/event_channel.hpp"
#include "include/invocation_tracker.hpp"
#include "include/raw_socket.hpp"
#include "include/shard_group.hpp"
#include "include/websocket.hpp"
#include <catch2/catch_test_macros.hpp>
#include <type_traits>

// Types that move through the hot path or sit in std::vector / std::variant / hash maps must move without
// throwing: a throwing move makes std::vector reallocate by copying (and makes std::variant potentially
// valueless). The types are rule-of-zero, so this holds only while every member's move is noexcept; the
// asserts catch a member added later (or a standard library) that breaks it.

using namespace wamp;

template<typename T>
inline constexpr bool kNothrowMovable = std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_assignable_v<T>;

static_assert(kNothrowMovable<EventToSend>);
static_assert(kNothrowMovable<BlockedSend>);
static_assert(kNothrowMovable<PendingCall>);
static_assert(kNothrowMovable<CrossCall>);
static_assert(kNothrowMovable<CrossFrame>);
static_assert(kNothrowMovable<CrossCancel>);
static_assert(kNothrowMovable<CrossMessage>);
static_assert(kNothrowMovable<EventTemplate>);
static_assert(kNothrowMovable<ws::FrameHeaderBytes>);
static_assert(kNothrowMovable<ws::Parsed>);
static_assert(kNothrowMovable<rawsocket::FrameHeader>);

TEST_CASE("Hot-path types move without throwing", "[types]") {
    SUCCEED("checked by static_assert");
}
