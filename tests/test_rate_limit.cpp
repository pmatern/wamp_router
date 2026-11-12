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


#include "include/rate_limit.hpp"
#include <catch2/catch_test_macros.hpp>

using namespace wamp;
using namespace std::chrono_literals;
using Clock = TokenBucket::Clock;

TEST_CASE("TokenBucket allows a burst, then the rate", "[rate]") {
    const auto t0 = Clock::now();
    TokenBucket bucket{10.0, 5.0, t0};   // 10 per second, burst 5

    for (int i = 0; i < 5; ++i) CHECK(bucket.try_consume(t0));
    CHECK_FALSE(bucket.try_consume(t0));                    // burst used up
    CHECK_FALSE(bucket.try_consume(t0 + 50ms));             // 0.5 token
    CHECK(bucket.try_consume(t0 + 100ms));                  // 1 token after 100 ms at 10/s
    CHECK_FALSE(bucket.try_consume(t0 + 100ms));

    // never more than the burst, however long it idles
    for (int i = 0; i < 5; ++i) CHECK(bucket.try_consume(t0 + 1h));
    CHECK_FALSE(bucket.try_consume(t0 + 1h));
}

TEST_CASE("TokenBucket::consume reports how long the debt takes to pay", "[rate]") {
    const auto t0 = Clock::now();
    TokenBucket bucket{100.0, 10.0, t0};

    CHECK(bucket.consume(10, t0) == 0ns);                    // exactly the burst
    CHECK(bucket.consume(5, t0) == 50ms);                    // 5 tokens in debt at 100/s
    CHECK(bucket.consume(0, t0 + 50ms) == 0ns);              // paid off after waiting
    CHECK(bucket.consume(30, t0 + 50ms) == 300ms);

    // the debt is carried (a big read is paid for over time), and huge counts cannot overflow
    TokenBucket other{100.0, 10.0, t0};
    CHECK(other.consume(1'000, t0) == 9900ms);
    CHECK(other.consume(UINT64_MAX / 2, t0) > 1h);
}

TEST_CASE("TokenBucket survives a clock that stands still or goes back", "[rate]") {
    const auto t0 = Clock::now();
    TokenBucket bucket{10.0, 2.0, t0 + 1s};
    CHECK(bucket.try_consume(t0));    // earlier than its last update: no refill, no crash
    CHECK(bucket.try_consume(t0));
    CHECK_FALSE(bucket.try_consume(t0));
}

TEST_CASE("TokenBucket::full tells when nothing is left to remember", "[rate]") {
    const auto t0 = Clock::now();
    TokenBucket bucket{10.0, 5.0, t0};
    CHECK(bucket.full(t0));
    REQUIRE(bucket.try_consume(t0));
    CHECK_FALSE(bucket.full(t0));
    CHECK_FALSE(bucket.full(t0 + 50ms));
    CHECK(bucket.full(t0 + 100ms));
}

TEST_CASE("ConnectionRateLimiter limits each address separately", "[rate]") {
    const auto t0 = Clock::now();
    ConnectionRateLimiter limiter{2.0, 3.0};   // 2 per second, burst 3
    const auto a = asio::ip::make_address("10.0.0.1");
    const auto b = asio::ip::make_address("10.0.0.2");

    for (int i = 0; i < 3; ++i) CHECK(limiter.admit(a, t0));
    CHECK_FALSE(limiter.admit(a, t0));
    CHECK(limiter.admit(b, t0));                    // another address has its own allowance
    CHECK_FALSE(limiter.admit(a, t0 + 400ms));      // 0.8 token
    CHECK(limiter.admit(a, t0 + 500ms));            // 1 token
    CHECK(limiter.tracked() == 2);
}

TEST_CASE("ConnectionRateLimiter off, and pruning", "[rate]") {
    const auto t0 = Clock::now();
    ConnectionRateLimiter off{0.0, 0.0};
    CHECK_FALSE(off.enabled());
    for (int i = 0; i < 1000; ++i) CHECK(off.admit(asio::ip::make_address("10.0.0.1"), t0));
    CHECK(off.tracked() == 0);

    // many one-off addresses: entries whose bucket refilled are dropped by the periodic prune
    ConnectionRateLimiter limiter{1000.0, 1.0};
    for (uint32_t i = 0; i < ConnectionRateLimiter::kPruneEvery - 1; ++i) {
        CHECK(limiter.admit(asio::ip::address_v4{0x0A000000u + i}, t0));
    }
    CHECK(limiter.tracked() == ConnectionRateLimiter::kPruneEvery - 1);
    CHECK(limiter.admit(asio::ip::address_v4{0x0B000000u}, t0 + 10s));   // the prune runs on this call
    CHECK(limiter.tracked() == 1);
}
