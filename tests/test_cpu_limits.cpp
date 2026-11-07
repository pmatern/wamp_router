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
#include "include/cpu_limits.hpp"

using namespace wamp;

TEST_CASE("cgroup v2 cpu.max parsing", "[cpu_limits]") {
    REQUIRE(parse_cgroup_v2_cpu_max("max 100000\n") == std::nullopt);
    REQUIRE(parse_cgroup_v2_cpu_max("200000 100000\n") == 2.0);
    REQUIRE(parse_cgroup_v2_cpu_max("150000 100000") == 1.5);
    REQUIRE(parse_cgroup_v2_cpu_max("50000 100000") == 0.5);
    REQUIRE(parse_cgroup_v2_cpu_max("") == std::nullopt);
    REQUIRE(parse_cgroup_v2_cpu_max("garbage") == std::nullopt);
    REQUIRE(parse_cgroup_v2_cpu_max("100000 0") == std::nullopt);
}

TEST_CASE("cgroup v1 quota parsing", "[cpu_limits]") {
    REQUIRE(parse_cgroup_v1("-1\n", "100000\n") == std::nullopt);
    REQUIRE(parse_cgroup_v1("400000\n", "100000\n") == 4.0);
    REQUIRE(parse_cgroup_v1("nonsense", "100000") == std::nullopt);
}

TEST_CASE("CPU budget combines hardware, affinity and cgroup quota", "[cpu_limits]") {
    SECTION("no limits: all hardware threads") {
        auto l = combine_cpu_limits(16, std::nullopt, std::nullopt);
        REQUIRE(l.available == 16);
        REQUIRE(l.source == "hardware");
    }
    SECTION("a quota below the host's CPUs wins (Fargate / Kubernetes)") {
        auto l = combine_cpu_limits(64, 64u, 2.0);
        REQUIRE(l.available == 2);
        REQUIRE(l.source == "cgroup cpu quota");
    }
    SECTION("fractional quotas round up, never to zero") {
        REQUIRE(combine_cpu_limits(8, std::nullopt, 1.5).available == 2);
        REQUIRE(combine_cpu_limits(8, std::nullopt, 0.25).available == 1);
        REQUIRE(combine_cpu_limits(8, std::nullopt, 2.0).available == 2);
    }
    SECTION("cpuset / affinity below the quota wins") {
        auto l = combine_cpu_limits(32, 4u, 16.0);
        REQUIRE(l.available == 4);
        REQUIRE(l.source == "cpu affinity");
    }
    SECTION("a quota above the CPUs we may use changes nothing") {
        REQUIRE(combine_cpu_limits(4, 4u, 16.0).available == 4);
    }
    SECTION("degenerate inputs still give at least one CPU") {
        REQUIRE(combine_cpu_limits(0, 0u, std::nullopt).available == 1);
    }
}

TEST_CASE("Detection returns a usable budget on this machine", "[cpu_limits]") {
    auto l = detect_cpu_limits();
    REQUIRE(l.available >= 1);
    REQUIRE(l.available <= std::max(l.hardware, 1u));
}
