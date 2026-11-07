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

// How many CPUs may this process actually use? std::thread::hardware_concurrency() reports the host's
// CPUs, ignoring container limits: a Fargate task or a Kubernetes pod with a 2-CPU quota on a 64-CPU host
// would start 64 threads and be throttled. A thread-per-core router sizes its thread count from here.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#if defined(__linux__)
#include <sched.h>
#endif

namespace wamp {

struct CpuLimits {
    unsigned hardware{};                  // hardware_concurrency()
    std::optional<unsigned> affinity;     // CPUs this process may be scheduled on (Linux sched_getaffinity)
    std::optional<double> cgroup_quota;   // CFS bandwidth limit in CPUs (quota / period), if one is set
    unsigned available{};                 // what to size thread pools from (at least 1)
    std::string source;                   // which limit decided `available`
};

// cgroup v2 "cpu.max": "max 100000" (no limit) or "<quota> <period>" in microseconds
[[nodiscard]] inline std::optional<double> parse_cgroup_v2_cpu_max(std::string_view text) {
    std::istringstream in{std::string{text}};
    std::string quota;
    double period = 0;
    if (!(in >> quota >> period) || period <= 0 || quota == "max") return std::nullopt;
    try {
        const double q = std::stod(quota);
        return q > 0 ? std::optional<double>{q / period} : std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// cgroup v1 "cpu.cfs_quota_us" (-1 = no limit) and "cpu.cfs_period_us"
[[nodiscard]] inline std::optional<double> parse_cgroup_v1(std::string_view quota_text, std::string_view period_text) {
    try {
        const double quota = std::stod(std::string{quota_text});
        const double period = std::stod(std::string{period_text});
        return (quota > 0 && period > 0) ? std::optional<double>{quota / period} : std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

namespace detail {
[[nodiscard]] inline std::optional<std::string> read_file(const char* path) {
    std::ifstream file{path};
    if (!file) return std::nullopt;
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}
}  // namespace detail

// Combines the inputs into a CPU budget. Pure function, so it can be tested without a container.
[[nodiscard]] inline CpuLimits combine_cpu_limits(unsigned hardware, std::optional<unsigned> affinity,
                                                   std::optional<double> cgroup_quota) {
    CpuLimits limits;
    limits.hardware = hardware;
    limits.affinity = affinity;
    limits.cgroup_quota = cgroup_quota;

    unsigned available = std::max(hardware, 1u);
    limits.source = "hardware";
    if (affinity && *affinity >= 1 && *affinity < available) {
        available = *affinity;
        limits.source = "cpu affinity";
    }
    if (cgroup_quota) {
        // A fractional quota (1.5 CPUs) rounds up: the extra thread still gets scheduled within the budget
        const auto quota_cpus = static_cast<unsigned>(std::max(1.0, std::ceil(*cgroup_quota - 1e-9)));
        if (quota_cpus < available) {
            available = quota_cpus;
            limits.source = "cgroup cpu quota";
        }
    }
    limits.available = std::max(available, 1u);
    return limits;
}

[[nodiscard]] inline CpuLimits detect_cpu_limits() {
    std::optional<unsigned> affinity;
#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        affinity = static_cast<unsigned>(CPU_COUNT(&set));
    }
#endif

    std::optional<double> quota;
    if (auto v2 = detail::read_file("/sys/fs/cgroup/cpu.max")) {
        quota = parse_cgroup_v2_cpu_max(*v2);
    } else if (auto q = detail::read_file("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")) {
        if (auto p = detail::read_file("/sys/fs/cgroup/cpu/cpu.cfs_period_us")) {
            quota = parse_cgroup_v1(*q, *p);
        }
    }
    return combine_cpu_limits(std::thread::hardware_concurrency(), affinity, quota);
}

}  // namespace wamp
