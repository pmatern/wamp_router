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
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#if defined(__linux__)
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace wamp {

struct CpuLimits {
    unsigned hardware{};                  // hardware_concurrency()
    std::optional<unsigned> affinity;     // CPUs this process may be scheduled on (Linux sched_getaffinity)
    std::optional<double> cgroup_quota;   // CFS bandwidth limit in CPUs (quota / period), if one is set
    std::optional<double> ecs_task_cpu;   // ECS/Fargate task CPU limit in vCPUs (from the task metadata endpoint)
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

// The task-level CPU limit from the ECS task metadata document (GET $ECS_CONTAINER_METADATA_URI_V4/task):
//   {"Cluster":..., "Limits":{"CPU":0.5,"Memory":1024}, ..., "Containers":[{... "Limits":{"CPU":2} ...}]}
// Per-container "Limits" inside the Containers array are ignored.
[[nodiscard]] inline std::optional<double> parse_ecs_task_cpu_limit(std::string_view json) {
    std::string text{json};

    // drop the Containers array (bracket matching, skipping strings) so only task-level keys remain
    if (auto key = text.find("\"Containers\""); key != std::string::npos) {
        if (auto open = text.find('[', key); open != std::string::npos) {
            int depth = 0;
            bool in_string = false;
            size_t i = open;
            for (; i < text.size(); ++i) {
                const char c = text[i];
                if (in_string) {
                    if (c == '\\') ++i;
                    else if (c == '"') in_string = false;
                } else if (c == '"') {
                    in_string = true;
                } else if (c == '[') {
                    ++depth;
                } else if (c == ']' && --depth == 0) {
                    break;
                }
            }
            text.erase(open, i - open + 1);
        }
    }

    auto limits = text.find("\"Limits\"");
    if (limits == std::string::npos) return std::nullopt;
    auto end = text.find('}', limits);
    auto cpu = text.find("\"CPU\"", limits);
    if (cpu == std::string::npos || (end != std::string::npos && cpu > end)) return std::nullopt;
    auto colon = text.find(':', cpu);
    if (colon == std::string::npos) return std::nullopt;
    try {
        const double v = std::stod(text.substr(colon + 1, 24));
        return v > 0 ? std::optional<double>{v} : std::nullopt;
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
                                                   std::optional<double> cgroup_quota,
                                                   std::optional<double> ecs_task_cpu = std::nullopt) {
    CpuLimits limits;
    limits.hardware = hardware;
    limits.affinity = affinity;
    limits.cgroup_quota = cgroup_quota;
    limits.ecs_task_cpu = ecs_task_cpu;

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
    if (ecs_task_cpu) {
        // Fargate does not expose its limit through the cgroup (and shows 2 CPUs even to a 0.5 or 1 vCPU task)
        const auto task_cpus = static_cast<unsigned>(std::max(1.0, std::ceil(*ecs_task_cpu - 1e-9)));
        if (task_cpus < available) {
            available = task_cpus;
            limits.source = "ECS task CPU limit";
        }
    }
    limits.available = std::max(available, 1u);
    return limits;
}

#if defined(__linux__)
namespace detail {
// Minimal blocking HTTP GET to the ECS metadata endpoint (a link-local address, answers in under a
// millisecond). Used once at startup, only when ECS_CONTAINER_METADATA_URI_V4 is set.
[[nodiscard]] inline std::optional<std::string> http_get(const std::string& url, int timeout_ms) {
    constexpr std::string_view scheme = "http://";
    if (url.compare(0, scheme.size(), scheme) != 0) return std::nullopt;
    const auto host_end = url.find('/', scheme.size());
    std::string host_port = url.substr(scheme.size(), host_end == std::string::npos ? std::string::npos : host_end - scheme.size());
    const std::string path = host_end == std::string::npos ? "/" : url.substr(host_end);
    std::string host = host_port, port = "80";
    if (auto colon = host_port.find(':'); colon != std::string::npos) {
        host = host_port.substr(0, colon);
        port = host_port.substr(colon + 1);
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0 || !result) return std::nullopt;

    int fd = ::socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0) { freeaddrinfo(result); return std::nullopt; }
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    const int connected = ::connect(fd, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    if (connected != 0) { ::close(fd); return std::nullopt; }

    const std::string request = "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (::send(fd, request.data(), request.size(), 0) != static_cast<ssize_t>(request.size())) {
        ::close(fd);
        return std::nullopt;
    }
    std::string response;
    char buffer[4096];
    while (true) {
        const ssize_t n = ::recv(fd, buffer, sizeof buffer, 0);
        if (n <= 0) break;
        response.append(buffer, static_cast<size_t>(n));
        if (response.size() > (1u << 20)) break;
    }
    ::close(fd);

    const auto body = response.find("\r\n\r\n");
    if (body == std::string::npos || response.compare(0, 9, "HTTP/1.0 ") != 0 && response.compare(0, 9, "HTTP/1.1 ") != 0) {
        return std::nullopt;
    }
    return response.substr(body + 4);
}
}  // namespace detail
#endif

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
    std::optional<double> ecs_task_cpu;
#if defined(__linux__)
    if (const char* uri = std::getenv("ECS_CONTAINER_METADATA_URI_V4")) {
        if (auto body = detail::http_get(std::string{uri} + "/task", 500)) {
            ecs_task_cpu = parse_ecs_task_cpu_limit(*body);
        }
    }
#endif
    return combine_cpu_limits(std::thread::hardware_concurrency(), affinity, quota, ecs_task_cpu);
}

}  // namespace wamp
