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


// Minimal plain-TCP router for profiling: one io_context thread, logging off, no config file.
//
//   ./wamp_profile_router [--port 9000] [--queue-size 100] [--overflow backpressure|drop]
//   perf record -e cpu-clock -g -p <pid> -- sleep 10      # while wamp_load --port 9000 runs
//
// Pair it with `wamp_load --host 127.0.0.1 --port 9000` so router and load generator are separate
// processes and the profile contains only router work.

#include "include/config.hpp"
#include "include/cpu_limits.hpp"
#include "include/router.hpp"
#include <asio.hpp>
#include <spdlog/spdlog.h>
#include <cstdio>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <string>
#include <unistd.h>

int main(int argc, char** argv) {
    using namespace wamp;

    unsigned short port = 9000;
    unsigned threads = 1;
    ServerConfig config;
    bool log = false;
    config.max_pending_invocations = 10000;
    config.log_level = spdlog::level::off;
    config.events.size = 100;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        if (a == "--port") { if (auto v = next()) port = static_cast<unsigned short>(std::atoi(v)); }
        else if (a == "--threads") { if (auto v = next()) threads = static_cast<unsigned>(std::atoi(v)); }
        else if (a == "--max-connections") { if (auto v = next()) config.max_connections = std::strtoul(v, nullptr, 10); }
        else if (a == "--queue-size") { if (auto v = next()) config.events.size = std::strtoul(v, nullptr, 10); }
        else if (a == "--overflow") {
            if (auto v = next()) {
                config.events.overflow = std::string{v} == "drop" ? OverflowPolicy::DROP : OverflowPolicy::BACKPRESSURE;
            }
        }
        else if (a == "--log") log = true;
        else { std::puts("wamp_profile_router [--port P] [--threads N] [--max-connections N] [--queue-size N] [--overflow backpressure|drop] [--log]"); return 1; }
    }

    spdlog::set_level(log ? spdlog::level::info : spdlog::level::off);

    config.port = port;
    Router router{config, Router::Transport::PLAIN, threads};
    router.stop_on_signals();
    router.start();
    const auto cpus = detect_cpu_limits();
    std::printf("wamp_profile_router listening on %u (pid %d), %zu shard thread(s); CPUs available %u (hardware %u, limited by %s)\n",
                router.port(), static_cast<int>(getpid()), router.shard_count(), cpus.available, cpus.hardware,
                cpus.source.c_str());
    std::fflush(stdout);
    std::atomic<bool> stats_stop{false};
    std::thread stats([&] {
        uint64_t last = 0;
        while (!stats_stop.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            const auto total = router.dropped_events();
            if (total != last) {
                std::printf("drops total %llu (cross-shard inbox %llu)\n", static_cast<unsigned long long>(total),
                            static_cast<unsigned long long>(router.inbox_dropped_events()));
                std::fflush(stdout);
                last = total;
            }
        }
    });
    router.wait();
    stats_stop = true;
    stats.join();
    const auto rejected = router.rejected_connections();
    std::printf("rejected connections: %llu over max_connections, %llu over the per-address cap\n",
                static_cast<unsigned long long>(rejected.total_limit), static_cast<unsigned long long>(rejected.address_limit));
}
