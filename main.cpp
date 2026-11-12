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


#include "include/wamp_server.hpp"
#include "include/config.hpp"
#include "include/procedure_handler.hpp"
#include "include/cpu_limits.hpp"
#include "include/router.hpp"
#include <print>
#include "include/logging.hpp"
#include <spdlog/spdlog.h>
#include <filesystem>

int main(int argc, char* argv[]) {
    try {
        std::filesystem::path config_path{ "config.toml" };
        if (argc > 1) {
            if (std::string{argv[1]} == "--config" && argc > 2) {
                config_path = argv[2];
            } else if (std::string{argv[1]} == "--help" || std::string{argv[1]} == "-h") {
                std::print("Usage: {} [--config <path>]\n", argv[0]);
                std::print("  Default config: config.toml\n");
                std::print("  --config <path>  Specify custom configuration file\n");
                std::print("  --help, -h       Show this help message\n");
                return 0;
            } else {
                std::print(stderr, "Unknown option: {}\n", argv[1]);
                std::print(stderr, "Use --help for usage information\n");
                return 1;
            }
        }

        auto config_result = wamp::Config::load(config_path);
        if (!config_result.has_value()) {
            std::print(stderr, "Failed to load configuration from {}: {}\n",
                config_path.string(), config_result.error().message());
            return 1;
        }
        const auto& config = *config_result;

        wamp::logging::init({config.log_level, config.log_async, config.log_queue_size, config.log_file});

        std::print("\n");
        std::print("╔════════════════════════════════════════╗\n");
        std::print("║              WAMP Router               ║\n");
        std::print("╚════════════════════════════════════════╝\n");
        std::print("\n");
        std::print("Configuration:\n");
        std::print("  Port: {}\n", config.port);
        std::print("  TLS Certificate: {}\n", config.tls.cert_path.string());
        std::print("  TLS Key: {}\n", config.tls.key_path.string());
        if (config.tls.ca_path) {
            std::print("  TLS CA: {}\n", config.tls.ca_path->string());
        }
        if (config.tls.require_client_cert) {
            std::print("  Client Cert Required: yes\n");
        }
        std::print("  Max Pending Invocations: {}\n",
            config.max_pending_invocations);
        std::print("  Call Timeout: {} ms\n", config.call_timeout.count());
        {
            const auto cpus = wamp::detect_cpu_limits();
            std::print("  CPUs available: {} (hardware {}, limited by {})\n", cpus.available, cpus.hardware, cpus.source);
        }
        std::print("  Event Queue: {} per session, overflow={}, backpressure timeout={} ms, slow subscriber limit={}\n",
            config.events.size,
            config.events.overflow == wamp::OverflowPolicy::BACKPRESSURE ? "backpressure" : "drop",
            config.events.backpressure_timeout.count(),
            config.events.slow_subscriber_limit);
        std::print("  Threads (shards): {}\n", config.threads == 0 ? std::string{"auto"} : std::to_string(config.threads));
        std::print("  Log Level: {}\n",
            spdlog::level::to_string_view(config.log_level));
        std::print("  Authentication Keys: {}\n",
            config.auth_keys.size());
        std::print("\n");
        std::print("Press Ctrl+C to stop\n\n");

        if (const auto fds = wamp::raise_fd_limit()) {
            spdlog::info("Open-file limit: {}", *fds);
        }
        const unsigned threads = config.threads == 0 ? wamp::detect_cpu_limits().available : config.threads;
        wamp::Router router{config, wamp::Router::Transport::TLS, threads};
        router.stop_on_signals();
        router.start();
        router.wait();
        const auto stats = router.stats();
        for (size_t i = 0; i < stats.size(); ++i) {
            const auto& s = stats[i];
            spdlog::info("shard {}: accepted={} publishes={} calls={} handshake_timeouts={} event_drops={} inbox_received={} inbox_dropped={} rate_throttles={} rate_closes={}",
                         i, s.accepted, s.publishes, s.calls, s.handshake_timeouts, s.event_drops, s.inbox_received, s.inbox_dropped,
                         s.rate_throttles, s.rate_closes);
        }
        if (const auto rejected = router.rejected_connections(); rejected.total_limit + rejected.address_limit + rejected.rate_limit > 0) {
            spdlog::info("Rejected connections: {} over max_connections, {} over max_connections_per_ip, {} over the connection rate",
                         rejected.total_limit, rejected.address_limit, rejected.rate_limit);
        }
        if (const auto lost = wamp::logging::overruns(); lost > 0) {
            spdlog::warn("{} log line(s) were dropped because the log writer could not keep up", lost);
        }
        spdlog::shutdown();   // flushes the async writer

    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
