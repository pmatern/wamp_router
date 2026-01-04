// Copyright 2026 Patrick Matern
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
#include <fmt/core.h>
#include <spdlog/spdlog.h>
#include <filesystem>

int main(int argc, char* argv[]) {
    try {
        std::filesystem::path config_path = "config.toml";
        if (argc > 1) {
            if (std::string{argv[1]} == "--config" && argc > 2) {
                config_path = argv[2];
            } else if (std::string{argv[1]} == "--help" || std::string{argv[1]} == "-h") {
                fmt::print("Usage: {} [--config <path>]\n", argv[0]);
                fmt::print("  Default config: config.toml\n");
                fmt::print("  --config <path>  Specify custom configuration file\n");
                fmt::print("  --help, -h       Show this help message\n");
                return 0;
            } else {
                fmt::print(stderr, "Unknown option: {}\n", argv[1]);
                fmt::print(stderr, "Use --help for usage information\n");
                return 1;
            }
        }

        auto config_result = wamp::Config::load(config_path);
        if (!config_result.has_value()) {
            fmt::print(stderr, "Failed to load configuration from {}: {}\n",
                config_path.string(), config_result.error().message());
            return 1;
        }
        const auto& config = *config_result;

        spdlog::set_level(config.log_level);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] %v");

        wamp::ProcedureHandler::set_max_pending_invocations(
            config.max_pending_invocations);

        fmt::print("\n");
        fmt::print("╔════════════════════════════════════════╗\n");
        fmt::print("║   WAMP Router (RawSocket + CBOR)      ║\n");
        fmt::print("╚════════════════════════════════════════╝\n");
        fmt::print("\n");
        fmt::print("Configuration:\n");
        fmt::print("  Port: {}\n", config.port);
        fmt::print("  TLS Certificate: {}\n", config.tls.cert_path.string());
        fmt::print("  TLS Key: {}\n", config.tls.key_path.string());
        if (config.tls.ca_path) {
            fmt::print("  TLS CA: {}\n", config.tls.ca_path->string());
        }
        if (config.tls.require_client_cert) {
            fmt::print("  Client Cert Required: yes\n");
        }
        fmt::print("  Max Pending Invocations: {}\n",
            config.max_pending_invocations);
        fmt::print("  Log Level: {}\n",
            spdlog::level::to_string_view(config.log_level));
        fmt::print("  Authentication Keys: {}\n",
            config.auth_keys.size());
        fmt::print("\n");
        fmt::print("Press Ctrl+C to stop\n\n");

        boost::asio::io_context io_context;

        wamp::WampTlsServer server{io_context, config};
        server.start();

        io_context.run();

    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
