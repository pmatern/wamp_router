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


#pragma once

#include <toml.hpp>
#include <filesystem>
#include <expected>
#include <system_error>
#include <string>
#include <optional>
#include <unordered_map>
#include <spdlog/spdlog.h>

namespace wamp {

// ============================================================================
// ConfigError - Error codes for configuration loading
// ============================================================================
enum class ConfigError {
    FILE_NOT_FOUND = 1,
    PARSE_ERROR,
    MISSING_REQUIRED_FIELD,
    INVALID_VALUE,
    CERT_FILE_NOT_FOUND,
    KEY_FILE_NOT_FOUND,
    INVALID_AUTH_KEY,
    NO_AUTH_KEYS
};

class ConfigErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override {
        return "wamp_config";
    }

    [[nodiscard]] std::string message(int ev) const override {
        switch (static_cast<ConfigError>(ev)) {
            case ConfigError::FILE_NOT_FOUND:
                return "Configuration file not found";
            case ConfigError::PARSE_ERROR:
                return "Failed to parse configuration file";
            case ConfigError::MISSING_REQUIRED_FIELD:
                return "Required configuration field is missing";
            case ConfigError::INVALID_VALUE:
                return "Configuration value is invalid";
            case ConfigError::CERT_FILE_NOT_FOUND:
                return "TLS certificate file not found";
            case ConfigError::KEY_FILE_NOT_FOUND:
                return "TLS private key file not found";
            case ConfigError::INVALID_AUTH_KEY:
                return "Invalid authentication key format (must be 64 hex chars)";
            case ConfigError::NO_AUTH_KEYS:
                return "No authentication keys configured (at least one required)";
            default:
                return "Unknown configuration error";
        }
    }
};

inline const ConfigErrorCategory& config_error_category() {
    static ConfigErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(ConfigError e) {
    return {static_cast<int>(e), config_error_category()};
}

// ============================================================================
// TlsConfig - TLS certificate and key configuration
// ============================================================================
struct TlsConfig {
    std::filesystem::path cert_path;
    std::filesystem::path key_path;

    // Optional: CA certificate path for client cert verification
    std::optional<std::filesystem::path> ca_path;

    // Optional: Require client certificates (mutual TLS)
    bool require_client_cert = false;
};

// ============================================================================
// ServerConfig - Complete server configuration
// ============================================================================
struct ServerConfig {
    unsigned short port;
    TlsConfig tls;
    size_t max_pending_invocations;
    spdlog::level::level_enum log_level;

    // Authentication: authid → Ed25519 public key (hex-encoded, 64 chars = 32 bytes)
    std::unordered_map<std::string, std::string> auth_keys;
};

// ============================================================================
// Config - Configuration loader and parser
// ============================================================================
class Config {
public:
    // Load configuration from TOML file
    [[nodiscard]] static std::expected<ServerConfig, std::error_code> load(
        const std::filesystem::path& config_path
    ) {
        if (!std::filesystem::exists(config_path)) {
            spdlog::error("Configuration file not found: {}", config_path.string());
            return std::unexpected{make_error_code(ConfigError::FILE_NOT_FOUND)};
        }

        toml::value config_data;
        try {
            config_data = toml::parse(config_path.string());
        } catch (const std::exception& e) {
            spdlog::error("Failed to parse config file: {}", e.what());
            return std::unexpected{make_error_code(ConfigError::PARSE_ERROR)};
        }

        ServerConfig config;

        try {
            const auto& server = toml::find(config_data, "server");
            config.port = toml::find<unsigned short>(server, "port");

            const auto& tls = toml::find(server, "tls");
            config.tls.cert_path = toml::find<std::string>(tls, "cert");
            config.tls.key_path = toml::find<std::string>(tls, "key");

            if (tls.contains("ca")) {
                config.tls.ca_path = toml::find<std::string>(tls, "ca");
            }

            if (tls.contains("require_client_cert")) {
                config.tls.require_client_cert =
                    toml::find<bool>(tls, "require_client_cert");
            }

            if (server.contains("rpc")) {
                const auto& rpc = toml::find(server, "rpc");
                config.max_pending_invocations =
                    toml::find<size_t>(rpc, "max_pending_invocations");
            } else {
                config.max_pending_invocations = 10000; // Default
            }

            if (config_data.contains("logging")) {
                const auto& logging = toml::find(config_data, "logging");
                std::string level_str = toml::find<std::string>(logging, "level");
                config.log_level = parse_log_level(level_str);
            } else {
                config.log_level = spdlog::level::info; // Default
            }

            if (config_data.contains("auth")) {
                const auto& auth = toml::find(config_data, "auth");
                if (auth.contains("keys")) {
                    const auto& keys = toml::find(auth, "keys").as_table();
                    if (keys.empty()) {
                        spdlog::warn("No authentication keys configured in [auth.keys]");
                    }

                    for (const auto& [authid, public_key_value] : keys) {
                        std::string public_key_hex = public_key_value.as_string();

                        // Validate: must be exactly 64 hex characters (32 bytes)
                        if (public_key_hex.length() != 64) {
                            spdlog::error("Invalid public key for authid '{}': length {} (expected 64)",
                                authid, public_key_hex.length());
                            return std::unexpected{make_error_code(ConfigError::INVALID_AUTH_KEY)};
                        }

                        // Validate: all characters must be valid hex
                        for (char c : public_key_hex) {
                            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                                spdlog::error("Invalid public key for authid '{}': contains non-hex character '{}'",
                                    authid, c);
                                return std::unexpected{make_error_code(ConfigError::INVALID_AUTH_KEY)};
                            }
                        }

                        config.auth_keys[authid] = public_key_hex;
                        spdlog::debug("Loaded public key for authid: {}", authid);
                    }

                    spdlog::info("Loaded {} authentication key(s)", config.auth_keys.size());
                }
            }

        } catch (const std::exception& e) {
            spdlog::error("Missing or invalid config field: {}", e.what());
            return std::unexpected{
                make_error_code(ConfigError::MISSING_REQUIRED_FIELD)};
        }

        if (!std::filesystem::exists(config.tls.cert_path)) {
            spdlog::error("TLS certificate not found: {}",
                config.tls.cert_path.string());
            return std::unexpected{make_error_code(ConfigError::CERT_FILE_NOT_FOUND)};
        }

        if (!std::filesystem::exists(config.tls.key_path)) {
            spdlog::error("TLS private key not found: {}",
                config.tls.key_path.string());
            return std::unexpected{make_error_code(ConfigError::KEY_FILE_NOT_FOUND)};
        }

        if (config.tls.ca_path && !std::filesystem::exists(*config.tls.ca_path)) {
            spdlog::error("TLS CA certificate not found: {}",
                config.tls.ca_path->string());
            return std::unexpected{make_error_code(ConfigError::CERT_FILE_NOT_FOUND)};
        }

        return config;
    }

private:
    static spdlog::level::level_enum parse_log_level(const std::string& level) {
        if (level == "trace") return spdlog::level::trace;
        if (level == "debug") return spdlog::level::debug;
        if (level == "info") return spdlog::level::info;
        if (level == "warn") return spdlog::level::warn;
        if (level == "error") return spdlog::level::err;
        if (level == "critical") return spdlog::level::critical;
        return spdlog::level::info; // Default
    }
};

} // namespace wamp

namespace std {
    template<>
    struct is_error_code_enum<wamp::ConfigError> : true_type {};
}
