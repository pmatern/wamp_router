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

#include "authorizer.hpp"
#include <toml.hpp>
#include <filesystem>
#include <chrono>
#include <expected>
#include <system_error>
#include <string>
#include <optional>
#include <unordered_map>
#include <unordered_set>
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
// EventQueueConfig - Per-session delivery queue (router -> client) settings
// ============================================================================
enum class OverflowPolicy {
    BACKPRESSURE,  // Suspend the sending session until the queue drains (bounded by timeout)
    DROP           // Drop the event and count it
};

struct EventQueueConfig {
    size_t size{100};                                       // Events queued per session
    OverflowPolicy overflow{OverflowPolicy::BACKPRESSURE};
    std::chrono::milliseconds backpressure_timeout{1000};   // Max wait before dropping under BACKPRESSURE
    size_t slow_subscriber_limit{3};                        // Consecutive timeouts before a subscriber is skipped (0 = never)
};

// ============================================================================
// AuthRole - the role name(s) an authid gets: one for every realm, optionally overridden per realm
// ============================================================================
struct AuthRole {
    std::string default_role;                              // empty = no role unless a realm entry matches
    std::unordered_map<std::string, std::string> by_realm;  // realm → role name

    AuthRole() = default;
    AuthRole(std::string role) : default_role(std::move(role)) {}  // NOLINT: allows `= "role"`
    AuthRole(const char* role) : default_role(role) {}             // NOLINT

    // Role name for a realm; empty if there is none
    [[nodiscard]] const std::string& role_for(const std::string& realm) const {
        if (auto it = by_realm.find(realm); it != by_realm.end()) {
            return it->second;
        }
        return default_role;
    }
};

// ============================================================================
// ServerConfig - Complete server configuration
// ============================================================================
struct ServerConfig {
    unsigned short port{};
    // Router threads, one shard each. 0 = one per available CPU (see cpu_limits.hpp). Sessions on different
    // shards still reach each other (pub/sub and RPC are routed across shards).
    unsigned threads{1};
    TlsConfig tls{};
    size_t max_pending_invocations{};
    std::chrono::milliseconds call_timeout{30000};  // 0 disables
    EventQueueConfig events{};
    spdlog::level::level_enum log_level{};

    // Authentication: authid → Ed25519 public key (hex-encoded, 64 chars = 32 bytes)
    std::unordered_map<std::string, std::string> auth_keys;

    // Authorization: authid → role name, and role name → permitted URIs per action.
    // Only enforced when auth_keys is non-empty (then default-deny).
    std::unordered_map<std::string, AuthRole> auth_roles;
    std::unordered_map<std::string, Permissions> roles;

    // Realms each authid may join: authid → realm names. Only enforced when auth_keys is non-empty
    // (an authid with no entry can authenticate nowhere). Without auth any realm is accepted.
    std::unordered_map<std::string, std::unordered_set<std::string>> auth_realms;

    [[nodiscard]] bool may_join(const std::string& authid, const std::string& realm) const {
        auto it = auth_realms.find(authid);
        return it != auth_realms.end() && it->second.contains(realm);
    }
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

            if (server.contains("threads")) {
                const auto& value = toml::find(server, "threads");
                if (value.is_string() && value.as_string() == "auto") {
                    config.threads = 0;
                } else if (value.is_integer() && value.as_integer() >= 1 && value.as_integer() <= 1024) {
                    config.threads = static_cast<unsigned>(value.as_integer());
                } else {
                    spdlog::error("[server] threads must be an integer from 1 to 1024 or \"auto\"");
                    return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                }
            }

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
                if (rpc.contains("call_timeout_ms")) {
                    config.call_timeout = std::chrono::milliseconds{
                        toml::find<size_t>(rpc, "call_timeout_ms")};
                }
            } else {
                config.max_pending_invocations = 10000; // Default
            }

            if (server.contains("events")) {
                const auto& events = toml::find(server, "events");

                if (events.contains("queue_size")) {
                    const auto size = toml::find<size_t>(events, "queue_size");
                    if (size == 0) {
                        spdlog::error("[server.events] queue_size must be greater than 0");
                        return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                    }
                    config.events.size = size;
                }

                if (events.contains("overflow")) {
                    const auto overflow = toml::find<std::string>(events, "overflow");
                    if (overflow == "backpressure") {
                        config.events.overflow = OverflowPolicy::BACKPRESSURE;
                    } else if (overflow == "drop") {
                        config.events.overflow = OverflowPolicy::DROP;
                    } else {
                        spdlog::error("[server.events] overflow must be \"backpressure\" or \"drop\", got \"{}\"",
                                      overflow);
                        return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                    }
                }

                if (events.contains("backpressure_timeout_ms")) {
                    const auto ms = toml::find<size_t>(events, "backpressure_timeout_ms");
                    if (ms == 0) {
                        spdlog::error("[server.events] backpressure_timeout_ms must be greater than 0");
                        return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                    }
                    config.events.backpressure_timeout = std::chrono::milliseconds{ms};
                }

                if (events.contains("slow_subscriber_limit")) {
                    config.events.slow_subscriber_limit =
                        toml::find<size_t>(events, "slow_subscriber_limit");
                }
            }

            if (config_data.contains("logging")) {
                const auto& logging = toml::find(config_data, "logging");
                std::string level_str = toml::find<std::string>(logging, "level");
                config.log_level = parse_log_level(level_str);
            } else {
                config.log_level = spdlog::level::info; // Default
            }

            if (config_data.contains("roles")) {
                for (const auto& [role_name, role_value] : toml::find(config_data, "roles").as_table()) {
                    Permissions role;
                    if (role_value.contains("rules")) {
                        for (const auto& rule : toml::find(role_value, "rules").as_array()) {
                            const auto uri = toml::find<std::string>(rule, "uri");
                            if (uri.empty()) {
                                spdlog::error("[roles.{}] rule has an empty uri", role_name);
                                return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                            }

                            bool prefix = false;
                            if (rule.contains("match")) {
                                const auto match = toml::find<std::string>(rule, "match");
                                if (match != "exact" && match != "prefix") {
                                    spdlog::error("[roles.{}] match must be \"exact\" or \"prefix\", got \"{}\"",
                                                  role_name, match);
                                    return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                                }
                                prefix = match == "prefix";
                            }

                            const auto allow = toml::find<std::vector<std::string>>(rule, "allow");
                            if (allow.empty()) {
                                spdlog::error("[roles.{}] rule for '{}' allows no actions", role_name, uri);
                                return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                            }
                            for (const auto& name : allow) {
                                const auto action = parse_action(name);
                                if (!action) {
                                    spdlog::error("[roles.{}] unknown action \"{}\" (call, register, publish, subscribe)",
                                                  role_name, name);
                                    return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                                }
                                role.add_rule(*action, uri, prefix);
                            }
                        }
                    }
                    config.roles.emplace(role_name, std::move(role));
                }
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

                if (auth.contains("realms")) {
                    for (const auto& [authid, realms_value] : toml::find(auth, "realms").as_table()) {
                        if (!config.auth_keys.contains(authid)) {
                            spdlog::error("[auth.realms] authid '{}' has no entry in [auth.keys]", authid);
                            return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                        }
                        auto& realms = config.auth_realms[authid];
                        for (const auto& realm_value : realms_value.as_array()) {
                            const std::string realm = realm_value.as_string();
                            if (realm.empty()) {
                                spdlog::error("[auth.realms] authid '{}' has an empty realm name", authid);
                                return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                            }
                            realms.insert(realm);
                        }
                        if (realms.empty()) {
                            spdlog::error("[auth.realms] authid '{}' has an empty realm list", authid);
                            return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                        }
                    }
                }

                if (auth.contains("roles")) {
                    auto require_role = [&](const std::string& authid, const std::string& role_name) {
                        if (!config.roles.contains(role_name)) {
                            spdlog::error("[auth.roles] authid '{}' uses undefined role '{}'", authid, role_name);
                            return false;
                        }
                        return true;
                    };

                    for (const auto& [authid, role_value] : toml::find(auth, "roles").as_table()) {
                        if (!config.auth_keys.contains(authid)) {
                            spdlog::error("[auth.roles] authid '{}' has no entry in [auth.keys]", authid);
                            return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                        }

                        AuthRole auth_role;
                        if (role_value.is_string()) {
                            // One role in every realm the authid may join
                            auth_role.default_role = role_value.as_string();
                            if (!require_role(authid, auth_role.default_role)) {
                                return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                            }
                        } else {
                            // realm → role
                            for (const auto& [realm, realm_role] : role_value.as_table()) {
                                const std::string role_name = realm_role.as_string();
                                if (!config.may_join(authid, realm)) {
                                    spdlog::error("[auth.roles] authid '{}' has a role for realm '{}', which is "
                                                  "not in its [auth.realms] list", authid, realm);
                                    return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                                }
                                if (!require_role(authid, role_name)) {
                                    return std::unexpected{make_error_code(ConfigError::INVALID_VALUE)};
                                }
                                auth_role.by_realm[realm] = role_name;
                            }
                        }
                        config.auth_roles[authid] = std::move(auth_role);
                    }
                }

                for (const auto& [authid, key] : config.auth_keys) {
                    auto realms_it = config.auth_realms.find(authid);
                    if (realms_it == config.auth_realms.end()) {
                        spdlog::warn("authid '{}' has no entry in [auth.realms]; it cannot join any realm", authid);
                        continue;
                    }
                    for (const auto& realm : realms_it->second) {
                        auto role_it = config.auth_roles.find(authid);
                        if (role_it == config.auth_roles.end() || role_it->second.role_for(realm).empty()) {
                            spdlog::warn("authid '{}' has no role in realm '{}'; it can connect but not call, "
                                         "register, publish or subscribe", authid, realm);
                        }
                    }
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

template<>
struct std::is_error_code_enum<wamp::ConfigError> : true_type {};
