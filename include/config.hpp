#pragma once

#include <toml.hpp>
#include <filesystem>
#include <expected>
#include <system_error>
#include <string>
#include <optional>
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
    KEY_FILE_NOT_FOUND
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
        // Check file exists
        if (!std::filesystem::exists(config_path)) {
            spdlog::error("Configuration file not found: {}", config_path.string());
            return std::unexpected(make_error_code(ConfigError::FILE_NOT_FOUND));
        }

        // Parse TOML
        toml::value config_data;
        try {
            config_data = toml::parse(config_path.string());
        } catch (const std::exception& e) {
            spdlog::error("Failed to parse config file: {}", e.what());
            return std::unexpected(make_error_code(ConfigError::PARSE_ERROR));
        }

        ServerConfig config;

        // Parse server section
        try {
            const auto& server = toml::find(config_data, "server");
            config.port = toml::find<unsigned short>(server, "port");

            // Parse TLS section
            const auto& tls = toml::find(server, "tls");
            config.tls.cert_path = toml::find<std::string>(tls, "cert");
            config.tls.key_path = toml::find<std::string>(tls, "key");

            // Optional CA path
            if (tls.contains("ca")) {
                config.tls.ca_path = toml::find<std::string>(tls, "ca");
            }

            // Optional client cert requirement
            if (tls.contains("require_client_cert")) {
                config.tls.require_client_cert =
                    toml::find<bool>(tls, "require_client_cert");
            }

            // Parse RPC section (optional)
            if (server.contains("rpc")) {
                const auto& rpc = toml::find(server, "rpc");
                config.max_pending_invocations =
                    toml::find<size_t>(rpc, "max_pending_invocations");
            } else {
                config.max_pending_invocations = 10000; // Default
            }

            // Parse logging section (optional)
            if (config_data.contains("logging")) {
                const auto& logging = toml::find(config_data, "logging");
                std::string level_str = toml::find<std::string>(logging, "level");
                config.log_level = parse_log_level(level_str);
            } else {
                config.log_level = spdlog::level::info; // Default
            }

        } catch (const std::exception& e) {
            spdlog::error("Missing or invalid config field: {}", e.what());
            return std::unexpected(
                make_error_code(ConfigError::MISSING_REQUIRED_FIELD));
        }

        // Validate TLS files exist
        if (!std::filesystem::exists(config.tls.cert_path)) {
            spdlog::error("TLS certificate not found: {}",
                config.tls.cert_path.string());
            return std::unexpected(make_error_code(ConfigError::CERT_FILE_NOT_FOUND));
        }

        if (!std::filesystem::exists(config.tls.key_path)) {
            spdlog::error("TLS private key not found: {}",
                config.tls.key_path.string());
            return std::unexpected(make_error_code(ConfigError::KEY_FILE_NOT_FOUND));
        }

        if (config.tls.ca_path && !std::filesystem::exists(*config.tls.ca_path)) {
            spdlog::error("TLS CA certificate not found: {}",
                config.tls.ca_path->string());
            return std::unexpected(make_error_code(ConfigError::CERT_FILE_NOT_FOUND));
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
