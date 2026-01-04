#include "include/config.hpp"
#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

// Helper to create a temporary config file
class TempConfigFile {
public:
    explicit TempConfigFile(const std::string& content)
        : path_(fs::temp_directory_path() / ("test_config_" + std::to_string(counter_++) + ".toml"))
    {
        std::ofstream file(path_);
        file << content;
        file.close();
    }

    ~TempConfigFile() {
        fs::remove(path_);
    }

    const fs::path& path() const { return path_; }

private:
    fs::path path_;
    static inline int counter_ = 0;
};

// Helper to create a temporary certificate file
class TempCertFile {
public:
    explicit TempCertFile(const std::string& suffix = "cert")
        : path_(fs::temp_directory_path() / ("test_" + suffix + "_" + std::to_string(counter_++) + ".pem"))
    {
        std::ofstream file(path_);
        file << "DUMMY CERTIFICATE DATA\n";
        file.close();
    }

    ~TempCertFile() {
        fs::remove(path_);
    }

    const fs::path& path() const { return path_; }

private:
    fs::path path_;
    static inline int counter_ = 0;
};

TEST_CASE("Config::load() with valid configuration", "[config]") {
    TempCertFile cert("cert");
    TempCertFile key("key");

    std::string config_content = R"(
[server]
port = 8080

[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("

[server.rpc]
max_pending_invocations = 5000

[logging]
level = "debug"
)";

    TempConfigFile config(config_content);

    auto result = wamp::Config::load(config.path());
    REQUIRE(result.has_value());

    const auto& cfg = *result;
    CHECK(cfg.port == 8080);
    CHECK(cfg.tls.cert_path == cert.path());
    CHECK(cfg.tls.key_path == key.path());
    CHECK(cfg.tls.ca_path == std::nullopt);
    CHECK(cfg.tls.require_client_cert == false);
    CHECK(cfg.max_pending_invocations == 5000);
    CHECK(cfg.log_level == spdlog::level::debug);
}

TEST_CASE("Config::load() with minimal configuration", "[config]") {
    TempCertFile cert("cert");
    TempCertFile key("key");

    std::string config_content = R"(
[server]
port = 9000

[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
)";

    TempConfigFile config(config_content);

    auto result = wamp::Config::load(config.path());
    REQUIRE(result.has_value());

    const auto& cfg = *result;
    CHECK(cfg.port == 9000);
    CHECK(cfg.max_pending_invocations == 10000);  // Default
    CHECK(cfg.log_level == spdlog::level::info);  // Default
}

TEST_CASE("Config::load() with CA certificate", "[config]") {
    TempCertFile cert("cert");
    TempCertFile key("key");
    TempCertFile ca("ca");

    std::string config_content = R"(
[server]
port = 8080

[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
ca = ")" + ca.path().string() + R"("
require_client_cert = true
)";

    TempConfigFile config(config_content);

    auto result = wamp::Config::load(config.path());
    REQUIRE(result.has_value());

    const auto& cfg = *result;
    CHECK(cfg.tls.ca_path.has_value());
    CHECK(*cfg.tls.ca_path == ca.path());
    CHECK(cfg.tls.require_client_cert == true);
}

TEST_CASE("Config::load() with different log levels", "[config]") {
    TempCertFile cert("cert");
    TempCertFile key("key");

    SECTION("trace level") {
        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[logging]
level = "trace"
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->log_level == spdlog::level::trace);
    }

    SECTION("warn level") {
        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[logging]
level = "warn"
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->log_level == spdlog::level::warn);
    }

    SECTION("error level") {
        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[logging]
level = "error"
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->log_level == spdlog::level::err);
    }

    SECTION("critical level") {
        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[logging]
level = "critical"
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->log_level == spdlog::level::critical);
    }

    SECTION("invalid level defaults to info") {
        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[logging]
level = "invalid"
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->log_level == spdlog::level::info);
    }
}

TEST_CASE("Config::load() with non-existent file", "[config]") {
    auto result = wamp::Config::load("nonexistent_config.toml");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::FILE_NOT_FOUND));
}

TEST_CASE("Config::load() with invalid TOML syntax", "[config]") {
    std::string config_content = R"(
[server
port = invalid syntax
)";

    TempConfigFile config(config_content);

    auto result = wamp::Config::load(config.path());
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::PARSE_ERROR));
}

TEST_CASE("Config::load() with missing required fields", "[config]") {
    SECTION("missing port") {
        TempCertFile cert("cert");
        TempCertFile key("key");

        std::string config_content = R"(
[server]
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
)";

        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::MISSING_REQUIRED_FIELD));
    }

    SECTION("missing tls section") {
        std::string config_content = R"(
[server]
port = 8080
)";

        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::MISSING_REQUIRED_FIELD));
    }

    SECTION("missing cert path") {
        TempCertFile key("key");

        std::string config_content = R"(
[server]
port = 8080
[server.tls]
key = ")" + key.path().string() + R"("
)";

        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::MISSING_REQUIRED_FIELD));
    }

    SECTION("missing key path") {
        TempCertFile cert("cert");

        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
)";

        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::MISSING_REQUIRED_FIELD));
    }
}

TEST_CASE("Config::load() with non-existent certificate files", "[config]") {
    SECTION("missing cert file") {
        TempCertFile key("key");

        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = "nonexistent_cert.pem"
key = ")" + key.path().string() + R"("
)";

        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::CERT_FILE_NOT_FOUND));
    }

    SECTION("missing key file") {
        TempCertFile cert("cert");

        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = "nonexistent_key.pem"
)";

        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::KEY_FILE_NOT_FOUND));
    }

    SECTION("missing CA file") {
        TempCertFile cert("cert");
        TempCertFile key("key");

        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
ca = "nonexistent_ca.pem"
)";

        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == wamp::make_error_code(wamp::ConfigError::CERT_FILE_NOT_FOUND));
    }
}

TEST_CASE("Config::load() with various port values", "[config]") {
    TempCertFile cert("cert");
    TempCertFile key("key");

    SECTION("port 443") {
        std::string config_content = R"(
[server]
port = 443
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->port == 443);
    }

    SECTION("port 65535") {
        std::string config_content = R"(
[server]
port = 65535
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->port == 65535);
    }
}

TEST_CASE("Config::load() with custom max_pending_invocations", "[config]") {
    TempCertFile cert("cert");
    TempCertFile key("key");

    SECTION("small value") {
        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[server.rpc]
max_pending_invocations = 100
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->max_pending_invocations == 100);
    }

    SECTION("large value") {
        std::string config_content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[server.rpc]
max_pending_invocations = 100000
)";
        TempConfigFile config(config_content);
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->max_pending_invocations == 100000);
    }
}

TEST_CASE("ConfigError error category", "[config]") {
    SECTION("error category name") {
        auto ec = wamp::make_error_code(wamp::ConfigError::FILE_NOT_FOUND);
        CHECK(std::string(ec.category().name()) == "wamp_config");
    }

    SECTION("error messages") {
        CHECK(wamp::make_error_code(wamp::ConfigError::FILE_NOT_FOUND).message()
            == "Configuration file not found");
        CHECK(wamp::make_error_code(wamp::ConfigError::PARSE_ERROR).message()
            == "Failed to parse configuration file");
        CHECK(wamp::make_error_code(wamp::ConfigError::MISSING_REQUIRED_FIELD).message()
            == "Required configuration field is missing");
        CHECK(wamp::make_error_code(wamp::ConfigError::CERT_FILE_NOT_FOUND).message()
            == "TLS certificate file not found");
        CHECK(wamp::make_error_code(wamp::ConfigError::KEY_FILE_NOT_FOUND).message()
            == "TLS private key file not found");
    }
}
