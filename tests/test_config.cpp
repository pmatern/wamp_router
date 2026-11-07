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

TEST_CASE("Config::load() event queue settings", "[config][events]") {
    TempCertFile cert("cert");
    TempCertFile key("key");

    auto load = [&](const std::string& events_section) {
        std::string content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
)" + events_section;
        TempConfigFile config(content);
        return wamp::Config::load(config.path());
    };

    SECTION("defaults when [server.events] is absent") {
        auto result = load("");
        REQUIRE(result.has_value());
        CHECK(result->events.size == 100);
        CHECK(result->events.overflow == wamp::OverflowPolicy::BACKPRESSURE);
        CHECK(result->events.backpressure_timeout == std::chrono::milliseconds{1000});
        CHECK(result->events.slow_subscriber_limit == 3);
    }

    SECTION("all settings") {
        auto result = load(R"(
[server.events]
queue_size = 5000
overflow = "drop"
backpressure_timeout_ms = 250
slow_subscriber_limit = 5
)");
        REQUIRE(result.has_value());
        CHECK(result->events.size == 5000);
        CHECK(result->events.overflow == wamp::OverflowPolicy::DROP);
        CHECK(result->events.backpressure_timeout == std::chrono::milliseconds{250});
        CHECK(result->events.slow_subscriber_limit == 5);
    }

    SECTION("partial settings keep defaults") {
        auto result = load(R"(
[server.events]
queue_size = 7
)");
        REQUIRE(result.has_value());
        CHECK(result->events.size == 7);
        CHECK(result->events.overflow == wamp::OverflowPolicy::BACKPRESSURE);
    }

    SECTION("zero queue_size is rejected") {
        auto result = load("[server.events]\nqueue_size = 0\n");
        REQUIRE(!result.has_value());
        CHECK(result.error() == wamp::ConfigError::INVALID_VALUE);
    }

    SECTION("unknown overflow policy is rejected") {
        auto result = load("[server.events]\noverflow = \"block\"\n");
        REQUIRE(!result.has_value());
        CHECK(result.error() == wamp::ConfigError::INVALID_VALUE);
    }

    SECTION("zero backpressure timeout is rejected") {
        auto result = load("[server.events]\nbackpressure_timeout_ms = 0\n");
        REQUIRE(!result.has_value());
        CHECK(result.error() == wamp::ConfigError::INVALID_VALUE);
    }
}

TEST_CASE("Config::load() call_timeout_ms", "[config]") {
    TempCertFile cert("cert");
    TempCertFile key("key");
    auto make = [&](const std::string& rpc_extra) {
        return std::string(R"(
[server]
port = 8080
[server.tls]
cert = ")") + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[server.rpc]
max_pending_invocations = 100
)" + rpc_extra;
    };

    SECTION("default is 30s") {
        TempConfigFile config(make(""));
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->call_timeout == std::chrono::milliseconds{30000});
    }
    SECTION("explicit value, 0 disables") {
        TempConfigFile config(make("call_timeout_ms = 0\n"));
        auto result = wamp::Config::load(config.path());
        REQUIRE(result.has_value());
        CHECK(result->call_timeout == std::chrono::milliseconds{0});
    }
}

TEST_CASE("Config::load() roles and authorization", "[config][authz]") {
    TempCertFile cert("cert");
    TempCertFile key("key");
    const std::string pub(64, 'a');

    auto load = [&](const std::string& extra) {
        std::string content = R"(
[server]
port = 8080
[server.tls]
cert = ")" + cert.path().string() + R"("
key = ")" + key.path().string() + R"("
[auth.keys]
alice = ")" + pub + R"("
bob = ")" + pub + R"("
)" + extra;
        TempConfigFile config(content);
        return wamp::Config::load(config.path());
    };

    SECTION("parses roles, rules and the authid mapping") {
        auto result = load(R"(
[auth.roles]
alice = "publisher"

[[roles.publisher.rules]]
uri = "com.example."
match = "prefix"
allow = ["publish", "subscribe"]

[[roles.publisher.rules]]
uri = "com.example.add"
allow = ["call"]
)");
        REQUIRE(result.has_value());
        CHECK(result->auth_roles.at("alice") == "publisher");
        CHECK_FALSE(result->auth_roles.contains("bob"));

        const auto& role = result->roles.at("publisher");
        CHECK(role.allows(wamp::Action::PUBLISH, "com.example.x"));
        CHECK(role.allows(wamp::Action::SUBSCRIBE, "com.example.y"));
        CHECK(role.allows(wamp::Action::CALL, "com.example.add"));
        CHECK_FALSE(role.allows(wamp::Action::CALL, "com.example.add2"));   // exact by default
        CHECK_FALSE(role.allows(wamp::Action::REGISTER, "com.example.add"));
    }

    SECTION("no roles configured") {
        auto result = load("");
        REQUIRE(result.has_value());
        CHECK(result->roles.empty());
        CHECK(result->auth_roles.empty());
    }

    SECTION("invalid configurations are rejected") {
        CHECK_FALSE(load("[[roles.r.rules]]\nuri = \"a\"\nallow = [\"fly\"]\n").has_value());
        CHECK_FALSE(load("[[roles.r.rules]]\nuri = \"a\"\nmatch = \"glob\"\nallow = [\"call\"]\n").has_value());
        CHECK_FALSE(load("[[roles.r.rules]]\nuri = \"\"\nallow = [\"call\"]\n").has_value());
        CHECK_FALSE(load("[[roles.r.rules]]\nuri = \"a\"\nallow = []\n").has_value());
        CHECK_FALSE(load("[auth.roles]\nalice = \"missing\"\n").has_value());
        CHECK_FALSE(load("[auth.roles]\nnobody = \"r\"\n[[roles.r.rules]]\nuri = \"a\"\nallow = [\"call\"]\n").has_value());
    }
}
