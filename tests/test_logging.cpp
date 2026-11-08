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

#include "include/logging.hpp"
#include <catch2/catch_test_macros.hpp>
#include <spdlog/sinks/base_sink.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

using namespace std::chrono_literals;

namespace {

// A sink that takes 20 ms per line, like a stalled pipe
class SlowSink : public spdlog::sinks::base_sink<std::mutex> {
public:
    std::atomic<int> written{0};
protected:
    void sink_it_(const spdlog::details::log_msg&) override { std::this_thread::sleep_for(20ms); ++written; }
    void flush_() override {}
};

std::string read_file(const std::filesystem::path& p) {
    std::ifstream in{p};
    std::stringstream s;
    s << in.rdbuf();
    return s.str();
}

// Restore the default logger other tests expect
struct RestoreLogger {
    ~RestoreLogger() { wamp::logging::init({spdlog::level::off, false, 8192, ""}); }
};

} // namespace

TEST_CASE("A slow log sink does not stall the logging thread", "[logging]") {
    RestoreLogger restore;
    wamp::logging::init({spdlog::level::info, true, 128, ""});
    auto sink = std::make_shared<SlowSink>();
    auto logger = std::make_shared<spdlog::async_logger>("slow", sink, spdlog::thread_pool(),
                                                         spdlog::async_overflow_policy::overrun_oldest);
    constexpr int kLines = 5000;   // 100 s of sink time if the caller had to wait for it

    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < kLines; ++i) logger->info("line {}", i);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(elapsed < 2s);
    CHECK(wamp::logging::overruns() > 0);   // the queue (128) overflowed and the oldest lines were dropped, not awaited
    logger.reset();
}

TEST_CASE("Log lines carry the shard of the thread that wrote them", "[logging]") {
    RestoreLogger restore;
    const auto path = std::filesystem::temp_directory_path() / "wamp_logging_test.log";
    std::filesystem::remove(path);
    wamp::logging::init({spdlog::level::info, true, 1024, path.string()});

    spdlog::info("from main");
    std::thread{[] {
        wamp::logging::register_shard_thread(3);
        spdlog::info("from shard");
    }}.join();
    spdlog::shutdown();   // flushes the writer

    const auto text = read_file(path);
    CHECK(text.find("[main] from main") != std::string::npos);
    CHECK(text.find("[shard 3] from shard") != std::string::npos);
    std::filesystem::remove(path);
}
