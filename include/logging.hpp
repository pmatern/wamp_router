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

#include <spdlog/async.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace wamp::logging {

// ============================================================================
// Logging that cannot stall a shard
// ============================================================================
// A synchronous spdlog sink takes a process-wide mutex and does its I/O on the calling thread, so one
// slow sink (a full pipe, a network filesystem, a terminal) stalls every shard that logs. In async mode a
// shard formats the line, pushes it onto a bounded queue and goes on; one background thread writes it.
// When the queue is full the OLDEST queued line is overwritten and counted (overruns()), so logging
// never blocks routing. Each line is tagged with the shard thread that produced it ("shard 2").

struct Options {
    spdlog::level::level_enum level{spdlog::level::info};
    bool async{true};
    size_t queue_size{8192};   // lines buffered between the shards and the writer thread
    std::string file;          // log to this file instead of the console when not empty
};

namespace detail {
inline std::mutex& shard_mutex() { static std::mutex m; return m; }
inline std::unordered_map<size_t, unsigned>& shard_threads() { static std::unordered_map<size_t, unsigned> t; return t; }

// %* -> "shard N" for a registered shard thread, "main" otherwise. Looked up by the thread id captured when
// the line was logged, so it is right on the async writer thread too.
class ShardFlag : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&, spdlog::memory_buf_t& dest) override {
        std::string tag = "main";
        {
            std::lock_guard lock{shard_mutex()};
            auto it = shard_threads().find(msg.thread_id);
            if (it != shard_threads().end()) tag = "shard " + std::to_string(it->second);
        }
        dest.append(tag.data(), tag.data() + tag.size());
    }
    [[nodiscard]] std::unique_ptr<custom_flag_formatter> clone() const override { return std::make_unique<ShardFlag>(); }
};
} // namespace detail

// Call from a shard's own thread before it logs
inline void register_shard_thread(unsigned index) {
    std::lock_guard lock{detail::shard_mutex()};
    detail::shard_threads()[spdlog::details::os::thread_id()] = index;
}

inline std::unique_ptr<spdlog::formatter> make_formatter() {
    auto formatter = std::make_unique<spdlog::pattern_formatter>();
    formatter->add_flag<detail::ShardFlag>('*').set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%*] %v");
    return formatter;
}

// Replaces the default logger. Safe to call again (tests do).
inline void init(const Options& options) {
    spdlog::shutdown();   // flush and drop the previous logger / writer thread
    spdlog::sink_ptr sink;
    if (options.file.empty()) sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    else sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(options.file);

    std::shared_ptr<spdlog::logger> logger;
    if (options.async) {
        spdlog::init_thread_pool(options.queue_size > 0 ? options.queue_size : 8192, 1);
        logger = std::make_shared<spdlog::async_logger>("wamp", sink, spdlog::thread_pool(),
                                                        spdlog::async_overflow_policy::overrun_oldest);
    } else {
        logger = std::make_shared<spdlog::logger>("wamp", sink);
    }
    logger->set_formatter(make_formatter());
    logger->set_level(options.level);
    logger->flush_on(spdlog::level::warn);
    spdlog::set_default_logger(std::move(logger));
}

// Lines overwritten in the async queue because the writer could not keep up (0 when synchronous)
inline uint64_t overruns() {
    auto pool = spdlog::thread_pool();
    return pool ? pool->overrun_counter() : 0;
}

} // namespace wamp::logging
