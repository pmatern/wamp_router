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


// End-to-end load test: real WampClient connections over TCP RawSocket.
//
//   cmake --preset local-release && cmake --build build-local-release --target wamp_load
//   ./build-local-release/wamp_load                       # embedded router, both scenarios
//   ./build-local-release/wamp_load --mode pubsub --subscribers 50 --messages 20000 --rate 5000
//   ./build-local-release/wamp_load --port 8080 --mode rpc  # external plain-TCP router
//
// The router needs a plain TCP listener (WampServer); the production TLS server is not supported
// by WampClient. By default the router runs in-process on its own thread, so client and router
// share the machine's CPUs.

#include "include/config.hpp"
#include "include/wamp_client.hpp"
#include "include/wamp_server.hpp"
#include <boost/asio.hpp>
#include <spdlog/spdlog.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace wamp;
using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::use_awaitable;
using Clock = std::chrono::steady_clock;

namespace {

struct Options {
    std::string host = "127.0.0.1";
    uint16_t port = 0;           // 0 = embedded router
    std::string mode = "both";   // pubsub | rpc | both
    size_t subscribers = 10;
    size_t callers = 10;
    size_t messages = 10000;     // events published
    size_t calls = 1000;         // calls per caller
    size_t payload_args = 10;
    size_t connections = 1000;   // idle: connections to open
    size_t instance = 0;         // names the topic/procedure/realm so several wamp_load processes can share one router
    size_t hold_seconds = 3;     // idle: how long to keep them open (so memory can be sampled)
    size_t queue_size = 100;     // embedded router: per-session event queue size
    std::string overflow = "backpressure";  // embedded router: backpressure | drop
    size_t rate = 2000;          // events/s, 0 = unpaced (stress: the router drops events when subscriber queues fill)
    bool verbose = false;
};

void usage() {
    std::puts(
        "wamp_load [options]\n"
        "  --mode pubsub|rpc|both|idle  scenarios to run (default both; idle opens connections and holds them)\n"
        "  --connections N          idle: connections to open (default 1000)\n"
        "  --instance N             suffix topic/procedure names with N, to run several wamp_load processes against one router\n"
        "  --hold S                 idle: seconds to keep them open (default 3)\n"
        "  --subscribers N          pubsub: subscriber clients (default 10)\n"
        "  --messages N             pubsub: events published (default 10000)\n"
        "  --rate R                 pubsub: events/s, 0 = unpaced stress test (default 2000)\n"
        "  --callers N              rpc: concurrent caller clients (default 10)\n"
        "  --calls N                rpc: calls per caller (default 1000)\n"
        "  --payload-args N         positional arguments per message (default 10)\n"
        "  --queue-size N           embedded router: per-session event queue size (default 100)\n"
        "  --overflow P             embedded router: backpressure | drop (default backpressure)\n"
        "  --host H --port P        target an external plain-TCP router (default: embedded)\n"
        "  --verbose                keep router/client logging on\n");
}

bool parse(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        auto number = [&](size_t& out) {
            const char* v = next();
            if (!v) return false;
            out = std::strtoull(v, nullptr, 10);
            return true;
        };
        if (a == "--help" || a == "-h") { usage(); return false; }
        else if (a == "--verbose") o.verbose = true;
        else if (a == "--mode") { const char* v = next(); if (!v) return false; o.mode = v; }
        else if (a == "--host") { const char* v = next(); if (!v) return false; o.host = v; }
        else if (a == "--port") { size_t p = 0; if (!number(p)) return false; o.port = static_cast<uint16_t>(p); }
        else if (a == "--subscribers") { if (!number(o.subscribers)) return false; }
        else if (a == "--callers") { if (!number(o.callers)) return false; }
        else if (a == "--messages") { if (!number(o.messages)) return false; }
        else if (a == "--calls") { if (!number(o.calls)) return false; }
        else if (a == "--queue-size") { if (!number(o.queue_size)) return false; }
        else if (a == "--overflow") { const char* v = next(); if (!v) return false; o.overflow = v; }
        else if (a == "--rate") { if (!number(o.rate)) return false; }
        else if (a == "--connections") { if (!number(o.connections)) return false; }
        else if (a == "--instance") { if (!number(o.instance)) return false; }
        else if (a == "--hold") { if (!number(o.hold_seconds)) return false; }
        else if (a == "--payload-args") { if (!number(o.payload_args)) return false; }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(); return false; }
    }
    if (o.mode != "pubsub" && o.mode != "rpc" && o.mode != "both" && o.mode != "idle") {
        std::fprintf(stderr, "invalid --mode: %s\n", o.mode.c_str());
        return false;
    }
    if (o.overflow != "backpressure" && o.overflow != "drop") {
        std::fprintf(stderr, "invalid --overflow: %s\n", o.overflow.c_str());
        return false;
    }
    if (o.queue_size == 0 || o.subscribers == 0 || o.callers == 0 || o.messages == 0 || o.calls == 0) {
        std::fprintf(stderr, "counts must be greater than zero\n");
        return false;
    }
    return true;
}

// Router on its own thread/io_context so it doesn't share an event loop with the clients.
class EmbeddedRouter {
public:
    explicit EmbeddedRouter(ServerConfig config) {
        std::promise<std::pair<uint16_t, boost::asio::io_context*>> ready;
        auto future = ready.get_future();
        thread_ = std::thread([ready = std::move(ready), config = std::move(config)]() mutable {
            boost::asio::io_context io;
            WampServer server{io, 0, config};
            ready.set_value({server.port(), &io});
            server.start();
            io.run();
        });
        std::tie(port_, io_) = future.get();
    }
    ~EmbeddedRouter() {
        io_->stop();
        thread_.join();
    }
    EmbeddedRouter(const EmbeddedRouter&) = delete;
    EmbeddedRouter& operator=(const EmbeddedRouter&) = delete;

    [[nodiscard]] uint16_t port() const { return port_; }

private:
    std::thread thread_;
    uint16_t port_ = 0;
    boost::asio::io_context* io_ = nullptr;
};

int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
}

// args[0] carries the send timestamp; the rest is filler of realistic mixed types.
WampList make_payload(size_t n) {
    WampList args;
    args.emplace_back(int64_t{0});
    for (size_t i = 1; i < n; ++i) {
        switch (i % 3) {
            case 0: args.emplace_back(std::string{"argument-value-"} + std::to_string(i)); break;
            case 1: args.emplace_back(static_cast<int64_t>(i * 1000)); break;
            default: args.emplace_back(i % 2 == 0); break;
        }
    }
    return args;
}

struct Latencies {
    std::vector<int64_t> ns;

    void add(int64_t v) { ns.push_back(v); }

    void print(const char* label) {
        if (ns.empty()) {
            std::printf("%-16s no samples\n", label);
            return;
        }
        std::sort(ns.begin(), ns.end());
        auto pct = [&](double p) {
            size_t idx = static_cast<size_t>(p * static_cast<double>(ns.size() - 1));
            return static_cast<double>(ns[idx]) / 1e6;
        };
        std::printf("%-16s p50 %.3f ms   p90 %.3f ms   p99 %.3f ms   max %.3f ms\n",
                    label, pct(0.50), pct(0.90), pct(0.99), static_cast<double>(ns.back()) / 1e6);
    }
};

// Clients must outlive their coroutines and any late router traffic, so they are owned by main()
// (declared after the io_context, destroyed before it) rather than by the scenario coroutines.
using ClientPool = std::vector<std::shared_ptr<WampClient>>;

awaitable<void> disconnect_quietly(WampClient& client) {
    try {
        co_await client.disconnect();
    } catch (const std::exception&) {
    }
}

struct PubSubState {
    Latencies latency;
    size_t delivered = 0;
    Clock::time_point last_event = Clock::now();
};

awaitable<void> sleep_for(boost::asio::io_context& io, std::chrono::microseconds d) {
    boost::asio::steady_timer timer{io};
    timer.expires_after(d);
    co_await timer.async_wait(use_awaitable);
}

double seconds(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}

// ----------------------------------------------------------------------------
// PubSub: 1 publisher -> N subscribers
// ----------------------------------------------------------------------------
awaitable<void> run_pubsub(boost::asio::io_context& io, ClientPool& pool, const Options& o, std::string host, uint16_t port,
                           bool embedded) {
    const std::string kTopic = "load.pubsub." + std::to_string(o.instance);

    // Event callbacks can fire after this coroutine returns, so they share ownership of the stats
    auto state = std::make_shared<PubSubState>();

    auto publisher_ptr = std::make_shared<WampClient>(io);
    pool.push_back(publisher_ptr);
    WampClient& publisher = *publisher_ptr;
    std::vector<std::shared_ptr<WampClient>> subs;
    for (size_t i = 0; i < o.subscribers; ++i) {
        subs.push_back(std::make_shared<WampClient>(io));
        pool.push_back(subs.back());
    }

    co_await publisher.connect(host, port, "load.realm");
    for (auto& sub : subs) {
        co_await sub->connect(host, port, "load.realm");
        co_await sub->subscribe(kTopic, [state](const EventMessage& ev) {
            const int64_t t = ev.arguments.empty() ? 0 : std::get<int64_t>(ev.arguments[0]);
            state->latency.add(now_ns() - t);
            ++state->delivered;
            state->last_event = Clock::now();
        });
    }
    co_await sleep_for(io, std::chrono::milliseconds(100));

    auto args = make_payload(o.payload_args);
    const auto start = Clock::now();
    for (size_t i = 0; i < o.messages; ++i) {
        if (o.rate > 0) {
            const auto due = start + std::chrono::nanoseconds(static_cast<int64_t>(
                static_cast<double>(i) * 1e9 / static_cast<double>(o.rate)));
            if (const auto now = Clock::now(); due > now) {
                co_await sleep_for(io, std::chrono::duration_cast<std::chrono::microseconds>(due - now));
            }
        }
        args[0] = now_ns();
        (void)co_await publisher.publish(kTopic, args);
    }
    const auto publish_end = Clock::now();

    // Wait for deliveries to finish: all arrived, or nothing new for 1 s
    const size_t expected = o.messages * o.subscribers;
    state->last_event = Clock::now();
    while (state->delivered < expected && Clock::now() - state->last_event < std::chrono::seconds(1)) {
        co_await sleep_for(io, std::chrono::milliseconds(10));
    }
    const size_t delivered = state->delivered;
    const auto end = delivered > 0 ? state->last_event : Clock::now();

    std::printf("\n== PubSub: 1 publisher -> %zu subscribers, %zu events, %zu args%s ==\n",
                o.subscribers, o.messages, o.payload_args,
                o.rate ? (", paced " + std::to_string(o.rate) + "/s").c_str() : ", unpaced");
    std::printf("%-16s %zu in %.2f s (%.0f msg/s)\n", "published", o.messages,
                seconds(start, publish_end), static_cast<double>(o.messages) / seconds(start, publish_end));
    std::printf("%-16s %zu / %zu (%zu lost, %.2f%%)\n", "delivered", delivered, expected,
                expected - delivered, 100.0 * static_cast<double>(expected - delivered) / static_cast<double>(expected));
    std::printf("%-16s %.0f events/s\n", "delivery rate",
                static_cast<double>(delivered) / std::max(seconds(start, end), 1e-9));
    state->latency.print("latency");
    if (embedded) {
        std::printf("%-16s %llu\n", "router drops",
                    static_cast<unsigned long long>(EventChannelRegistry::dropped_count()));
    }

    co_await disconnect_quietly(publisher);
    for (auto& sub : subs) {
        co_await disconnect_quietly(*sub);
    }
}

// ----------------------------------------------------------------------------
// RPC: N concurrent callers -> 1 callee (echo)
// ----------------------------------------------------------------------------
awaitable<void> run_rpc(boost::asio::io_context& io, ClientPool& pool, const Options& o, std::string host, uint16_t port) {
    const std::string kProcedure = "load.echo." + std::to_string(o.instance);

    auto callee_ptr = std::make_shared<WampClient>(io);
    pool.push_back(callee_ptr);
    WampClient& callee = *callee_ptr;
    std::vector<std::shared_ptr<WampClient>> callers;
    for (size_t i = 0; i < o.callers; ++i) {
        callers.push_back(std::make_shared<WampClient>(io));
        pool.push_back(callers.back());
    }

    co_await callee.connect(host, port, "load.realm");
    co_await callee.register_procedure(kProcedure,
        [](const InvocationMessage& inv) -> awaitable<YieldMessage> {
            co_return YieldMessage{inv.request_id, {}, inv.arguments, inv.arguments_kw};
        });
    for (auto& caller : callers) {
        co_await caller->connect(host, port, "load.realm");
    }

    Latencies latency;
    size_t ok = 0;
    size_t failed = 0;
    size_t running = callers.size();
    const auto args_template = make_payload(o.payload_args);

    const auto start = Clock::now();
    for (auto& caller : callers) {
        co_spawn(io, [&, c = caller.get()]() -> awaitable<void> {
            auto args = args_template;
            for (size_t i = 0; i < o.calls; ++i) {
                args[0] = now_ns();
                try {
                    (void)co_await c->call_result(kProcedure, args);
                    latency.add(now_ns() - std::get<int64_t>(args[0]));
                    ++ok;
                } catch (const std::exception&) {
                    ++failed;
                }
            }
            --running;
        }, detached);
    }
    while (running > 0) {
        co_await sleep_for(io, std::chrono::milliseconds(5));
    }
    const auto end = Clock::now();

    std::printf("\n== RPC: %zu callers x %zu calls -> 1 callee, %zu args ==\n",
                o.callers, o.calls, o.payload_args);
    std::printf("%-16s %zu ok, %zu failed in %.2f s\n", "calls", ok, failed, seconds(start, end));
    std::printf("%-16s %.0f calls/s\n", "throughput", static_cast<double>(ok) / std::max(seconds(start, end), 1e-9));
    latency.print("round trip");

    co_await disconnect_quietly(callee);
    for (auto& caller : callers) {
        co_await disconnect_quietly(*caller);
    }
}

// ----------------------------------------------------------------------------
// Idle: open N sessions (RawSocket + HELLO/WELCOME), hold them, report the connect rate
// ----------------------------------------------------------------------------
awaitable<void> run_idle(boost::asio::io_context& io, ClientPool& pool, const Options& o, std::string host, uint16_t port) {
    constexpr size_t kConcurrent = 64;  // connects in flight, so the router sees a burst rather than a trickle
    std::printf("\n== Idle: %zu connections, %zu in flight ==\n", o.connections, kConcurrent);

    size_t next = 0;
    size_t done = 0;
    size_t failed = 0;
    size_t active = 0;
    const auto start = Clock::now();
    auto worker = [&]() -> awaitable<void> {
        while (next < o.connections) {
            ++next;
            auto client = std::make_shared<WampClient>(io);
            pool.push_back(client);
            try {
                co_await client->connect(host, port, "load.realm");
                ++done;
            } catch (const std::exception&) {
                ++failed;
            }
        }
        --active;
    };
    for (size_t i = 0; i < kConcurrent; ++i) {
        ++active;
        co_spawn(io, worker(), detached);
    }
    while (active > 0) {
        co_await sleep_for(io, std::chrono::milliseconds(5));
    }
    const double elapsed = seconds(start, Clock::now());
    std::printf("connected        %zu ok, %zu failed in %.2f s (%.0f connections/s)\n", done, failed, elapsed,
                static_cast<double>(done) / elapsed);
    std::printf("holding %zu s (sample the router's memory now)...\n", o.hold_seconds);
    co_await sleep_for(io, std::chrono::seconds(o.hold_seconds));
}

}  // namespace

int main(int argc, char** argv) {
    Options opts;
    if (!parse(argc, argv, opts)) {
        return 1;
    }
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    spdlog::set_level(opts.verbose ? spdlog::level::info : spdlog::level::off);

    std::unique_ptr<EmbeddedRouter> router;
    uint16_t port = opts.port;
    if (port == 0) {
        ServerConfig config;
        config.events.size = opts.queue_size;
        config.events.overflow = opts.overflow == "drop" ? OverflowPolicy::DROP : OverflowPolicy::BACKPRESSURE;
        EventChannelRegistry::reset_dropped_count();
        router = std::make_unique<EmbeddedRouter>(std::move(config));
        port = router->port();
        std::printf("embedded router on 127.0.0.1:%u (shares CPUs with the load clients), "
                    "event queue %zu, overflow=%s\n", port, opts.queue_size, opts.overflow.c_str());
    } else {
        std::printf("target router %s:%u\n", opts.host.c_str(), port);
    }

    boost::asio::io_context io;
    ClientPool pool;
    bool failed = false;
    co_spawn(io, [&]() -> awaitable<void> {
        try {
            if (opts.mode == "pubsub" || opts.mode == "both") {
                co_await run_pubsub(io, pool, opts, opts.host, port, router != nullptr);
            }
            if (opts.mode == "rpc" || opts.mode == "both") {
                co_await run_rpc(io, pool, opts, opts.host, port);
            }
            if (opts.mode == "idle") {
                co_await run_idle(io, pool, opts, opts.host, port);
            }
        } catch (const std::exception& e) {
            std::fprintf(stderr, "load test failed: %s\n", e.what());
            failed = true;
        }
        io.stop();
    }, detached);
    io.run();

    return failed ? 1 : 0;
}
