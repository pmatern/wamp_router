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

#include "connection_limiter.hpp"
#include "cpu_limits.hpp"
#include "cross_shard.hpp"
#include "logging.hpp"
#include "shard.hpp"
#include "shard_group.hpp"
#include "wamp_server.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <atomic>
#include <concepts>
#include <csignal>
#include <memory>
#include <chrono>
#include <thread>
#include <vector>

namespace wamp {

// ============================================================================
// Router - N shards, one thread each
// ============================================================================
// One acceptor thread takes new connections and hands each to the shard with the fewest sessions. From
// then on the connection (TLS handshake included) lives entirely on that shard's thread, with that
// shard's own io_context, event channels, realms and pending calls: no locks, no shared mutable state.
//
// Sessions on different shards reach each other through ShardGroup: pub/sub via replicated topic interest
// and one inbox per shard (one message per interested shard); RPC via a replicated procedure table, with
// the callee's shard owning the pending call. threads = 1 behaves exactly like one WampServer.
class Router {
public:
    enum class Transport { PLAIN, TLS };

    // threads == 0 means one per available CPU. config must outlive nothing: it is copied.
    Router(ServerConfig config, Transport transport, unsigned threads)
        : config_(std::move(config))
        , transport_(transport)
        , tls_context_(ssl::context::tlsv13)
        , acceptor_(accept_io_, tcp::endpoint(tcp::v4(), config_.port))
        , bound_port_(acceptor_.local_endpoint().port())
        , limiter_(config_.max_connections.value_or(auto_max_connections()), config_.max_connections_per_ip)
    {
        spdlog::info("Connection limit: {} total, {} per address",
                     limiter_.max_total() == 0 ? std::string{"unlimited"} : std::to_string(limiter_.max_total()),
                     limiter_.max_per_address() == 0 ? std::string{"unlimited"} : std::to_string(limiter_.max_per_address()));
        if (transport_ == Transport::TLS) {
            configure_tls_context(tls_context_, config_.tls);
        }
        if (threads == 0) threads = detect_cpu_limits().available;
        const auto shard_config = ShardConfig::from(config_);
        for (unsigned i = 0; i < threads; ++i) {
            workers_.push_back(std::make_unique<Worker>(shard_config));
        }
        group_ = std::make_unique<ShardGroup>(threads, [](Shard& shard, std::vector<CrossMessage> batch) {
            return dispatch_cross_messages(shard, std::move(batch));
        });
        for (unsigned i = 0; i < threads; ++i) {
            group_->attach(i, *workers_[i]->shard, workers_[i]->io);
        }
    }

    ~Router() {
        stop();
    }

    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    // Starts the shard threads and the acceptor thread; returns immediately
    void start() {
        if (started_.exchange(true)) return;
        for (auto& worker : workers_) {
            asio::co_spawn(worker->io, call_timeout_sweeper(worker->shard), asio::detached);
            worker->thread = std::thread([w = worker.get(), index = static_cast<unsigned>(&worker - workers_.data())] {
                logging::register_shard_thread(index);
                w->io.run();
            });
        }
        asio::co_spawn(accept_io_, accept_loop(), asio::detached);
        acceptor_thread_ = std::thread([this] { accept_io_.run(); });
        spdlog::info("Router started with {} shard thread(s) on port {}", workers_.size(), bound_port_);
    }

    static constexpr std::chrono::milliseconds kShutdownGrace{2000};

    // Stops accepting, drains the cross-shard inboxes (up to kShutdownGrace) and closes the sessions; safe to call from any thread, more than once
    void stop() {
        if (!started_.load() || stopped_.exchange(true)) return;
        asio::post(accept_io_, [this] {
            std::error_code ignored;
            acceptor_.close(ignored);
            accept_io_.stop();
        });
        if (acceptor_thread_.joinable() && acceptor_thread_.get_id() != std::this_thread::get_id()) {
            acceptor_thread_.join();
        }
        // No new connections now. Let cross-shard events, calls and results already queued reach their
        // sessions before the shard threads stop (bounded: a stuck inbox must not block shutdown).
        const auto give_up = std::chrono::steady_clock::now() + kShutdownGrace;
        while (group_->pending() > 0 && std::chrono::steady_clock::now() < give_up) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        if (const auto left = group_->pending(); left > 0) {
            spdlog::warn("Shutdown: {} cross-shard message(s) were not delivered", left);
        }
        for (auto& worker : workers_) {
            worker->io.stop();
        }
        for (auto& worker : workers_) {
            if (worker->thread.joinable()) worker->thread.join();
        }
    }

    // Blocks until stop() has been called (by a signal handler or another thread)
    void wait() {
        if (acceptor_thread_.joinable()) acceptor_thread_.join();
        stop();
    }

    // Stop on SIGINT / SIGTERM
    void stop_on_signals() {
        signals_.emplace(accept_io_, SIGINT, SIGTERM);
        signals_->async_wait([this](const std::error_code& ec, int) {
            if (!ec) {
                spdlog::info("Shutting down");
                acceptor_.close();
                accept_io_.stop();
            }
        });
    }

    // Runs `fn` on shard `index`'s thread (tests use it to stall a shard)
    template<std::invocable F>
    void post_to_shard(size_t index, F&& fn) {
        asio::post(workers_.at(index)->io, std::forward<F>(fn));
    }

    [[nodiscard]] unsigned short port() const { return bound_port_; }
    [[nodiscard]] size_t shard_count() const { return workers_.size(); }

    // Sessions assigned to each shard that have not ended yet (approximate while connections come and go)
    [[nodiscard]] std::vector<size_t> sessions_per_shard() const {
        std::vector<size_t> counts;
        for (const auto& worker : workers_) counts.push_back(worker->sessions.load(std::memory_order_relaxed));
        return counts;
    }

    // Connections handed to each shard since startup
    [[nodiscard]] std::vector<uint64_t> accepted_per_shard() const {
        std::vector<uint64_t> counts;
        for (const auto& worker : workers_) counts.push_back(worker->accepted.load(std::memory_order_relaxed));
        return counts;
    }

    // One shard's counters at a point in time (each read is atomic; the set is not a consistent snapshot)
    struct ShardStats {
        size_t sessions{};            // open sessions
        uint64_t accepted{};          // connections handed to this shard since startup
        uint64_t publishes{};         // PUBLISH messages handled
        uint64_t calls{};             // CALL messages handled
        uint64_t handshake_timeouts{};   // connections closed for not becoming a session in time
        uint64_t event_drops{};       // events dropped on full session queues
        size_t inbox_depth{};         // cross-shard messages waiting or being delivered
        uint64_t inbox_received{};    // cross-shard messages taken from the inbox
        uint64_t inbox_dropped{};     // cross-shard events dropped because the inbox was full
    };

    [[nodiscard]] std::vector<ShardStats> stats() const {
        std::vector<ShardStats> all;
        for (size_t i = 0; i < workers_.size(); ++i) {
            const auto& w = *workers_[i];
            all.push_back({w.sessions.load(std::memory_order_relaxed), w.accepted.load(std::memory_order_relaxed),
                           w.shard->counters.publishes.load(std::memory_order_relaxed),
                           w.shard->counters.calls.load(std::memory_order_relaxed),
                           w.shard->counters.handshake_timeouts.load(std::memory_order_relaxed),
                           w.shard->channels.dropped_count(), group_->depth(static_cast<unsigned>(i)),
                           group_->received(static_cast<unsigned>(i)), group_->dropped(static_cast<unsigned>(i))});
        }
        return all;
    }

    // Connections closed at accept because a limit was reached
    struct RejectedConnections {
        uint64_t total_limit{};     // [server] max_connections
        uint64_t address_limit{};   // [server] max_connections_per_ip
    };
    [[nodiscard]] RejectedConnections rejected_connections() const {
        return {rejected_total_.load(std::memory_order_relaxed), rejected_per_address_.load(std::memory_order_relaxed)};
    }

    // Connections open now (admitted and not yet ended)
    [[nodiscard]] size_t open_connections() const { return limiter_.open(); }

    // Events dropped on all shards (the counters are atomic, so this is safe to call from any thread)
    [[nodiscard]] uint64_t dropped_events() const {
        uint64_t total = 0;
        for (const auto& worker : workers_) total += worker->shard->channels.dropped_count();
        return total + group_->dropped();
    }

    // Cross-shard events dropped because the destination shard's inbox was full (part of dropped_events())
    [[nodiscard]] uint64_t inbox_dropped_events() const {
        return group_->dropped();
    }

private:
    struct Worker {
        explicit Worker(const ShardConfig& shard_config)
            : io(1)  // concurrency hint 1: only this thread ever runs the io_context, so asio can skip its locking
            , shard(std::make_shared<Shard>(shard_config))
        {}

        asio::io_context io;
        std::shared_ptr<Shard> shard;
        std::thread thread;
        std::atomic<size_t> sessions{0};
        std::atomic<uint64_t> accepted{0};
    };

    Worker& least_loaded() {
        Worker* best = workers_.front().get();
        for (auto& worker : workers_) {
            if (worker->sessions.load(std::memory_order_relaxed) < best->sessions.load(std::memory_order_relaxed)) {
                best = worker.get();
            }
        }
        return *best;
    }

    template<WampSocket Socket>
    asio::awaitable<void> run_session(Worker& worker, const ServerConfig& config, Socket socket,
                                      asio::ip::address peer) {
        (void)co_await handle_wamp_session<Socket>(std::move(socket), worker.io, config, worker.shard);
        worker.sessions.fetch_sub(1, std::memory_order_relaxed);
        limiter_.release(peer);
    }

    asio::awaitable<void> accept_loop() {
        spdlog::info("WAMP router listening on port {} ({})", bound_port_,
                     transport_ == Transport::TLS ? "TLS 1.3" : "plain TCP");
        while (true) {
            auto [ec, socket] = co_await acceptor_.async_accept(asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (ec == asio::error::operation_aborted) co_return;
                if (++accept_errors_ == 1 || accept_errors_ % 1000 == 0) {
                    spdlog::error("Accept error: {} ({} so far)", ec.message(), accept_errors_);
                }
                // Out of descriptors (EMFILE/ENFILE) or similar: retrying at once would spin; wait a moment
                asio::steady_timer backoff{accept_io_, std::chrono::milliseconds{100}};
                co_await backoff.async_wait(asio::as_tuple(asio::use_awaitable));
                continue;
            }

            std::error_code peer_ec;
            const auto peer = socket.remote_endpoint(peer_ec).address();
            if (const auto verdict = limiter_.admit(peer); verdict != ConnectionLimiter::Result::ADMITTED) {
                auto& counter = verdict == ConnectionLimiter::Result::TOTAL_LIMIT ? rejected_total_ : rejected_per_address_;
                const auto n = counter.fetch_add(1, std::memory_order_relaxed) + 1;
                if (n == 1 || n % 1000 == 0) {
                    spdlog::warn("Rejected connection from {}: {} limit reached ({} rejected so far)", peer.to_string(),
                                 verdict == ConnectionLimiter::Result::TOTAL_LIMIT ? "total connection" : "per-address",
                                 n);
                }
                std::error_code ignored;
                socket.close(ignored);
                continue;
            }

            Worker& worker = least_loaded();
            worker.sessions.fetch_add(1, std::memory_order_relaxed);
            worker.accepted.fetch_add(1, std::memory_order_relaxed);

            // Move the connection to the shard's thread by handing over the descriptor
            const auto native = socket.release();
            asio::post(worker.io, [this, &worker, native, peer] {
                tcp::socket adopted{worker.io};
                std::error_code assign_ec;
                adopted.assign(tcp::v4(), native, assign_ec);
                if (assign_ec) {
                    spdlog::error("Could not adopt connection on shard: {}", assign_ec.message());
                    worker.sessions.fetch_sub(1, std::memory_order_relaxed);
                    limiter_.release(peer);
                    return;
                }
                if (transport_ == Transport::TLS) {
                    ssl::stream<tcp::socket> tls{std::move(adopted), tls_context_};
                    set_socket_options(tls);
                    asio::co_spawn(worker.io, run_session<ssl::stream<tcp::socket>>(worker, config_, std::move(tls), peer),
                                   asio::detached);
                } else {
                    set_socket_options(adopted);
                    asio::co_spawn(worker.io, run_session<tcp::socket>(worker, config_, std::move(adopted), peer),
                                   asio::detached);
                }
            });
        }
    }

    ServerConfig config_;
    Transport transport_;
    asio::io_context accept_io_;
    ssl::context tls_context_;
    tcp::acceptor acceptor_;
    unsigned short bound_port_;
    ConnectionLimiter limiter_;
    std::atomic<uint64_t> rejected_total_{0};
    std::atomic<uint64_t> rejected_per_address_{0};
    uint64_t accept_errors_{0};   // touched only by the acceptor thread
    std::unique_ptr<ShardGroup> group_;  // declared before the workers: their sessions may still use it while they shut down
    std::vector<std::unique_ptr<Worker>> workers_;
    std::thread acceptor_thread_;
    std::optional<asio::signal_set> signals_;
    std::atomic<bool> started_{false};
    std::atomic<bool> stopped_{false};
};

} // namespace wamp
