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

#include "wamp_session.hpp"
#include "event_channel.hpp"
#include "config.hpp"
#include "procedure_handler.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <spdlog/spdlog.h>
#include <expected>
#include <system_error>
#include <span>
#include <memory>
#include <optional>
#include <openssl/ssl.h>

namespace wamp {

using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

// ============================================================================
// Socket Helper Functions - Work with both plain TCP and TLS sockets
// ============================================================================

template<typename SocketType>
inline auto get_remote_endpoint(SocketType& socket) {
    if constexpr (requires { socket.lowest_layer(); }) {
        // SSL socket - use lowest_layer()
        return socket.lowest_layer().remote_endpoint();
    } else {
        // Plain socket
        return socket.remote_endpoint();
    }
}

// Set socket options (works for both plain and SSL sockets)
template<typename SocketType>
inline void set_socket_options(SocketType& socket) {
    if constexpr (requires { socket.lowest_layer(); }) {
        // SSL socket
        socket.lowest_layer().set_option(tcp::no_delay(true));
    } else {
        // Plain socket
        socket.set_option(tcp::no_delay(true));
    }
}

// ============================================================================
// Session I/O: a reader coroutine and a writer coroutine per established session
// ============================================================================
// The reader owns the socket's read side: it parses client messages and writes their direct responses.
// The writer waits on the session's event channel and sends everything queued in one gathered write.
// Both write to the same socket, so writes take a WriteLock (they would otherwise interleave frames).

// Mutual exclusion for coroutines on one io_context thread. Uncontended lock/unlock never suspend.
class WriteLock {
public:
    explicit WriteLock(boost::asio::io_context& io) : token_(io, 1) {
        token_.try_send(boost::system::error_code{});
    }

    // False if the wait was cancelled (the session is closing)
    boost::asio::awaitable<bool> lock() {
        if (token_.try_receive([](boost::system::error_code) {})) {
            co_return true;
        }
        auto [ec] = co_await token_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        co_return !ec;
    }

    void unlock() {
        token_.try_send(boost::system::error_code{});
    }

    class Guard {
    public:
        explicit Guard(WriteLock& lock) : lock_(lock) {}
        ~Guard() { lock_.unlock(); }
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
    private:
        WriteLock& lock_;
    };

private:
    boost::asio::experimental::channel<void(boost::system::error_code)> token_;
};

// Upper bounds for one gathered write, so a flood for one subscriber cannot hold the socket (and the
// write lock) for long
inline constexpr size_t kMaxBatchFrames = 64;
inline constexpr size_t kMaxBatchBytes = 256 * 1024;

// Handles one socket read result. `write_lock` is null before the session's writer exists.
template<typename SocketType>
inline boost::asio::awaitable<std::expected<bool, std::error_code>>
handle_socket_read_completion(
    SocketType& socket,
    const std::array<uint8_t, 8192>& buffer,
    WampSession& protocol,
    const std::string& remote_address,
    boost::system::error_code ec_read,
    std::size_t bytes_read,
    WriteLock* write_lock = nullptr
) {
    // Check for EOF (client disconnected gracefully)
    if (ec_read == boost::asio::error::eof) {
        spdlog::info("Client {} disconnected", remote_address);
        protocol.on_disconnect();
        co_return std::unexpected{ec_read};
    }

    if (ec_read == boost::asio::error::operation_aborted) {
        spdlog::debug("Read from {} canceled", remote_address);
        protocol.on_disconnect();
        co_return std::unexpected{ec_read};
    }

    if (ec_read) {
        spdlog::error("Read error from {}: {}", remote_address, ec_read.message());
        protocol.on_disconnect();
        co_return std::unexpected{ec_read};
    }

    spdlog::debug("Received {} bytes from {}", bytes_read, remote_address);

    auto result = protocol.process(std::span<const uint8_t>(buffer.data(), bytes_read));

    if (!result) {
        spdlog::error("Protocol error from {}: {}", remote_address, result.error().message());
        protocol.on_disconnect();
        co_return std::unexpected{result.error()};
    }

    // Backpressure: if delivering this input's events/invocations hit a full subscriber queue,
    // stop reading from this client until the subscribers catch up (bounded by the timeout)
    if (auto blocked = EventChannelRegistry::take_blocked(); !blocked.empty()) {
        co_await EventChannelRegistry::deliver_blocked(std::move(blocked));
    }

    if (!result->empty()) {
        if (write_lock && !co_await write_lock->lock()) {
            protocol.on_disconnect();
            co_return std::unexpected{make_error_code(std::errc::operation_canceled)};
        }
        std::optional<WriteLock::Guard> guard;
        if (write_lock) guard.emplace(*write_lock);

        auto [ec_write, bytes_written] = co_await boost::asio::async_write(
            socket,
            boost::asio::buffer(*result),
            boost::asio::as_tuple(boost::asio::use_awaitable)
        );

        if (ec_write) {
            spdlog::error("Write error to {}: {}", remote_address, ec_write.message());
            protocol.on_disconnect();
            co_return std::unexpected{ec_write};
        }

        spdlog::debug("Sent {} bytes to {}", bytes_written, remote_address);
    }

    co_return true;  // Continue processing
}

// Reads client messages until the connection ends
template<typename SocketType>
inline boost::asio::awaitable<std::expected<void, std::error_code>>
session_reader(SocketType& socket, std::array<uint8_t, 8192>& buffer, WampSession& protocol,
               const std::string& remote_address, WriteLock& write_lock) {
    while (true) {
        auto [ec_read, bytes_read] = co_await socket.async_read_some(
            boost::asio::buffer(buffer),
            boost::asio::as_tuple(boost::asio::use_awaitable)
        );

        auto result = co_await handle_socket_read_completion(
            socket, buffer, protocol, remote_address, ec_read, bytes_read, &write_lock
        );
        if (!result) {
            co_return std::unexpected{result.error()};
        }
    }
}

// Sends queued events/invocations/results to the client, coalescing whatever is already waiting
// into one gathered write
template<typename SocketType>
inline boost::asio::awaitable<std::expected<void, std::error_code>>
session_writer(SocketType& socket, EventChannel& channel, const std::string& remote_address,
               WriteLock& write_lock) {
    std::vector<std::shared_ptr<const std::vector<uint8_t>>> frames;
    std::vector<boost::asio::const_buffer> buffers;

    while (true) {
        auto [ec_channel, first] = co_await channel.async_receive(
            boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_channel) {
            // Closed on disconnect, or cancelled because the reader finished
            co_return std::unexpected{ec_channel};
        }

        frames.clear();
        buffers.clear();
        size_t bytes = 0;
        auto add = [&](boost::system::error_code ec, EventToSend event) {
            if (!ec && event.event_data) {
                bytes += event.event_data->size();
                buffers.emplace_back(event.event_data->data(), event.event_data->size());
                frames.push_back(std::move(event.event_data));
            }
        };
        add(ec_channel, std::move(first));
        while (frames.size() < kMaxBatchFrames && bytes < kMaxBatchBytes &&
               channel.try_receive(add)) {
        }

        if (!co_await write_lock.lock()) {
            co_return std::unexpected{make_error_code(std::errc::operation_canceled)};
        }
        WriteLock::Guard guard{write_lock};

        auto [ec_write, bytes_written] = co_await boost::asio::async_write(
            socket, buffers, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_write) {
            if (ec_write != boost::asio::error::operation_aborted) {
                spdlog::error("Write error sending events to {}: {}", remote_address, ec_write.message());
            }
            co_return std::unexpected{ec_write};
        }

        spdlog::debug("Sent {} events ({} bytes) to {}", frames.size(), bytes_written, remote_address);
    }
}

template<typename SocketType>
inline boost::asio::awaitable<std::expected<void, std::error_code>>
handle_wamp_session(SocketType socket, boost::asio::io_context& io, const ServerConfig& config) {
    std::array<uint8_t, 8192> buffer{};

    auto remote_endpoint = get_remote_endpoint(socket);
    std::string remote_address = remote_endpoint.address().to_string();

    // Perform TLS handshake if this is an SSL socket
    if constexpr (requires { socket.async_handshake(ssl::stream_base::server, boost::asio::use_awaitable); }) {
        spdlog::debug("Starting TLS handshake with {}", remote_address);
        auto [ec_handshake] = co_await socket.async_handshake(
            ssl::stream_base::server,
            boost::asio::as_tuple(boost::asio::use_awaitable)
        );

        if (ec_handshake) {
            spdlog::error("TLS handshake failed from {}: {} (Client may not support TLS 1.3)",
                remote_address, ec_handshake.message());
            co_return std::unexpected{ec_handshake};
        }

        spdlog::info("TLS handshake complete with {}", remote_address);
    }

    spdlog::info("WAMP session started with {}", remote_address);

    WampSession protocol{io, config};
    protocol.on_connect();

    // Until the WAMP session is established nothing can be queued for the client, so a plain
    // read loop is enough
    while (!protocol.is_established()) {
        auto [ec_read, bytes_read] = co_await socket.async_read_some(
            boost::asio::buffer(buffer),
            boost::asio::as_tuple(boost::asio::use_awaitable)
        );

        auto result = co_await handle_socket_read_completion(
            socket, buffer, protocol, remote_address, ec_read, bytes_read
        );
        if (!result) {
            co_return std::unexpected{result.error()};
        }
    }

    // Established: one coroutine reads, another writes queued events; whichever ends first
    // (disconnect, error) cancels the other
    auto event_channel = EventChannelRegistry::get_or_create(protocol.session_id(), io);
    spdlog::debug("Event channel acquired for session {}", protocol.session_id());

    WriteLock write_lock{io};
    auto executor = co_await boost::asio::this_coro::executor;

    auto [order, reader_ex, reader_result, writer_ex, writer_result] =
        co_await boost::asio::experimental::make_parallel_group(
            boost::asio::co_spawn(executor,
                session_reader(socket, buffer, protocol, remote_address, write_lock),
                boost::asio::deferred),
            boost::asio::co_spawn(executor,
                session_writer(socket, *event_channel, remote_address, write_lock),
                boost::asio::deferred)
        ).async_wait(boost::asio::experimental::wait_for_one(), boost::asio::use_awaitable);

    protocol.on_disconnect();

    // Only the coroutine that finished first reports; the other was cancelled
    if (auto ex = order[0] == 0 ? reader_ex : writer_ex) std::rethrow_exception(ex);
    const auto& finished = order[0] == 0 ? reader_result : writer_result;
    if (!finished) {
        co_return std::unexpected{finished.error()};
    }
    co_return std::expected<void, std::error_code>{};
}

// Periodically fails pending calls whose callee has not answered in time.
inline boost::asio::awaitable<void> call_timeout_sweeper() {
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    for (;;) {
        timer.expires_after(std::chrono::milliseconds(50));
        auto [ec] = co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec) co_return;
        ProcedureHandler::expire_calls();
    }
}

class WampServer {
public:
    WampServer(boost::asio::io_context& io_context, unsigned short port, const ServerConfig& config)
        : io_context_(io_context)
        , acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
        , bound_port_(acceptor_.local_endpoint().port())
        , config_(config)
    {
        EventChannelRegistry::configure(config.events);
        ProcedureHandler::set_default_call_timeout(config.call_timeout);
    }

    void start() {
        boost::asio::co_spawn(io_context_, call_timeout_sweeper(), boost::asio::detached);
        boost::asio::co_spawn(
            io_context_,
            accept_loop(),
            boost::asio::detached
        );
    }

    [[nodiscard]] unsigned short port() const {
        return bound_port_;
    }

private:
    boost::asio::awaitable<void> accept_loop() {
        spdlog::info("WAMP Server listening on port {}", bound_port_);

        while (true) {
            auto [ec, socket] = co_await acceptor_.async_accept(
                boost::asio::as_tuple(boost::asio::use_awaitable)
            );

            if (ec) {
                spdlog::error("Accept error: {}", ec.message());
                continue;
            }

            auto remote_endpoint = socket.remote_endpoint();
            spdlog::info("Accepted connection from {}",
                remote_endpoint.address().to_string());

            set_socket_options(socket);

            boost::asio::co_spawn(
                acceptor_.get_executor(),
                handle_wamp_session<tcp::socket>(std::move(socket), io_context_, config_),
                boost::asio::detached
            );
        }
    }

    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    unsigned short bound_port_;
    const ServerConfig& config_;
};

// ============================================================================
// WampTlsServer - WAMP Server with TLS 1.3 support
// ============================================================================
class WampTlsServer {
public:
    WampTlsServer(
        boost::asio::io_context& io_context,
        const ServerConfig& config
    )
        : io_context_(io_context)
        , ssl_context_(ssl::context::tlsv13)
        , acceptor_(io_context, tcp::endpoint(tcp::v4(), config.port))
        , bound_port_(acceptor_.local_endpoint().port())
        , config_(config)
    {
        EventChannelRegistry::configure(config.events);
        ProcedureHandler::set_default_call_timeout(config.call_timeout);
        setup_ssl_context(config.tls);
    }

    void start() {
        boost::asio::co_spawn(io_context_, call_timeout_sweeper(), boost::asio::detached);
        boost::asio::co_spawn(
            io_context_,
            accept_loop(),
            boost::asio::detached
        );
    }

    [[nodiscard]] unsigned short port() const {
        return bound_port_;
    }

private:
    void setup_ssl_context(const TlsConfig& tls_config) {
        // Set TLS 1.3 only (reject TLS 1.2 and earlier)
        SSL_CTX_set_min_proto_version(
            ssl_context_.native_handle(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(
            ssl_context_.native_handle(), TLS1_3_VERSION);

        // Load certificate and private key
        ssl_context_.use_certificate_chain_file(tls_config.cert_path.string());
        ssl_context_.use_private_key_file(
            tls_config.key_path.string(),
            ssl::context::pem
        );

        // Optional: Load CA certificate for client verification
        if (tls_config.ca_path) {
            ssl_context_.load_verify_file(tls_config.ca_path->string());
        }

        // Optional: Require client certificates
        if (tls_config.require_client_cert) {
            ssl_context_.set_verify_mode(
                ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
        } else {
            ssl_context_.set_verify_mode(ssl::verify_none);
        }

        // Set cipher suite preferences (TLS 1.3 ciphers)
        SSL_CTX_set_ciphersuites(
            ssl_context_.native_handle(),
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
        );

        spdlog::info("TLS context configured (TLS 1.3 only)");
        spdlog::info("  Certificate: {}", tls_config.cert_path.string());
        spdlog::info("  Private key: {}", tls_config.key_path.string());
        if (tls_config.ca_path) {
            spdlog::info("  CA cert: {}", tls_config.ca_path->string());
        }
        if (tls_config.require_client_cert) {
            spdlog::info("  Client cert required: yes");
        }
    }

    boost::asio::awaitable<void> accept_loop() {
        using ssl_socket = ssl::stream<tcp::socket>;

        spdlog::info("WAMP Server listening on port {}", bound_port_);

        while (true) {
            auto [ec, plain_socket] = co_await acceptor_.async_accept(
                boost::asio::as_tuple(boost::asio::use_awaitable)
            );

            if (ec) {
                spdlog::error("Accept error: {}", ec.message());
                continue;
            }

            auto remote_endpoint = plain_socket.remote_endpoint();
            spdlog::info("Accepted TLS connection from {}",
                remote_endpoint.address().to_string());

            // Wrap plain socket in SSL stream
            ssl_socket tls_socket{std::move(plain_socket), ssl_context_};

            set_socket_options(tls_socket);

            boost::asio::co_spawn(
                acceptor_.get_executor(),
                handle_wamp_session<ssl_socket>(std::move(tls_socket), io_context_, config_),
                boost::asio::detached
            );
        }
    }

    boost::asio::io_context& io_context_;
    ssl::context ssl_context_;
    tcp::acceptor acceptor_;
    unsigned short bound_port_;
    const ServerConfig& config_;
};

} // namespace wamp
