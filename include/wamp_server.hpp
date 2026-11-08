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
#include "shard.hpp"
#include "shard_group.hpp"
#include "event_channel.hpp"
#include "config.hpp"
#include "procedure_handler.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/experimental/parallel_group.hpp>
#include <spdlog/spdlog.h>
#include <expected>
#include <system_error>
#include <span>
#include <memory>
#include <optional>
#include <openssl/ssl.h>

namespace wamp {

using asio::ip::tcp;
namespace ssl = asio::ssl;

// A TLS stream (ssl::stream<...>): the one kind of socket that has a server-side handshake
template<typename SocketType>
concept TlsSocket =
    requires(SocketType& s) { s.async_handshake(ssl::stream_base::server, asio::use_awaitable); };

// What the session code needs from a connection: a plain tcp::socket or an ssl::stream<tcp::socket>
template<typename SocketType>
concept WampSocket = requires(SocketType& s, asio::mutable_buffer in, asio::const_buffer out) {
    s.lowest_layer();
    s.get_executor();
    s.async_read_some(in, asio::use_awaitable);
    s.async_write_some(out, asio::use_awaitable);
};

// ============================================================================
// Socket Helper Functions - Work with both plain TCP and TLS sockets
// ============================================================================

template<WampSocket SocketType>
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
template<WampSocket SocketType>
inline void set_socket_options(SocketType& socket) {
    if constexpr (TlsSocket<SocketType>) {
        socket.lowest_layer().set_option(tcp::no_delay(true));
    } else {
        // Non-blocking so a read after wait_read never waits (see read_some)
        socket.set_option(tcp::no_delay(true));
        socket.non_blocking(true);
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
    explicit WriteLock(asio::io_context& io) : token_(io, 1) {
        token_.try_send(std::error_code{});
    }

    // False if the wait was cancelled (the session is closing)
    asio::awaitable<bool> lock() {
        if (token_.try_receive([](std::error_code) {})) {
            co_return true;
        }
        auto [ec] = co_await token_.async_receive(asio::as_tuple(asio::use_awaitable));
        co_return !ec;
    }

    void unlock() {
        token_.try_send(std::error_code{});
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
    asio::experimental::channel<void(std::error_code)> token_;
};

// Upper bounds for one gathered write, so a flood for one subscriber cannot hold the socket (and the
// write lock) for long
inline constexpr size_t kMaxBatchFrames = 64;
inline constexpr size_t kMaxBatchBytes = 256 * 1024;

// ----------------------------------------------------------------------------
// Reading without a per-session buffer
// ----------------------------------------------------------------------------
// A session blocked in a read must not own a large buffer (8 KiB of the ~11 KiB each idle session
// cost). Plain sockets wait for readability first and then read into one scratch buffer shared by every
// session on the thread; the read completes synchronously and process() copies what it needs before
// the next suspension, so the scratch is never held across one. TLS streams cannot do this (OpenSSL
// may hold decrypted bytes the socket no longer signals), so they keep a small per-session buffer.
inline constexpr size_t kSharedReadScratch = 64 * 1024;
inline constexpr size_t kTlsReadBuffer = 4 * 1024;

inline std::span<uint8_t> shared_read_scratch() {
    static thread_local std::array<uint8_t, kSharedReadScratch> scratch;
    return scratch;
}

// Per-session read state: unused for plain sockets, a small buffer for TLS
template<WampSocket SocketType>
struct ReadState {
    std::vector<uint8_t> tls_buffer;
};

struct ReadResult {
    std::error_code ec;
    std::span<const uint8_t> data;  // valid until the next suspension point
};

template<WampSocket SocketType>
inline asio::awaitable<ReadResult> read_some(SocketType& socket, ReadState<SocketType>& state) {
    if constexpr (TlsSocket<SocketType>) {
        if (state.tls_buffer.empty()) state.tls_buffer.resize(kTlsReadBuffer);
        auto [ec, n] = co_await socket.async_read_some(
            asio::buffer(state.tls_buffer), asio::as_tuple(asio::use_awaitable));
        co_return ReadResult{ec, std::span<const uint8_t>{state.tls_buffer.data(), n}};
    } else {
        while (true) {
            auto [ec_wait] = co_await socket.async_wait(
                tcp::socket::wait_read, asio::as_tuple(asio::use_awaitable));
            if (ec_wait) co_return ReadResult{ec_wait, {}};

            auto scratch = shared_read_scratch();
            std::error_code ec;
            const size_t n = socket.read_some(asio::buffer(scratch.data(), scratch.size()), ec);
            if (ec == asio::error::would_block) continue;  // readiness was spurious
            co_return ReadResult{ec, std::span<const uint8_t>{scratch.data(), n}};
        }
    }
}

// Handles one socket read result. `write_lock` is null before the session's writer exists.
template<WampSocket SocketType>
inline asio::awaitable<std::expected<bool, std::error_code>>
handle_socket_read_completion(
    SocketType& socket,
    WampSession& protocol,
    const std::string& remote_address,
    const ReadResult& read,
    WriteLock* write_lock = nullptr
) {
    const auto ec_read = read.ec;
    // Check for EOF (client disconnected gracefully)
    if (ec_read == asio::error::eof) {
        spdlog::info("Client {} disconnected", remote_address);
        protocol.on_disconnect();
        co_return std::unexpected{ec_read};
    }

    if (ec_read == asio::error::operation_aborted) {
        spdlog::debug("Read from {} canceled", remote_address);
        protocol.on_disconnect();
        co_return std::unexpected{ec_read};
    }

    if (ec_read) {
        spdlog::error("Read error from {}: {}", remote_address, ec_read.message());
        protocol.on_disconnect();
        co_return std::unexpected{ec_read};
    }

    spdlog::debug("Received {} bytes from {}", read.data.size(), remote_address);

    auto result = protocol.process(read.data);

    if (!result) {
        spdlog::error("Protocol error from {}: {}", remote_address, result.error().message());
        protocol.on_disconnect();
        co_return std::unexpected{result.error()};
    }

    // Backpressure: if delivering this input's events/invocations hit a full subscriber queue,
    // stop reading from this client until the subscribers catch up (bounded by the timeout)
    if (auto blocked = protocol.shard().channels.take_blocked(); !blocked.empty()) {
        co_await protocol.shard().channels.deliver_blocked(std::move(blocked));
    }
    // Same for subscribers on other shards whose inbox is filling up
    if (auto& shard = protocol.shard(); !shard.congested.empty()) {
        co_await shard.group->wait_for_room(std::exchange(shard.congested, {}),
                                            shard.channels.config().backpressure_timeout);
    }

    if (!result->empty()) {
        if (write_lock && !co_await write_lock->lock()) {
            protocol.on_disconnect();
            co_return std::unexpected{make_error_code(std::errc::operation_canceled)};
        }
        std::optional<WriteLock::Guard> guard;
        if (write_lock) guard.emplace(*write_lock);

        auto [ec_write, bytes_written] = co_await asio::async_write(
            socket,
            asio::buffer(*result),
            asio::as_tuple(asio::use_awaitable)
        );

        if (ec_write) {
            spdlog::error("Write error to {}: {}", remote_address, ec_write.message());
            protocol.on_disconnect();
            co_return std::unexpected{ec_write};
        }

        spdlog::debug("Sent {} bytes to {}", bytes_written, remote_address);
    }

    if (protocol.should_close()) {
        // The final bytes (a WebSocket close frame or an HTTP error) are out: close our side, but let the
        // client read them first
        std::error_code ignored;
        socket.lowest_layer().shutdown(asio::socket_base::shutdown_send, ignored);
        protocol.on_disconnect();
        co_return std::unexpected{make_error_code(std::errc::connection_aborted)};
    }

    co_return true;  // Continue processing
}

// Reads client messages until the connection ends
template<WampSocket SocketType>
inline asio::awaitable<std::expected<void, std::error_code>>
session_reader(SocketType& socket, ReadState<SocketType>& state, WampSession& protocol,
               const std::string& remote_address, WriteLock& write_lock) {
    while (true) {
        auto read = co_await read_some(socket, state);

        auto result = co_await handle_socket_read_completion(
            socket, protocol, remote_address, read, &write_lock
        );
        if (!result) {
            co_return std::unexpected{result.error()};
        }
    }
}

// Sends queued events/invocations/results to the client, coalescing whatever is already waiting
// into one gathered write
template<WampSocket SocketType>
inline asio::awaitable<std::expected<void, std::error_code>>
session_writer(SocketType& socket, EventChannel& channel, const std::string& remote_address,
               WriteLock& write_lock, bool websocket) {
    std::vector<std::shared_ptr<const std::vector<uint8_t>>> frames;
    std::vector<asio::const_buffer> buffers;
    // WebSocket: the router's frames are [4-byte RawSocket header][payload]; each is sent as a binary
    // message made of a small WebSocket header (kept here, addresses stable) and the shared payload, unmodified
    std::vector<ws::FrameHeaderBytes> ws_headers;
    ws_headers.reserve(kMaxBatchFrames + 1);

    while (true) {
        auto [ec_channel, first] = co_await channel.async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec_channel) {
            // Closed on disconnect, or cancelled because the reader finished
            co_return std::unexpected{ec_channel};
        }

        frames.clear();
        buffers.clear();
        ws_headers.clear();
        size_t bytes = 0;
        bool closing = false;   // a close_after frame is in this batch: nothing after it is sent
        auto add = [&](std::error_code ec, EventToSend event) {
            if (!ec && event.event_data && !closing) {
                closing = event.close_after;
                bytes += event.event_data->size();
                if (websocket) {
                    if (event.event_data->size() <= rawsocket::FRAME_HEADER_SIZE) return;
                    const auto payload_size = event.event_data->size() - rawsocket::FRAME_HEADER_SIZE;
                    ws_headers.push_back(ws::encode_header(ws::Opcode::BINARY, payload_size));
                    buffers.emplace_back(ws_headers.back().bytes.data(), ws_headers.back().size);
                    buffers.emplace_back(event.event_data->data() + rawsocket::FRAME_HEADER_SIZE, payload_size);
                } else {
                    buffers.emplace_back(event.event_data->data(), event.event_data->size());
                }
                frames.push_back(std::move(event.event_data));
            }
        };
        add(ec_channel, std::move(first));
        while (!closing && frames.size() < kMaxBatchFrames && bytes < kMaxBatchBytes &&
               channel.try_receive(add)) {
        }

        if (!co_await write_lock.lock()) {
            co_return std::unexpected{make_error_code(std::errc::operation_canceled)};
        }
        WriteLock::Guard guard{write_lock};

        auto [ec_write, bytes_written] = co_await asio::async_write(
            socket, buffers, asio::as_tuple(asio::use_awaitable));
        if (ec_write) {
            if (ec_write != asio::error::operation_aborted) {
                spdlog::error("Write error sending events to {}: {}", remote_address, ec_write.message());
            }
            co_return std::unexpected{ec_write};
        }

        spdlog::debug("Sent {} events ({} bytes) to {}", frames.size(), bytes_written, remote_address);

        if (closing) {
            // The router is shutting down and the GOODBYE is out: end the WebSocket properly (1001 going
            // away), close our side and let the session end
            if (websocket) {
                static constexpr std::array<uint8_t, 4> kCloseGoingAway{0x88, 0x02, 0x03, 0xE9};
                (void)co_await asio::async_write(socket, asio::buffer(kCloseGoingAway),
                                                 asio::as_tuple(asio::use_awaitable));
            }
            std::error_code ignored;
            socket.lowest_layer().shutdown(asio::socket_base::shutdown_send, ignored);
            co_return std::expected<void, std::error_code>{};
        }
    }
}

template<WampSocket SocketType>
inline asio::awaitable<std::expected<void, std::error_code>>
handle_wamp_session(SocketType socket, asio::io_context& io, const ServerConfig& config,
                    std::shared_ptr<Shard> shard) {
    // `shard` is held by this coroutine frame, so the shard outlives the session even if the server
    // object is destroyed first (e.g. io_context shutdown destroys suspended sessions)
    ReadState<SocketType> read_state;

    auto remote_endpoint = get_remote_endpoint(socket);
    std::string remote_address = remote_endpoint.address().to_string();

    // A connection that does not become an established session in time is closed: closing the socket makes
    // whatever read or handshake the session is waiting in fail. The deadline covers everything before
    // WELCOME, so trickling bytes does not extend it. The timer lives in this frame; cancelling it on
    // exit (or when it is destroyed) calls the handler with operation_aborted, which touches nothing.
    asio::steady_timer handshake_timer{io};
    bool handshake_done = false;
    if (config.handshake_timeout.count() > 0) {
        handshake_timer.expires_after(config.handshake_timeout);
        handshake_timer.async_wait([&socket, &handshake_done, &shard, remote_address, limit = config.handshake_timeout](
                                       std::error_code ec) {
            // A timer that had already expired when the session got established still runs its handler
            // with success; handshake_done tells it to leave the live session alone.
            if (ec || handshake_done) return;
            shard->counters.handshake_timeouts.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("Closing {}: no established session within {} ms", remote_address, limit.count());
            std::error_code ignored;
            socket.lowest_layer().close(ignored);
        });
    }

    // Perform TLS handshake if this is an SSL socket
    if constexpr (requires { socket.async_handshake(ssl::stream_base::server, asio::use_awaitable); }) {
        spdlog::debug("Starting TLS handshake with {}", remote_address);
        auto [ec_handshake] = co_await socket.async_handshake(
            ssl::stream_base::server,
            asio::as_tuple(asio::use_awaitable)
        );

        if (ec_handshake) {
            spdlog::error("TLS handshake failed from {}: {} (Client may not support TLS 1.3)",
                remote_address, ec_handshake.message());
            co_return std::unexpected{ec_handshake};
        }

        spdlog::info("TLS handshake complete with {}", remote_address);
    }

    spdlog::info("WAMP session started with {}", remote_address);

    WampSession protocol{io, config, *shard};
    protocol.on_connect();

    // Until the WAMP session is established nothing can be queued for the client, so a plain
    // read loop is enough
    while (!protocol.is_established()) {
        auto read = co_await read_some(socket, read_state);

        auto result = co_await handle_socket_read_completion(
            socket, protocol, remote_address, read
        );
        if (!result) {
            co_return std::unexpected{result.error()};
        }
    }

    handshake_done = true;
    handshake_timer.cancel();

    // Established: one coroutine reads, another writes queued events; whichever ends first
    // (disconnect, error) cancels the other
    auto event_channel = shard->channels.get_or_create(protocol.session_id(), io);
    spdlog::debug("Event channel acquired for session {}", protocol.session_id());

    WriteLock write_lock{io};
    auto executor = co_await asio::this_coro::executor;

    auto [order, reader_ex, reader_result, writer_ex, writer_result] =
        co_await asio::experimental::make_parallel_group(
            asio::co_spawn(executor,
                session_reader(socket, read_state, protocol, remote_address, write_lock),
                asio::deferred),
            asio::co_spawn(executor,
                session_writer(socket, *event_channel, remote_address, write_lock, protocol.is_websocket()),
                asio::deferred)
        ).async_wait(asio::experimental::wait_for_one(), asio::use_awaitable);

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
inline asio::awaitable<void> call_timeout_sweeper(std::shared_ptr<Shard> shard) {
    auto executor = co_await asio::this_coro::executor;
    asio::steady_timer timer(executor);
    for (;;) {
        timer.expires_after(std::chrono::milliseconds(50));
        auto [ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec) co_return;
        ProcedureHandler::expire_calls(*shard);
    }
}

// TLS 1.3 only server context from the configuration (shared by WampTlsServer and Router)
inline void configure_tls_context(ssl::context& ssl_context_, const TlsConfig& tls_config) {
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

class WampServer {
public:
    WampServer(asio::io_context& io_context, unsigned short port, const ServerConfig& config)
        : io_context_(io_context)
        , acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
        , bound_port_(acceptor_.local_endpoint().port())
        , config_(config)
        , shard_(std::make_shared<Shard>(ShardConfig::from(config)))
    {
    }

    void start() {
        asio::co_spawn(io_context_, call_timeout_sweeper(shard_), asio::detached);
        asio::co_spawn(
            io_context_,
            accept_loop(),
            asio::detached
        );
    }

    [[nodiscard]] Shard& shard() const {
        return *shard_;
    }

    [[nodiscard]] unsigned short port() const {
        return bound_port_;
    }

private:
    asio::awaitable<void> accept_loop() {
        spdlog::info("WAMP Server listening on port {}", bound_port_);

        while (true) {
            auto [ec, socket] = co_await acceptor_.async_accept(
                asio::as_tuple(asio::use_awaitable)
            );

            if (ec) {
                spdlog::error("Accept error: {}", ec.message());
                continue;
            }

            auto remote_endpoint = socket.remote_endpoint();
            spdlog::info("Accepted connection from {}",
                remote_endpoint.address().to_string());

            set_socket_options(socket);

            asio::co_spawn(
                acceptor_.get_executor(),
                handle_wamp_session<tcp::socket>(std::move(socket), io_context_, config_, shard_),
                asio::detached
            );
        }
    }

    asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    unsigned short bound_port_;
    const ServerConfig& config_;
    std::shared_ptr<Shard> shard_;  // this server's routing state, shared with its sessions
};

// ============================================================================
// WampTlsServer - WAMP Server with TLS 1.3 support
// ============================================================================
class WampTlsServer {
public:
    WampTlsServer(
        asio::io_context& io_context,
        const ServerConfig& config
    )
        : io_context_(io_context)
        , ssl_context_(ssl::context::tlsv13)
        , acceptor_(io_context, tcp::endpoint(tcp::v4(), config.port))
        , bound_port_(acceptor_.local_endpoint().port())
        , config_(config)
        , shard_(std::make_shared<Shard>(ShardConfig::from(config)))
    {
        setup_ssl_context(config.tls);
    }

    void start() {
        asio::co_spawn(io_context_, call_timeout_sweeper(shard_), asio::detached);
        asio::co_spawn(
            io_context_,
            accept_loop(),
            asio::detached
        );
    }

    [[nodiscard]] Shard& shard() const {
        return *shard_;
    }

    [[nodiscard]] unsigned short port() const {
        return bound_port_;
    }

private:
    void setup_ssl_context(const TlsConfig& tls_config) {
        configure_tls_context(ssl_context_, tls_config);
    }

    asio::awaitable<void> accept_loop() {
        using ssl_socket = ssl::stream<tcp::socket>;

        spdlog::info("WAMP Server listening on port {}", bound_port_);

        while (true) {
            auto [ec, plain_socket] = co_await acceptor_.async_accept(
                asio::as_tuple(asio::use_awaitable)
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

            asio::co_spawn(
                acceptor_.get_executor(),
                handle_wamp_session<ssl_socket>(std::move(tls_socket), io_context_, config_, shard_),
                asio::detached
            );
        }
    }

    asio::io_context& io_context_;
    ssl::context ssl_context_;
    tcp::acceptor acceptor_;
    unsigned short bound_port_;
    const ServerConfig& config_;
    std::shared_ptr<Shard> shard_;  // this server's routing state, shared with its sessions
};

} // namespace wamp
