// Copyright 2026 Patrick Matern
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
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <spdlog/spdlog.h>
#include <expected>
#include <system_error>
#include <span>
#include <memory>
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

template<typename SocketType>
inline boost::asio::awaitable<std::expected<bool, std::error_code>>
handle_socket_read_completion(
    SocketType& socket,
    const std::array<uint8_t, 8192>& buffer,
    WampSession& protocol,
    const std::string& remote_address,
    boost::system::error_code ec_read,
    std::size_t bytes_read
) {
    // Check for EOF (client disconnected gracefully)
    if (ec_read == boost::asio::error::eof) {
        spdlog::info("Client {} disconnected", remote_address);
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

    if (!result->empty()) {
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

    std::shared_ptr<EventChannel> event_channel;

    while (true) {
        // Get event channel once session is established
        if (!event_channel && protocol.is_established()) {
            event_channel = EventChannelRegistry::get_or_create(protocol.session_id(), io);
            spdlog::debug("Event channel acquired for session {}", protocol.session_id());
        }

        if (event_channel) {
            // Session established - wait concurrently on socket and event channel
            auto [order, ec_read, bytes_read, ec_channel, event] = co_await boost::asio::experimental::make_parallel_group(
                socket.async_read_some(
                    boost::asio::buffer(buffer),
                    boost::asio::deferred
                ),
                event_channel->async_receive(
                    boost::asio::deferred
                )
            ).async_wait(
                boost::asio::experimental::wait_for_one(),
                boost::asio::use_awaitable
            );

            if (order[0] == 0) {
                // Socket read completed
                auto result = co_await handle_socket_read_completion(
                    socket, buffer, protocol, remote_address, ec_read, bytes_read
                );
                if (!result) {
                    co_return std::unexpected{result.error()};
                }

            } else {
                // Event channel received an event
                if (ec_channel) {
                    spdlog::error("Event channel error: {}", ec_channel.message());
                    // Don't disconnect on channel error, just continue
                    continue;
                }

                spdlog::debug("Sending {} byte event to session {}",
                    event.event_data->size(), event.target_session_id);

                auto [ec_write, bytes_written] = co_await boost::asio::async_write(
                    socket,
                    boost::asio::buffer(*event.event_data),
                    boost::asio::as_tuple(boost::asio::use_awaitable)
                );

                if (ec_write) {
                    spdlog::error("Write error sending event to {}: {}",
                        remote_address, ec_write.message());
                    protocol.on_disconnect();
                    co_return std::unexpected{ec_write};
                }

                spdlog::debug("Sent event: {} bytes to {}",
                    bytes_written, remote_address);
            }

        } else {
            // Session not yet established - only wait on socket
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
    }

    void start() {
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
        setup_ssl_context(config.tls);
    }

    void start() {
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
