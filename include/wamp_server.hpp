#pragma once

#include "wamp_session.hpp"
#include "event_channel.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <spdlog/spdlog.h>
#include <expected>
#include <system_error>
#include <span>
#include <memory>

namespace wamp {

using boost::asio::ip::tcp;

// Helper function to handle socket read completion
inline boost::asio::awaitable<std::expected<bool, std::error_code>>
handle_socket_read_completion(
    tcp::socket& socket,
    const std::array<uint8_t, 8192>& buffer,
    WampSession& protocol,
    const tcp::endpoint& remote_endpoint,
    boost::system::error_code ec_read,
    std::size_t bytes_read
) {
    // Check for EOF (client disconnected gracefully)
    if (ec_read == boost::asio::error::eof) {
        spdlog::info("Client {} disconnected", remote_endpoint.address().to_string());
        protocol.on_disconnect();
        co_return std::unexpected(ec_read);
    }

    if (ec_read) {
        spdlog::error("Read error from {}: {}",
            remote_endpoint.address().to_string(), ec_read.message());
        protocol.on_disconnect();
        co_return std::unexpected(ec_read);
    }

    spdlog::debug("Received {} bytes from {}",
        bytes_read, remote_endpoint.address().to_string());

    auto result = protocol.process(std::span<const uint8_t>(buffer.data(), bytes_read));

    if (!result) {
        spdlog::error("Protocol error from {}: {}",
            remote_endpoint.address().to_string(), result.error().message());
        protocol.on_disconnect();
        co_return std::unexpected(result.error());
    }

    if (!result->empty()) {
        auto [ec_write, bytes_written] = co_await boost::asio::async_write(
            socket,
            boost::asio::buffer(*result),
            boost::asio::as_tuple(boost::asio::use_awaitable)
        );

        if (ec_write) {
            spdlog::error("Write error to {}: {}",
                remote_endpoint.address().to_string(), ec_write.message());
            protocol.on_disconnect();
            co_return std::unexpected(ec_write);
        }

        spdlog::debug("Sent {} bytes to {}",
            bytes_written, remote_endpoint.address().to_string());
    }

    co_return true;  // Continue processing
}

inline boost::asio::awaitable<std::expected<void, std::error_code>>
handle_wamp_session(tcp::socket socket, boost::asio::io_context& io) {
    std::array<uint8_t, 8192> buffer{};

    auto remote_endpoint = socket.remote_endpoint();
    spdlog::info("WAMP session started with {}", remote_endpoint.address().to_string());

    WampSession protocol{io};
    protocol.on_connect();

    std::shared_ptr<EventChannel> event_channel;
    uint64_t last_session_id = 0;

    while (true) {
        // Check if session was established and we need to get the event channel
        uint64_t current_session_id = protocol.session_id();
        if (current_session_id != 0 && last_session_id == 0) {
            // Session just established, get the event channel
            event_channel = EventChannelRegistry::get_or_create(current_session_id, io);
            spdlog::debug("Event channel acquired for session {}", current_session_id);
            last_session_id = current_session_id;
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
                    socket, buffer, protocol, remote_endpoint, ec_read, bytes_read
                );
                if (!result) {
                    co_return std::unexpected(result.error());
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
                        remote_endpoint.address().to_string(), ec_write.message());
                    protocol.on_disconnect();
                    co_return std::unexpected(ec_write);
                }

                spdlog::debug("Sent event: {} bytes to {}",
                    bytes_written, remote_endpoint.address().to_string());
            }

        } else {
            // Session not yet established - only wait on socket
            auto [ec_read, bytes_read] = co_await socket.async_read_some(
                boost::asio::buffer(buffer),
                boost::asio::as_tuple(boost::asio::use_awaitable)
            );

            auto result = co_await handle_socket_read_completion(
                socket, buffer, protocol, remote_endpoint, ec_read, bytes_read
            );
            if (!result) {
                co_return std::unexpected(result.error());
            }
        }
    }
}

class WampServer {
public:
    WampServer(boost::asio::io_context& io_context, unsigned short port)
        : io_context_(io_context)
        , acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
        , bound_port_(acceptor_.local_endpoint().port())
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

            socket.set_option(tcp::no_delay(true));

            boost::asio::co_spawn(
                acceptor_.get_executor(),
                handle_wamp_session(std::move(socket), io_context_),
                boost::asio::detached
            );
        }
    }

    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    unsigned short bound_port_;
};

} // namespace wamp
