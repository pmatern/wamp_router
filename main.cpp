#include "include/wamp_server.hpp"
#include <fmt/core.h>
#include <spdlog/spdlog.h>

int main(int argc, char* argv[]) {
    try {
        // Configure logging
        spdlog::set_level(spdlog::level::info);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] %v");

        // TODO: Load configuration from file/environment
        // Example:
        // wamp::ProcedureHandler::set_max_pending_invocations(20000);

        // Parse port from command line (default: 8080)
        unsigned short port = 8080;
        if (argc > 1) {
            port = static_cast<unsigned short>(std::stoi(argv[1]));
        }

        fmt::print("\n");
        fmt::print("╔════════════════════════════════════════╗\n");
        fmt::print("║   WAMP Router (RawSocket + CBOR)      ║\n");
        fmt::print("╚════════════════════════════════════════╝\n");
        fmt::print("\n");
        fmt::print("Starting WAMP router on port {}...\n", port);
        fmt::print("\n");
        fmt::print("Press Ctrl+C to stop\n\n");

        // Create io_context
        boost::asio::io_context io_context;

        // Create and start WAMP server with event channel support
        wamp::WampServer server(io_context, port);
        server.start();

        // Run the event loop
        io_context.run();

    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}
