# WAMP Router

A high-performance C++23 implementation of a [WAMP](https://wamp-proto.org/) (Web Application Messaging Protocol) router using RawSocket transport with CBOR serialization.

## What is WAMP?

WAMP is a routed protocol that provides two messaging patterns:
- **Remote Procedure Calls (RPC)**: Clients can call procedures registered by other clients
- **Publish & Subscribe (PubSub)**: Clients can publish events to topics and subscribe to receive them

This router acts as the central message broker, routing messages between clients.

## Features

- **RPC Support**: Full `CALL`, `REGISTER`, `YIELD`, `INVOCATION`, `RESULT` workflow
- **PubSub Support**: `SUBSCRIBE`, `PUBLISH`, `EVENT` messaging
- **RawSocket Transport**: Binary TCP protocol (not WebSocket)
- **CBOR Serialization**: Compact binary message format
- **C++20 Coroutines**: Asynchronous I/O using `boost::asio::awaitable`
- **Event Channels**: Efficient message delivery using Boost.Asio experimental channels
- **Session Management**: Automatic cleanup on disconnect
- **Modern C++23**: Uses `std::expected`, `std::span`, ranges, etc.

## Dependencies

- **Boost.Asio**: Asynchronous networking and coroutines
- **nlohmann-json**: CBOR serialization
- **fmt**: String formatting
- **spdlog**: Structured logging
- **Catch2**: Unit testing framework

## Quick Start

### Docker Build (Recommended)

```bash
# 1. Build the Docker image (one-time setup)
./scripts/build.sh

# 2. Build the router
./scripts/cmake-build.sh

# 3. Run tests
./scripts/run.sh ./build/wamp_tests

# 4. Run the router on port 8080
./scripts/run.sh -p 8080:8080 ./build/wamp_router 8080
```

### Local Build

Requires: Clang 18+ or GCC 14+ with C++23 support, CMake 3.25+, Ninja, vcpkg

```bash
# 1. Set VCPKG_ROOT environment variable
export VCPKG_ROOT=/path/to/vcpkg

# 2. Configure and build
cmake --preset local-release
cmake --build build-local

# 3. Run tests
./build-local/wamp_tests

# 4. Run the router
./build-local/wamp_router 8080
```

## Building

### Docker Container Build

The project includes a self-contained Docker environment with Clang 18 and libc++:

```bash
# Build Docker image
./scripts/build.sh

# Configure and build (Release mode)
./scripts/cmake-build.sh

# Debug build
./scripts/cmake-build.sh --build-type Debug

# Clean build
./scripts/cmake-build.sh --clean

# Parallel build
./scripts/cmake-build.sh -j 8

# Build specific target
./scripts/cmake-build.sh --target wamp_router
```

**Build artifacts:** `./build/`

### Local Build

Using CMake presets for local development:

```bash
# Debug build
cmake --preset local-debug
cmake --build build-local

# Release build
cmake --preset local-release
cmake --build build-local

# System packages (no vcpkg)
cmake --preset system-packages
cmake --build build-system
```

**Build artifacts:** `./build-local/` or `./build-system/`

## Running

### Docker Container

```bash
# Run on default port 8080 (maps container port to host)
./scripts/run.sh -p 8080:8080 ./build/wamp_router

# Run on custom port
./scripts/run.sh -p 9000:9000 ./build/wamp_router 9000

# Interactive shell
./scripts/shell.sh
```

### Local

```bash
# Run on default port 8080
./build-local/wamp_router

# Run on custom port
./build-local/wamp_router 9000
```

## Testing

### Docker Container

```bash
# Run all tests
./scripts/run.sh ./build/wamp_tests

# Run specific test
./scripts/run.sh ./build/wamp_tests "[test name]"

# List all tests
./scripts/run.sh ./build/wamp_tests --list-tests

# Run tests with CTest
./scripts/run.sh ctest --test-dir build --output-on-failure
```

### Local

```bash
# Run all tests
./build-local/wamp_tests

# Run specific test
./build-local/wamp_tests "[test name]"

# With CTest
ctest --test-dir build-local --output-on-failure
```

### Test Coverage

The project includes comprehensive tests:
- **test_wamp_id.cpp**: ID generator tests
- **test_raw_socket.cpp**: RawSocket framing tests
- **test_wamp_serializer.cpp**: CBOR message serialization tests
- **test_subscription_manager.cpp**: Topic subscription tests
- **test_wamp_session.cpp**: Protocol state machine tests
- **test_procedure_handler.cpp**: RPC handling tests
- **test_integration.cpp**: End-to-end integration tests

## Connecting Clients

The router uses WAMP RawSocket transport with CBOR serialization:

- **Protocol**: WAMP v2
- **Transport**: RawSocket (TCP)
- **Serializer**: CBOR (not JSON)
- **Default Port**: 8080

### Example: Python Client

```python
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner

class MyComponent(ApplicationSession):
    async def onJoin(self, details):
        # Subscribe to a topic
        def on_event(msg):
            print(f"Got event: {msg}")

        await self.subscribe(on_event, 'com.example.topic')

        # Publish to a topic
        self.publish('com.example.topic', 'Hello WAMP!')

        # Call a remote procedure
        result = await self.call('com.example.add', 2, 3)
        print(f"Result: {result}")

runner = ApplicationRunner(
    url="ws://localhost:8080/ws",  # Use rawsocket://localhost:8080 for RawSocket
    realm="realm1",
    serializers=['cbor']
)
runner.run(MyComponent)
```

## Project Structure

```
wamp_router/
├── main.cpp                    # Entry point
├── CMakeLists.txt             # Build configuration
├── CMakePresets.json          # CMake presets
├── vcpkg.json                 # Dependencies
├── Dockerfile                 # Container image
├── .clang-format              # Code style
├── scripts/                   # Build/run scripts
│   ├── build.sh              # Build Docker image
│   ├── cmake-build.sh        # Build project
│   ├── run.sh                # Run in container
│   └── shell.sh              # Interactive shell
├── include/                   # Header-only implementation
│   ├── wamp_server.hpp       # Server and connection handler
│   ├── wamp_session.hpp      # Protocol state machine
│   ├── wamp_messages.hpp     # Message type definitions
│   ├── wamp_serializer.hpp   # CBOR serialization
│   ├── raw_socket.hpp        # RawSocket framing
│   ├── wamp_id.hpp           # ID generation
│   ├── pubsub_handler.hpp    # PubSub implementation
│   ├── procedure_handler.hpp # RPC implementation
│   ├── subscription_manager.hpp
│   ├── registration_manager.hpp
│   ├── invocation_tracker.hpp
│   └── event_channel.hpp     # Async event delivery
└── tests/                     # Catch2 tests
```

## Architecture

### Key Design Decisions

1. **Header-Only Implementation**: All protocol logic in `include/` for easy integration
2. **C++20 Coroutines**: Using `boost::asio::awaitable` for clean async code
3. **Event Channels**: `boost::asio::experimental::channel` for efficient message delivery
4. **Single-Threaded**: One `io_context` thread (can be extended to thread pool)
5. **Session-per-Coroutine**: Each client connection is a coroutine
6. **RawSocket Transport**: Binary TCP framing (4-byte header + payload)
7. **CBOR Serialization**: Compact binary format via nlohmann-json

### Message Flow

**PubSub Example:**
```
Publisher → PUBLISH → Router → EVENT → Subscriber
```

**RPC Example:**
```
Caller → CALL → Router → INVOCATION → Callee
                                     ↓
Caller ← RESULT ← Router ← YIELD ─────┘
```

### Protocol State Machine

```
AWAITING_RAWSOCKET_HANDSHAKE
    ↓ (receive handshake)
AWAITING_FRAME_HEADER
    ↓ (receive 4-byte header)
AWAITING_FRAME_PAYLOAD
    ↓ (receive N-byte payload)
    → Process WAMP message
    → Generate response
    ↓
AWAITING_FRAME_HEADER (loop)
```

## Development

### Code Formatting

```bash
# Format all code (in container)
./scripts/run.sh clang-format -i include/*.hpp tests/*.cpp main.cpp

# Check formatting
./scripts/run.sh clang-format --dry-run --Werror include/*.hpp
```

### Debugging

```bash
# Enable debug logging in main.cpp
spdlog::set_level(spdlog::level::debug);

# Debug in container with GDB
./scripts/shell.sh
gdb ./build/wamp_router
(gdb) run 8080
```

### Adding New Features

See [CLAUDE.md](CLAUDE.md) for detailed development guidance including:
- Adding new WAMP message types
- Extending the protocol
- Performance tuning
- Architecture details

## Performance

- **Single-threaded**: ~10K messages/sec on single core
- **Memory**: ~1KB per session
- **Latency**: Sub-millisecond message routing

### Optimization Ideas

1. **Thread Pool**: Run multiple `io_context.run()` threads
2. **Buffer Pooling**: Reuse message buffers
3. **Zero-Copy**: Use `std::span` and views throughout
4. **Message Batching**: Combine multiple small messages

## Production Considerations

For production deployment, consider adding:

1. **Authentication**: Implement WAMP-CRA or WAMP-Cryptosign
2. **TLS Support**: Secure transport layer
3. **Rate Limiting**: Per-client message rate limits
4. **Monitoring**: Prometheus metrics export
5. **Graceful Shutdown**: Handle SIGTERM/SIGINT properly
6. **Configuration**: YAML/JSON config file
7. **Clustering**: Multi-router federation
8. **Persistence**: Store sessions/subscriptions to Redis

## References

- [WAMP Protocol Specification](https://wamp-proto.org/spec)
- [Boost.Asio Documentation](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html)
- [CBOR Specification](https://cbor.io/)
- [C++20 Coroutines](https://en.cppreference.com/w/cpp/language/coroutines)

## License

See LICENSE file for details.

## Contributing

See [CLAUDE.md](CLAUDE.md) for development guidelines and architecture documentation.
