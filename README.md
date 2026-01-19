# WAMP Router

A header only C++23 implementation of a [WAMP](https://wamp-proto.org/) (Web Application Messaging Protocol) router using RawSocket transport with CBOR serialization.

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
- **TLS 1.3 Support**: Encrypted transport with optional client certificates
- **WAMP-Cryptosign Authentication**: Ed25519 signature-based authentication
- **C++20 Coroutines**: Asynchronous I/O using `boost::asio::awaitable`
- **Event Channels**: Efficient message delivery using Boost.Asio experimental channels
- **Session Management**: Automatic cleanup on disconnect
- **Modern C++23**: Uses `std::expected`, `std::span`, ranges, etc.

## Dependencies

- **Boost.Asio**: Asynchronous networking and coroutines
- **OpenSSL**: TLS 1.3 support and Ed25519 cryptography
- **nlohmann-json**: CBOR serialization
- **fmt**: String formatting
- **spdlog**: Structured logging
- **toml11**: TOML configuration parsing
- **Catch2**: Unit testing framework

## Configuration

The router requires a TOML configuration file specifying TLS certificates and authentication keys.

### Generate Test Certificates

```bash
# Generate self-signed certificates for testing
./scripts/gen-test-certs.sh
```

This creates `test_certs/server.crt`, `test_certs/server.key`, and `test_certs/ca.crt`.

### Create config.toml

```toml
[server]
port = 8080

[server.tls]
cert = "test_certs/server.crt"
key = "test_certs/server.key"
# ca = "test_certs/ca.crt"  # Optional: for client certificate verification
# require_client_cert = false  # Optional: require client certificates

[server.rpc]
max_pending_invocations = 10000

[logging]
level = "info"  # trace, debug, info, warn, error, critical

# Optional: WAMP-Cryptosign authentication keys (Ed25519 public keys)
# If omitted, authentication is disabled and sessions are established without challenge
[auth.keys]
# "user1" = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
# "admin" = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
```

## Quick Start

### Docker Build (Recommended)

```bash
# 1. Build the Docker image (one-time setup)
./scripts/build.sh

# 2. Generate test certificates
./scripts/gen-test-certs.sh

# 3. Create config.toml (see Configuration section above)

# 4. Build the router
./scripts/cmake-build.sh

# 5. Run tests
./scripts/run.sh ./build/wamp_tests

# 6. Run the router with configuration
./scripts/run.sh -p 8080:8080 ./build/wamp_router --config config.toml
```

### Local Build

Requires: Clang 18+ or GCC 14+ with C++23 support, CMake 3.25+, Ninja, vcpkg

```bash
# 1. Set VCPKG_ROOT environment variable
export VCPKG_ROOT=/path/to/vcpkg

# 2. Generate test certificates
./scripts/gen-test-certs.sh

# 3. Create config.toml (see Configuration section above)

# 4. Configure and build
cmake --preset local-release
cmake --build build-local

# 5. Run tests
./build-local/wamp_tests

# 6. Run the router with configuration
./build-local/wamp_router --config config.toml
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
# Run with default config.toml
./scripts/run.sh -p 8080:8080 ./build/wamp_router

# Run with custom configuration
./scripts/run.sh -p 8080:8080 ./build/wamp_router --config /path/to/config.toml

# Show help
./scripts/run.sh ./build/wamp_router --help

# Interactive shell
./scripts/shell.sh
```

### Local

```bash
# Run with default config.toml
./build-local/wamp_router

# Run with custom configuration
./build-local/wamp_router --config /path/to/config.toml

# Show help
./build-local/wamp_router --help
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

## Connecting Clients

The router uses WAMP RawSocket transport with CBOR serialization over TLS 1.3:

- **Protocol**: WAMP v2
- **Transport**: RawSocket over TLS 1.3 (TCP)
- **Serializer**: CBOR (not JSON)
- **Default Port**: Configured in config.toml (typically 8080)
- **Authentication**: WAMP-Cryptosign with Ed25519 signatures (optional)

### Authentication

If `[auth.keys]` is configured in config.toml, clients must authenticate using WAMP-Cryptosign:

1. Client sends HELLO with `authid` and `authmethods=["cryptosign"]`
2. Router responds with CHALLENGE containing a random nonce
3. Client signs `challenge|session_id|authid|authrole` with Ed25519 private key
4. Client sends AUTHENTICATE with the signature
5. Router verifies signature against public key from config
6. If valid, router sends WELCOME and session is established

If `[auth.keys]` is empty or omitted, authentication is disabled and sessions are established immediately after HELLO.

### Example: Python Client (with authentication)

```python
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

class MyComponent(ApplicationSession):
    def __init__(self, config):
        super().__init__(config)
        # Load Ed25519 private key
        self.signing_key = SigningKey(
            b'your_32_byte_private_key_here',  # 32 bytes
            encoder=HexEncoder
        )

    def onChallenge(self, challenge):
        if challenge.method == "cryptosign":
            # Sign: challenge|session_id|authid|authrole
            challenge_hex = challenge.extra["challenge"]
            message = f"{challenge_hex}|0|user1|user"
            signature = self.signing_key.sign(message.encode()).signature
            return signature.hex()

    async def onJoin(self, details):
        print(f"Authenticated as: {details.authid}")

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
    url="rawsocket://localhost:8080",  # RawSocket over TLS
    realm="com.example.realm",
    serializers=['cbor'],
    authentication={
        'cryptosign': {
            'authid': 'user1'
        }
    }
)
runner.run(MyComponent)
```

## Architecture

### Key Design Decisions

1. **Header-Only Implementation**: All protocol logic in `include/` for easy integration
2. **TLS 1.3**: Encrypted transport using OpenSSL with optional mutual TLS
3. **WAMP-Cryptosign**: Ed25519 signature-based authentication (optional)
4. **C++20 Coroutines**: Using `boost::asio::awaitable` for clean async code
5. **Event Channels**: `boost::asio::experimental::channel` for efficient message delivery
6. **Single-Threaded**: One `io_context` thread (can be extended to thread pool)
7. **Session-per-Coroutine**: Each client connection is a coroutine
8. **RawSocket Transport**: Binary TCP framing (4-byte header + payload)
9. **CBOR Serialization**: Compact binary format via nlohmann-json

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
    ↓ (receive HELLO)
    → Check authentication required?
    ├─ Yes: Send CHALLENGE
    │   ↓
    │   AWAITING_AUTHENTICATE
    │   ↓ (receive AUTHENTICATE)
    │   → Verify signature
    │   → Send WELCOME if valid, ABORT if invalid
    │   ↓
    └─ No: Send WELCOME immediately
    ↓
AWAITING_FRAME_HEADER (session established)
    ↓ (receive 4-byte header)
AWAITING_FRAME_PAYLOAD
    ↓ (receive N-byte payload)
    → Process WAMP message (SUBSCRIBE, PUBLISH, CALL, etc.)
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

## References

- [WAMP Protocol Specification](https://wamp-proto.org/spec)
- [Boost.Asio Documentation](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html)
- [CBOR Specification](https://cbor.io/)
- [C++20 Coroutines](https://en.cppreference.com/w/cpp/language/coroutines)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

SPDX-License-Identifier: Apache-2.0

## Contributing

See [CLAUDE.md](CLAUDE.md) for development guidelines and architecture documentation.
