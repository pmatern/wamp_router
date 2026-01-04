# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a C++23 WAMP (Web Application Messaging Protocol) router implementation using RawSocket transport with CBOR serialization. The project runs inside a Docker container (`cpp23-builder`) that provides Clang 18+, CMake, Ninja, and vcpkg for dependency management.

**Key Architecture**: Single-threaded asynchronous I/O using C++20 coroutines with Boost.Asio. The router implements the WAMP protocol's core features: RPC (CALL/REGISTER/YIELD) and PubSub (PUBLISH/SUBSCRIBE/EVENT). The architecture uses `awaitable` coroutines and concurrent operations via `parallel_group` for handling both socket I/O and event channel notifications.

## Build Environment

This project is self-contained and supports two build environments:

**Development Workflow:** Use **local builds** for task-by-task development. Docker container builds can be used periodically to test that everything works in the standardized environment.

### 1. Local Build (Recommended for Development)
Requires local installation of:
- Clang 18+ or compatible C++23 compiler
- CMake 3.25+
- Ninja
- vcpkg (with `VCPKG_ROOT` environment variable set)

**Local build commands:**
```bash
# Configure using CMake presets
cmake --preset local-debug    # or local-release

# Build (with parallel compilation)
cmake --build build-local --parallel 8

# Run
./build-local/wamp_router
./build-local/wamp_tests

# Run specific tests
./build-local/wamp_tests "[test name]"
```

### 2. Docker Container Build (For CI/Testing)
Uses a custom Docker image with Clang 18 and libc++ for full C++23 support. Both GCC 14 and Clang 18 are available in the container.

**First-time setup:**
```bash
# Build the Docker image (one-time, or when Dockerfile changes)
./scripts/build.sh
```

**Compiler:** Clang 18 with libc++ (default)
- Full C++23 support: `std::expected`, coroutines, `std::span`, ranges, etc.
- Excellent diagnostics and modern standard library
- vcpkg dependencies automatically built with libc++
- GCC 14 also available if needed

**Docker build commands:** Use `./scripts/cmake-build.sh` and `./scripts/run.sh`

### Configuration Files
- **.version**: Docker image version (used by `./scripts/build.sh`)
- **CMakePresets.json**: CMake presets for different build configurations:
  - `local-debug` / `local-release`: Local builds with system vcpkg
  - `container`: Container build with Clang 18 + libc++ (default)
  - `system-packages`: Local build without vcpkg
- **.clang-format**: Code formatting rules (C++23 LLVM style)
- **.dockerignore**: Files excluded from Docker build context
- **config/**: Shared configuration templates
  - **clang-format**: Template for .clang-format (copy to project root)
  - **vcpkg-baseline.json**: Pins vcpkg version (2024.11.16) for reproducibility

## Build Commands (Docker)

**Note:** Commands below use Docker scripts. For local builds, use CMake directly with presets.

### Standard Build
```bash
# Configure and build (Release mode by default)
./scripts/cmake-build.sh

# Debug build
./scripts/cmake-build.sh --build-type Debug

# Clean build
./scripts/cmake-build.sh --clean

# Build with parallel jobs
./scripts/cmake-build.sh -j 8
```

### Running Tests
```bash
# Build and run all tests
./scripts/cmake-build.sh
./scripts/run.sh ./build/wamp_tests

# Run specific test
./scripts/run.sh ./build/wamp_tests "test case name"
```

### Running the Router

**IMPORTANT**: The router now requires TLS 1.3 and a configuration file.

#### Quick Start (Development)
```bash
# 1. Generate test certificates (one-time)
./scripts/gen-test-certs.sh

# 2. Run with test configuration
./scripts/run.sh -p 8080:8080 ./build/wamp_router --config test_config.toml

# Local build:
./build-local/wamp_router --config test_config.toml
```

#### Configuration

The router requires a TOML configuration file (default: `config.toml`).

**Example configuration:**
```toml
[server]
port = 8080

[server.tls]
cert = "test_certs/cert.pem"
key = "test_certs/key.pem"
# Optional: ca = "ca.pem"
# Optional: require_client_cert = false

[server.rpc]
max_pending_invocations = 10000

[logging]
level = "info"  # trace, debug, info, warn, error, critical
```

**Command-line options:**
```bash
# Use default config.toml
./build-local/wamp_router

# Use custom config file
./build-local/wamp_router --config /path/to/config.toml

# Show help
./build-local/wamp_router --help
```

#### TLS Certificate Setup

**Development (self-signed certificates):**
```bash
# Generate test certificates
./scripts/gen-test-certs.sh

# Output: test_certs/cert.pem and test_certs/key.pem
```

**Production (real certificates):**
- Use certificates from Let's Encrypt, your CA, or certificate provider
- Update config.toml with paths to your certificate and private key
- Ensure files are readable by the router process

**Testing TLS connection:**
```bash
# Verify TLS 1.3 with openssl s_client
openssl s_client -connect localhost:8080 -tls1_3

# Expected output should show: Protocol: TLSv1.3
```

#### Authentication Setup (Optional)

The router supports WAMP-Cryptosign authentication with Ed25519 signatures. Authentication is **optional** - if no authentication keys are configured, the router allows unauthenticated connections (legacy behavior).

**Key Generation:**
```bash
# Generate Ed25519 key pair for testing
./scripts/gen-test-keypair.sh

# This creates:
#   test_auth/private.pem  (keep secret - client uses this)
#   test_auth/public.pem   (extract hex for config.toml)
```

**Configuration:**
Add authentication keys to config.toml:
```toml
[auth.keys]
# Map authid → Ed25519 public key (hex-encoded, 64 chars = 32 bytes)
"user1" = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
"admin" = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
```

**Authentication Protocol Flow:**
1. Client sends `HELLO` with `authid="user1"` and `authmethods=["cryptosign"]`
2. Router sends `CHALLENGE` with random 32-byte nonce (hex-encoded)
3. Client signs: `challenge_hex + "|0|" + authid + "|user"` with private key
4. Client sends `AUTHENTICATE` with Ed25519 signature (hex-encoded)
5. Router verifies signature with public key from config
   - Success: Sends `WELCOME` with authid, authrole, authmethod
   - Failure: Sends `ABORT` with `wamp.error.not_authorized`

**Security Notes:**
- Public keys are stored in config.toml (not secret)
- Private keys never touch the server (client-side only)
- Challenge is cryptographically random (32 bytes from OpenSSL RAND_bytes)
- Signature verification uses constant-time comparison (EVP_DigestVerify)

**Disabling Authentication:**
Simply omit the `[auth.keys]` section from config.toml, or leave it empty. The router will accept all connections without authentication.

### Development Workflow
```bash
# Enter container shell for interactive development
./scripts/shell.sh

# Inside container, you can run:
cmake --build build
./build/wamp_router
./build/wamp_tests
clang++ --version
vcpkg search [package]
```

## Project Structure

```
wamp_router/
├── main.cpp                    # Entry point, loads config, starts WampTlsServer
├── config.toml                # Example configuration file
├── test_config.toml           # Development configuration with test certificates
├── CMakeLists.txt             # Build config (C++23, Catch2 tests)
├── CMakePresets.json          # CMake presets for local and container builds
├── vcpkg.json                 # Dependencies manifest
├── .version                   # Docker image version
├── Dockerfile                 # Build container definition
├── .clang-format              # Code formatting configuration
├── .dockerignore              # Docker build context exclusions
├── config/                    # Configuration templates
│   ├── clang-format          # Clang-format template
│   └── vcpkg-baseline.json   # vcpkg version pinning
├── scripts/                   # Docker wrapper scripts and utilities
│   ├── build.sh              # Build Docker image
│   ├── cmake-build.sh        # Configure and build project
│   ├── run.sh                # Run commands in container
│   ├── shell.sh              # Interactive container shell
│   ├── debug.sh              # Debug with GDB in container
│   ├── ci-build.sh           # CI/CD build script
│   ├── gen-test-certs.sh     # Generate self-signed TLS certificates for testing
│   └── gen-test-keypair.sh   # Generate Ed25519 key pair for authentication
├── test_certs/                # Generated test certificates (not in git)
│   ├── cert.pem              # Self-signed certificate
│   └── key.pem               # Private key
├── test_auth/                 # Generated authentication keys (not in git)
│   ├── private.pem           # Ed25519 private key (client-side)
│   └── public.pem            # Ed25519 public key
├── include/                   # Header-only implementation
│   ├── config.hpp            # TOML configuration loader with auth keys support
│   ├── crypto_utils.hpp      # Ed25519 signature verification, challenge generation
│   ├── wamp_server.hpp       # WampServer (plain TCP for tests), WampTlsServer (TLS 1.3)
│   ├── wamp_session.hpp      # Protocol state machine, buffering, authentication
│   ├── wamp_messages.hpp     # WAMP message types (HELLO, CHALLENGE, AUTHENTICATE, etc.)
│   ├── wamp_serializer.hpp   # CBOR serialization/deserialization
│   ├── raw_socket.hpp        # RawSocket framing (4-byte header)
│   ├── wamp_id.hpp           # ID generators (global, router-scoped)
│   ├── pubsub_handler.hpp    # SUBSCRIBE/PUBLISH/EVENT handling
│   ├── procedure_handler.hpp # REGISTER/CALL/YIELD handling
│   ├── subscription_manager.hpp  # Topic subscription tracking
│   ├── registration_manager.hpp  # Procedure registration tracking
│   ├── invocation_tracker.hpp    # Pending RPC call tracking
│   └── event_channel.hpp     # Asio channel for event delivery
└── tests/                     # Catch2 unit and integration tests
    ├── test_wamp_id.cpp
    ├── test_raw_socket.cpp
    ├── test_wamp_serializer.cpp
    ├── test_subscription_manager.cpp
    ├── test_wamp_session.cpp
    ├── test_procedure_handler.cpp
    └── test_integration.cpp
```

## Code Architecture

### WAMP Protocol Overview
WAMP is a routed protocol providing RPC and PubSub patterns. This router acts as the central message broker:
- **RPC**: Callers invoke procedures on callees via CALL → router → INVOCATION → callee → YIELD → router → RESULT
- **PubSub**: Publishers send events to subscribers via PUBLISH → router → EVENT → subscribers

### Core Components

#### Configuration (config.hpp)
- **Config::load()**: Loads and validates TOML configuration from file
- **ServerConfig**: Holds port, TLS paths, RPC limits, logging level
- **TlsConfig**: Certificate paths, CA path, client cert requirements
- Validates certificate files exist at startup (fail-fast on misconfiguration)
- Uses `std::expected` for error handling with detailed error codes

#### WampTlsServer (wamp_server.hpp)
- **Production TLS server** - Only accepts TLS 1.3 connections
- Owns `ssl::context` configured for TLS 1.3 only (rejects TLS ≤ 1.2)
- Loads certificates from TlsConfig (cert.pem, key.pem)
- `setup_ssl_context()`: Configures TLS 1.3, cipher suites, client cert requirements
- `accept_loop()`: Accepts connections, wraps in `ssl::stream<tcp::socket>`, spawns `handle_wamp_session`
- TLS handshake occurs in `handle_wamp_session` before WAMP protocol handshake

#### WampServer (wamp_server.hpp)
- **Plain TCP server** - Used for testing only (not in production)
- Owns the `tcp::acceptor` and spawns coroutines for each accepted connection
- `accept_loop()`: Infinite coroutine accepting connections, spawning `handle_wamp_session` for each
- Uses `co_spawn` to launch detached coroutines

#### handle_wamp_session() (wamp_server.hpp)
- **Templated function** - Works with both `tcp::socket` (tests) and `ssl::stream<tcp::socket>` (production)
- Coroutine managing a single client connection's lifetime
- For TLS sockets: Performs `async_handshake` before entering main loop
- Uses `parallel_group` with `wait_for_one()` to concurrently wait on:
  - Socket reads (client → router messages)
  - Event channel receives (router → client events/invocations)
- Continues until EOF or error, then calls `protocol.on_disconnect()` for cleanup
- Socket abstraction via template enables zero-overhead polymorphism

#### WampSession (wamp_session.hpp)
- Protocol state machine with buffering: `AWAITING_RAWSOCKET_HANDSHAKE` → `AWAITING_FRAME_HEADER` → `AWAITING_FRAME_PAYLOAD`
- `process()`: Receives data, appends to buffer, processes complete frames
- State transitions occur as data arrives, extracting complete WAMP messages for handling
- Calls into PubSubHandler and ProcedureHandler for message dispatch
- Manages session ID (generated on HELLO, sent in WELCOME)

#### PubSubHandler (pubsub_handler.hpp)
- Handles SUBSCRIBE/PUBLISH messages
- Maintains global SubscriptionManager (topic → subscription_id → session_id mappings)
- On PUBLISH: looks up subscribers, sends EVENT messages via EventChannel to each subscriber's session

#### ProcedureHandler (procedure_handler.hpp)
- Handles REGISTER/CALL/YIELD messages
- Maintains global RegistrationManager (procedure URI → registration_id → session_id)
- Maintains global InvocationTracker (pending CALLs awaiting YIELD responses)
- On CALL: finds callee, generates invocation_id, sends INVOCATION via EventChannel to callee
- On YIELD: finds pending call, sends RESULT via EventChannel to caller

#### EventChannel (event_channel.hpp)
- Wraps `boost::asio::experimental::channel<void(boost::system::error_code, Event)>`
- Registry maintains one channel per session_id
- Used to push EVENT and INVOCATION/RESULT messages to sessions asynchronously
- Channel receives are co_awaited in `handle_wamp_session`'s parallel_group

#### RawSocket Framing (raw_socket.hpp)
- 4-byte header: `[0:3] = length (24-bit big-endian)`, `[3] = flags (reserved, must be 0)`
- `parse_header()`: Extracts message length from 4-byte header
- `create_wamp_message()`: Wraps CBOR payload in RawSocket frame

#### WAMP Serialization (wamp_serializer.hpp)
- CBOR encoding/decoding for WAMP messages
- Message format: `[message_type, ...fields]` (array with type code as first element)
- Deserialize functions parse CBOR arrays into C++ structs
- Serialize functions convert C++ structs to CBOR arrays

#### ID Generators (wamp_id.hpp)
- **GlobalIdGenerator**: Generates IDs in global scope (publication_id)
- **RouterScopeIdGenerator**: Generates IDs in router scope (subscription_id, registration_id)
- **SessionScopeIdGenerator**: Generates IDs per-session (request_id) - currently unused (clients generate request_ids)

### Async I/O Pattern: C++20 Coroutines
- All I/O operations use `boost::asio::awaitable<T>` coroutines
- `co_await` suspends until async operation completes, resuming with result
- `as_tuple(use_awaitable)` returns `[error_code, result]` tuple instead of throwing
- `parallel_group` enables concurrent waiting on multiple async operations
- `co_spawn(..., detached)` launches coroutines without blocking

### Lifetime Management
- Sessions are stack-allocated coroutines (not heap via `shared_from_this`)
- Coroutine lifetime = connection lifetime
- EventChannel registry uses `weak_ptr` to avoid keeping dead channels
- On disconnect, all subscriptions/registrations for session_id are removed

### Message Flow Examples

#### SUBSCRIBE Flow
1. Client sends HELLO → router assigns session_id, sends WELCOME
2. Client sends SUBSCRIBE → `WampSession::process()` → `PubSubHandler::handle_subscribe()`
3. SubscriptionManager creates subscription (topic → subscription_id → session_id)
4. Router sends SUBSCRIBED response with subscription_id

#### PUBLISH Flow
1. Client sends PUBLISH → `PubSubHandler::handle_publish()`
2. Look up all subscribers for topic from SubscriptionManager
3. For each subscriber session_id, create EVENT message
4. Send EVENT via EventChannel to subscriber's session
5. `handle_wamp_session`'s parallel_group receives event from channel, writes to socket

#### RPC Flow
1. Callee sends REGISTER → `ProcedureHandler::handle_register()` → stores in RegistrationManager
2. Caller sends CALL → `ProcedureHandler::handle_call()`
3. Look up callee session_id, generate invocation_id, store in InvocationTracker
4. Send INVOCATION via EventChannel to callee
5. Callee sends YIELD → `ProcedureHandler::handle_yield()`
6. Look up pending call in InvocationTracker, send RESULT via EventChannel to caller

### Dependencies
- **Boost.Asio**: Asynchronous networking, coroutines (`io_context`, `tcp::acceptor`, `awaitable`, `experimental::channel`)
- **Boost.Asio.SSL**: TLS 1.3 support (`ssl::context`, `ssl::stream<tcp::socket>`)
- **OpenSSL**: TLS implementation (required by Boost.Asio.SSL)
- **toml11**: TOML configuration file parsing
- **fmt**: String formatting
- **spdlog**: Structured logging
- **nlohmann-json**: Used only for CBOR serialization (nlohmann-json's CBOR support)
- **Catch2**: Unit testing framework

### Important Build Details
- **Toolchain**: vcpkg toolchain at `/opt/vcpkg/scripts/buildsystems/vcpkg.cmake`
- **Compiler**: Clang 18 with libc++ (container default)
  - Full C++23 support: `std::expected`, coroutines, `std::span`, ranges, etc.
  - Uses `-stdlib=libc++` and `-lc++abi` for LLVM standard library
  - vcpkg dependencies automatically built with libc++
  - GCC 14 also available in container for alternative builds
- **Local builds**: Any C++23-compliant compiler (Clang 16+, GCC 13+)
- **Warnings**: `-Wall -Wextra -Wpedantic` enabled
- **Optimization**: `-O3` for Release builds
- **Tests**: Integrated with CTest via `catch_discover_tests()`

## Common Development Patterns

### Adding New WAMP Message Types
1. Add message type enum to `MessageType` in wamp_messages.hpp
2. Create message struct in wamp_messages.hpp
3. Add serialize function in wamp_serializer.hpp
4. Add deserialize function in wamp_serializer.hpp
5. Add handler in WampSession::handle_message()
6. Write unit tests in tests/

### Adding New Dependencies
1. Add to `vcpkg.json` dependencies array
2. Add `find_package()` in CMakeLists.txt
3. Add to `target_link_libraries()` for both `wamp_router` and `wamp_tests`
4. Rebuild: `./scripts/cmake-build.sh --clean`

### Debugging
```bash
# Enable debug logging: modify main.cpp:8
spdlog::set_level(spdlog::level::debug);

# Use GDB in container:
./scripts/shell.sh
gdb ./build/wamp_router
(gdb) run
```

### Configuration
The router uses TOML configuration files (config.toml or test_config.toml) for all settings:
- Server port, TLS certificate paths, logging level
- `max_pending_invocations` - limits pending RPC calls (set via `ProcedureHandler::set_max_pending_invocations()`)
- Optional authentication keys for WAMP-Cryptosign

### Performance Considerations
- **Single-threaded**: Currently runs on single io_context thread. For multi-threading, create thread pool calling `io_context.run()`
- **Buffer sizes**: 8KB buffers in handle_wamp_session. Adjust for large payloads
- **Event channels**: One channel per session. Channel capacity defaults to 0 (unlimited queue)
- **ID generation**: Atomic counters, lock-free

## Testing

Tests use Catch2 framework with CTest integration:
- **test_wamp_id.cpp**: ID generator behavior
- **test_raw_socket.cpp**: Frame parsing/creation
- **test_wamp_serializer.cpp**: CBOR message serialization
- **test_subscription_manager.cpp**: Subscription tracking
- **test_wamp_session.cpp**: Protocol state machine
- **test_procedure_handler.cpp**: RPC message handling
- **test_integration.cpp**: End-to-end scenarios with mock sockets

Run specific test: `./scripts/run.sh ./build/wamp_tests "[test name]"`

## Important Constraints

- **Self-Contained Project**: This project is standalone with its own Dockerfile, scripts, and config files
- **Docker vs Local**:
  - Docker builds use `./scripts/` wrappers (recommended for consistency)
  - Local builds use CMake presets directly (requires local toolchain setup)
- **Port Mapping**: When using Docker, use `-p` flag with run.sh to expose container ports (e.g., `-p 8080:8080`)
- **vcpkg Manifest Mode**: Uses manifest mode (vcpkg.json), not classic mode
- **Coroutine Requirement**: C++20 coroutines required (Clang 18+ or compatible compiler)
- **Single-threaded**: io_context runs on main thread; handlers must not block
- **Build Directories**:
  - `build/`: Docker container builds (Clang 18 + libc++)
  - `build-local/`: Local machine builds (when using CMake presets directly)
  - `build-system/`: System packages without vcpkg (alternative local build)
- **C++23 Features**: Full support for `std::expected`, `std::span`, coroutines, ranges, etc.
- **Standard Library**: LLVM libc++ provides cutting-edge C++23 support
