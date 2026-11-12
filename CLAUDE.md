# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a C++23 WAMP (Web Application Messaging Protocol) router implementation speaking CBOR, JSON or MessagePack over RawSocket or WebSocket, all on one port. The project runs inside a Docker container (`cpp23-builder`) that provides Clang 18+, CMake, Ninja, and vcpkg for dependency management.

**Key Architecture**: Thread-per-core, shared-nothing asynchronous I/O (N shard threads, default 1, plus an acceptor thread; see `docs/architecture.md`) using C++20 coroutines with standalone Asio (no Boost). The router implements the WAMP protocol's core features: RPC (CALL/REGISTER/YIELD) and PubSub (PUBLISH/SUBSCRIBE/EVENT). The architecture uses `awaitable` coroutines and concurrent operations via `parallel_group` for handling both socket I/O and event channel notifications.

**Outstanding work:** see [TODO.md](TODO.md) for the prioritized task list. Update it as items are completed.

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
async = true       # a background thread writes the log; a slow sink never stalls a shard
queue_size = 8192  # buffered lines; the oldest is dropped when full
# file = "router.log"
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
3. Client signs the raw challenge bytes (the 32 bytes behind the hex string) with its private key; the 64-byte signature is returned hex-encoded (`signature||challenge`, 96 bytes, is also accepted)
4. Client sends `AUTHENTICATE` with Ed25519 signature (hex-encoded)
5. Router verifies signature with public key from config
   - Success: Sends `WELCOME` with authid, authrole, authmethod
   - Failure: Sends `ABORT` with `wamp.error.not_authorized`

**Realms:** `[auth.realms]` maps each authid to the realms it may join (HELLO for any other realm is aborted with `wamp.error.not_authorized`). Topics and procedures are isolated per realm (`Realm` in `include/realm.hpp`); `[auth.roles]` may give a role per realm.

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
├── docs/                      # architecture.md (threads, coordination), threading-analysis.md (profile, measurements)
├── bench/                     # wamp_bench, wamp_load, wamp_profile_router, wamp_handoff_bench, wamp_tls_probe
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
│   ├── authorizer.hpp        # Role permissions (Action, Permissions): exact/prefix URI rules
│   ├── cpu_limits.hpp        # Container-aware CPU budget (cgroup quota, affinity, ECS task metadata)
│   ├── router.hpp            # Router: N shards, one thread each, acceptor hands connections to the least-loaded shard
│   ├── logging.hpp           # Async logger (bounded queue, one writer thread), shard tag per line
│   ├── shard_group.hpp       # ShardGroup: cross-shard topic interest, procedure table, per-shard inboxes
│   ├── cross_shard.hpp       # Dispatch of inbox messages (events, forwarded calls, results) on the destination shard
│   ├── shard.hpp             # Shard: all routing state one thread owns (channels, pending calls, realms, ids)
│   ├── realm.hpp             # Realm (per-realm subscriptions + registrations), RealmRegistry
│   ├── crypto_utils.hpp      # Ed25519 signature verification, challenge generation
│   ├── wamp_server.hpp       # WampServer (plain TCP for tests), WampTlsServer (TLS 1.3)
│   ├── wamp_session.hpp      # Protocol state machine, buffering, authentication
│   ├── wamp_client.hpp       # Coroutine-based WAMP client implementation
│   ├── wamp_messages.hpp     # WAMP message types (HELLO, CHALLENGE, AUTHENTICATE, etc.)
│   ├── cbor.hpp              # Minimal CBOR reader/writer used by the hot-path serializers
│   ├── wamp_serializer.hpp   # CBOR serialization/deserialization
│   ├── raw_socket.hpp        # RawSocket framing (4-byte header)
│   ├── rate_limit.hpp         # TokenBucket, ConnectionRateLimiter (new connections per second per address)
│   ├── connection_limiter.hpp # ConnectionLimiter (total and per-address connection caps), open-file limit helpers
│   ├── ppt.hpp               # Payload passthru mode helpers (ppt_* extraction/validation, feature name)
│   ├── wire.hpp / msgpack.hpp # Wire enum and wirecodec dispatch; MessagePack <-> CBOR streaming transcoders (wamp.2.msgpack)
│   ├── json.hpp              # JSON <-> CBOR streaming transcoders for wamp.2.json (edge of a JSON session)
│   ├── base64.hpp / utf8.hpp # base64 (JSON binary strings, WebSocket accept key), UTF-8 validation
│   ├── websocket.hpp         # WebSocket (RFC 6455): upgrade parsing, frame parser, frame encoding (wamp.2.cbor only)
│   ├── wamp_id.hpp           # ID generators (global, router-scoped)
│   ├── pubsub_handler.hpp    # SUBSCRIBE/PUBLISH/EVENT handling
│   ├── procedure_handler.hpp # REGISTER/CALL/YIELD handling
│   ├── uri_match.hpp         # Match (exact/prefix/wildcard), pattern matching and precedence helpers
│   ├── subscription_manager.hpp  # Topic subscription tracking (exact, prefix, wildcard)
│   ├── registration_manager.hpp  # Procedure registration tracking (exact, prefix, wildcard; best match wins)
│   ├── invocation_tracker.hpp    # Pending RPC call tracking
│   └── event_channel.hpp     # Asio channel for event delivery
└── tests/                     # Catch2 unit and integration tests
    ├── test_wamp_id.cpp
    ├── test_raw_socket.cpp
    ├── test_wamp_serializer.cpp
    ├── test_subscription_manager.cpp
    ├── test_wamp_session.cpp
    ├── test_procedure_handler.cpp
    ├── test_config.cpp
    ├── test_wamp_client.cpp
    ├── test_integration.cpp
    ├── test_protocol_gaps.cpp
    ├── test_event_queue.cpp
    ├── test_authorization.cpp
    ├── test_router.cpp
    ├── test_websocket.cpp
    ├── test_json.cpp
    ├── test_msgpack.cpp
    ├── test_ppt.cpp
    ├── test_rate_limit.cpp
    ├── test_patterns.cpp
    ├── test_logging.cpp
    ├── test_cpu_limits.cpp
    ├── test_cbor.cpp
    ├── test_realms.cpp
    └── test_crypto_utils.cpp
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

#### WampClient (wamp_client.hpp)
- **Coroutine-based WAMP client** - C++ client for connecting to WAMP routers
- Handles RawSocket handshake, HELLO/WELCOME exchange
- Supports SUBSCRIBE/PUBLISH for PubSub and REGISTER/CALL for RPC
- Uses `EventCallback` and `InvocationHandler` function types for async notifications
- Manages pending calls via internal tracking with request IDs

#### handle_wamp_session() (wamp_server.hpp)
- **Templated function** - Works with both `tcp::socket` (tests) and `ssl::stream<tcp::socket>` (production)
- Coroutine managing a single client connection's lifetime
- For TLS sockets: Performs `async_handshake` before entering main loop
- Before the WAMP session is established: a plain read loop. After: a reader coroutine (socket reads, direct responses) and a writer coroutine (drains the event channel, coalesces queued frames into one gathered write) run under a `parallel_group` with `wait_for_one()`; a `WriteLock` serializes their socket writes
- Continues until EOF or error, then calls `protocol.on_disconnect()` for cleanup
- Socket abstraction via template enables zero-overhead polymorphism

#### WampSession (wamp_session.hpp)
- Protocol state machine with buffering: `AWAITING_RAWSOCKET_HANDSHAKE` → `AWAITING_FRAME_HEADER` → `AWAITING_FRAME_PAYLOAD`
- `process()`: Receives data, appends to buffer, processes complete frames
- State transitions occur as data arrives, extracting complete WAMP messages for handling
- Calls into PubSubHandler and ProcedureHandler for message dispatch
- Manages session ID (generated on HELLO, sent in WELCOME)

#### WebSocket (websocket.hpp, wamp_session.hpp)
- `WampSession` decides the transport from the first byte: `0x7F` = RawSocket handshake, `G` (and `[server.websocket] enabled`) = HTTP upgrade. After the upgrade `process_websocket()` parses frames with `ws::FrameParser` and hands each complete binary message to the same `handle_wamp_message` RawSocket uses.
- All code that builds outgoing messages still produces RawSocket frames (4-byte header + CBOR payload), which are shared between sessions and shards. A WebSocket session converts at the edge: `ws_wrap` for direct responses, and `session_writer` (wamp_server.hpp) gathers a small WebSocket header plus the shared payload (offset 4) for queued events, with no copy.
- `WampSession::should_close()` tells `handle_socket_read_completion` to close after the pending output (an HTTP error or a WebSocket close frame) is written.
- `wamp.2.cbor` and `wamp.2.msgpack` (binary frames) and `wamp.2.json` (text frames); `Wire` in `WampSession` records it; the choice is made at the upgrade (`ws::parse_upgrade` picks the client's first enabled subprotocol).

#### JSON and MessagePack (json.hpp, msgpack.hpp, wire.hpp)
- `Wire { CBOR, JSON, MSGPACK }` is chosen per session (`ws::parse_upgrade` subprotocol or the RawSocket serializer); `wirecodec::to_cbor/from_cbor` dispatch to `jsoncodec` or `msgpackcodec`, and everything below applies to MessagePack in the same way as to JSON (binary frames instead of text, `bin` instead of base64).

#### JSON (json.hpp)
- The router core always works on CBOR. A JSON session converts at its edge: `core_payload()` (JSON text to CBOR on input), `to_wire()` / `ws_wrap()` (CBOR replies to JSON), and `session_writer` (queued shared frames to JSON text, per recipient). `jsoncodec::to_cbor` writes indefinite-length containers, which the CBOR reader accepts.
- The value model (`WampValue` in `wamp_messages.hpp`) is lossless: null, bool, int64, double, string, bytes, list, dict, nested without limit except the 64-level depth cap.

#### Pattern-based subscriptions and registrations
- `SUBSCRIBE`/`REGISTER` `match` option (`exact`, `prefix`, `wildcard`) is parsed in `WampSession::pattern_match` (invalid values and patterns get an ERROR, `Permissions::allows_pattern` authorizes). `SubscriptionManager::for_each_subscriber` reports each match's `Match`; pattern matches get an EVENT with `details.topic` (`handle_publish` builds that template on demand, `CrossPublish::pattern_event` carries it). `RegistrationManager::find_callee` returns the best registration (`uri::more_specific`); `ProcedureHandler::handle_call` compares it with `ShardGroup::find_registration` (best remote). `ShardGroup` keeps pattern interest/registration lists next to the exact tables.

#### Progressive call results
- `receive_progress` (CALL option) is offered to a callee in `Shard::progress_sessions` (INVOCATION details); a YIELD with `progress: true` goes through `InvocationTracker::peek_and_refresh` (keeps the `PendingCall`, pushes its deadline out by its timeout) and is forwarded as a RESULT with `details.progress`; any other YIELD or an ERROR ends the call as before. Client: `call_progressive`, `register_streaming_procedure` / `ProgressSender`.

#### Call canceling
- `CANCEL` (caller) is handled by `ProcedureHandler::handle_cancel`: it finds the call through `InvocationTracker::find_by_call` (index by caller session + request id) and applies `skip`, `killnowait` or `kill`; for a callee on another shard it sends `CrossCancelCall` to the other shards, and the one holding the call answers the caller with a `CrossFrame`. The dealer announces `call_canceling`.

#### Payload passthru (ppt.hpp)
- `ppt_*` PUBLISH/CALL options and a single binary argument are validated (`ppt::valid`) and forwarded as EVENT/INVOCATION/RESULT details; YIELD options are kept for this. A session announces `payload_passthru_mode` in its HELLO role features (`WampSession::ppt_`, registered in `Shard::ppt_sessions`); the router announces it in WELCOME. Subscribers/callees without it are skipped / refused (`wamp.error.feature_not_supported`). `[roles.<name>] ppt_schemes` restricts schemes (`Permissions::allows_ppt_scheme`).

#### Router (router.hpp)
- `Router(config, Transport::PLAIN|TLS, threads)` starts one acceptor thread and N worker threads, each with its own `io_context(1)` and `Shard`. The acceptor passes each accepted socket (as a native handle) to the shard with the fewest sessions; the TLS handshake and the whole session then run on that shard's thread. `main.cpp` uses it (`[server] threads`, default 1).
- **Cross-shard:** `ShardGroup` (`shard_group.hpp`) connects the shards. Pub/sub: replicated topic interest plus one inbox per shard. RPC: a replicated procedure table (one registration per procedure across all shards); a CALL for a remote callee is forwarded to that shard, which owns the pending call and sends the RESULT/ERROR back. Publishers and callers are slowed (`wait_for_room`) when a destination inbox backs up. `include/cross_shard.hpp` dispatches inbox messages.

#### Shard (shard.hpp)
- Owns everything a router thread mutates: `EventChannelRegistry channels`, `InvocationTracker invocations`, `RealmRegistry realms`, the id generators and the default call timeout. There are no process-wide mutable statics.
- One `Shard` per server (`WampServer::shard()`); sessions, handlers and the call sweeper receive it by reference, and each session coroutine also holds a `shared_ptr<Shard>` so it outlives the server object. A shard is single-threaded and unsynchronized, which is what lets several shards run side by side (one per core) without sharing mutable state.
- Tests build their own `Shard` (a `test_shard()` helper per file) and pass it to `WampSession` and the handlers.

#### PubSubHandler (pubsub_handler.hpp)
- Handles SUBSCRIBE/PUBLISH messages
- Uses the SubscriptionManager of the session's `Realm` (topic → subscription_id → session_id mappings)
- On PUBLISH: looks up subscribers, sends EVENT messages via EventChannel to each subscriber's session

#### ProcedureHandler (procedure_handler.hpp)
- Handles REGISTER/CALL/YIELD messages
- Uses the RegistrationManager of the session's `Realm` (procedure URI → registration_id → session_id)
- Uses the Shard's InvocationTracker (pending CALLs awaiting YIELD responses)
- On CALL: finds callee, generates invocation_id, sends INVOCATION via EventChannel to callee
- On YIELD: finds pending call, sends RESULT via EventChannel to caller

#### EventChannel (event_channel.hpp)
- Part of the Shard: `shard.channels` is an instance of `EventChannelRegistry`, not a static class.
- Wraps `asio::experimental::channel<void(std::error_code, Event)>`
- Registry maintains one channel per session_id
- Used to push EVENT and INVOCATION/RESULT messages to sessions asynchronously
- Channel receives are co_awaited in `handle_wamp_session`'s parallel_group

#### RawSocket Framing (raw_socket.hpp)
- 4-byte header: `[0]` = frame type (0 regular, 1 ping, 2 pong; upper 5 bits reserved, must be 0), `[1:4]` = payload length (24-bit big-endian)
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
- All I/O operations use `asio::awaitable<T>` coroutines
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
- **Asio** (standalone, `asio` in vcpkg; `std::error_code`): Asynchronous networking, coroutines (`io_context`, `tcp::acceptor`, `awaitable`, `experimental::channel`)
- **Asio SSL**: TLS 1.3 support (`ssl::context`, `ssl::stream<tcp::socket>`)
- **OpenSSL**: TLS implementation (required by Asio SSL)
- **toml11**: TOML configuration file parsing
- **spdlog**: Structured logging
- **nlohmann-json**: tests only, as an independent CBOR oracle for `include/cbor.hpp`
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
- `threads` (`[server]`) - router threads / shards (default 1, `"auto"` = available CPUs); sessions on different shards still reach each other, see Router
- `shutdown_grace_ms` (`[server]`) - how long `Router::stop()` waits for sessions to leave after sending each GOODBYE `wamp.close.system_shutdown` (default 3000, 0 = no wait); the writer closes a connection after writing a frame marked `EventToSend::close_after`
- `max_connections_per_second_per_ip` / `connection_burst` and `max_messages_per_second` / `message_burst` / `rate_limit_grace_ms` (`[server]`) - opt-in rate limits (default 0 = off): connections per address are closed at accept (`ConnectionRateLimiter`), a session over its message rate is throttled (`WampSession::settle_rate`, the reader sleeps `take_throttle()`) and aborted after the grace period
- `max_malformed_messages` (`[server]`) - undecodable messages in a row before a session is ABORTed with `wamp.error.protocol_violation` and closed (default 10, 0 = never); counted in `WampSession::malformed()`
- `max_connections` / `max_connections_per_ip` (`[server]`) - open connection caps (default `"auto"` = open-file limit minus 128, and 0 = off); enforced by the acceptor through `ConnectionLimiter` (`connection_limiter.hpp`), which the session releases when it ends
- `handshake_timeout_ms` (`[server]`) - deadline for a new connection to become an established session (default 10000, 0 disables); enforced in `handle_wamp_session` with a timer that closes the socket
- `max_pending_invocations` - limits pending RPC calls (set via `ProcedureHandler::set_max_pending_invocations()`)
- `call_timeout_ms` (`[server.rpc]`) - callee answer deadline, 0 disables; CALL `timeout` option overrides
- `[server.events]` - `queue_size`, `overflow` (`backpressure` | `drop`), `backpressure_timeout_ms`, `slow_subscriber_limit`
- Optional authentication keys for WAMP-Cryptosign, plus `[auth.roles]` / `[[roles.<name>.rules]]` authorization (default-deny once keys exist; see `include/authorizer.hpp`)

### Performance Considerations
- **Threads**: `[server] threads` shards, each one thread with its own `io_context` and `Shard`; no shared routing state, cross-shard traffic goes through `ShardGroup` (`docs/architecture.md`)
- **Buffer sizes**: 8KB buffers in handle_wamp_session. Adjust for large payloads
- **Event channels**: One bounded channel per session (`[server.events] queue_size`, default 100). When a queue is full, `overflow = "backpressure"` (default) suspends the sending session until the subscriber drains it (bounded by `backpressure_timeout_ms`), `"drop"` discards and counts the event. See `EventChannelRegistry` in `event_channel.hpp`.
- **ID generation**: Per-shard generators (`Shard::ids`); session and publication ids are random global-scope ids, the rest sequential per shard

## Testing

Tests use Catch2 framework with CTest integration:
- **test_wamp_id.cpp**: ID generator behavior
- **test_raw_socket.cpp**: Frame parsing/creation
- **test_wamp_serializer.cpp**: CBOR message serialization
- **test_subscription_manager.cpp**: Subscription tracking
- **test_wamp_session.cpp**: Protocol state machine
- **test_procedure_handler.cpp**: RPC message handling
- **test_config.cpp**: TOML configuration loading
- **test_wamp_client.cpp**: WAMP client functionality
- **test_integration.cpp**: End-to-end scenarios with mock sockets
- **test_protocol_gaps.cpp**: UNSUBSCRIBE/UNREGISTER, payload forwarding, callee errors, pipelined frames
- **test_event_queue.cpp**: Event queue sizing, drop/backpressure policies, timeout
- **test_authorization.cpp**: Permissions matching, role enforcement in the session, no restrictions without auth
- **test_router.cpp**: Multi-shard Router (spread, self-contained sessions, clean stop, threads = 1 routing)
- **test_cpu_limits.cpp**: cgroup/ECS limit parsing and CPU budget
- **test_cbor.cpp**: Direct CBOR codec vs nlohmann (byte-identical output, decoding, malformed/fuzzed input)
- **test_realms.cpp**: Realm isolation of topics and procedures
- **test_crypto_utils.cpp**: Ed25519 signature verification and challenge generation
- **test_patterns.cpp**: URI matching, precedence, SubscriptionManager/RegistrationManager patterns, pattern authorization; end-to-end pattern tests are in test_router.cpp
- **test_rate_limit.cpp**: TokenBucket and ConnectionRateLimiter with a fake clock; end-to-end rate limit tests are in test_router.cpp
- **test_ppt.cpp**: payload passthru (ppt_* validation, option round trips, EventTemplate details, role features); end-to-end passthru tests are in test_router.cpp
- **test_msgpack.cpp**: MessagePack <-> CBOR transcoding (vectors, errors, nlohmann oracle both ways, fuzz); end-to-end MessagePack tests are in test_router.cpp
- **test_json.cpp**: JSON <-> CBOR transcoding (spec vectors, errors, nesting limits, nlohmann oracle on random payloads, fuzz), UTF-8, base64; JSON end-to-end tests are in test_router.cpp
- **test_websocket.cpp**: WebSocket upgrade parsing, frame parser (lengths, masking, fragmentation, violations, fuzz); end-to-end WebSocket tests live in test_router.cpp (`tests/ws_test_client.hpp` is the blocking test client)
- **test_logging.cpp**: Async logger (slow sink does not stall the caller), shard tag on log lines

### Benchmarks

`bench/` holds `wamp_bench` (Catch2 micro-benchmarks) and `wamp_load` (end-to-end load test over `WampClient`). Both are `EXCLUDE_FROM_ALL` CMake targets; build and run them in a Release build (`cmake --build build-local-release --target wamp_bench wamp_load`). Baseline numbers are in the README. `wamp_profile_router`, `wamp_handoff_bench` and `wamp_tls_probe` are further `EXCLUDE_FROM_ALL` tools used by the threading analysis (`docs/threading-analysis.md`). The run-time threading design (threads, coordination, scheduling criteria) is described in `docs/architecture.md`.

Run specific test: `./scripts/run.sh ./build/wamp_tests "[test name]"`

## Important Constraints

- **Self-Contained Project**: This project is standalone with its own Dockerfile, scripts, and config files
- **Docker vs Local**:
  - Docker builds use `./scripts/` wrappers (recommended for consistency)
  - Local builds use CMake presets directly (requires local toolchain setup)
- **Port Mapping**: When using Docker, use `-p` flag with run.sh to expose container ports (e.g., `-p 8080:8080`)
- **vcpkg Manifest Mode**: Uses manifest mode (vcpkg.json), not classic mode
- **Coroutine Requirement**: C++20 coroutines required (Clang 18+ or compatible compiler)
- **One thread per shard**: a shard's state is touched only by its own thread, and handlers must not block; anything cross-shard goes through `ShardGroup`
- **Build Directories**:
  - `build/`: Docker container builds (Clang 18 + libc++)
  - `build-local/`: Local machine builds (when using CMake presets directly)
  - `build-system/`: System packages without vcpkg (alternative local build)
- **C++23 Features**: Full support for `std::expected`, `std::span`, coroutines, ranges, etc.
- **Standard Library**: LLVM libc++ provides cutting-edge C++23 support
