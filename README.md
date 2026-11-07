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
- **C++20 Coroutines**: Asynchronous I/O using `asio::awaitable`
- **Event Channels**: Efficient message delivery using Asio experimental channels
- **Session Management**: Automatic cleanup on disconnect
- **Modern C++23**: Uses `std::expected`, `std::span`, ranges, etc.

## Dependencies

- **Asio** (standalone): Asynchronous networking and coroutines
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

### Realms

Each realm has its own topics and procedures: a publish in `realm1` never reaches subscribers in `realm2`, and the same procedure name can be registered in both. A session is bound to the realm named in its HELLO. When authentication is enabled, `[auth.realms]` lists the realms each authid may join; any other realm (or an authid with no entry) is refused with `wamp.error.not_authorized`, the same answer for unknown and forbidden realms. Without authentication any realm can be joined.

```toml
[auth.realms]
"user1" = ["realm1"]
"admin" = ["realm1", "realm2"]
```

### Authorization

When authentication is enabled, what a session may do is decided by its role. `[auth.roles]` maps each authid to a role (or, as a table such as `{ realm1 = "admin", realm2 = "user" }`, to a role per realm); `[[roles.<name>.rules]]` lists what the role may do:

```toml
[auth.roles]
"user1" = "user"

[[roles.user.rules]]
uri = "com.example."
match = "prefix"          # "exact" (default) or "prefix"
allow = ["call", "publish", "subscribe"]   # also: "register"
```

Access is default-deny: SUBSCRIBE, PUBLISH, REGISTER and CALL need a matching rule, and denied requests get `wamp.error.not_authorized`. An unacknowledged PUBLISH that is denied gets no reply, as the WAMP spec requires. An authid with no role can connect but cannot do anything. The role name is reported as `authrole` in WELCOME. With authentication disabled nothing is restricted. A permission check costs roughly 25-70 ns.

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
            # Sign the raw challenge bytes (the 32 bytes behind the hex string)
            challenge = bytes.fromhex(challenge.extra["challenge"])
            return self.signing_key.sign(challenge).signature.hex()

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

## Benchmarks

Micro-benchmarks (Catch2 `BENCHMARK`) cover serialization, RawSocket framing, routing tables and handler paths. Build and run them in Release:

```bash
cmake --preset local-release
cmake --build build-local-release --target wamp_bench
./build-local-release/wamp_bench
```

Baseline (Release, Intel i7-1068NG7 @ 2.3 GHz, single thread, mean of 50 samples; "10 args + kw" = 10 positional arguments plus 3 keyword arguments):

| Benchmark | Mean |
|---|---|
| Serialize CALL / EVENT, no args | 60 ns / 47 ns (was 0.62 / 0.50 µs) |
| Serialize CALL / PUBLISH / EVENT / INVOCATION / RESULT, 10 args + kw | 0.27 – 0.38 µs (was 1.9 – 2.8 µs) |
| Deserialize CALL / PUBLISH / EVENT / INVOCATION / RESULT, 10 args + kw | 0.82 – 0.93 µs (was 4.5 – 5.1 µs); message type peek 13 ns |
| RawSocket frame 128 B / 16 KiB | 52 ns / 146 ns |
| `for_each_subscriber` (in place), 1 / 100 / 10,000 subscribers | 25 ns / 198 ns / 19 µs |
| `get_subscribers` (copies the id set), 1 / 100 / 10,000 subscribers | 59 ns / 274 ns / 26 µs |
| `find_callee` (1,000 registrations) | 32 ns |
| Invocation tracker track + retrieve | 87 ns |
| EVENT per subscriber: full serialize + frame / `EventTemplate::frame_for` | 2.6 µs / 55 ns |
| PUBLISH fan-out to 1 / 10 / 100 subscribers (incl. drain) | 3.1 µs / 4.7 µs / 18.8 µs (was 3.1 / 28 / 279 µs) |
| CALL → INVOCATION → YIELD → RESULT through the handlers (no socket I/O) | 3.5 µs (was 12.5 µs) |

These are in-process numbers: they exclude socket I/O and TLS. Before the direct CBOR codec (`include/cbor.hpp`) the cost was dominated by (de)serialization through nlohmann::json. PUBLISH fan-out serializes the EVENT once and stamps in each subscriber's subscription id (`EventTemplate`), so it costs about 0.15 µs per subscriber instead of 2.8 µs.

### Load test

`wamp_load` drives real `WampClient` connections against a router over TCP RawSocket and reports throughput and latency percentiles. By default the router runs in-process on its own thread (so router and clients share the machine's CPUs); `--host/--port` targets an external plain-TCP router.

```bash
cmake --build build-local-release --target wamp_load
./build-local-release/wamp_load                                   # both scenarios
./build-local-release/wamp_load --mode pubsub --subscribers 100 --messages 5000 --rate 1000
./build-local-release/wamp_load --mode rpc --callers 50 --calls 200
```

Baseline (Release, same machine as above, embedded router, 10 positional arguments per message):

| Scenario | Result |
|---|---|
| RPC, 1 caller, 5,000 calls | 4.3k calls/s, p50 0.22 ms, p99 0.39 ms |
| RPC, 10 callers x 1,000 calls | 13.6k calls/s, p50 0.66 ms, p99 1.4 ms |
| RPC, 50 callers x 200 calls | 12.1k calls/s, p50 3.4 ms, p99 11.7 ms |
| PubSub, 10 subscribers, 2,000 events/s | 0 lost, p50 0.20 ms, p99 4.4 ms |
| PubSub, 10 subscribers, 5,000 events/s | 0 lost, p50 0.18 ms, p99 7.4 ms |
| PubSub, 100 subscribers, 1,000 events/s | 0 lost, p50 1.6 ms, p99 2.6 ms (was p99 39 ms) |
| PubSub, 10 subscribers, unpaced (`--rate 0`), backpressure | 0 lost; publisher throttled to ~19k msg/s |
| PubSub, 10 subscribers, unpaced, `--overflow drop` | 98% lost |

The direct CBOR codec raised the load-test rates again (RPC with 10 callers 17.8k -> 29k calls/s, router CPU -35%; unpaced 10-subscriber fan-out router CPU -65%). The session reader/writer split earlier raised unpaced 10-subscriber fan-out from 46k to 84k events/s (see [docs/threading-analysis.md](docs/threading-analysis.md)). RPC rows above were measured before the event-queue work; a rerun gives about 18k calls/s with 10 callers (p50 0.55 ms, p99 0.8–1.1 ms).

### Profiling and threading analysis

`wamp_profile_router` (plain-TCP router, logging off), `wamp_load --mode idle --connections N` (open and hold N sessions), `wamp_handoff_bench` (cross-thread handoff costs) and `wamp_tls_probe` (TLS 1.3 handshake and record costs) support the profile in [docs/threading-analysis.md](docs/threading-analysis.md), which also holds the recommended thread-per-core design.

### Event queue and backpressure

Each session has a bounded queue of messages waiting to be written to its client (EVENT, INVOCATION, RESULT, ERROR). Size and overflow behaviour are configurable:

```toml
[server.events]
queue_size = 100                 # events queued per session
overflow = "backpressure"        # or "drop"
backpressure_timeout_ms = 1000   # longest a sender waits for queue space
```

- **`backpressure` (default):** when a subscriber's queue is full, the session that triggered the delivery (the publisher, or the callee sending a YIELD) stops reading its socket until the subscriber catches up, so TCP flow control slows the sender. Nothing is lost. A slow subscriber therefore slows every publisher to its topics; `backpressure_timeout_ms` bounds that stall, after which the event is dropped and counted. It also breaks wait cycles between sessions that publish to each other.
- **`drop`:** the event is discarded and counted. The publisher is never slowed.

Dropped events are counted (`EventChannelRegistry::dropped_count()`) and logged at warning level: the first drop, then every 1,000th. Use `wamp_load --queue-size N --overflow drop|backpressure` to compare the policies.

## Architecture

### Key Design Decisions

1. **Header-Only Implementation**: All protocol logic in `include/` for easy integration
2. **TLS 1.3**: Encrypted transport using OpenSSL with optional mutual TLS
3. **WAMP-Cryptosign**: Ed25519 signature-based authentication (optional)
4. **C++20 Coroutines**: Using `asio::awaitable` for clean async code
5. **Event Channels**: `asio::experimental::channel` for efficient message delivery
6. **Thread per shard**: `[server] threads` runs that many shards, each with its own `io_context` and routing state (default 1); delivery between shards is not implemented yet, so keep it at 1 for normal routing (see docs/threading-analysis.md)
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
- [Asio Documentation](https://think-async.com/Asio/asio-1.32.0/doc/)
- [CBOR Specification](https://cbor.io/)
- [C++20 Coroutines](https://en.cppreference.com/w/cpp/language/coroutines)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

SPDX-License-Identifier: Apache-2.0

## Contributing

See [CLAUDE.md](CLAUDE.md) for development guidelines and architecture documentation.
