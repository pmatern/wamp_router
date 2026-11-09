# WAMP Router

A header only C++23 implementation of a [WAMP](https://wamp-proto.org/) (Web Application Messaging Protocol) router speaking CBOR or JSON over RawSocket or WebSocket, on one port.

## What is WAMP?

WAMP is a routed protocol that provides two messaging patterns:
- **Remote Procedure Calls (RPC)**: Clients can call procedures registered by other clients
- **Publish & Subscribe (PubSub)**: Clients can publish events to topics and subscribe to receive them

This router acts as the central message broker, routing messages between clients.

## Features

- **RPC Support**: Full `CALL`, `REGISTER`, `YIELD`, `INVOCATION`, `RESULT` workflow
- **PubSub Support**: `SUBSCRIBE`, `PUBLISH`, `EVENT` messaging
- **RawSocket and WebSocket Transport**: both on the same port, told apart by the first byte of the connection
- **CBOR and JSON serializers**: `wamp.2.cbor` and `wamp.2.json` over WebSocket, serializers 3 and 1 over RawSocket; sessions with different serializers talk to each other (MessagePack is not supported yet)
- **Lossless payloads**: null, booleans, integers, floats, strings, byte strings, lists and dicts of any nesting pass through unchanged
- **TLS 1.3 Support**: Encrypted transport with optional client certificates
- **WAMP-Cryptosign Authentication**: Ed25519 signature-based authentication
- **C++20 Coroutines**: Asynchronous I/O using `asio::awaitable`
- **Event Channels**: Efficient message delivery using Asio experimental channels
- **Thread per core**: `[server] threads` runs that many shards; pub/sub and RPC are routed across them (see [docs/architecture.md](docs/architecture.md))
- **Session Management**: Automatic cleanup on disconnect
- **Modern C++23**: Uses `std::expected`, `std::span`, ranges, etc.

## Dependencies

- **Asio** (standalone): Asynchronous networking and coroutines
- **OpenSSL**: TLS 1.3 support and Ed25519 cryptography
- **nlohmann-json**: tests only, as an independent oracle for the CBOR codec (`include/cbor.hpp`)
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

This creates a self-signed certificate and key: `test_certs/cert.pem` and `test_certs/key.pem`.

### Create config.toml

```toml
[server]
port = 8080
threads = 1   # router threads, one shard each; "auto" = one per available CPU (container-aware)
handshake_timeout_ms = 10000   # a new connection must become a session (TLS, handshake, HELLO, auth) in this time; 0 = no limit
max_connections = "auto"       # open connections allowed; "auto" = open-file limit minus a reserve, 0 = no limit
max_connections_per_ip = 0     # per client address, 0 = no limit (leave off behind a proxy or NAT)
max_malformed_messages = 10    # undecodable messages in a row before a session is aborted; 0 = never
shutdown_grace_ms = 3000       # on shutdown, how long sessions get to leave after GOODBYE; 0 = do not wait

[server.tls]
cert = "test_certs/cert.pem"
key = "test_certs/key.pem"
# ca = "test_certs/ca.pem"  # Optional: for client certificate verification
# require_client_cert = false  # Optional: require client certificates

[server.rpc]
max_pending_invocations = 10000
call_timeout_ms = 30000   # callee answer deadline, 0 = none; a CALL's "timeout" option overrides it

[server.websocket]
enabled = true            # accept WebSocket (wamp.2.cbor) upgrades on the same port
allowed_origins = []      # empty = any origin; otherwise a request with an Origin header must match one entry exactly
subprotocols = ["wamp.2.cbor", "wamp.2.json"]   # offered on the upgrade; "wamp.2.json" also enables JSON over RawSocket
# max_message_size = 16777215   # bytes (the maximum)

# Per-session event queue and overflow policy: see "Event queue and backpressure" below
# [server.events]

[logging]
level = "info"  # trace, debug, info, warn, error, critical
async = true       # a background thread writes the log; a slow sink never stalls a shard
queue_size = 8192  # buffered lines; the oldest is dropped when full
# file = "router.log"

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
cmake --build build-local-release

# 5. Run tests
./build-local-release/wamp_tests

# 6. Run the router with configuration
./build-local-release/wamp_router --config config.toml
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
cmake --build build-local-release

# System packages (no vcpkg)
cmake --preset system-packages
cmake --build build-system
```

**Build artifacts:** `./build-local/` (debug), `./build-local-release/` (release) or `./build-system/`

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

The router speaks CBOR or JSON over TLS 1.3, with either WAMP RawSocket or WebSocket transport. All of them are served on the same port; the router looks at the first byte of each connection (`0x7F` = RawSocket, `G` of `GET` = WebSocket upgrade) and the client picks the serializer:

- **Protocol**: WAMP v2
- **Transport**: RawSocket, or WebSocket (RFC 6455), over TLS 1.3 (TCP)
- **Serializer**: CBOR (`wamp.2.cbor`, RawSocket serializer 3) or JSON (`wamp.2.json`, RawSocket serializer 1); MessagePack is not supported yet
- **Default Port**: Configured in config.toml (typically 8080)
- **Authentication**: WAMP-Cryptosign with Ed25519 signatures (optional)

### WebSocket

A client opens a normal WebSocket connection (`ws://` or, with TLS, `wss://`; any path) and offers `wamp.2.cbor` and/or `wamp.2.json` in `Sec-WebSocket-Protocol`. Each WAMP message is one WebSocket message: a binary frame for CBOR, a text frame for JSON. Behavior:

- **Handshake:** the router answers `101` with the subprotocol it chose: the first one the client offers that is listed in `[server.websocket] subprotocols`. Requests that offer none of them get `400`, a version other than 13 gets `426`, and a disallowed origin gets `403`; the connection is then closed.
- **Origin check:** browsers send an `Origin` header and cannot be stopped from opening connections to any host, so set `[server.websocket] allowed_origins` to the sites that may use the router. A request with an `Origin` that is not on the list is refused; requests without one (non-browser clients) are accepted. An empty list accepts any origin.
- **Frames:** fragmented messages are reassembled, pings are answered with pongs, and a client close frame is echoed before the connection is closed. After a WAMP GOODBYE the router sends a close frame. Client frames must be masked and use no extensions (no `permessage-deflate`). A frame of the wrong kind for the subprotocol (text on `wamp.2.cbor`, binary on `wamp.2.json`) closes the connection with code 1003; a JSON text message that is not valid UTF-8 closes it with 1007.
- **Limits:** a message may be at most `max_message_size` bytes (default and maximum 16,777,215, the same limit as RawSocket). The router does not send pings of its own.
- **Everything else is shared:** authentication, realms, authorization and routing are identical to RawSocket, and WebSocket and RawSocket sessions see each other's events and calls, also across shards.

### JSON

`wamp.2.json` (WebSocket text frames) and RawSocket serializer 1 carry the same messages as CBOR. A JSON session and a CBOR session can publish to and call each other: the router works in CBOR internally and converts at the edge of a JSON session (`include/json.hpp`), so CBOR sessions pay nothing. Rules:

- Payloads are lossless in both directions: null, true/false, integers, floats, strings, lists and objects of any nesting (up to 64 levels). Integers outside int64 become floats on the way in. A JSON number with a fraction or exponent is a float; `2.0` stays a float.
- **Binary data** is a string that starts with a NUL character followed by standard base64 (`"\u0000AQID"`), as the WAMP spec says; it corresponds to a CBOR byte string. A JSON object key is never binary.
- CBOR NaN and infinities have no JSON form and are sent as `null` (as `JSON.stringify` does). CBOR tags are dropped. Text must be valid UTF-8 in both directions.
- Invalid JSON counts as a malformed message (see below); as the first message of a session it closes the connection.
- JSON numbers above 2^53 lose precision in JavaScript clients; the router passes them through exactly.
- Cost: converting a 10-argument message takes about 0.9 µs (CBOR to JSON) and 1.0 µs (JSON to CBOR) on the machine used for the other micro-benchmarks, per message per JSON session. A JSON subscriber therefore costs more per delivered event than a CBOR one (60 ns with the stamped template); in the in-process load test with 10 subscribers JSON fan-out ran at about 75% of the CBOR rate and JSON RPC at 82%, with the client's own conversion included.
- Tested with Autobahn|Python over `wss://` and `rss://` with `JsonSerializer` and Cryptosign, including floats, `None`, nested containers and bytes.

### Authentication
### Authentication

If `[auth.keys]` is configured in config.toml, clients must authenticate using WAMP-Cryptosign:

1. Client sends HELLO with `authid` and `authmethods=["cryptosign"]`
2. Router responds with CHALLENGE containing a random nonce
3. Client signs the raw challenge bytes (the 32 bytes behind the hex string) with its Ed25519 private key
4. Client sends AUTHENTICATE with the hex-encoded 64-byte signature (`signature||challenge`, 96 bytes, is also accepted)
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

Access is default-deny: SUBSCRIBE, PUBLISH, REGISTER and CALL need a matching rule, and denied requests get `wamp.error.not_authorized`. An unacknowledged PUBLISH that is denied gets no reply, as the WAMP spec requires. An authid with no role can connect but cannot do anything. The role name is reported as `authrole` in WELCOME. With authentication disabled nothing is restricted. A permission check costs roughly 25-40 ns.

### Example: Python Client (with authentication)

Tested with Autobahn|Python 24.4.2 (Twisted) against this router (port 8080, run from the repository root), using the keys, realms and roles from `config.toml` (`admin` may register and call in `realm1`) and the certificate from `scripts/gen-test-certs.sh`. The private key is the public RFC 8032 test key behind `config.toml`'s `admin` entry; never use it outside testing. Install with `pip install "autobahn[twisted,serialization,encryption]" pynacl`. Autobahn speaks RawSocket through the `rs://` (plain) and `rss://` (TLS) URL schemes.

```python
from autobahn.twisted.util import sleep
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from autobahn.wamp.serializer import CBORSerializer
from autobahn.wamp.types import PublishOptions
from nacl.signing import SigningKey
from twisted.internet import reactor
from twisted.internet.ssl import Certificate, CertificateOptions

# The Ed25519 private key (32-byte seed) whose public key is configured under [auth.keys]
SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")

class MyComponent(ApplicationSession):
    def onConnect(self):
        self.join(self.config.realm, authmethods=["cryptosign"], authid="admin")

    def onChallenge(self, challenge):
        if challenge.method == "cryptosign":
            # Sign the raw challenge bytes (the 32 bytes behind the hex string); reply with the hex signature
            raw = bytes.fromhex(challenge.extra["challenge"])
            return SigningKey(SEED).sign(raw).signature.hex()

    async def onJoin(self, details):
        print(f"Authenticated as {details.authid} (role {details.authrole})")

        await self.subscribe(lambda msg: print(f"Got event: {msg}"), "com.example.topic")
        self.publish("com.example.topic", "Hello WAMP!", options=PublishOptions(exclude_me=False))

        await self.register(lambda a, b: a + b, "com.example.add")
        print(f"Result: {await self.call('com.example.add', 2, 3)}")

        await sleep(0.2)
        self.leave()

    def onLeave(self, details):
        reactor.stop()

# Trust the router's certificate (here the self-signed one from scripts/gen-test-certs.sh)
with open("test_certs/cert.pem") as f:
    ssl = CertificateOptions(trustRoot=Certificate.loadPEM(f.read()))

runner = ApplicationRunner(
    url="rss://localhost:8080",   # RawSocket over TLS ("rs://" is RawSocket without TLS)
    realm="realm1",
    serializers=[CBORSerializer()],
    ssl=ssl,
)
runner.run(MyComponent)
```

To use WebSocket instead, change only the URL to `wss://localhost:8080/ws` (also run and verified; the router logs `WebSocket upgrade complete`). For JSON use `serializers=[JsonSerializer()]` (from `autobahn.wamp.serializer`) with either URL; this was run too, with the same output. Output:

```
Authenticated as admin (role admin)
Got event: Hello WAMP!
Result: 5
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
| Serialize CALL / EVENT, no args | 64 ns / 46 ns (was 0.62 / 0.50 µs) |
| Serialize CALL / PUBLISH / EVENT / INVOCATION / RESULT, 10 args + kw | 0.26 – 0.33 µs (was 1.9 – 2.8 µs) |
| Deserialize CALL / PUBLISH / EVENT / INVOCATION / RESULT, 10 args + kw | 0.89 – 1.01 µs (was 4.5 – 5.1 µs); message type peek 11 ns |
| RawSocket frame 128 B / 16 KiB | 54 ns / 171 ns |
| `for_each_subscriber` (in place), 1 / 100 / 10,000 subscribers | 29 ns / 226 ns / 21 µs |
| `get_subscribers` (copies the id set), 1 / 100 / 10,000 subscribers | 67 ns / 274 ns / 18 µs |
| `find_callee` (1,000 registrations) | 35 ns |
| Invocation tracker track + retrieve | 90 ns |
| EVENT per subscriber: full serialize + frame / `EventTemplate::frame_for` | 0.33 µs / 62 ns |
| PUBLISH fan-out to 1 / 10 / 100 subscribers (incl. drain) | 1.5 µs / 2.7 µs / 15.7 µs (was 3.1 / 28 / 279 µs) |
| CALL → INVOCATION → YIELD → RESULT through the handlers (no socket I/O) | 4.0 µs (was 12.5 µs) |
| JSON edge conversion, 10 args + kw: CBOR → JSON / JSON → CBOR | 0.86 µs / 1.0 µs (paid per message by JSON sessions only) |

These are in-process numbers: they exclude socket I/O and TLS. Before the direct CBOR codec (`include/cbor.hpp`) the cost was dominated by (de)serialization through nlohmann::json. PUBLISH fan-out serializes the EVENT once and stamps in each subscriber's subscription id (`EventTemplate`), so a subscriber costs about 62 ns (`frame_for`) instead of a full serialize and frame each time (0.33 µs now, 2.6 µs with the old nlohmann path).

### Load test

`wamp_load` drives real `WampClient` connections against a router over TCP RawSocket and reports throughput and latency percentiles. By default the router runs in-process on its own thread (so router and clients share the machine's CPUs); `--host/--port` targets an external plain-TCP router.

```bash
cmake --build build-local-release --target wamp_load
./build-local-release/wamp_load                                   # both scenarios
./build-local-release/wamp_load --mode pubsub --subscribers 100 --messages 5000 --rate 1000
./build-local-release/wamp_load --mode rpc --callers 50 --calls 200
```

Baseline (Release, same machine as above, embedded router, one shard thread, 10 positional arguments per message; the publisher waits for each PUBLISHED acknowledgement):

| Scenario | Result |
|---|---|
| RPC, 1 caller, 5,000 calls | 7.8k calls/s, p50 0.12 ms, p99 0.29 ms |
| RPC, 10 callers x 1,000 calls | 29.7k calls/s, p50 0.29 ms, p99 1.1 ms |
| RPC, 50 callers x 200 calls | 30.1k calls/s, p50 1.5 ms, p99 7.6 ms |
| PubSub, 10 subscribers, 2,000 events/s | 0 lost, p50 0.13 ms, p99 0.46 ms |
| PubSub, 10 subscribers, 5,000 events/s | 0 lost, p50 0.10 ms, p99 0.60 ms |
| PubSub, 100 subscribers, 1,000 events/s | 0 lost, p50 0.45 ms, p99 1.8 ms |
| PubSub, 10 subscribers, unpaced (`--rate 0`), 200,000 events | 0 lost, 32k events/s published, 324k deliveries/s |

Both overflow policies lose nothing in this closed-loop test, because the publisher waits for each acknowledgement and the subscribers keep up. The policies are exercised by `tests/test_event_queue.cpp`. Earlier versions of this table showed losses with `--overflow drop`; that no longer reproduces. (The unpaced PubSub run delivers 10x its publish rate because each event goes to 10 subscribers.)

The reader/writer split and the direct CBOR codec are what moved these numbers (see [docs/threading-analysis.md](docs/threading-analysis.md)).

### Scaling across threads

Measured on EC2 (c7i.4xlarge router pinned to 1 / 2 / 4 cores, `wamp_load` on separate c7i.2xlarge hosts, plain TCP, 10 positional arguments); details and method in [docs/threading-analysis.md](docs/threading-analysis.md):

| Workload | 1 thread | 2 threads | 4 threads |
|---|---|---|---|
| RPC, each client calls itself (calls/s) | 60k | 132k | 221k |
| RPC, callers and callee on different shards (calls/s) | 130k | 192k | 327k |
| Pub/sub, each client publishes to itself (publishes/s) | 87k | 167k | 259k |
| Pub/sub fan-out across shards, 10 subscribers per topic (deliveries/s) | 278k | 570-590k | 0.92-1.18M |

Crossing shards adds roughly 0.2-0.3 ms per crossing on an idle router (RPC p50 1.3 ms with one thread, 1.7-2.0 ms with two); under load the difference mostly disappears.

### Profiling and threading analysis

`wamp_profile_router` (plain-TCP router, logging off), `wamp_load --mode idle --connections N` (open and hold N sessions), `wamp_handoff_bench` (cross-thread handoff costs) and `wamp_tls_probe` (TLS 1.3 handshake and record costs) support the profile in [docs/threading-analysis.md](docs/threading-analysis.md), which also holds the recommended thread-per-core design. The current threading architecture is described in [docs/architecture.md](docs/architecture.md).

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

Across shards, a publisher or caller whose destination shard has a backlog (4,096 queued cross-shard messages) is slowed the same way until the backlog is under 2,048 (see [docs/architecture.md](docs/architecture.md)).

Dropped events are counted (`EventChannelRegistry::dropped_count()`) and logged at warning level: the first drop, then every 1,000th. Use `wamp_load --queue-size N --overflow drop|backpressure` to compare the policies.

## Architecture

### Key Design Decisions

1. **Header-Only Implementation**: All protocol logic in `include/` for easy integration
2. **TLS 1.3**: Encrypted transport using OpenSSL with optional mutual TLS
3. **WAMP-Cryptosign**: Ed25519 signature-based authentication (optional)
4. **C++20 Coroutines**: Using `asio::awaitable` for clean async code
5. **Event Channels**: `asio::experimental::channel` for efficient message delivery
6. **Thread per shard**: `[server] threads` runs that many shards, each with its own `io_context` and routing state (default 1); sessions on different shards still reach each other (pub/sub and RPC are routed across shards) (see [docs/architecture.md](docs/architecture.md))
7. **Session-per-Coroutine**: Each client connection is a coroutine
8. **RawSocket and WebSocket Transport**: RawSocket is binary TCP framing (4-byte header + payload); WebSocket (`include/websocket.hpp`) is detected on the same port by the first byte. The router builds every outgoing message in RawSocket framing and a WebSocket session re-wraps it as a binary message when writing (the payload bytes are shared, not copied)
9. **CBOR Serialization**: Compact binary format, direct codec in `include/cbor.hpp`

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
# Enable debug logging: set level = "debug" under [logging] in the config file
# (test_config.toml already does)

# Debug in container with GDB
./scripts/shell.sh
gdb ./build/wamp_router
(gdb) run --config test_config.toml
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
