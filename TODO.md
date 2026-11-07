# TODO

Outstanding work, as of 2026-11-05. Check items off as they land.

## Protocol gaps
- [x] Dispatch UNSUBSCRIBE and UNREGISTER (ownership-checked; ERROR `no_such_subscription` / `no_such_registration`).
- [x] Handle callee ERROR replies to INVOCATION and forward them to the caller.
- [x] Forward Arguments/ArgumentsKw through CALL→INVOCATION, PUBLISH→EVENT and ERROR (YIELD→RESULT already worked).
- [x] PUBLISH `acknowledge` was already correct; added `exclude_me` (defaults to true per spec).
- [x] Fail pending calls with `wamp.error.callee_failure` when the callee disconnects.
- [x] Call timeouts: `[server.rpc] call_timeout_ms` (default 30000, 0 disables) and the CALL `timeout` option; a 50 ms sweeper fails overdue calls with `wamp.error.timeout`.
- [x] Router sends INTERRUPT (`mode: killnowait`) to the callee when a call times out; `WampClient` cancels the running handler and replies `wamp.error.canceled`. The `call_canceling` feature is not yet announced in WELCOME/HELLO (role features are still stubbed as empty).
- [x] `WampClient::call`/`call_result` take a `timeout` (sent as the CALL `timeout` option).
- [x] `WampClient` now supports unsubscribe, unregister, args on `call`/`call_result`/`publish` (plus `exclude_me`), args on received events/invocations, and `WampException` for ERROR replies and for handlers that want to return an ERROR.

## Code quality and tests
- [x] Found by the load test: `WampSession::process` handled one frame per socket read (pipelined messages sat in the buffer, and a partial 4-byte header spun forever); `handle_wamp_session` dropped an event or client bytes when the read and channel receive completed together; `WampClient` interleaved socket writes from concurrent invocation handlers; `WampClient::disconnect` used immediately-invoked coroutine lambdas (use-after-free in release builds).
- [x] Flaky test "WampClient - Register procedure and handle call": the integration test fixture stopped its server before it saw the client EOF, so `WampSession` never ran `on_disconnect()` and `com.example.add` stayed registered in the process-wide registry. `WampSession` now cleans up in its destructor.
- [x] Fixed `-Wunused-result` and unused-variable warnings in `tests/test_wamp_session.cpp`.
- [x] Clean-disconnect "Operation canceled" read errors (client read loop, server read) are logged at debug; also stopped logging a cancelled event-channel receive (the loser of the read/event race) as an error.
- [x] Integration tests: one `RouterFixture` owns the io_context/server and stops it thread-safely (no pointer into the server thread's stack, no startup sleeps); the test clients are purely blocking with real deadlines (`read_exact` + `poll`). Removed the async receive loop that raced the blocking reads for the same socket bytes (the actual source of the flakiness and of hangs when a reply never came).
- [x] Removed the stale TODO at `include/wamp_session.hpp:35` (in-process use is already covered: tests drive `WampSession::process()` directly without sockets).
- [x] Docker build re-verified (Clang 18 + libc++): builds cleanly and all 128 tests pass in the container (re-verified after the realm work).
- [x] `test_crypto_utils.cpp` is in the `CLAUDE.md` test list.

## Performance
Do the protocol gaps (arguments forwarding in particular) first so benchmarks measure realistic payloads.
- [x] Catch2 `BENCHMARK` micro-benchmarks in `bench/bench_micro.cpp` (target `wamp_bench`, not built by default). Baseline numbers are in the README.
- [x] End-to-end load tool `wamp_load` (`bench/load_test.cpp`, not built by default). Baseline numbers are in the README.
- [x] Event loss under load: queue size, overflow policy (`backpressure` default | `drop`) and backpressure timeout are configurable under `[server.events]`; drops are counted and logged. Unpaced publishing is now lossless.
- [x] Slow subscribers: after `[server.events] slow_subscriber_limit` (default 3, 0 = off) consecutive backpressure timeouts a subscriber is skipped (events dropped immediately while its queue is full) until it makes room again. Not done: disconnecting chronically stalled subscribers.
- [x] Serialize each EVENT once per PUBLISH (`EventTemplate`): per-subscriber cost 2.6 µs → 55 ns; 100-subscriber fan-out 279 µs → 19 µs.
- [x] `SubscriptionManager::for_each_subscriber` iterates in place (no vector copy, no per-subscriber lookup); the publish path uses it. At 10,000 subscribers the remaining cost is walking the hash map (19 µs); a flat vector of subscriptions per topic would be the next step if that matters.
- [x] Threading analysis: profiled the single-threaded router and measured handoff/TLS costs; findings and the recommended thread-per-core design are in [docs/threading-analysis.md](docs/threading-analysis.md). Tools: `wamp_profile_router`, `wamp_load --mode idle`, `wamp_handoff_bench`, `wamp_tls_probe`.
- [x] Stage 0.1: each established session now runs a reader coroutine and a writer coroutine; the writer coalesces queued frames into one gathered write (up to 64 frames / 256 KiB), a `WriteLock` serializes the two write paths. Fan-out throughput 46k -> 84k events/s, router CPU -26%, about 0.35 syscalls per delivered event (was 2.5). RPC unchanged.
- [x] Stage 0.2: no per-session read buffer for plain sockets (wait for readability, read into a shared per-thread 64 KiB scratch; TLS keeps 4 KiB): idle session memory 11.0 KB -> 4.5 KB.
- [x] Stage 0.3: direct CBOR codec (`include/cbor.hpp`) for the hot-path messages: byte-identical wire format, serialize 7x and deserialize 5.5x faster, RPC 17.8k -> 29k calls/s, router CPU -35% (RPC) / -65% (fan-out). Handshake/auth messages still use nlohmann (rare); could be ported to drop the dependency.
- [x] Stage 0.4 (frame buffer pooling): measured and skipped. After the codec, allocation is about 2% of router CPU, so a pool cannot win more than that (profile in docs/threading-analysis.md).
- [x] Stage 0.5: Asio io_uring backend evaluated and rejected (40% slower on RPC, 50-80% more kernel CPU in the Linux VM; see docs/threading-analysis.md). Stage 0 is finished.
- [x] Re-profiled on AWS EC2 (c7i.2xlarge router core + 1-3 load-generator instances, results in docs/threading-analysis.md): RPC 100-118k calls/s and about 4.8 us per delivered event on one core. Found and fixed a quadratic buffer erase in `WampSession` (-20% fan-out CPU). `wamp_load --instance N` lets several processes share one router.
- [ ] Cheap user-space follow-ups from the EC2 profile: cache the event channel in the session instead of `EventChannelRegistry::find` per delivery; reduce asio overhead on the delivery path (coroutine resumes, channel operations).
- [x] Stage 1 of the thread-per-core plan: `Shard` (include/shard.hpp) owns the event channels, pending-call tracker, realms and id generators; no process-wide mutable state remains; each server has its own shard.
- [x] Container-aware CPU budget (`include/cpu_limits.hpp`: cgroup v1/v2 quota, affinity, ECS task metadata) and its Fargate validation; Fargate hides its limit from the cgroup and shows 2 CPUs to 0.5/1 vCPU tasks, so the metadata endpoint is required (docs/threading-analysis.md).
- [ ] Thread-per-core, shared-nothing router (remaining stages: N shards with an acceptor and SPSC lanes; replicated interest/registration tables with cross-shard pub/sub and RPC; per-shard metrics and logging). Needs Stage 0 and the bare-metal profile first.

## Backlog
- [x] Roles and authorization per authid: `[auth.roles]` + `[[roles.<name>.rules]]` (exact/prefix URIs; call, register, publish, subscribe), default-deny once `[auth.keys]` is set, `wamp.error.not_authorized`. Not done: wildcard URI patterns, reloading permissions without a restart.
- [x] Realm support: Cryptosign signs the raw challenge bytes as the spec does; subscriptions and registrations are isolated per realm (`Realm` in `include/realm.hpp`, one pair of managers per realm, cached by the session; the invocation tracker and event channels stay global); `[auth.realms]` lists the realms each authid may join; `[auth.roles]` may give a role per realm. For the threading review: a `Realm` is the natural shard unit.
- [ ] WebSocket transport; JSON and MessagePack serializers.
- [ ] Pattern-based subscriptions/registrations, call cancellation, progressive results.

## Dependencies (after Stage 0)
- [x] Dependencies: nlohmann-json is gone from production code (all messages use `cbor.hpp`; kept for tests as an oracle); `main.cpp` uses `std::print` and `fmt` is no longer a direct dependency (spdlog still pulls it in); Boost.Asio replaced by standalone Asio (`std::error_code`, no Boost). Sockets, TLS and coroutine executors have no standard replacement (no networking in C++23).
