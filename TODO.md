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
- [ ] Stage 0, single-thread fixes found by the profile: split each session into a reader and a writer coroutine with `writev` batching (today every delivered event cancels and re-arms the read, wastes a `recv` that returns EAGAIN, and does its own `send`); shrink the 8 KiB per-session receive buffer (about 70% of idle-session memory); replace nlohmann CBOR with a purpose-built codec (a third of RPC user time); pool frame buffers; evaluate the Asio io_uring backend.
- [ ] Reproduce the profile on bare-metal/normal Linux (Docker Desktop's VM inflates syscall cost) and make `wamp_load` multi-threaded/multi-process so it is not the bottleneck.
- [ ] Thread-per-core, shared-nothing router (staged: `Shard` object replacing the process-wide statics; N shards with an acceptor and SPSC lanes; replicated interest/registration tables with cross-shard pub/sub and RPC; per-shard metrics and logging). Needs Stage 0 and the bare-metal profile first.

## Backlog
- [x] Roles and authorization per authid: `[auth.roles]` + `[[roles.<name>.rules]]` (exact/prefix URIs; call, register, publish, subscribe), default-deny once `[auth.keys]` is set, `wamp.error.not_authorized`. Not done: wildcard URI patterns, reloading permissions without a restart.
- [x] Realm support: Cryptosign signs the raw challenge bytes as the spec does; subscriptions and registrations are isolated per realm (`Realm` in `include/realm.hpp`, one pair of managers per realm, cached by the session; the invocation tracker and event channels stay global); `[auth.realms]` lists the realms each authid may join; `[auth.roles]` may give a role per realm. For the threading review: a `Realm` is the natural shard unit.
- [ ] WebSocket transport; JSON and MessagePack serializers.
- [ ] Pattern-based subscriptions/registrations, call cancellation, progressive results.
