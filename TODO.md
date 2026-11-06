# TODO

Outstanding work, as of 2026-11-05. Check items off as they land.

## Protocol gaps
- [x] Dispatch UNSUBSCRIBE and UNREGISTER (ownership-checked; ERROR `no_such_subscription` / `no_such_registration`).
- [x] Handle callee ERROR replies to INVOCATION and forward them to the caller.
- [x] Forward Arguments/ArgumentsKw through CALL→INVOCATION, PUBLISH→EVENT and ERROR (YIELD→RESULT already worked).
- [x] PUBLISH `acknowledge` was already correct; added `exclude_me` (defaults to true per spec).
- [x] Fail pending calls with `wamp.error.callee_failure` when the callee disconnects.
- [ ] Call timeouts: pending invocations are only bounded by LRU eviction, so a callee that never replies leaves the caller waiting forever.
- [x] `WampClient` now supports unsubscribe, unregister, args on `call`/`call_result`/`publish` (plus `exclude_me`), args on received events/invocations, and `WampException` for ERROR replies and for handlers that want to return an ERROR.

## Code quality and tests
- [x] Flaky test "WampClient - Register procedure and handle call": the integration test fixture stopped its server before it saw the client EOF, so `WampSession` never ran `on_disconnect()` and `com.example.add` stayed registered in the process-wide registry. `WampSession` now cleans up in its destructor.
- [ ] Fix `-Wunused-result` warnings from unchecked `session.process(...)` in `tests/test_wamp_session.cpp`.
- [ ] Log the clean-disconnect "Operation canceled" read-loop error at debug, not error.
- [ ] Integration tests (`tests/test_integration.cpp`): graceful server shutdown instead of detach; timing-dependent tests.
- [ ] Resolve the TODO at `include/wamp_session.hpp:35` ("in process client support, fix names").
- [ ] Re-verify the Docker build (`./scripts/cmake-build.sh`).
- [ ] Add `test_crypto_utils.cpp` to the test list in `CLAUDE.md`.

## Performance
Do the protocol gaps (arguments forwarding in particular) first so benchmarks measure realistic payloads.
- [x] Catch2 `BENCHMARK` micro-benchmarks in `bench/bench_micro.cpp` (target `wamp_bench`, not built by default). Baseline numbers are in the README.
- [ ] End-to-end load tool on `WampClient`: N clients, PUBLISH→EVENT and CALL→RESULT p50/p99 latency and throughput.
- [ ] Serialize each EVENT once per PUBLISH instead of once per subscriber (only `subscription_id` differs); fan-out is ~2.8 µs per subscriber, nearly all serialization.
- [ ] `SubscriptionManager::get_subscribers` copies the whole subscriber set into a vector on every publish (31 µs at 10,000 subscribers); iterate in place or cache.
- [ ] After the load tool exists, revisit the single-threaded design and unbounded per-session channels (`include/event_channel.hpp`).

## Backlog
- [ ] Roles and authorization per authid.
- [ ] WebSocket transport; JSON and MessagePack serializers.
- [ ] Pattern-based subscriptions/registrations, call cancellation, progressive results.
