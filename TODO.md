# TODO

Outstanding work, as of 2026-11-05. Check items off as they land.

## Protocol gaps
- [x] Dispatch UNSUBSCRIBE and UNREGISTER (ownership-checked; ERROR `no_such_subscription` / `no_such_registration`).
- [x] Handle callee ERROR replies to INVOCATION and forward them to the caller.
- [x] Forward Arguments/ArgumentsKw through CALL→INVOCATION, PUBLISH→EVENT and ERROR (YIELD→RESULT already worked).
- [x] PUBLISH `acknowledge` was already correct; added `exclude_me` (defaults to true per spec).
- [x] Fail pending calls with `wamp.error.callee_failure` when the callee disconnects.
- [ ] Call timeouts: pending invocations are only bounded by LRU eviction, so a callee that never replies leaves the caller waiting forever.
- [ ] `WampClient` (`include/wamp_client.hpp`) lacks API for the new router features: unsubscribe, unregister, args on `call`/`publish`, args on received events/invocations, and returning an ERROR from an `InvocationHandler`.

## Code quality and tests
- [ ] Flaky test: "WampClient - Register procedure and handle call" (`tests/test_wamp_client.cpp:120`) fails in roughly half of full-suite runs but never in isolation, on the baseline too. Likely cause: the router's registration manager is a process-wide static, so `com.example.add` is still registered by an earlier test and REGISTER returns `procedure_already_exists`. Needs per-test isolation or unique procedure names.
- [ ] Fix `-Wunused-result` warnings from unchecked `session.process(...)` in `tests/test_wamp_session.cpp`.
- [ ] Log the clean-disconnect "Operation canceled" read-loop error at debug, not error.
- [ ] Integration tests (`tests/test_integration.cpp`): graceful server shutdown instead of detach; timing-dependent tests.
- [ ] Resolve the TODO at `include/wamp_session.hpp:35` ("in process client support, fix names").
- [ ] Re-verify the Docker build (`./scripts/cmake-build.sh`).
- [ ] Add `test_crypto_utils.cpp` to the test list in `CLAUDE.md`.

## Performance
Do the protocol gaps (arguments forwarding in particular) first so benchmarks measure realistic payloads.
- [ ] Catch2 `BENCHMARK` micro-benchmarks: CBOR serialize/deserialize, RawSocket framing, subscription lookup and fan-out. Tagged so normal test runs skip them.
- [ ] End-to-end load tool on `WampClient`: N clients, PUBLISH→EVENT and CALL→RESULT p50/p99 latency and throughput.
- [ ] Record baseline numbers in the README; revisit the single-threaded design and unbounded per-session channels (`include/event_channel.hpp`).

## Backlog
- [ ] Roles and authorization per authid.
- [ ] WebSocket transport; JSON and MessagePack serializers.
- [ ] Pattern-based subscriptions/registrations, call cancellation, progressive results.
