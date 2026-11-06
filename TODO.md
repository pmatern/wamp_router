# TODO

Outstanding work, as of 2026-11-05. Check items off as they land.

## Protocol gaps
- [ ] Dispatch UNSUBSCRIBE and UNREGISTER in `WampSession::handle_message` (`include/wamp_session.hpp`). Message types and serializers exist (`wamp_messages.hpp`); currently dropped by the "unexpected message type" default.
- [ ] Handle callee ERROR replies to INVOCATION and forward them to the caller.
- [ ] Forward Arguments/ArgumentsKw. `deserialize_call` drops options and args; the INVOCATION serializer has the same TODO (`include/wamp_serializer.hpp`). Verify PUBLISH/EVENT payloads too.
- [ ] Check PUBLISH `acknowledge` and `exclude_me` behavior against the WAMP spec.
- [ ] Clean up pending invocations when a callee disconnects; consider call timeouts.

## Code quality and tests
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
