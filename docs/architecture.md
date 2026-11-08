# Architecture

How the router is put together at run time: threads, the state each one owns, how they coordinate, and what decides where work runs. For the measurements and the reasoning behind the design see [threading-analysis.md](threading-analysis.md).

## Shape

A thread-per-core, shared-nothing router. Each **shard** is one thread with its own `io_context` and its own `Shard` (all routing state: channels, pending calls, realms, id generators). A session lives on one shard for its whole life. Shards share no mutable routing state; they reach each other only through the `ShardGroup` (`include/shard_group.hpp`).

```
                 accept_io_ (acceptor thread)
                        │  least-loaded shard, hands over the fd
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   shard 0 thread   shard 1 thread   shard N-1 thread      each: io_context(1) + Shard
   sessions, sweeper, drain coroutines
        ▲  ▲            ▲  ▲            ▲  ▲
        └──┴── inbox (mutex vector) per shard, replicated routing tables ──┘
                           ShardGroup

   log writer thread  ◄── bounded queue ── every thread
```

## Transports

RawSocket and WebSocket (`wamp.2.cbor`) share one port. `WampSession` looks at the first byte of the connection: `0x7F` is the RawSocket handshake, `G` is an HTTP upgrade request (if `[server.websocket] enabled`). This happens on the shard thread, after any TLS handshake, so the acceptor and the shard placement do not depend on the transport.

Everything inside the router (handlers, `EventTemplate`, cross-shard frames) builds RawSocket-framed messages, `[4-byte header][CBOR]`, shared as `shared_ptr<const vector>` between sessions and shards. A WebSocket session converts at the edge only: direct responses are re-wrapped as binary WebSocket frames in `WampSession`, and `session_writer` gathers a small unmasked WebSocket header followed by the shared payload (skipping the 4-byte RawSocket header), so event fan-out stays zero-copy for both transports. Consequence: a WebSocket message is limited to the same 16 MiB - 1 as a RawSocket frame.

### Connection limits

The acceptor thread asks a `ConnectionLimiter` (a mutex-protected total plus per-address counts, `connection_limiter.hpp`) before it hands a socket to a shard, and the shard's session releases the slot when it ends. The mutex is taken twice per connection lifetime and never on the message path. Over a limit, the socket is closed at once and a counter is bumped. `[server] max_connections` defaults to "auto" (open-file limit minus 128; `main` raises the soft limit to the hard limit first). Accept errors such as EMFILE back off for 100 ms instead of spinning.

### Stalled connections

`handle_wamp_session` arms a timer when a connection starts (`[server] handshake_timeout_ms`, default 10 s). If the session is not established when it fires (TLS handshake, RawSocket/WebSocket handshake, HELLO and authentication all count), it closes the socket, which fails whatever read or handshake the session coroutine is waiting in, and bumps `Shard::counters.handshake_timeouts`. The deadline is for the whole path, so trickling bytes does not extend it. Established sessions cancel the timer and may idle indefinitely.

## Threads

| Thread | Count | What it does |
|---|---|---|
| main | 1 | Loads config, starts logging, builds the `Router`, calls `start()`, blocks in `wait()`. After shutdown it logs per-shard stats. |
| acceptor | 1 | Runs `accept_io_`: the `accept_loop` coroutine and the SIGINT/SIGTERM handler. |
| shard | N (`[server] threads`; `"auto"` = cgroup-aware CPU count) | Runs everything for its sessions, including the TLS handshake and Cryptosign verification. |
| log writer | 1 (async logging) | The only thread that touches the log sink. |

There is no worker pool and nothing blocks: waits are awaitable timers. The router does not pin threads to cores (the benchmarks pin externally with `taskset`).

### On a shard thread

* One reader and one writer coroutine per session. They share a thread, so the write lock between them is uncontended.
* A 50 ms call-timeout sweeper.
* Cross-shard **drain** coroutines, started on demand.
* Short timer waits (100 µs polling) while a publisher or caller is held back for backpressure.

Scheduling within a shard is cooperative and single-threaded: asio resumes a coroutine when its I/O completes, handlers run in FIFO order, nothing preempts.

## Coordination between threads

| Mechanism | Between | Notes |
|---|---|---|
| Per-shard **inbox**: a mutex-protected `vector<CrossMessage>` (publish, forwarded call, result frame, cancel) | any shard → owner | Any shard pushes, only the owner drains. An atomic `depth` counts messages queued plus in delivery. |
| **Wake-up**: the first push into an idle inbox `co_spawn`s a drain onto the destination `io_context` | sender → destination | Pushes while a drain is running just append; the drain takes whole batches until empty. A burst costs one wake. |
| **Replicated routing tables**: per shard, "which other shards have subscribers for (realm, topic)" and "which shard owns (realm, procedure)" | owner reads, others write | Each replica has its own mutex. The owner takes it on every publish or call; other shards take it only when a subscription or registration changes. |
| Global **registration table** (one mutex) | REGISTER only | The arbiter for "one registration per procedure across all shards". It also writes the entry into every other shard's replica before REGISTERED is sent. |
| Shared **immutable data** | publisher shard → subscriber shards | A cross-shard EVENT is serialized once (`EventTemplate`) and shared as `shared_ptr<const>`; each destination stamps in its own subscription ids. Cost: an atomic refcount. |
| **Backpressure**: `wait_for_room` | destination inbox → sender session | Destinations at or above 4,096 queued messages are reported to the sending session, which stops reading its socket and polls `depth` every 100 µs until it is under 2,048 or `backpressure_timeout_ms` passes. Only events are dropped at the 65,536 hard cap; calls and results never are. |
| **Counters**: sessions, accepted, publishes, calls, drops, inbox depth/received/dropped | any thread reads (`Router::stats()`) | Relaxed atomics. |
| **Logging**: bounded queue (default 8192 lines) | all threads → writer | A full queue overwrites the oldest line and counts it. The shard-tag map has a mutex that only the writer reads on the hot side. |
| **Shutdown** | main / acceptor → shards | `stop()` closes the acceptor, polls until every inbox is empty (up to 2 s, 1 ms steps), stops each shard's `io_context`, then joins the threads. |

## What decides where work runs

* **Connection → shard:** the acceptor picks the shard with the fewest open sessions (ties go to the lowest index), hands over the file descriptor and posts it to that shard. The session never moves. The choice counts sessions, not load: an idle session weighs the same as a busy one, and there is no rebalancing.
* **Cross-shard work follows the data, not the load:**
  * **PUBLISH** goes to the shards that have subscribers for the topic.
  * **CALL** goes to the shard that owns the registration (the callee's shard). That shard generates the invocation id and owns the pending call; the callee's YIELD arrives there. It sends the RESULT or ERROR back to the caller's shard as a frame. The same applies to timeouts and callee disconnects.
  * **Caller disconnect** is broadcast as a cancel, only if the caller forwarded a call to another shard; each shard drops that caller's pending calls and sends INTERRUPT to the callees.
* **Ordering:** messages from one source shard to one destination stay in order (they append under one mutex), which gives WAMP's per-publisher, per-topic ordering. Different sources have no relative order.
* **Subscribe/register visibility:** a shard updates every other shard's replica before it sends SUBSCRIBED or REGISTERED, so anything published or called after the reply is seen.

## Known weak spots

* **Placement ignores load.** A hot connection can overload one shard while others idle.
* **One callee per procedure** means a hot procedure is limited to one core (many procedures spread evenly).
* **Waking an idle shard** costs about 0.2–0.3 ms per crossing on EC2 (not visible under load). A spin-before-sleep option would remove it at the price of CPU; not built.
* **Inbox is a mutex vector**, not an SPSC ring. The measurements showed no contention; the two were never benchmarked against each other.
* **Shutdown does not send GOODBYE;** open sessions are cut when the shard threads stop.

## Measured scaling (EC2, router pinned to 1 / 2 / 4 cores)

| Workload | 1 | 2 | 4 |
|---|---|---|---|
| Self-contained RPC (calls/s) | 60k | 132k | 221k |
| Self-contained pub/sub (publishes/s) | 87k | 167k | 259k |
| Cross-shard fan-out (deliveries/s) | 278k | 570–590k | 0.92–1.18M |
| Cross-shard RPC (calls/s) | 130k | 192k | 327k |
