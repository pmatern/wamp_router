# Threading analysis

Question: should the router stay on one `io_context` thread, and if not, what is the best thread-per-core design
(shared-nothing, minimal context switching, Linux containers, ordering at WAMP-spec level only)?

**Answer in one paragraph.** Do a few single-thread fixes first (they remove about a third of the per-message cost and make
threading cheaper), then move to a shared-nothing thread-per-core design: one `io_context` per core, sessions pinned to the core
that accepted them, **every table replicated per core** (subscriptions, registrations, realms), and cross-core traffic carried as
batched messages over SPSC lanes. The measurements say the cross-core hop (30-60 ns/message) is negligible next to the per-message
work (about 50 us of CPU per RPC, about 8 us per delivered event), so the design scales close to linearly with cores for both
workloads. For the idle/reconnect workload the gain is mostly TLS handshakes (0.5-1.1 ms of CPU each).

## What was measured, and how

All tools are in `bench/` and are not built by default. Release builds; Linux numbers come from the `cpp23-builder` image on Docker
Desktop (4 vCPUs, `perf record -e cpu-clock`, frame pointers), macOS numbers from the dev machine (Intel i7-1068NG7, 8 threads).

| Tool | Purpose |
|---|---|
| `wamp_profile_router` | plain-TCP router, logging off, one thread: the process to profile or run `ps`/`perf` against |
| `wamp_load` (`--mode rpc|pubsub|idle`) | load generator; `idle` opens N sessions and holds them |
| `wamp_handoff_bench` | cross-thread handoff and `shared_ptr` refcount costs |
| `wamp_tls_probe` | server CPU per TLS 1.3 handshake and per message, TLS vs plain |

```bash
cmake --build build-local-release --target wamp_profile_router wamp_load wamp_handoff_bench wamp_tls_probe
./build-local-release/wamp_profile_router --port 9000 &
./build-local-release/wamp_load --host 127.0.0.1 --port 9000 --mode rpc --callers 10 --calls 5000
./build-local-release/wamp_handoff_bench
./build-local-release/wamp_tls_probe test_certs/cert.pem test_certs/key.pem
```

**Profile after Stage 0.1-0.3 (Linux VM, share of router CPU):** kernel 74% (RPC) / 83% (fan-out), asio 10.6% / 10.5%, router
logic 3.8% / 2.0%, std containers 3.1% / 1.7%, libc 2.5% / 2.9%, allocation 2.3% / 2.1%, logging 0.6% / 0.3%, CBOR 0.4% / 0.3%.
What is left is the kernel (syscalls and TCP) and asio's own machinery.

**Caveat that matters.** Inside Docker Desktop's VM, syscalls are very expensive (about 20 us each), so the kernel share there is
80%; on macOS natively the router spends about one third of its CPU in the kernel. The *user-space* breakdown and the *syscall
counts per message* are reliable; the absolute kernel share is not. Re-run on bare-metal or a real Linux VM before committing to the
big stages below.

## Findings

### 1. One core's ceiling (macOS native, router on its own process, load generator separate)

| Scenario | Result | Router CPU |
|---|---|---|
| RPC, 10 callers x 5,000 calls | 16.7k calls/s, p50 0.57 ms | 49 us per call (33 user + 16 sys) |
| PubSub, 10 subscribers, unpaced | 46k events/s delivered | about 11 us per delivered event (5.5 user + 5.6 sys) |
| PubSub, 100 subscribers, paced 1000/s | 74k events/s delivered, p50 2 ms | about 8 us per delivered event (3.8 user + 4.3 sys) |

An RPC is four router messages (CALL in, INVOCATION out, YIELD in, RESULT out), so about 12 us of CPU per message. The in-process
micro-benchmarks (README) show the handler logic itself costs only 12.5 us per call, so most of the 49 us is serialization, asio
and syscalls, not routing.

### 2. Where the CPU goes

Router thread, Linux profile (percent of all samples, kernel included):

| Category | RPC (10 callers) | PubSub (10 subscribers, unpaced) |
|---|---|---|
| kernel (syscalls, scheduler, TCP) | 70% | 79% |
| asio (reactor, coroutines, `parallel_group`, channels) | 9.5% | 11.5% |
| CBOR (nlohmann + serializer) | 10% | 3% |
| allocation (`malloc`/`free`, asio recycling) | 5% | 3% |
| libc / std containers / variant | 7% | 5% |
| router logic (`wamp::`) | 1.6% | 0.8% |
| logging (spdlog with level `off`) | 0.7% | 0.4% |

Of the *user* time: RPC is one third CBOR, one third asio, one sixth allocation, about 5% actual routing. Pub/sub is more than half
asio. **The router's own logic is almost free; the cost is plumbing.** That is the key to the whole design: nearly all the work is
session-local (parse, serialize, syscalls) and parallelizes without sharing anything.

### 3. Syscalls per message (strace -c)

* RPC: 2.0 `sendto`, 3.0 `recvfrom` (one in three fails with EAGAIN), 2.0 `epoll_wait` per call. The minimum is 2 sends + 2 reads.
* PubSub: for every delivered event there is one `sendto`, and almost every `recvfrom` fails with EAGAIN (11,164 of 11,233).

**Why:** `handle_wamp_session` (`include/wamp_server.hpp`) runs a `parallel_group` of "read from socket" and "receive from the
event channel" in a loop. Every delivered event completes the channel side, cancels the pending read, writes the one frame with its
own `async_write`, then starts a fresh `async_read_some` (a speculative `recv` that returns EAGAIN, then an epoll re-arm). So each
delivered event costs a wasted read attempt, a cancellation, a coroutine/handler round trip and a lone `send`, and no frames are
ever coalesced. Syscalls are about half of the router CPU on macOS, so this is the largest single inefficiency.

### 4. TLS 1.3 (`wamp_tls_probe`, one server thread, macOS)

| | RSA-2048 cert (the test cert) | ECDSA P-256 cert |
|---|---|---|
| server CPU per handshake | 1.12 ms (about 890/s per core) | 0.47 ms (about 2,100/s per core) |
| plain TCP accept | 25 us | 11 us |

Record layer, per message read: 200 B +1.4 us (2.7 to 4.2), 1 KiB +2.0 us, 16 KiB +6.4 us. Against about 10 us of router CPU per
message that is a 10-15% tax for small messages. A reconnect storm of 100k clients costs 110 s (RSA) or 48 s (ECDSA) of CPU on one
core: **for a mostly idle fleet, handshakes are the cost, and they parallelize perfectly.** Recommend ECDSA certificates regardless.

### 5. Idle sessions

About 11 KB of RSS per connected session (5,000 sessions: 55 MB on macOS; 10,000: 111 MB on Linux). 8 KiB of that is the
`std::array<uint8_t, 8192>` receive buffer that lives in each session's coroutine frame. 100k idle sessions would be about
1.1 GB, mostly unused buffer; allocating the buffer only while a read is outstanding (or 1-2 KiB) would cut it by about 70%.
Connect rate in the harness was 3.5k-12k/s (client-bound, so a lower bound).

### 6. Cost of moving data between cores (`wamp_handoff_bench`, Linux VM, 4 vCPUs)

| Operation | Cost |
|---|---|
| mutex + deque + condvar, batch 16-128 | 31 ns/message |
| mutex + deque + condvar, batch 1 | 60 ns/message |
| SPSC ring (spinning consumer) | 63 ns/message (with a `shared_ptr` payload) |
| `asio::post` to another `io_context`, batch 16-128 | 34-40 ns/message |
| `asio::post`, batch 1 | 413 ns/message |
| `shared_ptr` copy+destroy of **one** frame: 1 / 2 / 4 threads | 13 / 56 / 136 ns per op |
| clone a frame instead (`make_shared<vector>` copy): 128 B / 512 B / 4 KiB / 64 KiB | 31 / 35 / 109 / 1,650 ns |

Takeaways: (a) handoff only has to be *batched*, after which the mechanism hardly matters (mutex/condvar, `asio::post` and a ring
are within 2x; unbatched `post` is 10x worse); (b) **do not share one frame's refcount across cores in the fan-out loop**: at 4
threads each atomic op costs 136 ns, more than cloning a frame of up to 4 KiB; (c) a 30-60 ns hop is 0.5% of the 12 us per-message
router cost, so the architecture is bound by per-session work, not by communication.

## Re-profile on real hardware (AWS EC2)

Setup (us-west-2, default VPC, torn down afterwards): the router (`wamp_profile_router`, one thread pinned to one core) on a
`c7i.2xlarge` (Sapphire Rapids, Ubuntu 24.04, Linux 7.0-aws), driven over the network from one to three more `c7i.2xlarge`
instances running 7 pinned `wamp_load` processes each (one process is single-threaded, so several are needed to saturate a core).
`perf record -e cpu-clock -F 1000 -g` on the router, kernel symbols available. Total cost a few dollars.

| Measurement (one router core, saturated) | Result |
|---|---|
| RPC, 7 x 20 callers | 100-118k calls/s; 8.3 s CPU per 8 s: about 4.3 us user + 4.3 us kernel per call |
| RPC CPU split | kernel 52%, asio 18-20%, CBOR 7.5%, router logic 5.4%, allocation 4.8%, std/libc 10%, logging 0.7% |
| PubSub, 21 x 10 subscribers, unpaced | 14.4M events delivered; 4.8 us CPU per delivered event (2.1 user + 2.7 kernel) |
| PubSub CPU split | kernel 56%, asio 28%, std/libc 7%, allocation 4.3%, router logic 3.9%, CBOR 0.7% |
| TLS 1.3 handshake, server CPU | 463 us (RSA-2048) / 217 us (ECDSA P-256) = 2.2k / 4.6k handshakes/s per core |
| TLS record layer, 200 B message | +0.32 us (x1.1), 16 KiB +1.9 us (x1.5) |
| Handoff between threads (batched) | mutex+condvar 33-39 ns, `asio::post` 36-58 ns; unbatched 155 / 713 ns |
| One `shared_ptr` frame copied on 1 / 2 / 4 threads | 9.6 / 70 / 150 ns per op; cloning 128 B costs 23 ns, 4 KiB 80 ns |

What changed compared with the Docker VM profile:
* **Syscalls are cheap on real hardware.** Kernel share is 52-59%, not 74-83%, and a whole RPC costs 8.5 us instead of about
  90 us. User space is now 41-48% of the router's CPU, so user-space work matters more than the VM suggested; asio's own
  machinery (reactor, coroutine resumes, channel operations) is the largest user-space cost at 18-28%.
* **TLS is much cheaper than on the laptop**: the record layer adds only 11% for small messages (AES-GCM with AVX-512), and a
  handshake is about 0.2-0.5 ms.
* **The thread hand-off and refcount findings hold** (same numbers within noise), so the design above is unchanged.

**A bug the real-hardware profile found.** One libc address took 17.7% of the fan-out profile: `WampSession` erased consumed
bytes from the front of its `std::vector` buffer once per frame, which moves everything behind it (quadratic in the number of
pipelined frames per read, and worse since the shared read scratch grew to 64 KiB). It now advances a read offset and compacts once
per `process()` call. Whole-run A/B on identical load (14.4M events delivered, 3 generators):

| | CPU | per delivered event | wall |
|---|---|---|---|
| before | 85.9 s (45.6 user + 40.3 sys) | 6.0 us | 97.8 s |
| after | 68.8 s (30.4 user + 38.5 sys) | 4.8 us | 77.7 s |

(-20% CPU, -33% user time.) A regression test now feeds 5,000 pipelined frames in uneven chunks.

Remaining user-space targets visible in the profile: asio overhead (about 20-28%), `EventChannelRegistry::find` once per
delivered event (about 1%, cacheable in the session), per-frame `shared_ptr<vector>` allocation (about 4%).

## Containers: ECS Fargate

`bench/container/` builds a test image (router, profiling router, `wamp_load`) that was run on Fargate (platform 1.4.0, x86_64,
us-west-2). What the container sees, by task size:

| Task size | `nproc` / `lscpu` | cgroup CFS quota | Task metadata `Limits.CPU` | `detect_cpu_limits()` |
|---|---|---|---|---|
| 0.5 vCPU | 2 (1 core, 2 threads) | none (-1) | 0.5 | 1 |
| 1 vCPU | 2 | none (-1) | 1 | 1 |
| 2 vCPU | 2 | none (-1) | 2 | 2 |
| 4 vCPU | 4 | none (-1) | 4 | 4 |

* **Fargate does not put its limit in the container's cgroup**, and a task smaller than 2 vCPU still sees 2 CPUs. Sizing a thread
  pool from `hardware_concurrency()` or the cgroup would start 2 threads on a 0.5 or 1 vCPU task. The authoritative source is the ECS
  task metadata endpoint (`$ECS_CONTAINER_METADATA_URI_V4/task`, `"Limits":{"CPU":0.5,...}`); `include/cpu_limits.hpp` reads it
  (plus cgroup v1/v2 quotas and CPU affinity for plain Docker/Kubernetes) and takes the minimum. The router prints the result at startup.
* **Throughput** (one 1 vCPU router task, three 2 vCPU load-generator tasks in one AZ; plain TCP, 10-argument messages): RPC
  about 51k calls/s in total (p50 0.7-1.6 ms), fan-out to 10 subscribers about 310k events/s in total, 0 lost. That is a single
  shared vCPU doing roughly half of what a full c7i core does (100-118k calls/s), as expected for a 2.5 GHz hyperthread.
* Fargate offers no `perf`, no capabilities and no choice of CPU generation (we saw Xeon 8259CL, 8175M and 8488C), so it is for
  checking container behaviour, not for profiling.

## Recommended design

### Stage 0: single-thread fixes first (independent of threading)

**Status: 0.1 is done** (`handle_wamp_session` in `include/wamp_server.hpp`). Measured effect, same harness as the profile:

| | before | after |
|---|---|---|
| PubSub, 10 subscribers, unpaced: delivery rate | 46k events/s | 84k events/s |
| same: router CPU (user + sys) | 2.23 s | 1.66 s (-26%) |
| same: p50 latency | 1.3 s (queues backed up) | 0.25 ms |
| PubSub, 100 subscribers, paced: router CPU | 8.1 s | 6.9 s (-15%) |
| RPC, 10 callers: calls/s, router CPU | 16.7k, 2.45 s | 17.8k, 2.44 s (unchanged) |
| syscalls per delivered event (Linux, `strace -c`) | about 2.5 | about 0.35 (sends carry 4-5 frames each) |
| syscalls per RPC call | 7.0 (2.0 sendto, 3.0 recvfrom, 2.0 epoll_wait) | 4.6 (1.3 sendmsg, 2.6 recvfrom, 0.7 epoll_wait) |

**0.3 (direct CBOR codec) is also done** (`include/cbor.hpp`; the hot-path messages in `wamp_serializer.hpp` no longer build an
`nlohmann::json` tree; HELLO/WELCOME/GOODBYE/ABORT/CHALLENGE/AUTHENTICATE still do, once per session). The bytes on the wire are
identical to what nlohmann produced (tests compare them byte for byte; map keys are written sorted). Measured, same harness:

| | before | after |
|---|---|---|
| serialize CALL/EVENT/RESULT, 10 args + kw | 1.9-2.8 us | 0.27-0.38 us |
| deserialize the same | 4.5-5.1 us | 0.82-0.93 us |
| CALL -> INVOCATION -> YIELD -> RESULT through the handlers | 12.5 us | 3.5 us |
| RPC, 10 callers: throughput / router CPU | 17.8k calls/s / 2.20 s | 29.0k calls/s / 1.42 s (-35%) |
| PubSub, 10 subscribers unpaced: router CPU | 1.66 s | 0.57 s (-65%) |
| PubSub, 100 subscribers paced: router CPU, p50 | 6.9 s, 2.0 ms | 5.0 s, 0.41 ms |

(The load generator uses the same codec in `WampClient`, so its own overhead also dropped; the router CPU rows are the reliable ones.)

The reader/writer gain shows up where events queue up behind each other (fan-out, bursts). A paced publisher with one event per subscriber per
millisecond has nothing to coalesce, so those workloads gain only the removed read cancel/re-arm. RPC is unchanged because its
messages are strictly request/response.

1. **(done)** **Split each session into a reader coroutine and a writer coroutine.** The writer waits on the queue, drains everything that is
   ready and writes it with one gathered `async_write` (`writev`). This removes the read cancel/re-arm, the EAGAIN `recv` per
   event, and turns N back-to-back events into one syscall. Expected: syscalls per delivered event from about 2.5 to 1/batch +
   small; the kernel half of the PubSub cost drops by roughly a third to a half under load. It also removes the `parallel_group`
   machinery (about 11% of PubSub CPU).
2. **(done)** **Shrink the per-session buffer.** Plain sockets wait for readability and then read into one 64 KiB scratch buffer shared by the thread's sessions (TLS keeps a 4 KiB per-session buffer): idle session RSS 11.0 KB -> 4.5 KB (-59%, macOS, 5,000 sessions), and the failed speculative `recv` per read is gone (RPC router CPU 2.44 s -> 2.20 s).
3. **(done)** **Replace nlohmann CBOR** with a purpose-built reader/writer for the WAMP message shapes (decode straight into `WampList`/
   `WampDict`, encode straight into the frame buffer; no `json` tree): CBOR is a third of RPC user time, and the README shows
   4.5-5 us to decode a 10-argument message.
4. **(measured, skipped)** Recycle frame buffers (pool) instead of `make_shared<vector>` per frame. After the codec work the Linux
   profile shows allocation at 2.3% (RPC) and 2.1% (fan-out) of router CPU, and the whole CBOR codec at 0.4% / 0.3% (it was 10% /
   3%; nlohmann no longer appears on the hot path). A pool could win at most that 2%, and the pooled `shared_ptr` deleter would add
   atomic work on the cross-core path the threaded design needs. Not worth the complexity; revisit if a later profile shows
   allocation growing.
5. **(measured, rejected)** Asio's io_uring backend (`BOOST_ASIO_HAS_IO_URING` + `BOOST_ASIO_DISABLE_EPOLL`, liburing, Linux 5.10
   VM, router and load generator both built with it; needs `--ulimit memlock=-1` and a seccomp profile that allows io_uring):

   | | epoll | io_uring |
   |---|---|---|
   | RPC, 10 callers: calls/s, router CPU (user + sys) | 11.3k, 0.79 + 3.15 s | 6.7k, 0.89 + 5.75 s |
   | PubSub, 10 subscribers unpaced: events/s, router CPU | 27.2k, 1.7 + 7.4 s | 21.6k, 1.3 + 10.6 s |

   io_uring was 40% slower on RPC and used 50-80% more kernel time. Asio submits one ring operation per socket read/write and does
   not use the features that make io_uring pay off (multishot receive, registered buffers, batched submission across sockets), so
   on many small messages it only adds ring overhead. Not worth enabling; revisit only with a hand-written io_uring transport
   (not through Asio) and on a newer kernel and bare metal, where it could differ.

### Stage 1: a `Shard` object instead of process-wide statics

**Status: done** (`include/shard.hpp`). `EventChannelRegistry`, `InvocationTracker`, `RealmRegistry`, the id generators and the call-timeout settings now live in a `Shard` that each server owns and passes to its sessions, handlers and sweeper; `Realm` keeps a reference to its shard. Nothing mutable is process-wide any more (only a `thread_local` read scratch buffer, which is per-thread by design). Two servers in one process share no state (test), and `N=1` behaviour and performance are unchanged. The original plan:

Move everything that is global today into one `Shard` that is passed by reference: `EventChannelRegistry` (channels, strikes,
blocked-send list, drop counter), `InvocationTracker`, `RealmRegistry` and its `Realm`s, ID generators, call sweeper, and the
`ProcedureHandler` settings. The session holds a `Shard&`. With one shard this is a behaviour-neutral refactor (and it makes the
unit tests independent of process-wide state). It is the prerequisite for everything below and the riskiest mechanical step.

### Stage 2: N shards, one thread each

**Status: done, behind `[server] threads` (default 1)** (`include/router.hpp`). The acceptor hands each connection to the shard with the fewest sessions by passing the socket's native handle to that shard's `io_context`; the whole session (TLS handshake included) then runs there. Verified with ThreadSanitizer (the full test suite is clean) and with self-contained load (`wamp_load --mode selfrpc|selfpubsub`, where every client registers/subscribes only to its own names). **Cross-shard delivery is not implemented**, so with more than one thread a publish reaches only subscribers on the publisher's shard and a CALL finds only callees on the caller's shard: the router warns at startup and `threads` stays 1 by default. Plan as designed:

* **Thread count:** the number of cores the container may actually use, from the cgroup (`cpu.max` on cgroup v2,
  `cpu.cfs_quota_us` on v1; `hardware_concurrency()` ignores quotas), overridable in config (`[server] threads`).
  Take it from `detect_cpu_limits()` (cgroup quota, affinity, ECS task metadata). Pin threads to CPUs only when the container has a `cpuset`; do not busy-poll under a CFS quota (throttling ruins tail latency).
* **Accepting:** one acceptor assigns each new socket to the least-loaded shard and `post`s it there; the TLS handshake and the
  whole session then run on that shard's thread. An accept is 11-25 us against a 0.5-1.1 ms handshake, so a single acceptor is not
  a bottleneck, and it balances better than `SO_REUSEPORT` hashing, which can leave cores idle when connections are few and long
  lived. `SO_REUSEPORT` stays an option for very high accept rates.
* **Lanes:** one bounded SPSC queue per ordered pair (source shard, destination shard), carrying small message structs. The
  consumer drains its lanes in a posted task and only the empty-to-non-empty transition wakes it (eventfd / `post`), so a busy
  pair does not pay one wake-up per message. Per-publisher ordering follows from FIFO per lane: all of one session's traffic to a
  given shard uses the same lane.

**Scaling measurement (AWS c7i.4xlarge router pinned to 1/2/4 physical cores, 4 x c7i.2xlarge generators running 28 `wamp_load` processes, 1,120 caller clients, plain TCP, self-contained sessions):**

| router threads | RPC calls/s | RPC router CPU per call | self-pubsub publishes/s (each delivered once) | pubsub CPU per publish |
|---|---|---|---|---|
| 1 | 60.2k | 16.7 us | 87.4k | 11.5 us |
| 2 | 132.2k (2.2x) | 15.1 us | 166.9k (1.9x) | 12.0 us |
| 4 | 220.7k (3.7x) | 15.9 us | 258.6k (3.0x) | 13.2 us |

CPU per operation stays flat (whole-run `/proc` tick deltas), so the shards do not contend: there is no shared mutable state to fight over. The 1-thread RPC figure is below the 100-118k calls/s of the earlier single-callee runs because here 1,120 connections share one core. The 4-thread pubsub row is likely limited by the generators (7 processes on 4 cores each) rather than the router, so 3.0x is a floor. No events were lost (160,000 / 160,000 received per generator).

### Stage 3: pub/sub across shards

**Status: done** (`include/shard_group.hpp`, `PubSubHandler`). Built as designed below with three simplifications, each chosen because it is simpler and still keeps the guarantees:

* **Interest replicas are updated directly, not by acknowledged broadcast.** The shard whose first local subscriber to a topic appears (or whose last one goes) locks each other shard's replica in turn and edits it before its own SUBSCRIBED/UNSUBSCRIBED is sent. That gives the same "subscribed means later publishes are seen" guarantee with no round trip. A replica's mutex is taken by its owner on every publish and by other shards only on those rare changes, so in steady state it is an uncontended lock on a cache line only that shard writes; only one such lock is held at a time (no deadlock).
* **Inbox = mutex-protected vector per shard instead of SPSC rings.** The sender wakes the destination only when its inbox was idle, so a burst costs one wake-up (the 33-60 ns batched hand-off measured above). Messages from one shard to another keep their order, so per-publisher, per-topic ordering holds. The inbox is capped at 65,536 messages; beyond that events are dropped and counted (`Router::dropped_events()`).
* **Backpressure:** the destination's drain coroutine delivers with the normal overflow policy and then waits (bounded by `backpressure_timeout_ms`) for parked sends, so a slow subscriber stalls its shard's inbox rather than growing memory; the inbox cap then bounds the damage.

Each PUBLISH is serialized once on the publishing shard and the immutable `EventTemplate` is shared (one refcount per interested shard, not per subscriber).

Every shard keeps a **private** `Realm` per realm name with its local subscribers, plus an **interest table** (topic -> set of
shards that have at least one subscriber). A PUBLISH on shard A:

1. looks up the interest table (local, no locking), serializes the EVENT frame template once as today,
2. sends one message per *interested remote shard* (not per subscriber), carrying a copy of the frame (clone up to about 4 KiB;
   above that share an immutable buffer with one atomic reference per shard-message, never per subscriber),
3. fans out to its own local subscribers, and each remote shard fans out to its own local subscribers.

Subscribe/unsubscribe changes the local table and broadcasts an interest delta to all shards; SUBSCRIBED is sent after every shard
has acknowledged (rare operation, one lane round trip), which preserves "subscribed means later publishes will be seen".
Rejected alternative: **topic ownership by hash**: adds a hop to every publish, serializes a hot topic on one core, and the
subscriber-per-core index is needed anyway for the final fan-out.

Slow-subscriber strikes, queue sizes and the drop policy stay per session on the shard that owns the subscriber. Lanes are
bounded: when a lane to shard B is full the publishing session pauses reading (the existing backpressure mechanism, with the lane
as the thing it waits on), so cross-core traffic cannot grow without bound.

**Fan-out measurement (AWS c7i.4xlarge router pinned to 1/2/4 cores, 4 x c7i.2xlarge generators, 28 `wamp_load --mode pubsub` processes: 28 topics, each with 1 unpaced publisher and 10 subscribers, so connections and publishers are spread over every shard and each publish crosses shards; 11.2M deliveries per run):**

| router threads | deliveries/s | router CPU per delivery | lost |
|---|---|---|---|
| 1 | 278k | 3.6 us | 0 |
| 2 | 570-590k (2.1x) | 4.0 us | 0 (one of four runs lost 6% on one generator, not reproduced and not explained) |
| 4 | 0.92-1.18M (3.3-4.2x) | 3.7-4.0 us | 0 |

Throughput is computed from the slowest generator's duration, so the 4-thread range reflects uneven generator finish times, not router noise. CPU per delivery rises about 10% over one thread (the inbox hand-off and the extra serialization-free template sharing), which is the whole cross-shard cost at this fan-out; there was no sign of inbox mutex contention (the mutex-vs-SPSC-ring question stays open but is not worth pursuing from this data).

**Finding: the first version lost events.** With no flow control between shards the same run at 4 threads lost about 55% of events (2.4M messages dropped at the inbox cap), because a publisher on one shard was never slowed by subscribers on another, unlike on a single shard where a full subscriber queue pauses the publisher. Fix: an inbox above a high-water mark (4,096 messages) is reported back to the publishing session, which stops reading its socket until the inbox falls under a low-water mark (2,048) or `backpressure_timeout_ms` passes (`ShardGroup::wait_for_room`). The inbox cap (65,536) stays as the hard limit and `wamp_profile_router` now prints drop counts (`Router::inbox_dropped_events()`).

### Stage 4: RPC across shards

* **Registrations:** replicated like interest, because they change rarely. The "one registration per procedure" rule needs one
  arbiter: send REGISTER to the shard that owns `hash(realm, procedure)`, which grants or rejects and then broadcasts the new
  registration; REGISTERED is sent after all shards acknowledged.
* **CALL on shard A:** the replicated table gives the callee's shard B. A sends a `Call` message on lane A to B (caller shard,
  caller session, request id, payload). **B owns the pending call**: invocation ids carry the shard number in their high bits, so
  the YIELD (which arrives on B, the callee's own session) finds its record in B's local tracker with no lookup elsewhere. B
  sends INVOCATION to the callee, and on YIELD sends a `Result` message on lane B to A, which writes RESULT to the caller.
* **Timeouts and INTERRUPT:** B sweeps its own tracker and tells A to send `wamp.error.timeout`; the existing 50 ms sweeper becomes
  per shard. Caller disconnect sends a `Cancel` to B so the pending record is dropped; callee disconnect fails the calls it owns,
  as today.
* **IDs:** per-shard ranges (shard number in the high bits) replace the shared atomic generators; no coordination.

### Stage 5: everything else that touches shared state

Per-shard counters aggregated on read (dropped events, active sessions), asynchronous or per-shard logging so a slow sink does not
stall a core, graceful shutdown that stops acceptors then drains lanes, and config reload (still "restart to change").

## Expected gains and risks

| Stage | Expected gain | Risk |
|---|---|---|
| 0.1 reader/writer split + writev | about 1.3-1.6x on fan-out; fewer syscalls on RPC | low |
| 0.2 smaller buffer | about 70% less memory per idle session | low |
| 0.3 custom CBOR + 0.4 buffer pool | about 1.2-1.4x on RPC (CBOR is a third of user time) | medium (new codec needs a fuzz/round-trip test suite) |
| 1 `Shard` refactor | none by itself | medium (touches every static) |
| 2-4 N shards | near-linear in cores for session-local work: projected 3-3.5x on 4 cores for RPC and fan-out, N-fold handshake rate for reconnect storms | high (concurrency; needs ordering tests and TSAN) |

These are projections from the profile, not measurements of a threaded router. Because the cross-core cost per message (30-60
ns) is two orders of magnitude below the per-message work, the dominant uncertainty is bare-metal syscall cost, which only
changes how much Stage 0 buys, not whether the design scales.

## What to do before building Stage 2

1. Reproduce the profile on bare-metal or a normal Linux VM (kernel symbols and a real syscall cost), with the load generator on
   separate hardware.
2. Implement Stage 0.1 and re-measure; it changes the profile, and the answer may shift how many cores a given load needs.
3. Add a multi-process/multi-host mode to `wamp_load` so the load generator is not the bottleneck (it shares a single thread across
   all clients today).
4. Decide the supported guarantees explicitly (per-publisher, per-topic ordering; subscribe-then-publish visibility) and write the
   ordering tests first.
