// Copyright 2026 Pete Matern
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


// Cost of the primitives a thread-per-core router would use to move a frame between cores:
//
//   cmake --build build-local-release --target wamp_handoff_bench && ./build-local-release/wamp_handoff_bench
//
// Each test moves N `shared_ptr<vector<uint8_t>>` frames (the type EventToSend carries today) from a
// producer thread to a consumer thread and reports throughput and the producer-side cost per message.
// Also: refcount traffic when several threads copy/destroy one shared frame, and the price of cloning
// a frame instead of sharing it.

#include <asio.hpp>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;
using Frame = std::shared_ptr<std::vector<uint8_t>>;

namespace {

constexpr size_t kMessages = 2'000'000;

double seconds(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}

void report(const char* name, double secs, size_t n) {
    std::printf("%-46s %8.1f ns/msg  %6.2f M msg/s\n", name, secs / static_cast<double>(n) * 1e9,
                static_cast<double>(n) / secs / 1e6);
}

Frame make_frame(size_t bytes) {
    return std::make_shared<std::vector<uint8_t>>(bytes, uint8_t{1});
}

// --- Mutex + deque, consumer woken by condition variable -------------------------------------
double mutex_queue(const Frame& frame, size_t n, size_t batch) {
    std::mutex m;
    std::condition_variable cv;
    std::deque<Frame> q;
    bool done = false;
    size_t received = 0;

    std::thread consumer([&] {
        std::deque<Frame> local;
        for (;;) {
            {
                std::unique_lock lock{m};
                cv.wait(lock, [&] { return !q.empty() || done; });
                local.swap(q);
                if (local.empty() && done) return;
            }
            received += local.size();
            local.clear();
        }
    });

    auto t0 = Clock::now();
    for (size_t i = 0; i < n; i += batch) {
        {
            std::lock_guard lock{m};
            for (size_t j = 0; j < batch; ++j) q.push_back(frame);
        }
        cv.notify_one();
    }
    {
        std::lock_guard lock{m};
        done = true;
    }
    cv.notify_one();
    consumer.join();
    auto t1 = Clock::now();
    return received == n ? seconds(t0, t1) : -1.0;
}

// --- Bounded SPSC ring, consumer spins -----------------------------------------------------------
class SpscRing {
public:
    explicit SpscRing(size_t capacity_pow2) : buf_(capacity_pow2), mask_(capacity_pow2 - 1) {}

    bool push(Frame f) {
        auto head = head_.load(std::memory_order_relaxed);
        if (head - tail_cache_ == buf_.size()) {
            tail_cache_ = tail_.load(std::memory_order_acquire);
            if (head - tail_cache_ == buf_.size()) return false;
        }
        buf_[head & mask_] = std::move(f);
        head_.store(head + 1, std::memory_order_release);
        return true;
    }

    bool pop(Frame& out) {
        auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_cache_) {
            head_cache_ = head_.load(std::memory_order_acquire);
            if (tail == head_cache_) return false;
        }
        out = std::move(buf_[tail & mask_]);
        tail_.store(tail + 1, std::memory_order_release);
        return true;
    }

private:
    std::vector<Frame> buf_;
    size_t mask_;
    alignas(64) std::atomic<size_t> head_{0};
    size_t tail_cache_{0};
    alignas(64) std::atomic<size_t> tail_{0};
    size_t head_cache_{0};
};

double spsc_ring(const Frame& frame, size_t n) {
    SpscRing ring{4096};
    std::atomic<size_t> received{0};
    std::thread consumer([&] {
        Frame f;
        size_t got = 0;
        while (got < n) {
            if (ring.pop(f)) { ++got; f.reset(); }
        }
        received = got;
    });

    auto t0 = Clock::now();
    for (size_t i = 0; i < n;) {
        if (ring.push(frame)) ++i;
    }
    consumer.join();
    auto t1 = Clock::now();
    return received == n ? seconds(t0, t1) : -1.0;
}

// --- asio::post from one io_context thread to another -------------------------------------------
double asio_post(const Frame& frame, size_t n, size_t batch) {
    asio::io_context target;
    auto guard = asio::make_work_guard(target);
    std::atomic<size_t> received{0};
    std::thread consumer([&] { target.run(); });

    auto t0 = Clock::now();
    for (size_t i = 0; i < n; i += batch) {
        // One post carries a batch, like draining a lane into the consumer's loop
        asio::post(target, [&received, batch, batch_frames = std::vector<Frame>(batch, frame)] {
            received.fetch_add(batch, std::memory_order_relaxed);
        });
    }
    guard.reset();
    consumer.join();
    auto t1 = Clock::now();
    return received == n ? seconds(t0, t1) : -1.0;
}

// --- shared_ptr refcount traffic ------------------------------------------------------------------
double refcount_contention(const Frame& frame, size_t threads, size_t per_thread) {
    std::atomic<bool> go{false};
    std::vector<std::thread> pool;
    auto t0 = Clock::now();
    for (size_t t = 0; t < threads; ++t) {
        pool.emplace_back([&] {
            while (!go.load(std::memory_order_acquire)) {}
            for (size_t i = 0; i < per_thread; ++i) {
                Frame copy = frame;          // atomic increment of a line shared by all threads
                asm volatile("" : : "r"(copy.get()) : "memory");
            }                                // atomic decrement
        });
    }
    t0 = Clock::now();
    go = true;
    for (auto& th : pool) th.join();
    return seconds(t0, Clock::now());
}

double clone_frame(size_t bytes, size_t n) {
    auto src = make_frame(bytes);
    size_t sink = 0;
    auto t0 = Clock::now();
    for (size_t i = 0; i < n; ++i) {
        auto copy = std::make_shared<std::vector<uint8_t>>(*src);
        sink += copy->back();
    }
    auto t1 = Clock::now();
    asm volatile("" : : "r"(sink));
    return seconds(t0, t1);
}

}  // namespace

int main() {
    std::printf("hardware threads: %u\n\n", std::thread::hardware_concurrency());
    auto frame = make_frame(200);

    std::puts("cross-thread handoff of a shared frame (producer -> consumer):");
    report("mutex+deque+condvar, batch 1", mutex_queue(frame, kMessages / 4, 1), kMessages / 4);
    report("mutex+deque+condvar, batch 16", mutex_queue(frame, kMessages, 16), kMessages);
    report("mutex+deque+condvar, batch 128", mutex_queue(frame, kMessages, 128), kMessages);
    report("SPSC ring (consumer spins)", spsc_ring(frame, kMessages), kMessages);
    report("asio::post, batch 1", asio_post(frame, kMessages / 4, 1), kMessages / 4);
    report("asio::post, batch 16", asio_post(frame, kMessages, 16), kMessages);
    report("asio::post, batch 128", asio_post(frame, kMessages, 128), kMessages);

    std::puts("\nshared_ptr copy+destroy of ONE frame on N threads (per operation):");
    for (size_t threads : {1, 2, 4}) {
        const size_t per = 5'000'000;
        // every thread does `per` operations concurrently, so wall time / per = cost per op per thread
        report(threads == 1 ? "1 thread" : threads == 2 ? "2 threads" : "4 threads",
               refcount_contention(frame, threads, per), per);
    }

    std::puts("\nclone a frame (make_shared<vector> copy) instead of sharing it:");
    for (size_t bytes : {128, 512, 4096, 65536}) {
        char label[48];
        std::snprintf(label, sizeof label, "%zu bytes", bytes);
        report(label, clone_frame(bytes, 1'000'000), 1'000'000);
    }
}
