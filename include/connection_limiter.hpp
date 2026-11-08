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


#pragma once

#include <asio/ip/address.hpp>
#include <sys/resource.h>
#include <cstddef>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace wamp {

// ============================================================================
// ConnectionLimiter - caps open connections, in total and per client address
// ============================================================================
// The acceptor admits a connection before handing it to a shard and the shard's session releases it when
// it ends, so the mutex is taken twice per connection lifetime, never on the message path. 0 = no limit.
class ConnectionLimiter {
public:
    enum class Result { ADMITTED, TOTAL_LIMIT, ADDRESS_LIMIT };

    ConnectionLimiter(size_t max_total, size_t max_per_address)
        : max_total_(max_total), max_per_address_(max_per_address) {}

    [[nodiscard]] Result admit(const asio::ip::address& address) {
        std::lock_guard lock{mutex_};
        if (max_total_ != 0 && total_ >= max_total_) return Result::TOTAL_LIMIT;
        if (max_per_address_ != 0) {
            auto& count = per_address_[address];
            if (count >= max_per_address_) return Result::ADDRESS_LIMIT;
            ++count;
        }
        ++total_;
        return Result::ADMITTED;
    }

    void release(const asio::ip::address& address) {
        std::lock_guard lock{mutex_};
        if (total_ > 0) --total_;
        if (max_per_address_ != 0) {
            if (auto it = per_address_.find(address); it != per_address_.end() && --it->second == 0) {
                per_address_.erase(it);
            }
        }
    }

    [[nodiscard]] size_t open() const {
        std::lock_guard lock{mutex_};
        return total_;
    }

    [[nodiscard]] size_t max_total() const { return max_total_; }
    [[nodiscard]] size_t max_per_address() const { return max_per_address_; }

private:
    size_t max_total_;
    size_t max_per_address_;
    mutable std::mutex mutex_;
    size_t total_{0};
    std::unordered_map<asio::ip::address, size_t> per_address_;
};

// Raises the soft limit on open files to the hard limit (capped at `cap`), because every connection costs a
// descriptor and many systems default to 256 or 1024. Returns the soft limit now in effect, nullopt if unlimited
// or unknown.
inline std::optional<size_t> raise_fd_limit(size_t cap = 1 << 20) {
    rlimit limit{};
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return std::nullopt;
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < limit.rlim_max) {
        rlimit wanted = limit;
        wanted.rlim_cur = (limit.rlim_max == RLIM_INFINITY || limit.rlim_max > cap) ? cap : limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &wanted) == 0) limit = wanted;
    }
    if (limit.rlim_cur == RLIM_INFINITY) return std::nullopt;
    return static_cast<size_t>(limit.rlim_cur);
}

// The connection cap used when [server] max_connections is "auto": the descriptor limit minus a reserve
// for the listening socket, log file, TLS and the like. 0 (no cap) if the limit is unlimited or unknown.
inline size_t auto_max_connections() {
    rlimit limit{};
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur == RLIM_INFINITY) return 0;
    constexpr size_t kReserve = 128;
    const auto soft = static_cast<size_t>(limit.rlim_cur);
    return soft > kReserve + 16 ? soft - kReserve : 16;
}

} // namespace wamp
