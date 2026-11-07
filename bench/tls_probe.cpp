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


// What does TLS 1.3 cost the router per connection and per message?
//
//   cmake --build build-local-release --target wamp_tls_probe
//   ./build-local-release/wamp_tls_probe test_certs/cert.pem test_certs/key.pem
//
// A blocking server thread accepts connections and either completes a TLS 1.3 handshake or does
// nothing (plain), then reads fixed-size messages. Its *thread CPU time* is measured, so the numbers
// are what one router core pays, independent of the client threads that generate the load.

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using asio::ip::tcp;

namespace {

double thread_cpu_seconds() {
    timespec ts{};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) * 1e-9;
}

ssl::context make_server_ctx(const std::string& cert, const std::string& key) {
    ssl::context ctx{ssl::context::tlsv13_server};
    ctx.use_certificate_chain_file(cert);
    ctx.use_private_key_file(key, ssl::context::pem);
    return ctx;
}

// Server: handles `connections` connections one after another; per connection reads `messages`
// messages of `size` bytes and echoes nothing. Returns server-thread CPU seconds spent.
struct Result {
    double handshake_cpu = 0;  // seconds of server CPU in accept + handshake
    double data_cpu = 0;       // seconds of server CPU reading the messages
};

Result run(bool use_tls, const std::string& cert, const std::string& key, int connections, int messages, size_t size) {
    asio::io_context io;
    tcp::acceptor acceptor{io, tcp::endpoint{tcp::v4(), 0}};
    const auto port = acceptor.local_endpoint().port();
    auto server_ctx = make_server_ctx(cert, key);
    Result result;

    std::thread server([&] {
        for (int c = 0; c < connections; ++c) {
            double t0 = thread_cpu_seconds();
            tcp::socket sock{io};
            acceptor.accept(sock);
            sock.set_option(tcp::no_delay{true});
            std::vector<char> buf(size);
            if (use_tls) {
                ssl::stream<tcp::socket> stream{std::move(sock), server_ctx};
                stream.handshake(ssl::stream_base::server);
                double t1 = thread_cpu_seconds();
                result.handshake_cpu += t1 - t0;
                for (int m = 0; m < messages; ++m) asio::read(stream, asio::buffer(buf));
                result.data_cpu += thread_cpu_seconds() - t1;
            } else {
                double t1 = thread_cpu_seconds();
                result.handshake_cpu += t1 - t0;
                for (int m = 0; m < messages; ++m) asio::read(sock, asio::buffer(buf));
                result.data_cpu += thread_cpu_seconds() - t1;
            }
        }
    });

    ssl::context client_ctx{ssl::context::tlsv13_client};
    client_ctx.set_verify_mode(ssl::verify_none);
    std::vector<char> payload(size, 'x');
    for (int c = 0; c < connections; ++c) {
        tcp::socket sock{io};
        sock.connect(tcp::endpoint{asio::ip::make_address("127.0.0.1"), port});
        sock.set_option(tcp::no_delay{true});
        if (use_tls) {
            ssl::stream<tcp::socket> stream{std::move(sock), client_ctx};
            stream.handshake(ssl::stream_base::client);
            for (int m = 0; m < messages; ++m) asio::write(stream, asio::buffer(payload));
        } else {
            for (int m = 0; m < messages; ++m) asio::write(sock, asio::buffer(payload));
        }
    }
    server.join();
    return result;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::puts("usage: wamp_tls_probe <cert.pem> <key.pem>");
        return 1;
    }
    const std::string cert = argv[1], key = argv[2];

    const int handshakes = 300;
    auto plain = run(false, cert, key, handshakes, 0, 200);
    auto tls = run(true, cert, key, handshakes, 0, 200);
    std::printf("connection setup, server CPU per connection:\n");
    std::printf("  plain TCP accept        %8.1f us\n", plain.handshake_cpu / handshakes * 1e6);
    std::printf("  accept + TLS 1.3 hshake %8.1f us   (=> %.0f handshakes/s per core)\n",
                tls.handshake_cpu / handshakes * 1e6, handshakes / tls.handshake_cpu);

    for (size_t size : {200, 1024, 16384}) {
        const int conns = 4, msgs = 20000;
        auto p = run(false, cert, key, conns, msgs, size);
        auto t = run(true, cert, key, conns, msgs, size);
        const double n = static_cast<double>(conns) * msgs;
        std::printf("read %5zu-byte message, server CPU:  plain %6.2f us   TLS %6.2f us   (TLS adds %.2f us, x%.1f)\n",
                    size, p.data_cpu / n * 1e6, t.data_cpu / n * 1e6, (t.data_cpu - p.data_cpu) / n * 1e6,
                    t.data_cpu / p.data_cpu);
    }
}
