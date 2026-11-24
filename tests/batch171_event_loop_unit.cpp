#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

import std;
import capy;
import corosio;
import config;
import control_api;
import control_api.types;
import net.stream_datagram_reply;
import packet;
import platform.tun_bridge;
import cli.tun_event_wait;
import relay;
import relay.l3_mux;
import tcp.engine;
import tcp.table;

namespace {
    using namespace std::chrono_literals;

    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL [batch171]: " << msg << '\n';
            std::exit(1);
        }
    }

    struct Fd {
        int fd = -1;
        Fd() = default;
        explicit Fd(int f) noexcept : fd(f) {}
        ~Fd() { if (fd >= 0) ::close(fd); }
        Fd(Fd const&) = delete;
        auto operator=(Fd const&) -> Fd& = delete;
    };

    auto wait_readable(int fd, std::chrono::steady_clock::time_point dl) -> int {
        for (;;) {
            auto now = std::chrono::steady_clock::now();
            if (now >= dl) { errno = EAGAIN; return 0; }
            auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(dl - now).count();
            pollfd pfd{fd, POLLIN, 0};
            int r = ::poll(&pfd, 1, static_cast<int>(std::clamp<long long>(rem, 1, 1000)));
            if (r < 0 && errno == EINTR) continue;
            return r;
        }
    }

    auto recv_exact(int fd, void* dst, std::size_t n, std::chrono::milliseconds to = 1500ms) -> ssize_t {
        auto* out = static_cast<std::uint8_t*>(dst);
        auto dl = std::chrono::steady_clock::now() + to;
        for (std::size_t got = 0; got < n; ) {
            if (wait_readable(fd, dl) <= 0) return -1;
            auto r = ::recv(fd, out + got, n - got, MSG_DONTWAIT);
            if (r < 0) { if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue; return -1; }
            if (r == 0) return 0;
            got += static_cast<std::size_t>(r);
        }
        return static_cast<ssize_t>(n);
    }

    auto echo_session(corosio::tcp_socket sock) -> capy::task<> {
        std::array<char, 128> b{};
        auto [re, n] = co_await sock.read_some(capy::mutable_buffer(b.data(), b.size()));
        if (!re && n) (void)co_await sock.write_some(capy::const_buffer(b.data(), n));
    }

    auto echo_accept_loop(corosio::io_context& ctx, corosio::tcp_acceptor& acc, std::atomic<bool>& stop) -> capy::task<> {
        while (!stop) {
            auto [ec, s] = co_await acc.accept();
            if (ec) break;
            capy::run_async(ctx.get_executor())(echo_session(std::move(s)));
        }
    }

    auto socks5_echo(std::uint16_t proxy_port, std::uint16_t echo_port) -> bool {
        Fd c(::socket(AF_INET, SOCK_STREAM, 0));
        if (c.fd < 0) return false;
        sockaddr_in a{.sin_family = AF_INET, .sin_port = htons(proxy_port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
        if (::connect(c.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
        std::array<std::uint8_t, 3> greet{5, 1, 0};
        if (::send(c.fd, greet.data(), greet.size(), 0) != 3) return false;
        std::array<std::uint8_t, 2> gr{};
        if (recv_exact(c.fd, gr.data(), 2) != 2 || gr[0] != 5 || gr[1] != 0) return false;
        std::array<std::uint8_t, 10> req{5, 1, 0, 1, 127, 0, 0, 1,
            static_cast<std::uint8_t>(echo_port >> 8), static_cast<std::uint8_t>(echo_port)};
        if (::send(c.fd, req.data(), req.size(), 0) != 10) return false;
        std::array<std::uint8_t, 10> rep{};
        if (recv_exact(c.fd, rep.data(), 10) != 10 || rep[1] != 0) return false;
        if (::send(c.fd, "pong", 4, 0) != 4) return false;
        std::array<char, 8> buf{};
        return recv_exact(c.fd, buf.data(), 4) == 4 && std::string_view(buf.data(), 4) == "pong";
    }

    auto test_171a_shared_io_context() -> void {
        corosio::io_context echo_ctx;
        corosio::tcp_acceptor echo_acc(echo_ctx);
        require(!echo_acc.open() && !echo_acc.bind({corosio::ipv4_address::loopback(), 0}) && !echo_acc.listen(), "echo listen");
        auto echo_port = echo_acc.local_endpoint().port();
        std::atomic<bool> echo_stop{false};
        capy::run_async(echo_ctx.get_executor())(echo_accept_loop(echo_ctx, echo_acc, echo_stop));
        std::jthread echo_thr([&] { echo_ctx.run_for(5s); });

        auto sio = relay::make_shared_io_context();
        require(sio.has_value() && *sio, "make_shared_io_context");
        auto s1 = relay::Server::create_shared(**sio);
        auto s2 = relay::Server::create_shared(**sio);
        auto s3 = relay::Server::create_shared(**sio); // Never started / registered
        require(s1.has_value() && s2.has_value() && s3.has_value(), "create_shared");
        require((*s1)->uses_shared_context() && (*s2)->uses_shared_context(), "uses_shared_context");
        require((*s1)->set_indexed_routes({}, 0).has_value() && (*s2)->set_indexed_routes({}, 0).has_value(), "routes");

        auto p1 = (*s1)->start(0, relay::Inbound::socks5, 1);
        auto p2 = (*s2)->start(0, relay::Inbound::socks5, 1);
        require(p1.has_value() && p2.has_value(), "shared listeners start");

        std::atomic<bool> loop_pause{false}, loop_paused{false}, loop_stop{false};
        std::atomic<bool> s1_active{true}, s2_active{true};
        std::jthread io_thr([&] {
            while (!loop_stop.load(std::memory_order_acquire)) {
                if (loop_pause.load(std::memory_order_acquire)) {
                    loop_paused.store(true, std::memory_order_release);
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                loop_paused.store(false, std::memory_order_release);
                if (s1_active) (void)(*s1)->prepare_poll();
                if (s2_active) (void)(*s2)->prepare_poll();
                (*sio)->restart();
                (void)(*sio)->run_for(5ms);
                auto now = std::chrono::steady_clock::now();
                if (s1_active) (*s1)->finish_poll(now, false);
                if (s2_active) (*s2)->finish_poll(now, true);
            }
        });

        require(socks5_echo(*p1, echo_port), "shared listener 1 works");
        require(socks5_echo(*p2, echo_port), "shared listener 2 works");

        // Destroying an unregistered shared Server must not stop shared_io or poison s1/s2.
        s3->reset();
        require((*s1)->healthy() && (*s2)->healthy(), "unregistered shared stop keeps peers healthy");
        require(socks5_echo(*p1, echo_port) && socks5_echo(*p2, echo_port), "peers still proxy after unregistered teardown");

        // Stop s1 cleanly while s2 continues serving on the same shared io_context.
        loop_pause.store(true, std::memory_order_release);
        while (!loop_paused.load(std::memory_order_acquire)) std::this_thread::sleep_for(1ms);
        s1_active = false;
        (*s1)->stop();
        s1->reset();
        loop_pause.store(false, std::memory_order_release);

        require((*s2)->healthy(), "s2 remains healthy after s1 stop");
        require(socks5_echo(*p2, echo_port), "s2 still proxies after s1 stop");

        loop_pause.store(true, std::memory_order_release);
        while (!loop_paused.load(std::memory_order_acquire)) std::this_thread::sleep_for(1ms);
        s2_active = false;
        (*s2)->stop();
        s2->reset();
        loop_stop.store(true, std::memory_order_release);
        io_thr.join();

        echo_stop = true; echo_ctx.stop(); echo_thr.join(); echo_acc.close();
    }

    auto test_171b_control_http_lazy_and_sse() -> void {
        control_api::HttpControlServer http;
        require(http.start(config::ControlHttpConfig{.host = "127.0.0.1", .port = 0}).has_value(), "http start");
        int lfd = http.listen_native_fd();
        require(lfd >= 0, "listen_native_fd >= 0");
        require(!http.next_poll_delay().has_value(), "idle next_poll_delay nullopt");

        sockaddr_in addr{}; socklen_t len = sizeof(addr);
        require(::getsockname(lfd, reinterpret_cast<sockaddr*>(&addr), &len) == 0, "getsockname http");
        auto http_port = ntohs(addr.sin_port);

        struct Tracker {
            int calls = 0;
            control_api::SnapshotFields last_fields{};
            std::optional<std::uint64_t> last_cid{};
        } tracker;

        auto build = [&](control_api::SnapshotFields fields, std::optional<std::uint64_t> cid) {
            ++tracker.calls;
            tracker.last_fields = fields;
            tracker.last_cid = cid;
            control_api::ControlSnapshot snap;
            snap.instance = "test";
            snap.route_mode = "global";
            snap.connections.push_back(control_api::ConnectionMetric{
                .id = 200, .listener = 0, .protocol = "socks5", .destination_port = 443, .target = "1.1.1.1:443", .can_close = true
            });
            return snap;
        };
        auto cmd = [&](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            if (!args.empty() && args[0] == "logs") return R"({"entries":[]})";
            return "ok";
        };

        auto direct = [&](std::string_view req) { return http.handle_direct_http_for_test(req, build, cmd); };
        require(direct("GET /v1/logs HTTP/1.1\r\nHost: x\r\n\r\n").starts_with("HTTP/1.1 200") && tracker.calls == 0, "/v1/logs 0 snaps");
        require(direct("POST /v1/reload HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n").starts_with("HTTP/1.1 202") && tracker.calls == 0, "/v1/reload 0 snaps");
        require(direct("DELETE /v1/connections/123 HTTP/1.1\r\nHost: x\r\n\r\n").starts_with("HTTP/1.1 200") && tracker.calls == 0, "DELETE conn 0 snaps");
        require(direct("PUT /v1/groups/auto HTTP/1.1\r\nHost: x\r\nContent-Length: 14\r\n\r\n{\"member\":\"a\"}").starts_with("HTTP/1.1 200") && tracker.calls == 0, "PUT group 0 snaps");

        auto mode_rep = direct("PUT /v1/mode HTTP/1.1\r\nHost: x\r\nContent-Length: 17\r\n\r\n{\"mode\":\"global\"}");
        require(mode_rep.starts_with("HTTP/1.1 200") && tracker.calls == 1, "PUT /v1/mode 1 snap after cmd");

        auto conn_rep = direct("GET /v1/connections/200 HTTP/1.1\r\nHost: x\r\n\r\n");
        require(conn_rep.starts_with("HTTP/1.1 200") && tracker.last_cid == std::optional<std::uint64_t>{200} && conn_rep.contains("\"id\":\"200\""), "GET /v1/connections/200 exact id");

        // Live SSE peer makes next_poll_delay bounded non-nullopt.
        Fd sse(::socket(AF_INET, SOCK_STREAM, 0));
        require(sse.fd >= 0 && ::connect(sse.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "sse connect");
        std::string_view sse_req = "GET /v1/logs?stream=1 HTTP/1.1\r\nHost: x\r\n\r\n";
        (void)::send(sse.fd, sse_req.data(), sse_req.size(), 0);
        for (int i = 0; i < 10 && !http.next_poll_delay().has_value(); ++i) {
            http.poll(build, cmd);
            std::this_thread::sleep_for(2ms);
        }
        require(http.next_poll_delay().has_value(), "SSE peer gives bounded next_poll_delay");
        http.stop();
        require(!http.active() && http.listen_native_fd() < 0, "http stop clears fd");
        (void)http_port;
    }

    auto test_171c_tun_engine_bridge_and_wait() -> void {
        // 1. tcp::MemoryEngine & MemoryEngine6 flush() populate report.id on delivery and stale drop.
        packet::MemoryLink link4({1500, 1, 4096});
        auto t4 = tcp::ConnectionTable::create(4, 32);
        require(t4.has_value(), "t4 create");
        tcp::MemoryEngine e4(link4, *t4, 1500);

        auto mk_syn4 = [](std::uint16_t sport, std::uint32_t seq) {
            packet::Tcp4View v{.source = {10,0,0,2}, .destination = {10,0,0,1}, .source_port = sport,
                .destination_port = 80, .sequence = seq, .flags = 0x02, .window = 65535};
            return packet::make_tcp4(v);
        };
        auto syn1 = mk_syn4(40001, 100);
        auto syn2 = mk_syn4(40002, 200);
        auto syn3 = mk_syn4(40003, 300);
        require(syn1 && syn2 && syn3, "mk_syn4");

        require(link4.send(packet::Side::first, *syn1).has_value(), "send syn1");
        auto s1 = e4.step(10, 1000);
        require(s1 && s1->delivered && s1->id.has_value(), "syn1 delivered SYN-ACK fills capacity=1");

        // Second SYN's SYN-ACK backpressures into pending_.
        require(link4.send(packet::Side::first, *syn2).has_value(), "send syn2");
        auto s2 = e4.step(20, 2000);
        require(s2 && s2->backpressured && s2->id.has_value(), "syn2 backpressured");
        auto expected_id2 = *s2->id;
        require(link4.receive(packet::Side::first).has_value(), "drain syn1 reply");
        auto s2_flush = e4.step(30, 3000);
        require(s2_flush && s2_flush->delivered && s2_flush->id == std::optional{expected_id2}, "v4 delivered flush sets report.id");

        // Third SYN -> backpressure -> abort before draining -> stale_reply sets report.id.
        require(link4.send(packet::Side::first, *syn3).has_value(), "send syn3");
        auto s3 = e4.step(40, 4000);
        require(s3 && s3->backpressured && s3->id.has_value(), "syn3 backpressured");
        auto expected_id3 = *s3->id;
        require(t4->abort(expected_id3), "abort id3");
        require(link4.receive(packet::Side::first).has_value(), "drain syn2 reply");
        auto s3_stale = e4.step(50, 5000);
        require(s3_stale && s3_stale->stale_reply && s3_stale->id == std::optional{expected_id3}, "v4 stale flush sets report.id");

        packet::MemoryLink link6({1500, 1, 4096});
        auto t6 = tcp::ConnectionTable6::create(4, 32);
        require(t6.has_value(), "t6 create");
        tcp::MemoryEngine6 e6(link6, *t6, 1500);
        auto mk_syn6 = [](std::uint16_t sport, std::uint32_t seq) {
            packet::Address6 src{}, dst{}; src[15] = 2; dst[15] = 1; src[0] = 0xfd; dst[0] = 0xfd;
            packet::Tcp6View v{.source = src, .destination = dst, .source_port = sport,
                .destination_port = 80, .sequence = seq, .flags = 0x02, .window = 65535};
            return packet::make_tcp6(v);
        };
        auto x1 = mk_syn6(41001, 100), x2 = mk_syn6(41002, 200);
        require(x1 && x2 && link6.send(packet::Side::first, *x1).has_value(), "send v6 syn1");
        require(e6.step(10, 1000).has_value() && link6.send(packet::Side::first, *x2).has_value(), "send v6 syn2");
        auto v6_bp = e6.step(20, 2000);
        require(v6_bp && v6_bp->backpressured && v6_bp->id.has_value(), "v6 backpressured");
        require(link6.receive(packet::Side::first).has_value(), "drain v6 syn1");
        auto v6_fl = e6.step(30, 3000);
        require(v6_fl && v6_fl->delivered && v6_fl->id == v6_bp->id, "v6 delivered flush sets report.id");

        // 2. ExternalTunBridge wake callback.
        std::atomic<int> wakes{0};
        platform::ExternalTunBridge bridge(1500);
        bridge.set_wake_callback([](void* c) noexcept { static_cast<std::atomic<int>*>(c)->fetch_add(1); }, &wakes);
        std::array<std::uint8_t, 20> fake_pkt{0x45};
        require(bridge.inject_packet(fake_pkt).has_value(), "inject_packet");
        require(wakes.load() >= 1, "inject_packet wakes bridge");
        bridge.close();
        require(wakes.load() >= 2, "close wakes bridge");
        bridge.set_wake_callback(nullptr, nullptr);

        // 3. TunEventWait pipe + Linux UDP epoll dispatch.
        corosio::io_context io;
        cli::tun_enabled::TunEventWait wait;
        wait.start(io, -1);
        wait.arm();
        wait.notify_async();
        io.restart();
        require(io.run_for(100ms) > 0, "TunEventWait notify_async wakes io_context");
        wait.drain_wake();

#if defined(__linux__)
        Fd udp_rx(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        Fd udp_tx(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        sockaddr_in uaddr{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(udp_rx.fd >= 0 && udp_tx.fd >= 0 && ::bind(udp_rx.fd, reinterpret_cast<sockaddr*>(&uaddr), sizeof(uaddr)) == 0, "udp bind");
        socklen_t ulen = sizeof(uaddr);
        require(::getsockname(udp_rx.fd, reinterpret_cast<sockaddr*>(&uaddr), &ulen) == 0, "udp getsockname");
        wait.watch_udp({udp_rx.fd, -1}, {false, true, 42});
        require(::sendto(udp_tx.fd, "ping", 4, 0, reinterpret_cast<sockaddr*>(&uaddr), sizeof(uaddr)) == 4, "udp sendto");
        std::vector<cli::tun_enabled::UdpWatchKey> ready_keys;
        require(wait.drain_ready_udp([&](cli::tun_enabled::UdpWatchKey k) { ready_keys.push_back(k); }), "drain_ready_udp");
        require(ready_keys.size() == 1 && !ready_keys[0].is_v6 && ready_keys[0].is_alias && ready_keys[0].flow == 42, "exact UdpWatchKey");
        wait.unwatch_udp({udp_rx.fd, -1});
#endif
        wait.stop();
    }

    auto wait_direct_coro(net::stream_datagrams::DirectSocketWait& wait, bool& ok) -> capy::task<> {
        ok = co_await wait.wait(false);
    }

    auto test_171d_direct_wait_and_l3_mux() -> void {
        corosio::io_context io;
        Fd rx(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        Fd tx(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        sockaddr_in uaddr{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(rx.fd >= 0 && tx.fd >= 0 && ::bind(rx.fd, reinterpret_cast<sockaddr*>(&uaddr), sizeof(uaddr)) == 0, "direct rx bind");
        socklen_t ulen = sizeof(uaddr);
        require(::getsockname(rx.fd, reinterpret_cast<sockaddr*>(&uaddr), &ulen) == 0, "direct rx name");

        net::stream_datagrams::DirectSocketWait wait(io);
        wait.watch({rx.fd, -1});
        bool ok = false;
        capy::run_async(io.get_executor())(wait_direct_coro(wait, ok));
        io.restart();
        (void)io.poll();
        require(::sendto(tx.fd, "hi", 2, 0, reinterpret_cast<sockaddr*>(&uaddr), sizeof(uaddr)) == 2, "direct sendto");
        (void)io.run_for(100ms);
        require(ok, "DirectSocketWait wakes on UDP datagram");
        wait.stop();
        (void)io.poll();

        auto noop_send = [](void*, std::span<std::uint8_t const>) -> bool { return true; };
        relay::L3Mux mux({true, {10, 0, 0, 2}, false, {}, 1420}, noop_send, nullptr);
        require(!mux.next_tick_ms(100).has_value(), "L3Mux idle next_tick_ms nullopt");
        auto flow = mux.open_tcp(corosio::endpoint(corosio::ipv4_address({1, 1, 1, 1}), 443), 12345, 100);
        require(flow != nullptr && mux.next_tick_ms(100) == std::optional<std::uint64_t>{1100}, "L3Mux syn_deadline exact");
        mux.reset_flows();
        require(!mux.next_tick_ms(100).has_value(), "L3Mux reset clears timer deadline");
    }
}

int main() {
    test_171a_shared_io_context();
    test_171b_control_http_lazy_and_sse();
    test_171c_tun_engine_bridge_and_wait();
    test_171d_direct_wait_and_l3_mux();
    std::cout << "batch171-event-loop-unit: ALL PASSED\n";
    return 0;
}
