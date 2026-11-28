#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/capy/ex/run_async.hpp>

import std;
import capy;
import corosio;
import config;
import cli.proxy_ntp;
import cli.proxy_services;
import control_api;
import control_api.types;
import control_api.ssmapi;
import crypto;
import dns.message;
import dns.message_cache;
import dns.reverse;
import encoding.base64_key;
import logging;
import logging.cli;
import memory.watchdog;
import ntp;
import platform.socket_options;
import platform.wall_clock;
import reality.auth;
import reality.server_auth;
import relay;
import rules;
import shadowsocks.corosio_client;
import shadowsocks.frame;
import shadowsocks.key;
import shadowsocks.replay;
import shadowsocks.udp_client;
import ss_udp.inbounds;
import ss_udp.listener_ingress;
import tls.hello;
import tls.key_share;
import utility;

namespace {
    using namespace std::chrono_literals;

    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL [batch170]: " << msg << '\n';
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

    auto recv_exact(int fd, void* dst, std::size_t n, std::chrono::milliseconds to = 1000ms) -> ssize_t {
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

    auto recv_dgram_retry(int fd, void* dst, std::size_t cap, std::chrono::milliseconds to = 400ms) -> ssize_t {
        auto dl = std::chrono::steady_clock::now() + to;
        for (;;) {
            if (wait_readable(fd, dl) <= 0) return -1;
            auto r = ::recv(fd, dst, cap, MSG_DONTWAIT);
            if (r < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            return r;
        }
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

    auto ss_tcp_client_task(corosio::io_context& ctx, std::uint16_t ss_port, std::uint16_t echo_port,
        std::span<std::uint8_t const> u_psk, std::array<std::uint8_t, 32> i_psk32, std::string_view msg, bool& ok) -> capy::task<> {
        corosio::tcp_socket s(ctx);
        if (s.open()) co_return;
        auto dl = std::chrono::steady_clock::now() + 2s;
        auto [ce] = co_await corosio::timeout(s.connect({corosio::ipv4_address::loopback(), ss_port}), dl);
        if (ce) co_return;
        std::vector<std::uint8_t> addr{1, 127, 0, 0, 1, static_cast<std::uint8_t>(echo_port >> 8), static_cast<std::uint8_t>(echo_port)};
        std::array<std::array<std::uint8_t, 32>, 1> ids{i_psk32};
        auto st = co_await shadowsocks::detail::start_request(s, u_psk, addr, dl, ids);
        if (!st) co_return;
        shadowsocks::FrameEncoder enc(std::move(st->cipher));
        std::span<std::uint8_t const> p(reinterpret_cast<std::uint8_t const*>(msg.data()), msg.size());
        if (!co_await shadowsocks::detail::send_frame(s, enc, p, dl)) co_return;
        auto rx = co_await shadowsocks::detail::receive_response(s, u_psk, st->salt, dl);
        if (!rx) co_return;
        ok = std::string_view(reinterpret_cast<char const*>(rx->payload.data()), rx->payload.size()) == msg;
    }

    auto alloc_udp_port() -> std::uint16_t {
        Fd f(::socket(AF_INET, SOCK_DGRAM, 0));
        require(f.fd >= 0, "udp socket");
        sockaddr_in addr{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::bind(f.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "udp bind");
        socklen_t len = sizeof(addr);
        require(::getsockname(f.fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0, "udp getsockname");
        return ntohs(addr.sin_port);
    }

    auto test_170a_raii_reverse_teardown() -> void {
        std::vector<int> destroyed;
        struct Item {
            int id;
            std::vector<int>* log;
            ~Item() { log->push_back(id); }
        };
        {
            cli::OptionalServicesRuntime rt;
            rt.push_handle(cli::ServiceHandle::create(std::make_unique<Item>(1, &destroyed)));
            rt.push_handle(cli::ServiceHandle::create(std::make_unique<Item>(2, &destroyed)));
            rt.push_handle(cli::ServiceHandle::create(std::make_unique<Item>(3, &destroyed)));
            require(rt.active_count() == 3, "3 handles registered");
            rt.stop();
            require(rt.active_count() == 0, "cleared on stop");
            require((destroyed == std::vector<int>{3, 2, 1}), "strict LIFO reverse destruction order");
        }
        // Rollback when watchdog succeeds and a later service fails validation.
        logging::Runtime logs;
        cli::OptionalServicesRuntime rt;
        auto shed = std::make_shared<std::atomic_bool>(true);
        config::ServicesConfig cfg{};
        cfg.memory_watchdog = config::MemoryWatchdogConfig{};
        cfg.tor = config::TorServiceConfig{.socks_host = "198.51.100.1", .allow_remote_socks = false};
        auto res = rt.start(cfg, logs, {.watchdog = {shed, {}}});
        require(!res.has_value() && rt.active_count() == 0 && !shed->load(), "partial failure rolls back watchdog");
    }

    auto test_170b_watchdog_and_reclaim() -> void {
        std::vector<memory::PressureLevel> seen;
        memory::MemoryWatchdog wd(memory::WatchdogPolicy::ios_ne_50mib());
        constexpr std::uint64_t MiB = 1024ull * 1024ull;
        require(wd.evaluate(20 * MiB, 1000, [&](auto l) { seen.push_back(l); }) == memory::PressureLevel::normal, "normal");
        require(wd.evaluate(38 * MiB, 2000, [&](auto l) { seen.push_back(l); }) == memory::PressureLevel::soft, "soft");
        require(wd.evaluate(49 * MiB, 2500, [&](auto l) { seen.push_back(l); }) == memory::PressureLevel::emergency, "emergency");
        require(!wd.should_admit_new_session(), "emergency rejects new sessions");
        require(wd.evaluate(20 * MiB, 2600, [&](auto l) { seen.push_back(l); }) == memory::PressureLevel::normal, "recover normal");
        require(wd.should_admit_new_session(), "recovered admits sessions");
        // Cooldown was reset on normal, so soft immediately triggers again at t=2700 (< cooldown).
        require(wd.evaluate(38 * MiB, 2700, [&](auto l) { seen.push_back(l); }) == memory::PressureLevel::soft, "re-escalate");
        require(seen.size() == 4 && seen[2] == memory::PressureLevel::normal && seen[3] == memory::PressureLevel::soft, "normal callback & re-arm");

        // Cache reclaim helpers.
        dns::MessageCache mc(std::chrono::seconds(0), 64);
        mc.clear_entries();
        require(mc.entry_count() == 0, "message cache empty");
        dns::ReverseCache rc(64, 1, {0x11, 0x22});
        std::array<dns::Address, 1> addrs{dns::Address{{1, 2, 3, 4}, 4}};
        require(rc.record(0, "a.example", addrs, 60, 1000, rc.token()) == dns::ReverseRecord::stored, "rev store");
        require(rc.clear(), "rev clear");
        require(!rc.lookup(0, addrs[0], 1001).has_value(), "rev cleared");

        // Live Server emergency shed + recovery + reclaim.
        corosio::io_context echo_ctx;
        corosio::tcp_acceptor echo_acc(echo_ctx);
        require(!echo_acc.open() && !echo_acc.bind(corosio::endpoint(corosio::ipv4_address::loopback(), 0)) && !echo_acc.listen(), "echo listen");
        auto echo_port = echo_acc.local_endpoint().port();
        std::atomic<bool> stop{false};
        capy::run_async(echo_ctx.get_executor())(echo_accept_loop(echo_ctx, echo_acc, stop));
        std::jthread echo_thr([&] { echo_ctx.run_for(5s); });

        auto srv = relay::Server::create();
        require(srv.has_value(), "srv create");
        require((*srv)->set_indexed_routes({}, 0).has_value(), "srv routes");
        auto shed = std::make_shared<std::atomic_bool>(true);
        (*srv)->set_memory_shed(shed);
        auto listen_port = (*srv)->start(0, relay::Inbound::socks5, 1);
        require(listen_port.has_value(), "srv start");
        std::atomic<bool> srv_stop{false};
        std::jthread srv_thr([&] { while (!srv_stop) (*srv)->poll(5ms); (*srv)->stop(); });

        auto try_socks5 = [&](bool expect_ok) -> bool {
            Fd c(::socket(AF_INET, SOCK_STREAM, 0));
            if (c.fd < 0) return false;
            sockaddr_in a{.sin_family = AF_INET, .sin_port = htons(*listen_port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
            if (::connect(c.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return !expect_ok;
            std::array<std::uint8_t, 3> g{5, 1, 0};
            (void)::send(c.fd, g.data(), g.size(), 0);
            std::array<std::uint8_t, 2> gr{};
            errno = 0;
            auto gn = recv_exact(c.fd, gr.data(), gr.size());
            if (!expect_ok) return gn == 0 || (gn < 0 && (errno == ECONNRESET || errno == EPIPE));
            if (gn != 2 || gr[0] != 5 || gr[1] != 0) return false;
            std::array<std::uint8_t, 10> req{5, 1, 0, 1, 127, 0, 0, 1,
                static_cast<std::uint8_t>(echo_port >> 8), static_cast<std::uint8_t>(echo_port)};
            (void)::send(c.fd, req.data(), req.size(), 0);
            std::array<std::uint8_t, 10> rep{};
            if (recv_exact(c.fd, rep.data(), rep.size()) != 10 || rep[1] != 0) return false;
            (void)::send(c.fd, "ping", 4, 0);
            std::array<char, 8> buf{};
            auto rn = recv_exact(c.fd, buf.data(), 4);
            return rn == 4 && std::string_view(buf.data(), 4) == "ping";
        };

        require(try_socks5(false), "shedding drops new TCP sessions");
        shed->store(false, std::memory_order_release);
        (*srv)->request_memory_reclaim(2);
        std::this_thread::sleep_for(20ms);
        require(try_socks5(true), "recovery re-admits TCP sessions");

        srv_stop = true; srv_thr.join();
        stop = true; echo_ctx.stop(); echo_thr.join(); echo_acc.close();
    }

    auto test_170c_ntp_and_wall_clock() -> void {
        utility::scope_exit reset_clock([]() noexcept { ntp::global_calibrator().apply({0, 0, 1}); });
        utility::scope_exit reset_protect([]() noexcept { platform::set_protect_fd_callback(nullptr, nullptr); });

        // 1. Async non-blocking start & fast stop on blackhole UDP port.
        Fd bh(::socket(AF_INET, SOCK_DGRAM, 0));
        sockaddr_in baddr{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::bind(bh.fd, reinterpret_cast<sockaddr*>(&baddr), sizeof(baddr)) == 0, "bh bind");
        socklen_t blen = sizeof(baddr);
        require(::getsockname(bh.fd, reinterpret_cast<sockaddr*>(&baddr), &blen) == 0, "bh name");

        logging::Runtime logs;
        cli::NtpRuntime ntp_rt;
        config::NtpConfig bh_cfg{.host = "127.0.0.1", .port = ntohs(baddr.sin_port), .interval_ms = 60000, .timeout_ms = 2000};
        auto t0 = std::chrono::steady_clock::now();
        require(ntp_rt.start(bh_cfg, logs).has_value(), "ntp async start");
        auto start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        require(start_ms < 200, "ntp start non-blocking");
        auto t1 = std::chrono::steady_clock::now();
        ntp_rt.stop();
        auto stop_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t1).count();
        require(stop_ms < 350, "ntp fast stop");

        // 2. invoke_protect_fd integration + mock SNTP response.
        struct ProtectState { std::atomic<int> calls{0}; std::atomic<int> rc{EPERM}; } pstate;
        platform::set_protect_fd_callback([](int fd, void* ctx) -> int {
            auto* s = static_cast<ProtectState*>(ctx);
            s->calls.fetch_add(1, std::memory_order_relaxed);
            return fd >= 0 ? s->rc.load(std::memory_order_relaxed) : EBADF;
        }, &pstate);
        auto denied = ntp::sync_once("127.0.0.1", ntohs(baddr.sin_port), 500);
        require(!denied.has_value() && denied.error() == ntp::SntpError::io_error && pstate.calls.load() == 1, "protect_fd failure aborts sync");

        std::atomic<bool> sstop{false};
        std::jthread mock_ntp([&] {
            pollfd pfd{bh.fd, POLLIN, 0};
            while (!sstop) {
                if (::poll(&pfd, 1, 10) <= 0) continue;
                std::array<std::uint8_t, 64> req{};
                sockaddr_in cli{}; socklen_t cl = sizeof(cli);
                if (::recvfrom(bh.fd, req.data(), req.size(), 0, reinterpret_cast<sockaddr*>(&cli), &cl) >= 48) {
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count() + 12000;
                    auto ts = ntp::unix_ms_to_ntp(now_ms);
                    std::array<std::uint8_t, 48> rep{};
                    rep[0] = 0x24; rep[1] = 2;
                    std::ranges::copy_n(req.data() + 40, 8, rep.data() + 24);
                    auto put = [&](std::size_t off, ntp::Timestamp t) {
                        rep[off] = static_cast<std::uint8_t>(t.seconds >> 24); rep[off+1] = static_cast<std::uint8_t>(t.seconds >> 16);
                        rep[off+2] = static_cast<std::uint8_t>(t.seconds >> 8); rep[off+3] = static_cast<std::uint8_t>(t.seconds);
                        rep[off+4] = static_cast<std::uint8_t>(t.fraction >> 24); rep[off+5] = static_cast<std::uint8_t>(t.fraction >> 16);
                        rep[off+6] = static_cast<std::uint8_t>(t.fraction >> 8); rep[off+7] = static_cast<std::uint8_t>(t.fraction);
                    };
                    put(32, ts); put(40, ts);
                    (void)::sendto(bh.fd, rep.data(), rep.size(), 0, reinterpret_cast<sockaddr*>(&cli), cl);
                }
            }
        });
        pstate.rc.store(0, std::memory_order_relaxed);
        auto sample = ntp::sync_once("127.0.0.1", ntohs(baddr.sin_port), 1500);
        sstop = true; mock_ntp.join();
        require(sample.has_value() && sample->offset_ms > 10000 && pstate.calls.load() == 2, "mock SNTP protected ok");

        // 3. Calibrator wired to SS-2022 & REALITY wall clock.
        ntp::global_calibrator().apply({60000, 5, 2});
        auto cal_s = static_cast<std::uint64_t>(platform::calibrated_wall_seconds());
        auto raw_s = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        require(cal_s >= raw_s + 58 && cal_s <= raw_s + 62, "calibrated_wall_seconds +60s");

        shadowsocks::ReplayTable rt(64);
        std::array<std::uint8_t, 16> s1{}, s2{1};
        require(rt.admit_current(s1, cal_s).has_value(), "SS-2022 uses calibrated wall clock");
        require(!rt.admit_current(s2, raw_s).has_value(), "uncalibrated timestamp rejected after +60s calibration");

        auto cli_k = *crypto::X25519Private::generate();
        auto srv_k = *crypto::X25519Private::generate();
        tls::ClientHello ch{}; ch.session_id.resize(32); ch.cipher_suites = {0x1301}; ch.compression_methods = {0};
        ch.extensions.push_back({0, {0, 12, 0, 0, 9, 'l','o','c','a','l','h','o','s','t'}});
        ch.extensions.push_back({43, {2, 3, 4}});
        auto cp = *cli_k.public_key();
        tls::KeyShareEntry ks{0x001d, crypto::Bytes(cp.begin(), cp.end())};
        ch.extensions.push_back({51, *tls::KeyShare::encode_client(std::span{&ks, 1})});
        auto body = *ch.encode();
        crypto::Bytes wire{1, static_cast<std::uint8_t>(body.size() >> 16), static_cast<std::uint8_t>(body.size() >> 8), static_cast<std::uint8_t>(body.size())};
        wire.insert(wire.end(), body.begin(), body.end());
        reality::Identity rid{{1, 2, 3}, static_cast<std::uint32_t>(cal_s), {1,2,3,4,5,6,7,8}};
        auto sealed = *reality::seal_client_hello(wire, cli_k, *srv_k.public_key(), rid);
        std::array names{std::string("localhost")}; std::array<std::array<std::uint8_t, 8>, 1> ids{rid.short_id};
        reality::ServerPolicy pol{names, ids, {{1,2,3}}, {{1,2,3}}, 10};
        require(reality::authenticate_server_hello(sealed.wire, srv_k, pol, static_cast<std::uint64_t>(platform::calibrated_wall_seconds())).has_value(), "REALITY calibrated ok");
    }

    auto test_170d_ssmapi_live_ss2022() -> void {
        // TCP & UDP echo servers on loopback.
        corosio::io_context echo_ctx;
        corosio::tcp_acceptor tcp_echo(echo_ctx);
        require(!tcp_echo.open() && !tcp_echo.bind(corosio::endpoint(corosio::ipv4_address::loopback(), 0)) && !tcp_echo.listen(), "tcp echo");
        auto tcp_echo_port = tcp_echo.local_endpoint().port();
        std::atomic<bool> stop{false};
        capy::run_async(echo_ctx.get_executor())(echo_accept_loop(echo_ctx, tcp_echo, stop));
        std::jthread echo_thr([&] { echo_ctx.run_for(10s); });

        Fd udp_echo(::socket(AF_INET, SOCK_DGRAM, 0));
        sockaddr_in ua{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::bind(udp_echo.fd, reinterpret_cast<sockaddr*>(&ua), sizeof(ua)) == 0, "udp echo bind");
        socklen_t ulen = sizeof(ua);
        require(::getsockname(udp_echo.fd, reinterpret_cast<sockaddr*>(&ua), &ulen) == 0, "udp echo name");
        auto udp_echo_port = ntohs(ua.sin_port);
        std::jthread uecho_thr([&] {
            pollfd pfd{udp_echo.fd, POLLIN, 0};
            std::array<char, 256> b{};
            while (!stop) {
                if (::poll(&pfd, 1, 10) <= 0) continue;
                sockaddr_in cli{}; socklen_t cl = sizeof(cli);
                if (auto n = ::recvfrom(udp_echo.fd, b.data(), b.size(), 0, reinterpret_cast<sockaddr*>(&cli), &cl); n > 0)
                    (void)::sendto(udp_echo.fd, b.data(), static_cast<std::size_t>(n), 0, reinterpret_cast<sockaddr*>(&cli), cl);
            }
        });

        std::array<std::uint8_t, 16> i_psk{}; i_psk.fill(0x55);
        std::array<std::uint8_t, 32> i_psk32{}; std::ranges::copy(i_psk, i_psk32.begin());
        auto dir = std::make_shared<relay::ShadowsocksUserDirectory>();

        // 1. SS-2022 TCP Server with ssmapi user directory.
        auto ss_tcp = relay::Server::create();
        require(ss_tcp.has_value(), "ss_tcp create");
        (*ss_tcp)->set_shadowsocks_dynamic_users(dir);
        require((*ss_tcp)->prepare_shadowsocks_inbound(i_psk).has_value(), "ss_tcp prep");
        require((*ss_tcp)->set_indexed_routes({}, 0).has_value(), "ss_tcp routes");
        auto ss_tcp_port = (*ss_tcp)->start(0, relay::Inbound::shadowsocks, 1);
        require(ss_tcp_port.has_value(), "ss_tcp start");
        std::jthread tcp_thr([&] { while (!stop) (*ss_tcp)->poll(5ms); (*ss_tcp)->stop(); });

        // 2. SS-2022 UDP Inbounds with dynamic base.
        relay::udp_runtime::UdpInbounds udp_in;
        auto pol = rules::RouteProgram::compile_policy({}, 0, 2);
        require(pol.has_value(), "udp pol");
        std::uint16_t ss_udp_port = alloc_udp_port();
        require(udp_in.add_dynamic_base(i_psk, ss_udp_port, *pol, nullptr, dir).has_value(), "add_dynamic_base");
        relay::DnsRouting drouting{{relay::DnsServer{}}, {}, 0};
        require(!udp_in.start(drouting), "udp_in start");
        std::mutex udp_mu;
        std::jthread udp_thr([&] { while (!stop) { std::lock_guard lk(udp_mu); udp_in.poll(5ms); std::this_thread::sleep_for(2ms); } udp_in.stop(); });

        // 3. HttpControlServer with ssmapi attached.
        control_api::HttpControlServer ctl;
        require(ctl.configure_ssmapi(true, "/ssmapi").has_value(), "ctl ssmapi");
        ctl.attach_ssmapi_users(dir);
        auto snap_fn = []() -> control_api::ControlSnapshot { return {}; };
        auto cmd_fn = [](std::span<std::string_view const>) -> std::expected<std::string, std::string> { return std::string{"ok"}; };
        auto http = [&](std::string_view method, std::string_view path, std::string_view body = {}) {
            std::string req = body.empty()
                ? std::format("{} {} HTTP/1.1\r\nHost: localhost\r\n\r\n", method, path)
                : std::format("{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}", method, path, body.size(), body);
            return ctl.handle_direct_http_for_test(req, snap_fn, cmd_fn);
        };

        std::array<std::uint8_t, 16> u_psk{}; u_psk.fill(0x01);
        constexpr std::string_view u_b64 = "AQEBAQEBAQEBAQEBAQEBAQ==";
        std::array<std::uint8_t, 16> chk{};
        require(encoding::decode_key(std::span<char const>(u_b64.data(), u_b64.size()), chk) && chk == u_psk, "b64 test vector");

        auto ss_tcp_roundtrip = [&](std::string_view msg) -> bool {
            corosio::io_context cctx;
            bool ok = false;
            capy::run_async(cctx.get_executor())(ss_tcp_client_task(cctx, *ss_tcp_port, tcp_echo_port, u_psk, i_psk32, msg, ok));
            cctx.run_for(3s);
            return ok;
        };

        auto ss_udp_roundtrip = [&](std::string_view msg) -> bool {
            std::array<std::uint8_t, 8> cid{}; require(crypto::random_bytes(cid).has_value(), "cid");
            shadowsocks::UdpClientSession cli(u_psk, cid, 4);
            std::array<std::uint8_t, 7> addr{1, 127, 0, 0, 1, static_cast<std::uint8_t>(udp_echo_port >> 8), static_cast<std::uint8_t>(udp_echo_port)};
            std::array<std::array<std::uint8_t, 32>, 1> ids{i_psk32};
            auto wall = static_cast<std::uint64_t>(platform::calibrated_wall_seconds());
            auto req = *cli.request(addr, {reinterpret_cast<std::uint8_t const*>(msg.data()), msg.size()}, {}, std::chrono::steady_clock::now(), wall, ids);
            Fd sock(::socket(AF_INET, SOCK_DGRAM, 0));
            sockaddr_in dst{.sin_family = AF_INET, .sin_port = htons(ss_udp_port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
            (void)::sendto(sock.fd, req.data(), req.size(), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
            std::array<std::uint8_t, 512> buf{};
            auto n = recv_dgram_retry(sock.fd, buf.data(), buf.size());
            if (n <= 0) return false;
            auto pkt = cli.receive(std::span(buf.data(), static_cast<std::size_t>(n)), std::chrono::steady_clock::now(), wall);
            return pkt && std::string_view(reinterpret_cast<char const*>(pkt->payload.data()), pkt->payload.size()) == msg;
        };

        // Before POST: both rejected.
        require(!ss_tcp_roundtrip("hello-170"), "TCP rejected before ssmapi POST");
        require(!ss_udp_roundtrip("udp-170"), "UDP rejected before ssmapi POST");

        // POST alice: both succeed without restart + byte/packet counters update.
        auto r_post = http("POST", "/ssmapi/users", std::format(R"({{"username":"alice","uPSK":"{}","enabled":true,"byteQuota":4096}})", u_b64));
        require(r_post.contains("201 Created"), "POST alice");
        std::this_thread::sleep_for(30ms);
        require(ss_tcp_roundtrip("hello-tcp-ssmapi!"), "TCP works immediately after ssmapi POST");
        require(ss_udp_roundtrip("hello-udp-ssmapi!"), "UDP works immediately after ssmapi POST");

        auto r_user = http("GET", "/ssmapi/users/alice");
        require(r_user.contains("200 OK") && !r_user.contains("\"uplinkBytes\":0") && !r_user.contains("\"downlinkBytes\":0") && !r_user.contains("\"uplinkPackets\":0"), "traffic & packets recorded");

        // PUT disable -> both rejected immediately.
        require(http("PUT", "/ssmapi/users/alice", std::format(R"({{"uPSK":"{}","enabled":false,"byteQuota":4096}})", u_b64)).contains("200 OK"), "PUT disable");
        std::this_thread::sleep_for(20ms);
        require(!ss_tcp_roundtrip("disabled"), "TCP rejected when disabled");
        require(!ss_udp_roundtrip("disabled"), "UDP rejected when disabled");

        // PUT re-enable with tiny quota < already-used bytes -> both rejected by quota.
        require(http("PUT", "/ssmapi/users/alice", std::format(R"({{"uPSK":"{}","enabled":true,"byteQuota":1}})", u_b64)).contains("200 OK"), "PUT quota");
        std::this_thread::sleep_for(20ms);
        require(!ss_tcp_roundtrip("over-quota"), "TCP rejected over quota");
        require(!ss_udp_roundtrip("over-quota"), "UDP rejected over quota");

        // DELETE alice -> 404 on GET & rejected.
        require(http("DELETE", "/ssmapi/users/alice").contains("204 No Content"), "DELETE alice");
        std::this_thread::sleep_for(20ms);
        require(http("GET", "/ssmapi/users/alice").contains("404 Not Found"), "GET after DELETE 404");

        stop = true; tcp_thr.join(); udp_thr.join(); uecho_thr.join(); echo_ctx.stop(); echo_thr.join(); tcp_echo.close();
    }

    auto test_170e_fail_closed_services() -> void {
        logging::Runtime logs;
        cli::OptionalServicesRuntime rt;
        // Invalid service configurations still fail closed cleanly without leaking handles.
        auto check_fail = [&](config::ServicesConfig const& c, std::string_view tag) {
            auto r = rt.start(c, logs);
            require(!r.has_value() && rt.active_count() == 0, tag);
        };
        { config::ServicesConfig c; c.acme = config::AcmeServiceConfig{}; check_fail(c, "acme invalid config"); }
        { config::ServicesConfig c; c.sni_demux = config::SniDemuxConfig{.listen_host = "not-an-ip", .listen_port = 0}; check_fail(c, "sni-demux invalid host"); }
        { config::ServicesConfig c; c.reverse_tunnel = config::ReverseTunnelServiceConfig{}; check_fail(c, "reverse-tunnel empty token"); }
        { config::ServicesConfig c; c.bridge = config::BridgeServiceConfig{.physical_interface = "nx_no_if99"}; check_fail(c, "bridge missing iface"); }
        { config::ServicesConfig c; c.tor = config::TorServiceConfig{.socks_host = "198.51.100.1", .allow_remote_socks = false}; check_fail(c, "tor remote socks rejected"); }
        { config::ServicesConfig c; c.derp_server = config::DerpServerServiceConfig{.listen_host = "not-an-ip"}; check_fail(c, "derp-server invalid host"); }
    }
}

int main() {
    test_170a_raii_reverse_teardown();
    test_170b_watchdog_and_reclaim();
    test_170c_ntp_and_wall_clock();
    test_170d_ssmapi_live_ss2022();
    test_170e_fail_closed_services();
    std::cout << "BATCH 170 SERVICES REAL WIRING & RAII TESTS PASSED\n";
    return 0;
}
