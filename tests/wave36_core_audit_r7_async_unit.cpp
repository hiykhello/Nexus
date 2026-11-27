#include <cstdio>
#include <cstdlib>
#if !defined(_WIN32)
#include <net/if.h>
#endif

import std;
import capy;
import corosio;
import config;
import dns.corosio_query;
import dns.dhcp_upstream;
import dns.input_budget;
import dns.message;
import cli.dns_transports;
import cli.proxy_ntp;
import logging.cli;
import ntp;
import packet;
import platform.ip_address;
import platform.wall_clock;
import tcp.connection;
import tcp.send;
import utility;

namespace {
    auto require(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::fprintf(stderr, "FAIL: %.*s\n", static_cast<int>(msg.size()), msg.data());
            std::exit(1);
        }
    }

    auto test_r7_p2_1_dhcp_ipv6_scope() -> void {
        // 1. Explicit %zone preserved and distinct zones do not collide.
        auto parsed = dns::parse_dhcp_lease_text(
            "DNS=192.168.1.1%eth0 fe80::1%eth0 fe80::1%lo 2001:4860:4860::8888\n");
        require(parsed.size() == 4, "P2-1: expected 4 entries with distinct v6 scopes");
        require(parsed[0].address.size == 4 && parsed[0].scope.empty(), "P2-1: IPv4 ignores scope");
        require(parsed[1].address.size == 16 && parsed[1].scope == "eth0", "P2-1: fe80::1%eth0 scope preserved");
        require(parsed[2].address.size == 16 && parsed[2].scope == "lo", "P2-1: fe80::1%lo distinct from %eth0");
        require(parsed[3].address.size == 16 && parsed[3].scope.empty(), "P2-1: global IPv6 keeps empty scope");

        // 2. Link-local IPv6 without %zone inherits block interface or configured interface_filter.
        constexpr std::string_view lease6_text =
            "lease6 {\n"
            "  option dhcp6.name-servers fe80::2, 2001:db8::53;\n"
            "  interface \"eth0\";\n"
            "}\n";
        auto v6_block = dns::parse_dhcp_lease_text(lease6_text, "eth0");
        require(v6_block.size() == 2, "P2-1: lease6 block yields 2 servers");
        require(v6_block[0].scope == "eth0", "P2-1: link-local inherits block interface even if declared after option");
        require(v6_block[1].scope.empty(), "P2-1: global v6 in lease6 does not gain link-local scope");

        auto flat_fallback = dns::parse_dhcp_lease_text("INTERFACE=lo\nDNS=fe80::3\n", "lo");
        require(flat_fallback.size() == 1 && flat_fallback[0].scope == "lo", "P2-1: flat link-local inherits INTERFACE");

        // 3. Scope ID resolution (numeric + real loopback interface + unknown rejection).
        require(dns::resolve_ipv6_scope_id("7") == 7u, "P2-1: numeric scope 7");
        require(dns::resolve_ipv6_scope_id("nexus_no_such_iface99") == 0u, "P2-1: unknown iface -> 0");

        auto ll_ip = *platform::parse_ip_address("fe80::1");
        require(dns::is_ipv6_link_local(ll_ip), "P2-1: fe80::1 is link-local");
        auto ep_num = cli::resolve_dhcp_endpoint(ll_ip, "7", {}, 53);
        require(ep_num.has_value() && ep_num->is_v6() && ep_num->address().to_v6().scope_id() == 7u && ep_num->port() == 53,
            "P2-1: numeric scope populates sin6_scope_id");
        auto ep_bad = cli::resolve_dhcp_endpoint(ll_ip, "nexus_no_such_iface99", {}, 53);
        require(!ep_bad.has_value(), "P2-1: unresolvable link-local scope rejected instead of zeroing");

#if !defined(_WIN32)
        unsigned lo_idx = ::if_nametoindex("lo");
        if (lo_idx == 0) lo_idx = ::if_nametoindex("lo0");
        std::string_view lo_name = ::if_nametoindex("lo") ? "lo" : "lo0";
        require(lo_idx != 0, "P2-1: loopback interface index exists");
        auto ep_fb = cli::resolve_dhcp_endpoint(ll_ip, {}, lo_name, 5353);
        require(ep_fb.has_value() && ep_fb->address().to_v6().scope_id() == lo_idx && ep_fb->port() == 5353,
            "P2-1: fallback interface resolves sin6_scope_id via if_nametoindex");
#endif
    }

    auto make_a_reply(std::span<std::uint8_t const> req, std::array<std::uint8_t, 4> ip) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> out(req.begin(), req.end());
        if (out.size() < 12) return {};
        out[2] = 0x81; out[3] = 0x80; // QR=1, RD=1, RA=1, NOERROR
        out[6] = 0x00; out[7] = 0x01; // ANCOUNT=1
        out[8] = 0x00; out[9] = 0x00; out[10] = 0x00; out[11] = 0x00;
        out.insert(out.end(), {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04});
        out.insert(out.end(), ip.begin(), ip.end());
        return out;
    }

    auto test_r7_p2_2_dhcp_async_staggered_fallback() -> void {
        corosio::io_context io;
        corosio::udp_socket dead1(io), dead2(io), live(io);
        auto lo = corosio::endpoint(corosio::ipv4_address::loopback(), 0);
        require(!dead1.open(lo.address().family()) && !dead1.bind(lo), "P2-2: dead1 bind");
        require(!dead2.open(lo.address().family()) && !dead2.bind(lo), "P2-2: dead2 bind");
        require(!live.open(lo.address().family()) && !live.bind(lo), "P2-2: live bind");

        auto dead1_ep = corosio::endpoint(corosio::ipv4_address::loopback(), dead1.local_endpoint().port());
        auto dead2_ep = corosio::endpoint(corosio::ipv4_address::loopback(), dead2.local_endpoint().port());
        auto live_ep = corosio::endpoint(corosio::ipv4_address::loopback(), live.local_endpoint().port());

        std::atomic<int> dead1_hits{0}, live_hits{0};
        std::stop_source srv_stop;

        auto dead_sink = [&]() -> capy::task<void> {
            std::array<std::uint8_t, 512> buf{};
            std::stop_callback cb(srv_stop.get_token(), [&]() noexcept { dead1.cancel(); });
            while (!srv_stop.stop_requested()) {
                corosio::endpoint peer{};
                auto [ec, n] = co_await dead1.recv_from(capy::mutable_buffer(buf.data(), buf.size()), peer);
                if (ec) break;
                if (n >= 12) dead1_hits.fetch_add(1, std::memory_order_relaxed);
            }
        };

        auto live_responder = [&]() -> capy::task<void> {
            std::array<std::uint8_t, 512> buf{};
            std::stop_callback cb(srv_stop.get_token(), [&]() noexcept { live.cancel(); });
            while (!srv_stop.stop_requested()) {
                corosio::endpoint peer{};
                auto [ec, n] = co_await live.recv_from(capy::mutable_buffer(buf.data(), buf.size()), peer);
                if (ec) break;
                if (n < 12) continue;
                live_hits.fetch_add(1, std::memory_order_relaxed);
                auto rep = make_a_reply(std::span(buf).first(n), {203, 0, 113, 42});
                (void)co_await live.send_to(capy::const_buffer(rep.data(), rep.size()), peer);
            }
        };

        bool fallback_ok = false, cancel_ok = false;
        auto client_test = [&]() -> capy::task<void> {
            dns::InputBudget budget(64 * 1024);
            dns::QueryMessage q{.id = 0x4242, .question = {.name = "example.test", .type = 1, .klass = 1}};

            // Case A: Primary silently drops all packets; secondary responds after stagger well under 2500ms deadline.
            std::array<corosio::endpoint, 2> eps{dead1_ep, live_ep};
            auto t0 = std::chrono::steady_clock::now();
            auto res = co_await cli::query_dhcp_endpoints(
                io, eps, q, 0x4242, t0 + std::chrono::milliseconds(2500), budget, {});
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
            require(res.has_value(), "P2-2: secondary DHCP DNS must succeed when primary drops");
            require(elapsed_ms < 1500, "P2-2: staggered fallback must complete well before 2500ms deadline");
            require(res->records.size() == 1 && res->records[0].type == 1 && res->records[0].data_length == 4 &&
                    res->records[0].data_offset + 4 <= res->wire.size() &&
                    res->wire[res->records[0].data_offset] == 203 &&
                    res->wire[res->records[0].data_offset + 3] == 42,
                "P2-2: response matches secondary A record 203.0.113.42");
            require(dead1_hits.load() >= 1 && live_hits.load() >= 1,
                "P2-2: primary was attempted first and secondary answered");
            fallback_ok = true;

            // Case B: External stop_token cancels all concurrent DHCP probes immediately.
            std::stop_source cancel_src;
            auto cancel_trigger = [&]() -> capy::task<void> {
                (void)co_await corosio::delay(std::chrono::milliseconds(80));
                cancel_src.request_stop();
            };
            capy::run_async(io.get_executor(), []() noexcept {}, [](std::exception_ptr) noexcept {})(cancel_trigger());
            std::array<corosio::endpoint, 2> dead_eps{dead1_ep, dead2_ep};
            auto t1 = std::chrono::steady_clock::now();
            auto cres = co_await cli::query_dhcp_endpoints(
                io, dead_eps, q, 0x4243, t1 + std::chrono::milliseconds(5000), budget, cancel_src.get_token());
            auto celapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t1).count();
            require(!cres.has_value() && cres.error() == dns::detail::UdpError::canceled,
                "P2-2: stop_token cancels concurrent DHCP queries");
            require(celapsed_ms < 600, "P2-2: cancellation returns promptly");
            cancel_ok = true;

            srv_stop.request_stop();
            dead1.close();
            dead2.close();
            live.close();
        };

        capy::run_async(io.get_executor(), []() noexcept {}, [](std::exception_ptr) noexcept {})(dead_sink());
        capy::run_async(io.get_executor(), []() noexcept {}, [](std::exception_ptr) noexcept {})(live_responder());
        capy::run_async(io.get_executor(), []() noexcept {}, [](std::exception_ptr) noexcept {})(client_test());
        io.run();
        require(fallback_ok && cancel_ok, "P2-2: all async DHCP fan-out assertions executed");
    }

    auto test_r7_p2_3_tcp_rfc5681_dupack() -> void {
        // 1. Direct TimedSend RFC 5681 §2 unit checks.
        auto ts = tcp::TimedSend::create(1000, 1024);
        require(ts.has_value(), "P2-3: TimedSend::create");
        std::array<std::uint8_t, 64> bytes{};
        bytes.fill(0x5au);
        ts->set_peer_window(4096);
        require(ts->enqueue(bytes).has_value() && ts->sent(64, 100).has_value(), "P2-3: send 64 bytes");

        // (a) 5 bidirectional data ACKs with unchanged ack & unchanged window -> NOT dup-ACKs.
        for (std::uint64_t i = 0; i < 5; ++i) {
            auto acked = ts->acknowledge(1000, 110 + i, true, 4096u);
            require(acked && *acked == 0, "P2-3: data ACK accepted");
        }
        require(ts->dup_acks() == 0 && !ts->fast_retransmit_pending(),
            "P2-3: bidirectional data segments must not count as dup-ACKs");

        // (b) 5 pure window updates with unchanged ack -> NOT dup-ACKs.
        for (std::uint32_t i = 1; i <= 5; ++i) {
            auto acked = ts->acknowledge(1000, 120 + i, false, 4096u + i * 1024u);
            require(acked && *acked == 0, "P2-3: window update accepted");
        }
        require(ts->dup_acks() == 0 && !ts->fast_retransmit_pending(),
            "P2-3: pure window updates must not count as dup-ACKs");
        auto early_due = ts->due(200, 64);
        require(early_due && !early_due->has_value(), "P2-3: no premature retransmit before RTO");

        // (c) 3 genuine empty duplicate ACKs with unchanged window (9216) -> MUST trigger fast retransmit!
        for (std::uint64_t i = 0; i < 2; ++i) {
            auto acked = ts->acknowledge(1000, 210 + i, false, 9216u);
            require(acked && *acked == 0 && !ts->fast_retransmit_pending(), "P2-3: 1-2 dup-ACKs do not trigger yet");
        }
        auto third = ts->acknowledge(1000, 215, false, 9216u);
        require(third && *third == 0 && ts->dup_acks() == 3 && ts->fast_retransmit_pending(),
            "P2-3: 3rd genuine empty dup-ACK triggers fast retransmit");
        auto fr_due = ts->due(215, 64);
        require(fr_due && fr_due->has_value() && (**fr_due).sequence == 1000 && (**fr_due).bytes.size() == 64,
            "P2-3: fast retransmit immediately returns unacked slice before RTO");

        // 2. End-to-end PassiveConnection check.
        packet::Tcp4View syn{.source = {10, 0, 0, 1}, .destination = {10, 0, 0, 2},
            .source_port = 40000, .destination_port = 443, .sequence = 100, .acknowledgement = 0,
            .flags = 0x02, .window = 4096};
        auto conn = tcp::PassiveConnection::accept(syn, 50, 4096, 10);
        require(conn.has_value(), "P2-3: PassiveConnection::accept");
        packet::Tcp4View hs_ack = syn;
        hs_ack.sequence = 101; hs_ack.acknowledgement = 51; hs_ack.flags = 0x10; hs_ack.window = 4096;
        require(conn->input(hs_ack, 20).value_or(false), "P2-3: handshake complete");
        require(conn->enqueue(bytes).has_value() && conn->sent(64, 30).has_value(), "P2-3: conn send 64B");

        // 4 bidirectional data packets from peer with unchanged ack=51 & window=4096.
        std::array<std::uint8_t, 4> chunk{'p', 'i', 'n', 'g'};
        for (std::uint32_t i = 0; i < 4; ++i) {
            packet::Tcp4View data_seg = hs_ack;
            data_seg.sequence = 101 + i * 4;
            data_seg.flags = 0x18;
            data_seg.payload = chunk;
            require(conn->input(data_seg, 40 + i).value_or(false), "P2-3: conn bidirectional data");
        }
        auto d1 = conn->send_due(50, 64);
        require(d1 && !d1->has_value(), "P2-3: PassiveConnection bidirectional data does not trigger fast retransmit");

        // 4 pure window updates from peer with unchanged ack=51.
        for (std::uint16_t i = 1; i <= 4; ++i) {
            packet::Tcp4View win_seg = hs_ack;
            win_seg.sequence = 117;
            win_seg.window = static_cast<std::uint16_t>(4096 + i * 512);
            require(conn->input(win_seg, 60 + i).value_or(false), "P2-3: conn window update");
        }
        auto d2 = conn->send_due(70, 64);
        require(d2 && !d2->has_value(), "P2-3: PassiveConnection window updates do not trigger fast retransmit");

        // 3 genuine empty duplicate ACKs at unchanged window (6144) -> triggers fast retransmit before RTO (1030).
        for (std::uint64_t i = 0; i < 3; ++i) {
            packet::Tcp4View dup_seg = hs_ack;
            dup_seg.sequence = 117;
            dup_seg.window = 6144;
            require(conn->input(dup_seg, 80 + i).value_or(false), "P2-3: conn genuine dup-ACK");
        }
        auto d3 = conn->send_due(85, 64);
        require(d3 && d3->has_value() && (**d3).sequence == 51 && (**d3).bytes.size() == 64,
            "P2-3: PassiveConnection 3 genuine dup-ACKs trigger immediate fast retransmit");
    }

    struct SlowResolveCtx {
        std::mutex mu;
        std::condition_variable cv;
        std::atomic<bool> entered{false};
        bool release{false};
        std::vector<corosio::endpoint> result;
    };

    auto slow_resolve_cb(std::string_view, std::uint16_t, void* raw) -> std::vector<corosio::endpoint> {
        auto* ctx = static_cast<SlowResolveCtx*>(raw);
        ctx->entered.store(true, std::memory_order_release);
        std::unique_lock lk(ctx->mu);
        ctx->cv.wait_for(lk, std::chrono::seconds(3), [&] { return ctx->release; });
        return ctx->result;
    }

    auto test_r7_p2_4_and_5_async_ntp_and_reset() -> void {
        utility::scope_exit reset_hook([]() noexcept { ntp::set_host_resolve_callback(nullptr, nullptr); });
        utility::scope_exit reset_cal([]() noexcept { ntp::reset_offset(); });

        // 1. Live async loopback SNTP server + custom hostname resolution path.
        corosio::io_context srv_io;
        corosio::udp_socket srv_sock(srv_io), silent_sock(srv_io);
        auto lo = corosio::endpoint(corosio::ipv4_address::loopback(), 0);
        require(!srv_sock.open(lo.address().family()) && !srv_sock.bind(lo), "P2-4: mock ntp bind");
        require(!silent_sock.open(lo.address().family()) && !silent_sock.bind(lo), "P2-4: silent ntp bind");
        auto srv_port = srv_sock.local_endpoint().port();
        auto silent_port = silent_sock.local_endpoint().port();

        std::stop_source srv_stop;
        auto run_mock_ntp = [&]() -> capy::task<void> {
            std::array<std::uint8_t, 64> req{};
            std::stop_callback cb(srv_stop.get_token(), [&]() noexcept { srv_sock.cancel(); });
            while (!srv_stop.stop_requested()) {
                corosio::endpoint peer{};
                auto [ec, n] = co_await srv_sock.recv_from(capy::mutable_buffer(req.data(), req.size()), peer);
                if (ec) break;
                if (n < ntp::packet_size) continue;
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count() + 15000;
                auto ts = ntp::unix_ms_to_ntp(now_ms);
                std::array<std::uint8_t, ntp::packet_size> rep{};
                rep[0] = 0x24; rep[1] = 2;
                std::ranges::copy_n(req.data() + 40, 8, rep.data() + 24);
                auto put32 = [&](std::size_t off, std::uint32_t v) {
                    rep[off] = static_cast<std::uint8_t>(v >> 24); rep[off + 1] = static_cast<std::uint8_t>(v >> 16);
                    rep[off + 2] = static_cast<std::uint8_t>(v >> 8); rep[off + 3] = static_cast<std::uint8_t>(v);
                };
                put32(32, ts.seconds); put32(36, ts.fraction);
                put32(40, ts.seconds); put32(44, ts.fraction);
                (void)co_await srv_sock.send_to(capy::const_buffer(rep.data(), rep.size()), peer);
            }
        };
        std::jthread srv_thr([&] {
            capy::run_async(srv_io.get_executor(), []() noexcept {}, [](std::exception_ptr) noexcept {})(run_mock_ntp());
            srv_io.run();
        });
        utility::scope_exit stop_srv([&] {
            srv_stop.request_stop();
            srv_sock.close();
            silent_sock.close();
            if (srv_thr.joinable()) srv_thr.join();
        });

        // Fast hostname lookup via hook succeeds through async path.
        struct FastCtx { std::uint16_t port; } fctx{srv_port};
        ntp::set_host_resolve_callback([](std::string_view, std::uint16_t port, void*) -> std::vector<corosio::endpoint> {
            return {corosio::endpoint(corosio::ipv4_address::loopback(), port)};
        }, &fctx);
        auto sample = ntp::sync_once("mock-ntp.local", srv_port, 1500);
        require(sample.has_value() && sample->offset_ms > 12000 && sample->offset_ms < 18000,
            "P2-4: async hostname resolve + UDP SNTP exchange succeeds");

        // 2. Hanging hostname resolution respects unified timeout_ms (does NOT block 3s).
        auto slow_timeout = std::make_shared<SlowResolveCtx>();
        utility::scope_exit release_slow_timeout([slow_timeout] {
            { std::lock_guard lk(slow_timeout->mu); slow_timeout->release = true; }
            slow_timeout->cv.notify_all();
        });
        ntp::set_host_resolve_callback(&slow_resolve_cb, slow_timeout.get());
        auto t0 = std::chrono::steady_clock::now();
        auto timed_out = ntp::sync_once("hanging-dns.test.invalid", srv_port, 160);
        auto dt0 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        require(!timed_out.has_value() && timed_out.error() == ntp::SntpError::timeout,
            "P2-4: hanging DNS returns SntpError::timeout");
        require(dt0 < 600, "P2-4: unified timeout bounds hostname resolution (did not wait 3s)");

        // 3. Hanging hostname resolution inside NtpRuntime does NOT block core shutdown (stop()).
        auto slow_stop = std::make_shared<SlowResolveCtx>();
        utility::scope_exit release_slow_stop([slow_stop] {
            { std::lock_guard lk(slow_stop->mu); slow_stop->release = true; }
            slow_stop->cv.notify_all();
        });
        ntp::set_host_resolve_callback(&slow_resolve_cb, slow_stop.get());
        logging::Runtime logs;
        cli::NtpRuntime ntp_rt;
        config::NtpConfig hang_cfg{.host = "hanging-shutdown.test.invalid", .port = srv_port,
            .interval_ms = 60000, .timeout_ms = 5000};
        require(ntp_rt.start(hang_cfg, logs).has_value(), "P2-4: NtpRuntime start");
        auto wait_enter = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (!slow_stop->entered.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < wait_enter) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        require(slow_stop->entered.load(std::memory_order_acquire), "P2-4: worker entered hanging resolver");
        auto t1 = std::chrono::steady_clock::now();
        ntp_rt.stop();
        auto dt1 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t1).count();
        require(dt1 < 400, "P2-4: NtpRuntime::stop returns promptly even while DNS resolver is hung");

        // 4. Silent UDP blackhole cancels immediately on stop_token.
        ntp::set_host_resolve_callback(nullptr, nullptr);
        std::stop_source udp_stop;
        std::jthread stopper([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(70));
            udp_stop.request_stop();
        });
        auto t2 = std::chrono::steady_clock::now();
        auto canceled_udp = ntp::sync_once("127.0.0.1", silent_port, 5000, udp_stop.get_token());
        auto dt2 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t2).count();
        require(!canceled_udp.has_value() && canceled_udp.error() == ntp::SntpError::timeout && dt2 < 500,
            "P2-4: stop_token cancels in-flight async UDP SNTP query promptly");

        // 5. R7 P2-5: NTP global offset resets cleanly to 0 on stop() AND on disabled startup!
        ntp::global_calibrator().apply({45000, 10, 2});
        require(ntp::global_calibrator().offset_ms() == 45000 && platform::wall_clock_offset_ms() == 45000,
            "P2-5: published non-zero offset visible globally");
        ntp_rt.stop();
        require(ntp::global_calibrator().offset_ms() == 0 && platform::wall_clock_offset_ms() == 0,
            "P2-5: NtpRuntime::stop resets global NTP and wall-clock offset to 0");

        ntp::global_calibrator().apply({-30000, 8, 2});
        require(platform::wall_clock_offset_ms() == -30000, "P2-5: stale offset simulated before restart");
        require(ntp_rt.start(std::nullopt, logs).has_value(), "P2-5: restart with NTP disabled");
        require(ntp::global_calibrator().offset_ms() == 0 && platform::wall_clock_offset_ms() == 0,
            "P2-5: starting NtpRuntime with NTP disabled clears stale offset to 0");
        auto raw_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto cal_s = platform::calibrated_wall_seconds();
        require(std::llabs(cal_s - raw_s) <= 2, "P2-5: calibrated wall clock matches system clock after reset");
    }
}

int main() {
    test_r7_p2_1_dhcp_ipv6_scope();
    test_r7_p2_2_dhcp_async_staggered_fallback();
    test_r7_p2_3_tcp_rfc5681_dupack();
    test_r7_p2_4_and_5_async_ntp_and_reset();
    std::println("wave36 core audit R7 Track B (DHCP scope + async stagger + TCP RFC5681 dup-ACK + async NTP + reset) passed");
    return 0;
}
