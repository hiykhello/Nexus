#include <csignal>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import cli.dns_transports;
import cli.proxy_services;
import config;
import dns.mdns;
import dns.message;
import logging.cli;
import memory.watchdog;
import packet;
import packet.bridge;

namespace {
    using namespace std::chrono_literals;
    int g_failures = 0;

    auto check(bool ok, std::string_view label) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << label << "\n";
            ++g_failures;
        }
    }

    struct Fd {
        int fd = -1;
        explicit Fd(int f = -1) noexcept : fd(f) {}
        Fd(Fd const&) = delete;
        auto operator=(Fd const&) -> Fd& = delete;
        ~Fd() { if (fd >= 0) ::close(fd); }
    };

    auto make_ipv4_pkt(std::array<std::uint8_t, 4> src, std::array<std::uint8_t, 4> dst, std::uint8_t ttl = 64)
        -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> pkt(28, 0);
        pkt[0] = 0x45; pkt[3] = 28; pkt[8] = ttl; pkt[9] = 17;
        std::ranges::copy(src, pkt.begin() + 12);
        std::ranges::copy(dst, pkt.begin() + 16);
        auto sum = packet::internet_checksum(std::span(pkt).first(20));
        pkt[10] = static_cast<std::uint8_t>(sum >> 8);
        pkt[11] = static_cast<std::uint8_t>(sum & 0xffu);
        return pkt;
    }

    auto make_ipv6_pkt(std::array<std::uint8_t, 16> src, std::array<std::uint8_t, 16> dst, std::uint8_t hop = 32)
        -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> pkt(48, 0);
        pkt[0] = 0x60; pkt[5] = 8; pkt[6] = 17; pkt[7] = hop;
        std::ranges::copy(src, pkt.begin() + 8);
        std::ranges::copy(dst, pkt.begin() + 24);
        return pkt;
    }

    auto test_r8_p1_3_bridge_mac_and_tx_stats() -> void {
        using namespace packet::bridge;
        MacAddress const mac_host{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
        MacAddress const mac_gw4{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
        MacAddress const mac_v6_host{0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
        MacAddress const mac_gw6{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

        std::array<std::uint8_t, 16> onlink_net4{192, 168, 1, 0};
        std::array<std::uint8_t, 16> gw4_ip{192, 168, 1, 1};
        std::array<std::uint8_t, 16> host4_ip{192, 168, 1, 42};
        std::array<std::uint8_t, 16> onlink_net6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1};
        std::array<std::uint8_t, 16> gw6_ip{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        std::array<std::uint8_t, 16> host6_ip{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7};

        std::vector<RouteHint> routes{
            {.destination = {}, .gateway = gw4_ip, .priority = 100, .family = 4, .prefix = 0},
            {.destination = onlink_net4, .gateway = std::nullopt, .priority = 50, .family = 4, .prefix = 24},
            {.destination = {}, .gateway = gw6_ip, .priority = 100, .family = 6, .prefix = 0},
            {.destination = onlink_net6, .gateway = std::nullopt, .priority = 50, .family = 6, .prefix = 64},
        };
        std::vector<NeighborEntry> neigh{
            {.address = host4_ip, .mac = mac_host, .family = 4},
            {.address = gw4_ip, .mac = mac_gw4, .family = 4},
            {.address = host6_ip, .mac = mac_v6_host, .family = 6},
            {.address = gw6_ip, .mac = mac_gw6, .family = 6},
            {.address = std::array<std::uint8_t, 16>{192, 168, 1, 99}, .mac = MacAddress{}, .family = 4},
        };

        // 1. Broadcast IPv4 -> ff:ff:ff:ff:ff:ff
        auto bcast = resolve_destination_mac(make_ipv4_pkt({192, 168, 1, 2}, {255, 255, 255, 255}), routes, neigh);
        check(bcast && *bcast == MacAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "R8 P1-3 IPv4 broadcast MAC");

        // 2. Multicast IPv4 -> RFC 1112 (bit 7 masked on second octet)
        auto m4a = resolve_destination_mac(make_ipv4_pkt({192, 168, 1, 2}, {224, 0, 0, 251}), routes, neigh);
        check(m4a && *m4a == MacAddress{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, "R8 P1-3 IPv4 mDNS multicast MAC");
        auto m4b = resolve_destination_mac(make_ipv4_pkt({192, 168, 1, 2}, {239, 255, 255, 250}), routes, neigh);
        check(m4b && *m4b == MacAddress{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}, "R8 P1-3 IPv4 SSDP multicast bit-7 mask");

        // 3. Multicast IPv6 -> RFC 2464 (33:33 + low 4 bytes)
        std::array<std::uint8_t, 16> m6_dst{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xab, 0xcd, 0xef};
        auto m6 = resolve_destination_mac(make_ipv6_pkt(host6_ip, m6_dst), routes, neigh);
        check(m6 && *m6 == MacAddress{0x33, 0x33, 0xff, 0xab, 0xcd, 0xef}, "R8 P1-3 IPv6 multicast MAC");

        // 4. On-link unicast IPv4 & IPv6 -> direct neighbor MAC
        auto u4 = resolve_destination_mac(make_ipv4_pkt({192, 168, 1, 2}, {192, 168, 1, 42}), routes, neigh);
        check(u4 && *u4 == mac_host, "R8 P1-3 IPv4 on-link neighbor MAC");
        auto u6 = resolve_destination_mac(make_ipv6_pkt(gw6_ip, host6_ip), routes, neigh);
        check(u6 && *u6 == mac_v6_host, "R8 P1-3 IPv6 on-link neighbor MAC");

        // 5. Off-link unicast IPv4 & IPv6 -> gateway MAC (NOT destination)
        auto off4 = resolve_destination_mac(make_ipv4_pkt({192, 168, 1, 2}, {8, 8, 8, 8}), routes, neigh);
        check(off4 && *off4 == mac_gw4, "R8 P1-3 IPv4 off-link gateway MAC");
        std::array<std::uint8_t, 16> pub6{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        auto off6 = resolve_destination_mac(make_ipv6_pkt(host6_ip, pub6), routes, neigh);
        check(off6 && *off6 == mac_gw6, "R8 P1-3 IPv6 off-link gateway MAC");

        // 6. Missing or all-zero neighbor MAC -> nullopt (drop, never emit zero MAC!)
        auto miss = resolve_destination_mac(make_ipv4_pkt({192, 168, 1, 2}, {192, 168, 1, 77}), routes, neigh);
        check(!miss.has_value(), "R8 P1-3 missing neighbor drops instead of zero MAC");
        auto zero = resolve_destination_mac(make_ipv4_pkt({192, 168, 1, 2}, {192, 168, 1, 99}), routes, neigh);
        check(!zero.has_value(), "R8 P1-3 all-zero neighbor MAC rejected");

        // 7. Live FD pump: egress write error MUST NOT increment forwarded_v4/v6 and MUST increment dropped_tx!
        (void)std::signal(SIGPIPE, SIG_IGN);
        int tun_sp[2]{-1, -1}, phys_sp[2]{-1, -1};
        check(::socketpair(AF_UNIX, SOCK_DGRAM, 0, tun_sp) == 0 && ::socketpair(AF_UNIX, SOCK_DGRAM, 0, phys_sp) == 0,
              "R8 P1-3 socketpair");
        Fd tun_peer(tun_sp[1]);
        ::close(phys_sp[1]); // Peer closed -> egress writes fail with ECONNREFUSED/EPIPE.

        logging::Runtime logs;
        config::BridgeServiceConfig bcfg{.tun_interface = "nx-tun0", .physical_interface = "eth0", .mtu = 1500};
        auto handle = cli::init_bridge_service_with_fds(bcfg, tun_sp[0], phys_sp[0], logs);
        check(handle.has_value(), "R8 P1-3 init_bridge_service_with_fds");
        if (handle) {
            auto p4 = make_ipv4_pkt({10, 0, 0, 1}, {10, 0, 0, 2});
            auto p6 = make_ipv6_pkt(host6_ip, pub6);
            check(::send(tun_peer.fd, p4.data(), p4.size(), 0) == static_cast<ssize_t>(p4.size()), "R8 P1-3 send v4");
            check(::send(tun_peer.fd, p6.data(), p6.size(), 0) == static_cast<ssize_t>(p6.size()), "R8 P1-3 send v6");
            auto dl = std::chrono::steady_clock::now() + 1s;
            cli::BridgeStatsSnapshot st{};
            while (std::chrono::steady_clock::now() < dl) {
                st = cli::bridge_stats(*handle);
                if (st.dropped_tx >= 2) break;
                std::this_thread::sleep_for(10ms);
            }
            check(st.forwarded_v4 == 0 && st.forwarded_v6 == 0,
                  "R8 P1-3 failed egress send does not increment forwarded_v4/v6");
            check(st.dropped_tx >= 2, "R8 P1-3 failed egress send increments dropped_tx");
        }
    }

    auto append_name(std::vector<std::uint8_t>& out, std::string_view name) -> void {
        if (name == ".") { out.push_back(0); return; }
        std::size_t pos = 0;
        while (pos < name.size()) {
            auto dot = name.find('.', pos);
            auto lbl = dot == std::string_view::npos ? name.substr(pos) : name.substr(pos, dot - pos);
            out.push_back(static_cast<std::uint8_t>(lbl.size()));
            for (char c : lbl) out.push_back(static_cast<std::uint8_t>(c));
            if (dot == std::string_view::npos) break;
            pos = dot + 1;
        }
        out.push_back(0);
    }

    auto make_mdns_rr_packet(std::string_view owner, std::uint16_t type, std::uint32_t ttl,
                             std::span<std::uint8_t const> rdata) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> pkt{0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0};
        append_name(pkt, owner);
        pkt.insert(pkt.end(), {
            static_cast<std::uint8_t>(type >> 8), static_cast<std::uint8_t>(type & 0xffu),
            0x80, 0x01, // IN + cache-flush
            static_cast<std::uint8_t>(ttl >> 24), static_cast<std::uint8_t>(ttl >> 16),
            static_cast<std::uint8_t>(ttl >> 8), static_cast<std::uint8_t>(ttl & 0xffu),
            static_cast<std::uint8_t>(rdata.size() >> 8), static_cast<std::uint8_t>(rdata.size() & 0xffu),
        });
        pkt.insert(pkt.end(), rdata.begin(), rdata.end());
        return pkt;
    }

    auto test_r8_p2_4_mdns_ptr_srv_txt() -> void {
        // 1. PTR record: _http._tcp.local -> web._http._tcp.local (TTL=120)
        std::vector<std::uint8_t> ptr_rdata;
        append_name(ptr_rdata, "web._http._tcp.local");
        auto ptr_pkt = make_mdns_rr_packet("_http._tcp.local", 12, 120, ptr_rdata);
        auto res_ptr = cli::convert_mdns_response(dns::Question{"_http._tcp.local", 12, 1}, 0x1122, ptr_pkt);
        check(res_ptr.has_value() && res_ptr->has_value(), "R8 P2-4 PTR mDNS response converted");
        if (res_ptr && *res_ptr) {
            check((*res_ptr)->rcode == 0 && (*res_ptr)->records.size() == 1, "R8 P2-4 PTR 1 answer record");
            auto const& r = (*res_ptr)->records.front();
            check(r.type == 12 && r.ttl == 120 && r.data_length == ptr_rdata.size(), "R8 P2-4 PTR type/ttl/len");
            auto actual = std::span((*res_ptr)->wire).subspan(r.data_offset, r.data_length);
            check(std::ranges::equal(actual, ptr_rdata), "R8 P2-4 PTR wire target matches");
        }

        // 2. SRV record: web._http._tcp.local -> prio=10 weight=20 port=8080 target=printer.local (TTL=60)
        std::vector<std::uint8_t> srv_rdata{0x00, 0x0a, 0x00, 0x14, 0x1f, 0x90};
        append_name(srv_rdata, "printer.local");
        auto srv_pkt = make_mdns_rr_packet("web._http._tcp.local", 33, 60, srv_rdata);
        auto res_srv = cli::convert_mdns_response(dns::Question{"web._http._tcp.local", 33, 1}, 0x3344, srv_pkt);
        check(res_srv.has_value() && res_srv->has_value(), "R8 P2-4 SRV mDNS response converted");
        if (res_srv && *res_srv) {
            check((*res_srv)->rcode == 0 && (*res_srv)->records.size() == 1, "R8 P2-4 SRV 1 answer record");
            auto const& r = (*res_srv)->records.front();
            check(r.type == 33 && r.ttl == 60 && r.data_length == srv_rdata.size(), "R8 P2-4 SRV type/ttl/len");
            auto actual = std::span((*res_srv)->wire).subspan(r.data_offset, r.data_length);
            check(std::ranges::equal(actual, srv_rdata), "R8 P2-4 SRV wire prio/weight/port/target match");
        }

        // 3. TXT record: multi-string ["path=/api", "ver=2"] (TTL=45)
        std::vector<std::uint8_t> txt_rdata;
        for (std::string_view s : {"path=/api", "ver=2"}) {
            txt_rdata.push_back(static_cast<std::uint8_t>(s.size()));
            txt_rdata.insert(txt_rdata.end(), s.begin(), s.end());
        }
        auto txt_pkt = make_mdns_rr_packet("web._http._tcp.local", 16, 45, txt_rdata);
        auto res_txt = cli::convert_mdns_response(dns::Question{"web._http._tcp.local", 16, 1}, 0x5566, txt_pkt);
        check(res_txt.has_value() && res_txt->has_value(), "R8 P2-4 TXT mDNS response converted");
        if (res_txt && *res_txt) {
            check((*res_txt)->rcode == 0 && (*res_txt)->records.size() == 1, "R8 P2-4 TXT 1 answer record");
            auto const& r = (*res_txt)->records.front();
            check(r.type == 16 && r.ttl == 45 && r.data_length == txt_rdata.size(), "R8 P2-4 TXT type/ttl/len");
            auto actual = std::span((*res_txt)->wire).subspan(r.data_offset, r.data_length);
            check(std::ranges::equal(actual, txt_rdata), "R8 P2-4 TXT wire strings match");
        }

        // 4. Empty TXT record (0-byte RDATA) encodes as single 0x00 byte per RFC 6763 §6.1.
        auto empty_txt_pkt = make_mdns_rr_packet("empty._http._tcp.local", 16, 30, {});
        auto res_empty = cli::convert_mdns_response(dns::Question{"empty._http._tcp.local", 16, 1}, 0x7788, empty_txt_pkt);
        check(res_empty.has_value() && res_empty->has_value(), "R8 P2-4 empty TXT converted cleanly");
        if (res_empty && *res_empty) {
            auto const& r = (*res_empty)->records.front();
            check(r.data_length == 1 && (*res_empty)->wire[r.data_offset] == 0, "R8 P2-4 empty TXT single 0x00");
        }

        // 5. TTL=0 goodbye PTR is still filtered out (returns nullopt).
        auto bye_ptr = make_mdns_rr_packet("_http._tcp.local", 12, 0, ptr_rdata);
        auto res_bye = cli::convert_mdns_response(dns::Question{"_http._tcp.local", 12, 1}, 0x99aa, bye_ptr);
        check(res_bye.has_value() && !res_bye->has_value(), "R8 P2-4 TTL=0 goodbye PTR filtered");
    }

    auto test_r8_p2_6_memory_watchdog_cgroup_vs_rss() -> void {
        constexpr std::uint64_t MiB = 1024ull * 1024ull;
        constexpr std::uint64_t GiB = 1024ull * MiB;

        // 1. /proc/self/cgroup parsing.
        auto p1 = memory::parse_cgroup_v2_path("0::/system.slice/nexus.service\n");
        check(p1 && *p1 == "/system.slice/nexus.service", "R8 P2-6 parse unified v2 path");
        auto p2 = memory::parse_cgroup_v2_path("12:memory:/legacy\n0::/user.slice/user-1000.slice\r\n");
        check(p2 && *p2 == "/user.slice/user-1000.slice", "R8 P2-6 parse hybrid v1+v2 path");
        auto p3 = memory::parse_cgroup_v2_path("0::/\n");
        check(p3 && *p3 == "/", "R8 P2-6 parse root cgroup path");
        check(!memory::parse_cgroup_v2_path("0::/../etc/passwd\n").has_value(), "R8 P2-6 reject path traversal");
        check(!memory::parse_cgroup_v2_path("1:name=systemd:/foo\n").has_value(), "R8 P2-6 reject v1-only without 0::");

        // 2. Root cgroup / unlimited shared cgroup / noisy sibling slice NEVER trigger shedding when RSS is small!
        memory::WatchdogPolicy pol = memory::WatchdogPolicy::ios_ne_50mib(); // 36 / 44 / 48 MiB
        memory::MemoryWatchdog wd(pol);
        int callbacks = 0;
        auto cb = [&](memory::PressureLevel) { ++callbacks; };

        // 2a. Root cgroup reporting 16 GiB total host usage, Nexus RSS = 16 MiB -> normal!
        memory::MemorySample root_sample{.process_rss_bytes = 16 * MiB, .cgroup_bytes = 16 * GiB,
                                         .cgroup_limit_bytes = 16 * GiB, .cgroup_is_root = true};
        check(wd.evaluate(root_sample, 1000, cb) == memory::PressureLevel::normal && wd.should_admit_new_session(),
              "R8 P2-6 root cgroup noise does not shed");
        check(wd.stats().last_rss_bytes == 16 * MiB && wd.stats().last_cgroup_bytes == 16 * GiB,
              "R8 P2-6 RSS and cgroup tracked separately");

        // 2b. Non-root shared slice with memory.max="max" (limit=0) and 8 GiB sibling usage -> normal!
        memory::MemorySample unlim_sample{.process_rss_bytes = 16 * MiB, .cgroup_bytes = 8 * GiB,
                                          .cgroup_limit_bytes = 0, .cgroup_is_root = false};
        check(wd.evaluate(unlim_sample, 2000, cb) == memory::PressureLevel::normal && wd.should_admit_new_session(),
              "R8 P2-6 unlimited non-root cgroup does not shed");

        // 2c. Non-root slice with 16 GiB limit and 4 GiB sibling usage (25%), Nexus RSS = 20 MiB -> normal!
        memory::MemorySample sibling_sample{.process_rss_bytes = 20 * MiB, .cgroup_bytes = 4 * GiB,
                                            .cgroup_limit_bytes = 16 * GiB, .cgroup_is_root = false};
        check(wd.evaluate(sibling_sample, 3000, cb) == memory::PressureLevel::normal && wd.should_admit_new_session(),
              "R8 P2-6 noisy sibling cgroup below container limit does not shed");
        check(callbacks == 0, "R8 P2-6 zero false pressure callbacks");

        // 2d. Dedicated container cgroup (64 MiB limit) near OOM (62 MiB = 96.9%) -> emergency!
        memory::MemorySample container_oom{.process_rss_bytes = 20 * MiB, .cgroup_bytes = 62 * MiB,
                                           .cgroup_limit_bytes = 64 * MiB, .cgroup_is_root = false};
        check(wd.evaluate(container_oom, 4000, cb) == memory::PressureLevel::emergency && !wd.should_admit_new_session(),
              "R8 P2-6 dedicated finite container near OOM triggers emergency");

        // 2e. Recovery + process RSS driven emergency.
        check(wd.evaluate(sibling_sample, 5000, cb) == memory::PressureLevel::normal && wd.should_admit_new_session(),
              "R8 P2-6 recovers to normal");
        memory::MemorySample rss_oom{.process_rss_bytes = 50 * MiB, .cgroup_bytes = 0, .cgroup_limit_bytes = 0, .cgroup_is_root = true};
        check(wd.evaluate(rss_oom, 6000, cb) == memory::PressureLevel::emergency && !wd.should_admit_new_session(),
              "R8 P2-6 process RSS exceeding emergency_bytes sheds");

        // 3. Live Linux sampling: process_rss_bytes > 0 and below 1 GiB for this tiny unit test process!
        auto live = memory::sample_memory_usage();
        auto rss_only = memory::sample_process_rss_bytes();
        check(live.process_rss_bytes > 0 && rss_only > 0, "R8 P2-6 live process RSS non-zero");
        check(live.process_rss_bytes < 512 * MiB && rss_only < 512 * MiB,
              "R8 P2-6 live process RSS not inflated by root/host cgroup");
    }
}

auto main() -> int {
    try {
        test_r8_p1_3_bridge_mac_and_tx_stats();
        test_r8_p2_4_mdns_ptr_srv_txt();
        test_r8_p2_6_memory_watchdog_cgroup_vs_rss();
    } catch (std::exception const& ex) {
        std::cerr << "EXCEPTION: " << ex.what() << "\n";
        return 1;
    }
    if (g_failures != 0) {
        std::cerr << "wave36_r8_bridge_mdns_watchdog_unit: FAIL (" << g_failures << " failures)\n";
        return 1;
    }
    std::cout << "wave36_r8_bridge_mdns_watchdog_unit: PASS\n";
    return 0;
}
