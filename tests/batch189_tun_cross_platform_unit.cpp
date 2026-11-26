#include "../include/nexus/core_c_api.h"
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

import std;
import config;
import relay;
import rules;
import platform.socket_options;
import platform.tun_bridge;
import platform.nftables;
import packet;
import packet.fd;
import packet.tun_device;
import packet.tun_network_plan;
import packet.tun_network_darwin;
import packet.tun_network_windows;
import cli.tun_host;
import cli.tun_enabled;
import state.fakeip;
import udp.direct;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    auto make_ipv4_tcp_syn(std::array<std::uint8_t, 4> src, std::uint16_t sport,
        std::array<std::uint8_t, 4> dst, std::uint16_t dport, std::uint32_t seq) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> pkt(40, 0);
        pkt[0] = 0x45; pkt[1] = 0; pkt[2] = 0; pkt[3] = 40;
        pkt[4] = 0x12; pkt[5] = 0x34; pkt[6] = 0x40; pkt[7] = 0;
        pkt[8] = 64; pkt[9] = 6; // TCP
        std::ranges::copy(src, pkt.begin() + 12);
        std::ranges::copy(dst, pkt.begin() + 16);
        auto csum = [](std::uint32_t sum, std::span<std::uint8_t const> bytes) -> std::uint16_t {
            for (std::size_t i = 0; i + 1 < bytes.size(); i += 2)
                sum += (std::uint32_t(bytes[i]) << 8) | bytes[i + 1];
            if (bytes.size() & 1u) sum += std::uint32_t(bytes.back()) << 8;
            while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
            return static_cast<std::uint16_t>(~sum);
        };
        std::uint16_t ip_sum = csum(0, std::span(pkt).first(20));
        pkt[10] = static_cast<std::uint8_t>(ip_sum >> 8);
        pkt[11] = static_cast<std::uint8_t>(ip_sum & 0xff);

        pkt[20] = static_cast<std::uint8_t>(sport >> 8); pkt[21] = static_cast<std::uint8_t>(sport & 0xff);
        pkt[22] = static_cast<std::uint8_t>(dport >> 8); pkt[23] = static_cast<std::uint8_t>(dport & 0xff);
        pkt[24] = static_cast<std::uint8_t>(seq >> 24); pkt[25] = static_cast<std::uint8_t>(seq >> 16);
        pkt[26] = static_cast<std::uint8_t>(seq >> 8); pkt[27] = static_cast<std::uint8_t>(seq);
        pkt[32] = 0x50; pkt[33] = 0x02; // data offset=5, SYN=0x02
        pkt[34] = 0xff; pkt[35] = 0xff; // window=65535
        std::uint32_t pseudo = 6u + 20u;
        for (int i = 0; i < 4; i += 2) {
            pseudo += (std::uint32_t(src[i]) << 8) | src[i + 1];
            pseudo += (std::uint32_t(dst[i]) << 8) | dst[i + 1];
        }
        std::uint16_t tcp_sum = csum(pseudo, std::span(pkt).subspan(20));
        pkt[36] = static_cast<std::uint8_t>(tcp_sum >> 8);
        pkt[37] = static_cast<std::uint8_t>(tcp_sum & 0xff);
        return pkt;
    }

    auto test_protect_fd() -> void {
        struct State { int last_fd = -1; int rc = 0; unsigned calls = 0; } state;
        auto cb = +[](int fd, void* ctx) -> int {
            auto* s = static_cast<State*>(ctx);
            s->last_fd = fd;
            ++s->calls;
            return s->rc;
        };
        nexus_core_set_protect_fd_callback(cb, &state);
        require(platform::has_protect_fd_callback(), "protect_fd registered");
        platform::SocketBinding empty_binding;
        require(empty_binding.configured(), "SocketBinding::configured reflects global protect_fd");

        auto sock = platform::open_physical_socket(false, true, false, {});
        require(sock.has_value(), "open physical UDP socket");
        auto err = platform::apply_socket_binding(*sock, empty_binding, true);
        require(!err && state.calls == 1 && state.last_fd == *sock, "protect_fd invoked on physical socket");

        state.rc = EACCES;
        auto err2 = platform::apply_socket_binding(*sock, empty_binding, true);
        require(err2 == std::errc::permission_denied && state.calls == 2, "protect_fd rejection propagates errno");

        platform::close_unadopted_socket(*sock);
        nexus_core_set_protect_fd_callback(nullptr, nullptr);
        require(!platform::has_protect_fd_callback(), "protect_fd cleared cleanly");
    }

    auto test_route_plans_and_attach() -> void {
        auto v4 = packet::parse_tun_cidr("172.19.0.1/30");
        auto v6 = packet::parse_tun_cidr("fdfe:dcba:9876::1/126");
        require(v4 && v6, "parse IPv4 and IPv6 CIDRs");
        packet::TunRoutePlanInput in{
            .inet4 = *v4, .inet6 = *v6, .mtu = 1500, .auto_route = true, .route_exclude_private = true
        };
        auto plan = packet::plan_cross_platform_tun_routes(in);
        require(plan.has_value() && plan->addresses.size() == 2 &&
            plan->routes.size() == 4 && plan->excludes.size() == 7,
            "dual-stack split default routes + 7 private excludes");

        auto bad_darwin = packet::plan_darwin_tun_network(in, "eth0");
        require(!bad_darwin.has_value(), "Darwin rejects non-utun name");
        auto ok_darwin = packet::plan_darwin_tun_network(in, "utun7");
        require(ok_darwin.has_value(), "Darwin accepts utun7");

        auto bad_v6_mtu = in;
        bad_v6_mtu.mtu = 1200;
        require(!packet::plan_windows_tun_network(bad_v6_mtu).has_value(), "IPv6 rejects MTU < 1280");

        int sv[2]{-1, -1};
        require(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "socketpair for Android external tun-fd");
        int f0 = ::fcntl(sv[0], F_GETFL, 0);
        require(::fcntl(sv[0], F_SETFL, f0 | O_NONBLOCK) == 0, "nonblock socketpair");
        require(!packet::LinuxTun::attach(sv[0], packet::TunFdOwnership::borrow).has_value(),
            "strict LinuxTun::attach rejects non-TUN fd");
        auto ext = packet::LinuxTun::attach_external(sv[1], packet::TunFdOwnership::borrow, false);
        require(ext.has_value() && ext->name() == "tun-android",
            "Android attach_external skips TUNGETIFF ioctl and sets O_NONBLOCK");
        ext->close();
        require((::fcntl(sv[1], F_GETFL, 0) & O_NONBLOCK) == 0,
            "borrow attach_external restores blocking flag on close");

        nexus_core_set_tun_fd(sv[0], 0, 1);
        auto ov = platform::consume_external_tun_fd();
        require(ov && ov->fd == sv[0] && !ov->adopt && ov->skip_ioctl, "C-API set_tun_fd roundtrip");
        ::close(sv[0]); ::close(sv[1]);
    }

    auto test_ios_bridge_e2e() -> void {
        struct Capture {
            std::mutex mutex;
            std::condition_variable cv;
            std::vector<std::vector<std::uint8_t>> pkts;
        } cap;
        auto on_out = +[](std::uint8_t const* data, std::size_t len, void* ctx) {
            auto* c = static_cast<Capture*>(ctx);
            {
                std::lock_guard lock(c->mutex);
                c->pkts.emplace_back(data, data + len);
            }
            c->cv.notify_all();
        };
        require(nexus_core_tun_bridge_enable(1, 1500, on_out, &cap) == 0, "enable C-API TUN bridge");
        auto bridge = platform::global_tun_bridge();
        require(bridge != nullptr && bridge->device_name() == "nexus-bridge", "global bridge created");

        auto server = relay::Server::create();
        require(server.has_value(), "create relay::Server");
        config::TunInbound tun_cfg;
        tun_cfg.mtu = 1500;
        tun_cfg.interface_name = "utun-ios";
        cli::tun_enabled::TunHost host(**server, tun_cfg, false, {});
        auto started = host.start(bridge);
        require(started.has_value() && *started == "nexus-bridge", "TunHost started on ExternalTunBridge");

        // Block target in policy or let TCP SYN hit userspace TCP listener -> TCP SYN-ACK emitted!
        auto syn = make_ipv4_tcp_syn({10, 0, 0, 2}, 41234, {198, 51, 100, 42}, 80, 0x10203040u);
        require(nexus_core_tun_bridge_inject(syn.data(), syn.size()) == 0, "inject raw IPv4 TCP SYN");

        std::vector<std::uint8_t> reply;
        {
            std::unique_lock lock(cap.mutex);
            bool got = cap.cv.wait_for(lock, std::chrono::seconds(2), [&] { return !cap.pkts.empty(); });
            require(got, "TunHost emits outbound IPv4 TCP SYN-ACK over bridge");
            reply = std::move(cap.pkts.front());
        }
        require(reply.size() >= 40 && (reply[0] >> 4) == 4 && reply[9] == 6 &&
            reply[12] == 198 && reply[13] == 51 && reply[14] == 100 && reply[15] == 42 &&
            reply[16] == 10 && reply[17] == 0 && reply[18] == 0 && reply[19] == 2 &&
            ((reply[33] & 0x12) == 0x12), "valid IPv4 SYN-ACK returned from nexus-bridge");

        host.stop();
        require(nexus_core_tun_bridge_enable(0, 0, nullptr, nullptr) == 0, "disable C-API TUN bridge");

        // Closing bridge triggers fatal error propagation on TunHost::healthy().
        require(nexus_core_tun_bridge_enable(1, 1500, nullptr, nullptr) == 0, "re-enable bridge");
        auto b2 = platform::global_tun_bridge();
        cli::tun_enabled::TunHost host2(**server, tun_cfg, false, {});
        require(host2.start(b2).has_value(), "start TunHost for bridge close health test");
        b2->close();
        for (int i = 0; i < 100 && host2.healthy(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        require(!host2.healthy() && host2.failure().has_value(),
            "TunHost marks unhealthy when TUN bridge closes");
        host2.stop();
        require(nexus_core_tun_bridge_enable(0, 0, nullptr, nullptr) == 0, "cleanup bridge");
    }

    auto test_p0_fd_drop_direct_protect_and_fd_sock() -> void {
        int sv[2]{-1, -1};
        require(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "socketpair for FdPump drop test");
        int f0 = ::fcntl(sv[0], F_GETFL, 0);
        require(::fcntl(sv[0], F_SETFL, f0 | O_NONBLOCK) == 0, "set O_NONBLOCK");
        ::close(sv[1]); // permanent ECONNREFUSED on write

        packet::MemoryLink link({1500, 8, 65536});
        auto pump = packet::FdPump::create(sv[0], link, 1500);
        require(pump.has_value(), "FdPump::create");
        std::vector<std::uint8_t> pkt(20, 0x45);
        require(link.send(packet::Side::second, pkt).has_value(), "enqueue outbound packet");
        auto st = pump->step();
        auto st2 = pump->step();
        require(st.output_error.has_value() && !st2.output_error.has_value(),
            "non-temporary FdPump write error drops bad packet without wedging");
        ::close(sv[0]);

        auto reject_cb = +[](int, void*) -> int { return EACCES; };
        nexus_core_set_protect_fd_callback(reject_cb, nullptr);
        udp::Direct4 d4(rules::Matcher{}, udp::Mapping::endpoint_independent,
            udp::Filtering::endpoint_independent, udp::Limits{16, 4, 5000}, 1500);
        std::vector<std::uint8_t> u4(29, 0);
        u4[0] = 0x45; u4[3] = 29; u4[8] = 64; u4[9] = 17;
        u4[12] = 10; u4[15] = 2; u4[16] = 198; u4[17] = 51; u4[18] = 100; u4[19] = 1;
        u4[20] = 0x10; u4[21] = 0; u4[22] = 0x00; u4[23] = 53; u4[25] = 9;
        auto sub = d4.submit(u4, 1);
        require(!sub.has_value(), "udp::Direct4 honors protect_fd rejection");
        nexus_core_set_protect_fd_callback(nullptr, nullptr);

        // NEXUS_TUN_FD_SOCK SCM_RIGHTS handoff end-to-end test.
        auto sock_path = std::filesystem::temp_directory_path() /
            ("nexus-tun-sock-" + std::to_string(::getpid()) + ".sock");
        std::error_code ec;
        std::filesystem::remove(sock_path, ec);
        int srv = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        require(srv >= 0, "create AF_UNIX server");
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::ranges::copy(sock_path.string(), addr.sun_path);
        require(::bind(srv, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) == 0 && ::listen(srv, 1) == 0,
            "bind/listen NEXUS_TUN_FD_SOCK");
        int tun_sv[2]{-1, -1};
        require(::socketpair(AF_UNIX, SOCK_DGRAM, 0, tun_sv) == 0, "socketpair as mock Android TUN");
        std::jthread sender([&] {
            int cli = ::accept(srv, nullptr, nullptr);
            if (cli >= 0) {
                char b = 0;
                if (::recv(cli, &b, 1, 0) == 1) {
                    iovec iov{&b, 1};
                    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int))> cbuf{};
                    msghdr msg{};
                    msg.msg_iov = &iov; msg.msg_iovlen = 1;
                    msg.msg_control = cbuf.data(); msg.msg_controllen = cbuf.size();
                    auto* cm = CMSG_FIRSTHDR(&msg);
                    cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
                    std::memcpy(CMSG_DATA(cm), &tun_sv[0], sizeof(int));
                    (void)::sendmsg(cli, &msg, MSG_NOSIGNAL);
                }
                ::close(cli);
            }
        });
        ::setenv("NEXUS_TUN_FD_SOCK", sock_path.c_str(), 1);
        auto cfg = config::parse_kdl(R"kdl(
schema-version 1
role "client"
inbounds { inbound "android-tun" type="tun" { mtu 1400; }; }
outbounds { outbound "direct" type="direct"; }
routing { default-outbound "direct"; }
)kdl");
        require(cfg.has_value(), "parse Android-style TUN config");
        auto r_srv = relay::Server::create();
        require(r_srv.has_value(), "create server for NEXUS_TUN_FD_SOCK");
        cli::tun_enabled::Runtime rt;
        rt.resize(1);
        require(rt.configure(0, cfg->inbounds[0], *cfg).has_value(), "configure TUN runtime");
        auto started_name = rt.start(0, **r_srv);
        require(started_name.has_value() && *started_name == "tun-android",
            "Runtime::start receives TUN FD over NEXUS_TUN_FD_SOCK");
        rt.stop();
        sender.join();
        ::unsetenv("NEXUS_TUN_FD_SOCK");
        ::close(srv);
        ::close(tun_sv[0]);
        ::close(tun_sv[1]);
        std::filesystem::remove(sock_path, ec);
    }

    auto test_linux_redirect_and_config_polish() -> void {
        std::string excludes;
        for (int i = 0; i < 36; ++i)
            excludes += std::format("    route-exclude \"198.18.{}.0/24\"\n", i);
        auto kdl = std::format(R"kdl(
schema-version 1
role "client"
inbounds {{
    inbound "tun" type="tun" {{
        inet4-address "172.19.0.1/30"
        auto-route #true
        auto-redirect #true
        auto-redirect-input-mark 0x1111
        auto-redirect-output-mark 0x2222
        auto-redirect-reset-mark 0x3333
        include-uid 1000
        include-uid "2000:2999"
        exclude-uid 0
        include-android-user 10
        include-interface "wlan0"
        exclude-interface "rmnet0"
{}
    }}
}}
outbounds {{ outbound "direct" type="direct"; }}
routing {{ default-outbound "direct"; }}
)kdl", excludes);
        auto cfg = config::parse_kdl(kdl);
        require(cfg.has_value(), cfg ? "" : cfg.error());
        auto const& tun = *cfg->inbounds[0].tun;
        require(tun.extra.auto_redirect_input_mark == 0x1111u &&
            tun.extra.auto_redirect_output_mark == 0x2222u &&
            tun.extra.auto_redirect_reset_mark == 0x3333u &&
            tun.extra.include_uids.size() == 2 && tun.extra.include_uids[1].max == 2999u &&
            tun.extra.exclude_uids.size() == 1 && tun.extra.include_android_users.size() == 1 &&
            tun.extra.include_interfaces.size() == 1 && tun.extra.exclude_interfaces.size() == 1 &&
            tun.route_excludes.size() == 36, "KDL auto-redirect marks, uid ranges, interfaces, 36 excludes");

        auto bridge_cfg = config::parse_kdl(R"kdl(
schema-version 1
role "client"
inbounds {
    inbound "tun" type="tun" {
        device-mode "bridge"
        mtu 1400
    }
}
outbounds { outbound "direct" type="direct"; }
routing { default-outbound "direct"; }
)kdl");
        require(bridge_cfg.has_value() && bridge_cfg->inbounds[0].tun->extra.bridge_mode, "device-mode bridge parsed");

        auto skip_cfg = config::parse_kdl(R"kdl(
schema-version 1
role "client"
inbounds {
    inbound "tun" type="tun" {
        device-fd 5 ownership="borrow" skip-ioctl=#true
    }
}
outbounds { outbound "direct" type="direct"; }
routing { default-outbound "direct"; }
)kdl");
        require(skip_cfg.has_value() && skip_cfg->inbounds[0].tun->extra.device_fd_skip_ioctl,
            "device-fd skip-ioctl parsed");

        namespace nft = platform::nftables;
        std::vector<nft::Prefix> nft_exc;
        for (std::uint8_t i = 0; i < 40; ++i) nft_exc.push_back({4, 24, {198, 18, i, 0}});
        std::array<nft::UidRange, 2> inc_uids{{{1000, 1000}, {1000000, 1099999}}};
        std::array<nft::UidRange, 1> exc_uids{{{0, 0}}};
        std::array<std::array<char, 16>, 1> inc_ifs{{{'w', 'l', 'a', 'n', '0'}}};
        std::array<std::array<char, 16>, 1> exc_ifs{{{'r', 'm', 'n', 'e', 't', '0'}}};
        nft::Redirect rd{
            .port = 32123, .ipv4 = true, .ipv6 = false, .intercept_dns = true, .socket_mark = 0x6e780001u,
            .excludes = nft_exc, .input_mark = 0x1111u, .output_mark = 0x2222u, .reset_mark = 0x3333u,
            .include_uids = inc_uids, .exclude_uids = exc_uids,
            .include_interfaces = inc_ifs, .exclude_interfaces = exc_ifs
        };
        auto tx = nft::encode("nexus_auto_redirect_polish", &rd, 1);
        require(tx.has_value() && tx->end > 80 && tx->bytes.size() > 512,
            "nftables encodes marks, uid ranges, interfaces, and 40 excludes");

        // Batch 169: nftables::Table stop() cleans up cleanly even without active kernel table
        nft::Table tbl;
        require(!tbl.stop(nft::Clock::now() + std::chrono::milliseconds(50)), "nftables unowned stop returns ok");

        // Batch 169: FakeIpStore::flush() + stop() durability roundtrip
        auto fk_dir = std::filesystem::temp_directory_path() / ("nexus-b169-fakeip-" + std::to_string(::getpid()));
        std::error_code ec;
        std::filesystem::remove_all(fk_dir, ec);
        std::filesystem::create_directories(fk_dir, ec);
        std::filesystem::permissions(fk_dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
        {
            state::FakeIpScope scope{0xc6120000u, 0xc61200ffu, 0xc6120001u, 0xc61200feu};
            auto store = state::FakeIpStore::open(fk_dir, scope, state::CrashMode::range_reserve);
            require(store.has_value(), "FakeIpStore::open");
            auto a1 = (*store)->assign("alpha.example", 0);
            auto a2 = (*store)->assign("beta.example", 0);
            require(a1.has_value() && a2.has_value() && *a1 != *a2, "FakeIpStore::assign");
            require((*store)->flush().has_value() && (*store)->stop().has_value(), "FakeIpStore::flush + stop");
        }
        {
            state::FakeIpScope scope{0xc6120000u, 0xc61200ffu, 0xc6120001u, 0xc61200feu};
            auto reopened = state::FakeIpStore::open(fk_dir, scope, state::CrashMode::range_reserve);
            require(reopened.has_value(), "FakeIpStore::reopen");
            std::vector<std::string> domains;
            require((*reopened)->visit_recovered([&](state::FakeIpRow const& r) {
                domains.push_back(r.domain); return true;
            }), "FakeIpStore::visit_recovered");
            require(std::ranges::contains(domains, "alpha.example") && std::ranges::contains(domains, "beta.example"),
                "FakeIpStore::flush/stop persisted both domains");
            require((*reopened)->stop().has_value(), "reopened stop");
        }
        std::filesystem::remove_all(fk_dir, ec);
    }
}

int main() {
    test_protect_fd();
    test_route_plans_and_attach();
    test_ios_bridge_e2e();
    test_linux_redirect_and_config_polish();
    test_p0_fd_drop_direct_protect_and_fd_sock();
    std::cout << "BATCH 189 CROSS-PLATFORM TUN TESTS PASSED\n";
    return 0;
}
