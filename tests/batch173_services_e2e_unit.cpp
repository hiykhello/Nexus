#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import config;
import cli.proxy_services;
import logging;
import logging.cli;
import packet;
import relay;
import rules;

namespace {
    using namespace std::chrono_literals;

    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) { std::cerr << "FAIL [batch173]: " << msg << '\n'; std::exit(1); }
    }

    struct Fd {
        int fd = -1;
        Fd() = default;
        explicit Fd(int f) noexcept : fd(f) {}
        ~Fd() { if (fd >= 0) ::close(fd); }
        Fd(Fd const&) = delete;
        auto operator=(Fd const&) -> Fd& = delete;
        Fd(Fd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
        auto operator=(Fd&& o) noexcept -> Fd& { if (this != &o) { if (fd >= 0) ::close(fd); fd = std::exchange(o.fd, -1); } return *this; }
    };

    auto connect_loopback(std::uint16_t port) -> Fd {
        Fd s(::socket(AF_INET, SOCK_STREAM, 0));
        require(s.fd >= 0, "socket");
        sockaddr_in a{.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::connect(s.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0, "connect loopback");
        return s;
    }

    auto listen_loopback() -> std::pair<Fd, std::uint16_t> {
        Fd s(::socket(AF_INET, SOCK_STREAM, 0));
        require(s.fd >= 0, "listen socket");
        int one = 1; (void)::setsockopt(s.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::bind(s.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0 && ::listen(s.fd, 16) == 0, "bind/listen");
        socklen_t len = sizeof(a);
        require(::getsockname(s.fd, reinterpret_cast<sockaddr*>(&a), &len) == 0, "getsockname");
        return {std::move(s), ntohs(a.sin_port)};
    }

    auto send_all(int fd, std::span<std::uint8_t const> data) -> bool {
        while (!data.empty()) {
            auto n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
            if (n <= 0) return false;
            data = data.subspan(static_cast<std::size_t>(n));
        }
        return true;
    }
    auto send_str(int fd, std::string_view s) -> bool {
        return send_all(fd, {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()});
    }

    auto recv_exact(int fd, std::span<std::uint8_t> dst, int timeout_ms = 2000) -> bool {
        auto dl = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (!dst.empty()) {
            auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(dl - std::chrono::steady_clock::now()).count();
            if (rem <= 0) return false;
            pollfd p{fd, POLLIN, 0};
            if (::poll(&p, 1, static_cast<int>(rem)) <= 0) return false;
            auto n = ::recv(fd, dst.data(), dst.size(), 0);
            if (n <= 0) return false;
            dst = dst.subspan(static_cast<std::size_t>(n));
        }
        return true;
    }

    auto build_client_hello(std::string_view sni, std::initializer_list<std::string_view> alpns) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> ext;
        if (!sni.empty()) {
            std::uint16_t ll = static_cast<std::uint16_t>(3 + sni.size()), el = static_cast<std::uint16_t>(2 + ll);
            ext.insert(ext.end(), {0, 0, std::uint8_t(el >> 8), std::uint8_t(el), std::uint8_t(ll >> 8), std::uint8_t(ll), 0,
                std::uint8_t(sni.size() >> 8), std::uint8_t(sni.size())});
            ext.insert(ext.end(), sni.begin(), sni.end());
        }
        if (alpns.size()) {
            std::vector<std::uint8_t> al;
            for (auto p : alpns) { al.push_back(std::uint8_t(p.size())); al.insert(al.end(), p.begin(), p.end()); }
            std::uint16_t ll = static_cast<std::uint16_t>(al.size()), el = static_cast<std::uint16_t>(2 + ll);
            ext.insert(ext.end(), {0, 16, std::uint8_t(el >> 8), std::uint8_t(el), std::uint8_t(ll >> 8), std::uint8_t(ll)});
            ext.insert(ext.end(), al.begin(), al.end());
        }
        std::vector<std::uint8_t> h{3, 3};
        h.resize(h.size() + 32, 0x22);
        h.insert(h.end(), {0, 0, 2, 0x13, 0x01, 1, 0, std::uint8_t(ext.size() >> 8), std::uint8_t(ext.size())});
        h.insert(h.end(), ext.begin(), ext.end());
        std::size_t hl = h.size(), rl = hl + 4;
        std::vector<std::uint8_t> out{0x16, 3, 1, std::uint8_t(rl >> 8), std::uint8_t(rl),
            1, std::uint8_t(hl >> 16), std::uint8_t(hl >> 8), std::uint8_t(hl)};
        out.insert(out.end(), h.begin(), h.end());
        return out;
    }

    // 173.A: SNI-Demux Real Front TCP Listener + ClientHello Peek + Raw Relay
    auto test_173a_sni_demux_e2e() -> void {
        auto [acc_a, port_a] = listen_loopback();
        auto [acc_b, port_b] = listen_loopback();
        auto [acc_fb, port_fb] = listen_loopback();
        std::atomic_bool stop{false};

        auto run_tag_backend = [&](int lfd, std::string tag) {
            return std::jthread([lfd, tag = std::move(tag), &stop] {
                while (!stop) {
                    pollfd p{lfd, POLLIN, 0};
                    if (::poll(&p, 1, 10) <= 0) continue;
                    Fd c(::accept(lfd, nullptr, nullptr));
                    if (c.fd < 0) continue;
                    std::array<std::uint8_t, 2048> buf{};
                    pollfd cp{c.fd, POLLIN, 0};
                    if (::poll(&cp, 1, 1000) > 0) {
                        auto n = ::recv(c.fd, buf.data(), buf.size(), 0);
                        if (n > 0) {
                            (void)send_str(c.fd, tag);
                            (void)send_all(c.fd, std::span(buf.data(), static_cast<std::size_t>(n)));
                        }
                    }
                }
            });
        };
        auto th_a = run_tag_backend(acc_a.fd, "A:");
        auto th_b = run_tag_backend(acc_b.fd, "B:");
        auto th_fb = run_tag_backend(acc_fb.fd, "F:");

        logging::Runtime logs;
        config::SniDemuxConfig cfg{
            .listen_host = "127.0.0.1",
            .listen_port = 0,
            .fallback_upstream = std::format("127.0.0.1:{}", port_fb),
            .rules = {
                {"proxy.edge.example", "h2", "proxy", std::format("127.0.0.1:{}", port_a)},
                {"*.edge.example", "", "https", std::format("127.0.0.1:{}", port_b)},
            },
        };
        auto handle = cli::init_sni_demux_service(cfg, logs);
        require(handle.has_value(), handle ? "" : handle.error());
        auto dport = cli::sni_demux_bound_port(*handle);
        require(dport != 0, "sni-demux bound port");

        auto check_route = [&](std::vector<std::uint8_t> const& payload, std::string_view expected_prefix) {
            auto c = connect_loopback(dport);
            require(send_all(c.fd, payload), "send hello");
            std::vector<std::uint8_t> got(expected_prefix.size() + payload.size());
            require(recv_exact(c.fd, got), "recv tagged passthrough");
            require(std::string_view(reinterpret_cast<char const*>(got.data()), expected_prefix.size()) == expected_prefix, "backend tag");
            require(std::equal(payload.begin(), payload.end(), got.begin() + static_cast<std::ptrdiff_t>(expected_prefix.size())),
                "exact unmodified raw ClientHello passthrough");
        };
        check_route(build_client_hello("proxy.edge.example", {"h2", "http/1.1"}), "A:");
        check_route(build_client_hello("panel.edge.example", {"http/1.1"}), "B:");
        check_route(build_client_hello("other.invalid", {"h2"}), "F:");
        std::string_view plain_http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        check_route(std::vector<std::uint8_t>(plain_http.begin(), plain_http.end()), "F:");

        handle->state.reset();
        stop = true;
    }

    // 173.C: Tor Real Outbound Dial Factory (Stream Isolation) + ControlPort
    auto test_173c_tor_e2e() -> void {
        auto [socks_fd, socks_port] = listen_loopback();
        auto [ctrl_fd, ctrl_port] = listen_loopback();
        std::atomic_bool stop{false};
        std::mutex mu;
        std::vector<std::string> seen_users;
        std::vector<std::string> seen_domains;

        std::jthread socks_thr([&] {
            while (!stop) {
                pollfd p{socks_fd.fd, POLLIN, 0};
                if (::poll(&p, 1, 10) <= 0) continue;
                Fd c(::accept(socks_fd.fd, nullptr, nullptr));
                if (c.fd < 0) continue;
                std::array<std::uint8_t, 4> g{};
                if (!recv_exact(c.fd, std::span(g).first(2)) || g[0] != 5) continue;
                std::vector<std::uint8_t> methods(g[1]);
                if (!recv_exact(c.fd, methods)) continue;
                std::array<std::uint8_t, 2> pick{5, 2};
                if (!send_all(c.fd, pick)) continue;
                std::array<std::uint8_t, 2> ah{};
                if (!recv_exact(c.fd, ah) || ah[0] != 1) continue;
                std::string user(ah[1], '\0');
                if (!recv_exact(c.fd, {reinterpret_cast<std::uint8_t*>(user.data()), user.size()})) continue;
                std::uint8_t plen = 0;
                if (!recv_exact(c.fd, {&plen, 1})) continue;
                std::string pass(plen, '\0');
                if (!recv_exact(c.fd, {reinterpret_cast<std::uint8_t*>(pass.data()), pass.size()})) continue;
                std::array<std::uint8_t, 2> aok{1, 0};
                if (!send_all(c.fd, aok)) continue;
                std::array<std::uint8_t, 4> req{};
                if (!recv_exact(c.fd, req) || req[0] != 5 || req[1] != 1 || req[3] != 3) continue;
                std::uint8_t dlen = 0;
                if (!recv_exact(c.fd, {&dlen, 1})) continue;
                std::string dom(dlen, '\0');
                std::array<std::uint8_t, 2> dport{};
                if (!recv_exact(c.fd, {reinterpret_cast<std::uint8_t*>(dom.data()), dom.size()}) || !recv_exact(c.fd, dport)) continue;
                { std::lock_guard lk(mu); seen_users.push_back(user); seen_domains.push_back(dom); }
                std::array<std::uint8_t, 10> rep{5, 0, 0, 1, 127, 0, 0, 1, 0, 80};
                if (!send_all(c.fd, rep)) continue;
                std::array<std::uint8_t, 64> msg{};
                pollfd mp{c.fd, POLLIN, 0};
                if (::poll(&mp, 1, 1000) > 0) {
                    auto n = ::recv(c.fd, msg.data(), msg.size(), 0);
                    if (n > 0) (void)send_all(c.fd, std::span(msg.data(), static_cast<std::size_t>(n)));
                }
            }
        });

        std::atomic<int> newnym_count{0};
        std::jthread ctrl_thr([&] {
            while (!stop) {
                pollfd p{ctrl_fd.fd, POLLIN, 0};
                if (::poll(&p, 1, 10) <= 0) continue;
                Fd c(::accept(ctrl_fd.fd, nullptr, nullptr));
                if (c.fd < 0) continue;
                std::array<char, 256> b{};
                auto n = ::recv(c.fd, b.data(), b.size(), 0);
                if (n <= 0 || !std::string_view(b.data(), static_cast<std::size_t>(n)).starts_with("AUTHENTICATE \"secret-tor\"")) continue;
                (void)send_str(c.fd, "250 OK\r\n");
                n = ::recv(c.fd, b.data(), b.size(), 0);
                if (n <= 0) continue;
                std::string_view cmd(b.data(), static_cast<std::size_t>(n));
                if (cmd.starts_with("SIGNAL NEWNYM")) {
                    newnym_count.fetch_add(1);
                    (void)send_str(c.fd, "250 OK\r\n");
                } else if (cmd.starts_with("GETINFO status/bootstrap-phase")) {
                    (void)send_str(c.fd, "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n");
                }
            }
        });

        auto srv = relay::Server::create();
        require(srv.has_value(), "srv create");
        logging::Runtime logs;
        config::TorServiceConfig tcfg{
            .socks_host = "127.0.0.1", .socks_port = socks_port,
            .control_host = "127.0.0.1", .control_port = ctrl_port,
            .control_password = "secret-tor", .isolate_streams = true,
        };
        auto tor_h = cli::init_tor_service(tcfg, logs, {.register_outbound = [&](config::TorServiceConfig const& c) {
            return (*srv)->add_tor(c);
        }});
        require(tor_h.has_value(), tor_h ? "" : tor_h.error());
        std::array<rules::ProgramRule, 0> no_rules{};
        require((*srv)->set_ordered_tcp(no_rules, 2, 1000, false, false).has_value(), "ordered tcp -> tor");
        auto lp = (*srv)->start(0, relay::Inbound::socks5, 1);
        require(lp.has_value(), "srv start");
        std::jthread srv_thr([&] { while (!stop) (*srv)->poll(5ms); (*srv)->stop(); });

        auto dial_via_tor = [&](std::string_view domain, std::string_view msg) {
            auto c = connect_loopback(*lp);
            std::array<std::uint8_t, 3> gr{5, 1, 0};
            require(send_all(c.fd, gr), "socks5 greet");
            std::array<std::uint8_t, 2> gr_rep{};
            require(recv_exact(c.fd, gr_rep) && gr_rep[1] == 0, "socks5 greet rep");
            std::vector<std::uint8_t> req{5, 1, 0, 3, static_cast<std::uint8_t>(domain.size())};
            req.insert(req.end(), domain.begin(), domain.end());
            req.insert(req.end(), {0, 80});
            require(send_all(c.fd, req), "socks5 connect");
            std::array<std::uint8_t, 10> rep{};
            require(recv_exact(c.fd, rep) && rep[1] == 0, "socks5 connect ok");
            require(send_str(c.fd, msg), "send msg");
            std::vector<std::uint8_t> echo(msg.size());
            require(recv_exact(c.fd, echo) && std::string_view(reinterpret_cast<char const*>(echo.data()), echo.size()) == msg, "tor echo");
        };
        dial_via_tor("duck.onion", "hello-tor-1");
        dial_via_tor("duck.onion", "hello-tor-2");

        require(seen_users.size() == 2 && seen_users[0] != seen_users[1], "per-stream Tor circuit isolation credentials");
        require(seen_domains.size() == 2 && seen_domains[0] == "duck.onion", "ATYP=DOMAINNAME zero DNS leak");
        require(cli::tor_signal_newnym(*tor_h).has_value() && newnym_count.load() == 1, "Tor ControlPort NEWNYM");
        auto boot = cli::tor_query_bootstrap(*tor_h);
        require(boot.has_value() && *boot == 100, "Tor ControlPort bootstrap=100");
        stop = true;
    }

    // 173.E: Bridge Real Bidirectional L3 Packet Pump (TUN <-> Physical)
    auto test_173e_bridge_e2e() -> void {
        int tun_sp[2]{-1, -1}, phys_sp[2]{-1, -1};
        require(::socketpair(AF_UNIX, SOCK_DGRAM, 0, tun_sp) == 0 && ::socketpair(AF_UNIX, SOCK_DGRAM, 0, phys_sp) == 0, "socketpair");
        Fd tun_peer(tun_sp[1]), phys_peer(phys_sp[1]);
        logging::Runtime logs;
        config::BridgeServiceConfig bcfg{.tun_interface = "nx-tun0", .physical_interface = "eth0", .mtu = 1500};
        auto h = cli::init_bridge_service_with_fds(bcfg, tun_sp[0], phys_sp[0], logs);
        require(h.has_value(), h ? "" : h.error());

        std::vector<std::uint8_t> v4(28, 0);
        v4[0] = 0x45; v4[3] = 28; v4[8] = 64; v4[9] = 17;
        v4[12] = 10; v4[15] = 1; v4[16] = 10; v4[19] = 2;
        auto csum = packet::internet_checksum(std::span(v4).first(20));
        v4[10] = std::uint8_t(csum >> 8); v4[11] = std::uint8_t(csum);
        require(::send(tun_peer.fd, v4.data(), v4.size(), 0) == 28, "send v4");
        std::array<std::uint8_t, 64> rx{};
        pollfd p{phys_peer.fd, POLLIN, 0};
        require(::poll(&p, 1, 1000) > 0 && ::recv(phys_peer.fd, rx.data(), rx.size(), 0) == 28, "recv v4 on phys");
        require(rx[8] == 63 && packet::internet_checksum(std::span(rx).first(20)) == 0, "v4 TTL=63 & checksum ok");

        std::vector<std::uint8_t> v6(48, 0);
        v6[0] = 0x60; v6[5] = 8; v6[6] = 17; v6[7] = 32;
        v6[8] = 0x20; v6[9] = 0x01; v6[24] = 0x20; v6[25] = 0x01;
        require(::send(phys_peer.fd, v6.data(), v6.size(), 0) == 48, "send v6");
        pollfd tp{tun_peer.fd, POLLIN, 0};
        require(::poll(&tp, 1, 1000) > 0 && ::recv(tun_peer.fd, rx.data(), rx.size(), 0) == 48, "recv v6 on tun");
        require(rx[7] == 31, "v6 HopLimit=31");

        v4[8] = 1;
        require(::send(tun_peer.fd, v4.data(), v4.size(), 0) == 28, "send ttl=1");
        v4[8] = 64; v4[12] = 169; v4[13] = 254;
        require(::send(tun_peer.fd, v4.data(), v4.size(), 0) == 28, "send link-local");

        auto dl = std::chrono::steady_clock::now() + 1s;
        cli::BridgeStatsSnapshot st{};
        while (std::chrono::steady_clock::now() < dl) {
            st = cli::bridge_stats(*h);
            if (st.dropped_ttl >= 1 && st.dropped_filtered >= 1) break;
            std::this_thread::sleep_for(10ms);
        }
        require(st.forwarded_v4 == 1 && st.forwarded_v6 == 1 && st.dropped_ttl == 1 && st.dropped_filtered == 1, "bridge stats");
    }

    // 173.F: Reverse-Tunnel Real Control Connection + Multiplexed Streams
    auto test_173f_reverse_tunnel_e2e() -> void {
        auto [echo_fd, echo_port] = listen_loopback();
        std::atomic_bool stop{false};
        std::jthread echo_thr([&] {
            while (!stop) {
                pollfd p{echo_fd.fd, POLLIN, 0};
                if (::poll(&p, 1, 10) <= 0) continue;
                int c = ::accept(echo_fd.fd, nullptr, nullptr);
                if (c < 0) continue;
                std::thread([c] {
                    Fd g(c);
                    std::array<std::uint8_t, 1024> b{};
                    for (;;) {
                        auto n = ::recv(g.fd, b.data(), b.size(), 0);
                        if (n <= 0) break;
                        if (!send_all(g.fd, std::span(b.data(), static_cast<std::size_t>(n)))) break;
                    }
                }).detach();
            }
        });

        logging::Runtime logs;
        config::ReverseTunnelServiceConfig scfg{
            .token = "rt-secret-173", .max_streams = 64, .heartbeat_timeout_ms = 5000,
            .mode = "server", .control_host = "127.0.0.1", .control_port = 0,
            .expose_host = "127.0.0.1", .expose_port = 0,
        };
        auto srv_h = cli::init_reverse_tunnel_service(scfg, logs);
        require(srv_h.has_value(), srv_h ? "" : srv_h.error());
        auto cport = cli::reverse_tunnel_control_port(*srv_h);
        auto eport = cli::reverse_tunnel_expose_port(*srv_h);
        require(cport != 0 && eport != 0, "reverse-tunnel ports bound");

        config::ReverseTunnelServiceConfig ccfg{
            .token = "rt-secret-173", .max_streams = 64, .heartbeat_timeout_ms = 5000,
            .mode = "client", .control_host = "127.0.0.1", .control_port = cport,
            .target_host = "127.0.0.1", .target_port = echo_port,
        };
        auto cli_h = cli::init_reverse_tunnel_service(ccfg, logs);
        require(cli_h.has_value(), cli_h ? "" : cli_h.error());
        std::this_thread::sleep_for(60ms);

        std::array<Fd, 3> clients{connect_loopback(eport), connect_loopback(eport), connect_loopback(eport)};
        std::array<std::string, 3> msgs{"stream-alpha-173", "stream-beta-173-payload", "stream-gamma-173!"};
        for (std::size_t i = 0; i < 3; ++i) require(send_str(clients[i].fd, msgs[i]), "send mux stream");
        for (std::size_t i = 0; i < 3; ++i) {
            std::vector<std::uint8_t> got(msgs[i].size());
            require(recv_exact(clients[i].fd, got) &&
                std::string_view(reinterpret_cast<char const*>(got.data()), got.size()) == msgs[i], "mux echo");
        }
        cli_h->state.reset();
        srv_h->state.reset();
        stop = true;
    }
}

int main() {
    test_173a_sni_demux_e2e();
    test_173c_tor_e2e();
    test_173e_bridge_e2e();
    test_173f_reverse_tunnel_e2e();
    std::cout << "BATCH 173 SNI-DEMUX / TOR / BRIDGE / REVERSE-TUNNEL E2E TESTS PASSED\n";
    return 0;
}
