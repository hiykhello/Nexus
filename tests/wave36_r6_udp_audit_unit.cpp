#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

import std;
import cli.proxy_listener;
import cli.route_files;
import cli.udp_enabled;
import config;
import crypto;
import platform.wall_clock;
import relay;
import rules;
import shadowsocks.udp_client;

namespace {
    using namespace std::chrono_literals;
    int g_failures = 0;

    auto check(bool ok, std::string_view label) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << label << "\n";
            ++g_failures;
        }
    }

    struct TempDir {
        std::filesystem::path path;
        TempDir() {
            auto base = std::filesystem::temp_directory_path() / "nexus-r6-udp-audit-XXXXXX";
            std::string tmpl = base.string();
            char* created = ::mkdtemp(tmpl.data());
            if (!created) throw std::runtime_error("mkdtemp failed");
            path = created;
        }
        ~TempDir() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    };

    struct UdpFd {
        int fd = -1;
        UdpFd() = default;
        explicit UdpFd(int f) noexcept : fd(f) {}
        UdpFd(UdpFd const&) = delete;
        auto operator=(UdpFd const&) -> UdpFd& = delete;
        UdpFd(UdpFd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
        auto operator=(UdpFd&& o) noexcept -> UdpFd& {
            if (this != &o) { if (fd >= 0) ::close(fd); fd = std::exchange(o.fd, -1); }
            return *this;
        }
        ~UdpFd() { if (fd >= 0) ::close(fd); }
    };

    auto make_loopback_udp(std::uint16_t& port_out) -> UdpFd {
        UdpFd s(::socket(AF_INET, SOCK_DGRAM, 0));
        sockaddr_in sa{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        check(s.fd >= 0 && ::bind(s.fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0, "bind loopback UDP");
        socklen_t len = sizeof(sa);
        check(::getsockname(s.fd, reinterpret_cast<sockaddr*>(&sa), &len) == 0, "getsockname loopback UDP");
        port_out = ntohs(sa.sin_port);
        return s;
    }

    auto alloc_udp_port() -> std::uint16_t {
        std::uint16_t port = 0;
        auto s = make_loopback_udp(port);
        return port;
    }

    auto wait_readable(int fd, int timeout_ms) -> bool {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        for (;;) {
            auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (rem <= 0) return false;
            pollfd pfd{fd, POLLIN, 0};
            int r = ::poll(&pfd, 1, static_cast<int>(rem));
            if (r < 0 && errno == EINTR) continue;
            return r > 0 && (pfd.revents & POLLIN) != 0;
        }
    }

    auto recv_udp_with_timeout(int fd, std::span<std::uint8_t> buf, int timeout_ms) -> std::optional<std::size_t> {
        if (!wait_readable(fd, timeout_ms)) return std::nullopt;
        ssize_t n = -1;
        do {
            n = ::recvfrom(fd, buf.data(), buf.size(), 0, nullptr, nullptr);
        } while (n < 0 && errno == EINTR);
        if (n < 0) return std::nullopt;
        return static_cast<std::size_t>(n);
    }

    auto write_file_bytes(std::filesystem::path const& path, std::string_view content, bool private_mode = false) -> void {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.close();
        check(static_cast<bool>(out), "write file");
        if (private_mode) check(::chmod(path.c_str(), 0600) == 0, "chmod 0600");
    }

    auto test_r6_p2_1_ss2022_native_udp_nxmm(TempDir const& tmp) -> void {
        // Loopback UDP echo backend + hit counter.
        std::uint16_t echo_port = 0;
        auto echo_sock = make_loopback_udp(echo_port);
        std::atomic<bool> stop_echo{false};
        std::atomic<int> echo_hits{0};
        std::jthread echo_thr([&] {
            std::array<std::uint8_t, 512> buf{};
            while (!stop_echo.load(std::memory_order_relaxed)) {
                if (!wait_readable(echo_sock.fd, 15)) continue;
                sockaddr_in cli{}; socklen_t cl = sizeof(cli);
                ssize_t n = -1;
                do { n = ::recvfrom(echo_sock.fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&cli), &cl); }
                while (n < 0 && errno == EINTR);
                if (n < 0) continue;
                echo_hits.fetch_add(1, std::memory_order_relaxed);
                (void)::sendto(echo_sock.fd, buf.data(), static_cast<std::size_t>(n), 0, reinterpret_cast<sockaddr*>(&cli), cl);
            }
        });

        auto key_path = tmp.path / "ss.key";
        write_file_bytes(key_path, "AQEBAQEBAQEBAQEBAQEBAQ==", true);
        std::array<std::uint8_t, 16> psk{};
        psk.fill(0x01);

        rules::RuleSet rs{.rules = {
            {"ip-cidr", "127.0.0.1/32", {}},
            {"domain", "nxmm-rule.test", {}}
        }, .version = 2};
        auto nxmm = rules::compile_nxmm(rs);
        check(nxmm.has_value() && !nxmm->empty(), "R6 P2-1 compile_nxmm succeeded");
        if (!nxmm) { stop_echo = true; return; }
        auto nxmm_path = tmp.path / "route.nxmm";
        write_file_bytes(nxmm_path, *nxmm);

        rules::RuleSet rs_net{.rules = {{"ip-cidr", "127.0.0.0/8", {}}}, .version = 2};
        auto nxmm_net = rules::compile_nxmm(rs_net);
        check(nxmm_net.has_value() && !nxmm_net->empty(), "R6 P2-1 compile_nxmm subnet succeeded");
        if (!nxmm_net) { stop_echo = true; return; }
        write_file_bytes(tmp.path / "net.nxmm", *nxmm_net);

        auto run_case = [&](std::string_view label, bool two_rules_allow_first,
                            std::string_view payload, bool expect_echo) {
            std::uint16_t ss_port = alloc_udp_port();
            auto cfg_path = tmp.path / std::format("ss_{}.kdl", label);
            auto routing_block = two_rules_allow_first
                ? std::string(
                    "  rulesets {\n"
                    "    allow path=\"route.nxmm\" format=\"nxmm\"\n"
                    "    deny path=\"net.nxmm\" format=\"nxmm\"\n"
                    "  }\n"
                    "  rules {\n"
                    "    - kind=\"rule-set\" value=\"allow\" outbound=\"direct\"\n"
                    "    - kind=\"rule-set\" value=\"deny\" outbound=\"block\"\n"
                    "  }\n"
                    "  final \"direct\"\n")
                : std::string(
                    "  rulesets { nx path=\"route.nxmm\" format=\"nxmm\"; }\n"
                    "  rules { - kind=\"rule-set\" value=\"nx\" outbound=\"block\"; }\n"
                    "  final \"direct\"\n");
            auto kdl = std::format(
                "schema-version 1\nrole \"server\"\n"
                "inbounds {{ shadowsocks \"ss\" {{ listen host=\"127.0.0.1\" port={}; method \"2022-blake3-aes-128-gcm\"; key-file \"{}\"; }} }}\n"
                "outbounds {{ direct \"direct\"; block \"block\"; }}\n"
                "routing {{\n{}}}\n"
                "dns {{ servers {{ udp \"sys\" host=\"127.0.0.1\" port=5353; }}; final \"sys\"; }}\n",
                ss_port, key_path.string(), routing_block);
            write_file_bytes(cfg_path, kdl);

            auto cfg = config::parse_kdl(kdl);
            check(cfg.has_value(), cfg ? std::format("R6 P2-1 {} parse_kdl", label)
                : std::format("R6 P2-1 {} parse_kdl: {}", label, cfg.error()));
            if (!cfg) return;
            auto files = cli::load_route_files(*cfg, cfg_path.string());
            check(files.has_value(), std::format("R6 P2-1 {} load_route_files", label));
            if (!files) return;
            check(!files->indices.empty() && files->data[files->indices[0]].empty() &&
                  files->data_mmaps[files->indices[0]] != nullptr,
                  std::format("R6 P2-1 {} NXMM loaded into data_mmaps with empty data[]", label));

            std::vector<cli::run_detail::Listener> listeners;
            listeners.push_back(cli::run_detail::make_listener(nullptr, cfg->inbounds.front()));
            cli::ShadowsocksUdpRuntime udp;
            udp.resize(1, true);
            udp.remember(0, psk, {});
            auto configured = cli::run_detail::configure_native_udp(udp, *cfg, *files, listeners, {}, false);
            check(configured.has_value(), configured
                ? std::format("R6 P2-1 {} configure_native_udp accepts NXMM mmap", label)
                : std::format("R6 P2-1 {} configure_native_udp failed: {}", label, configured.error()));
            if (!configured) return;

            relay::SharedDnsGeneration dns_gen(1, 1, 0);
            check(udp.bind_shared_dns(dns_gen, 0, 0), std::format("R6 P2-1 {} bind_shared_dns", label));
            dns_gen.seal();
            auto started = udp.start();
            check(started.has_value(), started
                ? std::format("R6 P2-1 {} udp.start succeeded", label)
                : std::format("R6 P2-1 {} udp.start failed: {}", label, started.error()));
            if (!started) return;

            std::atomic<bool> stop_udp{false};
            std::jthread udp_thr([&] {
                while (!stop_udp.load(std::memory_order_relaxed)) udp.poll();
            });

            int hits_before = echo_hits.load(std::memory_order_relaxed);
            std::array<std::uint8_t, 8> cid{};
            check(crypto::random_bytes(cid).has_value(), "R6 P2-1 client id random");
            shadowsocks::UdpClientSession cli(psk, cid, 4);
            std::array<std::uint8_t, 7> addr{1, 127, 0, 0, 1,
                static_cast<std::uint8_t>(echo_port >> 8), static_cast<std::uint8_t>(echo_port & 0xff)};
            auto wall = static_cast<std::uint64_t>(platform::calibrated_wall_seconds());
            auto req = cli.request(addr, {reinterpret_cast<std::uint8_t const*>(payload.data()), payload.size()},
                {}, std::chrono::steady_clock::now(), wall);
            check(req.has_value(), std::format("R6 P2-1 {} encode SS UDP request", label));
            if (req) {
                std::uint16_t cli_port = 0;
                auto cli_sock = make_loopback_udp(cli_port);
                sockaddr_in dst{.sin_family = AF_INET, .sin_port = htons(ss_port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
                (void)::sendto(cli_sock.fd, req->data(), req->size(), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
                std::array<std::uint8_t, 512> resp{};
                auto got = recv_udp_with_timeout(cli_sock.fd, resp, expect_echo ? 1000 : 180);
                if (expect_echo) {
                    check(got.has_value(), std::format("R6 P2-1 {} received SS UDP reply", label));
                    if (got) {
                        auto pkt = cli.receive(std::span(resp).first(*got), std::chrono::steady_clock::now(), wall);
                        check(pkt.has_value() &&
                              std::string_view(reinterpret_cast<char const*>(pkt->payload.data()), pkt->payload.size()) == payload,
                              std::format("R6 P2-1 {} decrypted SS UDP echo matches payload", label));
                    }
                    check(echo_hits.load(std::memory_order_relaxed) == hits_before + 1,
                          std::format("R6 P2-1 {} echo server observed allowed packet", label));
                } else {
                    check(!got.has_value(), std::format("R6 P2-1 {} NXMM-blocked SS UDP packet dropped", label));
                    check(echo_hits.load(std::memory_order_relaxed) == hits_before,
                          std::format("R6 P2-1 {} echo server received 0 blocked packets", label));
                }
            }
            stop_udp.store(true, std::memory_order_relaxed);
            udp_thr.join();
            udp.stop();
        };

        // 1a: rule 0 (127.0.0.1/32 -> direct) preempts rule 1 (127.0.0.0/8 -> block) via NXMM mmap.
        run_case("allow", true, "r6-nxmm-allow", true);
        // 1b: default=direct, NXMM rule matches 127.0.0.1/32 -> block (proves NXMM blocks!).
        run_case("block", false, "r6-nxmm-block", false);

        // 1c: Raw NXMM bytes fallback when caller omits data_mmaps.
        {
            std::uint16_t ss_port = alloc_udp_port();
            auto kdl = std::format(
                "schema-version 1\nrole \"server\"\n"
                "inbounds {{ shadowsocks \"ss\" {{ listen host=\"127.0.0.1\" port={}; method \"2022-blake3-aes-128-gcm\"; key-file \"{}\"; }} }}\n"
                "outbounds {{ direct \"direct\"; block \"block\"; }}\n"
                "routing {{ rulesets {{ nx path=\"route.nxmm\" format=\"nxmm\"; }}; rules {{ - kind=\"rule-set\" value=\"nx\" outbound=\"block\"; }}; final \"direct\"; }}\n",
                ss_port, key_path.string());
            auto cfg = config::parse_kdl(kdl);
            check(cfg.has_value(), cfg ? "R6 P2-1 raw fallback parse_kdl" : ("R6 P2-1 raw fallback parse_kdl: " + cfg.error()));
            if (cfg) {
                std::array<std::string, 1> raw_data{*nxmm};
                std::array<std::size_t, 1> idx{0};
                cli::ShadowsocksUdpRuntime udp;
                udp.resize(1, true);
                udp.remember(0, psk, {});
                auto res = udp.configure(*cfg, raw_data, idx);
                check(res.has_value(), res ? "R6 P2-1 raw NXMM bytes fallback succeeded" : ("R6 P2-1 raw fallback: " + res.error()));
            }
        }

        stop_echo.store(true, std::memory_order_relaxed);
    }

    auto test_r6_p2_2_fixed_udp_ordered_runtime_mode() -> void {
        std::uint16_t echo_port = 0;
        auto echo_sock = make_loopback_udp(echo_port);
        std::atomic<bool> stop{false};
        std::atomic<int> echo_hits{0};
        std::jthread echo_thr([&] {
            std::array<std::uint8_t, 512> buf{};
            while (!stop.load(std::memory_order_relaxed)) {
                if (!wait_readable(echo_sock.fd, 15)) continue;
                sockaddr_in cli{}; socklen_t cl = sizeof(cli);
                ssize_t n = -1;
                do { n = ::recvfrom(echo_sock.fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&cli), &cl); }
                while (n < 0 && errno == EINTR);
                if (n < 0) continue;
                echo_hits.fetch_add(1, std::memory_order_relaxed);
                (void)::sendto(echo_sock.fd, buf.data(), static_cast<std::size_t>(n), 0, reinterpret_cast<sockaddr*>(&cli), cl);
            }
        });

        auto srv = relay::Server::create();
        check(srv.has_value(), "R6 P2-2 create relay::Server");
        if (!srv) { stop = true; return; }
        auto mode = std::make_shared<rules::RuntimeRouteMode>();
        mode->mode.store(rules::RouteMode::rule, std::memory_order_release);
        mode->global_outbound.store(0, std::memory_order_release);

        check((*srv)->set_fixed_udp_target("127.0.0.1", echo_port, 5000), "R6 P2-2 set_fixed_udp_target");
        check((*srv)->set_indexed_routes({}, 0).has_value(), "R6 P2-2 set_indexed_routes");
        rules::ProgramRule block_port{
            .predicates = {.rules = {{"port", std::to_string(echo_port), {}}}, .version = 2},
            .action = {.kind = rules::ProgramActionKind::reject}
        };
        std::array<rules::ProgramRule, 1> ordered{block_port};
        auto ord_ok = (*srv)->set_ordered_tcp(ordered, 0, 200, true, true);
        check(ord_ok.has_value(), ord_ok ? "R6 P2-2 set_ordered_tcp" : ("R6 P2-2 set_ordered_tcp: " + ord_ok.error()));
        (*srv)->set_runtime_mode(mode);

        auto bound = (*srv)->start(0, relay::Inbound::fixed_udp, 1);
        check(bound.has_value(), "R6 P2-2 start fixed-udp listener");
        if (!bound) { stop = true; return; }
        std::uint16_t fixed_port = *bound;
        std::jthread srv_thr([&] {
            while (!stop.load(std::memory_order_relaxed)) (*srv)->poll(5ms);
            (*srv)->stop();
        });

        auto probe = [&](std::string_view label, std::string_view msg, bool expect_echo) {
            int before = echo_hits.load(std::memory_order_relaxed);
            std::uint16_t cp = 0;
            auto cli = make_loopback_udp(cp);
            sockaddr_in dst{.sin_family = AF_INET, .sin_port = htons(fixed_port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
            (void)::sendto(cli.fd, msg.data(), msg.size(), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
            std::array<std::uint8_t, 256> buf{};
            auto got = recv_udp_with_timeout(cli.fd, buf, expect_echo ? 1000 : 180);
            if (expect_echo) {
                check(got.has_value() && std::string_view(reinterpret_cast<char const*>(buf.data()), *got) == msg,
                      std::format("R6 P2-2 {} echoed cleanly", label));
                check(echo_hits.load(std::memory_order_relaxed) == before + 1,
                      std::format("R6 P2-2 {} reached target", label));
            } else {
                check(!got.has_value(), std::format("R6 P2-2 {} blocked (no echo)", label));
                check(echo_hits.load(std::memory_order_relaxed) == before,
                      std::format("R6 P2-2 {} blocked before target", label));
            }
        };

        // 1. rule mode: ordered reject rule blocks target port.
        probe("rule-mode-blocks", "r6-rule-block", false);

        // 2. direct mode: bypasses ordered reject rule and echoes cleanly.
        mode->mode.store(rules::RouteMode::direct, std::memory_order_release);
        probe("direct-mode-allows", "r6-direct-ok", true);

        // 3. global mode (outbound 0 = direct): bypasses ordered reject rule and echoes cleanly.
        mode->global_outbound.store(0, std::memory_order_release);
        mode->mode.store(rules::RouteMode::global, std::memory_order_release);
        probe("global-direct-allows", "r6-global-ok", true);

        // 4. global mode (outbound 1 = block): rejects cleanly.
        mode->global_outbound.store(1, std::memory_order_release);
        probe("global-block-rejects", "r6-global-block", false);

        // 5. back to rule mode: ordered reject rule blocks again.
        mode->mode.store(rules::RouteMode::rule, std::memory_order_release);
        probe("rule-mode-restored-blocks", "r6-rule-again", false);

        stop.store(true, std::memory_order_relaxed);
    }
}

auto main() -> int {
    try {
        TempDir tmp;
        test_r6_p2_1_ss2022_native_udp_nxmm(tmp);
        test_r6_p2_2_fixed_udp_ordered_runtime_mode();
    } catch (std::exception const& ex) {
        std::cerr << "EXCEPTION: " << ex.what() << "\n";
        return 1;
    }
    if (g_failures != 0) {
        std::cerr << "wave36_r6_udp_audit_unit: FAIL (" << g_failures << " failures)\n";
        return 1;
    }
    std::cout << "wave36_r6_udp_audit_unit: PASS\n";
    return 0;
}
