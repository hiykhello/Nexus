#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import config;
import cli.gen_tools;
import cli.proxy_services;
import control_api;
import control_api.types;
import logging.cli;
import quic.ech_config;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }
}

int main() {
    // 1. Lightweight services KDL parsing (and verify non-wired services stay excluded).
    {
        auto tmp_dir = std::filesystem::temp_directory_path() / "nexus_batch168_acme";
        std::filesystem::create_directories(tmp_dir);
        std::string kdl = std::format(R"kdl(
schema-version 1
role "server"
inbounds {{
    inbound "socks" type="socks5" {{
        listen host="127.0.0.1" port=1080
        authentication "none"
    }}
}}
outbounds {{ outbound "direct" type="direct"; }}
services {{
    memory-watchdog soft-mb=32 hard-mb=48 emergency-mb=64 cooldown-ms=1000
    ssmapi enabled=#true prefix="/ssmapi"
    sni-demux listen-host="127.0.0.1" listen-port=8443 fallback-upstream="127.0.0.1:9443" {{
        rule "*.example.com" upstream="127.0.0.1:443" alpn="h2" role="https"
    }}
    acme directory-url="https://acme.invalid/dir" email="ops@example.com" challenge="http-01" state-dir="{}" {{
        domain "edge.example.com"
    }}
    reverse-tunnel token="secret-token" max-streams=64 heartbeat-timeout-ms=15000
    bridge tun-interface="nexus-tun9" physical-interface="eth0" mtu=1500 allow-ipv4=#true allow-ipv6=#false drop-link-local=#true
    tor socks-host="127.0.0.1" socks-port=9050 control-host="127.0.0.1" control-port=9051 isolate-streams=#true
    derp-server max-peers=128
}}
routing {{
    default-outbound "direct"
}}
)kdl", tmp_dir.string());

        auto cfg = config::parse_kdl(kdl);
        require(cfg.has_value(), cfg ? "" : cfg.error());
        require(cfg->services.any_configured(), "services configured");
        require(cfg->services.memory_watchdog && cfg->services.memory_watchdog->emergency_mb == 64, "watchdog");
        require(cfg->services.ssmapi && cfg->services.ssmapi->enabled, "ssmapi");
        require(cfg->services.sni_demux && cfg->services.sni_demux->rules.size() == 1, "sni-demux");
        require(cfg->services.acme && cfg->services.acme->domains.size() == 1, "acme");
        require(cfg->services.reverse_tunnel && cfg->services.reverse_tunnel->max_streams == 64, "reverse-tunnel");
        require(cfg->services.bridge && cfg->services.bridge->mtu == 1500, "bridge");
        require(cfg->services.tor && cfg->services.tor->socks_port == 9050, "tor");
        require(cfg->services.derp_server && cfg->services.derp_server->max_peers == 128, "derp-server");

        logging::Runtime logs;
        cli::OptionalServicesRuntime rt;
        // Batch 173: real runtime I/O for watchdog, sni-demux, acme, reverse-tunnel, tor, derp-server.
        config::ServicesConfig live_cfg = cfg->services;
        live_cfg.sni_demux->listen_port = 0;
        live_cfg.bridge.reset();
        auto started = rt.start(live_cfg, logs);
        require(started.has_value() && rt.active_count() == 6, started ? "6 services active" : started.error());
        rt.poll(1000, logs);
        rt.stop();

        // Non-existent bridge physical interface fails closed and rolls back all prior services cleanly.
        config::ServicesConfig fail_cfg = live_cfg;
        fail_cfg.bridge = config::BridgeServiceConfig{.tun_interface = "nx-tun-none", .physical_interface = "nx_nonexistent_if99"};
        auto full = rt.start(fail_cfg, logs);
        require(!full.has_value() && rt.active_count() == 0, "bridge failure rolls back earlier services");
        std::filesystem::remove_all(tmp_dir);

        auto bad_kdl = R"kdl(
schema-version 1
role "client"
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds { outbound "direct" type="direct"; }
services {
    openvpn
}
routing { default-outbound "direct" }
)kdl";
        require(!config::parse_kdl(bad_kdl).has_value(), "excluded service openvpn rejected");
    }

    // 2. HTTP control + ssmapi dispatch round-trip.
    {
        control_api::HttpControlServer srv;
        require(srv.configure_ssmapi(true, "/ssmapi").has_value(), "configure ssmapi");
        auto snap_fn = []() -> control_api::ControlSnapshot { return {}; };
        auto cmd_fn = [](std::span<std::string_view const>) -> std::expected<std::string, std::string> {
            return std::string{"ok"};
        };
        std::string_view body = R"({"username":"alice","uPSK":"secret123","enabled":true,"byteQuota":1024})";
        std::string post_req = std::format(
            "POST /ssmapi/users HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}", body.size(), body);
        auto post_resp = srv.handle_direct_http_for_test(post_req, snap_fn, cmd_fn);
        require(post_resp.contains("201 Created") && post_resp.contains("alice"), "ssmapi POST");

        std::string get_req = "GET /ssmapi/users HTTP/1.1\r\nHost: localhost\r\n\r\n";
        auto get_resp = srv.handle_direct_http_for_test(get_req, snap_fn, cmd_fn);
        require(get_resp.contains("200 OK") && get_resp.contains("alice"), "ssmapi GET");

        std::string stats_req = "GET /ssmapi/stats HTTP/1.1\r\nHost: localhost\r\n\r\n";
        auto stats_resp = srv.handle_direct_http_for_test(stats_req, snap_fn, cmd_fn);
        require(stats_resp.contains("200 OK") && stats_resp.contains("\"userCount\":1"), "ssmapi stats");
    }

    // 3. CLI generate & tools connect verification.
    {
        auto u = cli::generate_uuid();
        require(u && u->size() == 36 && (*u)[14] == '4', "uuid v4");
        auto rk = cli::generate_x25519_keypair(true);
        require(rk && rk->first.size() == 43 && rk->second.size() == 43, "reality keypair");
        auto wg = cli::generate_x25519_keypair(false);
        require(wg && wg->first.size() == 44 && wg->second.size() == 44, "wg keypair");
        auto ss = cli::generate_ss2022_key(32);
        require(ss && ss->size() == 44, "ss2022 key");
        auto cert = cli::generate_self_signed_tls("test.example", 30);
        require(cert && cert->first.contains("BEGIN CERTIFICATE") && cert->second.contains("BEGIN PRIVATE KEY"), "selfsigned tls");
        auto ech = cli::generate_ech_keypair("public.example.com");
        require(ech.has_value(), "ech keypair");
        auto parsed_ech = quic::select_ech_config(ech->config_list_wire);
        require(parsed_ech && parsed_ech->public_name == "public.example.com", "ech config list");

        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        require(fd >= 0, "socket");
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        require(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "bind");
        socklen_t len = sizeof(addr);
        require(::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0, "getsockname");
        require(::listen(fd, 4) == 0, "listen");
        auto rtt = cli::probe_tcp_connect("127.0.0.1", ntohs(addr.sin_port), 2000);
        require(rtt && *rtt >= 0.0, "probe_tcp_connect");
        ::close(fd);
    }

    std::cout << "BATCH 168 SERVICES AND CLI TOOLS UNIT TESTS PASSED\n";
    return 0;
}
