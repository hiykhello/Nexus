import std;
import capy;
import corosio;
import config;
import cli.dns_transports;
import dns.corosio_query;
import dns.input_budget;
import dns.local_config;
import dns.message;
import dns.quic_query;
import dns.tls_query;
import tls.certificate_trust;
import tls.profiles;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }
}

int main() {
    // 1. System trust bundle fallback works with empty ca-file.
    auto trust = tls::load_system_trust_bundle();
    require(trust.has_value(), "system trust bundle");
    auto tls_profile = tls::ClientProfile::load("example.com", "");
    require(tls_profile.has_value(), "tls profile with system CA fallback");

    // 2. Config parsing for hosts, dhcp, mdns, DoH/DoT without ca-file, and detoured plain DNS.
    auto hosts_path = std::filesystem::temp_directory_path() / "nexus_batch166_hosts.txt";
    {
        std::ofstream out(hosts_path);
        out << "192.0.2.55 app.localtest app-alias.localtest\n";
        out << "2001:db8::55 v6.localtest\n";
    }
    std::string kdl = std::format(R"kdl(
schema-version 1
role "client"
inbounds {{
    inbound "socks" type="socks5" {{
        listen host="127.0.0.1" port=1080
        authentication "none"
    }}
}}
outbounds {{
    outbound "direct" type="direct"
    outbound "proxy" type="socks5" {{
        server host="127.0.0.1" port=1081
        udp #true
    }}
}}
dns {{
    servers {{
        server "h" type="hosts" file="{}" {{
            entry host="inline.example" ip="198.51.100.7,2001:db8::7"
        }}
        server "d" type="dhcp" interface="eth0"
        server "m" type="mdns" interface="wlan0"
        server "doh" type="https" host="1.1.1.1" server-name="cloudflare-dns.com" path="/dns-query"
        server "plain-detour" type="udp" host="8.8.8.8" port=53 detour="proxy"
    }}
    final "h"
}}
routing {{
    final "proxy"
}}
)kdl", hosts_path.string());

    auto cfg = config::parse_kdl(kdl);
    require(cfg.has_value(), cfg ? "" : cfg.error());
    require(cfg->dns && cfg->dns->servers.size() == 5, "5 DNS servers parsed");
    require(cfg->dns->servers[0].kind == config::DnsServerKind::hosts, "hosts kind");
    require(cfg->dns->servers[1].kind == config::DnsServerKind::dhcp, "dhcp kind");
    require(cfg->dns->servers[2].kind == config::DnsServerKind::mdns, "mdns kind");
    require(cfg->dns->servers[3].upstream && cfg->dns->servers[3].upstream->tls && cfg->dns->servers[3].upstream->tls->ca_file.empty(), "empty ca_file");
    require(cfg->dns->servers[4].upstream && cfg->dns->servers[4].upstream->detour == std::optional<std::string>("proxy"), "detour proxy");

    // 3. Transport preparation + executing hosts queries (A, AAAA, NODATA, NXDOMAIN) + mDNS non-.local fast NXDOMAIN.
    auto transports = cli::prepare_dns_transports(*cfg);
    std::filesystem::remove(hosts_path);
    require(transports.has_value() && transports->size() == 5, transports ? "5 transports" : transports.error());
    require((*transports)[0] != nullptr && (*transports)[1] != nullptr && (*transports)[2] != nullptr, "extra transports prepared");

    corosio::io_context io;
    auto run_query = [&](std::size_t idx, std::string name, std::uint16_t type) {
        std::optional<std::expected<dns::Response, dns::detail::UdpError>> outcome;
        auto& qfn = *(*transports)[idx];
        auto task = [&]() -> capy::task<> {
            dns::QueryMessage msg{42, 0x0100, {name, type}, std::nullopt};
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            outcome = co_await qfn(io, corosio::endpoint(corosio::ipv4_address({127, 0, 0, 1}), 53),
                msg, 42, deadline, dns::default_upstream_receive_budget(), {});
        };
        capy::run_async(io.get_executor())(task());
        io.run();
        io.restart();
        require(outcome.has_value(), "query completed");
        return std::move(*outcome);
    };

    auto r1 = run_query(0, "inline.example", 1);
    require(r1.has_value() && r1->rcode == 0 && r1->records.size() == 1, "hosts inline A");
    auto r2 = run_query(0, "v6.localtest", 28);
    require(r2.has_value() && r2->rcode == 0 && r2->records.size() == 1, "hosts file AAAA");
    auto r3 = run_query(0, "app-alias.localtest", 28);
    require(r3.has_value() && r3->rcode == 0 && r3->records.empty(), "hosts NODATA");
    auto r4 = run_query(0, "missing.localtest", 1);
    require(r4.has_value() && r4->rcode == 3, "hosts NXDOMAIN");
    auto r5 = run_query(2, "example.com", 1);
    require(r5.has_value() && r5->rcode == 3, "mDNS non-.local fast NXDOMAIN");

    // 3. Batch 169: DoQ/DoT stop_quic_queries/stop_tls_queries complete pending queries < 500ms
    {
        auto quic_q = dns::make_quic_query("example.com", "", {});
        auto tls_q = dns::make_tls_query("example.com", "", {});
        require(quic_q.has_value() && tls_q.has_value(), "create DoQ & DoT query transports");
        corosio::io_context stop_io;
        bool q_done = false, t_done = false;
        auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        dns::QueryMessage msg{99, 0x0100, {"stop.test", 1}, std::nullopt};
        auto unreach = corosio::endpoint(corosio::ipv4_address({127, 0, 0, 1}), 65432);
        std::stop_source ss;
        capy::run_async(stop_io.get_executor())([&]() -> capy::task<> {
            (void)co_await (*quic_q)(stop_io, unreach, msg, 99, dl, dns::default_upstream_receive_budget(), ss.get_token());
            q_done = true;
        }());
        capy::run_async(stop_io.get_executor())([&]() -> capy::task<> {
            (void)co_await (*tls_q)(stop_io, unreach, msg, 99, dl, dns::default_upstream_receive_budget(), ss.get_token());
            t_done = true;
        }());
        auto t0 = std::chrono::steady_clock::now();
        stop_io.run_for(std::chrono::milliseconds(25));
        dns::stop_quic_queries(stop_io);
        dns::stop_tls_queries(stop_io);
        ss.request_stop();
        stop_io.restart();
        stop_io.run_for(std::chrono::milliseconds(450));
        auto elapsed = std::chrono::steady_clock::now() - t0;
        require(q_done && t_done && elapsed < std::chrono::milliseconds(500), "DoQ & DoT abort cleanly under 500ms");
    }

    // 4. Batch 169: stop_system_local_snapshots + lazy restart
    {
        auto s1 = dns::system_local_snapshots().acquire();
        require(static_cast<bool>(s1), "initial local snapshot");
        dns::stop_system_local_snapshots();
        auto s2 = dns::system_local_snapshots().acquire();
        require(static_cast<bool>(s2), "local snapshot restarts cleanly after stop");
        dns::stop_system_local_snapshots();
    }

    std::cout << "BATCH 166 EXTRA DNS TRANSPORTS UNIT TESTS PASSED\n";
    return 0;
}
