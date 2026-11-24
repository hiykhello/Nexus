import std;
import config;

namespace {
    constexpr std::string_view incoming=R"(anytls "in" {
 listen host="::1" port=8443;
 authentication { user "alice" password-file="/tmp/password"; }
 tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; }
})";
    constexpr std::string_view connection=R"(server host="remote.test" port=443;
authentication { password-file "/tmp/password"; }
tls { server-name "remote.test"; ca-file "/tmp/ca"; verify #true; }
)";
    auto document(std::string_view options={},std::string_view extra={},std::string_view inbound=incoming) {
        return config::parse_kdl(std::format(R"(schema-version 1
role "server"
inbounds {{ {} }}
outbound "direct" type="direct"
outbound "edge" type="anytls" {{ {} {} }}
{}
routing {{ default-outbound "edge"; }}
)",inbound,connection,options,extra));
    }
}
auto main() -> int {
    auto defaults=document();
    if (!defaults || defaults->default_outbound!=2 || defaults->tunnel_count()!=1 || defaults->inbounds.size()!=1 ||
        defaults->inbounds[0].type!=config::Inbound::anytls || !defaults->inbounds[0].anytls ||
        defaults->inbounds[0].trojan || !defaults->inbounds[0].listen_ipv6 || defaults->inbounds[0].anytls->users[0].name!="alice") return 1;
    auto const& pool=defaults->anytls_outbounds[0].config.pool;
    if (pool.max_sessions!=64 || pool.min_idle || pool.idle_timeout_ms!=30000 || pool.check_interval_ms!=30000) return 2;
    for (auto flag:{"#true","#false"}) {
        auto fast=document(std::string("tcp-fast-open ")+flag+";");
        if (!fast || fast->anytls_outbounds[0].config.connection.tcp_fast_open!=(std::string_view(flag)=="#true")) return 8;
    }
    for (auto bad:{"tcp-fast-open 1;","tcp-fast-open #true; tcp-fast-open #false;", "tcp-fast-open #true; detour \"direct\";"})
        if (document(bad)) return 9;
    auto configured=document(R"(pool { max-sessions 8; min-idle 2; idle-timeout-ms 60000; check-interval-ms 1000; }
connect-timeout-ms 12000;
bootstrap-resolver "dns";
detour "lower";
)",R"(outbound "lower" type="trojan" {
server host="127.0.0.1" port=443;
authentication { password-file "/tmp/password"; }
tls { server-name "localhost"; ca-file "/tmp/ca"; verify #true; }
}
dns { server "dns" type="udp" host="127.0.0.1"; })");
    if (!configured || configured->default_outbound!=3 || configured->tunnel_count()!=2) {
        if (!configured) std::cerr<<configured.error()<<'\n';
        return 3;
    }
    auto const& value=configured->anytls_outbounds[0].config;
    if (value.connection.detour_index!=2 || value.connection.bootstrap_index!=0 || value.connection.connect_timeout_ms!=12000 ||
        value.pool.max_sessions!=8 || value.pool.min_idle!=2 || value.pool.idle_timeout_ms!=60000 || value.pool.check_interval_ms!=1000) return 4;
    for (auto bad:{"pool { max-sessions 0; }","pool { max-sessions 257; }","pool { min-idle 65; }",
        "pool { idle-timeout-ms 0; }","pool { idle-timeout-ms 86400001; }","pool { check-interval-ms -1; }",
        "pool { max-sessions 1; min-idle 2; }","pool { min-idle 0; min-idle 1; }","pool { unknown 1; }",
        "pool value=1","pool {}\npool {}","pool { max-sessions #true; }","pool { min-idle 1 { unexpected 0; } }",
        "detour \"edge\"","detour \"missing\"","bootstrap-resolver \"missing\"","password \"inline\"",
        "fallback \"other\"","transport \"xhttp\"","tls { verify #false; }"})
        if (document(bad)) { std::cerr<<"accepted invalid AnyTLS field: "<<bad<<'\n'; return 5; }
    auto grpc_ok=document(R"(transport "grpc" { service-name "svc"; authority "remote.test"; };)");
    if (!grpc_ok || !grpc_ok->anytls_outbounds[0].config.connection.grpc) return 5;
    for (auto bad:{R"(anytls "in" { listen host="127.0.0.1" port=8443; authentication "none"; })",
        R"(anytls "in" { listen host="127.0.0.1" port=8443; authentication { user "x" password-file="relative"; } tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; } })",
        R"(anytls "in" { listen host="127.0.0.1" port=8443; authentication { user "x" password-file="/tmp/a"; user "x" password-file="/tmp/b"; } tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; } })"})
        if (document({}, {},bad)) return 6;
    auto duplicate=document({},std::format(R"(outbound "edge" type="trojan" {{ {} }})",connection));
    if (duplicate) return 7;
    auto cycle=document("detour \"lower\";",std::format(R"(outbound "lower" type="trojan" {{ {} detour "edge"; }})",connection));
    if (cycle) return 8;
    // The KDL DOM intentionally normalizes an empty child block to no children.
    auto empty_block=document("pool { min-idle 1 {} }");
    if (!empty_block || empty_block->anytls_outbounds[0].config.pool.min_idle!=1) return 9;
    std::println("AnyTLS password/TLS, pool bounds, shared indexes, bootstrap and mixed detour cycles passed");
}
