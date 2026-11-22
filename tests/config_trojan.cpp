import std;
import config;

namespace {
    auto document(std::string_view inbound,std::string_view outbound,std::string_view extra={},std::string_view route="edge") {
        return config::parse_kdl(std::format(R"(schema-version 1
role "server"
inbounds {{ {} }}
outbound "direct" type="direct"
outbound "edge" type="trojan" {{ {} }}
{}
routing {{ default-outbound "{}"; }}
)",inbound,outbound,extra,route));
    }
    constexpr std::string_view inbound=R"(trojan "edge-in" {
 listen host="::1" port=443;
 authentication { user "alice" password-file="/tmp/alice"; user "bob" password-file="/tmp/bob"; }
 tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; }
})";
    constexpr std::string_view outbound=R"(server host="remote.test" port=443;
authentication { password-file "/tmp/secret"; }
tls { server-name "remote.test"; ca-file "/tmp/ca"; verify #true; }
connect-timeout-ms 12000;
tcp-keepalive #true;
)";
}
auto main() -> int {
    auto parsed=document(inbound,outbound);
    if (!parsed || parsed->inbounds.size()!=1 || !parsed->inbounds[0].trojan || parsed->inbounds[0].type!=config::Inbound::trojan ||
        !parsed->inbounds[0].listen_ipv6 || parsed->inbounds[0].trojan->users.size()!=2 ||
        parsed->trojan_outbounds.size()!=1 || parsed->default_outbound!=2 || parsed->tunnel_count()!=1) return 1;
    auto const& config=parsed->trojan_outbounds[0].config;
    if (config.password_file!="/tmp/secret" || config.connect_timeout_ms!=12000 || config.tcp_options.keepalive!=true) return 2;
    for (auto bad:{std::string{},std::string(R"(server host="remote.test" port=443; authentication { password-file "/tmp/secret"; })"),
        std::string(outbound)+"\nconnect-timeout-ms 1;",std::string(outbound)+"\npassword \"inline\";",
        std::string(outbound)+"\ntls { verify #false; }",std::string(outbound)+"\ndetour \"edge\";",
        std::string(outbound)+"\ndetour \"missing\";",std::string(outbound)+"\nbootstrap-resolver \"missing\";"})
        if (document(inbound,bad)) return 3;
    for (auto bad:{R"(trojan "edge-in" { listen host="127.0.0.1" port=443; authentication "none"; })",
        R"(trojan "edge-in" { listen host="127.0.0.1" port=443; authentication { user "alice" password-file="relative"; } tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; } })",
        R"(trojan "edge-in" { listen host="127.0.0.1" port=443; authentication { user "alice" password-file="/tmp/a"; user "alice" password-file="/tmp/b"; } tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; } })"})
        if (document(bad,outbound)) return 4;
    auto plain=std::string(outbound);
    auto keepalive=plain.find("tcp-keepalive"); plain.erase(keepalive);
    auto detoured=document(inbound,plain+"detour \"ss\"; bootstrap-resolver \"dns\";",R"(
outbound "ss" type="shadowsocks" { server host="127.0.0.1" port=443; method "2022-blake3-aes-128-gcm"; key-file "/tmp/key"; }
dns { server "dns" type="udp" host="127.0.0.1"; }
)");
    if (!detoured || detoured->trojan_outbounds[0].config.detour_index!=2 || detoured->default_outbound!=3 ||
        detoured->trojan_outbounds[0].config.bootstrap_index!=0) return 5;
    auto duplicate=document(inbound,outbound,R"(outbound "edge" type="shadowsocks" { server host="127.0.0.1" port=443; method "2022-blake3-aes-128-gcm"; key-file "/tmp/key"; })");
    if (duplicate) return 6;
    for (auto flag:{"#true","#false"}) {
        auto fast=document(inbound,std::string(outbound)+"tcp-fast-open "+flag+";");
        if (!fast || fast->trojan_outbounds[0].config.tcp_fast_open!=(std::string_view(flag)=="#true")) return 7;
    }
    for (auto extra:{"tcp-fast-open 1;","tcp-fast-open #true; tcp-fast-open #false;",
                     "tcp-fast-open #true; detour \"direct\";"})
        if (document(inbound,plain+extra)) return 8;
    std::println("Trojan TLS, authentication, IPv6, dial fields, references and dependency validation passed");
}
