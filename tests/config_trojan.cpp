import std;
import config;

namespace {
    auto document(std::string_view inbound,std::string_view outbound,std::string_view extra_outbounds={},std::string_view route="edge",std::string_view extra_top={}) {
        return config::parse_kdl(std::format(R"(schema-version 1
role "server"
inbounds {{ {} }}
outbounds {{
outbound "direct" type="direct"
outbound "edge" type="trojan" {{ {} }}
{}
}}
{}
routing {{ final "{}"; }}
)",inbound,outbound,extra_outbounds,extra_top,route));
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
    auto detoured=document(inbound,plain+"detour \"ss\"; bootstrap-resolver \"dns\";",
        R"(outbound "ss" type="shadowsocks" { server host="127.0.0.1" port=443; method "2022-blake3-aes-128-gcm"; key-file "/tmp/key"; })",
        "edge",
        R"(dns { servers { server "dns" type="udp" host="127.0.0.1"; }; })");
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

    // Trojan inbound fallback & fallback-for-alpn (both host:port shorthand and host/port properties + block).
    auto fb_in = R"(trojan "edge-in" {
 listen host="127.0.0.1" port=443;
 authentication { user "alice" password-file="/tmp/alice"; }
 tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; alpn "h2" "http/1.1"; cert-hot-reload #true; ech-key-file "/tmp/ech.key"; }
 fallback "127.0.0.1:8080";
 fallback-for-alpn "h2" "127.0.0.1:8081";
 fallback-for-alpn "http/1.1" host="127.0.0.1" port=8082;
})";
    auto fb_out = R"(server host="remote.test" port=443;
authentication { password-file "/tmp/secret"; }
tls {
 server-name "remote.test"; ca-file "/tmp/ca"; verify #true;
 alpn "h2" "http/1.1";
 tls-fragment { record-fragment #true; min 12; max 64; fallback-delay-ms 400; }
}
)";
    auto fb = document(fb_in, fb_out);
    if (!fb || !fb->inbounds[0].trojan || !fb->inbounds[0].trojan->fallback ||
        fb->inbounds[0].trojan->fallback->host != "127.0.0.1" || fb->inbounds[0].trojan->fallback->port != 8080 ||
        fb->inbounds[0].trojan->fallback_for_alpn.size() != 2 ||
        fb->inbounds[0].trojan->fallback_for_alpn[0].first != "h2" ||
        fb->inbounds[0].trojan->fallback_for_alpn[0].second.port != 8081 ||
        fb->inbounds[0].trojan->fallback_for_alpn[1].first != "http/1.1" ||
        fb->inbounds[0].trojan->fallback_for_alpn[1].second.port != 8082 ||
        fb->inbounds[0].trojan->alpn.size() != 2 || !fb->inbounds[0].trojan->cert_hot_reload ||
        fb->inbounds[0].trojan->ech_key_file != "/tmp/ech.key" ||
        fb->trojan_outbounds[0].config.alpn.size() != 2 ||
        !fb->trojan_outbounds[0].config.tls_fragment.enabled ||
        !fb->trojan_outbounds[0].config.tls_fragment.record_fragment ||
        fb->trojan_outbounds[0].config.tls_fragment.min_bytes != 12 ||
        fb->trojan_outbounds[0].config.tls_fragment.max_bytes != 64 ||
        fb->trojan_outbounds[0].config.tls_fragment.fallback_delay_ms != 400)
        return 9;

    // Block form for fallback-for-alpn + host/port fallback + tls-fragment #true shorthand.
    auto fb_block = document(R"(trojan "edge-in" {
 listen host="127.0.0.1" port=443;
 authentication { user "alice" password-file="/tmp/alice"; }
 tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; }
 fallback host="127.0.0.1" port=9000;
 fallback-for-alpn { "h2" "127.0.0.1:9001"; "http/1.1" host="127.0.0.1" port=9002; }
})", R"(server host="remote.test" port=443;
authentication { password-file "/tmp/secret"; }
tls { server-name "remote.test"; ca-file "/tmp/ca"; verify #true; tls-fragment #true; }
)");
    if (!fb_block || !fb_block->inbounds[0].trojan->fallback || fb_block->inbounds[0].trojan->fallback->port != 9000 ||
        fb_block->inbounds[0].trojan->fallback_for_alpn.size() != 2 ||
        !fb_block->trojan_outbounds[0].config.tls_fragment.enabled ||
        fb_block->trojan_outbounds[0].config.tls_fragment.record_fragment)
        return 10;

    // Reject duplicate fallback, duplicate ALPN, invalid port, and conflicting certificate-provider + cert-file.
    for (auto bad_in : {
        R"(trojan "e" { listen host="127.0.0.1" port=443; authentication { user "a" password-file="/tmp/a"; } tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; } fallback "127.0.0.1:80"; fallback "127.0.0.1:81"; })",
        R"(trojan "e" { listen host="127.0.0.1" port=443; authentication { user "a" password-file="/tmp/a"; } tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; } fallback-for-alpn "h2" "127.0.0.1:80"; fallback-for-alpn "h2" "127.0.0.1:81"; })",
        R"(trojan "e" { listen host="127.0.0.1" port=443; authentication { user "a" password-file="/tmp/a"; } tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; } fallback "127.0.0.1:0"; })",
        R"(trojan "e" { listen host="127.0.0.1" port=443; authentication { user "a" password-file="/tmp/a"; } tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; certificate-provider "acme1"; } })",
    }) if (document(bad_in, outbound)) return 11;

    std::println("Trojan TLS, authentication, IPv6, dial fields, fallback/ALPN, tls-fragment, references and dependency validation passed");
}
