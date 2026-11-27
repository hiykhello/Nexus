import std;
import config;

auto main() -> int {
    auto shadowtls_cfg = R"(schema-version 1
role "server"
inbounds {
    inbound "stls-in" type="shadowtls" {
        listen host="127.0.0.1" port=8443
        handshake host="127.0.0.1" port=9443
        target host="127.0.0.1" port=10443
        strict-tls13 #true
        authentication { user "u1" password-file="/tmp/p1"; }
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "stls-out" type="shadowtls" {
        server host="127.0.0.1" port=8443
        strict-tls13 #false
        authentication { password-file "/tmp/p1"; }
        tls { server-name "cover.example"; ca-file "/tmp/ca.pem"; fingerprint "chrome"; verify #true; }
    }
}
routing { final "stls-out"; }
)";
    auto stls_parsed = config::parse_kdl(shadowtls_cfg);
    if (!stls_parsed || !stls_parsed->inbounds.front().shadowtls ||
        stls_parsed->shadowtls_outbounds.size() != 1 ||
        stls_parsed->shadowtls_outbounds.front().config.strict_tls13 ||
        stls_parsed->shadowtls_outbounds.front().config.connection.fingerprint != config::TlsFingerprint::chrome)
        return 1;

    auto tuic_cfg = R"(schema-version 1
role "server"
inbounds {
    inbound "tuic-in" type="tuic" {
        listen host="127.0.0.1" port=8444
        congestion-control "bbr"
        authentication { user "u1" uuid-file="/tmp/u1" password-file="/tmp/p1"; }
        tls { certificate-file "/tmp/cert.pem"; private-key-file "/tmp/key.pem"; }
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "tuic-out" type="tuic" {
        server host="127.0.0.1" port=8444
        congestion-control "bbr"
        udp-over-stream #true
        authentication { uuid-file "/tmp/u1"; password-file "/tmp/p1"; }
        tls { server-name "tuic.example"; ca-file "/tmp/ca.pem"; fingerprint "firefox"; verify #true; }
    }
}
routing { final "tuic-out"; }
)";
    auto tuic_parsed = config::parse_kdl(tuic_cfg);
    if (!tuic_parsed || !tuic_parsed->inbounds.front().tuic ||
        tuic_parsed->inbounds.front().tuic->congestion_control != "bbr" ||
        tuic_parsed->tuic_outbounds.size() != 1 || !tuic_parsed->tuic_outbounds.front().config.udp_over_stream ||
        tuic_parsed->tuic_outbounds.front().config.fingerprint != config::TlsFingerprint::firefox)
        return 2;

    auto masque_out_cfg = R"(schema-version 1
role "client"
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "mq" type="masque" {
        server host="127.0.0.1" port=8445
        authority "proxy.example"
        authentication { bearer-file "/tmp/bearer"; }
        tls { server-name "proxy.example"; ca-file "/tmp/ca.pem"; fingerprint "safari"; verify #true; }
    }
}
routing { final "mq"; }
)";
    auto mq_parsed = config::parse_kdl(masque_out_cfg);
    if (!mq_parsed || mq_parsed->masque_outbounds.size() != 1 ||
        mq_parsed->masque_outbounds.front().config.authority != "proxy.example" ||
        mq_parsed->masque_outbounds.front().config.fingerprint != config::TlsFingerprint::safari)
        return 3;

    for (auto [name, fp] : std::array<std::pair<std::string_view, config::TlsFingerprint>, 7>{
             {{"chrome", config::TlsFingerprint::chrome},
              {"firefox", config::TlsFingerprint::firefox},
              {"safari", config::TlsFingerprint::safari},
              {"ios", config::TlsFingerprint::ios},
              {"android", config::TlsFingerprint::android},
              {"edge", config::TlsFingerprint::edge},
              {"random", config::TlsFingerprint::random}}}) {
        if (!config::parse_tls_fingerprint(name) || *config::parse_tls_fingerprint(name) != fp ||
            config::tls_fingerprint_name(fp) != name)
            return 4;
    }

    auto tun_cfg = R"(schema-version 1
role "client"
inbounds {
    inbound "tun-in" type="tun" {
        interface-name "nx-tun0"
        inet4-address "10.77.0.1/24"
        inet6-address "fd77::1/64"
        mtu 1420
        auto-route #true
        strict-route #true
        stack "system"
        tcp-flows 512
        tcp-buffer 65536
        udp-idle-ms 30000
        socket-mark 42
        endpoint-independent-nat #false
    }
}
outbounds { outbound "direct" type="direct"; }
routing { final "direct"; }
)";
    auto tun_parsed = config::parse_kdl(tun_cfg);
    if (!tun_parsed || !tun_parsed->inbounds.front().tun ||
        tun_parsed->inbounds.front().tun->interface_name != "nx-tun0" ||
        tun_parsed->inbounds.front().tun->mtu != 1420 ||
        !tun_parsed->inbounds.front().tun->auto_route ||
        !tun_parsed->inbounds.front().tun->strict_route ||
        tun_parsed->inbounds.front().tun->socket_mark != 42u ||
        tun_parsed->direct_tcp_options.binding.routing_mark != 42u ||
        tun_parsed->inbounds.front().tun->endpoint_independent_nat)
        return 5;
    std::string unsupported_stack = tun_cfg;
    unsupported_stack.replace(unsupported_stack.find("system"), std::string_view("system").size(), "gvisor");
    if (config::parse_kdl(unsupported_stack))
        return 5;
    if (config::parse_kdl("schema-version 1\nrole \"client\"\ninbounds { inbound \"t\" type=\"tun\" {\n    auto-route #true\n}; }\noutbounds { outbound \"d\" type=\"direct\"; }\nrouting { final \"d\"; }\n"))
        return 6;
    if (config::parse_kdl("schema-version 1\nrole \"client\"\ninbounds { inbound \"t\" type=\"tun\" {\n    mtu 10\n}; }\noutbounds { outbound \"d\" type=\"direct\"; }\nrouting { final \"d\"; }\n"))
        return 7;

    auto wg_cfg = R"(schema-version 1
role "client"
inbounds { inbound "socks" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "direct" type="direct"
    outbound "wg" type="wireguard" {
        server host="127.0.0.1" port=51820
        private-key-file "/tmp/wg.key"
        peer-public-key-file "/tmp/wg.pub"
        preshared-key-file "/tmp/wg.psk"
        local-address "10.9.0.2/32"
        local-address "fd09::2/128"
        reserved 1 2 3
        mtu 1380
        persistent-keepalive 25
        routing-mark 42
    }
}
routing { final "wg"; }
)";
    auto wg_parsed = config::parse_kdl(wg_cfg);
    if (!wg_parsed || wg_parsed->wireguard_outbounds.size() != 1 ||
        wg_parsed->wireguard_outbounds.front().config.port != 51820 ||
        !wg_parsed->wireguard_outbounds.front().config.has_v4 ||
        !wg_parsed->wireguard_outbounds.front().config.has_v6 ||
        !wg_parsed->wireguard_outbounds.front().config.warp ||
        wg_parsed->wireguard_outbounds.front().config.reserved != std::array<std::uint8_t, 3>{1, 2, 3} ||
        wg_parsed->wireguard_outbounds.front().config.mtu != 1380 ||
        wg_parsed->wireguard_outbounds.front().config.keepalive_s != 25 ||
        wg_parsed->wireguard_outbounds.front().config.tcp_options.binding.routing_mark != 42u)
        return 8;

    auto wg_b64 = config::parse_kdl(R"(schema-version 1
role "client"
inbounds { inbound "socks" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "d" type="direct"
    outbound "wg" type="wireguard" {
        server host="127.0.0.1" port=51820
        private-key-file "/tmp/wg.key"
        peer-public-key-file "/tmp/wg.pub"
        reserved "AQID"
    }
}
routing { final "wg"; }
)");
    if (!wg_b64 || !wg_b64->wireguard_outbounds.front().config.warp ||
        wg_b64->wireguard_outbounds.front().config.reserved != std::array<std::uint8_t, 3>{1, 2, 3})
        return 9;

    auto mq_ip = config::parse_kdl(R"(schema-version 1
role "client"
inbounds { inbound "socks" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "d" type="direct"
    outbound "mq-ip" type="masque" {
        server host="127.0.0.1" port=8445
        authority "proxy.example"
        mode "connect-ip"
        path "/.well-known/masque/ip/*/*/"
        mtu 1360
        local-address "10.10.0.2/32"
        local-address "fd10::2/128"
        authentication { bearer-file "/tmp/bearer"; }
        tls { server-name "proxy.example"; ca-file "/tmp/ca.pem"; verify #true; }
    }
}
routing { final "mq-ip"; }
)");
    if (!mq_ip || mq_ip->masque_outbounds.size() != 1 || !mq_ip->masque_outbounds.front().config.connect_ip ||
        mq_ip->masque_outbounds.front().config.mtu != 1360 || !mq_ip->masque_outbounds.front().config.local_v4 ||
        !mq_ip->masque_outbounds.front().config.local_v6)
        return 10;

    // Wave 31E: ShadowTLS handshake-for-server-name (flat + block) & wildcard-sni.
    auto stls_w31 = config::parse_kdl(R"(schema-version 1
role "server"
inbounds {
    inbound "stls-in" type="shadowtls" {
        listen host="127.0.0.1" port=8443
        handshake host="127.0.0.1" port=9443
        target host="127.0.0.1" port=10443
        handshake-for-server-name "Alt.Example.COM" "127.0.0.1:9444"
        handshake-for-server-name {
            "cdn.example.com" host="127.0.0.1" port=9445
            server "api.example.com" "127.0.0.1:9446"
        }
        wildcard-sni "authed"
        authentication { user "u1" password-file="/tmp/p1"; }
    }
}
outbounds { outbound "direct" type="direct"; }
routing { final "direct"; }
)");
    if (!stls_w31 || !stls_w31->inbounds.front().shadowtls) return 11;
    auto const& s_in = *stls_w31->inbounds.front().shadowtls;
    if (s_in.wildcard_sni != "authed" || s_in.handshake_for_server_name.size() != 3 ||
        s_in.handshake_for_server_name[0].first != "alt.example.com" ||
        s_in.handshake_for_server_name[0].second.port != 9444 ||
        s_in.handshake_for_server_name[1].first != "cdn.example.com" ||
        s_in.handshake_for_server_name[1].second.port != 9445 ||
        s_in.handshake_for_server_name[2].first != "api.example.com" ||
        s_in.handshake_for_server_name[2].second.port != 9446)
        return 12;
    // Reject invalid wildcard-sni, duplicate SNI (case-insensitive), and IPv4 SNI.
    for (auto bad_s : {
        R"(wildcard-sni "invalid")",
        R"(wildcard-sni "all"; wildcard-sni "off")",
        R"(handshake-for-server-name "a.example" "127.0.0.1:443"; handshake-for-server-name "A.EXAMPLE" "127.0.0.1:444")",
        R"(handshake-for-server-name "127.0.0.1" "127.0.0.1:443")",
    }) {
        auto doc = std::format(R"(schema-version 1
role "server"
inbounds {{
    inbound "s" type="shadowtls" {{
        listen host="127.0.0.1" port=8443; handshake host="127.0.0.1" port=9443; target host="127.0.0.1" port=10443;
        authentication {{ user "u1" password-file="/tmp/p1"; }}
        {};
    }}
}}
outbounds {{ outbound "direct" type="direct"; }}
routing {{ final "direct"; }}
)", bad_s);
        if (config::parse_kdl(doc)) return 13;
    }

    // Wave 31E: TUIC zero-rtt-handshake (inbound + outbound), outbound alpn, and ech-query-server-name.
    auto tuic_w31 = config::parse_kdl(R"(schema-version 1
role "server"
dns { servers { server "d1" type="udp" host="127.0.0.1"; }; }
inbounds {
    inbound "tuic-in" type="tuic" {
        listen host="127.0.0.1" port=8444
        zero-rtt-handshake #true
        authentication { user "u1" uuid-file="/tmp/u1" password-file="/tmp/p1"; }
        tls { certificate-file "/tmp/cert.pem"; private-key-file "/tmp/key.pem"; }
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "tuic-out" type="tuic" {
        server host="127.0.0.1" port=8444
        zero-rtt-handshake #true
        authentication { uuid-file "/tmp/u1"; password-file "/tmp/p1"; }
        tls { server-name "tuic.example"; ca-file "/tmp/ca.pem"; alpn "h3"; ech-dns #true; ech-query-server-name "cloudflare-ech.com"; verify #true; }
    }
}
routing { final "tuic-out"; }
)");
    if (tuic_w31) {
        if (!tuic_w31->inbounds.front().tuic->zero_rtt_handshake ||
            !tuic_w31->tuic_outbounds.front().config.zero_rtt_handshake ||
            tuic_w31->tuic_outbounds.front().config.alpn != std::vector<std::string>{"h3"} ||
            tuic_w31->tuic_outbounds.front().config.ech.query_server_name != "cloudflare-ech.com")
            return 14;
    } else if (tuic_w31.error() != "ech-dns requires the dns-response feature") {
        return 14;
    }
    // Order-independent ech-query-server-name BEFORE ech-dns #true.
    auto ech_order = config::parse_kdl(R"(schema-version 1
role "client"
dns { servers { server "d1" type="udp" host="127.0.0.1"; }; }
inbounds { inbound "socks" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "d" type="direct"
    outbound "tuic-out" type="tuic" {
        server host="127.0.0.1" port=8444
        zero-rtt-handshake #false
        authentication { uuid-file "/tmp/u1"; password-file "/tmp/p1"; }
        tls { server-name "tuic.example"; ca-file "/tmp/ca.pem"; ech-query-server-name "ech.example.net"; ech-dns #true; verify #true; }
    }
}
routing { final "tuic-out"; }
)");
    if (ech_order) {
        if (ech_order->tuic_outbounds.front().config.ech.query_server_name != "ech.example.net" ||
            ech_order->tuic_outbounds.front().config.zero_rtt_handshake)
            return 15;
    } else if (ech_order.error() != "ech-dns requires the dns-response feature") {
        return 15;
    }
    // Reject ech-query-server-name without ech-dns, IPv4 query name, or duplicate zero-rtt-handshake.
    for (auto bad_ech : {
        R"(ech-query-server-name "ech.example.net")",
        R"(ech-dns #true; ech-query-server-name "127.0.0.1")",
        R"(ech-dns #true; ech-query-server-name "a.test"; ech-query-server-name "b.test")",
    }) {
        auto doc = std::format(R"(schema-version 1
role "client"
dns {{ servers {{ server "d1" type="udp" host="127.0.0.1"; }}; }}
inbounds {{ inbound "socks" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}; }}
outbounds {{
    outbound "d" type="direct"
    outbound "tuic-out" type="tuic" {{
        server host="127.0.0.1" port=8444
        authentication {{ uuid-file "/tmp/u1"; password-file "/tmp/p1"; }}
        tls {{ server-name "tuic.example"; ca-file "/tmp/ca.pem"; {}; verify #true; }}
    }}
}}
routing {{ final "tuic-out"; }}
)", bad_ech);
        if (config::parse_kdl(doc)) return 16;
    }

    std::println("ShadowTLS/TUIC/MASQUE/TUN/WireGuard KDL, ECH query-server-name, zero-rtt-handshake and SNI config validation passed");
}
