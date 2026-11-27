// Tunnel protocol configuration validation tests (split from tests/config.cpp).
import std;
import config;

static auto replace(std::string text, std::string_view before, std::string_view after) -> std::string {
    auto pos = text.find(before);
    if (pos == std::string::npos) throw std::runtime_error("missing test substring");
    text.replace(pos, before.size(), after);
    return text;
}

int main() {
    std::string const complete = R"(schema-version 1
role "client"
inbounds {
    inbound "local" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "reject" type="block"
}
routing {
    rule-set "blocked" path="rules/blocked.kdl" format="kdl"
    rules {
        - kind="rule-set" value="blocked" outbound="reject"
    }
    default-outbound "direct"
}
)";
    auto add_inbound = [&](std::string const& base, std::string_view extra) {
        return replace(base, "}\noutbounds {", std::string(extra) + "}\noutbounds {");
    };
    auto add_outbound = [&](std::string const& base, std::string_view extra) {
        return replace(base, "}\nrouting {", std::string(extra) + "}\nrouting {");
    };

    auto hy2 = R"(schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "direct" type="direct"
    outbound "lower" type="shadowsocks" { server host="127.0.0.1" port=8388; method "2022-blake3-aes-128-gcm"; key-file "/tmp/key"; }
    outbound "edge" type="hysteria2" { server host="127.0.0.1" port=443; authentication { password-file "/tmp/pass"; }; tls { server-name "localhost"; ca-file "/tmp/ca"; verify #true; }; detour "lower"; }
}
routing { default-outbound "edge"; }
)";
    auto unsupported_detour = config::parse_kdl(hy2);
    if (unsupported_detour || unsupported_detour.error().find("Shadowsocks datagram transport") == std::string::npos) {
        std::cerr << "Hysteria detour: " << (unsupported_detour ? "unexpected success" : unsupported_detour.error()) << '\n';
        return 1;
    }
    auto layered = config::parse_kdl(replace(hy2, "key-file \"/tmp/key\";", "key-file \"/tmp/key\"; udp-over-tcp \"v2\";"));
    if (!layered || layered->hysteria2_outbounds[0].config.connection.detour_index != 2) return 1;
    auto direct_config = replace(hy2, "detour \"lower\"", "detour \"direct\"");
    direct_config = replace(direct_config, "    outbound \"lower\" type=\"shadowsocks\" { server host=\"127.0.0.1\" port=8388; method \"2022-blake3-aes-128-gcm\"; key-file \"/tmp/key\"; }\n", "");
    auto direct_detour = config::parse_kdl(direct_config);
    if (!direct_detour) { std::cerr << "Hysteria direct: " << direct_detour.error() << '\n'; return 1; }
    if (direct_detour->hysteria2_outbounds[0].config.connection.detour_index != 0) return 1;

    for (auto [type, expected] : {std::pair{"trojan", config::TlsFingerprint::tls13_grease},
                                  std::pair{"anytls", config::TlsFingerprint::tls13_grease}}) {
        auto text = replace(direct_config, "type=\"hysteria2\"", std::string("type=\"") + type + "\"");
        text = replace(text, "verify #true", "fingerprint \"tls13-grease\"; verify #true");
        auto parsed = config::parse_kdl(text);
        if (!parsed) { std::cerr << "fingerprint config: " << parsed.error() << '\n'; return 1; }
        auto actual = std::string_view(type) == "trojan" ? parsed->trojan_outbounds[0].config.fingerprint : parsed->anytls_outbounds[0].config.connection.fingerprint;
        if (actual != expected) return 1;
        for (auto limit : {64, 1024, 16385}) {
            auto limited = config::parse_kdl(replace(text, "verify #true", std::string("record-size-limit ") + std::to_string(limit) + "; verify #true"));
            if (!limited) return 1;
            auto actual_limit = std::string_view(type) == "trojan" ? limited->trojan_outbounds[0].config.record_size_limit : limited->anytls_outbounds[0].config.connection.record_size_limit;
            if (actual_limit != limit) return 1;
        }
        for (auto bad : {"0", "63", "16386", "-1", "\"64\"", "64; record-size-limit 64"})
            if (config::parse_kdl(replace(text, "verify #true", std::string("record-size-limit ") + bad + "; verify #true"))) return 1;
        auto randomized = config::parse_kdl(replace(text, "tls13-grease", "tls13-randomized"));
        if (!randomized) return 1;
        actual = std::string_view(type) == "trojan" ? randomized->trojan_outbounds[0].config.fingerprint : randomized->anytls_outbounds[0].config.connection.fingerprint;
        if (actual != config::TlsFingerprint::tls13_randomized) return 1;
        auto chrome = config::parse_kdl(replace(text, "tls13-grease", "chrome"));
        if (!chrome) return 1;
        actual = std::string_view(type) == "trojan" ? chrome->trojan_outbounds[0].config.fingerprint : chrome->anytls_outbounds[0].config.connection.fingerprint;
        if (actual != config::TlsFingerprint::chrome) return 1;
        if (config::parse_kdl(replace(text, "tls13-grease", "unknown-browser")) ||
            config::parse_kdl(replace(text, "fingerprint \"tls13-grease\"", "fingerprint \"native\"; fingerprint \"tls13-grease\""))) return 1;
    }
    if (auto hy2_fp = config::parse_kdl(replace(direct_config, "verify #true", "fingerprint \"chrome\"; verify #true"));
        !hy2_fp || hy2_fp->hysteria2_outbounds[0].config.connection.fingerprint != config::TlsFingerprint::chrome) return 1;
    if (config::parse_kdl(replace(direct_config, "verify #true", "fingerprint \"unknown-browser\"; verify #true")) ||
        config::parse_kdl(replace(direct_config, "verify #true", "record-size-limit 1024; verify #true"))) return 1;

    auto hy2_obfs = replace(direct_config, "detour \"direct\"", "detour \"direct\"; quic { salamander-password-file \"/tmp/obfs\"; }");
    auto parsed_obfs = config::parse_kdl(hy2_obfs);
    if (!parsed_obfs || parsed_obfs->hysteria2_outbounds[0].config.transport.salamander_password_file != "/tmp/obfs" ||
        config::parse_kdl(replace(hy2_obfs, "/tmp/obfs", "relative")) ||
        config::parse_kdl(replace(hy2_obfs, "salamander-password-file \"/tmp/obfs\"", "salamander-password-file \"/tmp/obfs\"; salamander-password-file \"/tmp/obfs\""))) return 1;
    auto hy2_inbound = R"(    inbound "hy-in" type="hysteria2" {
        listen host="127.0.0.1" port=8443
        authentication { user "test" password-file="/tmp/pass"; }
        tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; }
        quic { salamander-password-file "/tmp/obfs"; }
    }
)";
    auto parsed_hy2_inbound = config::parse_kdl(add_inbound(complete, hy2_inbound));
    if (!parsed_hy2_inbound || !parsed_hy2_inbound->inbounds.back().hysteria2 ||
        parsed_hy2_inbound->inbounds.back().hysteria2->transport.salamander_password_file != "/tmp/obfs") return 1;
    auto hy2_mtu = replace(hy2_obfs, "salamander-password-file \"/tmp/obfs\"", "salamander-password-file \"/tmp/obfs\"; max-udp-payload-size 1208; disable-path-mtu-discovery #true");
    auto mtu_out = config::parse_kdl(hy2_mtu);
    if (!mtu_out || mtu_out->hysteria2_outbounds[0].config.transport.max_udp_payload_size != 1208 ||
        !mtu_out->hysteria2_outbounds[0].config.transport.disable_path_mtu_discovery) return 1;
    auto mtu_in = config::parse_kdl(add_inbound(complete, replace(hy2_inbound, "salamander-password-file \"/tmp/obfs\"", "salamander-password-file \"/tmp/obfs\"; max-udp-payload-size 1500; disable-path-mtu-discovery #false")));
    if (!mtu_in || mtu_in->inbounds.back().hysteria2->transport.max_udp_payload_size != 1500 ||
        mtu_in->inbounds.back().hysteria2->transport.disable_path_mtu_discovery) return 1;
    for (auto value : {"0", "1199", "1200", "1207", "1501", "-1", "\"1300\"", "1208; max-udp-payload-size 1300"})
        if (config::parse_kdl(replace(hy2_mtu, "1208", value))) return 1;
    for (auto value : {"0", "\"true\"", "#true; disable-path-mtu-discovery #false"})
        if (config::parse_kdl(replace(hy2_mtu, "disable-path-mtu-discovery #true", std::string("disable-path-mtu-discovery ") + value))) return 1;
    auto hy2_bandwidth = replace(hy2_mtu, "disable-path-mtu-discovery #true", "disable-path-mtu-discovery #true; send-bps 2000000; receive-bps 3000000; disable-loss-compensation #true");
    auto rate_out = config::parse_kdl(hy2_bandwidth);
    if (!rate_out || rate_out->hysteria2_outbounds[0].config.transport.send_bps != 2000000 ||
        rate_out->hysteria2_outbounds[0].config.transport.receive_bps != 3000000 ||
        !rate_out->hysteria2_outbounds[0].config.transport.disable_compensation) return 1;
    auto inbound_rate = replace(hy2_inbound, "salamander-password-file \"/tmp/obfs\"", "salamander-password-file \"/tmp/obfs\"; send-bps 1; receive-bps 0; ignore-client-bandwidth #true");
    auto rate_in = config::parse_kdl(add_inbound(complete, inbound_rate));
    if (!rate_in || rate_in->inbounds.back().hysteria2->transport.send_bps != 1 ||
        !rate_in->inbounds.back().hysteria2->transport.ignore_client_bandwidth) return 1;
    for (auto value : {"-1", "1000000000001", "\"1\"", "1; send-bps 2"})
        if (config::parse_kdl(replace(hy2_bandwidth, "send-bps 2000000", std::string("send-bps ") + value))) return 1;
    if (config::parse_kdl(replace(hy2_bandwidth, "send-bps 2000000", "send-bps 2; ignore-client-bandwidth #false"))) return 1;

    auto typed = replace(complete, "inbound \"local\" type=\"socks5\"", "socks5 \"local\"");
    typed = replace(typed, "outbound \"direct\" type=\"direct\"", "direct \"direct\"");
    typed = replace(typed, "outbound \"reject\" type=\"block\"", "block \"reject\"");
    auto vless_in_config = replace(typed, R"(socks5 "local" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    })", R"(vless "local" {
        listen host="127.0.0.1" port=1080
        authentication { user "alice" uuid-file="/a"; user "bob" uuid-file="/b"; }
        tls { certificate-file "/cert.der"; private-key-file "/key.der"; }
    })");
    auto incoming = config::parse_kdl(vless_in_config);
    if (!incoming || incoming->inbounds[0].type != config::Inbound::vless || !incoming->inbounds[0].vless ||
        incoming->inbounds[0].vless->users.size() != 2 || incoming->inbounds[0].vless->private_key_file != "/key.der") return 1;
    if (incoming->inbounds[0].vless->vision) return 1;
    auto vision_in_config = replace(vless_in_config, "authentication {", "flow \"xtls-rprx-vision\"; authentication {");
    auto vision_in = config::parse_kdl(vision_in_config);
    if (!vision_in || !vision_in->inbounds[0].vless || !vision_in->inbounds[0].vless->vision) return 1;
    for (auto bad : {replace(vision_in_config, "xtls-rprx-vision", "unknown"),
                     replace(vision_in_config, "flow \"xtls-rprx-vision\";", "flow \"xtls-rprx-vision\"; flow \"xtls-rprx-vision\";")})
        if (config::parse_kdl(bad)) return 1;
    for (auto bad : {replace(vless_in_config, "uuid-file=\"/a\"", "uuid-file=\"relative\""),
                     replace(vless_in_config, "user \"bob\"", "user \"alice\""),
                     replace(vless_in_config, "private-key-file \"/key.der\"", "private-key-file \"key.der\""),
                     replace(vless_in_config, "certificate-file \"/cert.der\";", ""),
                     replace(vless_in_config, "user \"alice\" uuid-file=\"/a\"; user \"bob\" uuid-file=\"/b\";", "")})
        if (config::parse_kdl(bad)) return 1;
    auto reality_in_config = replace(vless_in_config, "certificate-file \"/cert.der\"; private-key-file \"/key.der\";", R"(reality {
        private-key-file "/reality.key"; certificate-file "/cert.der"; signing-key-file "/sign.der";
        server-name "cover.test"; server-name "other.test"; short-id "0102"; short-id "";
        max-time-difference 120; fallback host="cover.test" port=443;
    })");
    auto reality_in = config::parse_kdl(reality_in_config);
    if (!reality_in || !reality_in->inbounds[0].vless || !reality_in->inbounds[0].vless->reality) return 1;
    auto generated_in = replace(replace(reality_in_config, "certificate-file \"/cert.der\";", ""), "signing-key-file \"/sign.der\";", "");
    auto generated_parsed = config::parse_kdl(generated_in);
    if (!generated_parsed || !generated_parsed->inbounds[0].vless->reality || !generated_parsed->inbounds[0].vless->reality->certificate_file.empty()) return 1;
    if (config::parse_kdl(replace(reality_in_config, "signing-key-file \"/sign.der\";", ""))) return 1;
    auto named_fallback = replace(generated_in, "fallback host=\"cover.test\" port=443;", "fallback host=\"cover.test\" port=443; fallback-resolver \"bootstrap\";");
    auto dns_reality = std::string("dns { servers { server \"bootstrap\" type=\"udp\" host=\"127.0.0.1\" port=5353; }; }\n") + named_fallback;
    auto resolved_reality = config::parse_kdl(dns_reality);
    if (!resolved_reality || resolved_reality->inbounds[0].vless->reality->fallback_resolver_index != 0) return 1;
    if (config::parse_kdl(named_fallback) ||
        config::parse_kdl(replace(dns_reality, "fallback-resolver \"bootstrap\"", "fallback-resolver \"missing\"")) ||
        config::parse_kdl(replace(dns_reality, "fallback host=\"cover.test\"", "fallback host=\"127.0.0.1\""))) return 1;
    auto const& inbound_reality = *reality_in->inbounds[0].vless->reality;
    if (inbound_reality.private_key_file != "/reality.key" || inbound_reality.fallback_host != "cover.test" ||
        inbound_reality.fallback_port != 443 || inbound_reality.max_time_difference_seconds != 120 ||
        inbound_reality.server_names.size() != 2 || inbound_reality.short_ids.size() != 2 ||
        inbound_reality.short_ids[0][0] != 1 || inbound_reality.short_ids[0][1] != 2 || inbound_reality.short_ids[0][2] != 0) return 1;
    for (auto bad : {replace(reality_in_config, "max-time-difference 120", "max-time-difference -1"),
                     replace(reality_in_config, "fallback host=\"cover.test\" port=443;", ""),
                     replace(reality_in_config, "short-id \"0102\"", "short-id \"xyz\""),
                     replace(reality_in_config, "short-id \"0102\"", "short-id \"0000\""),
                     replace(reality_in_config, "private-key-file \"/reality.key\"", "private-key-file \"relative\""),
                     replace(reality_in_config, "reality {", "certificate-file \"/extra\"; reality {")})
        if (config::parse_kdl(bad)) return 1;

    std::string const vless_node = R"(    outbound "edge" type="vless" {
        server host="127.0.0.1" port=443
        authentication { uuid-file "/tmp/edge.uuid"; }
        tls { server-name "edge.example"; ca-file "/tmp/ca.pem"; verify #true; }
    }
)";
    auto vless_config = add_outbound(complete, vless_node);
    vless_config = replace(vless_config, "default-outbound \"direct\"", "default-outbound \"edge\"");
    auto vless = config::parse_kdl(vless_config);
    auto combined = add_outbound(vless_config, "    outbound \"ss\" type=\"shadowsocks\" { server host=\"127.0.0.1\" port=8388; method \"2022-blake3-aes-256-gcm\"; key-file \"/secret\"; }\n");
    combined = replace(combined, "outbound=\"reject\"", "outbound=\"ss\"");
    auto combined_config = config::parse_kdl(combined);
    if (!combined_config || combined_config->default_outbound != 2 || combined_config->routes[0].outbound != 3) return 1;
    if (!vless || !vless->vless || vless->vless->host != "127.0.0.1" || vless->vless->port != 443 ||
        vless->vless->uuid_file != "/tmp/edge.uuid" || vless->vless->server_name != "edge.example" ||
        vless->vless->ca_file != "/tmp/ca.pem" || vless->vless->key_exchange != config::TlsKeyExchange::x25519) {
        std::cerr << "vless configuration rejected\n"; return 1;
    }
    for (auto [name, value] : {std::pair{"native", config::TlsFingerprint::native},
                               std::pair{"tls13-grease", config::TlsFingerprint::tls13_grease},
                               std::pair{"tls13-randomized", config::TlsFingerprint::tls13_randomized},
                               std::pair{"chrome", config::TlsFingerprint::chrome},
                               std::pair{"firefox", config::TlsFingerprint::firefox},
                               std::pair{"safari", config::TlsFingerprint::safari},
                               std::pair{"ios", config::TlsFingerprint::ios},
                               std::pair{"android", config::TlsFingerprint::android},
                               std::pair{"edge", config::TlsFingerprint::edge},
                               std::pair{"random", config::TlsFingerprint::random}}) {
        auto shaped = config::parse_kdl(replace(vless_config, "verify #true", std::string("fingerprint \"") + name + "\"; verify #true"));
        if (!shaped || !shaped->vless || shaped->vless->fingerprint != value) return 1;
    }
    if (config::parse_kdl(replace(vless_config, "verify #true", "fingerprint \"unknown-browser\"; verify #true")) ||
        config::parse_kdl(replace(vless_config, "verify #true", "fingerprint \"native\"; fingerprint \"tls13-grease\"; verify #true"))) return 1;
    auto grpc_tls = replace(vless_config, "authentication { uuid-file", "transport \"grpc\"; authentication { uuid-file");
    for (auto name : {"native", "tls13-grease", "tls13-randomized", "chrome", "firefox", "safari", "ios", "android", "edge", "random"}) {
        auto parsed = config::parse_kdl(replace(grpc_tls, "verify #true", std::string("fingerprint \"") + name + "\"; verify #true"));
        if (!parsed || !parsed->vless || !parsed->vless->grpc) return 1;
    }
    for (auto limit : {64, 1024, 16385}) {
        auto limited = config::parse_kdl(replace(vless_config, "verify #true", std::string("record-size-limit ") + std::to_string(limit) + "; verify #true"));
        if (!limited || !limited->vless || limited->vless->record_size_limit != limit) return 1;
    }
    for (auto bad : {"0", "63", "16386", "-1", "\"64\"", "64; record-size-limit 64"})
        if (config::parse_kdl(replace(vless_config, "verify #true", std::string("record-size-limit ") + bad + "; verify #true"))) return 1;
    if (vless->vless->vision) return 1;
    auto vless_timeout = replace(vless_config, "server host=\"127.0.0.1\"", "connect-timeout-ms 1500; server host=\"127.0.0.1\"");
    auto parsed_vless_timeout = config::parse_kdl(vless_timeout);
    if (!parsed_vless_timeout || !parsed_vless_timeout->vless || parsed_vless_timeout->vless->connect_timeout_ms != 1500 ||
        vless->vless->connect_timeout_ms != 10000) return 1;
    for (auto value : {"0", "3600001", "-1", "\"500\"", "500; connect-timeout-ms 500"})
        if (config::parse_kdl(replace(vless_timeout, "1500", value))) return 1;
    auto vision_config = replace(vless_config, "authentication { uuid-file", "flow \"xtls-rprx-vision\"; authentication { uuid-file");
    auto vision = config::parse_kdl(vision_config);
    if (!vision || !vision->vless || !vision->vless->vision) return 1;
    for (auto bad : {replace(vision_config, "xtls-rprx-vision", "unknown"),
                     replace(vision_config, "flow \"xtls-rprx-vision\";", "flow \"xtls-rprx-vision\"; flow \"xtls-rprx-vision\";")})
        if (config::parse_kdl(bad)) return 1;
    auto hybrid = config::parse_kdl(replace(vless_config, "verify #true", "verify #true; key-exchange \"x25519-mlkem768\""));
    if (!hybrid || !hybrid->vless || hybrid->vless->key_exchange != config::TlsKeyExchange::x25519_mlkem768) return 1;
    auto strict = config::parse_kdl(replace(vless_config, "verify #true", "verify #true; key-exchange \"x25519-mlkem768-only\""));
    if (!strict || !strict->vless || strict->vless->key_exchange != config::TlsKeyExchange::x25519_mlkem768_only) return 1;
    auto classical = config::parse_kdl(replace(vless_config, "verify #true", "verify #true; key-exchange \"x25519\""));
    if (!classical || !classical->vless || classical->vless->key_exchange != config::TlsKeyExchange::x25519) return 1;
    auto reality_config = replace(vless_config, "ca-file \"/tmp/ca.pem\"; verify #true", "reality { public-key \"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"; short-id \"0123\"; }");
    auto reality = config::parse_kdl(reality_config);
    if (!reality || !reality->vless || !reality->vless->reality || reality->vless->reality->public_key[31] != 31 ||
        reality->vless->reality->short_id[0] != 1 || reality->vless->reality->short_id[1] != 0x23 || reality->vless->reality->short_id[2] != 0) return 1;
    if (config::parse_kdl(replace(reality_config, "short-id \"0123\"", "short-id \"123\"")) ||
        config::parse_kdl(replace(reality_config, "short-id \"0123\"", "short-id \"zz\"")) ||
        config::parse_kdl(replace(reality_config, "reality {", "ca-file \"/tmp/ca.pem\"; reality {"))) return 1;
    auto shaped_reality = config::parse_kdl(replace(reality_config, "reality {", "fingerprint \"tls13-randomized\"; reality {"));
    if (!shaped_reality || !shaped_reality->vless || shaped_reality->vless->fingerprint != config::TlsFingerprint::tls13_randomized) return 1;
    for (auto group : {"x25519-mlkem768", "x25519-mlkem768-only"}) {
        auto configured = config::parse_kdl(replace(reality_config, "reality {", std::string("key-exchange \"") + group + "\"; reality {"));
        if (!configured || !configured->vless || !configured->vless->reality) return 1;
    }
    auto bootstrap_config = replace(vless_config, "server host=\"127.0.0.1\"", "bootstrap-resolver \"boot\"; server host=\"edge.example\"");
    bootstrap_config = "dns { servers { server \"boot\" type=\"udp\" host=\"127.0.0.1\"; }; }\n" + bootstrap_config;
    auto vless_bootstrap = config::parse_kdl(bootstrap_config);
    if (!vless_bootstrap || !vless_bootstrap->vless || vless_bootstrap->vless->bootstrap_index != 0) {
        std::cerr << "bootstrap: " << (vless_bootstrap ? "missing index" : vless_bootstrap.error()) << '\n'; return 1;
    }
    if (config::parse_kdl(replace(bootstrap_config, "bootstrap-resolver \"boot\"", "bootstrap-resolver \"missing\"")) ||
        config::parse_kdl(replace(bootstrap_config, "edge.example", "127.0.0.1")) ||
        config::parse_kdl(replace(bootstrap_config, "bootstrap-resolver \"boot\";", "bootstrap-resolver \"boot\"; bootstrap-resolver \"boot\";"))) return 1;

    auto route_direct = config::parse_kdl(replace(vless_config, "outbound=\"reject\"", "outbound=\"direct\""));
    if (!route_direct || route_direct->rule_action != config::RouteAction::direct ||
        route_direct->default_action != config::RouteAction::vless) return 1;
    auto route_vless = config::parse_kdl(replace(replace(vless_config, "outbound=\"reject\"", "outbound=\"edge\""),
        "default-outbound \"edge\"", "default-outbound \"direct\""));
    if (!route_vless || route_vless->rule_action != config::RouteAction::vless ||
        route_vless->default_action != config::RouteAction::direct) return 1;
    auto second_vless = replace(vless_node, "\"edge\"", "\"edge2\"");
    auto multi_vless = add_outbound(vless_config, second_vless);
    multi_vless = replace(multi_vless, "outbound=\"reject\"", "outbound=\"edge2\"");
    auto multiple_vless = config::parse_kdl(multi_vless);
    if (!multiple_vless || multiple_vless->vless_outbounds.size() != 2 || multiple_vless->default_outbound != 2 ||
        multiple_vless->routes.size() != 1 || multiple_vless->routes[0].outbound != 3) return 1;
    if (config::parse_kdl(replace(multi_vless, "outbound \"edge2\"", "outbound \"edge\""))) return 1;
    auto many = vless_config;
    for (int i = 2; i <= 17; ++i) {
        auto name = "edge" + std::to_string(i);
        many = add_outbound(many, replace(vless_node, "\"edge\"", "\"" + name + "\""));
        many = replace(many, "rules {", "rules {\n        - kind=\"rule-set\" value=\"blocked\" outbound=\"" + name + "\"");
    }
    if (auto parsed = config::parse_kdl(many); !parsed || parsed->vless_outbounds.size() != 17) return 1;
    auto scale_257 = vless_config;
    for (int i = 2; i <= 257; ++i) {
        auto name = "edge" + std::to_string(i);
        scale_257 = add_outbound(scale_257, replace(vless_node, "\"edge\"", "\"" + name + "\""));
        scale_257 = replace(scale_257, "rules {", "rules {\n        - kind=\"rule-set\" value=\"blocked\" outbound=\"" + name + "\"");
    }
    if (auto parsed = config::parse_kdl(scale_257); !parsed || parsed->vless_outbounds.size() != 257) return 1;

    for (auto const& [input, description] : std::vector<std::pair<std::string, std::string>>{
        {replace(vless_config, "verify #true", "verify #false"), "disabled TLS verification"},
        {replace(vless_config, "verify #true", ""), "missing TLS verification"},
        {replace(vless_config, "verify #true", "verify #true; verify #true"), "duplicate TLS verification"},
        {replace(vless_config, "verify #true", "verify #true; key-exchange \"unsupported\""), "unsupported TLS key exchange"},
        {replace(vless_config, "verify #true", "verify #true; key-exchange \"x25519\"; key-exchange \"x25519-mlkem768\""), "duplicate TLS key exchange"},
        {replace(vless_config, "uuid-file \"/tmp/edge.uuid\"", "uuid-file \"edge.uuid\""), "relative UUID file"},
        {replace(vless_config, "ca-file \"/tmp/ca.pem\"", "ca-file \"ca.pem\""), "relative CA file"},
        {replace(vless_config, "port=443", "port=0"), "zero VLESS server port"},
        {replace(vless_config, "server-name \"edge.example\"", "server-name \"\""), "empty TLS name"},
        {replace(vless_config, "default-outbound \"edge\"", "default-outbound \"direct\""), "unused VLESS outbound"},
        {replace(vless_config, "outbound \"edge\"", "outbound \"direct\""), "duplicate VLESS name"},
        {replace(vless_config, "server host=", "unsupported #true; server host="), "unknown VLESS node"},
    }) {
        if (config::parse_kdl(input)) {
            std::cerr << "invalid tunnel config accepted: " << description << '\n'; return 1;
        }
    }
    std::cout << "Tunnel protocol KDL configuration validation passed\n";
}
