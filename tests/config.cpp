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
    auto snell_inbound = [](std::string_view address) {
        return std::format(R"(    inbound "snell" type="snell" {{
        listen host="{}" port=1080
        version 5
        psk-file "/tmp/snell-psk"
        replay-window-seconds 60
    }}
)", address);
    };
    auto with_snell = [&](std::string_view address) { return add_inbound(complete, snell_inbound(address)); };
    if (!config::parse_kdl(with_snell("127.0.0.2")) ||
        config::parse_kdl(with_snell("127.0.0.1")) ||
        config::parse_kdl(with_snell("0.0.0.0")) ||
        !config::parse_kdl(with_snell("::1")) ||
        config::parse_kdl(with_snell("not-an-ip"))) return 1;
    if (!config::parse_kdl(add_inbound(with_snell("127.0.0.2"),
            replace(snell_inbound("127.0.0.3"), "inbound \"snell\"", "inbound \"snell2\"")))) return 1;

    auto grouped_snell = R"(schema-version 1
role "client"
inbounds { snell "in" { listen host="127.0.0.1" port=10080; version 5; psk-file "/tmp/psk"; replay-window-seconds 60; } }
outbounds { direct "direct"; snell "edge" { server host="127.0.0.1" port=1234; version 4; psk-file "/tmp/psk"; } }
routing { default-outbound "edge"; }
)";
    auto snell_groups = config::parse_kdl(grouped_snell);
    if (!snell_groups) { std::cerr << "grouped Snell: " << snell_groups.error() << '\n'; return 1; }
    if (snell_groups->inbounds.size() != 1 || snell_groups->inbounds[0].type != config::Inbound::snell ||
        snell_groups->snell_outbounds.size() != 1 || snell_groups->default_outbound != 2) return 1;
    for (auto flag : {"#true", "#false"}) {
        auto fast = config::parse_kdl(replace(grouped_snell, "version 4; psk-file", std::string("tcp-fast-open ") + flag + "; version 4; psk-file"));
        if (!fast || fast->snell_outbounds[0].config.tcp_fast_open != (std::string_view(flag) == "#true")) return 1;
    }
    for (auto field : {"tcp-fast-open 1", "tcp-fast-open #true; tcp-fast-open #false", "tcp-fast-open #true; detour \"direct\""})
        if (config::parse_kdl(replace(grouped_snell, "version 4; psk-file", std::string(field) + "; version 4; psk-file"))) return 1;
    if (snell_groups->snell_outbounds[0].config.reuse) return 1;
    for (auto flag : {"#true", "#false"}) {
        auto value = config::parse_kdl(replace(grouped_snell, "version 4; psk-file", std::string("reuse ") + flag + "; version 4; psk-file"));
        if (!value || value->snell_outbounds[0].config.reuse != (std::string_view(flag) == "#true")) return 1;
    }
    for (auto field : {"reuse 1", "reuse #true; reuse #false"})
        if (config::parse_kdl(replace(grouped_snell, "version 4; psk-file", std::string(field) + "; version 4; psk-file"))) return 1;
    auto snell_obfs = replace(grouped_snell, "version 4; psk-file", R"(obfs "http"; obfs-host "edge.example"; obfs-uri "/path"; version 4; psk-file)");
    snell_obfs = replace(snell_obfs, "version 5; psk-file", R"(obfs "http"; version 5; psk-file)");
    auto parsed_snell_obfs = config::parse_kdl(snell_obfs);
    if (!parsed_snell_obfs || !parsed_snell_obfs->inbounds[0].snell->http_obfs || !parsed_snell_obfs->snell_outbounds[0].config.http_obfs ||
        parsed_snell_obfs->snell_outbounds[0].config.obfs_host != "edge.example" || parsed_snell_obfs->snell_outbounds[0].config.obfs_uri != "/path") return 1;
    for (auto field : {R"(obfs "tls")", R"(obfs "http"; obfs "http")", R"(obfs-host "edge.example")",
                       R"(obfs "http"; obfs-host "bad host")", R"(obfs "http"; obfs-uri "relative")"})
        if (config::parse_kdl(replace(grouped_snell, "version 4; psk-file", std::string(field) + "; version 4; psk-file"))) return 1;
    if (config::parse_kdl(replace(grouped_snell, "version 5; psk-file", R"(obfs "tls"; version 5; psk-file)"))) return 1;

    auto config = config::parse_kdl(complete);
    auto direct_timeout = replace(complete, "outbound \"direct\" type=\"direct\"", "outbound \"direct\" type=\"direct\" { connect-timeout-ms 12500; }");
    auto parsed_direct_timeout = config::parse_kdl(direct_timeout);
    if (!parsed_direct_timeout || parsed_direct_timeout->direct_connect_timeout_ms != 12500 ||
        !config || config->direct_connect_timeout_ms != 10000) return 1;
    for (auto value : {"0", "3600001", "-1", "\"500\"", "500; connect-timeout-ms 500"})
        if (config::parse_kdl(replace(direct_timeout, "12500", value))) return 1;
    auto ipv6 = config::parse_kdl(replace(complete, "listen host=\"127.0.0.1\"", "listen host=\"::1\""));
    if (!ipv6 || !ipv6->listen_ipv6 || ipv6->inbounds.size() != 1 || !ipv6->inbounds[0].listen_ipv6) return 1;
    for (auto host : {"::1%lo", "[::1]", "not-an-ip", "256.0.0.1"})
        if (config::parse_kdl(replace(complete, "127.0.0.1", host))) return 1;

    auto ss = add_outbound(complete, "    outbound \"ss\" type=\"shadowsocks\" { server host=\"127.0.0.1\" port=8388; method \"2022-blake3-aes-128-gcm\"; key-file \"/secret\"; }\n");
    ss = replace(ss, "default-outbound \"direct\"", "default-outbound \"ss\"");
    auto parsed_ss = config::parse_kdl(ss);
    if (!parsed_ss || parsed_ss->shadowsocks_outbounds.size() != 1 || parsed_ss->default_outbound != 2 ||
        parsed_ss->shadowsocks_outbounds[0].config.key_file != "/secret" ||
        parsed_ss->shadowsocks_outbounds[0].config.connect_timeout_ms != 10000) return 1;
    for (auto flag : {"#true", "#false"}) {
        auto fast = config::parse_kdl(replace(ss, "key-file \"/secret\"", std::string("key-file \"/secret\"; tcp-fast-open ") + flag));
        if (!fast || fast->shadowsocks_outbounds[0].config.tcp_fast_open != (std::string_view(flag) == "#true")) return 1;
    }
    for (auto field : {"tcp-fast-open 1", "tcp-fast-open #true; tcp-fast-open #false", "tcp-fast-open #true; detour \"direct\""})
        if (config::parse_kdl(replace(ss, "key-file \"/secret\"", std::string("key-file \"/secret\"; ") + field))) return 1;
    auto ss_timeout = replace(ss, "key-file \"/secret\"", "key-file \"/secret\"; connect-timeout-ms 12500");
    auto parsed_ss_timeout = config::parse_kdl(ss_timeout);
    if (!parsed_ss_timeout || parsed_ss_timeout->shadowsocks_outbounds[0].config.connect_timeout_ms != 12500) return 1;
    for (auto value : {"0", "3600001", "-1", "\"500\"", "500; connect-timeout-ms 500"})
        if (config::parse_kdl(replace(ss_timeout, "12500", value))) return 1;
    for (auto bad : {replace(ss, "key-file \"/secret\"", "key-file \"relative\""),
                     replace(ss, "2022-blake3-aes-128-gcm", "aes-128-gcm"),
                     replace(ss, "outbound \"ss\"", "outbound \"direct\""),
                     replace(ss, "default-outbound \"ss\"", "default-outbound \"direct\"")})
        if (config::parse_kdl(bad)) return 1;
    auto ss_uot = replace(ss, "key-file \"/secret\"", "key-file \"/secret\"; udp-over-tcp \"v2\"");
    auto parsed_uot = config::parse_kdl(ss_uot);
    if (!parsed_uot || !parsed_uot->shadowsocks_outbounds[0].config.udp_over_tcp || parsed_ss->shadowsocks_outbounds[0].config.udp_over_tcp ||
        config::parse_kdl(replace(ss_uot, "udp-over-tcp \"v2\"", "udp-over-tcp \"v1\"")) ||
        config::parse_kdl(replace(ss_uot, "udp-over-tcp \"v2\"", "udp-over-tcp \"v2\"; udp-over-tcp \"v2\""))) return 1;
    auto ss_boot = replace(ss, "server host=\"127.0.0.1\"", "bootstrap-resolver \"boot\"; server host=\"edge.test\"");
    ss_boot = "dns { servers { server \"boot\" type=\"udp\" host=\"127.0.0.1\"; }; }\n" + ss_boot;
    auto ss_boot_uot = config::parse_kdl(replace(ss_boot, "key-file \"/secret\"", "key-file \"/secret\"; udp-over-tcp \"v2\""));
    if (!ss_boot_uot || !ss_boot_uot->shadowsocks_outbounds[0].config.udp_over_tcp || ss_boot_uot->shadowsocks_outbounds[0].config.bootstrap_index != 0) return 1;
    auto parsed_ss_boot = config::parse_kdl(ss_boot);
    if (!parsed_ss_boot || parsed_ss_boot->shadowsocks_outbounds[0].config.bootstrap_index != 0 ||
        config::parse_kdl(replace(ss_boot, "bootstrap-resolver \"boot\"", "bootstrap-resolver \"missing\"")) ||
        config::parse_kdl(replace(ss_boot, "edge.test", "127.0.0.1")) ||
        config::parse_kdl(replace(ss_boot, "bootstrap-resolver \"boot\";", "bootstrap-resolver \"boot\"; bootstrap-resolver \"boot\";"))) return 1;

    if (!config || config->port != 1080 || !config->block_rules ||
        config->block_rules->path != "rules/blocked.kdl" || config->block_rules->format != config::RuleFormat::kdl) {
        std::cerr << "valid configuration rejected\n"; return 1;
    }
    auto grouped_config = config::parse_kdl("dns { servers { server \"system\" type=\"local\"; server \"up\" type=\"udp\" host=\"127.0.0.1\"; }; final \"up\"; }\n" + complete);
    if (!grouped_config || !grouped_config->dns || grouped_config->dns->servers.size() != 2 || grouped_config->dns->final != 1 ||
        grouped_config->port != 1080 || !grouped_config->block_rules) return 1;
    for (auto bad : {"inbounds {}\n", "outbounds {}\n", "inbounds { other; }\n", "outbounds { other; }\n",
                     "inbounds x=1 {}\n", "outbounds \"x\" {}\n", "inbound \"extra\" type=\"socks5\" {}\n",
                     "outbound \"extra\" type=\"direct\"\n"})
        if (config::parse_kdl(std::string(bad) + complete)) return 1;
    for (auto bad : {"dns { servers {}; }\n", "dns { servers { other; }; }\n",
                     "dns { server \"a\" type=\"local\"; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; server \"b\" type=\"local\"; }\n",
                     "dns { server \"a\" type=\"local\"; servers { server \"b\" type=\"local\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; servers { server \"b\" type=\"local\"; }; }\n"})
        if (config::parse_kdl(std::string(bad) + complete)) return 1;
    auto multiple = replace(complete, "outbounds {", "inbounds {}\noutbounds {");
    auto second = add_inbound(complete, "    inbound \"other\" type=\"mixed\" { listen host=\"127.0.0.1\" port=1081; authentication \"none\"; }\n");
    auto parsed_multi = config::parse_kdl(second);
    auto dual = replace(second, "listen host=\"127.0.0.1\" port=1081", "listen host=\"::1\" port=1080");
    auto parsed_dual = config::parse_kdl(dual);
    if (!parsed_dual || parsed_dual->inbounds.size() != 2 || parsed_dual->inbounds[0].listen_ipv6 ||
        !parsed_dual->inbounds[1].listen_ipv6 || parsed_dual->inbounds[0].port != parsed_dual->inbounds[1].port ||
        config::parse_kdl(replace(dual, "listen host=\"127.0.0.1\" port=1080", "listen host=\"::1\" port=1080"))) return 1;
    if (!parsed_multi || parsed_multi->inbounds.size() != 2 || parsed_multi->inbounds[1].port != 1081 ||
        parsed_multi->inbounds[1].type != config::Inbound::mixed || config::parse_kdl(multiple) ||
        config::parse_kdl(replace(second, "port=1081", "port=1080")) ||
        config::parse_kdl(replace(second, "inbound \"other\"", "inbound \"local\""))) return 1;

    auto typed = replace(complete, "inbound \"local\" type=\"socks5\"", "socks5 \"local\"");
    typed = replace(typed, "outbound \"direct\" type=\"direct\"", "direct \"direct\"");
    typed = replace(typed, "outbound \"reject\" type=\"block\"", "block \"reject\"");
    auto ss_in = replace(typed, R"(socks5 "local" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    })", R"(shadowsocks "local" {
        listen host="127.0.0.1" port=1080
        method "2022-blake3-aes-128-gcm"
        key-file "/secret"
    })");
    auto ss_in_config = config::parse_kdl(ss_in);
    if (!ss_in_config || ss_in_config->inbounds[0].type != config::Inbound::shadowsocks ||
        !ss_in_config->inbounds[0].shadowsocks || ss_in_config->inbounds[0].shadowsocks->key_file != "/secret") return 1;
    for (auto bad : {replace(ss_in, "key-file \"/secret\"", "key-file \"relative\""),
                     replace(ss_in, "2022-blake3-aes-128-gcm", "aes-128-gcm"),
                     replace(ss_in, "key-file \"/secret\"", "key-file \"/secret\"; key-file \"/secret\""),
                     replace(ss_in, "key-file \"/secret\"", "authentication \"none\"; key-file \"/secret\"")})
        if (config::parse_kdl(bad)) return 1;
    auto new_style = config::parse_kdl("dns { servers { local \"system\"; udp \"up\" host=\"127.0.0.1\"; }; rules { - domain=\"example.test\" server=\"up\"; }; }\n" + typed);
    if (!new_style || new_style->inbounds.size() != 1 || !new_style->dns || new_style->dns->rules.size() != 1 ||
        new_style->dns->rules[0].server != 1) return 1;
    for (auto bad : {"dns { servers { udp \"a\" type=\"udp\" host=\"127.0.0.1\"; }; }\n",
                     "dns { servers { local \"a\"; }; rules { rule domain=\"x.test\" server=\"a\"; }; }\n",
                     "dns { servers { local \"a\"; }; rule domain=\"y.test\" server=\"a\"; }\n",
                     "dns { servers { local \"a\"; }; rules { - domain=\"x.test\" server=\"a\"; }; rule domain=\"y.test\" server=\"a\"; }\n"})
        if (config::parse_kdl(std::string(bad) + typed)) return 1;
    std::string many_inbounds = "inbounds {\n";
    for (int i = 0; i < 16; ++i)
        many_inbounds += "socks5 \"in" + std::to_string(i) + "\" { listen host=\"127.0.0.1\" port=" +
                         std::to_string(20000 + i) + "; authentication \"none\"; }\n";
    auto without_inbounds = complete.substr(0, complete.find("inbounds {")) + complete.substr(complete.find("outbounds {"));
    auto maximum = config::parse_kdl(many_inbounds + "}\n" + without_inbounds);
    if (!maximum || maximum->inbounds.size() != 16) return 1;
    many_inbounds += "socks5 \"overflow\" { listen host=\"127.0.0.1\" port=20016; authentication \"none\"; }\n";
    if (config::parse_kdl(many_inbounds + "}\n" + without_inbounds)) return 1;

    if (config->workers != 1) return 1;
    if (config::parse_kdl("dns-upstream host=\"127.0.0.1\" port=5353\n" + complete) ||
        config::parse_kdl("dns-upstream host=\"::1\" port=5353\n" + complete)) return 1;
    auto servers = config::parse_kdl(R"(dns {
        servers {
            server "system" type="local"
            server "remote" type="udp" host="::1" port=5353
        }
        final "remote"
    }
)" + complete);
    if (!servers || !servers->dns || servers->dns->final != 1 || !servers->dns->servers[1].upstream ||
        !servers->dns->servers[1].upstream->ipv6 || servers->dns->servers[1].upstream->port != 5353) return 1;
    auto first = config::parse_kdl("dns { servers { server \"remote\" type=\"udp\" host=\"127.0.0.1\"; server \"system\" type=\"local\"; }; }\n" + complete);
    if (!first || !first->dns || first->dns->final != 0 || first->dns->servers[0].upstream->port != 53) return 1;
    auto local = config::parse_kdl("dns { servers { server \"remote\" type=\"udp\" host=\"127.0.0.1\"; server \"system\" type=\"local\"; }; final \"system\"; }\n" + complete);
    if (!local || !local->dns || local->dns->final != 1 || local->dns->servers[1].upstream) return 1;
    auto tcp = config::parse_kdl("dns { servers { server \"tcp\" type=\"tcp\" host=\"::1\"; }; }\n" + complete);
    if (!tcp || !tcp->dns || !tcp->dns->servers[0].upstream || !tcp->dns->servers[0].upstream->tcp ||
        tcp->dns->servers[0].upstream->port != 53) return 1;
    for (auto const& [value, expected] : std::array{
        std::pair{"prefer_ipv4", config::DnsStrategy::prefer_ipv4},
        std::pair{"prefer_ipv6", config::DnsStrategy::prefer_ipv6},
        std::pair{"ipv4_only", config::DnsStrategy::ipv4_only},
        std::pair{"ipv6_only", config::DnsStrategy::ipv6_only}}) {
        auto parsed = config::parse_kdl("dns { servers { server \"a\" type=\"local\"; }; strategy \"" + std::string(value) + "\"; }\n" + complete);
        if (!parsed || !parsed->dns || parsed->dns->strategy != expected) return 1;
    }
    auto dns_rules = config::parse_kdl("dns { servers { server \"system\" type=\"local\"; server \"remote\" type=\"udp\" host=\"127.0.0.1\"; }; rules { - domain-suffix=\"Example.COM\" server=\"remote\"; - domain=\"host.example.com\" server=\"system\"; }; }\n" + complete);
    if (!dns_rules || !dns_rules->dns || dns_rules->dns->rules.size() != 2 || dns_rules->dns->rules[0].domain != "example.com" ||
        !dns_rules->dns->rules[0].suffix || dns_rules->dns->rules[0].server != 1 || dns_rules->dns->rules[1].server != 0) return 1;
    auto bootstrap = config::parse_kdl("dns { servers { server \"leaf\" type=\"tcp\" host=\"dns.example\" domain-resolver=\"middle\"; server \"middle\" type=\"udp\" host=\"next.example\" domain-resolver=\"root\"; server \"root\" type=\"local\"; }; }\n" + complete);
    if (!bootstrap || !bootstrap->dns || bootstrap->dns->servers[0].upstream->host != "dns.example" ||
        bootstrap->dns->servers[0].upstream->resolver != 1 || bootstrap->dns->servers[1].upstream->resolver != 2) return 1;
    auto no_cache = config::parse_kdl("dns { servers { server \"a\" type=\"local\"; }; disable-cache #true; }\n" + complete);
    auto cache = config::parse_kdl("dns { servers { server \"a\" type=\"local\"; }; disable-cache #false; }\n" + complete);
    if (!no_cache || !no_cache->dns || !no_cache->dns->disable_cache || !cache || !cache->dns || cache->dns->disable_cache) return 1;
    auto edns = config::parse_kdl("dns { servers { server \"a\" type=\"local\"; }; edns #true; }\n" + complete);
    if (!edns || !edns->dns || !edns->dns->edns) return 1;
    for (auto bad : {"dns {}\n", "dns { final \"missing\"; servers { server \"a\" type=\"local\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; server \"a\" type=\"local\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\" host=\"127.0.0.1\"; }; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"localhost\"; }; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"127.0.0.1\" extra=1; }; }\n",
                     "dns { servers { server \"a\" type=\"tls\" host=\"127.0.0.1\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; final \"a\"; final \"a\"; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; rules { - domain=\"example.com\" server=\"missing\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; rules { - domain=\"-bad.test\" server=\"a\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; rules { - domain=\"a.test\" domain-suffix=\"a.test\" server=\"a\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; strategy \"other\"; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; strategy \"ipv4_only\"; strategy \"ipv6_only\"; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; disable-cache \"true\"; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; disable-cache #true; disable-cache #false; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; edns \"true\"; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; edns #true; edns #false; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"dns.example\"; }; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"dns.example\" domain-resolver=\"missing\"; }; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"dns.example\" domain-resolver=\"a\"; }; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"a.example\" domain-resolver=\"b\"; server \"b\" type=\"tcp\" host=\"b.example\" domain-resolver=\"a\"; }; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"127.00.0.1\" domain-resolver=\"b\"; server \"b\" type=\"local\"; }; }\n",
                     "dns { servers { server \"a\" type=\"udp\" host=\"127.0.0.1\" domain-resolver=\"b\"; server \"b\" type=\"local\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; }\ndns-upstream host=\"127.0.0.1\" port=53\n",
                     "dns-upstream host=\"127.0.0.1\" port=53\ndns { servers { server \"a\" type=\"local\"; }; }\n"})
        if (config::parse_kdl(std::string(bad) + complete)) return 1;

    auto const host_h = config::detect_host_parallelism();
    if (host_h < 1 || !config::validate_workers_spec("auto") || !config::validate_workers_spec("max") ||
        !config::validate_workers_spec("max-0") || !config::validate_workers_spec("max-2") ||
        !config::validate_workers_spec("auto-2") || !config::validate_workers_spec("max-25") ||
        config::validate_workers_spec("") || config::validate_workers_spec("max-") ||
        config::validate_workers_spec("auto-") || config::validate_workers_spec("max-abc") ||
        config::validate_workers_spec("max--1") || config::validate_workers_spec("max-+1") ||
        config::validate_workers_spec("foo") || config::validate_workers_spec("AUTO") ||
        config::validate_workers_spec("max-99999999999999999999")) return 1;
    auto expect_resolve = [](std::string_view spec, std::optional<unsigned> cap, unsigned h, unsigned want) {
        auto r = config::resolve_workers_spec(spec, cap, h);
        return r && *r == want;
    };
    if (!expect_resolve("auto", {}, 20, 20) || !expect_resolve("max", {}, 20, 20) ||
        !expect_resolve("max-2", {}, 20, 18) || !expect_resolve("auto-2", {}, 20, 18) ||
        !expect_resolve("max-0", {}, 20, 20) || !expect_resolve("max-25", {}, 20, 1) ||
        !expect_resolve("auto", 8, 20, 8) || !expect_resolve("max-2", 12, 20, 12) ||
        !expect_resolve("max-2", 24, 20, 18) || !expect_resolve("auto", {}, 4, 4) ||
        !expect_resolve("max-2", {}, 4, 2) || !expect_resolve("auto", 8, 4, 4) ||
        !expect_resolve("max-4", {}, 2, 1) || !expect_resolve("max-1", {}, 2, 1) ||
        !expect_resolve("auto", {}, 1, 1) || !expect_resolve("max-2", {}, 1, 1) ||
        !expect_resolve("auto", {}, 0, 1) || config::resolve_workers_spec("auto", 0, 20).has_value() ||
        config::resolve_workers_spec("bad", {}, 20).has_value()) return 1;
    auto def_w = config::parse_kdl(complete);
    if (!def_w || def_w->workers != 1 || def_w->host_parallelism != host_h || def_w->workers_clamped_from) return 1;
    auto multi = config::parse_kdl("workers 2\n" + complete);
    if (!multi || multi->workers != std::min(2u, host_h) ||
        (host_h >= 2 ? multi->workers_clamped_from.has_value() : multi->workers_clamped_from != 2u)) return 1;
    auto over_req = host_h + 5u;
    auto clamped = config::parse_kdl("workers " + std::to_string(over_req) + "\n" + complete);
    if (!clamped || clamped->workers != host_h || clamped->workers_clamped_from != over_req) return 1;
    auto w_auto = config::parse_kdl("workers \"auto\"\n" + complete);
    auto w_max = config::parse_kdl("workers \"max\"\n" + complete);
    auto w_m2 = config::parse_kdl("workers \"max-2\"\n" + complete);
    auto w_a2 = config::parse_kdl("workers \"auto-2\"\n" + complete);
    auto w_m25 = config::parse_kdl("workers \"max-25\"\n" + complete);
    auto w_cap8 = config::parse_kdl("workers \"auto\" max=8\n" + complete);
    auto w_m2c12 = config::parse_kdl("workers \"max-2\" max=12\n" + complete);
    auto want_m2 = host_h > 2 ? host_h - 2 : 1u;
    if (!w_auto || w_auto->workers != host_h || w_auto->workers_clamped_from ||
        !w_max || w_max->workers != host_h || !w_m2 || w_m2->workers != want_m2 ||
        !w_a2 || w_a2->workers != want_m2 || !w_m25 || w_m25->workers != (host_h > 25 ? host_h - 25 : 1u) ||
        !w_cap8 || w_cap8->workers != std::min(host_h, 8u) ||
        !w_m2c12 || w_m2c12->workers != std::min(want_m2, 12u)) return 1;
    for (auto bad_w : {"workers 0\n", "workers -1\n", "workers 4 max=2\n", "workers \"auto\" max=0\n",
                       "workers \"auto\" max=-1\n", "workers \"auto\" other=1\n", "workers \"\"\n",
                       "workers \"max-\"\n", "workers \"max-abc\"\n", "workers \"max--1\"\n",
                       "workers \"foo\"\n", "workers 1\nworkers 2\n", "workers 1 { child; }\n"})
        if (config::parse_kdl(std::string(bad_w) + complete)) return 1;

    auto mixed = config::parse_kdl(replace(complete, "type=\"socks5\"", "type=\"mixed\""));
    if (!mixed || mixed->inbound != config::Inbound::mixed) return 1;
    auto authenticated = replace(complete, "authentication \"none\"", "authentication \"password\" username=\"alice\" password-file=\"/tmp/password\"");
    auto auth = config::parse_kdl(authenticated);
    if (!auth || !auth->password_auth || auth->password_auth->username != "alice" || auth->password_auth->password_file != "/tmp/password") return 1;
    auto auth_mixed = config::parse_kdl(replace(authenticated, "type=\"socks5\"", "type=\"mixed\""));
    if (!auth_mixed || !auth_mixed->password_auth) return 1;
    auto binary = config::parse_kdl(replace(complete, "format=\"kdl\"", "format=\"beve\""));
    if (!binary || !binary->block_rules || binary->block_rules->format != config::RuleFormat::beve) return 1;
    auto minimal = config::parse_kdl(R"(schema-version 1
role "server"
inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=65535; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; }
routing { default-outbound "direct"; }
)");
    if (!minimal || minimal->port != 65535 || minimal->block_rules) { std::cerr << "direct-only rejected\n"; return 1; }

    for (auto lan : {"0.0.0.0", "::", "192.168.1.10"}) {
        for (auto kind : {"socks5", "mixed", "http"}) {
            auto c = replace(replace(complete, "host=\"127.0.0.1\"", std::string("host=\"") + lan + "\""), "type=\"socks5\"", std::string("type=\"") + kind + "\"");
            auto p = config::parse_kdl(c);
            if (!p || p->inbounds.empty() || p->inbounds[0].listen_host != lan || !p->inbounds[0].listen_address) return 1;
        }
    }
    if (!config::parse_kdl(R"(schema-version 1
role "client"
inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; outbound "g" type="url-test" { member "direct"; probe-mode "http"; probe-url "https://127.0.0.1:443/h"; probe-ca-file "/tmp/ca.pem"; probe-server-name "h.example"; }; }
routing { default-outbound "g"; })")) return 1;
    if (!config::parse_kdl(R"(schema-version 1
role "client"
inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; outbound "lb" type="load-balance" { member "direct"; }; }
routing { default-outbound "lb"; })")) return 1;
    auto ordered = replace(replace(complete, "routing {", "routing {\n    rule-set \"other\" path=\"other.beve\" format=\"beve\""),
        "rules {", "rules {\n        - kind=\"rule-set\" value=\"other\" outbound=\"direct\"");
    auto ordered_config = config::parse_kdl(ordered);
    if (!ordered_config || ordered_config->routes.size() != 2 ||
        ordered_config->routes[0].file.path != "other.beve" || ordered_config->routes[0].file.format != config::RuleFormat::beve ||
        ordered_config->routes[0].action != config::RouteAction::direct || ordered_config->routes[1].action != config::RouteAction::block) return 1;
    auto direct_net = replace(complete, "outbound \"direct\" type=\"direct\"",
        "outbound \"direct\" type=\"direct\" {\n    network strategy=\"require\" type=\"wifi\" { interface \"wlan0\" type=\"wifi\"; }\n}");
    if (!config::parse_kdl(direct_net)) return 1;

    std::vector<std::pair<std::string, std::string>> cases{
        {replace(direct_net, "network strategy=", "inet4-bind-address \"127.0.0.1\"; network strategy="), "direct network with inet4-bind-address"},
        {replace(direct_net, "network strategy=", "inet6-bind-address \"::1\"; network strategy="), "direct network with inet6-bind-address"},
        {replace(complete, "schema-version 1", "schema-version 2"), "wrong version"},
        {complete + "schema-version 1\n", "duplicate version"},
        {replace(complete, "role \"client\"", "role \"router\""), "wrong role"},
        {replace(complete, "type=\"socks5\"", "type=\"unknown\""), "unsupported inbound"},
        {replace(complete, "host=\"127.0.0.1\"", "host=\"not-an-ip\""), "untrusted listener"},
        {replace(complete, "port=1080", "port=0"), "zero port"},
        {replace(complete, "port=1080", "port=65536"), "oversized port"},
        {replace(complete, "port=1080", "port=-1"), "negative port"},
        {replace(complete, "port=1080", "port=\"1080\""), "string port"},
        {replace(complete, "authentication \"none\"", "authentication \"password\""), "unsupported authentication"},
        {replace(replace(authenticated, "type=\"socks5\"", "type=\"mixed\""), "username=\"alice\"", "username=\"alice:bob\""), "mixed colon username"},
        {replace(authenticated, "password-file=\"/tmp/password\"", "password-file=\"relative\""), "relative password"},
        {replace(authenticated, "username=\"alice\"", "username=\"\""), "empty username"},
        {replace(authenticated, "username=\"alice\"", "username=\"a\\u{0}b\""), "NUL username"},
        {replace(authenticated, "password-file=\"/tmp/password\"", "password-file=\"/tmp/x\\u{0}y\""), "NUL password path"},
        {replace(complete, "authentication \"none\"", ""), "missing authentication"},
        {replace(complete, "authentication \"none\"", "authentication \"none\"; authentication \"none\""), "duplicate authentication"},
        {replace(complete, "type=\"direct\"", "type=\"vless\""), "unsupported outbound"},
        {replace(complete, "outbound \"reject\"", "outbound \"direct\""), "duplicate names"},
        {replace(complete, "default-outbound \"direct\"", "default-outbound \"reject\""), "unsupported default"},
        {replace(complete, "value=\"blocked\"", "value=\"missing\""), "missing rule set"},
        {replace(complete, "outbound=\"reject\"", "outbound=\"missing\""), "unknown rule action"},
        {replace(complete, "format=\"kdl\"", "format=\"yaml\""), "unsupported format"},
        {replace(complete, "path=\"rules/blocked.kdl\"", "path=\"\""), "empty path"},
        {replace(complete, "path=\"rules/blocked.kdl\"", "path=\"rules\\u{0}x\""), "NUL path"},
        {replace(complete, "routing {", "routing {\n    rule-set \"blocked\" path=\"other.kdl\" format=\"kdl\""), "duplicate rule-set"},
        {replace(complete, "routing {", "routing {\n    rule-set \"unused\" path=\"other.kdl\" format=\"kdl\""), "unreferenced rule-set"},
        {replace(complete, "routing {", "routing {\n    sniff #true"), "unknown routing node"},
        {replace(complete, "rules {\n        - kind=\"rule-set\" value=\"blocked\" outbound=\"reject\"\n    }", "rule kind=\"rule-set\" value=\"blocked\" outbound=\"reject\""), "legacy bare routing rule"},
        {complete + "dns {}\n", "unsupported top-level node"},
        {replace(complete, "role \"client\"", "role (x)\"client\""), "tagged role"},
        {std::string(config::max_config_bytes + 1, ' '), "oversized input"},
    };
    for (auto const& [input, description] : cases) {
        if (config::parse_kdl(input)) {
            std::cerr << "invalid configuration accepted: " << description << '\n'; return 1;
        }
    }
    std::cout << "KDL configuration parsing and validation passed\n";
}
