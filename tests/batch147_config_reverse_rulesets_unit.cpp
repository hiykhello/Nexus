import std;
import config;
import cli.route_files;
import dns.message;
import dns.reverse;
import rules;

namespace {
    auto check(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    auto test_symbolic_dns_types_and_predefined() -> void {
        constexpr std::string_view cfg = R"kdl(
schema-version 1
role "client"
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds { outbound "direct" type="direct"; }
dns {
    listen host="127.0.0.1" port=5353
    reverse-mapping #true
    cache-flush-interval-ms 5000
    message-cache-directory "/tmp/nexus-b147-dns-cache"
    servers { server "up" type="udp" host="127.0.0.1" port=5300; }
    rule-set "inline-block" {
        domain-suffix "ads.example"
        domain "tracker.example"
    }
    rules {
        - rule-set="inline-block" query-type="HTTPS" action="predefined" predefined-rcode="NOERROR"
        - domain-suffix="no6.example" query-type="SVCB" action="predefined" predefined-rcode="NOERROR"
        - domain-suffix="nx.example" query-type="caa" action="predefined" predefined-rcode="nxdomain"
    }
    final "up"
}
routing {
    default-outbound "direct"
}
)kdl";
        auto parsed = config::parse_kdl(cfg);
        check(parsed.has_value(), parsed ? "" : "parse symbolic DNS config failed: " + parsed.error());
        check(parsed->dns.has_value(), "dns missing");
        check(parsed->dns->reverse_mapping, "reverse-mapping not enabled");
        check(parsed->dns->cache_flush_interval_ms == 5000, "cache-flush-interval-ms mismatch");
        check(parsed->dns->rules.size() == 3, "expected 3 dns rules");
        check(parsed->dns->rules[0].query_type == 65, "HTTPS should be type 65");
        check(parsed->dns->rules[0].predefined && parsed->dns->rules[0].predefined->rcode == 0 &&
              parsed->dns->rules[0].predefined->records.empty(), "empty NOERROR predefined failed");
        check(parsed->dns->rules[1].query_type == 64, "SVCB should be type 64");
        check(parsed->dns->rules[2].query_type == 257, "CAA should be type 257");
        check(parsed->dns->rules[2].predefined && parsed->dns->rules[2].predefined->rcode == 3, "NXDOMAIN rcode != 3");
        check(parsed->dns->rule_files.size() == 1 && parsed->dns->rule_files[0].file.inline_rules.has_value(),
              "inline DNS rule-set missing");
    }

    auto test_reverse_mapping_and_zero_implicit_dns() -> void {
        // 1. reverse domain-source rejected without dns.reverse-mapping
        constexpr std::string_view missing_rev = R"kdl(
schema-version 1
role "client"
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "block" type="block"
}
dns {
    servers { server "up" type="udp" host="127.0.0.1" port=5300; }
    final "up"
}
routing {
    rule-set "vip" {
        domain "vip.example"
    }
    tcp-program sniff-timeout-ms=500 unknown="skip" {
        rule action="route" rule-set="vip" domain-source="reverse" outbound="block"
    }
    default-outbound "direct"
}
)kdl";
        check(!config::parse_kdl(missing_rev).has_value(), "reverse domain-source must fail without reverse-mapping #true");

        // 2. Accepted with reverse-mapping #true, and passive ReverseCache + RouteProgram never requests resolve
        constexpr std::string_view with_rev = R"kdl(
schema-version 1
role "client"
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "block" type="block"
}
dns {
    reverse-mapping #true
    servers { server "up" type="udp" host="127.0.0.1" port=5300; }
    final "up"
}
routing {
    rule-set "vip" {
        domain "vip.example"
    }
    rule-set "geoip-like" {
        ip-cidr "10.0.0.0/8"
    }
    tcp-program sniff-timeout-ms=500 unknown="skip" {
        rule action="route" rule-set="geoip-like" outbound="block"
        rule action="route" rule-set="vip" domain-source="reverse" outbound="block"
    }
    default-outbound "direct"
}
)kdl";
        auto parsed = config::parse_kdl(with_rev);
        check(parsed.has_value(), parsed ? "" : "valid reverse config rejected: " + parsed.error());
        auto files = cli::load_route_files(*parsed, "/tmp/nonexistent.kdl");
        check(files.has_value(), files ? "" : "inline load_route_files failed: " + files.error());
        auto program = rules::RouteProgram::compile(files->ordered, 2);
        check(program.has_value(), "RouteProgram::compile failed");

        // Zero implicit DNS check: domain target without IP traversing ip-cidr rule MUST NOT request resolve!
        rules::ProgramInput domain_only{};
        domain_only.explicit_domain = "regular.example";
        domain_only.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)] = true;
        domain_only.port = 443;
        domain_only.network = rules::Network::tcp;
        rules::ProgramCursor cursor;
        for (;;) {
            auto poll = cursor.poll(*program, domain_only);
            check(poll.has_value(), "poll failed");
            if (poll->kind == rules::ProgramPreflightKind::uncertain) {
                check(cursor.skip_unknown(poll->rule_index).has_value(), "skip_unknown failed");
                continue;
            }
            if (poll->kind == rules::ProgramPreflightKind::exhausted) break;
            check(poll->step->action.kind != rules::ProgramActionKind::resolve,
                  "implicit DNS resolve triggered when none was configured!");
            break;
        }

        // Passive ReverseCache check: record IP->domain, lookup in O(1) memory, route matches outbound=1 (block)
        dns::ReverseCache cache(64, 1, {0x123456789abcdef0ULL, 0xfedcba9876543210ULL});
        dns::Address ip4{};
        ip4.size = 4;
        ip4.bytes = {198, 51, 100, 7};
        auto rec = cache.record(0, "vip.example", std::span(&ip4, 1), 60, 1000, cache.token());
        check(rec == dns::ReverseRecord::stored, "reverse record failed");
        auto found = cache.lookup(0, ip4, 2000);
        check(found && found->view() == "vip.example", "reverse lookup mismatch");

        rules::ProgramInput ip_input{};
        ip_input.ip = "198.51.100.7";
        ip_input.reverse_domain = found->view();
        ip_input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)] = true;
        ip_input.port = 443;
        ip_input.network = rules::Network::tcp;
        rules::ProgramCursor cursor2;
        auto step = cursor2.poll(*program, ip_input);
        check(step && step->step &&
              step->step->action.kind == rules::ProgramActionKind::route &&
              step->step->action.outbound == 1,
              "reverse_domain failed to route to block outbound");
    }

    auto test_three_tier_http_clients_and_remote_rulesets() -> void {
        constexpr std::string_view cfg = R"kdl(
schema-version 1
role "client"
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "block" type="block"
}
dns {
    servers { server "up" type="udp" host="127.0.0.1" port=5300; }
    final "up"
}
http-clients {
    direct-http {
        outbound "direct"
        domain-resolver "up"
        ca-file "/tmp/ca.pem"
    }
    alt-http {
        outbound "direct"
        domain-resolver "up"
        ca-file "/tmp/ca.pem"
    }
}
routing {
    default-http-client "direct-http"
    rule-set "r1" url="https://rules.example/a.srs" format="srs" update-interval-ms=60000
    rule-set "r2" url="https://rules.example/b.kdl" format="kdl" http-client="alt-http"
    rules {
        - kind="rule-set" value="r1" outbound="block"
        - kind="rule-set" value="r2" outbound="direct"
    }
    default-outbound "direct"
}
)kdl";
        auto parsed = config::parse_kdl(cfg);
        check(parsed.has_value(), parsed ? "" : "3-tier http-clients remote rule-set rejected: " + parsed.error());
        check(parsed->default_http_client == "direct-http", "default_http_client mismatch");
        check(parsed->routes.size() == 2, "expected 2 routes");
        check(parsed->routes[0].file.http_client == "direct-http", "r1 did not inherit default-http-client");
        check(parsed->routes[1].file.http_client == "alt-http", "r2 did not override http-client");
        auto files = cli::load_route_files(*parsed, "/tmp/c.kdl", true);
        check(files.has_value(), "nexus check offline remote placeholder failed");
    }

    auto test_working_dir_and_config_dir() -> void {
        auto root = std::filesystem::temp_directory_path() / "nexus-batch147-unit-tmp";
        std::filesystem::remove_all(root);
        auto wd = root / "work";
        auto cfgd = root / "conf.d";
        std::filesystem::create_directories(wd);
        std::filesystem::create_directories(cfgd);
        {
            std::ofstream(wd / "rel.kdl") << "version 2\ndomain \"from-wd.example\"\n";
            std::ofstream(cfgd / "00-base.kdl") << "schema-version 1\nrole \"client\"\n";
            std::ofstream(cfgd / "10-net.kdl") << R"kdl(
inbounds { inbound "socks" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "direct" type="direct"
    outbound "block" type="block"
}
routing {
    rule-set "local" path="rel.kdl" format="kdl"
    rules {
        - kind="rule-set" value="local" outbound="block"
    }
    default-outbound "direct"
}
)kdl";
            std::ofstream(cfgd / "10-net.kdl.bak") << "THIS IS INVALID KDL AND MUST BE IGNORED {{{{";
            std::ofstream(cfgd / ".hidden.kdl") << "THIS IS HIDDEN AND MUST BE IGNORED {{{{";
        }
        cli::set_working_directory(wd);
        auto merged = cli::read_config_source(cfgd.string(), true);
        check(merged.has_value(), merged ? "" : "read_config_source dir failed: " + merged.error());
        auto parsed = config::parse_kdl(*merged);
        check(parsed.has_value(), parsed ? "" : "parse merged dir failed: " + parsed.error());
        auto files = cli::load_route_files(*parsed, cfgd.string());
        check(files.has_value(), files ? "" : "load_route_files via -D working dir failed: " + files.error());

        // Duplicate inbound tag across two files must fail naming both files
        std::ofstream(cfgd / "20-dup.kdl") << "inbounds { inbound \"socks\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1081; authentication \"none\"; }; }\n";
        auto dup = cli::read_config_source(cfgd.string(), true);
        check(!dup.has_value() && dup.error().find("20-dup.kdl") != std::string::npos &&
              dup.error().find("10-net.kdl") != std::string::npos,
              "duplicate inbound across -C files did not report both filenames");
        std::filesystem::remove_all(root);
    }

    auto test_host_override_ast_merge() -> void {
        auto root = std::filesystem::temp_directory_path() / "nexus_wave22_host_override_test";
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root);

        auto write = [&](std::string_view name, std::string_view content) {
            auto p = root / name;
            std::ofstream(p) << content;
            return p;
        };

        // 1. Singleton replacement + ergonomic inbounds { tun ... } replacement without mixing inbounds/inbound
        auto base1 = write("base1.kdl", R"kdl(schema-version 1
role "client"
workers 2
log { level "info"; }
inbounds {
    socks5 "local-socks" { listen "127.0.0.1:1080"; authentication "none"; }
    tun "old-tun" { inet4-address "198.18.0.1/30"; mtu 1400; }
}
outbounds { direct; block; }
routing { default "direct"; }
)kdl");
        auto ov1 = write("ov1.kdl", R"kdl(workers 4
log { level "warn"; }
control socket="/tmp/nexus-wave22-test.sock"
inbounds {
    inbound "local-socks" type="mixed" { listen host="127.0.0.1" port=7890; authentication "none"; }
    inbound "android-tun" type="tun" { device-fd 9; mtu 1500; }
    inbound "extra-http" type="http" { listen host="127.0.0.1" port=8080; authentication "none"; }
}
)kdl");
        auto m1 = cli::read_config_source(base1.string(), false, ov1.string());
        check(m1.has_value(), m1 ? "" : "host-override merge 1 failed: " + m1.error());
        auto c1 = config::parse_kdl(*m1);
        check(c1.has_value(), c1 ? "" : "parse merged 1 failed: " + c1.error());
        check(c1->workers == std::min(4u, config::detect_host_parallelism()) && c1->control_socket == "/tmp/nexus-wave22-test.sock", "singleton overrides applied");
        check(c1->inbounds.size() == 3, "replaced socks+tun and appended extra-http");
        check(c1->inbounds[0].name == "local-socks" && c1->inbounds[0].type == config::Inbound::mixed && c1->inbounds[0].port == 7890,
              "named inbound replaced in-place");
        bool saw_old_tun = false, saw_new_tun = false, saw_http = false;
        for (auto const& in : c1->inbounds) {
            if (in.name == "old-tun") saw_old_tun = true;
            if (in.name == "android-tun" && in.tun && in.tun->device_fd && in.tun->device_fd->number == 9 && in.tun->mtu == 1500) saw_new_tun = true;
            if (in.name == "extra-http" && in.type == config::Inbound::http && in.port == 8080) saw_http = true;
        }
        check(!saw_old_tun && saw_new_tun && saw_http, "old tun stripped, new tun + extra http active");

        // 2. strip-tun #true removes base TUN while keeping non-TUN inbounds and strips host-override block
        auto ov2 = write("ov2.kdl", R"kdl(host-override {
    strip-tun #true
}
)kdl");
        auto m2 = cli::read_config_source(base1.string(), false, ov2.string());
        check(m2.has_value() && m2->find("host-override") == std::string::npos, "strip-tun strips directive block");
        auto c2 = config::parse_kdl(*m2);
        check(c2.has_value() && c2->inbounds.size() == 1 && c2->inbounds[0].name == "local-socks",
              "strip-tun keeps only non-tun inbound");

        // 3. strip-inbounds #true removes all base inbounds and replaces with override inbound
        auto ov3 = write("ov3.kdl", R"kdl(host-override {
    strip-inbounds #true
}
inbounds { inbound "proxy-only" type="socks5" { listen host="127.0.0.1" port=10808; authentication "none"; }; }
)kdl");
        auto m3 = cli::read_config_source(base1.string(), false, ov3.string());
        check(m3.has_value(), m3 ? "" : "strip-inbounds failed: " + m3.error());
        auto c3 = config::parse_kdl(*m3);
        check(c3.has_value() && c3->inbounds.size() == 1 && c3->inbounds[0].name == "proxy-only" && c3->inbounds[0].port == 10808,
              "strip-inbounds replaces all base inbounds");

        // 4. Reject invalid KDL syntax and unknown host-override directives
        auto bad_kdl = write("bad.kdl", "inbound \"broken\" { {{\n");
        check(!cli::read_config_source(base1.string(), false, bad_kdl.string()).has_value(), "invalid KDL rejected");
        auto bad_dir = write("bad_dir.kdl", "host-override { unknown-flag #true; }\n");
        check(!cli::read_config_source(base1.string(), false, bad_dir.string()).has_value(), "unknown directive rejected");

        // 5. Config-dir + host-override composition
        auto dir = root / "cfgdir";
        std::filesystem::create_directories(dir);
        write("cfgdir/00-host.kdl", "schema-version 1\nrole \"client\"\nworkers 1\n");
        write("cfgdir/10-in.kdl", "inbounds { inbound \"s\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n");
        write("cfgdir/20-out.kdl", "outbounds { outbound \"direct\" type=\"direct\"; }\nrouting { default-outbound \"direct\"; }\n");
        auto m5 = cli::read_config_source(dir.string(), true, ov3.string());
        check(m5.has_value(), m5 ? "" : "config-dir + host-override failed: " + m5.error());
        auto c5 = config::parse_kdl(*m5);
        check(c5.has_value() && c5->inbounds.size() == 1 && c5->inbounds[0].name == "proxy-only",
              "config-dir + host-override parsed");

        // 6. Override TUN placed BEFORE host-override { strip-tun #false; } still strips base TUN
        auto ov6 = write("ov6.kdl", R"kdl(inbounds { inbound "new-tun" type="tun" { device-fd 5; mtu 1500; }; }
host-override {
    strip-tun #false
}
)kdl");
        auto m6 = cli::read_config_source(base1.string(), false, ov6.string());
        check(m6.has_value(), m6 ? "" : "tun-before-directive merge failed: " + m6.error());
        auto c6 = config::parse_kdl(*m6);
        check(c6.has_value() && c6->inbounds.size() == 2, "tun-before-directive kept socks + new-tun only");
        bool saw_old6 = false, saw_new6 = false;
        for (auto const& in : c6->inbounds) {
            if (in.name == "old-tun") saw_old6 = true;
            if (in.name == "new-tun") saw_new6 = true;
        }
        check(!saw_old6 && saw_new6, "strip-tun #false after override TUN did not retain base TUN");

        // 7. Process singletons (sessions-per-listener, shutdown-grace-ms, tcp-splice-pipes) replace cleanly
        auto base7 = write("base7.kdl", R"kdl(schema-version 1
role "client"
sessions-per-listener 128
shutdown-grace-ms 1000
tcp-splice-pipes 4
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; }
routing { default-outbound "direct"; }
)kdl");
        auto ov7 = write("ov7.kdl", "sessions-per-listener 256\nshutdown-grace-ms 2500\ntcp-splice-pipes 8\n");
        auto m7 = cli::read_config_source(base7.string(), false, ov7.string());
        check(m7.has_value(), m7 ? "" : "process singleton override failed: " + m7.error());
        auto c7 = config::parse_kdl(*m7);
        check(c7.has_value() && c7->sessions_per_listener == 256 && c7->shutdown_grace_ms == 2500 &&
              c7->tcp_splice_pipes == 8, "process singletons overridden without duplicate error");

        // 8. Oversized base / override rejected before AST parse
        auto big_ov = write("big_ov.kdl", std::string(config::max_config_bytes + 32, ' '));
        check(!cli::read_config_source(base7.string(), false, big_ov.string()).has_value(), "oversized host-override rejected");

        std::filesystem::remove_all(root);
    }
}

int main() {
    test_symbolic_dns_types_and_predefined();
    test_reverse_mapping_and_zero_implicit_dns();
    test_three_tier_http_clients_and_remote_rulesets();
    test_working_dir_and_config_dir();
    test_host_override_ast_merge();
    std::cout << "ALL BATCH 147 UNIT TESTS PASSED!\n";
    return 0;
}
