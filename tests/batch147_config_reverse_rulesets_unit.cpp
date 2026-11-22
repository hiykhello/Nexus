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
inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
dns {
    listen host="127.0.0.1" port=5353
    reverse-mapping #true
    cache-flush-interval-ms 5000
    message-cache-directory "/tmp/nexus-b147-dns-cache"
    server "up" type="udp" host="127.0.0.1" port=5300
    rule-set "inline-block" {
        domain-suffix "ads.example"
        domain "tracker.example"
    }
    rule rule-set="inline-block" query-type="HTTPS" action="predefined" predefined-rcode="NOERROR"
    rule domain-suffix="no6.example" query-type="SVCB" action="predefined" predefined-rcode="NOERROR"
    rule domain-suffix="nx.example" query-type="caa" action="predefined" predefined-rcode="nxdomain"
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
inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
outbound "block" type="block"
dns {
    server "up" type="udp" host="127.0.0.1" port=5300
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
inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
outbound "block" type="block"
dns {
    reverse-mapping #true
    server "up" type="udp" host="127.0.0.1" port=5300
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
inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
outbound "block" type="block"
dns {
    server "up" type="udp" host="127.0.0.1" port=5300
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
    rule kind="rule-set" value="r1" outbound="block"
    rule kind="rule-set" value="r2" outbound="direct"
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
inbound "socks" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }
outbound "direct" type="direct"
outbound "block" type="block"
routing {
    rule-set "local" path="rel.kdl" format="kdl"
    rule kind="rule-set" value="local" outbound="block"
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
        std::ofstream(cfgd / "20-dup.kdl") << "inbound \"socks\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1081; authentication \"none\"; }\n";
        auto dup = cli::read_config_source(cfgd.string(), true);
        check(!dup.has_value() && dup.error().find("20-dup.kdl") != std::string::npos &&
              dup.error().find("10-net.kdl") != std::string::npos,
              "duplicate inbound across -C files did not report both filenames");
        std::filesystem::remove_all(root);
    }
}

int main() {
    test_symbolic_dns_types_and_predefined();
    test_reverse_mapping_and_zero_implicit_dns();
    test_three_tier_http_clients_and_remote_rulesets();
    test_working_dir_and_config_dir();
    std::cout << "ALL BATCH 147 UNIT TESTS PASSED!\n";
    return 0;
}
