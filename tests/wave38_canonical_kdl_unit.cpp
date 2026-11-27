#include <cstdio>
#include <cstdlib>

import std;
import config;
import cli.route_files;
import platform.socket_options;
import rules;
import utility;

namespace {
    auto require(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::fprintf(stderr, "FAIL: %.*s\n", static_cast<int>(msg.size()), msg.data());
            std::exit(1);
        }
    }

    auto replace(std::string text, std::string_view before, std::string_view after) -> std::string {
        auto pos = text.find(before);
        require(pos != std::string::npos, "replace: target substring not found");
        text.replace(pos, before.size(), after);
        return text;
    }

    constexpr std::string_view kCanonicalBase = R"kdl(schema-version 1
role "client"
inbounds {
    socks5 "local" {
        listen "127.0.0.1:1080"
        authentication "none"
    }
}
outbounds {
    direct
    block
}
dns {
    servers {
        udp "sys" host="127.0.0.1" port=5353
        udp "cn" host="127.0.0.1" port=5354
    }
    default "sys"
    final "sys"
}
http-clients {
    default "dl"
    dl {
        outbound "direct"
        ca-file "/tmp/ca.pem"
    }
}
)kdl";

    // 1. Canonical routing, rulesets (inline props + child nodes + predicates), boolean sugar, and - final.
    auto test_canonical_routing_and_rulesets() -> void {
        std::string cfg = std::string(kCanonicalBase) + R"kdl(
routing {
    find-process #true
    rulesets {
        geosite-cn url="https://example.com/geosite-cn.srs" format="srs" update-interval-ms=3600000
        "GeoLocation-!CN" type="remote" url="https://example.com/noncn.srs" format="srs"
        high-purity path="rules/high-purity.kdl" format="kdl"
        my-direct {
            domain-suffix "example.local"
        }
        block-remote {
            type "remote"
            url "https://example.com/block.srs"
            format "srs"
            update-interval-ms 7200000
            http-client "dl"
            sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
        block-local {
            path "rules/block.kdl"
            format "kdl"
        }
        block-inline {
            type "inline"
            domain-suffix "child-inline.local"
            ip-cidr "10.0.0.0/8"
        }
    }
    rules {
        - ip-is-private to="direct"
        - source-ip-is-private to="direct"
        - rule-set "geosite-cn" to="direct"
        - rule-set "GeoLocation-!CN" to="block"
        - rule-set "high-purity" to="direct"
        - rule-set "my-direct" to="direct"
        - rule-set "block-remote" to="block"
        - rule-set "block-local" to="direct"
        - rule-set "block-inline" to="direct"
    }
    final "direct"
}
)kdl";
        auto parsed = config::parse_kdl(cfg);
        require(parsed.has_value(), parsed ? "" : "canonical routing failed: " + parsed.error());
        require(parsed->defaults.find_process, "routing find-process parsed");
        require(parsed->default_http_client == "dl", "http-clients default parsed");
        require(parsed->defaults.default_domain_resolver == "sys", "dns default dial resolver parsed");
        require(parsed->http_clients.size() == 1 && parsed->http_clients[0].resolver == "sys",
            "http-client inherited dns.default resolver");
        require(parsed->ordered_tcp.has_value() && parsed->ordered_tcp->sets.size() == 7,
            "all 7 canonical rulesets parsed");

        auto find_rs = [&](std::string_view name) -> config::BlockRules const& {
            for (auto const& [k, v] : parsed->ordered_tcp->sets)
                if (k == name) return v;
            require(false, "missing expected ruleset");
            std::unreachable();
        };
        require(find_rs("geosite-cn").http_client == "dl" &&
                find_rs("geosite-cn").update_interval_ms == 3600000, "remote ruleset inherited http-clients.default");
        require(find_rs("GeoLocation-!CN").url == "https://example.com/noncn.srs", "quoted special-char name");
        require(find_rs("high-purity").path == "rules/high-purity.kdl", "inline-prop local ruleset");
        require(find_rs("my-direct").inline_rules.has_value(), "inline predicate ruleset");
        auto const& br = find_rs("block-remote");
        require(br.url == "https://example.com/block.srs" && br.update_interval_ms == 7200000 &&
                br.sha256 == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "child-node remote ruleset fields");
        require(find_rs("block-local").path == "rules/block.kdl", "child-node local ruleset");
        require(find_rs("block-inline").inline_rules.has_value(), "child-node inline ruleset");
        require(parsed->ordered_tcp->rules.size() == 9 &&
                parsed->ordered_tcp->rules[0].predicates.rules.size() == 1 &&
                parsed->ordered_tcp->rules[0].predicates.rules[0].type == "ip-is-private" &&
                parsed->ordered_tcp->rules[0].predicates.rules[0].value == "true",
            "- ip-is-private omits redundant #true");
        require(parsed->ordered_tcp->rules[1].predicates.rules[0].type == "source-ip-is-private" &&
                parsed->ordered_tcp->rules[1].predicates.rules[0].value == "true",
            "- source-ip-is-private omits redundant #true");

        // Verify - final "<outbound>" inside rules { ... } is equivalent to routing { final "<outbound>" }.
        std::string via_rule_final = replace(cfg, "    final \"direct\"\n}", "}");
        via_rule_final = replace(via_rule_final,
            "        - rule-set \"block-inline\" to=\"direct\"\n    }",
            "        - rule-set \"block-inline\" to=\"direct\"\n        - final \"direct\"\n    }");
        auto p_rule_final = config::parse_kdl(via_rule_final);
        require(p_rule_final.has_value() && p_rule_final->default_outbound_name == "direct",
            p_rule_final ? "" : "- final inside rules failed: " + p_rule_final.error());
        auto id1 = config::reload_identities(cfg);
        auto id2 = config::reload_identities(via_rule_final);
        require(id1 && id2 && id1->full == id2->full, "reload_identities parity: final vs - final");
    }

    // 2. Canonical DNS (default dial resolver, final fallback, rulesets, aligned child-predicate rules) +
    //    outbounds dial defaults + vless uuid-file sugar + inbounds single-instance default tags.
    auto test_dns_outbounds_inbounds_canonical() -> void {
        constexpr std::string_view cfg = R"kdl(schema-version 1
role "client"
certificate {
    ca-file "/tmp/global-ca.pem"
}
inbounds {
    tun {
        inet4-address "198.18.0.1/30"
        mtu 1400
    }
    socks5 {
        listen "127.0.0.1:1080"
        authentication "none"
    }
}
outbounds {
    auto-detect-interface #true
    interface "lo"
    mark 0x1234
    network-type "wifi"
    network-strategy "hybrid"
    direct
    block
    vless "edge" {
        server "edge.example.test:443"
        uuid-file "/tmp/vless.uuid"
        tls {
            server-name "edge.example.test"
            ca-file "/tmp/ca.pem"
            verify #true
        }
    }
}
http-clients {
    default "dl"
    dl {
        outbound "direct"
    }
}
dns {
    servers {
        udp "sys" host="127.0.0.1" port=5353
        udp "cn" host="127.0.0.1" port=5354
    }
    default "sys"
    rulesets {
        geosite-cn {
            url "https://example.com/geosite-cn.srs"
            format "srs"
        }
        high-purity path="rules/high-purity.kdl" format="kdl"
        corp-inline {
            domain-suffix "corp.local"
        }
    }
    rules {
        - action="predefined" rcode="noerror" {
            rule-set "geosite-cn" "high-purity"
            query-type "AAAA" "HTTPS" "SVCB"
        }
        - rule-set "corp-inline" to="cn"
    }
    final "sys"
}
routing {
    final "edge"
}
)kdl";
        auto parsed = config::parse_kdl(cfg);
        require(parsed.has_value(), parsed ? "" : "full canonical config failed: " + parsed.error());
        require(parsed->inbounds.size() == 2 &&
                parsed->inbounds[0].name == "tun" && parsed->inbounds[0].type == config::Inbound::tun &&
                parsed->inbounds[1].name == "socks5" && parsed->inbounds[1].type == config::Inbound::socks5,
            "single-instance 0-arg inbound default tags");
        require(parsed->defaults.auto_detect_interface && parsed->defaults.default_interface == "lo" &&
                parsed->defaults.default_mark == 0x1234u &&
                parsed->defaults.default_network_strategy.has_value() &&
                parsed->defaults.default_network_strategy->strategy == platform::network::Strategy::hybrid &&
                parsed->defaults.default_network_strategy->preferred == platform::network::Type::wifi,
            "outbounds dial defaults parsed cleanly");
        require(parsed->vless_outbounds.size() == 1 && parsed->vless_outbounds[0].config.uuid_file == "/tmp/vless.uuid" &&
                parsed->vless_outbounds[0].config.bootstrap_resolver == "sys",
            "vless direct uuid-file sugar + inherited dns.default");
        require(parsed->http_clients.size() == 1 && parsed->http_clients[0].ca_file == "/tmp/global-ca.pem" &&
                parsed->http_clients[0].resolver == "sys",
            "http-client inherited certificate.ca-file and dns.default");
        require(parsed->dns.has_value() && parsed->dns->rule_files.size() == 3, "dns rulesets parsed 3 entries");
        require(parsed->dns->rules.size() == 3, "dns expanded 2 rule-set predefined rules + 1 corp-inline rule");
        require(parsed->dns->rules[0].predefined && parsed->dns->rules[0].predefined->rcode == 0 &&
                parsed->dns->rules[1].predefined && parsed->dns->rules[1].predefined->rcode == 0,
            "dns child-predicate predefined rcode=noerror rules expanded cleanly");
    }

    // 3. Reload identity parity (rulesets inline props == child nodes), log_protected_paths, and -D path resolution.
    auto test_reload_identity_and_working_dir() -> void {
        std::string const prop_cfg = std::string(kCanonicalBase) + R"kdl(
log { sink "stderr"; }
routing {
    rulesets {
        blocked path="rules/blocked.kdl" format="kdl"
        my-direct {
            domain-suffix "example.local"
        }
    }
    rules {
        - rule-set "blocked" to="block"
        - rule-set "my-direct" to="direct"
    }
    final "direct"
}
)kdl";
        std::string const child_cfg = replace(prop_cfg,
            "        blocked path=\"rules/blocked.kdl\" format=\"kdl\"",
            "        blocked {\n            path \"rules/blocked.kdl\"\n            format \"kdl\"\n        }");

        auto id_prop = config::reload_identities(prop_cfg);
        auto id_child = config::reload_identities(child_cfg);
        require(id_prop && id_child, "reload_identities succeeded for prop & child-node rulesets");
        require(id_prop->full == id_child->full && id_prop->dns_policy == id_child->dns_policy &&
                id_prop->process == id_child->process && id_prop->tun_live == id_child->tun_live,
            "reload_identities byte-for-byte parity: inline props == child nodes");

        auto parsed_child = config::parse_kdl(child_cfg);
        require(parsed_child.has_value(), "child_cfg parses");
        require(std::ranges::contains(parsed_child->log_protected_paths, std::string("rules/blocked.kdl")),
            "log_protected_paths collects path from child-node rulesets block");

        auto tmp = std::filesystem::temp_directory_path() / "nexus_wave38_canonical_kdl_wd_test";
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
        std::filesystem::create_directories(tmp / "rules", ec);
        {
            std::ofstream out(tmp / "rules" / "blocked.kdl", std::ios::binary);
            out << "schema-version 2\nkind \"predicate\"\nrule type=\"domain-suffix\" value=\"blocked.example\"\n";
        }
        auto prev_wd = cli::working_directory();
        utility::scope_exit cleanup([&] {
            cli::restore_working_directory(prev_wd);
            std::filesystem::remove_all(tmp, ec);
        });
        cli::set_working_directory(tmp);
        auto loaded = cli::load_route_files(*parsed_child, "ignored.kdl");
        require(loaded.has_value() && !loaded->ordered.empty(),
            loaded ? "" : "-D load_route_files failed: " + loaded.error());
    }

    // 4. Strict zero-compat negative rejection tests: EVERY removed legacy form & invalid shape MUST fail!
    auto test_strict_legacy_rejections() -> void {
        auto wrap_routing = [&](std::string_view rbody) {
            return std::string(kCanonicalBase) + "routing {\n" + std::string(rbody) + "\n}\n";
        };
        std::pair<std::string, std::string_view> const rejected_cases[] = {
            // Removed legacy routing forms
            {wrap_routing(R"(default-outbound "direct")"), "routing default-outbound"},
            {wrap_routing(R"(default "direct")"), "routing default"},
            {wrap_routing(R"(rules { - default "direct"; })"), "routing rules - default"},
            {wrap_routing(R"(rule-set "a" path="a.kdl" format="kdl"; rules { - rule-set "a" to="direct"; }; final "direct")"), "routing bare rule-set"},
            {wrap_routing(R"(rulesets { - "a" path="a.kdl" format="kdl"; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "routing rulesets dash"},
            {wrap_routing(R"(rulesets { remote "a" url="https://example.com/a.srs" format="srs"; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "routing rulesets typed remote"},
            {wrap_routing(R"(rulesets { local "a" path="a.kdl" format="kdl"; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "routing rulesets typed local"},
            {wrap_routing(R"(rulesets { inline "a" { domain-suffix "a.local"; }; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "routing rulesets typed inline"},
            {wrap_routing(R"(rule-sets { a path="a.kdl" format="kdl"; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "routing rule-sets alias"},
            {wrap_routing(R"(default-http-client "dl"; final "direct")"), "routing default-http-client"},
            {wrap_routing(R"(default-domain-resolver "sys"; final "direct")"), "routing default-domain-resolver"},
            {wrap_routing(R"(default-interface "lo"; final "direct")"), "routing default-interface"},
            {wrap_routing(R"(default-mark 1; final "direct")"), "routing default-mark"},
            {wrap_routing(R"(default-network-strategy "hybrid"; final "direct")"), "routing default-network-strategy"},
            {wrap_routing(R"(default-network-type "wifi"; final "direct")"), "routing default-network-type"},
            {wrap_routing(R"(auto-detect-interface #true; final "direct")"), "routing auto-detect-interface"},
            {wrap_routing(R"(rules { - final "direct"; }; final "direct")"), "duplicate final in routing & rules"},
            // Malformed rulesets shapes
            {wrap_routing(R"(rulesets { a path="a.kdl" { path "b.kdl"; format "kdl"; }; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "duplicate prop + child path"},
            {wrap_routing(R"(rulesets { a { path "a.kdl"; path "b.kdl"; format "kdl"; }; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "duplicate child path"},
            {wrap_routing(R"(rulesets { a { url "https://example.com/a.srs"; format "srs"; domain-suffix "x.local"; }; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "mixed url + inline predicate"},
            {wrap_routing(R"(rulesets { a path="a.kdl" format="kdl"; }; rulesets { b path="b.kdl" format="kdl"; }; rules { - rule-set "a" to="direct"; - rule-set "b" to="direct"; }; final "direct")"), "duplicate rulesets blocks"},
            {wrap_routing(R"(rulesets { (tag)a path="a.kdl" format="kdl"; }; rules { - rule-set "a" to="direct"; }; final "direct")"), "type-tagged ruleset node"},
            {wrap_routing(R"(rulesets { foo "bar" path="a.kdl" format="kdl"; }; rules { - rule-set "bar" to="direct"; }; final "direct")"), "extra positional arg in rulesets"},
            // Removed legacy http-clients { client "x" { ... } }
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; }
dns { servers { udp "sys" host="127.0.0.1" port=5353; }; final "sys"; }
http-clients { client "dl" { outbound "direct"; domain-resolver "sys"; ca-file "/tmp/ca.pem"; }; }
routing { final "direct"; }
)kdl", "http-clients client wrapper"},
            // Removed legacy dns { rule-set / rule-sets / domain-resolver }
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; }
dns { servers { udp "sys" host="127.0.0.1" port=5353; }; rule-set "a" path="a.kdl" format="kdl"; rules { - rule-set "a" to="sys"; }; final "sys"; }
routing { final "direct"; }
)kdl", "dns bare rule-set"},
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; }
dns { servers { udp "sys" host="127.0.0.1" port=5353; }; rule-sets { a path="a.kdl" format="kdl"; }; rules { - rule-set "a" to="sys"; }; final "sys"; }
routing { final "direct"; }
)kdl", "dns rule-sets alias"},
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; }
dns { servers { udp "sys" host="127.0.0.1" port=5353; }; domain-resolver "sys"; final "sys"; }
routing { final "direct"; }
)kdl", "dns legacy domain-resolver"},
            // Removed default-* prefixes in outbounds
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { default-interface "lo"; direct; }
routing { final "direct"; }
)kdl", "outbounds default-interface"},
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { default-mark 1; direct; }
routing { final "direct"; }
)kdl", "outbounds default-mark"},
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { default-network-strategy "hybrid"; direct; }
routing { final "direct"; }
)kdl", "outbounds default-network-strategy"},
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { default-network-type "wifi"; direct; }
routing { final "direct"; }
)kdl", "outbounds default-network-type"},
            // Duplicate single-instance default inbound tag
            {R"kdl(schema-version 1
role "client"
inbounds {
    tun { inet4-address "198.18.0.1/30"; mtu 1400; }
    tun { inet4-address "198.18.0.5/30"; mtu 1400; }
}
outbounds { direct; }
routing { final "direct"; }
)kdl", "duplicate 0-arg tun inbound"},
            // Duplicate vless uuid-file + authentication
            {R"kdl(schema-version 1
role "client"
inbounds { socks5 { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds {
    direct
    vless "v" {
        server "127.0.0.1:443"
        uuid-file "/tmp/a"
        authentication { uuid-file "/tmp/b"; }
        tls { server-name "a.test"; ca-file "/tmp/ca.pem"; verify #true; }
    }
}
routing { final "v"; }
)kdl", "duplicate vless uuid-file and authentication"},
        };

        for (auto const& [kdl, label] : rejected_cases) {
            auto r = config::parse_kdl(kdl);
            require(!r.has_value(), std::string("legacy/invalid case unexpectedly accepted: ") + std::string(label));
        }
    }
}

int main() {
    test_canonical_routing_and_rulesets();
    test_dns_outbounds_inbounds_canonical();
    test_reload_identity_and_working_dir();
    test_strict_legacy_rejections();
    std::println("Wave 38 strict canonical KDL 2.0 unit tests passed");
    return 0;
}
