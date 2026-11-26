import std;
import rules;
import rules.rule_input;
import rules.convert_external;
import rules.srs_payload;

namespace {
    int failures = 0;
    auto check(bool ok, std::string_view msg) -> void {
        if (!ok) {
            ++failures;
            std::cerr << "FAIL: " << msg << '\n';
        }
    }
}

int main() {
    using namespace rules;
    // 1. Scale above old 16,384 ceiling & uint16 child index (70,000 rules in a single compound OR + top-level list).
    {
        RuleSet big;
        big.version = 2;
        Rule compound{"or", {}, {}};
        compound.children.reserve(70001);
        for (unsigned i = 0; i < 50000; ++i) {
            compound.children.push_back({"domain-suffix", std::format("zone{}.bench.test", i), {}});
        }
        for (unsigned i = 0; i < 20000; ++i) {
            compound.children.push_back({"ip-cidr", std::format("10.{}.{}.0/24", (i >> 8) & 0xffu, i & 0xffu), {}});
        }
        compound.children.push_back({"port", "8443", {}});
        big.rules.push_back(std::move(compound));

        auto matcher = Matcher::compile(big);
        check(bool(matcher), "70,001-child OR rule-set compiles past 16K/65K ceiling");
        if (matcher) {
            auto d = matcher->match_truth_mapped({.domain = "sub.zone49999.bench.test"});
            auto ip = matcher->match_truth_mapped({.ip = "10.78.31.9"});
            auto port = matcher->match_truth_mapped({.port = 8443});
            auto miss = matcher->match_truth_mapped({.domain = "miss.test", .ip = "198.51.100.1", .port = 80});
            check(d && *d == Matcher::Truth::yes, "70K OR matches 49,999th domain suffix");
            check(ip && *ip == Matcher::Truth::yes, "70K OR matches 19,999th CIDR");
            check(port && *port == Matcher::Truth::yes, "70K OR matches last remainder port");
            check(miss && *miss == Matcher::Truth::no, "70K OR misses unrelated input");
        }

        // > 2 MiB BEVE roundtrip
        auto beve = write_beve(big);
        check(bool(beve) && beve->size() > 2u * 1024u * 1024u, "BEVE output > 2 MiB succeeds");
        if (beve) {
            auto parsed = parse_beve(*beve);
            check(parsed && *parsed == big, "BEVE > 2 MiB roundtrip");
        }
    }

    // 2. JSON rule-set conversion (strict & lenient)
    {
        constexpr std::string_view jsrc = R"({
            "version": 3,
            "rules": [
                {"domain": ["Exact.Test"], "domain_suffix": [".only.example", "root.example"], "ip_cidr": "192.0.2.0/24"},
                {"type": "logical", "mode": "and", "rules": [{"network": "tcp"}, {"port_range": "8000:9000"}], "invert": true}
            ]
        })";
        auto js = parse_rule_input(jsrc, InputFormat::json);
        check(bool(js) && js->rules.size() == 2, "JSON rule-set parses");
        if (js) {
            auto m = Matcher::compile(*js);
            check(bool(m), "converted JSON compiles");
            if (m) {
                check(m->match({.domain = "exact.test"}).value() == std::optional<std::size_t>{0}, "JSON domain match");
                check(m->match({.domain = "sub.only.example"}).value() == std::optional<std::size_t>{0}, "JSON subdomain match");
                check(!m->match({.domain = "only.example"}).value().has_value(), "JSON leading-dot excludes apex");
                check(m->match({.ip = "192.0.2.55"}).value() == std::optional<std::size_t>{0}, "JSON ip_cidr match");
                check(!m->match({.port = 8080, .network = Network::tcp}).value().has_value(), "JSON inverted logical excludes tcp:8080");
                check(m->match({.port = 80, .network = Network::tcp}).value() == std::optional<std::size_t>{1}, "JSON inverted logical matches tcp:80");
            }
        }
        constexpr std::string_view jlenient = R"({
            "version": 3,
            "rules": [
                {"future_unsupported_field": "x"},
                {"domain_suffix": ["Example.NET"], "future_extra": 123}
            ]
        })";
        check(!parse_rule_input(jlenient, InputFormat::json, false, false), "strict JSON rejects unknown fields");
        auto jl = parse_rule_input(jlenient, InputFormat::json, false, true);
        check(jl && jl->rules.size() == 1 && jl->rules[0].value == "example.net", "lenient JSON drops unsupported rules");
    }

    // 3. Domain list, IP CIDR list, Classical YAML list, AdGuard & Merge
    {
        auto doms = parse_rule_input("payload:\n  - '+.Alpha.Test'\n  - 'full:Beta.Test'\n  - '.sub.Test'\n", InputFormat::domain_list);
        check(doms && doms->rules.size() == 3, "YAML domain-list parses");
        auto cidrs = parse_rule_input("# v4 and v6\n192.0.2.10\n2001:db8::/32\n", InputFormat::ipcidr_list);
        check(cidrs && cidrs->rules.size() == 2 && cidrs->rules[0].value == "192.0.2.10/32", "IP CIDR list normalizes bare IP");
        auto cls = parse_rule_input("payload:\n  - 'DOMAIN-SUFFIX,Gamma.Test,no-resolve'\n  - 'IP-CIDR,198.51.100.0/24,no-resolve'\n  - 'GEOIP,CN,no-resolve'\n",
            InputFormat::classical, false, true);
        check(cls && cls->rules.size() == 2, "lenient classical YAML skips GEOIP");
        auto adg = parse_rule_input("! title\n||ads.example^\n|tracker.example^\n@@||good.ads.example^\n", InputFormat::adguard);
        check(bool(adg), "AdGuard filter converts with exceptions");
        if (adg) {
            auto m = Matcher::compile(*adg);
            check(bool(m), "AdGuard filter compiles");
            if (m) {
                check(bool(*m->match({.domain = "x.ads.example"})), "AdGuard blocks subdomain");
                check(!*m->match({.domain = "good.ads.example"}), "AdGuard exception allows");
            }
        }
        std::array<RuleSet, 3> to_merge{*doms, *cidrs, *cls};
        auto merged = merge_rule_sets(to_merge);
        check(merged && merged->rules.size() == 7, "merge deduplicates cleanly");
    }

    // 4. SRS v3 item 19 (network_is_expensive) decoded in both modes + lenient uppercase normalization
    {
        std::vector<std::uint8_t> srs{
            2, // 2 rules
            0, 19, 255, 0, // rule 0: network_is_expensive
            0, 3, 1, 3, 'D', 'N', 'S', 19, 255, 0 // rule 1: uppercase keyword "DNS" + network_is_expensive
        };
        check(!decode_srs_payload(srs, false, false), "strict SRS still rejects uppercase keyword");
        auto ok = decode_srs_payload(srs, false, true);
        check(ok && ok->rules.size() == 2 && ok->rules[0].type == "network-is-expensive", "lenient SRS lowercases & decodes item 19");
    }

    if (!failures) std::cout << "Batch 163 rule-set scale & conversion tests passed\n";
    return failures ? 1 : 0;
}
