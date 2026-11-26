import std;
import rules;

namespace {
    using namespace ::rules;
    int failures = 0;

    auto check(bool passed, std::string_view description) -> void {
        if (!passed) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
    }

    struct Case {
        MatchInput input;
        std::optional<std::size_t> expected;
        std::string_view label;
    };

    auto run_cases(Matcher const& matcher, std::vector<Case> const& cases) -> void {
        for (auto const& test : cases) {
            auto result = matcher.match(test.input);
            check(result && *result == test.expected, test.label);
        }
    }
}

int main() {
    constexpr auto source = R"(schema-version 2
kind "predicate"
rule type="ip-cidr" value="10.123.45.67/8"
rule type="domain-suffix" value="Example.COM"
rule type="domain-suffix" value="sub.example.com"
rule type="ip-cidr" value="2001:db8:1234::1/32"
rule type="ip-cidr" value="0.0.0.0/0"
rule type="ip-cidr" value="::/0"
)";
    auto set = parse_kdl(source);
    check(bool(set), "parse source rules");
    if (!set) return 1;
    auto matcher = Matcher::compile(*set);
    check(bool(matcher), "compile source rules");
    if (!matcher) return 1;

    std::vector<Case> cases{
        {{"example.com", {}}, 1, "exact suffix matches"},
        {{"SuB.ExAmPlE.cOm", {}}, 1, "first matching suffix wins over a later, longer suffix"},
        {{"badexample.com", {}}, {}, "suffix requires a label boundary"},
        {{"example.com.evil", {}}, {}, "suffix cannot occur in the middle"},
        {{{}, "10.0.0.1"}, 0, "IPv4 prefix ignores host bits"},
        {{"example.com", "10.10.10.10"}, 0, "first match wins across predicate kinds"},
        {{{}, "192.0.2.1"}, 4, "IPv4 /0 matches"},
        {{{}, "2001:DB8:ffff::1"}, 3, "IPv6 prefix matches case-insensitive notation"},
        {{{}, "2001:db9::1"}, 5, "IPv6 /0 matches outside earlier prefix"},
        {{{}, "::ffff:10.0.0.1"}, 5, "IPv4-mapped IPv6 remains an IPv6 address"},
        {{{}, {}}, {}, "missing fields do not match"},
    };
    run_cases(*matcher, cases);
    auto binary = write_beve(*set);
    check(bool(binary), "encode source rules");
    if (binary) {
        auto decoded = parse_beve(*binary);
        check(bool(decoded), "decode source rules");
        if (decoded) {
            auto binary_matcher = Matcher::compile(*decoded);
            check(bool(binary_matcher), "compile decoded rules");
            if (binary_matcher) run_cases(*binary_matcher, cases);
        }
    }
    check(!matcher->match({"bad..example", {}}), "invalid domain rejected");
    {
        auto fqdn = matcher->match({"example.com.", {}});
        check(fqdn && *fqdn == std::optional<std::size_t>{1}, "trailing FQDN dot normalized");
    }
    check(!matcher->match({"example.com..", {}}), "double trailing dot rejected");
    check(!matcher->match({std::string_view("a\0b", 3), {}}), "embedded NUL in domain rejected");
    check(!matcher->match({{}, "10.0.0.1/8"}), "CIDR is not an address query");
    check(!matcher->match({{}, "fe80::1%eth0"}), "IPv6 zone identifier rejected");
    check(!matcher->match({"example.com", "not-an-ip"}), "invalid supplied IP rejected even when domain matches");
    check(!Matcher::compile(RuleSet{{Rule{"ip-cidr", "10.0.0.1/33"}}}), "invalid source rule cannot compile");

    auto boundary = Matcher::compile(RuleSet{{
        {"ip-cidr", "192.0.2.3/31"}, {"ip-cidr", "198.51.100.1/32"},
        {"ip-cidr", "2001:db8::3/127"}, {"ip-cidr", "2001:db8:1::1/128"}
    }});
    check(bool(boundary), "compile prefix boundary rules");
    if (boundary) run_cases(*boundary, {
        {{{}, "192.0.2.2"}, 0, "IPv4 /31 lower boundary"},
        {{{}, "192.0.2.3"}, 0, "IPv4 /31 upper boundary"},
        {{{}, "192.0.2.4"}, {}, "IPv4 outside /31"},
        {{{}, "198.51.100.1"}, 1, "IPv4 /32 exact"},
        {{{}, "198.51.100.2"}, {}, "IPv4 outside /32"},
        {{{}, "2001:db8::2"}, 2, "IPv6 /127 lower boundary"},
        {{{}, "2001:db8::3"}, 2, "IPv6 /127 upper boundary"},
        {{{}, "2001:db8::4"}, {}, "IPv6 outside /127"},
        {{{}, "2001:db8:1::1"}, 3, "IPv6 /128 exact"},
        {{{}, "2001:db8:1::2"}, {}, "IPv6 outside /128"},
    });
    std::vector<RouteRule> routes{
        {RuleSet{{{"domain-suffix","example.com"},{"ip-cidr","10.0.0.0/8"}}},1},
        {RuleSet{{{"domain-suffix","sub.example.com"},{"ip-cidr","2001:db8::/32"}}},2}
    };
    auto routing=RouteMatcher::compile(routes,0,3);
    check(bool(routing),"compile route actions");
    if (routing) {
        check(routing->match({"sub.example.com",{}})==1,"first route wins for overlapping domains");
        check(routing->match({{},"10.1.2.3"})==1,"multiple predicates share an action");
        check(routing->match({{},"2001:db8::1"})==2,"IPv6 route action");
        check(routing->match({{},"192.0.2.1"})==0,"route default");
        check(!routing->match({"bad..name",{}}),"route rejects invalid input");
    }
    std::vector<RouteRule> mapped_rules{
        {RuleSet{{{"ip-cidr","10.0.0.0/8"}}},1},
        {RuleSet{{{"ip-cidr","::ffff:0:0/96"}}},2},
        {RuleSet{{{"domain-suffix","example.com"}}},0}
    };
    auto mapped_routing=RouteMatcher::compile(mapped_rules,0,3);
    check(mapped_routing && mapped_routing->match({"example.com","::ffff:10.1.2.3"})==1,
          "mapped IPv4 rule precedes matching IPv6 and domain rules");
    check(mapped_routing && mapped_routing->match({"example.com","::ffff:192.0.2.1"})==2,
          "mapped IPv6 rule precedes domain rule");
    std::swap(mapped_rules[0],mapped_rules[1]);
    mapped_routing=RouteMatcher::compile(mapped_rules,0,3);
    check(mapped_routing && mapped_routing->match({{},"::ffff:10.1.2.3"})==2,
          "mapped family match follows configuration order");
    check(mapped_routing && !mapped_routing->match({"bad..name","::ffff:10.1.2.3"}),
          "mapped target still validates domain");
    auto pre_ip=RouteMatcher::compile(mapped_rules,0,3);
    check(pre_ip && pre_ip->preflight("example.com") && !*pre_ip->preflight("example.com"),
          "earlier IP rule requires resolution before domain action");
    check(pre_ip && pre_ip->preflight("other.test") && !*pre_ip->preflight("other.test"),
          "IP rule requires resolution before default action");
    std::vector<RouteRule> pre_domains{
        {RuleSet{{{"domain-suffix","example.com"}}},1},
        {RuleSet{{{"ip-cidr","10.0.0.0/8"}}},2}
    };
    auto pre_domain=RouteMatcher::compile(pre_domains,0,3);
    check(pre_domain && pre_domain->preflight("www.example.com") && *pre_domain->preflight("www.example.com")==std::optional<std::size_t>(1),
          "earlier domain action is final without IP");
    check(pre_domain && pre_domain->preflight("other.test") && !*pre_domain->preflight("other.test"),
          "unmatched domain does not bypass later IP rule");
    check(pre_domain && !pre_domain->preflight("bad..name"),"preflight validates domain");
    std::vector<RouteRule> same_action{{RuleSet{{{"ip-cidr","10.0.0.0/8"},{"domain-suffix","blocked.test"}}},1}};
    auto same=RouteMatcher::compile(same_action,0,2);
    auto early=same->preflight("blocked.test");
    check(early && *early && **early==1,"same-action IP predicate preserves early domain block");
    auto no_rules=RouteMatcher::compile({},0,1);
    check(no_rules && no_rules->match({{},"::1"})==0 && no_rules->preflight("example.com") && *no_rules->preflight("example.com")==std::optional<std::size_t>(0),"empty routing uses default");
    check(!RouteMatcher::compile({},0,0),"empty outbound table rejected");
    check(!RouteMatcher::compile(routes,3,3),"invalid default action rejected");
    routes[1].outbound=3;
    check(!RouteMatcher::compile(routes,0,3),"invalid rule action rejected");
    routes[1].outbound=2; routes[1].predicates.rules.clear();
    check(!RouteMatcher::compile(routes,0,3),"empty predicate set rejected");

    // Multi-holder socket sharing: process-name, process-path, process-path-regex match if ANY candidate matches.
    {
        RuleSet proc_rules{{
            {"process-name", "curl"},
            {"process-path", "/opt/browser/helper"},
            {"process-path-regex", "^/usr/local/bin/worker-[0-9]+$"},
        }};
        auto pm = Matcher::compile(proc_rules);
        check(bool(pm), "compile multi-holder process matcher");
        if (pm) {
            std::array<std::string, 2> shared_curl{"/usr/bin/wrapper", "/usr/bin/curl"};
            MatchInput m_curl{};
            m_curl.process_path = shared_curl[0];
            m_curl.process_paths = std::span<std::string const>(shared_curl);
            auto r_curl = pm->match(m_curl);
            check(r_curl && *r_curl == std::optional<std::size_t>(0), "process-name matches second holder");

            std::array<std::string, 2> shared_path{"/usr/bin/wrapper", "/opt/browser/helper"};
            MatchInput m_path{};
            m_path.process_paths = std::span<std::string const>(shared_path);
            auto r_path = pm->match(m_path);
            check(r_path && *r_path == std::optional<std::size_t>(1), "process-path matches second holder without single process_path");

            std::array<std::string, 2> shared_rx{"/usr/bin/wrapper", "/usr/local/bin/worker-42"};
            MatchInput m_rx{};
            m_rx.process_paths = std::span<std::string const>(shared_rx);
            auto r_rx = pm->match(m_rx);
            check(r_rx && *r_rx == std::optional<std::size_t>(2), "process-path-regex matches second holder");

            std::array<std::string, 2> miss{"/usr/bin/wrapper", "/usr/bin/other"};
            MatchInput m_miss{};
            m_miss.process_paths = std::span<std::string const>(miss);
            auto r_miss = pm->match(m_miss);
            check(r_miss && !*r_miss, "unmatched multi-holder candidates return no match");

            MatchInput single_compat{};
            single_compat.process_path = "/usr/bin/curl";
            auto r_single = pm->match(single_compat);
            check(r_single && *r_single == std::optional<std::size_t>(0), "legacy single process_path remains backwards compatible");

            std::vector<std::string> too_many(65, "/usr/bin/a");
            MatchInput m_over{};
            m_over.process_paths = std::span<std::string const>(too_many);
            check(!pm->match(m_over), "more than 64 process_paths rejected");
        }

        std::vector<ProgramRule> prog_rules{
            {RuleSet{{{"process-name", "worker"}}}, {ProgramActionKind::route, 1}},
            {RuleSet{{{"process-path-regex", "^/opt/app/bin/.*"}}}, {ProgramActionKind::route, 2}},
        };
        auto prog = RouteProgram::compile(prog_rules, 3);
        check(bool(prog), "compile RouteProgram with process predicates");
        if (prog) {
            std::array<std::string, 2> holders{"/usr/bin/launcher", "/opt/app/bin/agent"};
            ProgramInput pin{.port = 443, .network = Network::tcp, .process_path = holders[0],
                .process_paths = std::span<std::string const>(holders)};
            auto step = prog->next(pin);
            check(step && *step && (*step)->action.outbound == 2, "RouteProgram propagates process_paths to matcher");
        }
    }

    if (!failures) std::cout << "Rule matcher tests passed\n";
    return failures ? 1 : 0;
}
