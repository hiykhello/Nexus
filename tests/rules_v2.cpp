import std;
import rules;

namespace {
    using namespace ::rules;
    unsigned failures=0;
    auto check(bool value,std::string_view label) -> void {
        if (!value) { ++failures; std::cerr << "FAIL: " << label << '\n'; }
    }
    auto parse(std::string_view body) -> std::expected<RuleSet,Error> {
        return parse_kdl(std::string("schema-version 2\nkind \"predicate\"\n")+std::string(body));
    }
}

auto main() -> int {
    using namespace ::rules;
    auto auth_rules=parse("rule type=\"and\" { rule type=\"auth-user\" value=\"Alice\"; rule type=\"network\" value=\"tcp\"; }\nrule type=\"not\" { rule type=\"auth-user\" value=\"Other\"; }");
    check(bool(auth_rules),"parse authenticated user predicates");
    if (auth_rules) {
        auto encoded=write_beve(*auth_rules);
        auto decoded=encoded ? parse_beve(*encoded) : std::expected<RuleSet,Error>{std::unexpected(Error{ErrorCode::schema,"encode"})};
        check(decoded && *decoded==*auth_rules,"authenticated user BEVE roundtrip");
        auto text=write_kdl(*auth_rules);
        auto text_decoded=text ? parse_kdl(*text) : std::expected<RuleSet,Error>{std::unexpected(Error{ErrorCode::schema,"encode"})};
        check(text_decoded && *text_decoded==*auth_rules,"authenticated user KDL roundtrip");
        auto matcher=Matcher::compile(*auth_rules);
        if (matcher) {
            auto unknown=matcher->match({.network=Network::tcp});
            auto exact=matcher->match({.network=Network::tcp,.auth_user="Alice"});
            auto other=matcher->match({.network=Network::tcp,.auth_user="alice"});
            check(unknown && !*unknown && exact && *exact==std::optional<std::size_t>(0) &&
                  other && *other==std::optional<std::size_t>(1),"authenticated user case and unknown under NOT");
            check(!matcher->match({.auth_user=""}),"empty authenticated user input rejected");
            Matcher copy=*matcher; *matcher=Matcher{};
            auto copied=copy.match({.network=Network::tcp,.auth_user="Alice"});
            check(copied && *copied==std::optional<std::size_t>(0),"authenticated user survives matcher copy");
        } else check(false,"compile authenticated user matcher");
        std::array routes{ProgramRule{*auth_rules,{ProgramActionKind::route,1}}};
        check(!RouteProgram::compile_policy(routes,0,2),"route without authenticated user metadata rejected");
        auto route=RouteProgram::compile_policy(routes,0,2,SourceMetadata::provided,{},AuthMetadata::provided);
        if (route) {
            auto unknown=route->preflight({.domain="example.test",.network=Network::tcp});
            auto known=route->preflight({.domain="example.test",.network=Network::tcp,.auth_user="Alice"});
            auto absent=route->match({.network=Network::tcp});
            check(route->needs_auth_user() && unknown && !*unknown && known && *known==std::optional<std::size_t>(1) &&
                  absent && *absent==0,"authenticated user preflight and unknown route");
        } else check(false,"compile authenticated user route");
        ProgramRule instruction{*auth_rules,{ProgramActionKind::reject}};
        auto program=RouteProgram::compile(std::span(&instruction,1),2);
        if (program) {
            auto unknown=program->next({.network=Network::tcp});
            auto known=program->next({.network=Network::tcp,.auth_user="Alice"});
            check(unknown && !*unknown && known && known->has_value(),"program forwards authenticated user context");
        } else check(false,"compile authenticated user program");
    }
    check(!parse("rule type=\"auth-user\" value=\"\"") &&
          !Matcher::compile(RuleSet{{{"auth-user",std::string(256,'x')}},2}),"invalid authenticated user names rejected");
    check(!parse_kdl("schema-version 1\nkind \"predicate\"\nrule type=\"auth-user\" value=\"alice\""),
          "authenticated user requires schema v2");
    auto inbound_rules=parse("rule type=\"inbound\" value=\"Edge\"\nrule type=\"not\" { rule type=\"inbound\" value=\"Other\"; }");
    check(bool(inbound_rules),"parse inbound predicates");
    if (inbound_rules) {
        auto text=write_kdl(*inbound_rules);
        auto text_decoded=text ? parse_kdl(*text) : std::expected<RuleSet,Error>{std::unexpected(Error{ErrorCode::schema,"encode"})};
        check(text_decoded && *text_decoded==*inbound_rules,"inbound KDL roundtrip");
        auto encoded=write_beve(*inbound_rules);
        auto decoded=encoded ? parse_beve(*encoded) : std::expected<RuleSet,Error>{std::unexpected(Error{ErrorCode::schema,"encode"})};
        check(decoded && *decoded==*inbound_rules,"inbound BEVE roundtrip");
        auto matcher=Matcher::compile(*inbound_rules);
        if (matcher) {
            auto unknown=matcher->match({}), exact=matcher->match({.inbound="Edge"});
            auto other=matcher->match({.inbound="edge"});
            check(unknown && !*unknown && exact && *exact==std::optional<std::size_t>(0) &&
                  other && *other==std::optional<std::size_t>(1),"inbound case and unknown under NOT");
            Matcher copy=*matcher; *matcher=Matcher{};
            check(copy.match({.inbound="Edge"})->value_or(99)==0,"inbound text survives matcher copy");
        } else check(false,"compile inbound matcher");
        std::array routes{ProgramRule{*inbound_rules,{ProgramActionKind::route,1}}};
        check(!RouteProgram::compile_policy(routes,0,2),"unbound inbound route rejected");
        auto route=RouteProgram::compile_policy(routes,0,2,SourceMetadata::provided,"Edge");
        if (route) {
            auto copy=*route;
            auto match=copy.match({}); auto preflight=copy.preflight({.domain="example.test"});
            check(match && *match==1 && preflight && *preflight==std::optional<std::size_t>(1),"bound inbound route survives copy");
            check(!copy.match({.inbound="Other"}),"conflicting inbound rejected");
        } else check(false,"compile bound inbound route");
        ProgramRule instruction{*inbound_rules,{ProgramActionKind::reject}};
        auto program=RouteProgram::compile(std::span(&instruction,1),2);
        if (program) {
            auto unknown=program->next({}), known=program->next({.inbound="Edge"});
            check(unknown && !*unknown && known && known->has_value(),"program forwards inbound context");
        } else check(false,"compile inbound program");
    }
    auto long_inbound=Matcher::compile(RuleSet{{{"inbound",std::string(255,'x')}},2});
    auto long_encoded=write_beve(RuleSet{{{"inbound",std::string(255,'x')}},2});
    check(long_inbound && long_encoded && parse_beve(*long_encoded),"255-byte inbound roundtrip");
    check(!Matcher::compile(RuleSet{{{"inbound",std::string(256,'x')}},2}) &&
          !parse("rule type=\"inbound\" value=\"\""),"invalid inbound names rejected");
    auto set=parse(R"(rule type="and" {
 rule type="domain-suffix" value="Example.COM"
 rule type="port-range" value="443-445"
 rule type="network" value="tcp"
}
rule type="or" {
 rule type="domain" value="Exact.Example"
 rule type="not" { rule type="ip-cidr" value="10.0.0.0/8"; }
}
)");
    check(set && set->version==2 && set->rules.size()==2,"parse nested v2 rules");
    if (!set) return 1;
    check(set->rules[0].children[0].value=="example.com","normalize nested domain");
    auto text=write_kdl(*set);
    auto text_roundtrip=text ? parse_kdl(*text) : std::expected<RuleSet,Error>{std::unexpected(Error{ErrorCode::syntax,"write"})};
    check(text_roundtrip && *text_roundtrip==*set,"nested KDL roundtrip");
    auto binary=write_beve(*set);
    auto decoded=binary ? parse_beve(*binary) : std::expected<RuleSet,Error>{std::unexpected(Error{ErrorCode::syntax,"write"})};
    check(decoded && *decoded==*set,"nested BEVE roundtrip");
    if (binary) {
        auto truncated=*binary; truncated.pop_back();
        check(!parse_beve(truncated),"truncated nested BEVE rejected");
    }
    auto matcher=Matcher::compile(*set);
    check(bool(matcher),"compile nested rules");
    if (matcher) {
        auto is=[&](MatchInput input,std::optional<std::size_t> expected) {
            auto result=matcher->match(input); return result && *result==expected;
        };
        check(is({.domain="www.EXAMPLE.com",.port=443,.network=Network::tcp},0),"AND matches all known fields");
        check(is({.domain="www.example.com",.port=445,.network=Network::tcp},0),"port range upper endpoint");
        check(is({.domain="www.example.com",.port=446,.network=Network::tcp},{}),"port outside range");
        check(is({.domain="www.example.com",.port=443,.network=Network::udp},{}),"network mismatch");
        check(is({.domain="exact.example"},1),"OR short-circuits known match");
        check(is({.domain="other.example"},{}),"NOT of unknown IP stays unknown");
        check(is({.ip="192.0.2.1"},1),"NOT of known nonmatching IP");
        check(is({.ip="10.2.3.4"},{}),"NOT of matching IP");
        check(!matcher->match({.domain="bad..name",.port=443,.network=Network::tcp}),"invalid supplied domain rejected");
        check(!matcher->match({.port=0}),"zero destination port rejected");
        check(!matcher->match({.network=static_cast<Network>(7)}),"unknown network rejected");
    }
    auto domain_patterns=parse(R"(rule type="domain-keyword" value="Track"
rule type="domain-wildcard" value="*.Example.COM"
rule type="domain" value="exact.example.com"
rule type="domain-suffix" value="elsewhere.test"
rule type="not" { rule type="domain-keyword" value="safe"; }
)");
    check(bool(domain_patterns),"parse domain keyword and wildcard");
    if (domain_patterns) {
        auto text_patterns=write_kdl(*domain_patterns);
        auto binary_patterns=write_beve(*domain_patterns);
        if (text_patterns) { auto roundtrip=parse_kdl(*text_patterns); check(roundtrip && *roundtrip==*domain_patterns,"domain patterns KDL roundtrip"); }
        else check(false,"domain patterns KDL encoding");
        if (binary_patterns) { auto roundtrip=parse_beve(*binary_patterns); check(roundtrip && *roundtrip==*domain_patterns,"domain patterns BEVE roundtrip"); }
        else check(false,"domain patterns BEVE encoding");
        auto patterns=Matcher::compile(*domain_patterns);
        check(bool(patterns),"compile domain patterns");
        if (patterns) {
            auto is=[&](MatchInput input,std::optional<std::size_t> expected) {
                auto result=patterns->match(input); return result && *result==expected;
            };
            check(is({.domain="x.TRACK.example.com"},0),"keyword is case insensitive and wins in order");
            check(is({.domain="Exact.Example.Com"},1),"wildcard matches one label before later exact rule");
            check(is({.domain="a.b.example.com"},4),"wildcard does not match multiple labels");
            check(is({.domain="example.com"},4),"wildcard does not match its base");
            check(is({.domain="safe.example.net"},{}),"keyword and NOT reject nonmatching and matching respectively");
            check(is({},{}),"missing domain remains unknown under NOT");
            Matcher copied=*patterns; *patterns=Matcher{};
            auto copied_match=copied.match({.domain="track.example"});
            check(copied_match && *copied_match==std::optional<std::size_t>(0),"copied keyword storage remains valid");
        }
    }
    for (auto invalid:{"rule type=\"domain-keyword\" value=\"\"", "rule type=\"domain-keyword\" value=\"ab_cd\"",
                       "rule type=\"domain-wildcard\" value=\"foo.*.example\"", "rule type=\"domain-wildcard\" value=\"*.bad..example\""})
        check(!parse(invalid),"invalid domain pattern rejected");
    check(!parse_kdl("schema-version 1\nkind \"predicate\"\nrule type=\"domain-keyword\" value=\"test\""),
          "new predicates rejected in schema v1");
    std::mt19937 keyword_random(0x27ab);
    for (unsigned trial=0;trial<1000;++trial) {
        std::string name,keyword;
        for (unsigned i=0,n=keyword_random()%63+1;i<n;++i) name+=static_cast<char>('a'+keyword_random()%3);
        for (unsigned i=0,n=keyword_random()%24+1;i<n;++i) keyword+=static_cast<char>('a'+keyword_random()%3);
        auto expected=name.find(keyword)!=std::string::npos;
        auto candidate=Matcher::compile(RuleSet{{{"domain-keyword",keyword,{}}},2});
        if (!candidate) { check(false,"compile random keyword"); break; }
        for (auto& c:name) if (keyword_random()%2) c=static_cast<char>(c-('a'-'A'));
        auto actual=candidate->match({.domain=name});
        if (!actual || bool(*actual)!=expected) { check(false,"keyword matches independent substring model"); break; }
    }
    auto version_rules=parse("rule type=\"ip-version\" value=\"4\"\nrule type=\"ip-version\" value=\"6\"");
    check(bool(version_rules),"parse IP version rules");
    if (version_rules) {
        auto encoded=write_beve(*version_rules);
        if (encoded) { auto decoded=parse_beve(*encoded); check(decoded && *decoded==*version_rules,"IP version BEVE roundtrip"); }
        else check(false,"IP version BEVE encoding");
        auto versions=Matcher::compile(*version_rules);
        if (versions) {
            auto v4=versions->match({.ip="192.0.2.1"}), v6=versions->match({.ip="2001:db8::1"});
            auto mapped_version=versions->match_mapped({.ip="::ffff:192.0.2.1"});
            auto unknown=versions->match({});
            check(v4 && *v4==std::optional<std::size_t>(0) && v6 && *v6==std::optional<std::size_t>(1) &&
                  mapped_version && *mapped_version==std::optional<std::size_t>(1) && unknown && !*unknown,
                  "IP version uses supplied address family, including mapped IPv6");
        } else check(false,"compile IP version rules");
        auto policy=RouteProgram::compile_policy(std::vector<ProgramRule>{{*version_rules,{ProgramActionKind::route,1}}},0,2);
        if (policy) {
            auto preflight=policy->preflight({.domain="example.test"});
            check(preflight && !*preflight,"IP version delays route until address is known");
        } else check(false,"compile IP version route");
    }
    check(!parse("rule type=\"ip-version\" value=\"ipv4\""),"invalid IP version rejected");
    auto private_set=parse("rule type=\"ip-is-private\" value=\"true\"");
    check(bool(private_set),"parse private-address predicate");
    if (private_set) {
        auto encoded=write_beve(*private_set);
        if (encoded) { auto decoded=parse_beve(*encoded); check(decoded && *decoded==*private_set,"private predicate BEVE roundtrip"); }
        else check(false,"private predicate BEVE encoding");
        auto private_matcher=Matcher::compile(*private_set);
        check(bool(private_matcher),"compile private-address predicate");
        if (private_matcher) {
            for (auto ip:{"10.1.2.3","172.16.0.1","172.31.255.255","192.168.0.1","127.0.0.1","169.254.0.1",
                         "224.0.0.1","0.0.0.0","fc00::1","fdff::1","fe80::1","::1","::","ff02::1","::ffff:192.168.1.1"}) {
                auto value=private_matcher->match({.ip=ip});
                check(value && value->has_value(),"non-public IP matches");
            }
            for (auto ip:{"8.8.8.8","172.15.255.255","172.32.0.0","192.167.0.1","169.253.1.1","240.0.0.1",
                         "100.64.0.1","2001:db8::1","fec0::1","::ffff:0.0.0.0"}) {
                auto value=private_matcher->match({.ip=ip});
                check(value && !*value,"outside defined non-public ranges does not match");
            }
            auto unknown=private_matcher->match({});
            check(unknown && !*unknown,"missing IP is unknown");
        }
    }
    check(!parse("rule type=\"ip-is-private\" value=\"false\""),"private predicate rejects false value");
    auto source_rules=parse(R"(rule type="and" {
 rule type="source-ip-cidr" value="192.0.2.0/24"
 rule type="source-port-range" value="1000-2000"
}
rule type="not" { rule type="source-ip-is-private" value="true"; }
)");
    check(bool(source_rules),"parse source rules");
    if (source_rules) {
        check(!RouteProgram::compile_policy(std::vector<ProgramRule>{{*source_rules,{ProgramActionKind::route,1}}},0,2),
              "production route rejects source rules until all inbounds provide metadata");
        auto encoded=write_beve(*source_rules);
        if (encoded) { auto decoded=parse_beve(*encoded); check(decoded && *decoded==*source_rules,"source rules BEVE roundtrip"); }
        else check(false,"source rules BEVE encoding");
        auto compiled=Matcher::compile(*source_rules);
        if (compiled) {
            auto match=compiled->match_mapped({.source_ip="::ffff:192.0.2.1",.source_port=1500});
            auto missing=compiled->match({});
            auto outside=compiled->match({.source_ip="10.1.2.3",.source_port=1500});
            check(match && *match==std::optional<std::size_t>(0) && missing && !*missing && outside && !*outside,
                  "source rules preserve mapped, unknown and private semantics");
            std::array<std::uint8_t,4> source4{192,0,2,1};
            std::array<std::uint8_t,16> source6{0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1};
            auto bytes4=compiled->match_mapped({.source_port=1500,.source_ip_bytes=source4});
            auto bytes6=compiled->match_mapped({.source_port=1500,.source_ip_bytes=source6});
            auto invalid=compiled->match({.source_ip_bytes=std::span(source4).first(3)});
            auto ambiguous=compiled->match({.source_ip="192.0.2.1",.source_ip_bytes=source4});
            check(bytes4 && *bytes4==std::optional<std::size_t>(0) && bytes6 && *bytes6==*bytes4 &&
                  !invalid && !ambiguous,"binary source addresses match and reject invalid input");
            std::vector<ProgramRule> program_rules{{*source_rules,{ProgramActionKind::reject}}};
            auto program=RouteProgram::compile(program_rules,1);
            if (program) {
                auto step=program->next({.source_port=1500,.source_ip_bytes=source6});
                check(step && *step && (*step)->action.kind==ProgramActionKind::reject,
                      "program accepts binary source address");
            } else check(false,"compile source program");
        } else check(false,"compile source rules");
    }
    auto first=parse(R"(rule type="and" {
 rule type="domain-suffix" value="example.com"
 rule type="port" value="443"
 rule type="network" value="tcp"
})");
    auto second=parse(R"(rule type="and" {
 rule type="ip-cidr" value="10.0.0.0/8"
 rule type="not" { rule type="network" value="udp"; }
})");
    auto third=parse("rule type=\"domain-suffix\" value=\"example.com\"");
    check(first && second && third,"parse ordered rules");
    if (first && second && third) {
        std::vector<ProgramRule> routes{{*first,{ProgramActionKind::route,1}},{*second,{ProgramActionKind::route,2}},{*third,{ProgramActionKind::route,0}}};
        auto policy=RouteProgram::compile_policy(routes,0,3);
        check(bool(policy),"compile ordered logical rules");
        if (policy) {
            auto immediate=policy->preflight({.domain="example.com",.port=443,.network=Network::tcp});
            check(immediate && *immediate==std::optional<std::size_t>(1),"known first rule avoids DNS");
            auto undecided=policy->preflight({.domain="example.com",.port=80,.network=Network::tcp});
            check(undecided && !*undecided,"earlier unknown IP delays later action");
            auto udp=policy->preflight({.domain="example.com",.port=80,.network=Network::udp});
            check(udp && *udp==std::optional<std::size_t>(0),"known false AND permits later action");
            check(policy->match({.domain="example.com",.ip="10.1.2.3",.port=80,.network=Network::tcp})==2,"resolved IP preserves rule order");
            check(policy->match({.domain="example.com",.ip="10.1.2.3",.port=443,.network=Network::tcp})==1,"earlier domain and port win over IP");
        }
    }
    auto mapped=parse(R"(rule type="and" {
 rule type="ip-cidr" value="10.0.0.0/8"
 rule type="ip-cidr" value="::ffff:0:0/96"
})");
    if (mapped) {
        auto policy=RouteProgram::compile_policy(std::vector<ProgramRule>{{*mapped,{ProgramActionKind::route,1}}},0,2);
        check(policy && policy->match({.ip="::ffff:10.1.2.3"})==1,"mapped IP satisfies both family predicates");
        auto simple=Matcher::compile(*mapped);
        if (simple) {
            auto inside=simple->match_mapped({.ip="::ffff:10.1.2.3"});
            auto outside=simple->match_mapped({.ip="::ffff:192.0.2.1"});
            check(inside && *inside==std::optional<std::size_t>(0), "simple matcher evaluates both families together");
            check(outside && !*outside, "mapped address outside IPv4 prefix does not match");
        } else check(false, "compile simple mapped matcher");
    } else check(false,"parse mapped rule");
    auto negated=parse("rule type=\"not\" { rule type=\"ip-cidr\" value=\"10.0.0.0/8\"; }");
    if (negated) {
        auto policy=RouteProgram::compile_policy(std::vector<ProgramRule>{{*negated,{ProgramActionKind::route,1}}},0,2);
        check(policy && policy->preflight("test.example") && !*policy->preflight("test.example"),"negated unknown IP requires DNS");
    } else check(false,"parse negation");
    for (auto invalid : {"rule type=\"port\" value=\"0\"", "rule type=\"port\" value=\"65536\"",
                         "rule type=\"port-range\" value=\"81-80\"", "rule type=\"network\" value=\"quic\"",
                         "rule type=\"and\"", "rule type=\"not\" { rule type=\"port\" value=\"1\"; rule type=\"port\" value=\"2\"; }",
                         "rule type=\"domain\" value=\"bad..name\""})
        check(!parse(invalid),"invalid v2 rule rejected");
    check(!parse_kdl("schema-version 1\nkind \"predicate\"\nrule type=\"port\" value=\"443\""),"v1 rejects v2 predicate");
    std::string nested="rule type=\"port\" value=\"1\"";
    for (unsigned i=0;i<max_rule_depth;++i) nested="rule type=\"not\" { "+nested+"; }";
    check(!parse(nested),"nesting depth limit enforced");
    auto sniff_condition=parse(R"(rule type="network" value="tcp")");
    auto route_condition=parse(R"(rule type="and" {
 rule type="domain" value="sniffed.example"
 rule type="ip-cidr" value="192.0.2.0/24"
})");
    if (sniff_condition && route_condition) {
        std::vector<ProgramRule> rules{
            {*sniff_condition,{ProgramActionKind::sniff}},
            {RuleSet{{},2},{ProgramActionKind::resolve}},
            {*route_condition,{ProgramActionKind::route,2},DomainSource::sniffed},
            {RuleSet{{},2},{ProgramActionKind::reject}},
        };
        auto program=RouteProgram::compile(rules,3);
        check(bool(program),"compile ordered action program");
        if (program) {
            auto sniff=program->next({.network=Network::tcp});
            check(sniff && *sniff && (**sniff).rule_index==0 && !(**sniff).terminal(),"sniff continues in order");
            auto resolve=program->next({.sniffed_domain="sniffed.example",.network=Network::tcp},1);
            check(resolve && *resolve && (**resolve).rule_index==1 && !(**resolve).terminal(),"resolve follows sniff");
            auto route=program->next({.explicit_domain="other.example",.sniffed_domain="sniffed.example",.ip="192.0.2.4",.network=Network::tcp},2);
            check(route && *route && (**route).rule_index==2 && (**route).action.outbound==2 && (**route).terminal(),
                  "resolved input selects route");
            auto unknown=program->next({.sniffed_domain="sniffed.example"},2);
            check(unknown && *unknown && (**unknown).rule_index==3 && (**unknown).terminal(),"unknown predicate falls through");
            auto wrong_source=program->next({.explicit_domain="sniffed.example",.ip="192.0.2.4"},2);
            check(wrong_source && *wrong_source && (**wrong_source).rule_index==3,
                  "domain conditions use the configured source only");
            auto udp=program->next({.network=Network::udp});
            check(udp && *udp && (**udp).rule_index==1,"nonmatching network skips sniff");
            auto done=program->next({},4);
            check(done && !*done,"program exhausts");
            check(!program->next({},5) && !program->next({.sniffed_domain="bad..name"},4),"cursor and input validated");
        }
        rules[2].domain_source=static_cast<DomainSource>(255);
        check(!RouteProgram::compile(rules,3),"invalid domain source rejected");
        rules[2].domain_source=DomainSource::sniffed;
        rules[2].action.outbound=3;
        check(!RouteProgram::compile(rules,3),"invalid action outbound rejected");
        rules[2].action={static_cast<ProgramActionKind>(255)};
        check(!RouteProgram::compile(rules,3),"invalid action kind rejected");
    } else check(false,"parse program conditions");
    // A high-scale wide expression (> old 262,144 ceiling) exercises large child indices and copy survival.
    constexpr unsigned wide_scale = 300000;
    Rule wide{"or","",{}};
    wide.children.reserve(wide_scale-1);
    for (unsigned i=0;i<wide_scale-2;++i) wide.children.push_back({"port","1",{}});
    wide.children.push_back({"port","65535",{}});
    auto wide_matcher=Matcher::compile(RuleSet{{wide},2});
    check(bool(wide_matcher),"compile high-scale node count");
    if (wide_matcher) {
        auto last=wide_matcher->match({.port=65535});
        auto missing=wide_matcher->match({});
        check(last && *last==std::optional<std::size_t>(0),"high-scale child index matches");
        check(missing && !*missing,"high-scale child index retains unknown");
        Matcher copy=*wide_matcher;
        *wide_matcher=Matcher{};
        auto copied=copy.match({.port=65535});
        check(copied && *copied==std::optional<std::size_t>(0),"copied child storage survives original");
    }
    RuleSet maximum_domains;
    maximum_domains.version=2;
    maximum_domains.rules.resize(wide_scale,{"domain","first.test",{}});
    maximum_domains.rules.back().value="last.test";
    auto domain_limit=Matcher::compile(maximum_domains);
    check(bool(domain_limit),"compile high-scale domain pool");
    if (domain_limit) {
        Matcher copied=*domain_limit;
        *domain_limit=Matcher{};
        auto last=copied.match({.domain="last.test"});
        check(last && *last==std::optional<std::size_t>(wide_scale-1),"copied high-scale domain pool retains last index");
    }
    RuleSet nested_text{{{"and","",{{"domain","nested.test",{}},{"port","443",{}}}},
                         {"domain","other.test",{}}},2};
    auto nested_original=Matcher::compile(nested_text);
    check(bool(nested_original),"compile nested and indexed domains");
    if (nested_original) {
        Matcher copied=*nested_original;
        *nested_original=Matcher{};
        Matcher moved=std::move(copied);
        auto nested=moved.match({.domain="nested.test",.port=443});
        auto top=moved.match({.domain="other.test",.port=443});
        check(nested && *nested==std::optional<std::size_t>(0) && top && *top==std::optional<std::size_t>(1),
              "copied nested and indexed domains survive original destruction");
    }
    // Indexes must remain valid when their owning matcher is copied or moved.
    RuleSet copies{{{"domain", "duplicate.long-example-domain.example", {}},
                    {"domain", "duplicate.long-example-domain.example", {}},
                    {"domain-suffix", "long-example-domain.example", {}},
                    {"domain", "short.test", {}}}, 2};
    auto original=Matcher::compile(copies);
    check(bool(original),"compile duplicate domain indexes");
    if (original) {
        Matcher copied;
        copied=*original;
        Matcher copy_constructed=copied;
        *original=Matcher{};
        copied=Matcher{};
        Matcher moved=std::move(copy_constructed);
        auto exact=moved.match({.domain="DUPLICATE.LONG-EXAMPLE-DOMAIN.EXAMPLE"});
        auto suffix=moved.match({.domain="other.long-example-domain.example"});
        check(exact && *exact==std::optional<std::size_t>(0),"copied index retains first duplicate");
        check(suffix && *suffix==std::optional<std::size_t>(2),"moved index retains suffix");
        auto short_name=moved.match({.domain="short.test"});
        check(short_name && *short_name==std::optional<std::size_t>(3),"copied index retains inline string");
    }
    // Compare shared program ranges against independently compiled rule sets,
    // including duplicate indexed values across and within instructions.
    std::vector<ProgramRule> ranged_rules;
    std::vector<Matcher> ranged_reference;
    for (unsigned i=0;i<24;++i) {
        RuleSet predicates{{},2};
        for (unsigned j=0;j<7;++j) {
            if (j%4==0) predicates.rules.push_back({"domain",std::format("host{}.example",(i+j)%9),{}});
            else if (j%4==1) predicates.rules.push_back({"domain-suffix",std::format("zone{}.example",(i+j)%7),{}});
            else if (j%4==2) predicates.rules.push_back({"ip-cidr",std::format("10.{}.0.0/16",(i+j)%11),{}});
            else predicates.rules.push_back({"port",std::to_string(8000+(i+j)%13),{}});
        }
        auto matcher=Matcher::compile(predicates);
        if (!matcher) { check(false,"compile range reference"); break; }
        ranged_reference.push_back(std::move(*matcher));
        ranged_rules.push_back({std::move(predicates),{ProgramActionKind::route,i%2},
                                i%2 ? DomainSource::sniffed : DomainSource::explicit_target});
    }
    auto ranged_program=RouteProgram::compile(ranged_rules,2);
    check(ranged_program && ranged_reference.size()==24,"compile shared program ranges");
    if (ranged_program && ranged_reference.size()==24) {
        for (unsigned n=0;n<500;++n) {
            auto explicit_name=std::format("host{}.example",n%13);
            auto sniffed_name=std::format("www.zone{}.example",n%11);
            auto ip=std::format("10.{}.1.2",n%17);
            auto begin=n%25;
            std::optional<std::uint16_t> port=n%2 ? std::optional<std::uint16_t>(8000+n%17) : std::nullopt;
            std::optional<std::size_t> expected;
            for (std::size_t i=begin;i<ranged_reference.size();++i) {
                auto found=ranged_reference[i].match_mapped({.domain=i%2 ? sniffed_name : explicit_name,.ip=ip,.port=port});
                if (!found) { check(false,"valid range input"); break; }
                if (*found) { expected=i; break; }
            }
            auto actual=ranged_program->next({.explicit_domain=explicit_name,.sniffed_domain=sniffed_name,.ip=ip,.port=port},begin);
            auto index=actual && *actual ? std::optional<std::size_t>((**actual).rule_index) : std::nullopt;
            if (!actual || index!=expected) { check(false,"shared range differential"); break; }
        }
    }
    // Wrap each rule in AND to force expression evaluation as an independent
    // linear reference for the indexed top-level predicates.
    RuleSet indexed{{},2}, linear{{},2};
    for (unsigned i=0;i<120;++i) {
        Rule rule;
        if (i%5==0) rule={"domain",std::format("host{}.example",i%23),{}};
        else if (i%5==1) rule={"domain-suffix",std::format("zone{}.example",i%17),{}};
        else if (i%5==2) rule={"ip-cidr",std::format("10.{}.0.0/{}",i%256,8+i%17),{}};
        else if (i%5==3) rule={"ip-cidr",std::format("2001:db8:{:x}::/{}",i,32+i%49),{}};
        else rule={"port-range",std::format("{}-{}",1000+i,1200+i),{}};
        indexed.rules.push_back(rule);
        linear.rules.push_back({"and","",{std::move(rule)}});
    }
    auto fast=Matcher::compile(indexed), reference=Matcher::compile(linear);
    check(fast && reference,"compile indexed and linear rule sets");
    if (fast && reference) {
        for (unsigned i=0;i<1000;++i) {
            auto domain=i%3==0 ? std::format("HOST{}.EXAMPLE",i%23) :
                std::format("www.zone{}.example",i%19);
            auto ip=i%3==0 ? std::format("10.{}.{}.{}",i%256,(i*13)%256,(i*31)%256) :
                i%3==1 ? std::format("2001:db8:{:x}::{:x}",i%120,i) :
                std::format("::ffff:10.{}.{}.{}",i%256,(i*13)%256,(i*31)%256);
            MatchInput input{.domain=domain,.ip=ip,.port=static_cast<std::uint16_t>(1000+i%400),.network=Network::udp};
            auto a=fast->match_mapped(input), b=reference->match_mapped(input);
            if (!a || !b || *a!=*b) { check(false,"indexed and linear differential"); break; }
        }
    }
    if (!failures) std::cout << "v2 rule formats, three-valued logic and routing passed\n";
    return failures ? 1 : 0;
}
