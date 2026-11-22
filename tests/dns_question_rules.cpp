import std;
import config;
import dns.policy;
import dns.address_sequence;
import rules;

namespace {
    auto parse(std::string_view fields) {
        return config::parse_kdl(std::format(R"(schema-version 1
role "client"
dns {{ server "a" type="udp" host="127.0.0.1"; server "b" type="local"; {} }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
)",fields));
    }
    namespace dns=dns;
    using Error=dns::detail::ResolveError;
    auto answer(std::string name,std::size_t count=1,std::uint32_t ttl=60) -> dns::AddressAnswer {
        dns::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
        return {name,{name},std::vector<dns::Address>(count,address),ttl};
    }
}

auto main() -> int {
#ifdef NEXUS_DNS_RESPONSE
    {
        auto ecs=parse(R"(rule action="route-options" client-subnet="192.0.2.255/25";
rule action="route" server="a" client-subnet="2001:db8::1234/64";)");
        if(!ecs || !ecs->dns || !ecs->dns->rules[0].client_subnet || !ecs->dns->rules[1].client_subnet) return 60;
        auto a=*ecs->dns->rules[0].client_subnet, b=*ecs->dns->rules[1].client_subnet;
        if(a.size!=4 || a.bits!=25 || a.address[3]!=128 || b.size!=16 || b.bits!=64 || b.address[15]!=0) return 61;
        for(auto invalid:{R"(rule action="route" server="a" client-subnet="192.0.2.1/33";)",
                          R"(rule action="route" server="a" client-subnet="2001:db8::1/129";)",
                          R"(rule action="route" server="a" client-subnet="192.0.2.1/";)",
                          R"(rule action="route" server="a" client-subnet="bad/24";)",
                          R"(rule action="route" server="a" client-subnet="192.0.2.1" remove-client-subnet=#true;)",
                          R"(rule action="reject" client-subnet="192.0.2.1";)",
                          R"(rule action="respond" remove-client-subnet=#true;)",
                          R"(rule action="route-options" remove-client-subnet=#false;)"})
            if(parse(invalid)) {std::cerr << "accepted invalid ECS rule: " << invalid << '\n';return 62;}
    }
#else
    if(parse(R"(rule action="route" server="a" client-subnet="192.0.2.1/24";)")) return 63;
#endif
    auto config=parse(R"(rule domain-suffix="Example.TEST" query-type="AAAA" server="b";
rule query-type=1 server="a";
rule domain="example.test" server="b";
final "a";)");
    if (!config || !config->dns || config->dns->rules.size()!=3) return 1;
    auto const& rules=config->dns->rules;
    if (rules[0].query_type!=28 || rules[0].domain!="example.test" || !rules[0].suffix ||
        rules[1].query_type!=1 || !rules[1].domain.empty() || rules[2].query_type) return 2;
    auto select=[&](std::string_view name,std::uint16_t type) {
        return ::policy::select_dns_action(rules,name,type,9).server;
    };
    if (select("EXAMPLE.test",28)!=1 || select("_service.Example.Test",28)!=1 ||
        select("other.test",1)!=0 || select("other.test",28)!=9 ||
        select("notexample.test",28)!=9 || select("example.test.attacker",28)!=9 ||
        select("example.test",1)!=0) return 3;
    for (auto field:{"query-type=1", "query-type=28", "query-type=65535", "query-type=\"A\"", "query-type=\"AAAA\""})
        if (!parse(std::format("rule {} server=\"b\";",field))) return 4;
    for (auto invalid:{R"(rule server="a";)", R"(rule query-type=0 server="a";)",
        R"(rule query-type=-1 server="a";)", R"(rule query-type=65536 server="a";)",
        R"(rule query-type=#true server="a";)", R"(rule query-type=#null server="a";)",
        R"(rule query-type="HTTPS" server="a";)", R"(rule query-type="1" server="a";)",
        R"(rule query-type=(tag)1 server="a";)", R"(rule query-type=1 server="missing";)",
        R"(rule domain="" query-type=1 server="a";)", R"(rule domain-suffix="" query-type=1 server="a";)",
        R"(rule domain=#true query-type=1 server="a";)", R"(rule domain-suffix=#null query-type=1 server="a";)",
        R"(rule domain="a.test" domain-suffix="a.test" query-type=1 server="a";)",
        R"(rule domain="a.test" query-type=1 server="a" extra=1;)",
        R"(rule "arg" query-type=1 server="a";)", R"(rule query-type=1 server="a" { x; };)"})
        if (parse(invalid)) { std::cerr << "accepted invalid DNS rule: " << invalid << '\n'; return 5; }
    auto last_property=parse(R"(rule query-type=1 query-type=28 server="a";)");
    if (!last_property || last_property->dns->rules[0].query_type!=28) return 11;
    auto patterns=parse(R"(rule domain-keyword="KEYWORD-_Svc" query-type="AAAA" server="b";
rule domain-wildcard="*.Single.TEST" server="a";)");
    if (!patterns || patterns->dns->rules[0].pattern!=::policy::DnsPattern::keyword ||
        patterns->dns->rules[0].domain!="keyword-_svc" ||
        patterns->dns->rules[1].pattern!=::policy::DnsPattern::wildcard ||
        patterns->dns->rules[1].domain!="*.single.test") return 12;
    auto pattern_select=[&](std::string_view name,std::uint16_t type) {
        return ::policy::select_dns_action(patterns->dns->rules,name,type,9).server;
    };
    if (pattern_select("pre-KEYWORD-_SVC.other",28)!=1 || pattern_select("pre-keyword-_svc.other",1)!=9 ||
        pattern_select("_svc.single.test",1)!=0 || pattern_select("single.test",1)!=9 ||
        pattern_select("deep.one.single.test",1)!=9 || pattern_select(".single.test",1)!=9) return 13;
    for (auto invalid:{R"(rule domain-keyword="" server="a";)", R"(rule domain-keyword=#true server="a";)",
        R"(rule domain-keyword="bad space" server="a";)", R"(rule domain-keyword="bad\\escape" server="a";)",
        R"(rule domain="a.test" domain-keyword="a" server="a";)",
        R"(rule domain-suffix="a.test" domain-wildcard="*.a.test" server="a";)",
        R"(rule domain-keyword="a" domain-wildcard="*.a.test" server="a";)",
        R"(rule domain-wildcard="" server="a";)", R"(rule domain-wildcard="a.test" server="a";)",
        R"(rule domain-wildcard="*" server="a";)", R"(rule domain-wildcard="*.*.test" server="a";)",
        R"(rule domain-wildcard=#false server="a";)"})
        if (parse(invalid)) return 14;
    if (parse("rule domain-keyword=\""+std::string(254,'a')+"\" server=\"a\";") ||
        !parse("rule domain-keyword=\""+std::string(253,'a')+"\" server=\"a\";")) return 15;
    auto actions=parse(R"(rule domain="allow.blocked.test" action="route" server="b";
rule domain-suffix="blocked.test" action="reject";
rule query-type=28 action="reject";
rule action="route" server="a";)");
    if (!actions || actions->dns->rules.size()!=4 || !actions->dns->rules[3].match_all ||
        actions->dns->rules[1].action!=::policy::DnsAction::reject) return 16;
    auto action_select=[&](std::string_view name,std::uint16_t type) {
        return ::policy::select_dns_action(actions->dns->rules,name,type,9);
    };
    if (action_select("allow.blocked.test",28)!=::policy::DnsDecision{::policy::DnsAction::route,1} ||
        action_select("deny.blocked.test",1).action!=::policy::DnsAction::reject ||
        action_select("other.test",28).action!=::policy::DnsAction::reject ||
        action_select("other.test",1)!=::policy::DnsDecision{::policy::DnsAction::route,0}) return 17;
    auto reject_all=parse(R"(rule action="reject";)");
    if (!reject_all || !reject_all->dns->rules[0].match_all ||
        ::policy::select_dns_action(reject_all->dns->rules,"other.test",1,9).action!=::policy::DnsAction::reject) return 18;
    for (auto invalid:{R"(rule action="reject" server="a";)", R"(rule action="route";)", R"(rule action="unknown";)",
        R"(rule action=#true;)", R"kdl(rule action=(tag)"reject";)kdl", R"(rule action="reject" extra=#true;)",
        R"(rule domain="" action="reject";)", R"(rule query-type=0 action="reject";)"})
        if (parse(invalid)) return 19;
    auto bad=actions->dns->rules[0];
    bad.match_all=true;
    if (::policy::normalize_dns_rule(bad,2)) return 20;
    bad=actions->dns->rules[0]; bad.action=static_cast<::policy::DnsAction>(255);
    if (::policy::normalize_dns_rule(bad,2)) return 21;
    bad=actions->dns->rules[1]; bad.server=1;
    if (::policy::normalize_dns_rule(bad,2)) return 22;
    auto options=parse(R"(rule domain="a.test" action="route-options" disable-cache=#true;
rule domain="a.test" query-type=1 action="route-options" disable-cache=#false;
rule domain="a.test" action="route" server="b";
rule domain="early.test" server="b";
rule action="route-options" disable-cache=#true;
rule action="route" server="a" disable-cache=#false;)");
    if (!options || options->dns->rules[0].action!=::policy::DnsAction::route_options ||
        options->dns->rules[0].disable_cache!=true || options->dns->rules[1].disable_cache!=false) return 23;
    auto option_select=[&](std::string_view name,std::uint16_t type,bool disabled=false) {
        return ::policy::select_dns_action(options->dns->rules,name,type,9,disabled);
    };
    if (option_select("a.test",1)!=::policy::DnsDecision{::policy::DnsAction::route,1,false} ||
        option_select("a.test",28)!=::policy::DnsDecision{::policy::DnsAction::route,1,true} ||
        option_select("early.test",1).disable_cache || !option_select("early.test",1,true).disable_cache ||
        option_select("other.test",1,true)!=::policy::DnsDecision{::policy::DnsAction::route,0,false}) return 24;
    auto fallback_options=parse(R"(rule action="route-options" disable-cache=#true;)");
    if (!fallback_options || ::policy::select_dns_action(fallback_options->dns->rules,"other.test",1,1)!=
        ::policy::DnsDecision{::policy::DnsAction::route,1,true}) return 25;
    for (auto invalid:{R"(rule action="route-options";)", R"(rule action="route-options" server="a" disable-cache=#true;)",
        R"(rule action="route-options" disable-cache=1;)", R"(rule action="route-options" disable-cache="true";)",
        R"(rule action="reject" disable-cache=#false;)", R"(rule action="reject" disable-cache=#true;)",
        R"(rule domain="a.test" disable-cache=#true;)", R"(rule action="route" server="a" disable-cache=#null;)"})
        if (parse(invalid)) return 26;
    bad=fallback_options->dns->rules[0]; bad.disable_cache.reset();
    if (::policy::normalize_dns_rule(bad,2)) return 27;

    auto contexts=parse(R"(rule domain-suffix="test" query-type=28 network="udp" source-ip-cidr="192.0.2.0/24" source-port-range="1000-2000" inbound="edge" auth-user="alice" server="b";
rule source-ip-is-private=#true network="tcp" action="route-options" disable-cache=#true;
rule auth-user="bob" source-port=443 action="reject";)");
    if (!contexts || contexts->dns->rules[0].context.size()!=5 || contexts->dns->rules[0].match_all) return 28;
    auto copied=contexts->dns->rules;
    contexts->dns->rules.clear();
    std::array<std::uint8_t,4> source{192,0,2,9},private_source{127,0,0,1};
    ::policy::DnsContext input{.network=::rules::Network::udp,.source_port=1234,
        .source_ip_bytes=source,.inbound="edge",.auth_user="alice"};
    auto selected=[&](auto const& value,std::uint16_t type=28) {
        return ::policy::select_dns_action(copied,"_svc.example.test",type,9,false,value);
    };
    if (selected(input).server!=1 || selected(input,1).server!=9 || selected(::policy::DnsContext{}).server!=9) return 29;
    auto requirements=::policy::dns_context_requirements(copied);
    if (!requirements.source || !requirements.auth_user) return 30;
    auto changed_context=input; changed_context.auth_user.reset();
    if (selected(changed_context).server!=9) return 31;
    changed_context=input; changed_context.inbound="other";
    if (selected(changed_context).server!=9) return 32;
    changed_context=input; changed_context.source_port=2001;
    if (selected(changed_context).server!=9) return 33;
    changed_context=input; changed_context.network=::rules::Network::tcp; changed_context.source_ip_bytes=private_source;
    if (selected(changed_context).server!=9 || !selected(changed_context).disable_cache) return 34;
    changed_context=input; changed_context.auth_user="bob"; changed_context.source_port=443;
    if (selected(changed_context).action!=::policy::DnsAction::reject) return 35;
    std::array<std::uint8_t,16> mapped{};
    mapped[10]=255; mapped[11]=255; std::ranges::copy(source,mapped.begin()+12);
    changed_context=input; changed_context.source_ip_bytes=mapped;
    if (selected(changed_context).server!=1) return 38;
    for (auto invalid:{R"(rule network="sctp" server="a";)", R"(rule network=1 server="a";)",
        R"(rule source-ip-cidr="bad" server="a";)", R"(rule source-ip-is-private=#false server="a";)",
        R"(rule source-ip-is-private="true" server="a";)", R"(rule source-port=0 server="a";)",
        R"(rule source-port="443" server="a";)", R"(rule source-port=65536 server="a";)",
        R"(rule source-port-range="2000-1000" server="a";)", R"(rule inbound="" server="a";)",
        R"(rule auth-user=#null server="a";)", R"kdl(rule auth-user=(tag)"alice" server="a";)kdl"})
        if (parse(invalid)) return 36;
    bad=copied[0]; bad.context[0].type="domain";
    if (::policy::normalize_dns_rule(bad,2)) return 37;

    // Inversion applies to the whole conjunction; unknown metadata remains
    // unknown, while a known false conjunct makes the conjunction false.
    auto inverted=parse(R"(rule domain-suffix="allowed.test" query-type=1 auth-user="alice" invert=#true action="reject";
rule action="route-options" disable-cache=#true;
rule action="route" server="b";)");
    if (!inverted || !inverted->dns->rules[0].invert) return 41;
    auto inv=[&](std::string_view name,std::uint16_t type,std::optional<std::string_view> user) {
        return ::policy::select_dns_action(inverted->dns->rules,name,type,0,false,{.auth_user=user});
    };
    if (inv("a.allowed.test",1,"alice")!=::policy::DnsDecision{::policy::DnsAction::route,1,true} ||
        inv("a.allowed.test",1,"bob").action!=::policy::DnsAction::reject ||
        inv("a.allowed.test",1,std::nullopt)!=::policy::DnsDecision{::policy::DnsAction::route,1,true} ||
        inv("outside.test",1,std::nullopt).action!=::policy::DnsAction::reject ||
        inv("a.allowed.test",28,std::nullopt).action!=::policy::DnsAction::reject) return 42;
    auto copy=inverted->dns->rules;
    if (::policy::select_dns_action(copy,"a.allowed.test",1,0,false,{.auth_user="bob"}).action!=::policy::DnsAction::reject) return 43;
    for (auto invalid:{R"(rule action="reject" invert=1;)",R"(rule action="reject" invert="true";)",R"(rule action="reject" invert=#null;)"})
        if (parse(invalid)) return 44;
    auto all_inverted=parse(R"(rule action="reject" invert=#true; rule action="route" server="a";)");
    if (!all_inverted || ::policy::select_dns_action(all_inverted->dns->rules,"a.test",1,1).server!=0) return 45;

    auto sets=parse(R"(rule-set "q" path="q.srs" format="srs";
rule rule-set="q" invert=#true action="reject";)");
    if (!sets || sets->dns->rule_files.size()!=1 || !sets->dns->rules[0].has_rule_set || sets->dns->rules[0].match_all) return 70;
    auto set_rule=sets->dns->rules[0];
    if (::policy::normalize_dns_rule(set_rule,2)) return 71;
    ::rules::RuleSet set{{{"and","",{{"domain-suffix","test",{}},{"query-type","1",{}},{"source-ip-cidr","192.0.2.0/24",{}}}}},2};
    if (!::policy::bind_dns_rule_set(set_rule,std::move(set)) || !::policy::normalize_dns_rule(set_rule,2)) return 72;
    auto set_requirements=::policy::dns_context_requirements(std::span(&set_rule,1));
    if (!set_requirements.source || set_requirements.auth_user) return 73;
    using Truth=::rules::Matcher::Truth;
    auto matched=::policy::dns_question_truth(set_rule,"a.test",1,{.source_ip_bytes=source});
    auto unknown=::policy::dns_question_truth(set_rule,"a.test",1,{});
    auto other=::policy::dns_question_truth(set_rule,"a.test",28,{});
    if (!matched || *matched!=Truth::yes || !unknown || *unknown!=Truth::unknown || !other || *other!=Truth::no ||
        ::policy::dns_rule_matches(set_rule,"a.test",1,{}) || !::policy::dns_rule_matches(set_rule,"a.test",28,{})) return 74;
    auto invalid_set=set_rule;
    if (::policy::bind_dns_rule_set(invalid_set,{{{"ip-cidr","192.0.2.0/24",{}}},2})) return 75;
    if (::policy::bind_dns_rule_set(invalid_set,{{{"query-type","1",{}}},1}) ||
        ::policy::bind_dns_rule_set(invalid_set,{{{"domain","a.test",{}}},99})) return 77;
    if (parse(R"(rule-set "q" path="q.kdl" format="kdl"; rule rule-set="q" ip-cidr-match-source=#true server="a";)") ||
        parse(R"(rule-set "q" path="q.srs" format="srs"; rule rule-set="missing" server="a";)") ||
        parse(R"(rule-set "q" path="q.srs" format="srs"; rule action="reject";)") ) return 76;

    dns::detail::AddressAnswers<true> combined;
    if (!combined.add(answer("canonical.test",32,60)) || !combined.add(answer("canonical.test",32,12))) return 6;
    auto full=combined.finish();
    if (!full || full->addresses.size()!=64 || full->canonical_name!="canonical.test" ||
        full->chain!=std::vector<std::string>{"canonical.test"} || full->ttl!=12) return 7;
    auto conflict=[](auto first,auto second,Error error) {
        dns::detail::AddressAnswers<false> sequence;
        if (!sequence.add(std::move(first))) return false;
        auto result=sequence.add(std::move(second));
        return !result && result.error()==error;
    };
    using Result=std::expected<dns::AddressAnswer,Error>;
    if (!conflict(Result(answer("a.test")),Result(answer("b.test")),Error::protocol) ||
        !conflict(Result(answer("a.test",40)),Result(answer("a.test",25)),Error::limit) ||
        !conflict(Result(answer("a.test")),Result(std::unexpected(Error::name_not_found)),Error::protocol) ||
        !conflict(Result(std::unexpected(Error::no_data)),Result(std::unexpected(Error::name_not_found)),Error::protocol) ||
        !conflict(Result(answer("a.test")),Result(std::unexpected(Error::timeout)),Error::timeout)) return 8;
    dns::detail::AddressAnswers<false> partial,empty,missing;
    if (!partial.add(std::unexpected(Error::no_data)) || !partial.add(answer("a.test")) || !partial.finish() ||
        !empty.add(std::unexpected(Error::no_data)) || empty.finish() || empty.finish().error()!=Error::no_data) return 9;
    auto nxdomain=missing.add(std::unexpected(Error::name_not_found));
    if (nxdomain || nxdomain.error()!=Error::name_not_found) return 10;
    std::println("DNS question conditions, continued options, route/reject actions and answer consistency passed");
}
