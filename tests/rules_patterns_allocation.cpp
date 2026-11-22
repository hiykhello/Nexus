import std;
import rules;
import dns.policy;

namespace {
    std::atomic<bool> deny{false};
    std::atomic<std::size_t> attempts{0};
}
void* operator new(std::size_t size) {
    attempts.fetch_add(1,std::memory_order_relaxed);
    if (deny.load(std::memory_order_relaxed)) throw std::bad_alloc{};
    if (auto* pointer=std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc{};
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete[](void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer,std::size_t) noexcept { std::free(pointer); }
void operator delete[](void* pointer,std::size_t) noexcept { std::free(pointer); }

int main() {
    using namespace ::rules;
    RuleSet rules{{{"domain-keyword","ababac",{}},{"domain-wildcard","*.example.test",{}},
                   {"ip-version","6",{}},{"domain","exact.index.test",{}},
                   {"domain-suffix","index.test",{}}},2};
    auto matcher=Matcher::compile(rules);
    auto routes=RouteMatcher::compile(std::vector<RouteRule>{{rules,1}},0,2);
    auto program=RouteProgram::compile(std::vector<ProgramRule>{{rules,{ProgramActionKind::route,1}}},2);
    RuleSet source_rules{{{"source-ip-cidr","192.0.2.0/24",{}}},2};
    auto source_matcher=Matcher::compile(source_rules);
    auto source_program=RouteProgram::compile(std::vector<ProgramRule>{{source_rules,{ProgramActionKind::reject}}},1);
    std::array<std::uint8_t,4> source{192,0,2,1};
    std::vector<::policy::DnsRule> dns_rules{{.domain="options.test",.suffix=true,.action=::policy::DnsAction::route_options,.disable_cache=true},
        {.domain="blocked.test",.suffix=true,.action=::policy::DnsAction::reject},
        {.domain="example.test",.suffix=true,.server=1,.query_type=28},
        {.domain="",.server=2,.query_type=1},
        {.domain="keyword-_svc",.server=2,.query_type=28,.pattern=::policy::DnsPattern::keyword},
        {.domain="*.single.test",.server=1,.query_type=28,.pattern=::policy::DnsPattern::wildcard}};
    dns_rules.insert(dns_rules.begin(),{.domain="context.test",.server=1,
        .context={{"network","udp"},{"source-ip-cidr","192.0.2.0/24"},{"source-port","1234"},{"inbound","edge"},{"auth-user","alice"}}});
    for (auto& rule:dns_rules) if (!::policy::normalize_dns_rule(rule,3)) return 1;
    std::vector<::policy::DnsRule> inverted{{.domain="context.test",.action=::policy::DnsAction::reject,
        .invert=true,.context={{"auth-user","alice"}}}};
    if (!::policy::normalize_dns_rule(inverted[0],3)) return 1;
    if (!matcher || !routes || !program || !source_matcher || !source_program) return 1;
    auto before=attempts.load(std::memory_order_relaxed);
    deny.store(true,std::memory_order_relaxed);
    bool ok=true;
    try {
        for (unsigned i=0;i<1000;++i) {
            auto keyword=matcher->match({.domain="ABABABAC.test"});
            auto wildcard=matcher->match({.domain="one.example.test"});
            auto version=matcher->match({.ip="2001:db8::1"});
            auto indexed_exact=matcher->match({.domain="exact.index.test"});
            auto indexed_mixed=matcher->match({.domain="EXACT.InDeX.TeSt"});
            auto indexed_suffix=matcher->match({.domain="other.index.test"});
            auto preflight=routes->preflight({.domain="one.example.test",.port=443,.network=Network::tcp});
            auto route=routes->match({.ip="2001:db8::1",.port=443,.network=Network::udp});
            auto step=program->next({.explicit_domain="ABABABAC.test"});
            auto source_match=source_matcher->match({.source_ip_bytes=source});
            auto source_step=source_program->next({.source_ip_bytes=source});
            auto dns_match=::policy::select_dns_action(dns_rules,"_api.ExAmPlE.TeSt",28,0);
            auto dns_type=::policy::select_dns_action(dns_rules,"other.test",1,0);
            auto dns_fallback=::policy::select_dns_action(dns_rules,"notexample.test",28,0);
            auto dns_keyword=::policy::select_dns_action(dns_rules,"PRE-KEYWORD-_SVC.other",28,0);
            auto dns_wildcard=::policy::select_dns_action(dns_rules,"_svc.single.test",28,0);
            auto dns_nested=::policy::select_dns_action(dns_rules,"deep.one.single.test",28,0);
            auto dns_denied=::policy::select_dns_action(dns_rules,"denied.blocked.test",1,0);
            auto dns_options=::policy::select_dns_action(dns_rules,"continued.options.test",28,2);
            auto dns_context=::policy::select_dns_action(dns_rules,"context.test",28,0,false,
                {.network=Network::udp,.source_port=1234,.source_ip_bytes=source,.inbound="edge",.auth_user="alice"});
            auto dns_unknown=::policy::select_dns_action(dns_rules,"context.test",28,0);
            auto inv_yes=::policy::select_dns_action(inverted,"context.test",1,0,false,{.auth_user="bob"});
            auto inv_unknown=::policy::select_dns_action(inverted,"context.test",1,0);
            ok &= keyword && *keyword==std::optional<std::size_t>(0) && wildcard && *wildcard==std::optional<std::size_t>(1) &&
                  version && *version==std::optional<std::size_t>(2) && preflight && *preflight==std::optional<std::size_t>(1) &&
                  indexed_exact && *indexed_exact==std::optional<std::size_t>(3) &&
                  indexed_mixed && *indexed_mixed==*indexed_exact &&
                  indexed_suffix && *indexed_suffix==std::optional<std::size_t>(4) &&
                  route && *route==1 && step && *step && (**step).action.outbound==1 &&
                  source_match && *source_match==std::optional<std::size_t>(0) && source_step && *source_step &&
                  dns_match.server==1 && dns_type.server==2 && dns_fallback.server==0 && dns_keyword.server==2 && dns_wildcard.server==1 && dns_nested.server==0 &&
                  dns_denied.action==::policy::DnsAction::reject && dns_options.server==2 && dns_options.disable_cache &&
                  dns_context.server==1 && dns_unknown.server==0 && inv_yes.action==::policy::DnsAction::reject &&
                  inv_unknown.action==::policy::DnsAction::route;
        }
    } catch (...) { ok=false; }
    deny.store(false,std::memory_order_relaxed);
    if (!ok || before!=attempts.load(std::memory_order_relaxed)) return 2;
    std::cout << "domain patterns, IP version and DNS question rules match without ordinary C++ allocation\n";
}
