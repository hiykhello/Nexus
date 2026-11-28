import std;
import rules;
import http.sniff;
import sniff.tls;
import sniff.tcp;

namespace {
    using Bytes=std::vector<std::uint8_t>;
    auto u16(Bytes& value,std::size_t n) -> void { value.push_back(static_cast<std::uint8_t>(n>>8)); value.push_back(static_cast<std::uint8_t>(n)); }
    auto client_hello(std::string_view name) -> Bytes {
        Bytes body{3,3}; body.resize(34,0); body.push_back(0); u16(body,2); body.insert(body.end(),{0x13,1,1,0});
        Bytes sni; u16(sni,name.size()+3); sni.push_back(0); u16(sni,name.size()); sni.insert(sni.end(),name.begin(),name.end());
        u16(body,sni.size()+4); u16(body,0); u16(body,sni.size()); body.insert(body.end(),sni.begin(),sni.end());
        Bytes wire{22,3,1}; u16(wire,body.size()+4); wire.push_back(1); wire.push_back(static_cast<std::uint8_t>(body.size()>>16));
        wire.push_back(static_cast<std::uint8_t>(body.size()>>8)); wire.push_back(static_cast<std::uint8_t>(body.size()));
        wire.insert(wire.end(),body.begin(),body.end()); return wire;
    }
}
int main() {
    using namespace ::rules;
    RuleSet explicit_block{{{"domain","blocked.example"}},2};
    RuleSet sniffed_match{{{"and","",{{"domain","site.example"},{"port","443"},{"network","tcp"}}}},2};
    std::vector<ProgramRule> rules{
        {explicit_block,{ProgramActionKind::reject}},
        {RuleSet{{},2},{ProgramActionKind::sniff}},
        {sniffed_match,{ProgramActionKind::route,2},DomainSource::sniffed},
        {RuleSet{{},2},{ProgramActionKind::reject}}
    };
    auto program=RouteProgram::compile(rules,3);
    if (!program) return 1;
    auto early=program->next({.explicit_domain="blocked.example",.port=443,.network=Network::tcp});
    if (!early || !*early || !(**early).terminal() || (**early).rule_index!=0) return 2;
    auto initial=program->next({.explicit_domain="other.example",.port=443,.network=Network::tcp});
    if (!initial || !*initial || (**initial).action.kind!=ProgramActionKind::sniff || (**initial).terminal()) return 3;
    std::string http="GET / HTTP/1.1\r\nHost: site.example\r\n\r\nbody";
    http::HttpSniffer http_sniffer;
    auto http_result=http_sniffer.inspect(http);
    if (http_result.status!=http::SniffStatus::matched || !http_result.domain) return 4;
    auto http_route=program->next({.explicit_domain="other.example",.sniffed_domain=http_result.domain,
                                   .port=443,.network=Network::tcp},(**initial).next_index);
    if (!http_route || !*http_route || !(**http_route).terminal() || (**http_route).action.outbound!=2) return 5;
    auto wire=client_hello("site.example");
    std::array<std::uint8_t,1024> scratch{};
    sniff::TlsSniffer tls_sniffer;
    auto tls_result=tls_sniffer.feed(wire,scratch);
    if (tls_result.status!=sniff::TlsStatus::matched || !tls_result.server_name) return 6;
    auto tls_route=program->next({.explicit_domain="other.example",.sniffed_domain=tls_result.server_name,
                                  .port=443,.network=Network::tcp},(**initial).next_index);
    if (!tls_route || !*tls_route || (**tls_route).action.outbound!=2) return 7;
    auto wrong_port=program->next({.sniffed_domain=tls_result.server_name,.port=80,.network=Network::tcp},(**initial).next_index);
    if (!wrong_port || !*wrong_port || (**wrong_port).action.kind!=ProgramActionKind::reject) return 8;
    std::array<std::uint8_t,1024> retained{},scratch2{};
    sniff::TcpSniffer buffered(retained,scratch2);
    auto bytes=std::span(reinterpret_cast<std::uint8_t const*>(http.data()),http.size());
    bool observed=false;
    for(std::size_t i=0;i<bytes.size();++i) {
        auto step=buffered.feed(bytes.subspan(i,1));
        if(step.consumed!=1)return 9;
        if(step.status==sniff::TcpStatus::matched) {
            if(step.protocol!=sniff::TcpProtocol::http || step.domain!="site.example" ||
                !std::ranges::equal(buffered.wire(),bytes.first(i+1)))return 10;
            observed=true;
            break;
        }
        if(step.status!=sniff::TcpStatus::need_more)return 11;
    }
    if(!observed)return 16;
    std::array<std::uint8_t,1024> retained_tls{},scratch_tls{};
    sniff::TcpSniffer buffered_tls(retained_tls,scratch_tls);
    auto half=wire.size()/2;
    if(buffered_tls.feed(std::span(wire).first(half)).status!=sniff::TcpStatus::need_more)return 12;
    auto final=buffered_tls.feed(std::span(wire).subspan(half));
    if(final.status!=sniff::TcpStatus::matched || final.domain!="site.example" ||
        final.protocol!=sniff::TcpProtocol::tls || !std::ranges::equal(buffered_tls.wire(),wire))return 13;
    std::array<std::uint8_t,1024> retained_full{},scratch_full{};
    sniff::TcpSniffer full(retained_full,scratch_full);
    auto whole=full.feed(bytes);
    if(whole.status!=sniff::TcpStatus::matched || whole.consumed!=bytes.size() ||
        !std::ranges::equal(full.wire(),bytes))return 15;
    std::array<std::uint8_t,4> tiny{},scratch_small{};sniff::TcpSniffer limited(tiny,scratch_small);
    auto overflow=limited.feed(bytes);
    if(overflow.status!=sniff::TcpStatus::too_large || overflow.consumed!=tiny.size() ||
        !std::ranges::equal(limited.wire(),bytes.first(tiny.size())))return 14;
    std::vector<ProgramRule> policy_rules{
        {RuleSet{{{"domain","special.example"},{"ip-cidr","10.0.0.0/8"}},2},{ProgramActionKind::route,1}},
        {RuleSet{{{"domain-suffix","example.org"}},2},{ProgramActionKind::route,2}}
    };
    std::vector<ProgramRule> prog_rules{
        {RuleSet{{{"domain","special.example"},{"ip-cidr","10.0.0.0/8"}},2},{ProgramActionKind::route,1}},
        {RuleSet{{{"domain-suffix","example.org"}},2},{ProgramActionKind::route,2}},
        {RuleSet{{},2},{ProgramActionKind::route,0}}
    };
    auto old=RouteProgram::compile_policy(policy_rules,0,3);
    auto unified=RouteProgram::compile(prog_rules,3);
    if(!old || !unified)return 17;
    for(auto domain:{"special.example","other.example","www.example.org"}) {
        for(auto address:{"10.1.2.3","192.0.2.4","::ffff:10.2.3.4"}) {
            auto expected=old->match({.domain=domain,.ip=address,.port=443,.network=Network::tcp});
            auto actual=unified->next({.explicit_domain=domain,.ip=address,.port=443,.network=Network::tcp});
            if(!expected || !actual || !*actual || (**actual).action.kind!=ProgramActionKind::route || (**actual).action.outbound!=*expected)return 19;
        }
    }
    if(unified->next({},prog_rules.size()+1))return 20;
    std::vector<ProgramRule> metadata_rules{
        {RuleSet{{{"source-ip-cidr","192.0.2.0/24"},{"auth-user","alice"},{"inbound","local"}},2},{ProgramActionKind::route,1}},
        {RuleSet{{},2},{ProgramActionKind::route,0}}
    };
    auto metadata=RouteProgram::compile(metadata_rules,2);
    if(!metadata)return 21;
    auto metadata_result=metadata->next({.source_ip="198.51.100.1",.inbound="local",.auth_user="bob"});
    if(!metadata_result || !*metadata_result || (**metadata_result).action.outbound!=1)return 22;
    auto empty=RouteProgram::compile({},3);
    auto empty_step=empty ? empty->next({}) : std::expected<std::optional<ProgramStep>,Error>(std::unexpected(Error{}));
    if(!empty || !empty_step || empty_step->has_value())return 23;
    std::vector<ProgramRule> deferred{
        {RuleSet{{{"ip-cidr","10.0.0.0/8"},{"domain","yes.example"}},2},{ProgramActionKind::route,1}},
        {RuleSet{{},2},{ProgramActionKind::sniff}}
    };
    auto ordered=RouteProgram::compile(deferred,2);if(!ordered)return 24;
    auto uncertain=ordered->preflight({.explicit_domain="no.example"});
    auto definite=ordered->preflight({.explicit_domain="yes.example"});
    auto skipped=ordered->preflight({.explicit_domain="no.example",.ip="192.0.2.1"});
    auto ended=ordered->preflight({},deferred.size());
    if(!uncertain || uncertain->kind!=ProgramPreflightKind::uncertain || uncertain->rule_index!=0 ||
        !definite || definite->kind!=ProgramPreflightKind::step || !definite->step || definite->step->action.outbound!=1 ||
        !skipped || skipped->kind!=ProgramPreflightKind::step || !skipped->step || skipped->step->action.kind!=ProgramActionKind::sniff ||
        !ended || ended->kind!=ProgramPreflightKind::exhausted || ordered->preflight({},deferred.size()+1))return 25;
    ProgramCursor cursor;
    auto waiting=cursor.poll(*ordered,{.explicit_domain="no.example"});
    if(!waiting || waiting->kind!=ProgramPreflightKind::uncertain || cursor.index()!=0 || cursor.poll(*program,{}))return 26;
    auto action=cursor.poll(*ordered,{.explicit_domain="no.example",.ip="192.0.2.1"});
    if(!action || !action->step || action->step->action.kind!=ProgramActionKind::sniff || cursor.poll(*ordered,{}))return 27;
    auto stale=*action->step;stale.next_index++;
    if(cursor.complete(stale) || !cursor.complete(*action->step) || cursor.index()!=2)return 28;
    auto end=cursor.poll(*ordered,{});
    if(!end || end->kind!=ProgramPreflightKind::exhausted || !cursor.terminal() || cursor.poll(*ordered,{}))return 29;
    ProgramCursor terminal;
    auto selected=terminal.poll(*ordered,{.explicit_domain="yes.example"});
    if(!selected || !selected->step || !terminal.terminal() || terminal.complete(*selected->step))return 30;
    std::array<ProgramAddress,2> addresses{{{{10,1,2,3},4},{{192,0,2,7},4}}};
    std::vector<ProgramRule> multi{
        {RuleSet{{{"and","",{{"ip-cidr","10.0.0.0/8"},{"ip-cidr","192.0.2.0/24"}}}},2},{ProgramActionKind::route,1}},
        {RuleSet{{},2},{ProgramActionKind::reject}}
    };
    auto multiple=RouteProgram::compile(multi,2);if(!multiple)return 31;
    auto matched=multiple->next({.candidates=std::span<ProgramAddress const>(addresses)});
    auto one=multiple->next({.candidates=std::span<ProgramAddress const>(addresses).first(1)});
    auto none=multiple->preflight({.candidates=std::span<ProgramAddress const>{}});
    auto unresolved=multiple->preflight({});
    if(!matched || !*matched || (**matched).action.outbound!=1 || !one || !*one || (**one).action.kind!=ProgramActionKind::reject ||
       !none || none->kind!=ProgramPreflightKind::step || !none->step || none->step->action.kind!=ProgramActionKind::reject ||
       !unresolved || unresolved->kind!=ProgramPreflightKind::uncertain ||
       multiple->next({.ip="10.1.2.3",.candidates=std::span<ProgramAddress const>(addresses)}))return 32;
    std::vector<ProgramRule> absent_rules{
        {RuleSet{{{"not","",{{"domain","site.example"}}}},2},{ProgramActionKind::route,1},DomainSource::sniffed},
        {RuleSet{{},2},{ProgramActionKind::reject}}
    };
    auto absent_program=RouteProgram::compile(absent_rules,2);if(!absent_program)return 33;
    ProgramInput unknown_name,absent_name;
    absent_name.domain_absent[static_cast<std::size_t>(DomainSource::sniffed)]=true;
    auto unknown_step=absent_program->preflight(unknown_name);
    auto absent_step=absent_program->preflight(absent_name);
    auto absent_next=absent_program->next(absent_name);
    if(!unknown_step || unknown_step->kind!=ProgramPreflightKind::uncertain ||
        !absent_step || !absent_step->step || absent_step->step->action.outbound!=1 ||
        !absent_next || !*absent_next || (**absent_next).action.outbound!=1)return 34;
    absent_name.sniffed_domain="site.example";
    if(absent_program->preflight(absent_name) || absent_program->next(absent_name))return 35;
    std::vector<ProgramRule> skip_rules{
        {RuleSet{{{"domain","first.example"}},2},{ProgramActionKind::reject},DomainSource::sniffed},
        {RuleSet{{},2},{ProgramActionKind::resolve}},
        {RuleSet{{{"domain","second.example"}},2},{ProgramActionKind::route,1},DomainSource::sniffed},
        {RuleSet{{},2},{ProgramActionKind::reject}}
    };
    auto skip_program=RouteProgram::compile(skip_rules,2);if(!skip_program)return 36;
    ProgramCursor selective;
    auto first_unknown=selective.poll(*skip_program,{});
    if(!first_unknown || first_unknown->kind!=ProgramPreflightKind::uncertain || first_unknown->rule_index!=0 ||
        selective.skip_unknown(1) || !selective.skip_unknown(0) || selective.skip_unknown(0))return 37;
    auto resolve=selective.poll(*skip_program,{});
    if(!resolve || !resolve->step || resolve->step->action.kind!=ProgramActionKind::resolve ||
        selective.skip_unknown(2) || !selective.complete(*resolve->step))return 38;
    auto second_unknown=selective.poll(*skip_program,{});
    if(!second_unknown || second_unknown->kind!=ProgramPreflightKind::uncertain || second_unknown->rule_index!=2)return 39;
    auto now_known=selective.poll(*skip_program,{.sniffed_domain="second.example"});
    if(!now_known || !now_known->step || now_known->step->action.outbound!=1 || selective.skip_unknown(2))return 40;
    {
        RuleSet nx_rs{{{"domain-suffix","nxmm.example"}},2};
        auto nx_bin=compile_nxmm(nx_rs);
        if(!nx_bin)return 41;
        auto nx_mm=MmapMatcher::open_bytes(std::move(*nx_bin));
        if(!nx_mm)return 42;
        auto nx_ptr=std::make_shared<MmapMatcher const>(std::move(*nx_mm));
        std::vector<ProgramRule> nx_rules{
            {RuleSet{{},2},{ProgramActionKind::route,1},DomainSource::explicit_target,nx_ptr},
            {RuleSet{{},2},{ProgramActionKind::route,0}}
        };
        auto nx_prog=RouteProgram::compile(nx_rules,2);
        if(!nx_prog)return 43;
        auto hit=nx_prog->next({.explicit_domain="api.nxmm.example"});
        auto miss=nx_prog->next({.explicit_domain="other.invalid"});
        if(!hit || !*hit || (**hit).action.outbound!=1 || !miss || !*miss || (**miss).action.outbound!=0)return 44;
    }
    std::cout << "HTTP/TLS sniff metadata and ordered rule actions passed\n";
}
