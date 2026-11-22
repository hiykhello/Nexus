import std;
import cli.route_files;
import config;
import dns.policy;
import http.connect;
import platform.ip_address;
import proxy;
import rulefile;
import rules;
import rules.rule_input;

namespace {
    namespace config=config;
    namespace rules = ::rules;
    namespace proxy=proxy;

    constexpr std::string_view usage=
        "usage: nexus rule explain <config> <inbound> <tcp|udp> <host:port> "
        "[--oneline] [dns-qtype=TYPE] [--expect-outbound=NAME] [--expect-action=ACTION] [--expect-dns=RESULT] "
        "[source-ip=IP] [source-port=PORT] [source-uid=UID] [process-path=PATH] [source-interface=NAME] [resolved-ip=IP] [auth-user=NAME] "
        "[protocol=http|tls|dns|ssh|stun|quic] [tls-ech=true|false] [dscp=0..63] [source-mac=MAC] [gateway-mac=MAC] [sniffed-domain=NAME|-] [fakeip-domain=NAME|-] [reverse-domain=NAME|-]\n";

    struct Query {
        rules::ProgramInput input;
        std::vector<rules::ProgramAddress> resolved;
        std::vector<std::string_view> resolved_text;
        bool oneline=false, show_dns=false;
        std::uint16_t dns_qtype=1;
        std::optional<std::string_view> expect_outbound, expect_action, expect_dns;
    };

    struct ExplainOutcome {
        std::string route_label{"default"};
        std::string action{"route"};
        std::string outbound;
        std::uint32_t udp_timeout_ms=0;
        bool udp_adaptive=false;
        std::optional<rules::Protocol> protocol;
    };

    auto argument_port(std::string_view text) -> std::optional<std::uint16_t> {
        std::uint16_t port=0;
        auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),port);
        if (end==text.data()+text.size() && error==std::errc{} && port) return port;
        return {};
    }

    auto parse_dns_qtype(std::string_view text) -> std::optional<std::uint16_t> {
        std::string up(text);
        for (auto& c : up) c=static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (up=="A") return 1;
        if (up=="NS") return 2;
        if (up=="CNAME") return 5;
        if (up=="SOA") return 6;
        if (up=="PTR") return 12;
        if (up=="MX") return 15;
        if (up=="TXT") return 16;
        if (up=="AAAA") return 28;
        if (up=="SRV") return 33;
        if (up=="SVCB") return 64;
        if (up=="HTTPS") return 65;
        if (up=="ANY") return 255;
        return argument_port(text);
    }

    auto query(std::string_view network,std::string_view authority,std::span<char*> options)
        -> std::expected<Query,std::string> {
        using Kind=http::HostKind;
        auto target=http::parse_destination_authority(authority);
        if (target.status!=http::ConnectStatus::accepted) return std::unexpected("invalid target authority");
        Query result;
        auto& input=result.input;
        if (network=="tcp") input.network=rules::Network::tcp;
        else if (network=="udp") input.network=rules::Network::udp;
        else return std::unexpected("invalid network");
        input.port=target.port;
        if (target.kind==Kind::domain)
            input.explicit_domain=authority.substr(0,authority.find(':'));
        else {
            auto open=authority.starts_with('[');
            input.ip=authority.substr(open ? 1 : 0,authority.rfind(open ? ']' : ':')-(open ? 1 : 0));
            input.domain_absent[0]=true;
        }
        auto domain=[&](std::optional<std::string_view>& slot,std::size_t source,std::string_view value) {
            if (slot || input.domain_absent[source]) return false;
            if (value=="-") {input.domain_absent[source]=true;return true;}
            if (!rules::valid_domain(value)) return false;
            slot=value;
            return true;
        };
        for (std::string_view option : options) {
            if (option=="--oneline") { result.oneline=true; continue; }
            auto separator=option.find('=');
            if (separator==option.npos || separator+1==option.size()) return std::unexpected("expected option=value");
            auto key=option.substr(0,separator);
            auto value=option.substr(separator+1);
            if (key=="--expect-outbound" && !result.expect_outbound) result.expect_outbound=value;
            else if (key=="--expect-action" && !result.expect_action) result.expect_action=value;
            else if (key=="--expect-dns" && !result.expect_dns) { result.expect_dns=value; result.show_dns=true; }
            else if (key=="dns-qtype") {
                auto qt=parse_dns_qtype(value);
                if (!qt) return std::unexpected("invalid dns-qtype");
                result.dns_qtype=*qt; result.show_dns=true;
            } else if (key=="source-ip" && !input.source_ip && ::platform::parse_ip_address(value))
                input.source_ip=value;
            else if (key=="source-port" && !input.source_port && argument_port(value))
                input.source_port=argument_port(value);
            else if (key=="source-uid" && !input.source_uid) {
                input.source_uid=rules::parse_source_uid(value);
                if (!input.source_uid) return std::unexpected("invalid source UID");
            }
            else if (key=="process-path" && !input.process_path && value.starts_with('/') && !value.ends_with('/') && value.size()<=4095)
                input.process_path=value;
            else if (key=="source-interface" && !input.source_interface && rules::valid_source_interface(value))
                input.source_interface=value;
            else if (key=="dscp" && !input.dscp && rules::parse_dscp(value)) input.dscp=rules::parse_dscp(value);
            else if (key=="source-mac" && !input.source_mac && rules::parse_mac(value)) input.source_mac=rules::parse_mac(value);
            else if (key=="gateway-mac" && !input.gateway_mac && rules::parse_mac(value)) input.gateway_mac=rules::parse_mac(value);
            else if (key=="auth-user" && !input.auth_user) input.auth_user=value;
            else if (key=="protocol" && !input.protocol) {
                input.protocol=rules::parse_protocol(value);
                if (!input.protocol) return std::unexpected("invalid protocol");
                if (input.protocol==rules::Protocol::tls_ech) {
                    if (input.tls_ech==false) return std::unexpected("conflicting TLS ECH metadata");
                    input.protocol=rules::Protocol::tls;
                    input.tls_ech=true;
                }
            } else if (key=="tls-ech" && !input.tls_ech && (value=="true" || value=="false")) {
                input.tls_ech=value=="true";
            } else if (key=="sniffed-domain" && domain(input.sniffed_domain,3,value)) {}
            else if (key=="fakeip-domain" && domain(input.fakeip_domain,1,value)) {}
            else if (key=="reverse-domain" && domain(input.reverse_domain,2,value)) {}
            else if (key=="resolved-ip" && input.explicit_domain && result.resolved.size()<64) {
                auto ip=::platform::parse_ip_address(value);
                if (!ip) return std::unexpected("invalid resolved-ip");
                result.resolved.push_back({ip->bytes,ip->size});
                result.resolved_text.push_back(value);
            } else return std::unexpected("invalid or duplicate option "+std::string(key));
        }
        if (input.tls_ech && input.protocol!=rules::Protocol::tls)
            return std::unexpected("tls-ech requires protocol=tls");
        return result;
    }

    auto leaf_name(config::Config const& config,std::size_t outbound) -> std::string_view {
        if (outbound==0) return config.direct_outbound_name;
        if (outbound==1) return config.block_outbound_name ? std::string_view(*config.block_outbound_name) : std::string_view{};
        auto find=[&](auto const&... groups) {
            std::string_view result;
            std::size_t index=2;
            auto visit=[&](auto const& entries) {
                for (auto const& entry : entries)
                    if (index++==outbound) result=entry.name;
            };
            (visit(groups),...);
            return result;
        };
        return find(config.vless_outbounds,config.shadowsocks_outbounds,config.trojan_outbounds,config.anytls_outbounds,
            config.hysteria2_outbounds,config.snell_outbounds,config.shadowtls_outbounds,config.tuic_outbounds,
            config.masque_outbounds,config.wireguard_outbounds,config.tailscale_outbounds,config.tcp_proxy_outbounds);
    }

    auto evaluate_dns_policy(config::Config& config,std::string_view config_path,Query const& q)
        -> std::expected<std::string,std::string> {
        if (!config.dns) return std::string("none");
        auto domain=q.input.explicit_domain ? q.input.explicit_domain
            : q.input.sniffed_domain ? q.input.sniffed_domain
            : q.input.fakeip_domain ? q.input.fakeip_domain
            : q.input.reverse_domain;
        if (!domain) return std::string("none");
        cli::RuleFileInput rinput(config_path,true);
        for (auto const& ref : config.dns->rule_files) {
            std::optional<rules::RuleSet> parsed;
            if (ref.file.inline_rules) parsed=*ref.file.inline_rules;
            else if (!ref.file.url.empty()) {
                rules::RuleSet placeholder{.version=2};
                placeholder.rules.push_back({"domain","remote-placeholder.invalid",{}});
                parsed=std::move(placeholder);
            } else {
                auto data=rinput.read(ref.file.path);
                if (!data) return std::unexpected("DNS rule-set: "+data.error());
                auto fmt=ref.file.format==config::RuleFormat::kdl ? rules::InputFormat::kdl
                    : ref.file.format==config::RuleFormat::beve ? rules::InputFormat::beve : rules::InputFormat::srs;
                auto dec=rules::parse_rule_input(*data,fmt,ref.file.ip_cidr_match_source);
                if (!dec) return std::unexpected("DNS rule-set: "+dec.error().message);
                parsed=std::move(*dec);
            }
            if (!policy::bind_dns_rule_set(config.dns->rules[ref.rule],std::move(*parsed)))
                return std::unexpected("DNS rule-set binding failed");
        }
        policy::DnsContext ctx{.network=q.input.network,.source_port=q.input.source_port,
            .inbound=q.input.inbound,.auth_user=q.input.auth_user,.source_interface=q.input.source_interface};
        std::array<std::uint8_t,16> sip_bytes{};
        if (q.input.source_ip) {
            if (auto p=platform::parse_ip_address(*q.input.source_ip)) {
                sip_bytes=p->bytes;
                ctx.source_ip_bytes=std::span(sip_bytes).first(p->size);
            }
        }
        auto server_label=[&](std::size_t idx) -> std::string {
            return idx<config.dns->servers.size() ? config.dns->servers[idx].name : std::string("unknown");
        };
        for (auto const& rule : config.dns->rules) {
            if (!policy::dns_rule_matches(rule,*domain,q.dns_qtype,ctx)) continue;
            if (rule.action==policy::DnsAction::route_options) continue;
            if (rule.action==policy::DnsAction::reject) return std::string("reject");
            if (rule.action==policy::DnsAction::predefined) return std::string("predefined");
            if (rule.action==policy::DnsAction::evaluate) return "evaluate:"+server_label(rule.server);
            if (rule.action==policy::DnsAction::route) return server_label(rule.server);
        }
        return server_label(config.dns->final);
    }

    auto route(config::Config const& config,std::string_view name,std::size_t outbound,bool quiet,ExplainOutcome& out) -> void {
        auto leaf=leaf_name(config,outbound);
        out.action=(outbound==1 ? "reject" : "route");
        out.outbound=leaf.empty() ? "block" : std::string(leaf);
        if (!quiet)
            std::cout << out.action << " configured=" << name << " outbound=" << out.outbound << '\n';
    }

    auto explain_ordered(config::Config const& config,proxy::RouteSnapshot const& snapshot,Query const& query,ExplainOutcome& out)
        -> std::expected<void,std::string> {
        auto input=query.input;
        auto const& ordered=*snapshot.ordered;
        auto const& declared=*config.ordered_tcp;
        input.sniffed_domain.reset();
        input.domain_absent[3]=false;
        input.protocol.reset();
        input.tls_ech.reset();
        rules::ProgramCursor cursor;
        auto apply_route=[&](std::string_view name,std::size_t action) {
            route(config,name,snapshot.matcher.choose_outbound(action,input.explicit_domain.value_or(input.ip.value_or(""))),query.oneline,out);
        };
        for (;;) {
            auto next=cursor.poll(ordered.program,input);
            if (!next) return std::unexpected(next.error().message);
            if (next->kind==rules::ProgramPreflightKind::exhausted) {
                if (input.explicit_domain && !input.candidates && query.resolved.empty()) {
                    out.action="needs-resolve"; out.outbound="unknown";
                    if (!query.oneline) std::cout << "requires resolved-ip before dialing\n";
                    return {};
                }
                out.route_label="default"; out.protocol=input.protocol;
                if (!query.oneline) std::cout << "default ";
                apply_route(config.default_outbound_name,ordered.fallback);
                return {};
            }
            auto const& configured=declared.rules[next->rule_index];
            auto label=[&] {
                if (query.oneline) return;
                std::cout << "rule=" << next->rule_index+1;
                if (configured.file) std::cout << " file=" << std::quoted(configured.file->path);
                std::cout << ' ';
            };
            if (next->kind==rules::ProgramPreflightKind::uncertain) {
                label();
                if (!query.oneline) std::cout << (declared.skip_unknown ? "unknown skipped\n" : "requires predicate metadata\n");
                if (!declared.skip_unknown) { out.action="needs-metadata"; out.outbound="unknown"; return {}; }
                if (!cursor.skip_unknown(next->rule_index)) return std::unexpected("invalid rule cursor");
                continue;
            }
            label();
            auto step=*next->step;
            if (step.action.udp_timeout_ms) out.udp_timeout_ms=step.action.udp_timeout_ms;
            if (step.action.udp_adaptive_timeout) out.udp_adaptive=true;
            switch (step.action.kind) {
            case rules::ProgramActionKind::route:
                if (step.action.outbound!=1 && input.explicit_domain && !input.candidates && query.resolved.empty()) {
                    auto leaf=snapshot.matcher.choose_outbound(step.action.outbound,*input.explicit_domain);
                    if (leaf!=1) {
                        out.action="needs-resolve"; out.outbound="unknown";
                        if (!query.oneline) std::cout << "requires resolved-ip before dialing\n";
                        return {};
                    }
                }
                out.route_label="rule:"+std::to_string(next->rule_index+1);
                out.protocol=input.protocol;
                if (!query.oneline) {
                    if (configured.action==config::OrderedTcpAction::bypass) std::cout << "bypass ";
                    if (step.action.connect_timeout_ms) std::cout << "connect-timeout-ms=" << step.action.connect_timeout_ms << ' ';
                    if (step.action.udp_timeout_ms) std::cout << "udp-timeout-ms=" << step.action.udp_timeout_ms << ' ';
                    if (step.action.udp_adaptive_timeout) std::cout << "udp-adaptive-timeout=true ";
                }
                apply_route(*configured.outbound_name,step.action.outbound);
                if (configured.action==config::OrderedTcpAction::bypass) out.action="bypass";
                return {};
            case rules::ProgramActionKind::bypass:
                return std::unexpected("bypass requires kernel pre-match");
            case rules::ProgramActionKind::reject:
                out.route_label="rule:"+std::to_string(next->rule_index+1);
                out.action="reject"; out.outbound="reject";
                if (!query.oneline) {
                    std::cout << "reject";
                    if (step.action.reject_method==rules::RejectMethod::drop) std::cout << " method=drop";
                    if (step.action.reject_no_drop) std::cout << " no-drop=true";
                    std::cout << '\n';
                }
                return {};
            case rules::ProgramActionKind::hijack_dns:
                out.route_label="rule:"+std::to_string(next->rule_index+1);
                out.action="hijack-dns"; out.outbound="dns";
                if (!query.oneline) std::cout << "hijack-dns\n";
                return {};
            case rules::ProgramActionKind::resolve: {
                auto action=step.action.route_only ? "resolve(route-only)" : "resolve";
                if (input.explicit_domain && query.resolved.empty()) {
                    out.action="needs-resolve"; out.outbound="unknown";
                    if (!query.oneline) std::cout << action << " requires resolved-ip\n";
                    return {};
                }
                if (input.explicit_domain) input.candidates=std::span(query.resolved);
                if (!query.oneline) std::cout << action << '\n';
                break;
            }
            case rules::ProgramActionKind::sniff:
                if (!query.input.sniffed_domain && !query.input.domain_absent[3] && !query.input.protocol) {
                    out.action="needs-sniff"; out.outbound="unknown";
                    if (!query.oneline) std::cout << "sniff requires protocol or sniffed-domain\n";
                    return {};
                }
                input.sniffed_domain=query.input.sniffed_domain;
                input.domain_absent[3]=query.input.domain_absent[3];
                input.protocol=query.input.protocol;
                input.tls_ech=query.input.tls_ech;
                if (!query.oneline) std::cout << "sniff\n";
                break;
            case rules::ProgramActionKind::route_options:
                if (!query.oneline) {
                    std::cout << "route-options";
                    if (step.action.connect_timeout_ms) std::cout << " connect-timeout-ms=" << step.action.connect_timeout_ms;
                    if (step.action.tls_record_fragment) std::cout << " tls-record-fragment=true";
                    if (step.action.tcp_prefix_len) std::cout << " tcp-prefix-len=" << unsigned(step.action.tcp_prefix_len);
                    if (step.action.udp_timeout_ms) std::cout << " udp-timeout-ms=" << step.action.udp_timeout_ms;
                    if (step.action.udp_adaptive_timeout) std::cout << " udp-adaptive-timeout=true";
                    std::cout << '\n';
                }
                break;
            }
            if (!cursor.complete(step)) return std::unexpected("invalid rule cursor");
        }
    }

    auto explain_indexed(config::Config const& config,proxy::RouteSnapshot const& snapshot,
        Query const& query,ExplainOutcome& out) -> std::expected<void,std::string> {
        auto const& input=query.input;
        rules::MatchInput match{.domain=input.explicit_domain,.ip=input.ip,.port=input.port,.network=input.network,
            .source_ip=input.source_ip,.source_port=input.source_port,.inbound=input.inbound,.auth_user=input.auth_user,.source_uid=input.source_uid,.process_path=input.process_path,.source_interface=input.source_interface,
            .dscp=input.dscp,.source_mac=input.source_mac,.gateway_mac=input.gateway_mac};
        if (match.domain && query.resolved.empty()) {
            auto preflight=snapshot.matcher.preflight(match);
            if (!preflight) return std::unexpected(preflight.error().message);
            if (*preflight!=1) {
                out.action="needs-resolve"; out.outbound="unknown";
                if (!query.oneline) std::cout << "requires resolved-ip before dialing\n";
                return {};
            }
        }
        auto show=[&](rules::MatchInput candidate) -> std::expected<void,std::string> {
            auto found=snapshot.matcher.match_with_rule(candidate);
            if (!found) return std::unexpected(found.error().message);
            if (found->rule) {
                auto const& rule=config.routes[*found->rule];
                out.route_label="rule:"+std::to_string(*found->rule+1);
                if (!query.oneline)
                    std::cout << "rule=" << *found->rule+1 << " file=" << std::quoted(rule.file.path)
                        << " predicate=" << *found->predicate+1 << ' ';
                route(config,rule.outbound_name,found->outbound,query.oneline,out);
                return {};
            }
            out.route_label="default";
            if (!query.oneline) std::cout << "default ";
            route(config,config.default_outbound_name,found->outbound,query.oneline,out);
            return {};
        };
        if (query.resolved.empty()) return show(match);
        for (auto text : query.resolved_text) {
            if (!query.oneline) std::cout << "candidate=" << text << ' ';
            match.ip=text;
            auto result=show(match);
            if (!result) return result;
        }
        return {};
    }
}

auto nexus_rule_explain(int argc,char** argv) -> int {
    if (argc==2 && std::string_view(argv[1])=="--help") { std::cout << usage; return 0; }
    if (argc<5) { std::cerr << usage; return 2; }
    auto fail=[](std::string_view error) { std::cerr << "rule explain: " << error << '\n'; return 1; };
    auto data=::rulefile::read_regular_file(argv[1]);
    if (!data) return fail(data.error());
    auto config=config::parse_kdl(*data);
    if (!config) return fail(config.error());
    auto inbound=std::ranges::find(config->inbounds,std::string_view(argv[2]),&config::InboundConfig::name);
    if (inbound==config->inbounds.end()) return fail("unknown inbound");
    auto context=query(argv[3],argv[4],std::span(argv+5,static_cast<std::size_t>(argc-5)));
    if (!context) return fail(context.error());
    context->input.inbound=inbound->name;
    context->input.dns_hijack_tcp=inbound->tun && inbound->tun->dns_hijack_tcp;
    using Inbound=config::Inbound;
    if (inbound->type==Inbound::masque ||
        (inbound->type==Inbound::tun && inbound->tun && inbound->tun->connect_ip_outbound))
        return fail("inbound uses its own routing policy");
    auto files=cli::load_route_files(*config,argv[1],true);
    if (!files) return fail(files.error());
    auto routes=cli::project_routes(*config,*files);
    auto snapshot=routes.compile(*config,inbound->name);
    if (!snapshot) return fail(snapshot.error());
    std::string dns_outcome="none";
    if (context->oneline || context->show_dns) {
        auto dns_res=evaluate_dns_policy(*config,argv[1],*context);
        if (!dns_res) return fail(dns_res.error());
        dns_outcome=std::move(*dns_res);
    }
    ExplainOutcome out{};
    auto ordered=snapshot->ordered && (context->input.network==rules::Network::tcp || snapshot->ordered->udp);
    auto result=ordered ? explain_ordered(*config,*snapshot,*context,out) : explain_indexed(*config,*snapshot,*context,out);
    if (!result) return fail(result.error());
    if (context->oneline) {
        std::cout << "dns=" << dns_outcome << " route=" << out.route_label
            << " action=" << out.action << " outbound=" << out.outbound;
        if (context->input.network==rules::Network::udp) {
            if (out.udp_timeout_ms) std::cout << " udp-timeout-ms=" << out.udp_timeout_ms;
            else if (out.udp_adaptive)
                std::cout << " udp-timeout-ms=" << rules::adaptive_udp_timeout_ms(out.protocol,context->input.port.value_or(0),60000);
        }
        std::cout << '\n';
    } else if (context->show_dns) {
        std::cout << "dns=" << dns_outcome << '\n';
    }
    if (context->expect_dns && dns_outcome!=*context->expect_dns)
        return fail("expected dns="+std::string(*context->expect_dns)+" got "+dns_outcome);
    if (context->expect_action && out.action!=*context->expect_action)
        return fail("expected action="+std::string(*context->expect_action)+" got "+out.action);
    if (context->expect_outbound && out.outbound!=*context->expect_outbound)
        return fail("expected outbound="+std::string(*context->expect_outbound)+" got "+out.outbound);
    return 0;
}

auto nexus_check(int argc,char** argv) -> int {
    constexpr std::string_view check_usage="usage: nexus check [--config|-c <config.kdl> | --config-dir|-C <dir>]\n";
    if (argc==2 && std::string_view(argv[1])=="--help") { std::cout << check_usage; return 0; }
    char const* path=nullptr;
    bool is_dir=false;
    if (argc==2) path=argv[1];
    else if (argc==3 && (std::string_view(argv[1])=="--config" || std::string_view(argv[1])=="-c")) path=argv[2];
    else if (argc==3 && (std::string_view(argv[1])=="--config-dir" || std::string_view(argv[1])=="-C")) { path=argv[2]; is_dir=true; }
    else { std::cerr << check_usage; return 2; }
    auto fail=[](std::string_view err) { std::cerr << "check: " << err << '\n'; return 1; };
    auto data=cli::read_config_source(path,is_dir);
    if (!data) return fail(data.error());
    auto cfg=config::parse_kdl(*data);
    if (!cfg) return fail(cfg.error());
#ifndef NEXUS_ENABLE_NTP
    if (cfg->ntp) return fail("NTP is not available in this build");
#endif
    auto files=cli::load_route_files(*cfg,path,true);
    if (!files) return fail(files.error());
    auto routes=cli::project_routes(*cfg,*files);
    for (auto const& in : cfg->inbounds) {
        if (in.type==config::Inbound::masque || (in.type==config::Inbound::tun && in.tun && in.tun->connect_ip_outbound)) continue;
        if (auto snap=routes.compile(*cfg,in.name); !snap) return fail(snap.error());
    }
    std::cout << "configuration valid\n";
    return 0;
}
