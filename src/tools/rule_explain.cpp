import std;
import cli.proxy_providers;
import cli.route_files;
import cli.rule_explain_query;
import config;
import dns.policy;
import platform.ip_address;
import relay;
import rulefile;
import rules;
import rules.rule_input;

namespace {
    namespace config=config;
    namespace rules = ::rules;
    namespace relay = ::relay;
    using namespace cli::explain;

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
            config.masque_outbounds,config.wireguard_outbounds,config.ssh_outbounds,config.naive_outbounds,
            config.openvpn_outbounds,config.openconnect_outbounds,config.tailscale_outbounds,config.tcp_proxy_outbounds);
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
                auto fmt=cli::rule_input_format(ref.file.format);
                auto dec=rules::parse_rule_input(*data,fmt,ref.file.ip_cidr_match_source);
                if (!dec) return std::unexpected("DNS rule-set: "+dec.error().message);
                parsed=std::move(*dec);
            }
            if (!policy::bind_dns_rule_set(config.dns->rules[ref.rule],std::move(*parsed)))
                return std::unexpected("DNS rule-set binding failed");
        }
        policy::DnsContext ctx{.network=q.input.network,.source_port=q.input.source_port,
            .inbound=q.input.inbound,.auth_user=q.input.auth_user,.source_interface=q.input.source_interface,
            .network_type=q.input.network_type,.network_is_expensive=q.input.network_is_expensive,
            .network_is_constrained=q.input.network_is_constrained,.wifi_ssid=q.input.wifi_ssid,
            .wifi_bssid=q.input.wifi_bssid,.default_interface_addresses=q.default_if_addrs,
            .source_uid=q.input.source_uid,.source_gid=q.input.source_gid,.source_user=q.input.source_user,
            .process_name=q.process_name,.process_path=q.input.process_path,.package_name=q.input.package_name,
            .route_mode=q.input.route_mode,.client=q.input.client};
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
        auto dec=policy::select_question_dns_action(config.dns->rules,*domain,q.dns_qtype,config.dns->final,config.dns->disable_cache,ctx);
        if (dec.action==policy::DnsAction::reject)
            return dec.reject_rcode ? ("reject:rcode="+std::to_string(*dec.reject_rcode)) : std::string("reject");
        if (dec.action==policy::DnsAction::predefined) return std::string("predefined");
        if (dec.action==policy::DnsAction::evaluate) return "evaluate:"+server_label(dec.server);
        return server_label(dec.server);
    }

    auto route(config::Config const& config,std::string_view name,std::size_t outbound,bool quiet,ExplainOutcome& out) -> void {
        auto leaf=leaf_name(config,outbound);
        out.action=(outbound==1 ? "reject" : "route");
        out.outbound=leaf.empty() ? "block" : std::string(leaf);
        if (!quiet)
            std::cout << out.action << " configured=" << name << " outbound=" << out.outbound << '\n';
    }

    auto explain_ordered(config::Config const& config,relay::RouteSnapshot const& snapshot,Query const& query,ExplainOutcome& out)
        -> std::expected<void,std::string> {
        auto input=query.input;
        auto const& ordered=*snapshot.ordered;
        auto const& declared=*config.ordered_tcp;
        input.sniffed_domain.reset();
        input.domain_absent[3]=false;
        input.protocol.reset();
        input.tls_ech.reset();
        input.client.reset();
        if (!query.default_if_addrs.empty()) input.default_interface_addresses=query.default_if_addrs;
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
                    if (step.action.udp_disable_domain_unmapping) std::cout << "udp-disable-domain-unmapping=true ";
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
                if (!query.oneline) {
                    std::cout << action;
                    if (step.action.resolve_strategy) std::cout << " strategy=" << rules::dns_rule_strategy_name(*step.action.resolve_strategy);
                    if (step.action.resolve_disable_cache) std::cout << " disable-cache=" << (*step.action.resolve_disable_cache ? "true" : "false");
                    if (step.action.resolve_rewrite_ttl) std::cout << " rewrite-ttl=" << *step.action.resolve_rewrite_ttl;
                    std::cout << '\n';
                }
                break;
            }
            case rules::ProgramActionKind::sniff:
                if (!query.input.sniffed_domain && !query.input.domain_absent[3] && !query.input.protocol && !query.input.client) {
                    out.action="needs-sniff"; out.outbound="unknown";
                    if (!query.oneline) std::cout << "sniff requires protocol or sniffed-domain\n";
                    return {};
                }
                input.sniffed_domain=query.input.sniffed_domain;
                input.domain_absent[3]=query.input.domain_absent[3];
                input.protocol=query.input.protocol;
                input.tls_ech=query.input.tls_ech;
                input.client=query.input.client;
                if (!query.oneline) {
                    std::cout << "sniff";
                    if (step.action.sniff_override_destination) std::cout << " override-destination=true";
                    if (step.action.sniff_timeout_ms) std::cout << " sniff-timeout-ms=" << step.action.sniff_timeout_ms;
                    std::cout << '\n';
                }
                break;
            case rules::ProgramActionKind::route_options:
                if (!query.oneline) {
                    std::cout << "route-options";
                    if (step.action.connect_timeout_ms) std::cout << " connect-timeout-ms=" << step.action.connect_timeout_ms;
                    if (step.action.tls_record_fragment) std::cout << " tls-record-fragment=true";
                    if (step.action.tls_fragment_fallback_delay_ms) std::cout << " tls-fragment-fallback-delay-ms=" << step.action.tls_fragment_fallback_delay_ms;
                    if (step.action.override_address) std::cout << " override-address=" << *step.action.override_address;
                    if (step.action.override_port) std::cout << " override-port=" << step.action.override_port;
                    if (step.action.tcp_prefix_len) std::cout << " tcp-prefix-len=" << unsigned(step.action.tcp_prefix_len);
                    if (step.action.udp_timeout_ms) std::cout << " udp-timeout-ms=" << step.action.udp_timeout_ms;
                    if (step.action.udp_adaptive_timeout) std::cout << " udp-adaptive-timeout=true";
                    if (step.action.udp_disable_domain_unmapping) std::cout << " udp-disable-domain-unmapping=true";
                    std::cout << '\n';
                }
                break;
            }
            if (!cursor.complete(step)) return std::unexpected("invalid rule cursor");
        }
    }

    auto explain_indexed(config::Config const& config,relay::RouteSnapshot const& snapshot,
        Query const& query,ExplainOutcome& out) -> std::expected<void,std::string> {
        auto const& input=query.input;
        rules::MatchInput match{.domain=input.explicit_domain,.ip=input.ip,.port=input.port,.network=input.network,
            .source_ip=input.source_ip,.source_port=input.source_port,.inbound=input.inbound,.auth_user=input.auth_user,
            .protocol=input.protocol,.source_uid=input.source_uid,.process_path=input.process_path,
            .source_interface=input.source_interface,.tls_ech=input.tls_ech,.dscp=input.dscp,
            .source_mac=input.source_mac,.gateway_mac=input.gateway_mac,.route_mode=input.route_mode,
            .network_type=input.network_type,.network_is_expensive=input.network_is_expensive,
            .network_is_constrained=input.network_is_constrained,.wifi_ssid=input.wifi_ssid,
            .wifi_bssid=input.wifi_bssid,
            .default_interface_addresses=query.default_if_addrs.empty() ?
                std::optional<std::span<rules::ProgramAddress const>>{} :
                std::optional<std::span<rules::ProgramAddress const>>{query.default_if_addrs},
            .source_gid=input.source_gid,.source_user=input.source_user,
            .package_name=input.package_name,.client=input.client};
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
    cli::ProxyProviderManager providers;
    auto expanded=providers.prepare_initial(*data,argv[1],true);
    if (!expanded) return fail(expanded.error());
    auto config=config::parse_kdl(*expanded);
    if (!config) return fail(config.error());
    auto inbound=std::ranges::find(config->inbounds,std::string_view(argv[2]),&config::InboundConfig::name);
    if (inbound==config->inbounds.end()) return fail("unknown inbound");
    auto context=parse_query_args(argv[3],argv[4],std::span(argv+5,static_cast<std::size_t>(argc-5)));
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
    constexpr std::string_view check_usage="usage: nexus check [--config|-c <config.kdl> | --config-dir|-C <dir>] [--host-override <file>] [--print-merged]\n";
    if (argc==2 && std::string_view(argv[1])=="--help") { std::cout << check_usage; return 0; }
    std::string path, host_override;
    bool is_dir=false, print_merged=false, has_host_override=false;
    for (int i=1; i<argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg=="--print-merged") { print_merged=true; continue; }
        if (arg=="--config" || arg=="-c" || arg=="--config-dir" || arg=="-C") {
            if (!path.empty() || i+1>=argc || std::string_view(argv[i+1]).empty()) { std::cerr << check_usage; return 2; }
            is_dir=(arg=="--config-dir" || arg=="-C");
            path=argv[++i];
            continue;
        }
        if (arg=="--host-override") {
            if (has_host_override || i+1>=argc || std::string_view(argv[i+1]).empty()) { std::cerr << check_usage; return 2; }
            has_host_override=true;
            host_override=argv[++i];
            continue;
        }
        if (arg.starts_with('-') || !path.empty()) { std::cerr << check_usage; return 2; }
        path=std::string(arg);
    }
    if (path.empty()) { std::cerr << check_usage; return 2; }
    auto fail=[](std::string_view err) { std::cerr << "check: " << err << '\n'; return 1; };
    auto data=cli::read_config_source(path,is_dir,host_override);
    if (!data) return fail(data.error());
    cli::ProxyProviderManager providers;
    auto expanded=providers.prepare_initial(*data,path,true);
    if (!expanded) return fail(expanded.error());
    auto cfg=config::parse_kdl(*expanded);
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
    if (print_merged) {
        std::cout << *expanded;
        if (!expanded->empty() && expanded->back()!='\n') std::cout << '\n';
    } else {
        std::cout << "configuration valid\n";
    }
    return 0;
}
