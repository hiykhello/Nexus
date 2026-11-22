// Candidate ownership spans the entire reload, including optional DNS sockets.
#pragma once
namespace cli::run_detail {
    struct ListenerReloadRuntime {
        std::vector<Listener>& listeners;
        std::optional<config::Config>& config;
        std::unique_ptr<proxy::SharedDnsGeneration>& dns;
        DnsMessageRuntime& messages;
        std::shared_ptr<proxy::RouteSnapshots>& routes;
        std::optional<RouteFiles>& group_files;
        std::shared_ptr<proxy::SnellReplayRegistry>& replay;
        std::shared_ptr<::platform::network::Monitor>& network;
        std::string& identity;
        logging::Runtime const& log;
        std::shared_ptr<dns::ReverseCache>& reverse_cache;
        RemoteRulesetManager& remote_rulesets;
    };

    struct ListenerReload {
        std::string process_identity,dns_policy_identity;
        std::shared_ptr<proxy::TcpAdmission> tcp_admission;
        proxy::PrincipalRegistry principals;
        std::uint64_t listener_generation=1;
        std::vector<std::unique_ptr<RetiredTcpGeneration>> retired_tcp;
        std::chrono::milliseconds listener_grace{};

        template<class UdpRuntime>
        auto apply(ListenerReloadRuntime running,std::string_view path,std::string_view input,
            std::string identity,bool traffic_stats,bool automatic_groups,std::shared_ptr<UdpRuntime>& udp,
            std::span<SelectorChoice const> choices)
            -> std::expected<void,std::string> {
            auto [listeners,reload_config,dns_generation,dns_messages,route_snapshots,group_route_files,
                snell_replay,network,reload_identity,log,reverse_cache,remote_rulesets]=running;
            auto workers=reload_config->workers;
            using config::ReloadIdentity;
            auto key=config::reload_identity(input,ReloadIdentity::process);
            if (!key) return std::unexpected(std::move(key.error()));
            if (*key!=process_identity) return std::unexpected("configuration change requires restart");
            auto dns_key=config::reload_identity(input,ReloadIdentity::dns_policy);
            if (!dns_key) return std::unexpected(std::move(dns_key.error()));
            auto config=config::parse_kdl(input);
            if (!config) return std::unexpected(std::move(config.error()));
            config->direct_tcp_options.binding.network=reload_config->direct_tcp_options.binding.network;
            if (!reloadable_tcp(*config)) return std::unexpected("listener change requires restart");
            if (automatic_groups || !choices.empty()) {
                auto wanted=*config;
                auto restored=overlay_selector_state(wanted,choices);
                if (!restored) return restored;
                for (auto& group : wanted.selectors) {
                    if (group.mode==config::OutboundGroupMode::select) continue;
                    auto running=std::ranges::find(reload_config->selectors,group.name,&config::OutboundSelector::name);
                    if (running!=reload_config->selectors.end()) group.selected=running->selected;
                }
                config=config::reselect_outbounds(*config,wanted);
                if (!config) return std::unexpected(std::move(config.error()));
            }
            RuleFileInput rule_input(path);
            remote_rulesets.seed_cached(rule_input);
            if (config->dns) {
                auto loaded=load_dns_rules(*config->dns,rule_input);
                if (!loaded) return std::unexpected(std::move(loaded.error()));
            }
            auto protections=cli::prepare_dns_transports(*config);
            if (!protections) return std::unexpected(std::move(protections.error()));
            auto files=cli::load_route_files(*config,rule_input);
            if (!files) return std::unexpected(std::move(files.error()));
            auto indexed=files->indexed(*config);
            TcpGeneration candidate;
            auto candidate_replay=snell_replay;
            auto candidate_udp=std::make_shared<UdpRuntime>();
            auto next=listener_generation+1;
            candidate_udp->stage_admission(udp.get(),next);
            candidate_udp->resize(config->inbounds.size(),std::ranges::any_of(config->inbounds,[](auto const& entry) {
                return entry.shadowsocks.has_value();
            }));
            auto has_udp=uses_native_udp(*config);
            auto native_readers=native_udp_dns_readers(*config);
            auto tcp_readers=config->inbounds.size()*workers;
            candidate.listeners.reserve(config->inbounds.size());
            candidate.dns=std::make_unique<proxy::SharedDnsGeneration>(
                config->inbounds.size()+has_udp,tcp_readers+native_readers,
                config->dns ? config->dns->optimistic_cache_seconds : 0);
            if (route_snapshots || uses_dns_groups(config->dns) ||
                (config->dns && (!config->dns->rule_files.empty() || config->dns->fakeip))) {
                candidate.routes=std::make_shared<proxy::RouteSnapshots>();
                if (route_snapshots)
                    candidate.routes->store(route_snapshots->load(std::memory_order_acquire),std::memory_order_relaxed);
            }
            auto candidate_reverse=config->dns && config->dns->reverse_mapping ?
                (reverse_cache ? reverse_cache : make_reverse_cache()) : std::shared_ptr<dns::ReverseCache>{};
            if ((config->dns && config->dns->listen) || dns_messages.has_listeners()) {
                candidate.messages=std::make_unique<cli::DnsMessageRuntime>(log);
                if (config->dns) {
                    auto prepared=candidate.messages->prepare(*config,*protections,
                        dns_rule_source(candidate.routes),&dns_messages,candidate_reverse);
                    if (!prepared) return std::unexpected("DNS listener: "+prepared.error());
                }
            }
            auto observe_neighbors=std::ranges::any_of(config->inbounds,uses_transparent_metadata);
            auto monitor=network;
            if (!monitor && observe_neighbors)
                monitor=std::make_shared<::platform::network::Monitor>(true);
            for (auto const& entry : config->inbounds) {
                auto server=proxy::Server::create();
                if (!server) return std::unexpected(server.error().message());
                if (uses_transparent_metadata(entry)) (*server)->set_network_monitor(monitor);
                auto index=candidate.listeners.size();
                auto remember=[&](std::span<std::uint8_t const> key,std::span<proxy::ShadowsocksUserKey const> users) {
                    candidate_udp->remember(index,key,users);
                };
                if (auto result=configure_listener(**server,*config,entry,*protections,*files,indexed,
                        candidate_replay,remember,principals); !result)
                    return std::unexpected("invalid TCP listener "+entry.name+": "+result.error());
                if (auto pipes=config->tcp_splice_pipes.value_or(0); pipes && !(*server)->set_tcp_splice_pipes(pipes))
                    return std::unexpected("cannot configure TCP splice");
                auto packet_slots=has_udp && entry.shadowsocks ? 64u : 0u;
                if (traffic_stats && !(*server)->enable_traffic_stats(packet_slots))
                    return std::unexpected("cannot enable traffic statistics");
                if (auto bound=(*server)->bind_shared_dns(*candidate.dns,index,index*workers); !bound)
                    return std::unexpected("DNS shared setup: "+bound.error().message());
                if (candidate.routes && !(*server)->set_route_snapshots(candidate.routes,index))
                    return std::unexpected("cannot initialize traffic route snapshots");
#ifdef NEXUS_ENABLE_FAKEIP
                if (auto owner=candidate.messages ? candidate.messages->fakeip() : nullptr;
                    owner && !(*server)->set_fakeip(std::move(owner),0)) return std::unexpected("cannot configure FakeIP");
#endif
                if (candidate_reverse && !(*server)->set_reverse_cache(candidate_reverse))
                    return std::unexpected("cannot configure reverse DNS cache");
                auto listener=make_listener(std::move(*server),entry);
                listener.packet_slots=packet_slots;
                candidate.listeners.push_back(std::move(listener));
            }
            if (auto result=configure_native_udp(*candidate_udp,*config,*files,candidate.listeners,*protections,traffic_stats);
                !result) return result;
            if (has_udp && !candidate_udp->bind_shared_dns(*candidate.dns,candidate.listeners.size(),tcp_readers))
                return std::unexpected("DNS UDP shared setup failed");
            candidate.dns->seal();
            if (candidate.routes) {
                auto compiled=publish_group_routes(candidate.listeners,*candidate.routes,*config,*files,
                    *dns_key!=dns_policy_identity || (config->dns && !config->dns->rule_files.empty()));
                if (!compiled) return compiled;
            }
            for (auto& listener : candidate.listeners) {
                auto previous=std::ranges::find_if(listeners,[&](auto const& item) {
                    return same_tcp_binding(listener,item);
                });
                auto staged=listener.server->stage_tcp(tcp_admission,next,listener.port,listener.inbound,workers,
                    listener.ipv6,listener.address,previous==listeners.end() ? nullptr : previous->server.get());
                if (!staged)
                    return std::unexpected(std::format("cannot stage TCP port {}: {}",listener.port,staged.error().message()));
                listener.port=*staged;
            }
            auto reuse_dns_binding=candidate.messages && dns_messages.same_binding(*candidate.messages);
            if (candidate.messages && !reuse_dns_binding) {
                auto started=candidate.messages->start(false);
                if (!started) return started;
            }
            if (auto started=candidate_udp->start(); !started) return started;
            auto retired=std::make_unique<RetiredTcpGeneration>();
            if (udp->has_listeners())
                retired->poll_udp=[previous=udp] {
                    previous->poll();
                    return previous->idle();
                };
            retired_tcp.reserve(retired_tcp.size()+1);
            if (stopped.load(std::memory_order_relaxed) || !candidate_udp->healthy() || (candidate.messages && !candidate.messages->healthy()) ||
                !std::ranges::all_of(candidate.listeners,[](auto const& item) {return item.server->healthy();}))
                return std::unexpected("TCP publication canceled");
            if (!tcp_admission->publish(next,[&]() noexcept {
                    auto now=std::chrono::steady_clock::now();
                    for (auto const& listener:candidate.listeners) listener.server->publish_principal_bytes(now);
                })) return std::unexpected("cannot publish TCP listeners");
            if (observe_neighbors) monitor->enable_neighbors();
            network=std::move(monitor);
            listener_generation=next;
            candidate_udp->publish_admission();
            udp=std::move(candidate_udp);
            retired->deadline=std::chrono::steady_clock::now()+listener_grace;
            for (auto& listener : listeners) listener.server->begin_drain();
            retired->listeners.swap(listeners);
            retired->dns=std::move(dns_generation);
            if (reuse_dns_binding) dns_messages.replace_program(*candidate.messages);
            else if (candidate.messages) {
                dns_messages.swap(*candidate.messages);
                dns_messages.admit();
                candidate.messages->begin_drain();
                retired->messages=std::move(candidate.messages);
            }
            retired_tcp.push_back(std::move(retired));
            listeners.swap(candidate.listeners);
            dns_generation=std::move(candidate.dns);
            route_snapshots=std::move(candidate.routes);
            reload_identity=std::move(identity);
            dns_policy_identity=std::move(*dns_key);
            snell_replay=std::move(candidate_replay);
            reverse_cache=std::move(candidate_reverse);
            reload_config=std::move(*config);
            if (group_route_files) *group_route_files=std::move(*files);
            return {};
        }
    };
}
