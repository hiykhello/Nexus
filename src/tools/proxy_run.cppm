module;
#include <csignal>

export module cli.proxy_run;
import std;
import utility;
import functional;
import corosio;
import rulefile;
import state.core;
import state.file;
import logging;
import logging.cli;
import relay;
import relay.host;
import relay.principal_limits;
import platform.network_state;
import platform.network_selection;
import platform.socket_options;
import rules;
import rules.rule_input;
import state.dns_cache;
import state.ruleset_cache;
import state.maintenance;
import platform.ip_address;
import encoding.base64_key;
import config;
import cli.dns_transports;
import dns.corosio_query;
import dns.corosio_local;
import dns.local_config;
import cli.dns_message_runtime;
import dns.message_program;
import cli.control;
import control_api;
import control_api.types;
import cli.outbounds;
import cli.route_files;
import cli.proxy_ntp;
import cli.proxy_providers;
import cli.proxy_services;
import http.connect;
import socks5;
export import cli.proxy_run_state;
export import cli.proxy_group_health;
export import cli.proxy_outbound_probe;
export import cli.proxy_listener;
export import cli.proxy_log;
export import cli.proxy_host;
export import cli.proxy_control_wake;
export import cli.proxy_dns_reload;
export import cli.proxy_selector_state;
export import cli.proxy_listener_reload;
export import cli.proxy_tun_reload;
export import cli.proxy_control_operations;
export import cli.proxy_mode;
export import cli.proxy_control;
export import cli.proxy_http_control;

export namespace cli {
    inline auto request_proxy_stop() noexcept -> void { run_detail::stopped.store(true, std::memory_order_relaxed); run_detail::notify_proxy_wakeup(); }
    inline auto request_proxy_reload() noexcept -> void { run_detail::reload_requested.store(true, std::memory_order_relaxed); run_detail::notify_proxy_wakeup(); }
    inline auto reset_proxy_signals() noexcept -> void { run_detail::stopped.store(false, std::memory_order_relaxed); run_detail::reload_requested.store(false, std::memory_order_relaxed); run_detail::traffic_requested.store(false, std::memory_order_relaxed); }
}

using namespace cli::run_detail;

export template<class UdpRuntime,class Hy2Runtime,class MasqueRuntime,class TuicRuntime,class TunRuntime>
auto nexus_run_proxy(int argc, char** argv, bool install_signals = true) -> int {
    cli::ensure_http_fetchers_registered();
    auto parsed_args = parse_run_args(argc, argv);
    if (!parsed_args) return parsed_args.error();
    if (parsed_args->help) return 0;
    auto const& run_args = *parsed_args;
    bool traffic_stats = run_args.traffic_stats, is_cfg = run_args.is_cfg, config_is_dir = run_args.config_is_dir;
    unsigned port = run_args.port, workers = 1;
    std::chrono::milliseconds shutdown_grace{};
    auto inbound = relay::Inbound::socks5;
    logging::Runtime logs;
    auto created = relay::Server::create();
    if (!created) { std::cerr << "cannot initialize proxy: " << created.error().message() << '\n'; return 1; }
    std::unique_ptr<corosio::io_context> shared_io;
    std::unique_ptr<relay::SharedDnsGeneration> dns_generation; std::shared_ptr<relay::SnellReplayRegistry> snell_replay;
    std::vector<Listener> listeners; std::vector<std::string> route_outbound_names{"direct","block"};
    std::optional<config::Config> reload_config; std::string reload_identity, reload_source;
    ListenerReload listener_reload; TunLiveReload tun_live_reload; AdHocOutboundProber outbound_prober;
    std::shared_ptr<relay::RouteSnapshots> route_snapshots;
    std::shared_ptr<dns::ReverseCache> reverse_cache; RemoteRulesetManager remote_rulesets; cli::ProxyProviderManager proxy_providers;
    std::optional<OutboundGroupHealth> group_health; std::optional<cli::RouteFiles> group_route_files;
    std::string_view reload_unavailable="no traffic rule files configured"; cli::DnsMessageRuntime dns_messages(logs);
    cli::LocalControl control; control_api::HttpControlServer http_control;
    std::optional<config::ControlHttpConfig> control_http_config;
    std::optional<config::NtpConfig> ntp_config; config::ServicesConfig services_config{};
    cli::NtpRuntime ntp_runtime; cli::OptionalServicesRuntime services_runtime;
    std::shared_ptr<relay::ShadowsocksUserDirectory> ssmapi_users;
    cli::SelectorState selector_state;
    std::shared_ptr<::platform::network::Monitor> network;
    std::string control_socket;
    std::optional<std::uint32_t> control_read_uid;
    ControlOperations control_operations; RuntimeRouteModeController route_mode;
    auto udp=std::make_shared<UdpRuntime>(); Hy2Runtime hy2; TuicRuntime tuic; TunRuntime tun;
#if BOOST_COROSIO_HAVE_LIBURING
    MasqueRuntime masque{true};
#else
    MasqueRuntime masque{false};
#endif
    listeners.push_back({std::move(*created),static_cast<std::uint16_t>(port),inbound});
    auto& server=*listeners.front().server;
    if (!run_args.rule_path.empty()) {
        std::string_view format = run_args.rule_format;
        auto input = ::rulefile::read_regular_file(run_args.rule_path);
        if (!input) { std::cerr << input.error() << '\n'; return 1; }
        auto result = server.set_block_rules(*input, format == "kdl" ? relay::RuleFormat::kdl :
            format == "beve" ? relay::RuleFormat::beve : format == "srs" ? relay::RuleFormat::srs : relay::RuleFormat::nxmm);
        if (!result) { std::cerr << "invalid block rules: " << result.error() << '\n'; return 1; }
    } else if (is_cfg) {
        auto input = cli::read_config_source(run_args.config_path, config_is_dir, run_args.host_override_path);
        if (!input) { std::cerr << "configuration: " << input.error() << '\n'; return 1; }
        auto expanded = proxy_providers.prepare_initial(*input, run_args.config_path, true);
        if (!expanded) { std::cerr << "configuration: " << expanded.error() << '\n'; return 1; }
        input = std::move(*expanded);
        reload_source = *input;
        auto config = config::parse_kdl(*input);
        if (!config) { std::cerr << "configuration: " << config.error() << '\n'; return 1; }
        if (auto ok = protect_host_override_path(config->log_protected_paths, run_args.host_override_path); !ok) {
            std::cerr << "configuration: " << ok.error() << '\n'; return 1;
        }
        auto log_start=logs.start(config->log.value_or(logging::Config{}),run_args.config_path,config->log_protected_paths);
        if (!log_start) { std::cerr << "configuration: " << log_start.error() << '\n'; return 1; }
        if (config->state) for (auto const* root:{&config->state->directory,&config->state->cache_directory}) {
            if (root->empty()) continue;
            auto created=::state::ensure_private_directory(*root);
            if (!created) return log_failure(logs,logging::Domain::core,"state directory",::state::describe(created.error().stage));
        }
        auto restored=initialize_selector_state(selector_state,*config);
        if (!restored) {return log_failure(logs,logging::Domain::core,"proxy configuration failed",restored.error());}
        if (reloadable_tcp(*config)) {
            listener_reload.tcp_admission=std::make_shared<relay::TcpAdmission>();
            udp->stage_admission(nullptr,1);
            listener_reload.listener_grace=std::chrono::milliseconds(config->shutdown_grace_ms.value_or(5000));
        }
        workers=config->workers;
        control_socket=config->control_socket;
        control_read_uid=config->control_read_uid;
        control_http_config=config->control_http;
        ntp_config=config->ntp; services_config=config->services;
        auto observe_neighbors=std::ranges::any_of(config->inbounds,uses_transparent_metadata);
        if (config->direct_network || !control_socket.empty() || observe_neighbors)
            network=std::make_shared<::platform::network::Monitor>(observe_neighbors);
        if (config->direct_network) {
            auto& binding=config->direct_tcp_options.binding;
            binding.network=std::make_shared<::platform::network::InterfaceSelection>(
                ::platform::network::SystemInterfaceSelection(network,*config->direct_network,binding));
        }
        shutdown_grace=std::chrono::milliseconds(config->shutdown_grace_ms.value_or(0));
        cli::RuleFileInput rule_input(run_args.config_path);
        if (auto fetched=remote_rulesets.fetch_initial(*config,*input,rule_input); !fetched)
            return log_failure(logs,logging::Domain::route,"remote rule-set failed",fetched.error());
        if (config->dns) {
            auto loaded=load_dns_rules(*config->dns,rule_input);
            if (!loaded) {return log_failure(logs,logging::Domain::core,"proxy configuration failed",loaded.error());}
            if (config->dns->reverse_mapping) reverse_cache=make_reverse_cache();
        }
        auto dns_transports=cli::prepare_dns_transports(*config);
        if(!dns_transports) {return log_failure(logs,logging::Domain::core,"proxy configuration failed",dns_transports.error());}
        if(auto supported=hy2.configure_outbound(*config);!supported){return log_failure(logs,logging::Domain::core,"proxy configuration failed",supported.error());}
        hy2.resize(config->inbounds.size());masque.resize(config->inbounds.size());tuic.resize(config->inbounds.size());tun.resize(config->inbounds.size());
        if (auto ok = init_run_listeners(*config, workers, listeners, shared_io); !ok)
            return log_failure(logs,logging::Domain::core,"cannot initialize proxy",ok.error());
        if (auto pipes=config->tcp_splice_pipes.value_or(default_tcp_splice_pipes()); pipes && !configure_splice(listeners,pipes)) {
            return log_failure(logs,logging::Domain::core,"cannot configure TCP splice");
        }
        auto route_files=cli::load_route_files(*config,rule_input);
        if(!route_files) {return log_failure(logs,logging::Domain::core,"routing rules",route_files.error());}
        auto indexed_routes=route_files->indexed(*config);
        udp->resize(listeners.size(),std::ranges::any_of(config->inbounds,[](auto const& entry) { return entry.shadowsocks.has_value(); }));
        auto configure=[&](relay::Server& server, std::size_t index) -> int {
            auto const& entry=config->inbounds[index];
            if (uses_transparent_metadata(entry)) server.set_network_monitor(network);
            auto remember=[&](std::span<std::uint8_t const> key,std::span<relay::ShadowsocksUserKey const> users) {
                udp->remember(index,key,users);
            };
            if (auto result=configure_listener(server,*config,entry,*dns_transports,*route_files,indexed_routes,
                    snell_replay,remember,listener_reload.principals); !result)
                return log_failure(logs,logging::Domain::proxy,"listener configuration failed",result.error());
            if(auto configured=hy2.configure(index,entry);!configured){return log_failure(logs,logging::Domain::core,"Hysteria2 configuration",configured.error());}
            if(auto configured=masque.configure(index,entry);!configured){return log_failure(logs,logging::Domain::core,"MASQUE configuration",configured.error());}
            if(auto configured=tuic.configure(index,entry);!configured){return log_failure(logs,logging::Domain::core,"TUIC configuration",configured.error());}
            auto entry_cfg=entry;
            if (entry_cfg.tun) if (auto ok=cli::apply_tun_route_sets(*entry_cfg.tun,*route_files); !ok) return log_failure(logs,logging::Domain::core,"TUN route-set",ok.error());
            if(auto configured=tun.configure(index,entry_cfg,*config);!configured){return log_failure(logs,logging::Domain::core,"TUN configuration",configured.error());}
            if(entry.tun && entry.tun->socket_mark && !config->direct_tcp_options.binding.routing_mark) {
                auto opts=config->direct_tcp_options;opts.binding.routing_mark=entry.tun->socket_mark;
                if(auto ok=server.set_direct_tcp_options(opts);!ok){return log_failure(logs,logging::Domain::core,"configuration",ok.error());}
            }
            return 0;
        };
        for (std::size_t i=0; i<listeners.size(); ++i) if (configure(*listeners[i].server,i)) return 1;
        route_mode.sync(*config); route_mode.attach(listeners);
        auto has_udp=uses_native_udp(*config);
        if (has_udp && (traffic_stats || !control_socket.empty() || control_http_config))
            for (std::size_t index=0;index<listeners.size();++index)
                if (config->inbounds[index].shadowsocks) listeners[index].packet_slots=64;
        if (services_config.ssmapi && services_config.ssmapi->enabled) {
            ssmapi_users=std::make_shared<relay::ShadowsocksUserDirectory>(); udp->set_dynamic_users(ssmapi_users);
            for (auto& l:listeners) l.server->set_shadowsocks_dynamic_users(ssmapi_users);
        }
        if (auto result=configure_native_udp(*udp,*config,*route_files,listeners,*dns_transports,
                traffic_stats || !control_socket.empty() || control_http_config); !result)
            return log_failure(logs,logging::Domain::proxy,"Shadowsocks UDP configuration failed",result.error());
        {
            auto readers=listeners.size()*workers+native_udp_dns_readers(*config);
            try {
                auto optimistic_seconds=config->dns ? config->dns->optimistic_cache_seconds : 0;
                dns_generation=std::make_unique<relay::SharedDnsGeneration>(
                    listeners.size()+has_udp,readers,optimistic_seconds);
                for (std::size_t i=0;i<listeners.size();++i) {
                    auto bound=listeners[i].server->bind_shared_dns(*dns_generation,i,i*workers);
                    if (!bound) { return log_failure(logs,logging::Domain::core,"DNS shared setup",bound.error().message()); }
                }
                if (has_udp && !udp->bind_shared_dns(*dns_generation,listeners.size(),listeners.size()*workers)) {
                    return log_failure(logs,logging::Domain::core,"DNS UDP shared setup failed");
                }
                dns_generation->seal();
            } catch (std::bad_alloc const&) { return log_failure(logs,logging::Domain::core,"DNS shared setup: out of memory"); }
        }
        bool has_route_files=!config->routes.empty() || (config->ordered_tcp &&
            !config->ordered_tcp->sets.empty());
        bool has_dns_rule_files=config->dns && !config->dns->rule_files.empty();
        bool specialized_listener=has_udp || std::ranges::any_of(listeners,[](auto const& item) {
            return item.masque || (item.tun && !item.routed_tun);
        });
        bool active_groups=std::ranges::any_of(config->selectors,[](auto const& group) {
            return group.mode==config::OutboundGroupMode::fallback || group.mode==config::OutboundGroupMode::url_test || !group.probe.url.empty();
        });
        if(active_groups && specialized_listener) {
            return log_failure(logs,logging::Domain::core,"automatic outbound groups require ordinary Server, routed TUN, Hysteria2 or TUIC listeners");
        }
        if (active_groups) {
            auto configured=OutboundGroupHealth::create(*config);
            if(!configured) {
                return log_failure(logs,logging::Domain::core,"outbound probe",configured.error());
            }
            group_health.emplace(std::move(*configured));
            group_route_files.emplace(std::move(*route_files));
        } else if ((!control_socket.empty() || control_http_config) && !specialized_listener && !config->selectors.empty()) {
            group_route_files.emplace(*route_files);
        }
        bool has_routed_tun = std::ranges::any_of(listeners, [](auto const& item) { return item.routed_tun; });
        auto supports_route_reload=!specialized_listener && (has_route_files || has_dns_rule_files || has_routed_tun ||
            !config->selectors.empty() || remote_rulesets.has_remote() || proxy_providers.has_providers() ||
            (listener_reload.tcp_admission && config->dns && config->dns->fakeip));
        if (specialized_listener) reload_unavailable="configured inbound has an independent packet routing context";
        if (supports_route_reload) {
            route_snapshots=std::make_shared<relay::RouteSnapshots>();
            for(std::size_t index=0;index<listeners.size();++index) {
                if(!listeners[index].server->set_route_snapshots(route_snapshots,index)) {
                    return log_failure(logs,logging::Domain::core,"cannot initialize traffic route snapshots");
                }
            }
            auto const& files=active_groups ? *group_route_files : *route_files;
            if (has_routed_tun) if (auto rec = tun_live_reload.record_initial_route_sets(*config, files); !rec)
                return log_failure(logs, logging::Domain::core, "TUN route-set", rec.error());
            auto result=publish_group_routes(listeners,*route_snapshots,*config,files);
            if(!result) {
                return log_failure(logs,logging::Domain::core,"traffic routes",result.error());
            }
        }
        if (config->dns) {
            auto prepared=dns_messages.prepare(*config,*dns_transports,dns_rule_source(route_snapshots),nullptr,reverse_cache);
            if (!prepared) {return log_failure(logs,logging::Domain::core,"DNS listener",prepared.error());}
        }
        if (reverse_cache) for (auto& listener : listeners)
            if (!listener.server->set_reverse_cache(reverse_cache))
                return log_failure(logs,logging::Domain::core,"cannot configure reverse DNS cache");
#ifdef NEXUS_ENABLE_FAKEIP
        if (auto owner=dns_messages.fakeip()) {
            for (auto& listener : listeners)
                if (!listener.server->set_fakeip(owner,0)) {
                    return log_failure(logs,logging::Domain::core,"cannot configure FakeIP on proxy listener");
                }
        }
#endif
        if (!control_socket.empty() || control_http_config) route_outbound_names=cli::outbound_names(*config);
        if (route_snapshots || listener_reload.tcp_admission || !control_socket.empty() || control_http_config)
            reload_config.emplace(std::move(*config));
    }
    if (!is_cfg) {
        auto started=logs.start({});
        if (!started) { std::cerr << started.error() << '\n'; return 1; }
    }
    SignalGuard signal_guard;
    utility::scope_exit stop_local_dns([]() noexcept { dns::stop_system_local_snapshots(); });
    if (install_signals) if (auto ok = signal_guard.install(is_cfg, traffic_stats); !ok)
        return log_failure(logs, logging::Domain::core, ok.error());
    ControlEventBridge control_wake;
    ProxyHost host{listeners,dns_messages,udp,hy2,masque,tuic,tun,listener_reload.retired_tcp,{},tun.owns_host_dns(),{},shared_io.get(),&control_wake};
    if (!control_socket.empty()) {
        auto started=control.start(control_socket,control_read_uid);
        if (!started) return log_failure(logs,logging::Domain::control,"control startup failed",started.error());
    }
    if (control_http_config) {
        if (auto started=http_control.start(*control_http_config); !started) return log_failure(logs,logging::Domain::control,"http control startup failed",started.error());
        if (services_config.ssmapi && services_config.ssmapi->enabled) {
            if (auto ok=http_control.configure_ssmapi(true,services_config.ssmapi->prefix); !ok) return log_failure(logs,logging::Domain::control,"ssmapi startup failed",ok.error());
            http_control.attach_ssmapi_users(ssmapi_users); }
    } else if (services_config.ssmapi && services_config.ssmapi->enabled)
        return log_failure(logs,logging::Domain::control,"ssmapi requires control-http listener");
    control_wake.attach(shared_io.get(), control.listen_native_fd(), http_control.listen_native_fd());
    if (auto started=ntp_runtime.start(ntp_config,logs); !started) return log_failure(logs,logging::Domain::core,"ntp startup failed",started.error());
    if (auto started=services_runtime.start(services_config,logs,host.make_watchdog_hooks()); !started) return log_failure(logs,logging::Domain::core,"optional services startup failed",started.error());
    using NetworkClock=::platform::network::Clock;
    NetworkClock::time_point retry_network{};
    auto refresh_network=[&] {
        auto now=NetworkClock::now();
        if (!network || now<retry_network) return;
        try {
            if (!network->started()) { if (!network->start(now+std::chrono::milliseconds(20))) retry_network=now+std::chrono::seconds(1); }
            else if (!network->poll(now+std::chrono::milliseconds(5))) retry_network=now+std::chrono::milliseconds(100);
        } catch (std::bad_alloc const&) { network->stop(); retry_network=now+std::chrono::seconds(1); }
    };
    refresh_network();
    auto admission_now=std::chrono::steady_clock::now();
    for (auto const& listener:listeners) listener.server->publish_principal_bytes(admission_now);
    if (auto started=host.start(workers,traffic_stats || control.active() || http_control.active(),listener_reload.tcp_admission); !started) {
        if (stopped.load(std::memory_order_relaxed)) return 0;
        return log_failure(logs,logging::Domain::proxy,"proxy startup failed",started.error());
    }
    report_ready(logs,listeners,workers,traffic_stats);
    if (reload_config && remote_rulesets.has_remote()) remote_rulesets.start_background(*reload_config,reload_source,logs);
    if (proxy_providers.has_providers()) proxy_providers.start_background(logs);
    bool provider_sync_trigger = false;
    auto reload_routes=[&](std::string_view input,config::Config requested)
        -> std::expected<void,std::string> {
        if (auto init = listener_reload.ensure_identities(reload_source, reload_identity); !init)
            return init;
        auto ids=config::reload_identities(input);
        if (!ids) return std::unexpected(std::move(ids.error()));
        auto const& key = ids->full;
        if (!reload_config || (!route_snapshots && !listener_reload.tcp_admission)) {
            if (key!=reload_identity) return std::unexpected(std::string(reload_unavailable));
            return {};
        }
        if (listener_reload.tcp_admission && (key!=reload_identity || !route_snapshots || udp->has_listeners())) {
            auto r=listener_reload.apply({listeners,reload_config,dns_generation,dns_messages,route_snapshots,
                group_route_files,group_health,snell_replay,network,reload_identity,logs,reverse_cache,remote_rulesets,route_mode.shared,host.memory_shed,ssmapi_users,shared_io.get(),host.tor_service ? &*host.tor_service : nullptr},run_args.config_path,input,std::string(key),
                traffic_stats || control.active() || http_control.active(),group_health.has_value(),udp,selector_state.choices(),
                provider_sync_trigger || proxy_providers.has_providers(), std::move(*ids));
            if (r) { reload_source.assign(input); route_mode.sync(reload_config); if (control.active() || http_control.active()) route_outbound_names=cli::outbound_names(*reload_config); }
            return r;
        }
        if (key!=reload_identity) {
            if (route_snapshots && std::ranges::any_of(listeners, [](auto const& item) { return item.routed_tun; })) {
                if (auto init = tun_live_reload.ensure_identity(reload_source); !init) return init;
                auto r = tun_live_reload.apply({listeners,reload_config,dns_messages,route_snapshots,group_route_files,
                    group_health,reload_identity,logs,reverse_cache,remote_rulesets},run_args.config_path,std::move(requested),std::move(*ids),selector_state.choices());
                if (r) { reload_source.assign(input); route_mode.sync(reload_config); if (control.active() || http_control.active()) route_outbound_names=cli::outbound_names(*reload_config); }
                return r;
            }
            return std::unexpected("configuration change requires restart");
        }
        cli::RuleFileInput rule_input(run_args.config_path);
        remote_rulesets.seed_cached(rule_input);
        std::optional<config::Config> selection;
        if(!reload_config->selectors.empty() || (reload_config->dns && !reload_config->dns->rule_files.empty())) {
            for(auto& group : requested.selectors) {
                if(group.mode==config::OutboundGroupMode::select) continue;
                auto running=std::ranges::find(reload_config->selectors,group.name,&config::OutboundSelector::name);
                if(running!=reload_config->selectors.end()) group.selected=running->selected;
            }
            auto restored=overlay_selector_state(requested,selector_state.choices());
            if (!restored) return restored;
            auto selected=config::reselect_outbounds(*reload_config,requested);
            if(!selected)return std::unexpected(std::move(selected.error()));
            if (requested.dns && !requested.dns->rule_files.empty()) {
                auto loaded=load_dns_rules(*requested.dns,rule_input);
                if (!loaded) return std::unexpected(std::move(loaded.error()));
                selected->dns->rules=std::move(requested.dns->rules);
                selected->dns->cache_rule_fingerprints=std::move(requested.dns->cache_rule_fingerprints);
            }
            selection.emplace(std::move(*selected));
        }
        auto const& config=selection ? *selection : *reload_config;
        auto files=cli::load_route_files(config,rule_input);
        if(!files)return std::unexpected(std::move(files.error()));
        auto replacing_dns=selection && selection->dns && !selection->dns->rule_files.empty();
        auto published=publish_group_routes(listeners,*route_snapshots,config,*files,replacing_dns,{},group_health ? &*group_health : nullptr);
        if(published) { reload_source.assign(input); if (selection) { reload_config=std::move(selection); route_mode.sync(reload_config); if (control.active() || http_control.active()) route_outbound_names=cli::outbound_names(*reload_config); } }
        if(published && group_route_files) *group_route_files=std::move(*files);
        return published;
    };
    auto select=[&](config::Config const& candidate,std::string_view group,std::string_view member,bool persist)
        -> std::expected<bool,std::string> {
        if (!route_snapshots || !group_route_files || udp->has_listeners()) return std::unexpected("selection-unavailable");
        bool durable=true;
        if (persist) {
            auto save=[&]() -> std::expected<void,std::string> {
                auto persisted=selector_state.select(group,member);
                if (!persisted) return std::unexpected(std::move(persisted.error()));
                durable=*persisted;
                return {};
            };
            auto published=publish_group_routes(listeners,*route_snapshots,candidate,*group_route_files,false,
                functional::function_ref<std::expected<void,std::string>()>{save},group_health ? &*group_health : nullptr);
            if (!published) return std::unexpected(std::move(published.error()));
            return durable;
        }
        auto published=publish_group_routes(listeners,*route_snapshots,candidate,*group_route_files,false,{},group_health ? &*group_health : nullptr);
        if (!published) return std::unexpected(std::move(published.error()));
        return true;
    };
    auto manage=[&](cli::ControlRole role,std::span<std::string_view const> command) -> std::expected<std::string,std::string> {
        if (command.front()=="log-level") return logs.control(role==cli::ControlRole::administrator,command.subspan(1));
        if (command.front()=="logs") return role==cli::ControlRole::administrator ? logs.control_logs(command.subspan(1)) : std::unexpected("permission-denied");
        auto generation=listener_reload.tcp_admission ? std::optional(listener_reload.listener_generation) : std::nullopt;
        auto snapshot=network ? network->get() : nullptr;
        return control_request(listeners,reload_config,workers,route_outbound_names,command,select,generation,snapshot.get(),
            group_health ? &*group_health : nullptr,role,control_operations,control,reverse_cache.get(),&route_mode,&outbound_prober,
            bool(route_snapshots || listener_reload.tcp_admission));
    };
    WinStopEventGuard win_stop;
    while (!stopped.load(std::memory_order_relaxed) && !win_stop.signaled() && host.healthy()) {
        refresh_network();
        control.poll(manage);
        if (http_control.active()) {
            http_control.poll(
                [&](control_api::SnapshotFields fields, std::optional<std::uint64_t> cid) {
                    auto snapshot = network ? network->get() : nullptr;
                    return build_control_api_snapshot(listeners, reload_config, workers, route_outbound_names, snapshot.get(),
                        group_health ? &*group_health : nullptr, control_operations, control, &route_mode, fields, cid);
                },
                [&](std::span<std::string_view const> args) { return manage(cli::ControlRole::administrator, args); });
        }
        if (traffic_requested.exchange(false,std::memory_order_relaxed)) emit_traffic_snapshot(listeners);
        provider_sync_trigger = proxy_providers.consume_updated();
        bool sig_reload = reload_requested.exchange(false,std::memory_order_relaxed) || control_operations.pending();
        if(sig_reload || remote_rulesets.consume_updated() || provider_sync_trigger) {
            auto previous=listener_reload.listener_generation;
            auto prep=[&](std::string_view raw) -> std::expected<std::string,std::string> {
                if (sig_reload) return proxy_providers.prepare_initial(raw, run_args.config_path, true);
                return proxy_providers.expand_kdl(raw);
            };
            auto success=reload_logging_and_routes(logs,run_args.config_path,config_is_dir,previous,listener_reload.listener_generation,reload_routes,prep,run_args.host_override_path);
            provider_sync_trigger = false;
            control_operations.finish_reload(success);
            if (success) {
                if (proxy_providers.has_providers()) proxy_providers.start_background(logs);
                if (reload_config) remote_rulesets.start_background(*reload_config, reload_source, logs);
            }
        }
        if(group_health) {
            try {
                auto snapshot=reload_config->direct_network && network ? network->get() : nullptr;
                auto picked=group_health->poll([&](std::shared_ptr<relay::OutboundProbe> probe) {
                    return queue_probe_on_listeners(listeners, tun, hy2, tuic, std::move(probe));
                },*reload_config,snapshot ? std::optional(snapshot->generation) : std::nullopt);
                if(picked) {
                    std::expected<void,std::string> published;
                    if(picked->balance_changed) published=publish_group_routes(listeners,*route_snapshots,*reload_config,*group_route_files,false,{},&*group_health);
                    else {
                        auto requested=*reload_config; requested.selectors[picked->group].selected=picked->member;
                        auto next=config::reselect_outbounds(*reload_config,requested);
                        published=next ? publish_group_routes(listeners,*route_snapshots,*next,*group_route_files,false,{},&*group_health) :
                            std::expected<void,std::string>(std::unexpected(std::move(next.error())));
                        if(published) *reload_config=std::move(*next);
                    }
                    if(published) { control_operations.published(); control_operations.record(ControlOperations::EventKind::selector_changed); route_mode.sync(reload_config); }
                    else log_failure(logs,logging::Domain::route,"outbound probe selection failed",published.error());
                }
            } catch(std::bad_alloc const&) {
                logs.emit(logging::Level::error,logging::Domain::route,108,{},"outbound probe selection: out of memory");
            }
        }
        if (outbound_prober.has_pending()) outbound_prober.poll([&](std::shared_ptr<relay::OutboundProbe> probe) {
            return queue_probe_on_listeners(listeners, tun, hy2, tuic, std::move(probe));
        });
        auto wait = compute_host_poll_wait(shared_io != nullptr, control_wake.has_events(), !shared_io && workers == 1,
            listeners.size(), control.next_poll_delay(), http_control.next_poll_delay(),
            !listener_reload.retired_tcp.empty(), group_health.has_value() || outbound_prober.has_pending() || services_runtime.active_count() > 0);
        host.poll(wait);
        services_runtime.poll(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()),logs);
    }
    control_wake.detach();
    proxy_providers.stop(); remote_rulesets.stop();
    services_runtime.stop(); ntp_runtime.stop();
    http_control.stop(); control.stop();
    logs.emit(logging::Level::info,logging::Domain::core,104,{.generation=listener_reload.listener_generation},"proxy draining");
    auto failed=!host.healthy(), udp_failed=udp->failed();
    if (!failed) { host.drain(shutdown_grace); dns_messages.checkpoint(); }
    host.stop();
    if (network) network->stop();
    failed|=!hy2.healthy() || !masque.healthy() || !tuic.healthy() || !tun.healthy();
    auto status=report_exit(logs,failed,udp_failed,listener_reload.listener_generation,listeners,masque,hy2,tuic,tun);
    logs.shutdown();
    return status;
}
