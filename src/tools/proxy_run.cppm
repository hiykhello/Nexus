module;
#include <csignal>
#include <string.h>
#include <sys/socket.h>

export module cli.proxy_run;
import std;
import nexus.compat;
import nexus.thirdparty.corosio;
import rulefile;
import state.core;
import state.file;
import logging;
import logging.cli;
import proxy;
import proxy.host;
import proxy.principal_limits;
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
import cli.dns_message_runtime;
import dns.message_program;
import cli.control;
import control_api;
import control_api.types;
import cli.outbounds;
import cli.route_files;
import cli.proxy_ntp;
import http.connect;
import socks5;

#include "proxy_group_health.hpp"

namespace cli::run_detail {
    struct SecretKey {
        std::array<std::uint8_t,32> bytes{};
        ~SecretKey() { explicit_bzero(bytes.data(),bytes.size()); }
    };
    using ::encoding::decode_key;
    static_assert(std::atomic<bool>::is_always_lock_free);
    std::atomic<bool> stopped{false};
    extern "C" auto handle_signal(int) -> void { stopped.store(true,std::memory_order_relaxed); }
    std::atomic<bool> reload_requested{false};
    extern "C" auto handle_reload(int) -> void { reload_requested.store(true,std::memory_order_relaxed); }
    std::atomic<bool> traffic_requested{false};
    extern "C" auto handle_traffic(int) -> void { traffic_requested.store(true,std::memory_order_relaxed); }
}

#include "proxy_listener.hpp"
#include "proxy_log.hpp"
#include "proxy_host.hpp"
#include "proxy_dns_reload.hpp"
#include "proxy_selector_state.hpp"
#include "proxy_listener_reload.hpp"
#include "proxy_control_operations.hpp"
#include "proxy_control.hpp"
#include "proxy_http_control.hpp"

using namespace cli::run_detail;

export template<class UdpRuntime,class Hy2Runtime,class MasqueRuntime,class TuicRuntime,class TunRuntime>
auto nexus_run_proxy(int argc, char** argv) -> int {
    bool traffic_stats=argc>1 && std::string_view(argv[1])=="--traffic-stats";
    if (traffic_stats) { --argc; ++argv; }
    constexpr std::string_view run_usage="usage: nexus run [--traffic-stats] <loopback-port> [kdl|beve|srs <block-rules>]\n"
        "       nexus run [--traffic-stats] --config|-c <config.kdl> | --config-dir|-C <dir>\n";
    if (argc == 2 && std::string_view(argv[1]) == "--help") { std::cout << run_usage; return 0; }
    if (argc != 2 && argc != 3 && argc != 4) { std::cerr << run_usage; return 2; }
    unsigned port = 0, workers = 1;
    std::chrono::milliseconds shutdown_grace{};
    auto inbound = proxy::Inbound::socks5;
    bool is_cfg=argc>=2 && is_config_flag(argv[1]), config_is_dir=argc>=2 && is_config_dir_flag(argv[1]);
    if ((argc == 3 && !is_cfg) || (argc != 3 && is_cfg)) {
        std::cerr << "--config/-c/--config-dir/-C accepts exactly one path\n";
        return 2;
    } else if (!is_cfg) {
        auto text = std::string_view(argv[1]);
        auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
        if (error != std::errc{} || end != text.data() + text.size() || port == 0 || port > 65535) {
            std::cerr << "port must be an integer from 1 to 65535\n";
            return 2;
        }
    }
    if (argc == 4 && std::string_view(argv[2]) != "kdl" && std::string_view(argv[2]) != "beve" && std::string_view(argv[2]) != "srs") {
        std::cerr << "rule format must be kdl, beve or srs\n";
        return 2;
    }
    logging::Runtime logs;
    auto created = proxy::Server::create();
    if (!created) { std::cerr << "cannot initialize proxy: " << created.error().message() << '\n'; return 1; }
    std::unique_ptr<proxy::SharedDnsGeneration> dns_generation;
    std::shared_ptr<proxy::SnellReplayRegistry> snell_replay;
    std::vector<Listener> listeners;
    std::vector<std::string> route_outbound_names{"direct","block"};
    std::optional<config::Config> reload_config;
    std::string reload_identity;
    ListenerReload listener_reload;
    std::shared_ptr<proxy::RouteSnapshots> route_snapshots;
    std::shared_ptr<dns::ReverseCache> reverse_cache;
    RemoteRulesetManager remote_rulesets;
    std::string reload_source;
    std::optional<OutboundGroupHealth> group_health;
    std::optional<cli::RouteFiles> group_route_files;
    std::string_view reload_unavailable="no traffic rule files configured";
    cli::DnsMessageRuntime dns_messages(logs);
    cli::LocalControl control;
    control_api::HttpControlServer http_control;
    std::optional<config::ControlHttpConfig> control_http_config;
    std::optional<config::NtpConfig> ntp_config;
    cli::NtpRuntime ntp_runtime;
    cli::SelectorState selector_state;
    std::shared_ptr<::platform::network::Monitor> network;
    std::string control_socket;
    std::optional<std::uint32_t> control_read_uid;
    ControlOperations control_operations;
    auto udp=std::make_shared<UdpRuntime>();
    Hy2Runtime hy2;
    TuicRuntime tuic;
    TunRuntime tun;
#if BOOST_COROSIO_HAVE_LIBURING
    MasqueRuntime masque(true);
#else
    MasqueRuntime masque(false);
#endif
    listeners.push_back({std::move(*created),static_cast<std::uint16_t>(port),inbound});
    auto& server=*listeners.front().server;
    if (argc == 4) {
        auto format = std::string_view(argv[2]);
        auto input = ::rulefile::read_regular_file(argv[3]);
        if (!input) { std::cerr << input.error() << '\n'; return 1; }
        auto result = server.set_block_rules(*input, format == "kdl" ? proxy::RuleFormat::kdl : format == "beve" ? proxy::RuleFormat::beve : proxy::RuleFormat::srs);
        if (!result) { std::cerr << "invalid block rules: " << result.error() << '\n'; return 1; }
    } else if (argc == 3 && is_cfg) {
        auto input = cli::read_config_source(argv[2], config_is_dir);
        if (!input) { std::cerr << "configuration: " << input.error() << '\n'; return 1; }
        reload_source = *input;
        auto config = config::parse_kdl(*input);
        if (!config) { std::cerr << "configuration: " << config.error() << '\n'; return 1; }
        auto log_start=logs.start(config->log.value_or(logging::Config{}),argv[2],config->log_protected_paths);
        if (!log_start) { std::cerr << "configuration: " << log_start.error() << '\n'; return 1; }
        if (config->state) for (auto const* root:{&config->state->directory,&config->state->cache_directory}) {
            if (root->empty()) continue;
            auto created=::state::ensure_private_directory(*root);
            if (!created) return log_failure(logs,logging::Domain::core,"state directory",::state::describe(created.error().stage));
        }
        auto restored=initialize_selector_state(selector_state,*config);
        if (!restored) {return log_failure(logs,logging::Domain::core,"proxy configuration failed",restored.error());}
        if (reloadable_tcp(*config)) {
            using config::ReloadIdentity;
            auto process=config::reload_identity(*input,ReloadIdentity::process);
            auto dns_key=config::reload_identity(*input,ReloadIdentity::dns_policy);
            if (!process || !dns_key) {
                return log_failure(logs,logging::Domain::core,"reload configuration",(!process ? process.error() : dns_key.error()));
            }
            listener_reload.process_identity=std::move(*process);
            listener_reload.dns_policy_identity=std::move(*dns_key);
            listener_reload.tcp_admission=std::make_shared<proxy::TcpAdmission>();
            udp->stage_admission(nullptr,1);
            listener_reload.listener_grace=std::chrono::milliseconds(config->shutdown_grace_ms.value_or(5000));
        }
        workers=config->workers;
        control_socket=config->control_socket;
        control_read_uid=config->control_read_uid;
        control_http_config=config->control_http;
        ntp_config=config->ntp;
        auto observe_neighbors=std::ranges::any_of(config->inbounds,uses_transparent_metadata);
        if (config->direct_network || !control_socket.empty() || observe_neighbors)
            network=std::make_shared<::platform::network::Monitor>(observe_neighbors);
        if (config->direct_network) {
            auto& binding=config->direct_tcp_options.binding;
            binding.network=std::make_shared<::platform::network::InterfaceSelection>(
                ::platform::network::SystemInterfaceSelection(network,*config->direct_network,binding));
        }
        shutdown_grace=std::chrono::milliseconds(config->shutdown_grace_ms.value_or(0));
        cli::RuleFileInput rule_input(argv[2]);
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
        listeners.front()=make_listener(std::move(listeners.front().server),config->inbounds.front());
        for (auto const& entry : std::span(config->inbounds).subspan(1)) {
            auto next=proxy::Server::create();
            if (!next) { return log_failure(logs,logging::Domain::core,"cannot initialize proxy",next.error().message()); }
            listeners.push_back(make_listener(std::move(*next),entry));
        }
        if (auto pipes=config->tcp_splice_pipes.value_or(0); pipes && !configure_splice(listeners,pipes)) {
            return log_failure(logs,logging::Domain::core,"cannot configure TCP splice");
        }
        auto route_files=cli::load_route_files(*config,rule_input);
        if(!route_files) {return log_failure(logs,logging::Domain::core,"routing rules",route_files.error());}
        auto indexed_routes=route_files->indexed(*config);
        udp->resize(listeners.size(),std::ranges::any_of(config->inbounds,[](auto const& entry) { return entry.shadowsocks.has_value(); }));
        auto configure=[&](proxy::Server& server, std::size_t index) -> int {
            auto const& entry=config->inbounds[index];
            if (uses_transparent_metadata(entry)) server.set_network_monitor(network);
            auto remember=[&](std::span<std::uint8_t const> key,std::span<proxy::ShadowsocksUserKey const> users) {
                udp->remember(index,key,users);
            };
            if (auto result=configure_listener(server,*config,entry,*dns_transports,*route_files,indexed_routes,
                    snell_replay,remember,listener_reload.principals); !result)
                return log_failure(logs,logging::Domain::proxy,"listener configuration failed",result.error());
            if(auto configured=hy2.configure(index,entry);!configured){return log_failure(logs,logging::Domain::core,"Hysteria2 configuration",configured.error());}
            if(auto configured=masque.configure(index,entry);!configured){return log_failure(logs,logging::Domain::core,"MASQUE configuration",configured.error());}
            if(auto configured=tuic.configure(index,entry);!configured){return log_failure(logs,logging::Domain::core,"TUIC configuration",configured.error());}
            if(auto configured=tun.configure(index,entry,*config);!configured){return log_failure(logs,logging::Domain::core,"TUN configuration",configured.error());}
            if(entry.tun && entry.tun->socket_mark && !config->direct_tcp_options.binding.routing_mark) {
                auto opts=config->direct_tcp_options;opts.binding.routing_mark=entry.tun->socket_mark;
                if(auto ok=server.set_direct_tcp_options(opts);!ok){return log_failure(logs,logging::Domain::core,"configuration",ok.error());}
            }
            return 0;
        };
        for (std::size_t i=0; i<listeners.size(); ++i) if (configure(*listeners[i].server,i)) return 1;
        auto has_udp=uses_native_udp(*config);
        if (has_udp && (traffic_stats || !control_socket.empty()))
            for (std::size_t index=0;index<listeners.size();++index)
                if (config->inbounds[index].shadowsocks) listeners[index].packet_slots=64;
        if (auto result=configure_native_udp(*udp,*config,*route_files,listeners,*dns_transports,
                traffic_stats || !control_socket.empty()); !result)
            return log_failure(logs,logging::Domain::proxy,"Shadowsocks UDP configuration failed",result.error());
        {
            auto readers=listeners.size()*workers+native_udp_dns_readers(*config);
            try {
                auto optimistic_seconds=config->dns ? config->dns->optimistic_cache_seconds : 0;
                dns_generation=std::make_unique<proxy::SharedDnsGeneration>(
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
            return group.mode!=config::OutboundGroupMode::select;
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
        auto supports_route_reload=!specialized_listener && (has_route_files || has_dns_rule_files ||
            !config->selectors.empty() || remote_rulesets.has_remote() || (listener_reload.tcp_admission && config->dns && config->dns->fakeip));
        if (specialized_listener) reload_unavailable="configured inbound has an independent packet routing context";
        {
            auto key=config::reload_identity(*input);
            if (!key) {return log_failure(logs,logging::Domain::core,"reload configuration",key.error());}
            reload_identity=std::move(*key);
        }
        if (supports_route_reload) {
            route_snapshots=std::make_shared<proxy::RouteSnapshots>();
            for(std::size_t index=0;index<listeners.size();++index) {
                if(!listeners[index].server->set_route_snapshots(route_snapshots,index)) {
                    return log_failure(logs,logging::Domain::core,"cannot initialize traffic route snapshots");
                }
            }
            auto const& files=active_groups ? *group_route_files : *route_files;
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
        if (route_snapshots || listener_reload.tcp_admission) reload_config.emplace(std::move(*config));
    }
    if (argc!=3) {
        auto started=logs.start({});
        if (!started) { std::cerr << started.error() << '\n'; return 1; }
    }
    if(argc==3 && std::signal(SIGHUP,handle_reload)==SIG_ERR) {
        return log_failure(logs,logging::Domain::core,"cannot install traffic rule reload signal handler");
    }
    if (traffic_stats && std::signal(SIGUSR1,handle_traffic)==SIG_ERR) {
        return log_failure(logs,logging::Domain::core,"cannot install traffic snapshot signal handler");
    }
    if (std::signal(SIGINT,handle_signal)==SIG_ERR || std::signal(SIGTERM,handle_signal)==SIG_ERR) {
        return log_failure(logs,logging::Domain::core,"cannot install proxy stop signal handlers");
    }
    ProxyHost host{listeners,dns_messages,udp,hy2,masque,tuic,tun,listener_reload.retired_tcp,{},tun.owns_host_dns()};
    if (!control_socket.empty()) {
        auto started=control.start(control_socket,control_read_uid);
        if (!started) return log_failure(logs,logging::Domain::control,"control startup failed",started.error());
    }
    if (control_http_config) {
        if (auto started=http_control.start(*control_http_config); !started) return log_failure(logs,logging::Domain::control,"http control startup failed",started.error());
    }
    if (auto started=ntp_runtime.start(ntp_config,logs); !started) return log_failure(logs,logging::Domain::core,"ntp startup failed",started.error());
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
    auto reload_routes=[&](std::string_view input,config::Config requested)
        -> std::expected<void,std::string> {
        auto key=config::reload_identity(input);
        if (!key) return std::unexpected(std::move(key.error()));
        if (!reload_config) {
            if (*key!=reload_identity) return std::unexpected(std::string(reload_unavailable));
            return {};
        }
        if (listener_reload.tcp_admission && (*key!=reload_identity || !route_snapshots || udp->has_listeners()))
            return listener_reload.apply({listeners,reload_config,dns_generation,dns_messages,route_snapshots,
                group_route_files,snell_replay,network,reload_identity,logs,reverse_cache,remote_rulesets},argv[2],input,std::move(*key),
                traffic_stats || control.active(),group_health.has_value(),udp,selector_state.choices());
        if (*key!=reload_identity) return std::unexpected("configuration change requires restart");
        cli::RuleFileInput rule_input(argv[2]);
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
        auto published=publish_group_routes(listeners,*route_snapshots,config,*files,replacing_dns);
        if(published && selection) reload_config=std::move(selection);
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
                nexus::function_ref<std::expected<void,std::string>()>{save});
            if (!published) return std::unexpected(std::move(published.error()));
            return durable;
        }
        auto published=publish_group_routes(listeners,*route_snapshots,candidate,*group_route_files);
        if (!published) return std::unexpected(std::move(published.error()));
        return true;
    };
    auto manage=[&](cli::ControlRole role,std::span<std::string_view const> command) -> std::expected<std::string,std::string> {
        if (command.front()=="log-level") return logs.control(role==cli::ControlRole::administrator,command.subspan(1));
        if (command.front()=="logs") return logs.control_logs(command.subspan(1));
        auto generation=listener_reload.tcp_admission ? std::optional(listener_reload.listener_generation) : std::nullopt;
        auto snapshot=network ? network->get() : nullptr;
        return control_request(listeners,reload_config,workers,route_outbound_names,command,select,generation,snapshot.get(),
            group_health ? &*group_health : nullptr,role,control_operations,control,reverse_cache.get());
    };
    while (!stopped.load(std::memory_order_relaxed) && host.healthy()) {
        refresh_network();
        control.poll(manage);
        if (http_control.active()) {
            http_control.poll(
                [&] {
                    auto snapshot=network ? network->get() : nullptr;
                    return build_control_api_snapshot(listeners,reload_config,workers,route_outbound_names,snapshot.get(),
                        group_health ? &*group_health : nullptr,control_operations,control);
                },
                [&](std::span<std::string_view const> args) { return manage(cli::ControlRole::administrator,args); });
        }
        if (traffic_requested.exchange(false,std::memory_order_relaxed)) emit_traffic_snapshot(listeners);
        if(reload_requested.exchange(false,std::memory_order_relaxed) || control_operations.pending() || remote_rulesets.consume_updated()) {
            auto previous=listener_reload.listener_generation;
            auto success=reload_logging_and_routes(logs,argv[2],config_is_dir,previous,listener_reload.listener_generation,reload_routes);
            control_operations.finish_reload(success);
        }
        if(group_health) {
            try {
                auto snapshot=reload_config->direct_network && network ? network->get() : nullptr;
                auto picked=group_health->poll([&](std::shared_ptr<proxy::OutboundProbe> probe) {
                    auto const& first=listeners.front();
                    if (first.routed_tun) return tun.queue_outbound_probe(0,std::move(probe));
                    if (first.hy2) return hy2.queue_outbound_probe(0,std::move(probe));
                    if (first.tuic) return tuic.queue_outbound_probe(0,std::move(probe));
                    return first.server->queue_outbound_probe(std::move(probe));
                },*reload_config,snapshot ? std::optional(snapshot->generation) : std::nullopt);
                if(picked) {
                    auto requested=*reload_config;
                    requested.selectors[picked->group].selected=picked->member;
                    auto next=config::reselect_outbounds(*reload_config,requested);
                    auto published=next ? publish_group_routes(listeners,*route_snapshots,*next,*group_route_files) :
                        std::expected<void,std::string>(std::unexpected(std::move(next.error())));
                    if(published) {
                        *reload_config=std::move(*next);
                        control_operations.published();
                        control_operations.record(ControlOperations::EventKind::selector_changed);
                    } else log_failure(logs,logging::Domain::route,"outbound probe selection failed",published.error());
                }
            } catch(std::bad_alloc const&) {
                logs.emit(logging::Level::error,logging::Domain::route,108,{},"outbound probe selection: out of memory");
            }
        }
        auto wait=std::chrono::milliseconds(std::max<std::size_t>(
            1,(control.active() || http_control.active() || !listener_reload.retired_tcp.empty() ? 20 : 100)/listeners.size()));
        host.poll(wait);
    }
    remote_rulesets.stop();
    ntp_runtime.stop();
    http_control.stop();
    control.stop();
    logs.emit(logging::Level::info,logging::Domain::core,104,
        {.generation=listener_reload.listener_generation},"proxy draining");
    auto failed=!host.healthy();
    auto udp_failed=udp->failed();
    if (!failed) {
        host.drain(shutdown_grace);
        dns_messages.checkpoint();
    }
    host.stop();
    if (network) network->stop();
    failed|=!hy2.healthy() || !masque.healthy() || !tuic.healthy() || !tun.healthy();
    auto status=report_exit(logs,failed,udp_failed,listener_reload.listener_generation,listeners,masque,hy2,tuic,tun);
    logs.shutdown();
    return status;
}
