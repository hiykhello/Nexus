// Staged TCP/DNS listener reload ownership and atomic generation publication.
module;
#include <csignal>

export module cli.proxy_listener_reload;
import std;
import cli.cert_reloader;
import cli.control;
import cli.dns_message_runtime;
import cli.dns_transports;
import cli.proxy_dns_reload;
import cli.proxy_group_health;
import cli.proxy_host;
import cli.proxy_listener;
import cli.proxy_run_state;
import cli.proxy_selector_state;
import cli.route_files;
import config;
import corosio;
import dns.reverse;
import logging;
import logging.cli;
import platform.network_state;
import relay;
import relay.principal_limits;
import rules;

export namespace cli::run_detail {
    struct ListenerReloadRuntime {
        std::vector<Listener>& listeners;
        std::optional<config::Config>& config;
        std::unique_ptr<relay::SharedDnsGeneration>& dns;
        DnsMessageRuntime& messages;
        std::shared_ptr<relay::RouteSnapshots>& routes;
        std::optional<RouteFiles>& group_files;
        std::optional<OutboundGroupHealth>& group_health;
        std::shared_ptr<relay::SnellReplayRegistry>& replay;
        std::shared_ptr<::platform::network::Monitor>& network;
        std::string& identity;
        logging::Runtime const& log;
        std::shared_ptr<dns::ReverseCache>& reverse_cache;
        RemoteRulesetManager& remote_rulesets;
        std::shared_ptr<rules::RuntimeRouteMode const> runtime_mode{};
        std::shared_ptr<std::atomic_bool const> memory_shed{};
        std::shared_ptr<relay::ShadowsocksUserDirectory> ssmapi_users{};
        corosio::io_context* shared_io = nullptr;
        config::TorServiceConfig const* tor_service = nullptr;
        std::shared_ptr<relay::GroupRuntimeHooks> group_hooks{};
        std::shared_ptr<void> acme_credential{};
        cli::CertReloaderHub* cert_reloaders = nullptr;
    };

    inline auto provider_refresh_process_options_match(config::Config const& a, config::Config const& b) noexcept -> bool {
        auto same_state = [](std::optional<config::StateOptions> const& x, std::optional<config::StateOptions> const& y) noexcept {
            if (x.has_value() != y.has_value()) return false;
            if (!x) return true;
            return x->directory == y->directory && x->cache_directory == y->cache_directory &&
                x->dns_cache_max_bytes == y->dns_cache_max_bytes &&
                x->ruleset_cache_max_bytes == y->ruleset_cache_max_bytes &&
                x->fakeip_per_mapping == y->fakeip_per_mapping;
        };
        auto same_ntp = [](std::optional<config::NtpConfig> const& x, std::optional<config::NtpConfig> const& y) noexcept {
            if (x.has_value() != y.has_value()) return false;
            if (!x) return true;
            return x->host == y->host && x->port == y->port &&
                x->interval_ms == y->interval_ms && x->timeout_ms == y->timeout_ms;
        };
        return a.workers == b.workers &&
            a.control_socket == b.control_socket &&
            a.control_read_uid == b.control_read_uid &&
            a.control_http == b.control_http &&
            a.selector_state_directory == b.selector_state_directory &&
            a.shutdown_grace_ms == b.shutdown_grace_ms &&
            a.sessions_per_listener == b.sessions_per_listener &&
            a.tcp_splice_pipes == b.tcp_splice_pipes &&
            same_state(a.state, b.state) &&
            same_ntp(a.ntp, b.ntp) &&
            a.services == b.services &&
            a.direct_network == b.direct_network;
    }

    struct ListenerReload {
        std::string process_identity, dns_policy_identity;
        bool identities_initialized = false;
        std::shared_ptr<relay::TcpAdmission> tcp_admission;
        relay::PrincipalRegistry principals;
        std::uint64_t listener_generation = 1;
        std::vector<std::unique_ptr<RetiredTcpGeneration>> retired_tcp;
        std::chrono::milliseconds listener_grace{};

        auto ensure_identities(std::string_view source, std::string& full_identity)
            -> std::expected<void, std::string> {
            if (identities_initialized) return {};
            auto ids = config::reload_identities(source);
            if (!ids) return std::unexpected(std::move(ids.error()));
            if (tcp_admission) {
                process_identity = std::move(ids->process);
                dns_policy_identity = std::move(ids->dns_policy);
            }
            full_identity = std::move(ids->full);
            identities_initialized = true;
            return {};
        }

        template<class UdpRuntime>
        auto apply(ListenerReloadRuntime running, std::string_view path, std::string_view input,
            std::string identity, bool traffic_stats, bool automatic_groups, std::shared_ptr<UdpRuntime>& udp,
            std::span<SelectorChoice const> choices, bool provider_refresh = false,
            std::optional<config::ReloadIdentities> precomputed = {})
            -> std::expected<void, std::string> {
            auto [listeners, reload_config, dns_generation, dns_messages, route_snapshots, group_route_files,
                group_health, snell_replay, network, reload_identity, log, reverse_cache, remote_rulesets, runtime_mode,
                memory_shed, ssmapi_users, shared_io, tor_service, group_hooks, acme_credential, cert_reloaders] = running;
            auto workers = reload_config->workers;
            if (!precomputed) {
                auto parsed_ids = config::reload_identities(input);
                if (!parsed_ids) return std::unexpected(std::move(parsed_ids.error()));
                precomputed = std::move(*parsed_ids);
            }
            auto& key = precomputed->process;
            if (!provider_refresh && key != process_identity) return std::unexpected("configuration change requires restart");
            auto& dns_key = precomputed->dns_policy;
            auto config = config::parse_kdl(input);
            if (!config) return std::unexpected(std::move(config.error()));
            if (provider_refresh && !provider_refresh_process_options_match(*config, *reload_config))
                return std::unexpected("configuration change requires restart");
            config->direct_tcp_options.binding.network = reload_config->direct_tcp_options.binding.network;
            if (!reloadable_tcp(*config)) return std::unexpected("listener change requires restart");
            if (automatic_groups || !choices.empty()) {
                auto wanted = *config;
                auto restored = overlay_selector_state(wanted, choices);
                if (!restored) return restored;
                for (auto& group : wanted.selectors) {
                    if (group.mode == config::OutboundGroupMode::select) continue;
                    auto running = std::ranges::find(reload_config->selectors, group.name, &config::OutboundSelector::name);
                    if (running != reload_config->selectors.end() && std::ranges::contains(group.members, running->selected))
                        group.selected = running->selected;
                }
                config = config::reselect_outbounds(*config, wanted);
                if (!config) return std::unexpected(std::move(config.error()));
            }
            bool next_active_groups = std::ranges::any_of(config->selectors, [](auto const& g) {
                return g.mode == config::OutboundGroupMode::fallback || g.mode == config::OutboundGroupMode::url_test ||
                    !g.probe.url.empty();
            });
            std::optional<OutboundGroupHealth> candidate_health;
            if (next_active_groups) {
                auto rebuilt = group_health ? group_health->reconciled(*config) : OutboundGroupHealth::create(*config);
                if (!rebuilt) return std::unexpected(std::move(rebuilt.error()));
                candidate_health.emplace(std::move(*rebuilt));
            }
            RuleFileInput rule_input(path);
            auto staged_remote = remote_rulesets.prepare_reload(*config, input, rule_input);
            if (!staged_remote) return std::unexpected(std::move(staged_remote.error()));
            if (config->dns) {
                auto loaded = load_dns_rules(*config->dns, rule_input);
                if (!loaded) return std::unexpected(std::move(loaded.error()));
            }
            auto protections = cli::prepare_dns_transports(*config);
            if (!protections) return std::unexpected(std::move(protections.error()));
            auto files = cli::load_route_files(*config, rule_input);
            if (!files) return std::unexpected(std::move(files.error()));
            auto indexed = files->indexed(*config);
            TcpGeneration candidate;
            cli::CertReloaderHub candidate_cert_reloaders;
            auto candidate_replay = snell_replay;
            auto candidate_udp = std::make_shared<UdpRuntime>();
            if (ssmapi_users) candidate_udp->set_dynamic_users(ssmapi_users);
            auto next = listener_generation + 1;
            candidate_udp->stage_admission(udp.get(), next);
            candidate_udp->resize(config->inbounds.size(), std::ranges::any_of(config->inbounds, [](auto const& entry) {
                return entry.shadowsocks.has_value();
            }));
            auto has_udp = uses_native_udp(*config);
            auto native_readers = native_udp_dns_readers(*config);
            auto tcp_readers = config->inbounds.size() * workers;
            candidate.listeners.reserve(config->inbounds.size());
            try {
                candidate.dns = std::make_unique<relay::SharedDnsGeneration>(
                    config->inbounds.size() + has_udp, tcp_readers + native_readers,
                    config->dns ? config->dns->optimistic_cache_seconds : 0);
            } catch (std::out_of_range const& e) {
                return std::unexpected("DNS shared setup: " + std::string(e.what()));
            }
            if (route_snapshots || uses_dns_groups(config->dns) || !config->selectors.empty() ||
                (config->dns && (!config->dns->rule_files.empty() || config->dns->fakeip))) {
                candidate.routes = std::make_shared<relay::RouteSnapshots>();
                if (route_snapshots)
                    candidate.routes->store(route_snapshots->load(std::memory_order_acquire), std::memory_order_relaxed);
            }
            auto candidate_reverse = config->dns && config->dns->reverse_mapping ?
                (reverse_cache ? reverse_cache : make_reverse_cache()) : std::shared_ptr<dns::ReverseCache>{};
            if ((config->dns && config->dns->listen) || dns_messages.has_listeners()) {
                candidate.messages = std::make_unique<cli::DnsMessageRuntime>(log);
                if (config->dns) {
                    auto prepared = candidate.messages->prepare(*config, *protections,
                        dns_rule_source(candidate.routes), &dns_messages, candidate_reverse);
                    if (!prepared) return std::unexpected("DNS listener: " + prepared.error());
                }
            }
            auto observe_neighbors = std::ranges::any_of(config->inbounds, uses_transparent_metadata);
            auto monitor = network;
            if (!monitor && observe_neighbors)
                monitor = std::make_shared<::platform::network::Monitor>(true);
            for (auto const& entry : config->inbounds) {
                auto server = (workers == 1 && shared_io) ? relay::Server::create_shared(*shared_io) : relay::Server::create();
                if (!server) return std::unexpected(server.error().message());
                if (monitor) (*server)->set_network_monitor(monitor);
                if (config->defaults.find_process) (*server)->set_find_process(true);
                if (group_hooks) (*server)->set_group_hooks(group_hooks);
                if (memory_shed) (*server)->set_memory_shed(memory_shed);
                if (ssmapi_users) (*server)->set_shadowsocks_dynamic_users(ssmapi_users);
                auto index = candidate.listeners.size();
                auto remember = [&](std::span<std::uint8_t const> key, std::span<relay::ShadowsocksUserKey const> users) {
                    candidate_udp->remember(index, key, users);
                };
                if (auto result = configure_listener(**server, *config, entry, *protections, *files, indexed,
                        candidate_replay, remember, principals, acme_credential, &candidate_cert_reloaders, &log); !result)
                    return std::unexpected("invalid TCP listener " + entry.name + ": " + result.error());
                if (tor_service) {
                    if (auto added = (*server)->add_tor(*tor_service); !added)
                        return std::unexpected("tor outbound registration failed: " + added.error());
                }
                if (auto pipes = config->tcp_splice_pipes.value_or(default_tcp_splice_pipes()); pipes) {
                    (void)std::signal(SIGPIPE, SIG_IGN);
                    if (!(*server)->set_tcp_splice_pipes(pipes))
                        return std::unexpected("cannot configure TCP splice");
                }
                auto packet_slots = has_udp && entry.shadowsocks ? 64u : 0u;
                if (traffic_stats && !(*server)->enable_traffic_stats(packet_slots))
                    return std::unexpected("cannot enable traffic statistics");
                if (auto bound = (*server)->bind_shared_dns(*candidate.dns, index, index * workers); !bound)
                    return std::unexpected("DNS shared setup: " + bound.error().message());
                if (runtime_mode) (*server)->set_runtime_mode(runtime_mode);
                if (candidate.routes && !(*server)->set_route_snapshots(candidate.routes, index))
                    return std::unexpected("cannot initialize traffic route snapshots");
#ifdef NEXUS_ENABLE_FAKEIP
                if (auto owner = candidate.messages ? candidate.messages->fakeip() : nullptr;
                    owner && !(*server)->set_fakeip(std::move(owner), 0)) return std::unexpected("cannot configure FakeIP");
#endif
                if (candidate_reverse && !(*server)->set_reverse_cache(candidate_reverse))
                    return std::unexpected("cannot configure reverse DNS cache");
                auto listener = make_listener(std::move(*server), entry);
                listener.packet_slots = packet_slots;
                candidate.listeners.push_back(std::move(listener));
            }
            wire_listener_detours(*config, candidate.listeners);
            if (auto result = configure_native_udp(*candidate_udp, *config, *files, candidate.listeners, *protections, traffic_stats);
                !result) return result;
            if (has_udp && !candidate_udp->bind_shared_dns(*candidate.dns, candidate.listeners.size(), tcp_readers))
                return std::unexpected("DNS UDP shared setup failed");
            candidate.dns->seal();
            if (candidate.routes) {
                auto compiled = publish_group_routes(candidate.listeners, *candidate.routes, *config, *files,
                    dns_key != dns_policy_identity || (config->dns && !config->dns->rule_files.empty()), {},
                    candidate_health ? &*candidate_health : nullptr);
                if (!compiled) return compiled;
            }
            for (auto& listener : candidate.listeners) {
                auto previous = std::ranges::find_if(listeners, [&](auto const& item) {
                    return same_tcp_binding(listener, item);
                });
                auto staged = listener.server->stage_tcp(tcp_admission, next, listener.port, listener.inbound, workers,
                    listener.ipv6, listener.address, previous == listeners.end() ? nullptr : previous->server.get());
                if (!staged)
                    return std::unexpected(std::format("cannot stage TCP port {}: {}", listener.port, staged.error().message()));
                listener.port = *staged;
            }
            auto reuse_dns_binding = candidate.messages && dns_messages.same_binding(*candidate.messages);
            if (candidate.messages && !reuse_dns_binding) {
                auto started = candidate.messages->start(false);
                if (!started) return started;
            }
            if (auto started = candidate_udp->start(); !started) return started;
            auto retired = std::make_unique<RetiredTcpGeneration>();
            if (udp->has_listeners())
                retired->poll_udp = [previous = udp] {
                    previous->poll();
                    return previous->idle();
                };
            retired_tcp.reserve(retired_tcp.size() + 1);
            if (stopped.load(std::memory_order_relaxed) || !candidate_udp->healthy() || (candidate.messages && !candidate.messages->healthy()) ||
                !std::ranges::all_of(candidate.listeners, [](auto const& item) { return item.server->healthy(); }))
                return std::unexpected("TCP publication canceled");
            if (!tcp_admission->publish(next, [&]() noexcept {
                    auto now = std::chrono::steady_clock::now();
                    for (auto const& listener : candidate.listeners) listener.server->publish_principal_bytes(now);
                })) return std::unexpected("cannot publish TCP listeners");
            if (observe_neighbors) monitor->enable_neighbors();
            network = std::move(monitor);
            listener_generation = next;
            candidate_udp->publish_admission();
            udp = std::move(candidate_udp);
            retired->deadline = std::chrono::steady_clock::now() + listener_grace;
            for (auto& listener : listeners) listener.server->begin_drain();
            clear_listener_detours(listeners);
            retired->listeners.swap(listeners);
            retired->dns = std::move(dns_generation);
            if (reuse_dns_binding) dns_messages.replace_program(*candidate.messages);
            else if (candidate.messages) {
                dns_messages.swap(*candidate.messages);
                dns_messages.admit();
                candidate.messages->begin_drain();
                retired->messages = std::move(candidate.messages);
            }
            retired_tcp.push_back(std::move(retired));
            listeners.swap(candidate.listeners);
            if (cert_reloaders) *cert_reloaders = std::move(candidate_cert_reloaders);
            dns_generation = std::move(candidate.dns);
            route_snapshots = std::move(candidate.routes);
            reload_identity = std::move(identity);
            process_identity = std::move(key);
            dns_policy_identity = std::move(dns_key);
            snell_replay = std::move(candidate_replay);
            reverse_cache = std::move(candidate_reverse);
            reload_config = std::move(*config);
            group_health = std::move(candidate_health);
            remote_rulesets.commit_reload(std::move(*staged_remote));
            if (group_route_files || group_health || !reload_config->selectors.empty()) group_route_files = std::move(*files);
            return {};
        }
    };
}
