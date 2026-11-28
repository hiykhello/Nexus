// Routed TUN live hot-reload for inline routing rules and DNS server/rule snapshots.
export module cli.proxy_tun_reload;
import std;
import cli.control;
import cli.dns_message_runtime;
import cli.dns_transports;
import cli.proxy_dns_reload;
import cli.proxy_group_health;
import cli.proxy_listener;
import cli.proxy_selector_state;
import cli.route_files;
import cli.tun_enabled;
import config;
import dns.policy;
import dns.reverse;
import functional;
import logging.cli;
import relay;

export namespace cli::run_detail {
    struct TunReloadRuntime {
        std::vector<Listener>& listeners;
        std::optional<config::Config>& reload_config;
        DnsMessageRuntime& dns_messages;
        std::shared_ptr<relay::RouteSnapshots>& route_snapshots;
        std::optional<RouteFiles>& group_route_files;
        std::optional<OutboundGroupHealth>& group_health;
        std::string& reload_identity;
        logging::Runtime const& logs;
        std::shared_ptr<dns::ReverseCache>& reverse_cache;
        RemoteRulesetManager& remote_rulesets;
    };

    namespace tun_reload_detail {
        inline auto build_relay_dns_routing(config::DnsRouting const& cfg,
            std::span<DnsProtection const> protections) -> relay::DnsRouting {
            relay::DnsRouting routing;
            routing.final = cfg.final;
            for (auto const& view : cfg.views) routing.view_finals.push_back(view.final);
            routing.disable_cache = cfg.disable_cache;
            routing.independent_cache = cfg.independent_cache;
            routing.edns = cfg.edns;
            routing.optimistic_cache_seconds = cfg.optimistic_cache_seconds;
            switch (cfg.strategy) {
            case config::DnsStrategy::automatic: break;
            case config::DnsStrategy::prefer_ipv4: routing.strategy = relay::DnsStrategy::prefer_ipv4; break;
            case config::DnsStrategy::prefer_ipv6: routing.strategy = relay::DnsStrategy::prefer_ipv6; break;
            case config::DnsStrategy::ipv4_only: routing.strategy = relay::DnsStrategy::ipv4_only; break;
            case config::DnsStrategy::ipv6_only: routing.strategy = relay::DnsStrategy::ipv6_only; break;
            }
            routing.servers.reserve(cfg.servers.size());
            for (std::size_t i = 0; i < cfg.servers.size(); ++i) {
                auto const& server = cfg.servers[i];
                relay::DnsServer entry;
                if (server.upstream) {
                    entry = {server.upstream->address, server.upstream->ipv6, server.upstream->port,
                        server.upstream->tcp, server.upstream->host, server.upstream->resolver};
                } else if (server.kind != config::DnsServerKind::standard) {
                    entry.address = {127, 0, 0, 1};
                    entry.port = 53;
                }
                if (i < protections.size()) entry.protection = protections[i];
                entry.proxy_detour = server.upstream && (server.upstream->detour_index || server.upstream->detour_group);
                routing.servers.push_back(std::move(entry));
            }
            routing.rules = cfg.rules;
            return routing;
        }

        inline auto strict_tun_dns_hijack_state(config::Config const& cfg) noexcept
            -> std::tuple<bool, bool, bool> {
            bool has_hijack = cfg.ordered_tcp && std::ranges::any_of(cfg.ordered_tcp->rules,
                [](auto const& rule) { return rule.action == config::OrderedTcpAction::hijack_dns; });
            bool tcp_dns = false;
            for (auto const& in : cfg.inbounds) {
                if (!in.tun || !in.tun->strict_route) continue;
                tcp_dns = in.tun->dns_hijack_tcp || (has_hijack && cfg.dns.has_value());
                break;
            }
            bool udp_dns = cfg.ordered_tcp && cfg.ordered_tcp->udp && has_hijack;
            return {has_hijack, tcp_dns, udp_dns};
        }

        inline auto outbound_bootstraps_match(config::Config const& running, config::Config const& requested) noexcept -> bool {
            auto same_vec = [](auto const& a, auto const& b) noexcept -> bool {
                if (a.size() != b.size()) return false;
                for (std::size_t i = 0; i < a.size(); ++i) {
                    auto const& ca = [&]() -> auto const& {
                        if constexpr (requires { a[i].config.connection; }) return a[i].config.connection;
                        else return a[i].config;
                    }();
                    auto const& cb = [&]() -> auto const& {
                        if constexpr (requires { b[i].config.connection; }) return b[i].config.connection;
                        else return b[i].config;
                    }();
                    if constexpr (requires { ca.bootstrap_index; }) {
                        if (ca.bootstrap_index != cb.bootstrap_index) return false;
                    }
                }
                return true;
            };
            auto all_same = [&](auto const&... pairs) noexcept { return (same_vec(pairs.first.get(), pairs.second.get()) && ...); };
            if (!all_same(
                    std::pair{std::cref(running.vless_outbounds), std::cref(requested.vless_outbounds)},
                    std::pair{std::cref(running.shadowsocks_outbounds), std::cref(requested.shadowsocks_outbounds)},
                    std::pair{std::cref(running.trojan_outbounds), std::cref(requested.trojan_outbounds)},
                    std::pair{std::cref(running.anytls_outbounds), std::cref(requested.anytls_outbounds)},
                    std::pair{std::cref(running.hysteria2_outbounds), std::cref(requested.hysteria2_outbounds)},
                    std::pair{std::cref(running.snell_outbounds), std::cref(requested.snell_outbounds)},
                    std::pair{std::cref(running.shadowtls_outbounds), std::cref(requested.shadowtls_outbounds)},
                    std::pair{std::cref(running.tuic_outbounds), std::cref(requested.tuic_outbounds)},
                    std::pair{std::cref(running.masque_outbounds), std::cref(requested.masque_outbounds)},
                    std::pair{std::cref(running.wireguard_outbounds), std::cref(requested.wireguard_outbounds)},
                    std::pair{std::cref(running.ssh_outbounds), std::cref(requested.ssh_outbounds)},
                    std::pair{std::cref(running.naive_outbounds), std::cref(requested.naive_outbounds)},
                    std::pair{std::cref(running.openvpn_outbounds), std::cref(requested.openvpn_outbounds)},
                    std::pair{std::cref(running.openconnect_outbounds), std::cref(requested.openconnect_outbounds)},
                    std::pair{std::cref(running.tcp_proxy_outbounds), std::cref(requested.tcp_proxy_outbounds)}))
                return false;
            if (running.inbounds.size() != requested.inbounds.size()) return false;
            for (std::size_t i = 0; i < running.inbounds.size(); ++i) {
                auto const& ra = running.inbounds[i].vless;
                auto const& rb = requested.inbounds[i].vless;
                if (bool(ra && ra->reality) != bool(rb && rb->reality)) return false;
                if (ra && ra->reality && ra->reality->fallback_resolver_index != rb->reality->fallback_resolver_index)
                    return false;
            }
            return true;
        }
    }

    struct TunLiveReload {
        struct AppliedRouteSets {
            std::vector<std::string> includes;
            std::vector<std::string> excludes;
        };
        struct PendingTunUpdate {
            std::size_t index;
            config::TunInbound tun;
            AppliedRouteSets sets;
        };
        std::string tun_live_identity;
        bool identity_initialized = false;
        std::vector<AppliedRouteSets> applied_route_sets;

        auto record_initial_route_sets(config::Config const& cfg, RouteFiles const& files)
            -> std::expected<void, std::string> {
            applied_route_sets.clear();
            applied_route_sets.resize(cfg.inbounds.size());
            for (std::size_t i = 0; i < cfg.inbounds.size(); ++i) {
                auto const& in = cfg.inbounds[i];
                if (!in.tun) continue;
                auto copy = *in.tun;
                if (!copy.route_address_sets.empty() || !copy.route_exclude_address_sets.empty()) {
                    if (auto ok = cli::apply_tun_route_sets(copy, files); !ok) return ok;
                }
                applied_route_sets[i] = {std::move(copy.route_includes), std::move(copy.route_excludes)};
            }
            return {};
        }

        auto plan_route_set_updates(config::Config const& cfg, RouteFiles const& files) const
            -> std::expected<std::vector<PendingTunUpdate>, std::string> {
            std::vector<PendingTunUpdate> pending;
            for (std::size_t i = 0; i < cfg.inbounds.size(); ++i) {
                auto const& in = cfg.inbounds[i];
                if (!in.tun) continue;
                bool has_sets = !in.tun->route_address_sets.empty() || !in.tun->route_exclude_address_sets.empty();
                bool had_applied = i < applied_route_sets.size() &&
                    (!applied_route_sets[i].includes.empty() || !applied_route_sets[i].excludes.empty());
                if (!has_sets && !had_applied) continue;
                auto copy = *in.tun;
                if (has_sets) {
                    if (auto ok = cli::apply_tun_route_sets(copy, files); !ok) return std::unexpected(std::move(ok.error()));
                }
                if (i >= applied_route_sets.size() ||
                    copy.route_includes != applied_route_sets[i].includes ||
                    copy.route_excludes != applied_route_sets[i].excludes) {
                    AppliedRouteSets next_sets{copy.route_includes, copy.route_excludes};
                    pending.push_back({i, std::move(copy), std::move(next_sets)});
                }
            }
            return pending;
        }

        auto commit_route_set_updates(std::span<PendingTunUpdate> pending, std::size_t inbound_count, auto&& apply_fn)
            -> std::expected<void, std::string> {
            if (pending.empty()) return {};
            if (applied_route_sets.size() < inbound_count) applied_route_sets.resize(inbound_count);
            for (auto& upd : pending) {
                auto applied = apply_fn(upd.index, upd.tun);
                if (!applied) return std::unexpected("TUN live route-set update failed: " + applied.error());
                if (!*applied) return std::unexpected("changing TUN kernel route address sets requires restart");
                applied_route_sets[upd.index] = std::move(upd.sets);
            }
            return {};
        }

        auto publish_same_config_routes_with(auto const& listeners, relay::RouteSnapshots& snapshots,
            config::Config const& cfg, RouteFiles const& files, bool replace_dns_policy,
            OutboundGroupHealth const* health, auto&& apply_fn) -> std::expected<void, std::string> {
            auto pending = plan_route_set_updates(cfg, files);
            if (!pending) return std::unexpected(std::move(pending.error()));
            auto apply_tun = [&]() -> std::expected<void, std::string> {
                return commit_route_set_updates(*pending, cfg.inbounds.size(), apply_fn);
            };
            using Hook = functional::function_ref<std::expected<void, std::string>()>;
            return publish_group_routes(listeners, snapshots, cfg, files, replace_dns_policy,
                pending->empty() ? std::optional<Hook>{} : std::optional<Hook>{apply_tun}, health);
        }

        auto publish_same_config_routes(auto const& listeners, relay::RouteSnapshots& snapshots,
            config::Config const& cfg, RouteFiles const& files, bool replace_dns_policy,
            OutboundGroupHealth const* health) -> std::expected<void, std::string> {
            return publish_same_config_routes_with(listeners, snapshots, cfg, files, replace_dns_policy, health,
                [&](std::size_t idx, config::TunInbound const& tun) {
                    return cli::tun_enabled::update_active_tun_route_sets(listeners[idx].server.get(), tun);
                });
        }

        auto ensure_identity(std::string_view source) -> std::expected<void, std::string> {
            if (identity_initialized) return {};
            auto id = config::reload_identity(source, config::ReloadIdentity::tun_live);
            if (!id) return std::unexpected(std::move(id.error()));
            tun_live_identity = std::move(*id);
            identity_initialized = true;
            return {};
        }

        auto apply(TunReloadRuntime rt, std::string_view config_path, config::Config requested,
            config::ReloadIdentities ids, std::span<SelectorChoice const> choices, std::string_view input = {})
            -> std::expected<void, std::string> {
            if (!rt.reload_config || !rt.route_snapshots)
                return std::unexpected("configuration change requires restart");
            if (ids.tun_live != tun_live_identity)
                return std::unexpected("configuration change requires restart");
            auto const& running = *rt.reload_config;
            if (running.inbounds.size() != requested.inbounds.size() || rt.listeners.size() != requested.inbounds.size())
                return std::unexpected("configuration change requires restart");

            bool has_strict_tun = std::ranges::any_of(running.inbounds, [](auto const& in) {
                return in.tun && in.tun->strict_route;
            });
            if (has_strict_tun &&
                tun_reload_detail::strict_tun_dns_hijack_state(running) !=
                    tun_reload_detail::strict_tun_dns_hijack_state(requested)) {
                return std::unexpected("changing TUN strict-route DNS hijack requires restart");
            }
#ifndef NEXUS_DNS_SHARED
            if (!running.dns && requested.dns)
                return std::unexpected("adding DNS requires restart");
#endif
            bool had_reverse = running.dns && running.dns->reverse_mapping;
            bool want_reverse = requested.dns && requested.dns->reverse_mapping;
            if (had_reverse != want_reverse)
                return std::unexpected("changing DNS reverse-mapping requires restart");
            if (!tun_reload_detail::outbound_bootstraps_match(running, requested))
                return std::unexpected("changing outbound bootstrap resolver requires restart");

            requested.direct_tcp_options.binding.network = running.direct_tcp_options.binding.network;
            config::Config next_cfg = std::move(requested);
            if (!next_cfg.selectors.empty()) {
                auto wanted = next_cfg;
                for (auto& group : wanted.selectors) {
                    if (group.mode == config::OutboundGroupMode::select) continue;
                    auto active_group = std::ranges::find(running.selectors, group.name, &config::OutboundSelector::name);
                    if (active_group != running.selectors.end() && std::ranges::contains(group.members, active_group->selected))
                        group.selected = active_group->selected;
                }
                if (auto restored = overlay_selector_state(wanted, choices); !restored) return restored;
                auto reselected = config::reselect_outbounds(next_cfg, wanted);
                if (!reselected) return std::unexpected(std::move(reselected.error()));
                if (auto stable = config::reselect_outbounds(running, *reselected); !stable)
                    return std::unexpected(std::move(stable.error()));
                next_cfg = std::move(*reselected);
            }

            cli::RuleFileInput rule_input(config_path);
            auto staged_remote = rt.remote_rulesets.prepare_reload(next_cfg, input, rule_input);
            if (!staged_remote) return std::unexpected(std::move(staged_remote.error()));
            if (next_cfg.dns) {
                if (auto loaded = load_dns_rules(*next_cfg.dns, rule_input); !loaded)
                    return std::unexpected(std::move(loaded.error()));
            }
#ifdef NEXUS_DNS_RESPONSE
            bool had_response = running.dns && policy::dns_has_response_program(running.dns->rules);
            bool want_response = next_cfg.dns && policy::dns_has_response_program(next_cfg.dns->rules);
            if (!had_response && want_response)
                return std::unexpected("adding response-phase DNS rules requires restart");
#endif
            auto files = cli::load_route_files(next_cfg, rule_input);
            if (!files) return std::unexpected(std::move(files.error()));
            auto pending_tun = plan_route_set_updates(next_cfg, *files);
            if (!pending_tun) return std::unexpected(std::move(pending_tun.error()));

            auto protections = cli::prepare_dns_transports(next_cfg);
            if (!protections) return std::unexpected(std::move(protections.error()));
            auto active = rt.route_snapshots->load(std::memory_order_acquire);
            auto generation = active && !active->empty() ? active->front().generation + 1 : std::uint64_t{2};
            auto prev_transports = active && !active->empty() ? active->front().dns_transports : nullptr;
            auto transports = cli::prepare_dns_transport_snapshot(next_cfg, generation, prev_transports, true);
            if (!transports) return std::unexpected(std::move(transports.error()));

            std::shared_ptr<relay::DnsRuntimeSnapshot const> dns_runtime;
            std::shared_ptr<relay::DnsRuleSnapshot const> dns_rule_snap;
            if (next_cfg.dns) {
                auto relay_dns = tun_reload_detail::build_relay_dns_routing(*next_cfg.dns, *protections);
                auto compiled_dns = relay::compile_dns_runtime_snapshot(std::move(relay_dns), generation);
                if (!compiled_dns) return std::unexpected(std::move(compiled_dns.error()));
                dns_runtime = std::move(*compiled_dns);
                auto view = next_cfg.dns->fakeip
                    ? durable_fakeip_view(next_cfg) : generation;
                dns_rule_snap = std::make_shared<relay::DnsRuleSnapshot>(next_cfg.dns->rules, view);
            }

            std::optional<DnsMessageRuntime> candidate_messages;
            if (rt.dns_messages.has_listeners() || (next_cfg.dns && next_cfg.dns->listen)) {
                if (!rt.dns_messages.has_listeners() || !next_cfg.dns || !next_cfg.dns->listen)
                    return std::unexpected("changing DNS listen endpoint requires restart");
                candidate_messages.emplace(rt.logs);
                if (auto prepared = candidate_messages->prepare(next_cfg, *protections,
                        dns_rule_source(rt.route_snapshots), &rt.dns_messages, rt.reverse_cache); !prepared)
                    return std::unexpected("DNS listener: " + prepared.error());
                if (!rt.dns_messages.same_binding(*candidate_messages))
                    return std::unexpected("changing DNS listen endpoint requires restart");
            }

            auto routes = cli::project_routes(next_cfg, *files);
            if (rt.group_health) routes.distribution = rt.group_health->filter_distribution(next_cfg, std::move(routes.distribution));
            auto next = std::make_shared<std::vector<relay::RouteSnapshot>>();
            next->reserve(rt.listeners.size());
            for (std::size_t i = 0; i < rt.listeners.size(); ++i) {
                auto candidate = rt.listeners[i].server->compile_route_snapshot({}, routes.default_outbound,
                    next_cfg.inbounds[i].name, routes.program(next_cfg), routes.distribution);
                if (!candidate) return std::unexpected(std::move(candidate.error()));
                candidate->dns = dns_rule_snap;
                candidate->dns_transports = *transports;
                candidate->dns_runtime = dns_runtime;
                candidate->dns_disabled = !next_cfg.dns.has_value();
                candidate->generation = generation;
                next->push_back(std::move(*candidate));
            }

            if (auto committed = commit_route_set_updates(*pending_tun, next_cfg.inbounds.size(),
                    [&](std::size_t idx, config::TunInbound const& tun) {
                        return cli::tun_enabled::update_active_tun_route_sets(rt.listeners[idx].server.get(), tun);
                    }); !committed) return committed;
            rt.route_snapshots->store(std::move(next), std::memory_order_release);
            if (candidate_messages) rt.dns_messages.replace_program(*candidate_messages);
            rt.reload_identity = std::move(ids.full);
            rt.reload_config = std::move(next_cfg);
            rt.remote_rulesets.commit_reload(std::move(*staged_remote));
            if (rt.group_route_files) *rt.group_route_files = std::move(*files);
            return {};
        }
    };
}
