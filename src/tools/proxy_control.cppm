// Private command adapter for the CLI host. Socket transport owns packet limits
// and peer authorization; Session workers keep ownership of connection close.
export module cli.proxy_control;
import std;
import cli.control;
import cli.proxy_control_operations;
import cli.proxy_group_health;
import cli.proxy_mode;
import cli.proxy_outbound_probe;
import cli.proxy_run_state;
import config;
import dns.reverse;
import functional;
import platform.ip_address;
import platform.network_state;
import relay;
import rules;
import state.core;
import state.dns_cache;
import state.file;
import state.maintenance;
import state.ruleset_cache;

export namespace cli::run_detail {
    inline auto control_path(relay::ConnectPath path) noexcept -> std::string_view {
        switch (path) {
        case relay::ConnectPath::dialing: return "dialing";
        case relay::ConnectPath::direct: return "direct";
        case relay::ConnectPath::tunnel: return "tunnel";
        case relay::ConnectPath::datagrams: return "datagrams";
        }
        return {};
    }

    inline auto control_endpoint(auto const& endpoint) -> std::string {
        if (endpoint.family == 6) {
            std::array<std::uint8_t, 16> v6{};
            std::copy_n(endpoint.address.begin(), 16, v6.begin());
            return std::format("[{}]:{}", platform::format_ipv6(v6), endpoint.port);
        }
        std::array<std::uint8_t, 4> v4{};
        std::copy_n(endpoint.address.begin(), 4, v4.begin());
        return std::format("{}:{}", platform::format_ipv4(v4), endpoint.port);
    }

    inline auto control_group_mode(config::OutboundGroupMode mode) noexcept -> std::string_view {
        switch (mode) {
        case config::OutboundGroupMode::select: return "selector";
        case config::OutboundGroupMode::fallback: return "fallback";
        case config::OutboundGroupMode::url_test: return "url-test";
        case config::OutboundGroupMode::load_balance: return "load-balance";
        }
        std::unreachable();
    }

    template<class Listeners>
    auto control_request(Listeners& listeners, std::optional<config::Config>& running, unsigned workers,
        std::span<std::string const> outbound_names, std::span<std::string_view const> args,
        functional::function_ref<std::expected<bool, std::string>(config::Config const&, std::string_view, std::string_view, bool)> publish,
        std::optional<std::uint64_t> listener_generation, platform::network::Snapshot const* network,
        OutboundGroupHealth* health, ControlRole role, ControlOperations& operations, LocalControl const& control,
        dns::ReverseCache* reverse_cache = nullptr, RuntimeRouteModeController* route_mode = nullptr,
        AdHocOutboundProber* prober = nullptr, bool reload_supported = true)
        -> std::expected<std::string, std::string> {
        auto command = args.front();
        if (role == ControlRole::reader && command != "status" && command != "operation" &&
            command != "events" && command != "diagnostics" && command != "probe-result" &&
            !(command == "mode" && args.size() == 1)) return std::unexpected("permission-denied");
        if (command == "mode")
            return route_mode ? route_mode->handle_command(running, role, args, operations) : std::unexpected("mode-unavailable");
        if (command == "connection" && args.size() == 2) {
            auto id = control_number(args[1]);
            if (!id || !*id) return std::unexpected("invalid-id");
            auto now = std::chrono::steady_clock::now();
            for (std::size_t idx = 0; idx < listeners.size(); ++idx) {
                auto snap = listeners[idx].server->traffic_snapshot();
                for (auto const& row : snap.active) {
                    if (row.id != *id) continue;
                    auto dur = now >= row.started ? std::chrono::duration_cast<std::chrono::milliseconds>(now - row.started).count() : 0;
                    auto out = std::format("id={} listener={} protocol={} path={} destination-port={} duration-ms={} can-close={} upload={} download={}",
                        row.id, idx, relay::traffic_protocol_name(row.protocol), control_path(row.path),
                        row.destination_port, dur, row.can_close ? 1 : 0, row.bytes.upload, row.bytes.download);
                    if (!row.inbound_name.empty()) out += std::format(" inbound={}", control_name(row.inbound_name));
                    if (row.source) out += std::format(" source={}", control_endpoint(*row.source));
                    if (!row.process_path.empty()) out += std::format(" process-path={:?}", row.process_path);
                    if (row.source_uid) out += std::format(" source-uid={}", *row.source_uid);
                    if (row.route) {
                        out += std::format(" target={} route-mode={} route-rule={}", control_endpoint(row.route->target),
                            row.route->mode == relay::TrafficRouteMode::ordered ? "ordered" : "indexed",
                            row.route->rule ? std::to_string(*row.route->rule + 1) : "default");
                        if (row.route->outbound < outbound_names.size())
                            out += std::format(" outbound={}", control_name(outbound_names[row.route->outbound]));
                    }
                    return out + "\n";
                }
            }
            return std::unexpected("unknown-connection");
        }
        if (command == "events" && args.size() <= 3)
            return operations.events(args, control.instance());
        if (command == "diagnostics" && args.size() == 1) {
            auto info = control.diagnostics();
            return std::format("authorized={} unauthorized={} expired={} reply-failed={}\n",
                info.authorized, info.unauthorized, info.expired, info.reply_failed);
        }
        if (command == "reload" && args.size() == 1) {
            if (!running || !reload_supported) return std::unexpected("reload-unavailable");
            return operations.queue_reload();
        }
        if (command == "clear-cache" && (args.size() == 1 || args.size() == 2)) {
            auto target = args.size() == 2 ? args[1] : std::string_view("all");
            if (target != "all" && target != "dns" && target != "rulesets")
                return std::unexpected("invalid-cache-target");
            bool clear_dns = (target == "all" || target == "dns");
            bool clear_rules = (target == "all" || target == "rulesets");
            if (running) {
                auto options = running->state.value_or(config::StateOptions{});
                if (!options.cache_directory.empty()) {
                    auto dir = ::state::ensure_private_directory(options.cache_directory);
                    if (!dir) return std::unexpected(std::string(::state::describe(dir.error().stage)));
                    if (clear_dns) {
                        auto done = ::state::DnsCache(options.cache_directory, options.dns_cache_max_bytes).clear();
                        if (!done) return std::unexpected(std::string(::state::describe(done.error().stage)));
                    }
                    if (clear_rules) {
                        auto done = ::state::RulesetCache(options.cache_directory, {options.ruleset_cache_max_bytes}).clear();
                        if (!done) return std::unexpected(std::string(::state::describe(done.error().stage)));
                    }
                }
                if (clear_dns && running->dns && !running->dns->message_cache_directory.empty()) {
                    auto done = ::state::clear_legacy_dns(running->dns->message_cache_directory);
                    if (!done) return std::unexpected(std::string(::state::describe(done.error().stage)));
                }
            }
            if (clear_dns && reverse_cache) (void)reverse_cache->clear();
            operations.published();
            operations.record(ControlOperations::EventKind::cache_cleared);
            return std::format("cleared={}\n", target == "all" ? "dns,rulesets" : target);
        }
        if (command == "network-change" && (args.size() == 1 || args.size() == 2)) {
            if (health) health->invalidate_network();
            operations.published();
            operations.record(ControlOperations::EventKind::network_changed);
            return std::format("network-changed control-generation={}\n", operations.generation());
        }
        if (command == "close-any" && args.size() == 2) {
            auto id = control_number(args[1]);
            if (!id || !*id) return std::unexpected("invalid-id");
            bool unavailable = false;
            for (auto& listener : listeners) {
                switch (listener.server->request_traffic_close(*id)) {
                case relay::TrafficCloseRequest::queued:
                    operations.record(ControlOperations::EventKind::close_queued);
                    return std::string("queued\n");
                case relay::TrafficCloseRequest::missing: break;
                case relay::TrafficCloseRequest::unavailable: unavailable = true; break;
                }
            }
            return std::unexpected(unavailable ? "close-unavailable" : "unknown-connection");
        }
        if (command == "close-all" && args.size() == 1) {
            std::size_t closed = 0;
            for (auto& listener : listeners) {
                auto snapshot = listener.server->traffic_snapshot();
                for (auto const& row : snapshot.active) {
                    if (listener.server->request_traffic_close(row.id) == relay::TrafficCloseRequest::queued) ++closed;
                }
            }
            if (closed > 0) operations.record(ControlOperations::EventKind::close_queued);
            return std::format("closed={}\n", closed);
        }
        if (command == "probe-outbound" && args.size() >= 2 && args.size() <= 5) {
            if (!running || !prober) return std::unexpected("probe-unavailable");
            std::string_view url = args.size() >= 3 ? args[2] : std::string_view{};
            if (url == "-") url = {};
            std::optional<std::uint32_t> timeout_ms;
            if (args.size() >= 4 && args[3] != "-") {
                auto parsed = control_number(args[3]);
                if (!parsed || *parsed == 0 || *parsed > 3600000u) return std::unexpected("invalid-timeout");
                timeout_ms = static_cast<std::uint32_t>(*parsed);
            }
            std::string_view mode = args.size() >= 5 ? args[4] : std::string_view{};
            auto res = prober->enqueue(*running, args[1], url, timeout_ms, mode, listeners_support_outbound_probe(listeners));
            if (res) operations.record(ControlOperations::EventKind::probe_triggered);
            return res;
        }
        if (command == "probe-result" && args.size() == 2) {
            if (!prober) return std::unexpected("probe-unavailable");
            auto id = control_number(args[1]);
            if (!id || !*id) return std::unexpected("invalid-id");
            return prober->result(*id);
        }
        if (command == "probe" && args.size() == 2) {
            if (!running) return std::unexpected("unknown-group");
            auto group = std::ranges::find(running->selectors, args[1], &config::OutboundSelector::name);
            if (group == running->selectors.end()) return std::unexpected("unknown-group");
            if (group->mode != config::OutboundGroupMode::url_test && group->mode != config::OutboundGroupMode::fallback &&
                (group->mode != config::OutboundGroupMode::load_balance || group->probe.url.empty()))
                return std::unexpected("not-probe-group");
            auto index = static_cast<std::size_t>(group - running->selectors.begin());
            if (!health || !health->trigger_probe(index)) return std::unexpected("probe-unavailable");
            operations.record(ControlOperations::EventKind::probe_triggered);
            return std::format("group={} probe=triggered\n", control_name(group->name));
        }
        if (command == "operation" && args.size() == 2)
            return operations.operation(args[1]);
        if (command == "group-health" && args.size() == 2) {
            if (!running) return std::unexpected("unknown-group");
            auto group = std::ranges::find(running->selectors, args[1], &config::OutboundSelector::name);
            if (group == running->selectors.end()) return std::unexpected("unknown-group");
            auto index = static_cast<std::size_t>(group - running->selectors.begin());
            auto generation = running->direct_network && network ? std::optional(network->generation) : std::nullopt;
            auto overridden = health && health->override_member(index).has_value();
            auto result = std::format("group={} mode={} selected={}{}\n",
                control_name(group->name), control_group_mode(group->mode), control_name(group->selected),
                overridden ? " override=1" : "");
            for (auto const& [member, name] : std::views::enumerate(group->members)) {
                auto row = health ? health->observe(*running, index, member, generation) :
                    OutboundGroupHealth::Observation{.outbound = config::configured_outbound_index(*running, name), .state = "not-probed"};
                result += std::format("member={} state={} probing={}", control_name(name), row.state, row.probing ? 1 : 0);
                if (row.outbound && *row.outbound < outbound_names.size())
                    result += std::format(" outbound={}", control_name(outbound_names[*row.outbound]));
                if (row.latency_ms) result += std::format(" latency-ms={}", *row.latency_ms);
                if (row.ewma_ms) result += std::format(" ewma-ms={}", *row.ewma_ms);
                if (row.last_status) result += std::format(" last-status={}", *row.last_status);
                if (row.breaker_open) result += " breaker=1";
                if (row.age) result += std::format(" sample-age-ms={}", row.age->count());
                result += '\n';
            }
            return result;
        }
        if (command == "user-usage" && args.size() == 2) {
            auto index = control_number(args[1]);
            if (!index || *index >= listeners.size()) return std::unexpected("unknown-listener");
            auto* principals = listeners[*index].server->principal_policy();
            if (!principals) return std::unexpected("no-authenticated-users");
            std::string result;
            for (auto const& budget : principals->entries()) {
                auto usage = budget.usage();
                result += std::format("user={} connections={} streams={} rejected-connections={} rejected-streams={}",
                    control_name(budget.limits().name), usage.connections, usage.streams, usage.rejected_connections, usage.rejected_streams);
                if (budget.bytes().metered()) {
                    auto bytes = budget.bytes().usage();
                    result += std::format(" upload={} download={} unconfirmed={} byte-limit-denials={}",
                        bytes.uploaded, bytes.downloaded, bytes.unconfirmed, bytes.denied);
                }
                result += '\n';
            }
            return result;
        }
        if (command == "status" && args.size() == 1) {
            std::string result = std::format("state=running workers={} listeners={}\n", workers, listeners.size());
            result += std::format("control-generation={}\ninstance={}\n", operations.generation(), control.instance());
            if (listener_generation) result += std::format("listener-generation={}\n", *listener_generation);
            if (network) {
                std::size_t ipv4_defaults = 0, ipv6_defaults = 0;
                for (auto const& route : network->routes) {
                    if (!route.default_route()) continue;
                    if (route.family == platform::network::constants::af_inet) ++ipv4_defaults;
                    else if (route.family == platform::network::constants::af_inet6) ++ipv6_defaults;
                }
                result += std::format("network-generation={} links={} addresses={} default-ipv4-routes={} default-ipv6-routes={}\n",
                    network->generation, network->links.size(), network->addresses.size(), ipv4_defaults, ipv6_defaults);
            } else result += "network-generation=unknown\n";
            for (std::size_t index = 0; index < listeners.size(); ++index) {
                auto const& listener = listeners[index];
                auto snapshot = listener.server->traffic_snapshot();
                result += std::format("listener={} port={} active={} upload={} download={}\n",
                    index, listener.port, snapshot.active.size(), snapshot.bytes.upload, snapshot.bytes.download);
            }
            if (running && role == ControlRole::administrator)
                for (std::size_t idx = 0; idx < running->selectors.size(); ++idx) {
                    auto const& group = running->selectors[idx];
                    auto overridden = health && health->override_member(idx).has_value();
                    result += std::format("group={} selected={}{}\n", control_name(group.name),
                        control_name(group.selected), overridden ? " override=1" : "");
                }
            return result;
        }
        auto mutation = command == "select" || command == "close";
        if (mutation && (args.size() == 4 || args.size() == 5)) {
            auto generation = control_number(args[3]);
            if (!generation || !*generation) return std::unexpected("invalid-generation");
            if (*generation != operations.generation() || (args.size() == 5 && args[4] != control.instance()))
                return std::unexpected("stale-generation");
        }
        if ((command == "connections" && (args.size() == 2 || args.size() == 3)) ||
            (command == "close" && args.size() >= 3 && args.size() <= 5)) {
            auto index = control_number(args[1]);
            if (!index || *index >= listeners.size()) return std::unexpected("unknown-listener");
            auto cursor = args.size() >= 3 ? control_number(args[2]) : std::optional<std::uint64_t>{0};
            if (!cursor) return std::unexpected("invalid-id");
            auto& server = *listeners[*index].server;
            if (command == "close") {
                switch (server.request_traffic_close(*cursor)) {
                case relay::TrafficCloseRequest::queued:
                    operations.record(ControlOperations::EventKind::close_queued);
                    return std::string("queued\n");
                case relay::TrafficCloseRequest::missing: return std::unexpected("unknown-connection");
                case relay::TrafficCloseRequest::unavailable: return std::unexpected("close-unavailable");
                }
            }
            auto snapshot = server.traffic_snapshot();
            auto& rows = snapshot.active;
            std::ranges::sort(rows, {}, &relay::ActiveConnection::id);
            auto next = std::ranges::upper_bound(rows, *cursor, {}, &relay::ActiveConnection::id);
            std::string result;
            for (std::size_t count = 0; next != rows.end() && count < 96; ++count, ++next) {
                auto const& row = *next;
                auto line = std::format("id={} protocol={} path={} source-port={} destination-port={} can-close={} upload={} download={}",
                    row.id, relay::traffic_protocol_name(row.protocol), control_path(row.path),
                    row.source ? row.source->port : 0, row.destination_port, row.can_close ? 1 : 0,
                    row.bytes.upload, row.bytes.download);
                if (!row.process_path.empty()) line += std::format(" process-path={:?}", row.process_path);
                if (row.source_uid) line += std::format(" source-uid={}", *row.source_uid);
                if (row.transparent_datagram) {
                    auto const& incoming = *row.transparent_datagram;
                    if (row.source) line += std::format(" transport-source={}", control_endpoint(*row.source));
                    line += std::format(" original-destination={}", control_endpoint(incoming.original_destination));
                    if (incoming.ingress_ifindex) line += std::format(" ingress-ifindex={}", incoming.ingress_ifindex);
                }
                if (row.route_generation) line += std::format(" route-generation={}", row.route_generation);
                if (row.route) {
                    auto const& route = *row.route;
                    auto mode = route.mode == relay::TrafficRouteMode::ordered ? "ordered" : "indexed";
                    line += std::format(" route-mode={} route-target={}", mode, control_endpoint(route.target));
                    if (route.rule) line += std::format(" route-rule={}", *route.rule + 1);
                    else line += " route-rule=default";
                    if (route.predicate) line += std::format(" route-predicate={}", *route.predicate + 1);
                    if (route.outbound < outbound_names.size()) {
                        line += std::format(" outbound={}", control_name(outbound_names[route.outbound]));
                    }
                    line += std::format(" outbound-index={}", route.outbound);
                }
                if (result.size() + line.size() >= 60 * 1024) break;
                result += line;
                result += '\n';
            }
            if (next != rows.end()) result += std::format("next={}\n", std::prev(next)->id);
            return result;
        }
        if (command == "select" && args.size() >= 3 && args.size() <= 5) {
            if (!running) return std::unexpected("selection-unavailable");
            auto requested = *running;
            auto group = std::ranges::find(requested.selectors, args[1], &config::OutboundSelector::name);
            if (group == requested.selectors.end()) return std::unexpected("unknown-group");
            auto index = static_cast<std::size_t>(group - requested.selectors.begin());
            if (group->mode == config::OutboundGroupMode::url_test) {
                if (!health) return std::unexpected("selection-unavailable");
                auto generation = running->direct_network && network ? std::optional(network->generation) : std::nullopt;
                bool reset = (args[2] == "--auto");
                std::string target_member;
                if (reset) {
                    auto best = health->best_up_member(*running, index, generation);
                    target_member = best ? std::string(*best) : group->selected;
                } else {
                    if (std::ranges::find(group->members, args[2]) == group->members.end())
                        return std::unexpected("unknown-group-member");
                    target_member = std::string(args[2]);
                }
                group->selected = target_member;
                auto candidate = config::reselect_outbounds(*running, requested);
                if (!candidate) return std::unexpected(std::move(candidate.error()));
                auto published = publish(*candidate, args[1], target_member, false);
                if (!published) return std::unexpected(std::move(published.error()));
                if (reset) health->clear_override(index);
                else health->set_override(index, target_member);
                *running = std::move(*candidate);
                operations.published();
                operations.record(ControlOperations::EventKind::selector_changed);
                return std::format("group={} selected={} override={}\n",
                    control_name(args[1]), control_name(target_member), reset ? 0 : 1);
            }
            if (group->mode != config::OutboundGroupMode::select) return std::unexpected("group-is-automatic");
            if (std::ranges::find(group->members, args[2]) == group->members.end())
                return std::unexpected("unknown-group-member");
            group->selected = args[2];
            auto candidate = config::reselect_outbounds(*running, requested);
            if (!candidate) return std::unexpected(std::move(candidate.error()));
            auto response = std::format("group={} selected={}\n", control_name(args[1]), control_name(args[2]));
            auto published = publish(*candidate, args[1], args[2], true);
            if (!published) return std::unexpected(std::move(published.error()));
            *running = std::move(*candidate);
            operations.published();
            operations.record(ControlOperations::EventKind::selector_changed);
            if (!*published) return std::unexpected("selector-active-persistence-uncertain");
            return response;
        }
        return std::unexpected("invalid-command-or-arguments");
    }
}
