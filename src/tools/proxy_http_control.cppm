// Private snapshot builder bridging ProxyRun state to control_api::HttpControlServer.
export module cli.proxy_http_control;
import std;
import cli.control;
import cli.proxy_control;
import cli.proxy_control_operations;
import cli.proxy_group_health;
import cli.proxy_listener;
import cli.proxy_mode;
import config;
import control_api;
import control_api.types;
import platform.network_state;
import relay;
import rules;

export namespace cli::run_detail {
    inline auto ordered_action_name(config::OrderedTcpAction action) noexcept -> std::string_view {
        switch (action) {
        case config::OrderedTcpAction::sniff: return "sniff";
        case config::OrderedTcpAction::resolve: return "resolve";
        case config::OrderedTcpAction::route: return "route";
        case config::OrderedTcpAction::reject: return "reject";
        case config::OrderedTcpAction::route_options: return "route-options";
        case config::OrderedTcpAction::hijack_dns: return "hijack-dns";
        case config::OrderedTcpAction::bypass: return "bypass";
        }
        return "route";
    }

    inline auto summarize_rule_predicate(rules::Rule const& rule) -> std::string {
        if (rule.children.empty())
            return rule.value.empty() ? rule.type : std::format("{}={}", rule.type, rule.value);
        std::string out = rule.type + "(";
        for (std::size_t i = 0; i < rule.children.size() && i < 4; ++i) {
            if (i) out += ", ";
            out += summarize_rule_predicate(rule.children[i]);
        }
        if (rule.children.size() > 4) out += std::format(", +{} more", rule.children.size() - 4);
        out.push_back(')');
        return out;
    }

    inline auto build_rules_snapshot(config::Config const& cfg) -> std::vector<control_api::RuleMetric> {
        std::vector<control_api::RuleMetric> out;
        auto default_target = cfg.default_outbound_name.empty()
            ? (cfg.default_outbound == 1 ? std::string("block") : cfg.direct_outbound_name)
            : cfg.default_outbound_name;
        if (cfg.ordered_tcp) {
            out.reserve(cfg.ordered_tcp->rules.size() + 1);
            for (std::size_t i = 0; i < cfg.ordered_tcp->rules.size(); ++i) {
                auto const& r = cfg.ordered_tcp->rules[i];
                control_api::RuleMetric rm{};
                rm.index = i + 1;
                rm.action = std::string(ordered_action_name(r.action));
                if (r.outbound_name) rm.target = *r.outbound_name;
                else if (r.action == config::OrderedTcpAction::bypass) rm.target = cfg.direct_outbound_name;
                else if (r.action == config::OrderedTcpAction::reject) rm.target = "reject";
                else if (r.action == config::OrderedTcpAction::hijack_dns) rm.target = "dns";
                if (r.set_tag) {
                    rm.type = "rule-set";
                    rm.summary = "rule-set=" + *r.set_tag;
                } else if (!r.predicates.rules.empty()) {
                    rm.type = r.predicates.rules.front().type;
                    rm.summary = summarize_rule_predicate(r.predicates.rules.front());
                } else {
                    rm.type = "match-all";
                    rm.summary = "any";
                }
                if (r.domain != config::OrderedTcpDomain::explicit_target) {
                    auto const* src = r.domain == config::OrderedTcpDomain::fakeip ? "fakeip"
                        : (r.domain == config::OrderedTcpDomain::reverse_dns ? "reverse" : "sniffed");
                    rm.summary += std::format(" domain-source={}", src);
                }
                if (rm.summary.size() > 192) { rm.summary.resize(189); rm.summary += "..."; }
                out.push_back(std::move(rm));
            }
            out.push_back({cfg.ordered_tcp->rules.size() + 1, "final",
                cfg.default_outbound == 1 ? "reject" : "route", default_target, "default-outbound"});
            return out;
        }
        out.reserve(cfg.routes.size() + 1);
        for (std::size_t i = 0; i < cfg.routes.size(); ++i) {
            auto const& r = cfg.routes[i];
            auto target = r.outbound_name.empty()
                ? (r.outbound == 1 ? std::string("block") : cfg.direct_outbound_name)
                : r.outbound_name;
            auto summary = !r.file.path.empty() ? r.file.path
                : (!r.file.url.empty() ? r.file.url : std::string("inline"));
            out.push_back({i + 1, "rule-set", r.outbound == 1 ? "reject" : "route", std::move(target), std::move(summary)});
        }
        out.push_back({cfg.routes.size() + 1, "final",
            cfg.default_outbound == 1 ? "reject" : "route", std::move(default_target), "default-outbound"});
        return out;
    }

    template<class Listeners>
    auto build_control_api_snapshot(
        Listeners const& listeners,
        std::optional<config::Config> const& running,
        unsigned workers,
        std::span<std::string const> outbound_names,
        platform::network::Snapshot const* network,
        OutboundGroupHealth const* health,
        ControlOperations const& operations,
        LocalControl const& control,
        RuntimeRouteModeController const* route_mode = nullptr,
        control_api::SnapshotFields fields = control_api::SnapshotFields::all,
        std::optional<std::uint64_t> target_connection_id = std::nullopt,
        std::span<std::unique_ptr<RetiredTcpGeneration> const> retired_tcp = {},
        std::pair<std::uint64_t, std::uint64_t> reclaimed_bytes = {0, 0}) -> control_api::ControlSnapshot {
        control_api::ControlSnapshot snap{};
        bool need_meta = control_api::has_field(fields, control_api::SnapshotFields::meta);
        bool need_listeners = control_api::has_field(fields, control_api::SnapshotFields::listeners);
        bool need_connections = control_api::has_field(fields, control_api::SnapshotFields::connections);
        bool need_groups = control_api::has_field(fields, control_api::SnapshotFields::groups);
        bool need_rules = control_api::has_field(fields, control_api::SnapshotFields::rules);
        if (need_meta) {
            if (route_mode) {
                snap.route_mode = std::string(route_mode->mode_name());
                snap.global_outbound = route_mode->global_outbound_name;
            } else if (running) {
                snap.global_outbound = running->default_outbound_name;
            }
            snap.instance = std::string(operations.resolve_instance(control.instance()));
            snap.workers = workers;
            snap.control_generation = operations.generation();
        }
        auto diag = control.diagnostics();
        snap.authorized_requests = diag.authorized;
        snap.unauthorized_requests = diag.unauthorized;
        snap.expired_requests = diag.expired;
        snap.reply_failed = diag.reply_failed;

        if (need_listeners || need_connections) {
            auto now = std::chrono::steady_clock::now();
            if (need_listeners) snap.listeners.reserve(listeners.size());
            auto collect_rows = [&](std::size_t index, std::span<relay::ActiveConnection const> active_rows) -> bool {
                if (!need_connections) return false;
                for (auto const& row : active_rows) {
                    if (target_connection_id) {
                        if (row.id != *target_connection_id) continue;
                    } else if (snap.connections.size() >= 1024) break;
                    control_api::ConnectionMetric cm{};
                    cm.id = row.id;
                    cm.listener = index;
                    cm.protocol = std::string(relay::traffic_protocol_name(row.protocol));
                    cm.path = std::string(control_path(row.path));
                    cm.destination_port = row.destination_port;
                    cm.upload_bytes = row.bytes.upload;
                    cm.download_bytes = row.bytes.download;
                    cm.inbound = row.inbound_name;
                    if (row.source) cm.source = control_endpoint(*row.source);
                    cm.process_path = row.process_path;
                    cm.source_uid = row.source_uid;
                    cm.can_close = row.can_close;
                    if (now >= row.started)
                        cm.duration_ms = static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(now - row.started).count());
                    if (row.route) {
                        cm.target = control_endpoint(row.route->target);
                        cm.route_mode = row.route->mode == relay::TrafficRouteMode::ordered ? "ordered" : "indexed";
                        cm.route_rule = row.route->rule ? std::to_string(*row.route->rule + 1) : "default";
                        if (row.route->outbound < outbound_names.size())
                            cm.outbound = outbound_names[row.route->outbound];
                    }
                    snap.connections.push_back(std::move(cm));
                    if (target_connection_id) return true;
                }
                return false;
            };
            for (std::size_t index = 0; index < listeners.size(); ++index) {
                auto const& listener = listeners[index];
                auto traffic = listener.server->traffic_snapshot();
                if (need_listeners)
                    snap.listeners.push_back({index, listener.port, traffic.active.size(),
                        traffic.bytes.upload, traffic.bytes.download});
                if (collect_rows(index, traffic.active)) return snap;
            }
            for (auto const& gen : retired_tcp) {
                if (!gen) continue;
                for (std::size_t index = 0; index < gen->listeners.size(); ++index) {
                    auto traffic = gen->listeners[index].server->traffic_snapshot();
                    if (need_listeners && !snap.listeners.empty()) {
                        auto& slot = snap.listeners[std::min(index, snap.listeners.size() - 1)];
                        slot.active_sessions += traffic.active.size();
                        slot.upload_bytes += traffic.bytes.upload;
                        slot.download_bytes += traffic.bytes.download;
                    }
                    if (collect_rows(index, traffic.active)) return snap;
                }
            }
            if (need_listeners && !snap.listeners.empty()) {
                snap.listeners.front().upload_bytes += reclaimed_bytes.first;
                snap.listeners.front().download_bytes += reclaimed_bytes.second;
            }
        }
        if (need_groups && running) {
            auto generation = network ? std::optional(network->generation) : std::nullopt;
            for (std::size_t idx = 0; idx < running->selectors.size(); ++idx) {
                auto const& group = running->selectors[idx];
                control_api::GroupMetric gm{group.name, std::string(control_group_mode(group.mode)),
                    group.selected, health && health->override_member(idx).has_value(), {}};
                for (std::size_t m = 0; m < group.members.size(); ++m) {
                    auto obs = health ? health->observe(*running, idx, m, generation) :
                        OutboundGroupHealth::Observation{.state = "not-probed"};
                    gm.members.push_back({group.members[m], std::string(obs.state), obs.latency_ms,
                        obs.ewma_ms, obs.last_status, obs.breaker_open});
                }
                snap.groups.push_back(std::move(gm));
            }
        }
        if (need_rules && running) snap.rules = build_rules_snapshot(*running);
        return snap;
    }
}
