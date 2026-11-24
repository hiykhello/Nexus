// Private snapshot builder bridging ProxyRun state to control_api::HttpControlServer.
export module cli.proxy_http_control;
import std;
import cli.control;
import cli.proxy_control;
import cli.proxy_control_operations;
import cli.proxy_group_health;
import cli.proxy_mode;
import config;
import control_api;
import control_api.types;
import platform.network_state;
import relay;

export namespace cli::run_detail {
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
        std::optional<std::uint64_t> target_connection_id = std::nullopt) -> control_api::ControlSnapshot {
        control_api::ControlSnapshot snap{};
        bool need_meta = control_api::has_field(fields, control_api::SnapshotFields::meta);
        bool need_listeners = control_api::has_field(fields, control_api::SnapshotFields::listeners);
        bool need_connections = control_api::has_field(fields, control_api::SnapshotFields::connections);
        bool need_groups = control_api::has_field(fields, control_api::SnapshotFields::groups);
        if (need_meta) {
            if (route_mode) {
                snap.route_mode = std::string(route_mode->mode_name());
                snap.global_outbound = route_mode->global_outbound_name;
            } else if (running) {
                snap.global_outbound = running->default_outbound_name;
            }
            snap.instance = std::string(control.instance());
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
            for (std::size_t index = 0; index < listeners.size(); ++index) {
                auto const& listener = listeners[index];
                auto traffic = listener.server->traffic_snapshot();
                if (need_listeners)
                    snap.listeners.push_back({index, listener.port, traffic.active.size(),
                        traffic.bytes.upload, traffic.bytes.download});
                if (!need_connections) continue;
                for (auto const& row : traffic.active) {
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
                    if (target_connection_id) return snap;
                }
            }
        }
        if (need_groups && running) {
            auto generation = running->direct_network && network ? std::optional(network->generation) : std::nullopt;
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
        return snap;
    }
}
