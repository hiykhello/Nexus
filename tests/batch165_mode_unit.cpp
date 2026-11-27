import std;
import cli.control;
import cli.outbounds;
import cli.proxy_control;
import cli.proxy_control_operations;
import cli.proxy_group_health;
import cli.proxy_http_control;
import cli.proxy_listener;
import cli.proxy_mode;
import cli.proxy_tun_reload;
import cli.route_files;
import config;
import control_api.types;
import glaze;
import platform.network_state;
import relay;
import rules;
import rules.kdl_predicate;

namespace {
    auto expect(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view tag) {
            auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            path = std::filesystem::temp_directory_path() / std::format("nexus_w36_{}_{}", tag, stamp);
            std::filesystem::create_directories(path);
        }
        ~TempDir() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    };

    auto write_text(std::filesystem::path const& p, std::string_view text) -> void {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        expect(bool(out), "open temp file");
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        out.flush();
        expect(out.good(), "flush temp file");
    }

    auto test_p1_1_tun_route_set_same_config_reload() -> void {
        TempDir dir("tun_rs");
        auto inc_file = dir.path / "inc.kdl";
        auto exc_file = dir.path / "exc.kdl";
        auto cfg_file = dir.path / "config.kdl";
        write_text(inc_file, "schema-version 2\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"10.10.0.0/16\"\n");
        write_text(exc_file, "schema-version 2\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"10.10.1.0/24\"\n");
        std::string kdl = std::format(R"kdl(schema-version 1
role "client"
inbounds {{
    tun "tun0" {{
        inet4-address "198.18.0.1/24"
        auto-route #true
        strict-route #true
        route-address-set "inc"
        route-exclude-address-set "exc"
    }}
}}
outbounds {{ direct; block; }}
routing {{
    rule-set "inc" path="{}" format="kdl"
    rule-set "exc" path="{}" format="kdl"
    rules udp=#true {{ - default "direct"; }}
}}
)kdl", inc_file.string(), exc_file.string());
        write_text(cfg_file, kdl);
        auto cfg = config::parse_kdl(kdl);
        expect(cfg.has_value(), cfg ? "" : cfg.error());
        auto srv = relay::Server::create();
        expect(srv.has_value(), "create relay server");
        std::vector<cli::run_detail::Listener> listeners;
        listeners.push_back({std::move(*srv), 0, relay::Inbound::socks5});
        relay::RouteSnapshots snapshots;
        cli::RuleFileInput r1(cfg_file.string());
        auto files1 = cli::load_route_files(*cfg, r1);
        expect(files1.has_value(), files1 ? "" : files1.error());

        cli::run_detail::TunLiveReload tun_reload;
        expect(tun_reload.record_initial_route_sets(*cfg, *files1).has_value(), "record initial TUN route sets");
        expect(cli::run_detail::publish_group_routes(listeners, snapshots, *cfg, *files1).has_value(), "initial publish");
        expect(snapshots.load()->front().generation == 1, "gen 1");

        // Unchanged rule-set files -> TUN route update callback MUST NOT run.
        int calls = 0;
        auto noop_ok = tun_reload.publish_same_config_routes_with(listeners, snapshots, *cfg, *files1, false, nullptr,
            [&](std::size_t, config::TunInbound const&) -> std::expected<bool, std::string> { ++calls; return true; });
        expect(noop_ok.has_value() && calls == 0 && snapshots.load()->front().generation == 2, "unchanged route-sets skip TUN update");

        // Modify ONLY inc.kdl & exc.kdl (main config text / identity 100% unchanged!).
        write_text(inc_file, "schema-version 2\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"10.10.0.0/16\"\nrule type=\"ip-cidr\" value=\"172.20.0.0/16\"\n");
        write_text(exc_file, "schema-version 2\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"172.20.1.0/24\"\n");
        cli::RuleFileInput r2(cfg_file.string());
        auto files2 = cli::load_route_files(*cfg, r2);
        expect(files2.has_value(), files2 ? "" : files2.error());

        // If TUN system route update fails, reload MUST fail BEFORE publishing new snapshot or updating applied_route_sets!
        auto fail_res = tun_reload.publish_same_config_routes_with(listeners, snapshots, *cfg, *files2, false, nullptr,
            [&](std::size_t, config::TunInbound const&) -> std::expected<bool, std::string> {
                ++calls;
                return std::unexpected("simulated netlink failure");
            });
        expect(!fail_res.has_value() && calls == 1 && snapshots.load()->front().generation == 2,
            "failed TUN route update aborts reload before snapshot publish");

        // Succeeding TUN update receives expanded CIDRs, publishes gen 3, and persists applied CIDRs so re-running skips.
        config::TunInbound observed{};
        auto ok_res = tun_reload.publish_same_config_routes_with(listeners, snapshots, *cfg, *files2, false, nullptr,
            [&](std::size_t idx, config::TunInbound const& tun) -> std::expected<bool, std::string> {
                expect(idx == 0, "TUN inbound index 0");
                observed = tun;
                ++calls;
                return true;
            });
        expect(ok_res.has_value() && calls == 2 && snapshots.load()->front().generation == 3,
            "changed route-set files trigger TUN update before publish");
        expect(std::ranges::contains(observed.route_includes, std::string("172.20.0.0/16")) &&
               std::ranges::contains(observed.route_excludes, std::string("172.20.1.0/24")),
            "TUN update receives newly expanded include & exclude CIDRs");

        auto ok_again = tun_reload.publish_same_config_routes_with(listeners, snapshots, *cfg, *files2, false, nullptr,
            [&](std::size_t, config::TunInbound const&) -> std::expected<bool, std::string> { ++calls; return true; });
        expect(ok_again.has_value() && calls == 2 && snapshots.load()->front().generation == 4,
            "persisted applied_route_sets avoids redundant TUN updates");
        std::cout << "  [PASS] P1-1 TUN route-set same-config hot-reload syncs expanded CIDRs before publish\n";
    }

    auto test_p1_2_global_mode_selector_sync() -> void {
        constexpr std::string_view kdl = R"kdl(schema-version 1
role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds {
    direct
    block
    socks5 "node-a" { server "127.0.0.1:1081"; }
    socks5 "node-b" { server "127.0.0.1:1082"; }
    selector "manual-grp" { member "node-a"; member "node-b"; selected "node-a"; }
    url-test "auto-grp" { member "node-a"; member "node-b"; probe-url "http://127.0.0.1:80/204"; probe-interval-ms 60000; probe-timeout-ms 1000; }
}
routing { default-outbound "manual-grp"; }
)kdl";
        auto parsed = config::parse_kdl(kdl);
        expect(parsed.has_value(), parsed ? "" : parsed.error());
        auto node_a = config::distributed_outbound_index(*parsed, "node-a");
        auto node_b = config::distributed_outbound_index(*parsed, "node-b");
        expect(node_a && node_b && *node_a != *node_b, "distinct outbound indices for node-a & node-b");

        auto srv = relay::Server::create();
        expect(srv.has_value(), "create server");
        std::vector<cli::run_detail::Listener> listeners;
        listeners.push_back({std::move(*srv), 1080, relay::Inbound::socks5});
        auto health = cli::run_detail::OutboundGroupHealth::create(*parsed);
        expect(health.has_value(), health ? "" : health.error());

        // Populate healthy probe latency favoring node-a (15ms) over node-b (200ms) for --auto reset test.
        auto t0 = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<relay::OutboundProbe>> probes;
        (void)health->poll([&](std::shared_ptr<relay::OutboundProbe> p) { probes.push_back(std::move(p)); return true; }, *parsed, std::nullopt, t0);
        expect(probes.size() == 2, "enqueued 2 probes for auto-grp");
        probes[0]->result.store(17, std::memory_order_release); probes[0]->status_code.store(204, std::memory_order_relaxed);
        probes[1]->result.store(202, std::memory_order_release); probes[1]->status_code.store(204, std::memory_order_relaxed);
        (void)health->poll([](std::shared_ptr<relay::OutboundProbe>) { return true; }, *parsed, std::nullopt, t0 + std::chrono::milliseconds(50));

        std::optional<config::Config> running = *parsed;
        cli::run_detail::RuntimeRouteModeController route_mode;
        route_mode.sync(*running);
        cli::run_detail::ControlOperations ops;
        cli::LocalControl ctrl;
        auto names = cli::outbound_names(*running);
        auto publish_ok = [](config::Config const&, std::string_view, std::string_view, bool) -> std::expected<bool, std::string> { return true; };

        // Enter global mode targeting manual-grp (initially node-a).
        std::array<std::string_view, 3> cmd_m1{"mode", "global", "manual-grp"};
        expect(cli::run_detail::control_request(listeners, running, 1, names, cmd_m1, publish_ok, std::nullopt,
            nullptr, &*health, cli::ControlRole::administrator, ops, ctrl, nullptr, &route_mode).has_value(), "mode global manual-grp");
        expect(route_mode.shared->mode.load() == rules::RouteMode::global &&
               route_mode.shared->global_outbound.load() == *node_a, "global manual-grp initially targets node-a");

        // Manual select switch manual-grp -> node-b MUST immediately sync route_mode global_outbound!
        std::array<std::string_view, 3> cmd_sel{"select", "manual-grp", "node-b"};
        expect(cli::run_detail::control_request(listeners, running, 1, names, cmd_sel, publish_ok, std::nullopt,
            nullptr, &*health, cli::ControlRole::administrator, ops, ctrl, nullptr, &route_mode).has_value(), "select manual-grp node-b");
        expect(route_mode.shared->global_outbound.load() == *node_b,
            "P1-2 manual select immediately updates global mode outbound to node-b");

        // Now global mode targeting url-test auto-grp: manual override to node-b -> syncs to node-b; --auto reset -> syncs back to node-a!
        std::array<std::string_view, 3> cmd_m2{"mode", "global", "auto-grp"};
        expect(cli::run_detail::control_request(listeners, running, 1, names, cmd_m2, publish_ok, std::nullopt,
            nullptr, &*health, cli::ControlRole::administrator, ops, ctrl, nullptr, &route_mode).has_value(), "mode global auto-grp");
        expect(route_mode.shared->global_outbound.load() == *node_a, "global auto-grp initially targets node-a");

        std::array<std::string_view, 3> cmd_ov{"select", "auto-grp", "node-b"};
        expect(cli::run_detail::control_request(listeners, running, 1, names, cmd_ov, publish_ok, std::nullopt,
            nullptr, &*health, cli::ControlRole::administrator, ops, ctrl, nullptr, &route_mode).has_value(), "override auto-grp node-b");
        expect(route_mode.shared->global_outbound.load() == *node_b,
            "P1-2 url-test manual override immediately updates global mode outbound to node-b");

        std::array<std::string_view, 3> cmd_rst{"select", "auto-grp", "--auto"};
        expect(cli::run_detail::control_request(listeners, running, 1, names, cmd_rst, publish_ok, std::nullopt,
            nullptr, &*health, cli::ControlRole::administrator, ops, ctrl, nullptr, &route_mode).has_value(), "reset auto-grp --auto");
        expect(!health->override_member(1).has_value() && route_mode.shared->global_outbound.load() == *node_a,
            "P1-2 url-test --auto reset immediately syncs global mode outbound back to best node-a");
        std::cout << "  [PASS] P1-2 global mode immediately syncs outbound on manual select, url-test override & --auto reset\n";
    }

    auto test_r2_p2_3_route_mode_unconfirmed_persistence() -> void {
        constexpr std::string_view kdl = R"kdl(schema-version 1; role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; block; }
routing { default-outbound "direct"; })kdl";
        auto parsed = config::parse_kdl(kdl);
        expect(parsed.has_value(), "parse minimal config");
        std::optional<config::Config> running = *parsed;
        cli::run_detail::RuntimeRouteModeController ctrl;
        ctrl.sync(*running);
        cli::run_detail::ControlOperations ops;

        // Hard write failure -> roll back in-memory mode and do NOT bump generation.
        std::array<std::string_view, 2> cmd{"mode", "direct"};
        auto hard = ctrl.handle_command_with(running, cli::ControlRole::administrator, cmd, ops,
            [](std::string_view, std::string_view) -> std::expected<bool, std::string> { return std::unexpected("disk-full"); });
        expect(!hard.has_value() && hard.error() == "disk-full" && ctrl.mode_name() == "rule" && ops.generation() == 1,
            "hard save failure rolls back mode and preserves generation");

        // Unconfirmed durability (save_route_mode returns false, e.g. dir fsync EIO) -> keep active mode, bump generation, return explicit error!
        auto unconfirmed = ctrl.handle_command_with(running, cli::ControlRole::administrator, cmd, ops,
            [](std::string_view, std::string_view) -> std::expected<bool, std::string> { return false; });
        expect(!unconfirmed.has_value() && unconfirmed.error() == "mode-active-persistence-uncertain",
            "R2 P2-3 unconfirmed durability reports mode-active-persistence-uncertain");
        expect(ctrl.mode_name() == "direct" && ctrl.shared->mode.load() == rules::RouteMode::direct && ops.generation() == 2,
            "R2 P2-3 keeps active in-memory direct mode and bumps control generation");
        std::cout << "  [PASS] R2 P2-3 unconfirmed route-mode persistence retains active mode and reports error\n";
    }

    auto test_r3_p1_2_outbound_secret_rotation_fingerprint() -> void {
        TempDir dir("sec_rot");
        auto pw_file = dir.path / "socks.pw";
        write_text(pw_file, "old-password-001\n");
        std::string kdl = std::format(R"kdl(schema-version 1; role "client"
inbounds {{ socks5 "in" {{ listen "127.0.0.1:1080"; authentication "none"; }}; }}
outbounds {{ direct; socks5 "up" {{ server "127.0.0.1:1081"; authentication username="u" password-file="{}"; }}; }}
routing {{ default-outbound "up"; }})kdl", pw_file.string());
        auto cfg1 = config::parse_kdl(kdl);
        expect(cfg1.has_value(), cfg1 ? "" : cfg1.error());
        auto id1 = config::reload_identities(kdl);
        auto fp1 = cli::outbound_secrets_fingerprint(*cfg1);
        expect(id1 && fp1, "initial reload identity & secret fingerprint");

        // Rotate ONLY the password inside the same secret file path (KDL text & path 100% identical!).
        write_text(pw_file, "rotated-password-002\n");
        auto cfg2 = config::parse_kdl(kdl);
        auto id2 = config::reload_identities(kdl);
        auto fp2 = cli::outbound_secrets_fingerprint(*cfg2);
        expect(id2 && fp2 && id1->full == id2->full && *fp1 != *fp2,
            "R3 P1-2 password rotation changes outbound_secrets_fingerprint even when KDL/path unchanged");
        std::cout << "  [PASS] R3 P1-2 outbound credential file content fingerprint detects password rotation\n";
    }

    auto test_r3_p2_1_retired_tcp_inspect_and_close() -> void {
        auto active_srv = relay::Server::create();
        auto retired_srv = relay::Server::create();
        auto retired_srv2 = relay::Server::create();
        expect(active_srv && retired_srv && retired_srv2 && (*active_srv)->enable_traffic_stats(0) &&
            (*retired_srv)->enable_traffic_stats(0) && (*retired_srv2)->enable_traffic_stats(0),
            "create active & 2 retired servers with traffic stats");
        std::vector<cli::run_detail::Listener> active_listeners;
        active_listeners.push_back({std::move(*active_srv), 1081, relay::Inbound::socks5});
        std::vector<std::unique_ptr<cli::run_detail::RetiredTcpGeneration>> retired_tcp;
        auto gen = std::make_unique<cli::run_detail::RetiredTcpGeneration>();
        gen->listeners.push_back({std::move(*retired_srv), 1080, relay::Inbound::socks5});
        gen->listeners.push_back({std::move(*retired_srv2), 1082, relay::Inbound::socks5});
        retired_tcp.push_back(std::move(gen));
        auto reg = retired_tcp.front()->listeners[0].server->track_traffic(
            relay::TrafficProtocol::socks5, relay::ConnectPath::direct, std::nullopt, 443, true);
        auto reg2 = retired_tcp.front()->listeners[1].server->track_traffic(
            relay::TrafficProtocol::socks5, relay::ConnectPath::direct, std::nullopt, 8443, true);
        auto retired_snap = retired_tcp.front()->listeners[0].server->traffic_snapshot();
        auto retired_snap2 = retired_tcp.front()->listeners[1].server->traffic_snapshot();
        expect(retired_snap.active.size() == 1 && retired_snap2.active.size() == 1, "retired servers track 2 active connections");
        auto conn_id = retired_snap.active.front().id;
        auto conn2_id = retired_snap2.active.front().id;
        auto conn_id_str = std::to_string(conn_id);
        auto conn2_id_str = std::to_string(conn2_id);

        std::optional<config::Config> running;
        cli::run_detail::ControlOperations ops;
        cli::LocalControl ctrl;
        std::vector<std::string> names{"direct", "block"};
        auto pub = [](config::Config const&, std::string_view, std::string_view, bool) -> std::expected<bool, std::string> { return true; };

        // UDS `connection <id>`, `connections 0` (incl. overflow retired listener after 2->1 shrink) and `status` MUST see all draining sessions.
        std::array<std::string_view, 2> cmd_conn{"connection", conn_id_str};
        auto c_res = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_conn, pub, std::nullopt,
            nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp);
        expect(c_res && c_res->contains("id=" + conn_id_str), "R3 P2-1 control `connection <id>` inspects retired_tcp");

        std::array<std::string_view, 2> cmd_list{"connections", "0"};
        auto l_res = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_list, pub, std::nullopt,
            nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp);
        expect(l_res && l_res->contains("id=" + conn_id_str) && l_res->contains("id=" + conn2_id_str),
            "R3 P2-1 control `connections 0` buckets overflow retired listener sessions after listener shrink");

        std::array<std::string_view, 1> cmd_status{"status"};
        auto s_res = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_status, pub, std::nullopt,
            nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp);
        expect(s_res && s_res->contains("active=2 "), "R3 P2-1 control `status` folds retired_tcp active sessions");

        // HTTP control snapshot MUST list & detail both draining connections and include their active session count.
        auto http_snap = cli::run_detail::build_control_api_snapshot(active_listeners, running, 1, names, nullptr, nullptr,
            ops, ctrl, nullptr, control_api::SnapshotFields::listeners | control_api::SnapshotFields::connections, std::nullopt, retired_tcp);
        expect(http_snap.connections.size() == 2 && http_snap.listeners.size() == 1 && http_snap.listeners[0].active_sessions == 2,
            "R3 P2-1 HTTP snapshot includes all retired_tcp draining connections");

        // `close-any <id>` and `close-all` MUST queue close on retired_tcp!
        std::array<std::string_view, 2> cmd_close_any{"close-any", conn_id_str};
        auto ca_res = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_close_any, pub, std::nullopt,
            nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp);
        expect(ca_res && *ca_res == "queued\n", "R3 P2-1 `close-any` closes retired_tcp connection");

        std::array<std::string_view, 1> cmd_close_all{"close-all"};
        auto all_res = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_close_all, pub, std::nullopt,
            nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp);
        expect(all_res && *all_res == "closed=2\n", "R3 P2-1 `close-all` closes all retired_tcp connections");
        std::cout << "  [PASS] R3 P2-1 control & HTTP API inspect and close draining connections on retired_tcp\n";
    }

    auto test_r3_p2_2_group_health_network_generation() -> void {
        constexpr std::string_view kdl = R"kdl(schema-version 1; role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds {
    direct; block
    socks5 "node-a" { server "127.0.0.1:1081"; }
    url-test "auto-grp" { member "node-a"; probe-url "http://127.0.0.1:80/204"; probe-interval-ms 60000; probe-timeout-ms 1000; }
}
routing { default-outbound "auto-grp"; })kdl";
        auto parsed = config::parse_kdl(kdl);
        expect(parsed && !parsed->direct_network.has_value(), "ordinary config has no direct_network");
        auto health = cli::run_detail::OutboundGroupHealth::create(*parsed);
        expect(health.has_value(), "create health");

        platform::network::Snapshot net_snap{};
        net_snap.generation = 1;
        auto t0 = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<relay::OutboundProbe>> probes;
        (void)health->poll([&](std::shared_ptr<relay::OutboundProbe> p) { probes.push_back(std::move(p)); return true; },
            *parsed, std::optional<std::uint64_t>(net_snap.generation), t0);
        expect(probes.size() == 1, "enqueued probe with net_gen=1");
        probes[0]->result.store(22, std::memory_order_release);
        probes[0]->status_code.store(204, std::memory_order_relaxed);
        (void)health->poll([](std::shared_ptr<relay::OutboundProbe>) { return true; },
            *parsed, std::optional<std::uint64_t>(net_snap.generation), t0 + std::chrono::milliseconds(50));

        auto srv = relay::Server::create();
        std::vector<cli::run_detail::Listener> listeners;
        listeners.push_back({std::move(*srv), 1080, relay::Inbound::socks5});
        std::optional<config::Config> running = *parsed;
        cli::run_detail::ControlOperations ops;
        cli::LocalControl ctrl;
        auto names = cli::outbound_names(*running);
        auto pub = [](config::Config const&, std::string_view, std::string_view, bool) -> std::expected<bool, std::string> { return true; };

        std::array<std::string_view, 2> cmd_gh{"group-health", "auto-grp"};
        auto gh = cli::run_detail::control_request(listeners, running, 1, names, cmd_gh, pub, std::nullopt,
            &net_snap, &*health, cli::ControlRole::administrator, ops, ctrl);
        expect(gh && gh->contains("member=node-a state=up") && !gh->contains("state=stale"),
            "R3 P2-2 control `group-health` reports up (not stale) with net_gen=1 and no direct_network");

        auto http_snap = cli::run_detail::build_control_api_snapshot(listeners, running, 1, names, &net_snap, &*health,
            ops, ctrl, nullptr, control_api::SnapshotFields::groups);
        expect(http_snap.groups.size() == 1 && http_snap.groups[0].members.size() == 1 &&
               http_snap.groups[0].members[0].state == "up",
            "R3 P2-2 HTTP /v1/outbounds reports up (not stale) with net_gen=1 and no direct_network");

        // R4 P2-5: HTTP-only mode (inactive UDS LocalControl) produces unique non-empty per-instance IDs.
        cli::run_detail::ControlOperations ops2;
        auto meta1 = cli::run_detail::build_control_api_snapshot(listeners, running, 1, names, nullptr, nullptr,
            ops, ctrl, nullptr, control_api::SnapshotFields::meta);
        auto meta2 = cli::run_detail::build_control_api_snapshot(listeners, running, 1, names, nullptr, nullptr,
            ops2, ctrl, nullptr, control_api::SnapshotFields::meta);
        expect(!meta1.instance.empty() && !meta2.instance.empty() && meta1.instance != meta2.instance,
            "R4 P2-5 HTTP-only snapshot returns distinct non-empty instance_id across startups");
        std::cout << "  [PASS] R3 P2-2 group health (up, not stale) & R4 P2-5 HTTP-only unique non-empty instance_id\n";
    }
}

int main() {
    using namespace rules;
    expect(parse_route_mode("rule") == RouteMode::rule, "parse rule");
    expect(parse_route_mode("global") == RouteMode::global, "parse global");
    expect(parse_route_mode("direct") == RouteMode::direct, "parse direct");
    expect(!parse_route_mode("other").has_value(), "reject invalid mode");
    expect(route_mode_name(RouteMode::global) == "global", "mode name");

    RuleSet r1;
    r1.version = 2;
    r1.rules.push_back(Rule{"domain-suffix", "blocked.test", {}});
    RuleSet r2;
    r2.version = 2;
    r2.rules.push_back(Rule{"route-mode", "rule", {}});
    r2.rules.push_back(Rule{"domain", "example.com", {}});

    std::vector<rules::RouteRule> routes{
        rules::RouteRule{r1, 1, 0},
        rules::RouteRule{r2, 2, 1},
    };
    auto compiled = RouteMatcher::compile(routes, 0, 4);
    expect(compiled.has_value(), "compile RouteMatcher");
    auto matcher = std::move(*compiled);

    auto dist = std::make_shared<OutboundDistribution>(4, std::vector<std::vector<std::size_t>>{{2, 3}});
    matcher.set_distribution(dist);

    auto state = std::make_shared<RuntimeRouteMode>();
    state->mode.store(RouteMode::rule, std::memory_order_release);
    state->global_outbound.store(2, std::memory_order_release);
    matcher.set_runtime_mode(state);

    // 1. rule mode evaluates normal predicates + route-mode="rule"
    auto m_block = matcher.match_with_rule(MatchInput{.domain = "sub.blocked.test", .port = 443, .network = Network::tcp});
    expect(m_block && m_block->outbound == 1, "rule mode matches block");
    auto m_ex = matcher.match_with_rule(MatchInput{.domain = "example.com", .port = 443, .network = Network::tcp});
    expect(m_ex && m_ex->outbound == 2, "rule mode matches example.com");
    auto pf_rule = matcher.preflight("example.com");
    expect(pf_rule && *pf_rule == 2, "preflight in rule mode");

    // 2. direct mode overrides rules -> outbound 0 (no recompile)
    state->mode.store(RouteMode::direct, std::memory_order_release);
    auto m_dir = matcher.match_with_rule(MatchInput{.domain = "sub.blocked.test", .port = 443, .network = Network::tcp});
    expect(m_dir && m_dir->outbound == 0 && !m_dir->rule.has_value(), "direct mode bypasses block");
    auto pf_dir = matcher.preflight("sub.blocked.test");
    expect(pf_dir && *pf_dir == 0, "preflight in direct mode returns 0");

    // 3. global mode sends to configured global outbound (including distributed group index >= 4)
    state->mode.store(RouteMode::global, std::memory_order_release);
    state->global_outbound.store(3, std::memory_order_release);
    auto m_glob = matcher.match_with_rule(MatchInput{.domain = "sub.blocked.test", .port = 443, .network = Network::tcp});
    expect(m_glob && m_glob->outbound == 3 && !m_glob->rule.has_value(), "global mode routes to outbound 3");
    state->global_outbound.store(4, std::memory_order_release);
    auto m_lb = matcher.match_with_rule(MatchInput{.domain = "host.example", .port = 443, .network = Network::tcp});
    expect(m_lb && (m_lb->outbound == 2 || m_lb->outbound == 3), "global mode distributes across load-balance group");

    // 4. RouteProgram supports route-mode predicate & KDL predicate decoding
    auto doc = glaze::read_kdl<glaze::KdlDocument>("route-mode \"rule\"");
    expect(doc && doc->size() == 1, "parse KDL route-mode");
    std::size_t kcount = 0;
    auto kpred = decode_kdl_predicate((*doc)[0], 1, kcount);
    expect(kpred && kpred->type == "route-mode" && kpred->value == "rule", "decode KDL route-mode");

    std::vector<ProgramRule> prog_rules{
        ProgramRule{RuleSet{{*kpred}, 2}, ProgramAction{ProgramActionKind::route, 2}, DomainSource::explicit_target},
    };
    auto prog = RouteProgram::compile(prog_rules, 4);
    expect(prog.has_value(), "compile RouteProgram with route-mode");
    auto s_rule = prog->next(ProgramInput{.port = 443, .network = Network::tcp, .route_mode = RouteMode::rule});
    expect(s_rule && *s_rule && (*s_rule)->action.outbound == 2, "program matches route_mode=rule");
    auto s_glob = prog->next(ProgramInput{.port = 443, .network = Network::tcp, .route_mode = RouteMode::global});
    expect(s_glob && !s_glob->has_value(), "program skips route_mode=rule when global");

    test_p1_1_tun_route_set_same_config_reload();
    test_p1_2_global_mode_selector_sync();
    test_r2_p2_3_route_mode_unconfirmed_persistence();
    test_r3_p1_2_outbound_secret_rotation_fingerprint();
    test_r3_p2_1_retired_tcp_inspect_and_close();
    test_r3_p2_2_group_health_network_generation();
    std::cout << "BATCH 165 RUNTIME ROUTE MODE UNIT TESTS PASSED\n";
    return 0;
}
