import std;
import cli.control;
import cli.dns_message_runtime;
import cli.proxy_control;
import cli.proxy_control_operations;
import cli.proxy_dns_reload;
import cli.proxy_group_health;
import cli.proxy_host;
import cli.proxy_http_control;
import cli.proxy_listener;
import cli.proxy_listener_reload;
import cli.proxy_providers;
import cli.route_files;
import cli.udp;
import config;
import control_api;
import control_api.types;
import dns.reverse;
import logging;
import logging.cli;
import platform.network_state;
import platform.socket_options;
import relay;
import rules;
import rules.rule_input;
import rules.convert_external;
import rules.srs_payload;

namespace {
    int failures = 0;
    auto check(bool ok, std::string_view msg) -> void {
        if (!ok) {
            ++failures;
            std::cerr << "FAIL: " << msg << '\n';
        }
    }

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view prefix) {
            auto stamp = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            path = std::filesystem::temp_directory_path() / std::format("{}-{}", prefix, stamp);
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
            std::filesystem::create_directories(path, ec);
        }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    };

    auto write_text(std::filesystem::path const& p, std::string_view text) -> void {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
    }

    auto test_r5_p2_1_failed_reload_preserves_provider(TempDir const& tmp) -> void {
        auto sub_file = tmp.path / "r5_sub.yaml";
        auto cfg_path = tmp.path / "r5_cfg.kdl";
        auto cache_dir = tmp.path / "r5_pcache";
        write_text(sub_file, "proxies:\n  - {name: \"N1\", type: socks5, server: 198.51.100.71, port: 1080}\n");
        auto kdl_with_prov = std::format(
            "schema-version 1\nrole \"client\"\n"
            "proxy-providers {{\n  provider \"p1\" {{ type \"file\"; path \"{}\"; cache-dir \"{}\"; update-interval-ms 1000; }}\n}}\n"
            "inbounds {{ socks5 \"in\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }}; }}\n"
            "outbounds {{ direct; block; selector \"proxy\" {{ use \"p1\"; }}; }}\n"
            "routing {{ default-outbound \"proxy\"; }}\n",
            sub_file.string(), cache_dir.string());
        constexpr std::string_view kdl_no_prov =
            "schema-version 1\nrole \"client\"\n"
            "inbounds { socks5 \"in\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\n"
            "outbounds { direct; block; }\n"
            "routing { default-outbound \"direct\"; }\n";

        cli::ProxyProviderManager mgr;
        auto init = mgr.prepare_initial(kdl_with_prov, cfg_path.string(), true);
        check(bool(init) && mgr.has_providers() && mgr.summaries().size() == 1 && mgr.summaries()[0].proxy_count == 1,
            init ? "R5 P2-1 initial file provider loaded (1 node)" : ("R5 P2-1 init error: " + init.error()));

        // Stage a reload that removes providers, then simulate reload failure by NOT calling commit_candidate().
        auto staged_empty = mgr.prepare_candidate(kdl_no_prov, cfg_path.string(), true);
        check(bool(staged_empty) && !staged_empty->has_providers(),
            staged_empty ? "R5 P2-1 stage provider-less candidate" : ("R5 P2-1 stage error: " + staged_empty.error()));
        check(mgr.has_providers() && mgr.summaries().size() == 1,
            "R5 P2-1 uncommitted candidate preserves active file provider table");

        // Update file provider and advance mtime: active manager must still detect and reload the 2nd node!
        write_text(sub_file,
            "proxies:\n"
            "  - {name: \"N1\", type: socks5, server: 198.51.100.71, port: 1080}\n"
            "  - {name: \"N2\", type: socks5, server: 198.51.100.72, port: 1080}\n");
        std::error_code ec;
        auto old_t = std::filesystem::last_write_time(sub_file, ec);
        std::filesystem::last_write_time(sub_file, old_t + std::chrono::seconds(2), ec);
        auto synced = mgr.sync_once(false);
        check(synced && *synced && mgr.summaries().size() == 1 && mgr.summaries()[0].proxy_count == 2,
            "R5 P2-1 active file provider still refreshes after aborted reload");

        // Explicit commit after reload succeeds clears providers as expected.
        if (staged_empty) mgr.commit_candidate(std::move(*staged_empty));
        check(!mgr.has_providers() && mgr.summaries().empty(), "R5 P2-1 commit_candidate clears providers");
        std::cout << "  [PASS] R5 P2-1 failed reload preserves active file provider refresh\n";
    }

    auto test_r5_p2_2_provider_refresh_process_options() -> void {
        constexpr std::string_view kdl_base =
            "schema-version 1\nrole \"client\"\n"
            "control socket=\"/tmp/nx-ctrl.sock\" selector-state-directory=\"/tmp/nx-sel-a\"\n"
            "state { directory \"/tmp/nx-state-a\"; }\n"
            "inbounds { socks5 \"in\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\n"
            "outbounds { direct; block; }\n"
            "routing { default-outbound \"direct\"; }\n";
        constexpr std::string_view kdl_outbounds =
            "schema-version 1\nrole \"client\"\n"
            "control socket=\"/tmp/nx-ctrl.sock\" selector-state-directory=\"/tmp/nx-sel-a\"\n"
            "state { directory \"/tmp/nx-state-a\"; }\n"
            "inbounds { socks5 \"in\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\n"
            "outbounds { direct; block; socks5 \"extra\" { server \"127.0.0.1:1089\"; }; }\n"
            "routing { default-outbound \"extra\"; }\n";
        constexpr std::string_view kdl_sel_dir =
            "schema-version 1\nrole \"client\"\n"
            "control socket=\"/tmp/nx-ctrl.sock\" selector-state-directory=\"/tmp/nx-sel-b\"\n"
            "state { directory \"/tmp/nx-state-a\"; }\n"
            "inbounds { socks5 \"in\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\n"
            "outbounds { direct; block; }\n"
            "routing { default-outbound \"direct\"; }\n";
        constexpr std::string_view kdl_state_dir =
            "schema-version 1\nrole \"client\"\n"
            "control socket=\"/tmp/nx-ctrl.sock\" selector-state-directory=\"/tmp/nx-sel-a\"\n"
            "state { directory \"/tmp/nx-state-b\"; }\n"
            "inbounds { socks5 \"in\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\n"
            "outbounds { direct; block; }\n"
            "routing { default-outbound \"direct\"; }\n";

        auto c_base = config::parse_kdl(kdl_base);
        auto c_out = config::parse_kdl(kdl_outbounds);
        auto c_sel = config::parse_kdl(kdl_sel_dir);
        auto c_st = config::parse_kdl(kdl_state_dir);
        check(c_base && c_out && c_sel && c_st, "R5 P2-2 configs parse");
        if (c_base && c_out && c_sel && c_st) {
            check(cli::run_detail::provider_refresh_process_options_match(*c_base, *c_out),
                "R5 P2-2 outbound-only change matches process options");
            check(!cli::run_detail::provider_refresh_process_options_match(*c_base, *c_sel),
                "R5 P2-2 selector-state-directory change requires restart");
            check(!cli::run_detail::provider_refresh_process_options_match(*c_base, *c_st),
                "R5 P2-2 state.directory change requires restart");
            auto c_ntp = *c_base; c_ntp.ntp = config::NtpConfig{.host = "127.0.0.1"};
            auto c_svc = *c_base; c_svc.services.memory_watchdog = config::MemoryWatchdogConfig{};
            auto c_net = *c_base; c_net.direct_network = platform::network::Policy{};
            check(!cli::run_detail::provider_refresh_process_options_match(*c_base, c_ntp), "R5 P2-2 ntp change requires restart");
            check(!cli::run_detail::provider_refresh_process_options_match(*c_base, c_svc), "R5 P2-2 services change requires restart");
            check(!cli::run_detail::provider_refresh_process_options_match(*c_base, c_net), "R5 P2-2 direct_network change requires restart");
        }
        std::cout << "  [PASS] R5 P2-2 provider-refresh rejects selector-state-directory / state changes\n";
    }

    auto test_r5_p2_3_hot_add_first_selector(TempDir const& tmp) -> void {
        auto port = static_cast<std::uint16_t>(42000 + (static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()) % 10000));
        auto kdl1 = std::format(
            "schema-version 1\nrole \"client\"\nworkers 1\n"
            "inbounds {{ socks5 \"in\" {{ listen \"127.0.0.1:{}\"; authentication \"none\"; }}; }}\n"
            "outbounds {{ direct; block; }}\n"
            "routing {{ default-outbound \"direct\"; }}\n", port);
        auto kdl2 = std::format(
            "schema-version 1\nrole \"client\"\nworkers 1\n"
            "inbounds {{ socks5 \"in\" {{ listen \"127.0.0.1:{}\"; authentication \"none\"; }}; }}\n"
            "outbounds {{\n  direct; block;\n  socks5 \"node-b\" {{ server \"127.0.0.1:1089\"; }};\n"
            "  selector \"manual\" {{ member \"direct\"; member \"node-b\"; selected \"direct\"; }};\n}}\n"
            "routing {{ default-outbound \"manual\"; }}\n", port);

        auto cfg1 = config::parse_kdl(kdl1);
        auto ids1 = config::reload_identities(kdl1);
        auto ids2 = config::reload_identities(kdl2);
        check(cfg1 && ids1 && ids2, "R5 P2-3 parse configs & reload identities");
        if (!cfg1 || !ids1 || !ids2) return;

        cli::run_detail::ListenerReload reloader;
        reloader.tcp_admission = std::make_shared<relay::TcpAdmission>();
        reloader.process_identity = ids1->process;
        reloader.dns_policy_identity = ids1->dns_policy;
        reloader.identities_initialized = true;

        auto srv0 = relay::Server::create();
        check(bool(srv0), "R5 P2-3 create initial server");
        if (!srv0) return;
        auto l0 = cli::run_detail::make_listener(std::move(*srv0), cfg1->inbounds.front());
        auto staged0 = l0.server->stage_tcp(reloader.tcp_admission, 1, l0.port, l0.inbound, 1, l0.ipv6, l0.address);
        check(bool(staged0) && reloader.tcp_admission->publish(1), "R5 P2-3 stage & publish initial listener");
        if (staged0) l0.port = *staged0;

        std::vector<cli::run_detail::Listener> listeners;
        listeners.push_back(std::move(l0));
        std::optional<config::Config> running = *cfg1;
        std::unique_ptr<relay::SharedDnsGeneration> dns_gen;
        logging::Runtime logs;
        cli::DnsMessageRuntime dns_messages(logs);
        std::shared_ptr<relay::RouteSnapshots> route_snapshots;
        std::optional<cli::RouteFiles> group_route_files;
        std::optional<cli::run_detail::OutboundGroupHealth> group_health;
        std::shared_ptr<relay::SnellReplayRegistry> replay;
        std::shared_ptr<platform::network::Monitor> network;
        std::string reload_identity = ids1->full;
        std::shared_ptr<dns::ReverseCache> reverse_cache;
        cli::run_detail::RemoteRulesetManager remote_rulesets;
        auto udp = std::make_shared<cli::UdpRuntime>();

        cli::run_detail::ListenerReloadRuntime rt{
            listeners, running, dns_gen, dns_messages, route_snapshots, group_route_files, group_health,
            replay, network, reload_identity, logs, reverse_cache, remote_rulesets};
        auto cfg_path = (tmp.path / "r5_sel.kdl").string();
        auto applied = reloader.apply(rt, cfg_path, kdl2, ids2->full, false, false, udp, {}, true);
        check(bool(applied), applied ? "R5 P2-3 listener reload succeeded" : ("R5 P2-3 reload error: " + applied.error()));
        check(route_snapshots != nullptr && group_route_files.has_value() && running && running->selectors.size() == 1,
            "R5 P2-3 hot-adding first selector initializes route_snapshots & group_route_files");

        if (route_snapshots && group_route_files && running) {
            cli::run_detail::ControlOperations ops;
            cli::LocalControl ctrl;
            auto names = cli::outbound_names(*running);
            auto pub = [&](config::Config const& cand, std::string_view, std::string_view, bool)
                -> std::expected<bool, std::string> {
                auto ok = cli::run_detail::publish_group_routes(listeners, *route_snapshots, cand, *group_route_files, false);
                if (!ok) return std::unexpected(ok.error());
                return true;
            };
            std::array<std::string_view, 3> cmd{"select", "manual", "node-b"};
            auto res = cli::run_detail::control_request(listeners, running, 1, names, cmd, pub, std::nullopt,
                nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl);
            check(res && running->selectors[0].selected == "node-b",
                res ? "R5 P2-3 select switches newly added selector" : ("R5 P2-3 select error: " + res.error()));
        }

        for (auto& l : listeners) if (l.server) l.server->stop();
        listeners.clear();
        for (auto& g : reloader.retired_tcp) for (auto& l : g->listeners) if (l.server) l.server->stop();
        reloader.retired_tcp.clear();
        dns_gen.reset();
        std::cout << "  [PASS] R5 P2-3 hot-added manual selector on provider-enabled reload is selectable\n";
    }

    std::atomic<int> g_mock_ruleset_fetches{0};
    auto mock_ruleset_fetcher(config::Config const&, std::string_view, config::BlockRules const& spec,
        std::string_view, bool, std::stop_token, void*) -> std::expected<cli::ManagedRulesetFetchResult, std::string> {
        g_mock_ruleset_fetches.fetch_add(1, std::memory_order_relaxed);
        if (spec.url == "https://mock.test/first.txt") return cli::ManagedRulesetFetchResult{"a.test\n", "e1", false};
        if (spec.url == "https://mock.test/second.txt") return cli::ManagedRulesetFetchResult{"b.test\n", "e2", false};
        return std::unexpected("mock fetch failed for " + spec.url);
    }

    auto test_r5_p2_4_remote_ruleset_url_change_reload(TempDir const& tmp) -> void {
        cli::ensure_http_fetchers_registered();
        g_mock_ruleset_fetches.store(0, std::memory_order_relaxed);
        cli::register_managed_ruleset_fetcher(&mock_ruleset_fetcher);
        struct Guard { ~Guard() { cli::register_managed_ruleset_fetcher(nullptr); } } reset_guard;

        auto make_kdl = [](std::string_view url) {
            return std::format(
                "schema-version 1\nrole \"client\"\n"
                "inbounds {{ socks5 \"in\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }}; }}\n"
                "outbounds {{ direct; block; }}\n"
                "http-clients {{ hc {{ outbound \"direct\"; domain-resolver \"sys\"; ca-file \"/tmp/ca.pem\"; }}; }}\n"
                "dns {{\n"
                "  servers {{ udp \"sys\" host=\"127.0.0.1\" port=53; }}\n"
                "  rule-set \"rs\" url=\"{}\" format=\"domain-list\" update-interval-ms=60000 http-client=\"hc\"\n"
                "  rules {{ - rule-set=\"rs\" to=\"sys\"; }}\n"
                "}}\n"
                "routing {{ default-outbound \"direct\"; }}\n", url);
        };
        auto k1 = make_kdl("https://mock.test/first.txt");
        auto k_fail = make_kdl("https://mock.test/fail.txt");
        auto k2 = make_kdl("https://mock.test/second.txt");
        auto c1 = config::parse_kdl(k1), cf = config::parse_kdl(k_fail), c2 = config::parse_kdl(k2);
        check(c1 && cf && c2, "R5 P2-4 remote DNS rule-set configs parse");
        if (!c1 || !cf || !c2) return;

        auto cfg_path = (tmp.path / "r5_rs.kdl").string();
        cli::run_detail::RemoteRulesetManager mgr;
        cli::RuleFileInput in1(cfg_path);
        auto f1 = mgr.fetch_initial(*c1, k1, in1);
        check(bool(f1) && bool(cli::run_detail::load_dns_rules(*c1->dns, in1)), "R5 P2-4 initial remote DNS rule-set fetches & loads");

        // Changing URL to an unreachable one fails cleanly without wiping existing cached entry.
        cli::RuleFileInput inf(cfg_path);
        auto sf = mgr.prepare_reload(*cf, k_fail, inf);
        check(!sf.has_value() && mgr.has_remote(), "R5 P2-4 failed URL fetch rejects reload & keeps previous remote entry");

        // Changing URL to a new reachable URL fetches the new URL so load_dns_rules succeeds (not ENOENT!).
        cli::RuleFileInput in2(cfg_path);
        auto s2 = mgr.prepare_reload(*c2, k2, in2);
        check(bool(s2), s2 ? "R5 P2-4 prepare_reload fetches new URL" : ("R5 P2-4 prepare_reload error: " + s2.error()));
        if (s2) {
            auto loaded2 = cli::run_detail::load_dns_rules(*c2->dns, in2);
            check(bool(loaded2), loaded2 ? "R5 P2-4 load_dns_rules succeeds on changed URL" : loaded2.error());
            mgr.commit_reload(std::move(*s2));
            cli::RuleFileInput in_cached(cfg_path);
            mgr.seed_cached(in_cached);
            auto body = in_cached.read("https://mock.test/second.txt");
            check(body && *body == "b.test\n", "R5 P2-4 commit_reload caches new URL body");
        }
        std::cout << "  [PASS] R5 P2-4 hot-reloading changed remote DNS rule-set URL fetches and commits cleanly\n";
    }

    auto test_r5_p2_5_retired_generation_traffic_preserved() -> void {
        auto active_srv = relay::Server::create();
        auto retired_srv = relay::Server::create();
        check(active_srv && retired_srv && (*active_srv)->enable_traffic_stats(0) && (*retired_srv)->enable_traffic_stats(0),
            "R5 P2-5 create active & retired servers");
        if (!active_srv || !retired_srv) return;

        std::vector<cli::run_detail::Listener> active_listeners;
        active_listeners.push_back({std::move(*active_srv), 1081, relay::Inbound::socks5});
        std::vector<std::unique_ptr<cli::run_detail::RetiredTcpGeneration>> retired_tcp;
        auto gen = std::make_unique<cli::run_detail::RetiredTcpGeneration>();
        gen->listeners.push_back({std::move(*retired_srv), 1080, relay::Inbound::socks5});
        retired_tcp.push_back(std::move(gen));

        std::optional<config::Config> running;
        cli::run_detail::ControlOperations ops;
        cli::LocalControl ctrl;
        std::vector<std::string> names{"direct", "block"};
        auto nop_pub = [](config::Config const&, std::string_view, std::string_view, bool) -> std::expected<bool, std::string> { return true; };
        std::array<std::string_view, 1> cmd_status{"status"};

        {
            auto reg = retired_tcp.front()->listeners.front().server->track_traffic(
                relay::TrafficProtocol::socks5, relay::ConnectPath::direct, std::nullopt, 443, true);
            reg.count(true, 4096);
            reg.count(false, 8192);
            auto during = cli::run_detail::build_control_api_snapshot(active_listeners, running, 1, names, nullptr, nullptr,
                ops, ctrl, nullptr, control_api::SnapshotFields::listeners, std::nullopt, retired_tcp, {0, 0});
            check(during.listeners.size() == 1 && during.listeners[0].upload_bytes == 4096 && during.listeners[0].download_bytes == 8192,
                "R5 P2-5 snapshot includes retired generation bytes while draining");
            auto st = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_status, nop_pub, std::nullopt,
                nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp, {0, 0});
            check(st && st->contains("active=1 upload=4096 download=8192"), "R5 P2-5 UDS status includes draining retired bytes");
        }

        // Reclaim drained retired generation after deadline: bytes MUST be folded into reclaimed accumulators!
        retired_tcp.front()->deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        std::uint64_t rec_up = 0, rec_down = 0;
        bool drained = cli::run_detail::reclaim_retired_generations(retired_tcp, false, rec_up, rec_down);
        check(drained && retired_tcp.empty() && rec_up == 4096 && rec_down == 8192,
            "R5 P2-5 reclaim_retired_generations folds drained bytes before erasing generation");

        auto after = cli::run_detail::build_control_api_snapshot(active_listeners, running, 1, names, nullptr, nullptr,
            ops, ctrl, nullptr, control_api::SnapshotFields::listeners, std::nullopt, retired_tcp, {rec_up, rec_down});
        check(after.listeners.size() == 1 && after.listeners[0].upload_bytes == 4096 && after.listeners[0].download_bytes == 8192,
            "R5 P2-5 cumulative traffic does not regress to 0 after retired generation eviction");
        auto st_after = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_status, nop_pub, std::nullopt,
            nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp, {rec_up, rec_down});
        check(st_after && st_after->contains("active=0 upload=4096 download=8192"), "R5 P2-5 UDS status preserves reclaimed bytes");

        {
            auto reg2 = active_listeners.front().server->track_traffic(
                relay::TrafficProtocol::socks5, relay::ConnectPath::direct, std::nullopt, 443, true);
            reg2.count(true, 1024);
            reg2.count(false, 2048);
            auto combined = cli::run_detail::build_control_api_snapshot(active_listeners, running, 1, names, nullptr, nullptr,
                ops, ctrl, nullptr, control_api::SnapshotFields::listeners, std::nullopt, retired_tcp, {rec_up, rec_down});
            check(combined.listeners.size() == 1 && combined.listeners[0].upload_bytes == 5120 && combined.listeners[0].download_bytes == 10240,
                "R5 P2-5 reclaimed bytes add cleanly with active generation bytes");
            auto st_comb = cli::run_detail::control_request(active_listeners, running, 1, names, cmd_status, nop_pub, std::nullopt,
                nullptr, nullptr, cli::ControlRole::administrator, ops, ctrl, nullptr, nullptr, nullptr, true, retired_tcp, {rec_up, rec_down});
            check(st_comb && st_comb->contains("active=1 upload=5120 download=10240"), "R5 P2-5 UDS status adds reclaimed + active bytes");
        }
        std::cout << "  [PASS] R5 P2-5 retired generation traffic preserved across generation reclamation\n";
    }
}

int main() {
    using namespace rules;
    // 1. Scale above old 16,384 ceiling & uint16 child index (70,000 rules in a single compound OR + top-level list).
    {
        RuleSet big;
        big.version = 2;
        Rule compound{"or", {}, {}};
        compound.children.reserve(70001);
        for (unsigned i = 0; i < 50000; ++i) {
            compound.children.push_back({"domain-suffix", std::format("zone{}.bench.test", i), {}});
        }
        for (unsigned i = 0; i < 20000; ++i) {
            compound.children.push_back({"ip-cidr", std::format("10.{}.{}.0/24", (i >> 8) & 0xffu, i & 0xffu), {}});
        }
        compound.children.push_back({"port", "8443", {}});
        big.rules.push_back(std::move(compound));

        auto matcher = Matcher::compile(big);
        check(bool(matcher), "70,001-child OR rule-set compiles past 16K/65K ceiling");
        if (matcher) {
            auto d = matcher->match_truth_mapped({.domain = "sub.zone49999.bench.test"});
            auto ip = matcher->match_truth_mapped({.ip = "10.78.31.9"});
            auto port = matcher->match_truth_mapped({.port = 8443});
            auto miss = matcher->match_truth_mapped({.domain = "miss.test", .ip = "198.51.100.1", .port = 80});
            check(d && *d == Matcher::Truth::yes, "70K OR matches 49,999th domain suffix");
            check(ip && *ip == Matcher::Truth::yes, "70K OR matches 19,999th CIDR");
            check(port && *port == Matcher::Truth::yes, "70K OR matches last remainder port");
            check(miss && *miss == Matcher::Truth::no, "70K OR misses unrelated input");
        }

        // > 2 MiB BEVE roundtrip
        auto beve = write_beve(big);
        check(bool(beve) && beve->size() > 2u * 1024u * 1024u, "BEVE output > 2 MiB succeeds");
        if (beve) {
            auto parsed = parse_beve(*beve);
            check(parsed && *parsed == big, "BEVE > 2 MiB roundtrip");
        }
    }

    // 2. JSON rule-set conversion (strict & lenient)
    {
        constexpr std::string_view jsrc = R"({
            "version": 3,
            "rules": [
                {"domain": ["Exact.Test"], "domain_suffix": [".only.example", "root.example"], "ip_cidr": "192.0.2.0/24"},
                {"type": "logical", "mode": "and", "rules": [{"network": "tcp"}, {"port_range": "8000:9000"}], "invert": true}
            ]
        })";
        auto js = parse_rule_input(jsrc, InputFormat::json);
        check(bool(js) && js->rules.size() == 2, "JSON rule-set parses");
        if (js) {
            auto m = Matcher::compile(*js);
            check(bool(m), "converted JSON compiles");
            if (m) {
                check(m->match({.domain = "exact.test"}).value() == std::optional<std::size_t>{0}, "JSON domain match");
                check(m->match({.domain = "sub.only.example"}).value() == std::optional<std::size_t>{0}, "JSON subdomain match");
                check(!m->match({.domain = "only.example"}).value().has_value(), "JSON leading-dot excludes apex");
                check(m->match({.ip = "192.0.2.55"}).value() == std::optional<std::size_t>{0}, "JSON ip_cidr match");
                check(!m->match({.port = 8080, .network = Network::tcp}).value().has_value(), "JSON inverted logical excludes tcp:8080");
                check(m->match({.port = 80, .network = Network::tcp}).value() == std::optional<std::size_t>{1}, "JSON inverted logical matches tcp:80");
            }
        }
        constexpr std::string_view jlenient = R"({
            "version": 3,
            "rules": [
                {"future_unsupported_field": "x"},
                {"domain_suffix": ["Example.NET"], "future_extra": 123}
            ]
        })";
        check(!parse_rule_input(jlenient, InputFormat::json, false, false), "strict JSON rejects unknown fields");
        auto jl = parse_rule_input(jlenient, InputFormat::json, false, true);
        check(jl && jl->rules.size() == 1 && jl->rules[0].value == "example.net", "lenient JSON drops unsupported rules");
    }

    // 3. Domain list, IP CIDR list, Classical YAML list, AdGuard & Merge
    {
        auto doms = parse_rule_input("payload:\n  - '+.Alpha.Test'\n  - 'full:Beta.Test'\n  - '.sub.Test'\n", InputFormat::domain_list);
        check(doms && doms->rules.size() == 3, "YAML domain-list parses");
        auto cidrs = parse_rule_input("# v4 and v6\n192.0.2.10\n2001:db8::/32\n", InputFormat::ipcidr_list);
        check(cidrs && cidrs->rules.size() == 2 && cidrs->rules[0].value == "192.0.2.10/32", "IP CIDR list normalizes bare IP");
        auto cls = parse_rule_input("payload:\n  - 'DOMAIN-SUFFIX,Gamma.Test,no-resolve'\n  - 'IP-CIDR,198.51.100.0/24,no-resolve'\n  - 'GEOIP,CN,no-resolve'\n",
            InputFormat::classical, false, true);
        check(cls && cls->rules.size() == 2, "lenient classical YAML skips GEOIP");
        auto adg = parse_rule_input("! title\n||ads.example^\n|tracker.example^\n@@||good.ads.example^\n", InputFormat::adguard);
        check(bool(adg), "AdGuard filter converts with exceptions");
        if (adg) {
            auto m = Matcher::compile(*adg);
            check(bool(m), "AdGuard filter compiles");
            if (m) {
                check(bool(*m->match({.domain = "x.ads.example"})), "AdGuard blocks subdomain");
                check(!*m->match({.domain = "good.ads.example"}), "AdGuard exception allows");
            }
        }
        std::array<RuleSet, 3> to_merge{*doms, *cidrs, *cls};
        auto merged = merge_rule_sets(to_merge);
        check(merged && merged->rules.size() == 7, "merge deduplicates cleanly");
    }

    // 4. SRS v3 item 19 (network_is_expensive) decoded in both modes + lenient uppercase normalization
    {
        std::vector<std::uint8_t> srs{
            2, // 2 rules
            0, 19, 255, 0, // rule 0: network_is_expensive
            0, 3, 1, 3, 'D', 'N', 'S', 19, 255, 0 // rule 1: uppercase keyword "DNS" + network_is_expensive
        };
        check(!decode_srs_payload(srs, false, false), "strict SRS still rejects uppercase keyword");
        auto ok = decode_srs_payload(srs, false, true);
        check(ok && ok->rules.size() == 2 && ok->rules[0].type == "network-is-expensive", "lenient SRS lowercases & decodes item 19");
    }

    {
        TempDir tmp("nexus-r5-audit");
        test_r5_p2_1_failed_reload_preserves_provider(tmp);
        test_r5_p2_2_provider_refresh_process_options();
        test_r5_p2_3_hot_add_first_selector(tmp);
        test_r5_p2_4_remote_ruleset_url_change_reload(tmp);
        test_r5_p2_5_retired_generation_traffic_preserved();
    }

    if (!failures) std::cout << "Batch 163 rule-set scale & conversion + R5 audit tests passed\n";
    return failures ? 1 : 0;
}
