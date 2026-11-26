// Wave 33 Stage 2 unit tests: local rule-set hot-reload watcher, inline logical DNS rules,
// network=icmp matcher & TUN ICMP routing, outbound bypass pre-match, and route-mode persistence.
import std;
import cli.control;
import cli.proxy_control_operations;
import cli.proxy_mode;
import cli.route_files;
import cli.rule_explain_query;
import cli.ruleset_watcher;
import cli.tun_host;
import cli.tun_udp_proxy;
import config;
import dns.policy;
import dns.response_program;
import packet;
import platform.tun_bridge;
import relay;
import rules;
import rules.rule_input;
import state.file;
import state.maintenance;
import state.snapshot;

namespace {
    void require(bool cond, std::string_view msg) {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    std::atomic<int> g_watcher_wakes{0};
    void record_wake() noexcept { g_watcher_wakes.fetch_add(1, std::memory_order_acq_rel); }

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view tag) {
            auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            path = std::filesystem::temp_directory_path() / std::format("nexus_wave33_{}_{}", tag, stamp);
            std::filesystem::create_directories(path);
        }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    };

    void write_text(std::filesystem::path const& p, std::string_view text) {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        require(bool(out), "open file for write");
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        out.flush();
        require(out.good(), "flush file");
    }

    void test_local_ruleset_watcher() {
        TempDir dir("watch");
        auto local_a = dir.path / "local-a.kdl";
        auto local_b = dir.path / "local-b.txt";
        auto cfg_path = dir.path / "config.kdl";
        write_text(local_a, "schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"a.test\"\n");
        write_text(local_b, "b.test\n");

        constexpr std::string_view kdl = R"kdl(schema-version 1; role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; block; }
dns {
    servers { local "sys"; }
    rule-set "dns-local" path="local-a.kdl" format="kdl"
    rules { - rule-set="dns-local" to="sys"; }
    final "sys"
}
routing {
    rule-set "r-local" path="local-b.txt" format="domain-list"
    rule-set "r-inline" { domain "inline.test"; }
    rules udp=#true { - rule-set "r-local" to="block"; - rule-set "r-inline" to="direct"; - default "direct"; }
})kdl";
        auto parsed = config::parse_kdl(kdl);
        require(parsed.has_value(), parsed ? "" : parsed.error());
        auto collected = cli::run_detail::collect_local_ruleset_paths(*parsed, cfg_path.string());
        require(collected.size() == 2, "collects 2 unique local rule-sets and skips inline");
        require(std::ranges::contains(collected, local_a.lexically_normal().string()), "contains local-a.kdl");
        require(std::ranges::contains(collected, local_b.lexically_normal().string()), "contains local-b.txt");

        g_watcher_wakes.store(0, std::memory_order_release);
        cli::run_detail::LocalRulesetWatcher watcher(
            std::chrono::milliseconds(80), std::chrono::milliseconds(50), &record_wake);
        watcher.start(*parsed, cfg_path.string());
        require(watcher.watched_count() == 2, "watcher tracks 2 local paths");
        require(!watcher.consume_updated(), "initially unchanged");

        // Atomic rename replacement triggers debounced update + wake callback.
        auto tmp = dir.path / "local-a.kdl.tmp";
        write_text(tmp, "schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"a2.test\"\n");
        std::filesystem::rename(tmp, local_a);
        bool triggered = false;
        for (int i = 0; i < 60; ++i) {
            if (watcher.consume_updated()) { triggered = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        require(triggered, "atomic rename triggers local ruleset watcher");
        require(g_watcher_wakes.load(std::memory_order_acquire) >= 1, "wake callback invoked");

        // In-place modification also triggers reload.
        write_text(local_b, "b1.test\nb2.test\n");
        triggered = false;
        for (int i = 0; i < 60; ++i) {
            if (watcher.consume_updated()) { triggered = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        require(triggered, "in-place edit triggers local ruleset watcher");
        watcher.stop();
        std::println("  [PASS] local rule-set watcher (collect + debounce + inotify/stat + atomic rename)");
    }

    void test_logical_dns_rules() {
        constexpr std::string_view kdl = R"kdl(schema-version 1; role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; block; }
dns {
    servers { local "local"; udp "cn" host="114.114.114.114" port=53; udp "intl" host="1.1.1.1" port=53; }
    rules {
        - mode="logical" logic="and" to="cn" { domain-suffix "example.cn"; query-type "A"; source-ip-cidr "10.0.0.0/8"; }
        - mode="logical" logic="or" action="reject" reject-rcode="NXDOMAIN" {
            domain "ad.blocked.test"
            and { domain-suffix "tracker.test"; query-type "AAAA"; }
        }
        - to="intl" { and { domain-suffix "corp.example"; not { process-name "curl"; }; }; }
        - mode="logical" logic="or" to="local" invert=#true { domain-suffix "external.test"; query-type 28; }
    }
    final "intl"
}
routing { default-outbound "direct"; })kdl";
        auto parsed = config::parse_kdl(kdl);
        require(parsed.has_value(), parsed ? "" : "logical DNS parse: " + parsed.error());
        require(parsed->dns && parsed->dns->rules.size() == 4, "4 inline logical DNS rules parsed");

        auto req = policy::dns_context_requirements(parsed->dns->rules);
        require(req.source && req.process, "recursive logical DNS context requirements tracked");

        auto const& rules = parsed->dns->rules;
        std::array<std::uint8_t, 4> lan_ip{10, 1, 2, 3};
        std::array<std::uint8_t, 4> pub_ip{8, 8, 8, 8};

        // Rule 0: mode="logical" logic="and" (domain-suffix + A + 10.0.0.0/8 -> cn = server 1).
        policy::DnsContext lan_ctx{.source_ip_bytes = std::span(lan_ip)};
        auto d1 = policy::select_question_dns_action(rules, "www.example.cn", 1, parsed->dns->final, false, lan_ctx);
        require(d1.action == policy::DnsAction::route && d1.server == 1, "logical AND matches cn");

        // Wrong QTYPE (AAAA) must not match Rule 0.
        auto d2 = policy::select_question_dns_action(rules, "www.example.cn", 28, parsed->dns->final, false, lan_ctx);
        require(d2.server != 1, "logical AND rejects AAAA mismatch");

        // Wrong source IP must not match Rule 0.
        policy::DnsContext pub_ctx{.source_ip_bytes = std::span(pub_ip)};
        auto d3 = policy::select_question_dns_action(rules, "www.example.cn", 1, parsed->dns->final, false, pub_ctx);
        require(d3.server != 1, "logical AND rejects non-LAN source IP");

        // Rule 1: mode="logical" logic="or" with nested AND -> reject NXDOMAIN.
        auto d4 = policy::select_question_dns_action(rules, "ad.blocked.test", 1, parsed->dns->final, false, {});
        require(d4.action == policy::DnsAction::reject && d4.reject_rcode == std::optional<std::uint8_t>(3),
            "logical OR branch 1 rejects NXDOMAIN");
        auto d5 = policy::select_question_dns_action(rules, "x.tracker.test", 28, parsed->dns->final, false, {});
        require(d5.action == policy::DnsAction::reject && d5.reject_rcode == std::optional<std::uint8_t>(3),
            "logical OR nested AND matches AAAA tracker");

        // Rule 2: canonical nested and + not process-name="curl" -> intl (server 2).
        policy::DnsContext browser_ctx{.process_name = "firefox"};
        policy::DnsContext curl_ctx{.process_name = "curl"};
        auto d6 = policy::select_question_dns_action(rules, "api.corp.example", 1, parsed->dns->final, false, browser_ctx);
        require(d6.action == policy::DnsAction::route && d6.server == 2 && d6.rule == std::optional<std::size_t>(2),
            "canonical nested and/not matches firefox");
        auto d7 = policy::select_question_dns_action(rules, "api.corp.example", 1, parsed->dns->final, false, curl_ctx);
        require(d7.rule != std::optional<std::size_t>(2), "canonical nested not excludes curl");

        // Rule 3: invert=#true on OR(external.test, AAAA) -> matches A query for other.test -> local (server 0).
        auto d8 = policy::select_question_dns_action(rules, "other.test", 1, parsed->dns->final, false, {});
        require(d8.action == policy::DnsAction::route && d8.server == 0 && d8.rule == std::optional<std::size_t>(3),
            "inverted logical OR matches other.test A");

        // ResponseWalk integration check.
        dns::ResponseWalk walk(rules, parsed->dns->final, false);
        auto step = walk.next("www.example.cn", 1, lan_ctx);
        require(step && step->action == policy::DnsAction::route && step->server == 1,
            "ResponseWalk evaluates logical DNS rule");

        // Recursion depth guard (> rules::max_rule_depth must be rejected cleanly!).
        std::string deep = "schema-version 1\nrole \"client\"\ninbounds { socks5 \"in\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\n"
            "outbounds { direct; }\ndns { servers { local \"s\"; }; rules { - to=\"s\" {\n";
        for (unsigned i = 0; i < rules::max_rule_depth + 4; ++i) deep += "and {\n";
        deep += "domain \"deep.test\"\n";
        for (unsigned i = 0; i < rules::max_rule_depth + 4; ++i) deep += "}\n";
        deep += "}; }; final \"s\"; }\nrouting { default-outbound \"direct\"; }\n";
        auto too_deep = config::parse_kdl(deep);
        require(!too_deep.has_value(), "excessive logical DNS nesting depth rejected");

        // Invalid mode/logic rejected.
        constexpr std::string_view bad_logic = R"kdl(schema-version 1; role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; }
dns { servers { local "s"; }; rules { - mode="logical" logic="xor" to="s" { domain "x.test"; }; }; final "s"; }
routing { default-outbound "direct"; })kdl";
        require(!config::parse_kdl(bad_logic).has_value(), "invalid logic=\"xor\" rejected");
        std::println("  [PASS] top-level inline logical (and/or/not) DNS rules + depth guard");
    }

    void test_icmp_and_bypass_routing() {
        constexpr std::string_view kdl = R"kdl(
schema-version 1
role "client"
inbounds {
    socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }
}
outbounds {
    direct
    block
    socks5 "proxy" { server "127.0.0.1:1081"; }
}
routing {
    rules udp=#true {
        - action="bypass"
        - ip-cidr "10.0.0.0/8" action="bypass"
        - domain-suffix "lan" action="bypass"
        - action="reject" { network "icmp"; ip-cidr "1.1.1.0/24"; }
        - network "icmp" action="bypass"
        - domain "explicit-bypass.test" action="bypass" to="proxy"
        - ip-cidr "203.0.113.0/24" action="reject"
        - default "proxy"
    }
}
)kdl";
        auto parsed = config::parse_kdl(kdl);
        require(parsed.has_value(), parsed ? "" : "icmp/bypass KDL: " + parsed.error());
        auto files = cli::load_route_files(*parsed, "/tmp/test.kdl", true);
        require(files.has_value(), files ? "" : files.error());
        auto projected = cli::project_routes(*parsed, *files);
        auto snap = projected.compile(*parsed, "in");
        require(snap && snap->ordered, "compiled ordered snapshot");
        auto const& prog = snap->ordered->program;

        // 1. Bare unconditional `action="bypass"` at index 0 is skipped (kernel marker),
        //    so public IP falls through to default/reject cleanly!
        auto pub_rej = prog.next({.ip = "203.0.113.5", .port = 443, .network = rules::Network::tcp});
        require(pub_rej && *pub_rej && (**pub_rej).action.kind == rules::ProgramActionKind::reject,
            "bare bypass does not shadow later rules");

        // 2. Predicated `action="bypass"` WITHOUT outbound terminates with bypass -> direct (outbound 0)!
        auto lan_byp = prog.next({.ip = "10.20.30.40", .port = 443, .network = rules::Network::tcp});
        require(lan_byp && *lan_byp && (**lan_byp).terminal() &&
            (**lan_byp).action.kind == rules::ProgramActionKind::bypass && (**lan_byp).action.outbound == 0,
            "predicated IP bypass terminates directly to outbound 0");

        auto dom_byp = prog.next({.explicit_domain = "nas.lan", .port = 443, .network = rules::Network::tcp});
        require(dom_byp && *dom_byp && (**dom_byp).action.kind == rules::ProgramActionKind::bypass &&
            (**dom_byp).action.outbound == 0, "domain-suffix bypass terminates directly");

        // 3. Explicit outbound bypass routes cleanly to chosen outbound (proxy = 2) AND sets tunnel_references!
        auto exp_byp = prog.next({.explicit_domain = "explicit-bypass.test", .port = 443, .network = rules::Network::tcp});
        require(exp_byp && *exp_byp && (**exp_byp).action.kind == rules::ProgramActionKind::bypass &&
            (**exp_byp).action.outbound == 2, "explicit outbound bypass targets proxy");
        auto ref_kdl = config::parse_kdl(R"kdl(schema-version 1; role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; block; socks5 "proxy" { server "127.0.0.1:1081"; }; }
routing { rules { - domain "b.test" action="bypass" to="proxy"; - default "direct"; }; })kdl");
        require(ref_kdl.has_value(), "parse bypass tunnel_references config");
        auto ref_files = cli::load_route_files(*ref_kdl, "/tmp/test.kdl", true);
        auto ref_snap = cli::project_routes(*ref_kdl, *ref_files).compile(*ref_kdl, "in");
        require(ref_snap && ref_snap->tunnel_references && ref_snap->tunnel_references->test(0),
            "explicit bypass outbound included in tunnel_references");

        // 4. UDP ordered routing handles bypass cleanly without dropping packets!
        auto now = std::chrono::steady_clock::now();
        auto dl = now + std::chrono::seconds(5);
        std::array<std::uint8_t, 4> udp_payload{1, 2, 3, 4};
        auto udp_act = cli::tun_enabled::TunUdpProxyOps::route_ordered_udp(
            udp_payload, rules::ProgramInput{.ip = "10.1.1.1", .port = 5353, .network = rules::Network::udp},
            *snap->ordered, now, dl);
        require(udp_act && udp_act->kind == rules::ProgramActionKind::bypass && udp_act->outbound == 0,
            "TUN ordered UDP routes bypass to outbound 0");

        // 5. network=icmp matching on IPv4 & IPv6 ICMP Echo packets via TUN ICMP router!
        std::array<std::uint8_t, 4> icmp_payload{0xde, 0xad, 0xbe, 0xef};
        auto pkt4_blk = packet::make_icmp_echo4({{10, 0, 0, 2}, {1, 1, 1, 1}, packet::EchoKind::request, 7, 1, icmp_payload}, 1500);
        require(pkt4_blk.has_value(), "build ICMPv4 echo to 1.1.1.1");
        auto dec4_blk = cli::tun_enabled::TunUdpProxyOps::route_tun_icmp(*pkt4_blk, snap->matcher, &*snap->ordered, "tun0");
        require(dec4_blk && dec4_blk->rejected && dec4_blk->outbound == 1, "ICMPv4 to 1.1.1.1 rejected by network=icmp rule");

        auto pkt4_ok = packet::make_icmp_echo4({{10, 0, 0, 2}, {8, 8, 8, 8}, packet::EchoKind::request, 7, 2, icmp_payload}, 1500);
        require(pkt4_ok.has_value(), "build ICMPv4 echo to 8.8.8.8");
        auto dec4_ok = cli::tun_enabled::TunUdpProxyOps::route_tun_icmp(*pkt4_ok, snap->matcher, &*snap->ordered, "tun0");
        require(dec4_ok && !dec4_ok->rejected && dec4_ok->bypassed && dec4_ok->outbound == 0,
            "ICMPv4 to 8.8.8.8 bypassed by network=icmp rule");

        auto pkt6_ok = packet::make_icmp_echo6({
            {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
            {0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11},
            packet::EchoKind::request, 9, 1, icmp_payload}, 1500);
        require(pkt6_ok.has_value(), "build ICMPv6 echo");
        auto dec6_ok = cli::tun_enabled::TunUdpProxyOps::route_tun_icmp(*pkt6_ok, snap->matcher, &*snap->ordered, "tun0");
        require(dec6_ok && !dec6_ok->rejected && dec6_ok->bypassed && dec6_ok->outbound == 0,
            "ICMPv6 bypassed by network=icmp rule");

        // 6. rule-explain CLI query parser accepts icmp without port.
        auto explain_q = cli::explain::parse_query_args("icmp", "1.1.1.1", {});
        require(explain_q && explain_q->input.network == rules::Network::icmp &&
            explain_q->input.ip == std::optional<std::string_view>("1.1.1.1") && !explain_q->input.port,
            "rule-explain parses portless icmp IPv4 query");

        // 7. JSON rule-set with network="icmp" parses and compiles cleanly.
        auto json_set = rules::parse_rule_input(R"({"version":2,"rules":[{"network":["icmp"]}]})", rules::InputFormat::json);
        require(json_set.has_value(), json_set ? "" : json_set.error().message);
        auto json_matcher = rules::Matcher::compile(*json_set);
        require(json_matcher.has_value(), "compile JSON network=icmp matcher");
        auto jm_hit = json_matcher->match({.network = rules::Network::icmp});
        auto jm_miss = json_matcher->match({.network = rules::Network::tcp});
        require(jm_hit && jm_hit->has_value() && jm_miss && !jm_miss->has_value(),
            "JSON network=icmp matches icmp only");

        // 8. Live TunHost ICMP Echo routing via ExternalTunBridge (reject vs bypass on same TUN IP).
        {
            auto srv = relay::Server::create();
            require(srv.has_value(), "create relay server for TUN ICMP");
            auto tk = config::parse_kdl(R"kdl(schema-version 1; role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; block; }
routing { rules udp=#true { - action="reject" { network "icmp"; source-ip-cidr "10.0.0.99/32"; }; - network "icmp" action="bypass"; - default "direct"; }; })kdl");
            require(tk.has_value(), "parse TUN ICMP config");
            auto tf = cli::load_route_files(*tk, "/tmp/test.kdl", true);
            auto ts = cli::project_routes(*tk, *tf).compile(*tk, "in");
            require(ts && ts->ordered, "compile TUN ICMP ordered snapshot");
            std::vector<relay::RouteSnapshot> vec; vec.push_back(std::move(*ts));
            auto snaps = std::make_shared<relay::RouteSnapshots>();
            snaps->store(std::make_shared<std::vector<relay::RouteSnapshot> const>(std::move(vec)), std::memory_order_release);
            require((*srv)->set_route_snapshots(snaps, 0), "set TUN ICMP snapshots");
            config::TunInbound tcfg{}; tcfg.mtu = 1500; tcfg.inet4_address = "198.18.0.1/24";
            auto bridge = std::make_shared<platform::ExternalTunBridge>(1500);
            cli::tun_enabled::TunHost host(**srv, tcfg, false);
            auto started = host.start(bridge);
            require(started.has_value(), started ? "" : started.error());
            auto req_blk = packet::make_icmp_echo4({{10, 0, 0, 99}, {198, 18, 0, 1}, packet::EchoKind::request, 42, 1, icmp_payload}, 1500);
            auto req_ok = packet::make_icmp_echo4({{10, 0, 0, 2}, {198, 18, 0, 1}, packet::EchoKind::request, 42, 2, icmp_payload}, 1500);
            require(req_blk && req_ok && bridge->inject_packet(*req_blk).has_value() && bridge->inject_packet(*req_ok).has_value(), "inject ICMP packets");
            std::array<std::uint8_t, 1500> out{};
            std::optional<packet::IcmpEcho4View> got;
            for (int i = 0; i < 100 && !got; ++i) {
                if (auto n = bridge->pop_outbound(out)) {
                    auto p = packet::parse_icmp_echo4(std::span(out).first(*n));
                    require(p && p->kind == packet::EchoKind::reply && p->sequence == 2 && p->destination == std::array<std::uint8_t, 4>{10, 0, 0, 2},
                        "rejected source dropped, bypassed source replied");
                    got = *p;
                } else std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            require(got.has_value(), "received live TUN ICMP echo reply");
            host.stop();
        }
        std::println("  [PASS] network=icmp matcher, TUN ICMP routing & outbound bypass pre-match");
    }

    void test_route_mode_persistence() {
        TempDir dir("mode");
        auto state_dir = dir.path / "state";
        require(state::ensure_private_directory(state_dir).has_value(), "create private state dir");

        constexpr std::string_view kdl = R"kdl(
schema-version 1
role "client"
inbounds { socks5 "in" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds {
    direct
    block
    socks5 "proxy-a" { server "127.0.0.1:1081"; }
}
routing { default-outbound "proxy-a"; }
)kdl";
        auto cfg = config::parse_kdl(kdl);
        require(cfg.has_value(), "parse mode config");
        std::optional<config::Config> running = *cfg;

        {
            cli::SelectorState state;
            require(state.open_route_mode_only(state_dir.string()).has_value(), "open state dir #1");
            cli::run_detail::RuntimeRouteModeController ctrl;
            ctrl.restore(state, *cfg);
            require(ctrl.mode_name() == "rule", "initial mode is rule");

            cli::run_detail::ControlOperations ops;
            std::array<std::string_view, 3> cmd{"mode", "global", "proxy-a"};
            auto res = ctrl.handle_command(running, cli::ControlRole::administrator, cmd, ops);
            require(res.has_value(), res ? "" : res.error());
            require(ctrl.mode_name() == "global" && ctrl.global_outbound_name == "proxy-a", "switched to global/proxy-a");
        }

        // Inspect NXST01 state inventory.
        auto inv = state::inspect_route_mode(state_dir);
        require(inv.version == "NXST01" && inv.health == "ok" && inv.entries == 1,
            "inspect_route_mode reports healthy NXST01 snapshot");

        // Restart #1: restore global/proxy-a, then switch to direct.
        {
            cli::SelectorState state;
            require(state.open_route_mode_only(state_dir.string()).has_value(), "open state dir #2");
            cli::run_detail::RuntimeRouteModeController ctrl;
            ctrl.restore(state, *cfg);
            require(ctrl.mode_name() == "global" && ctrl.global_outbound_name == "proxy-a",
                "restored global/proxy-a after restart");

            cli::run_detail::ControlOperations ops;
            std::array<std::string_view, 2> cmd{"mode", "direct"};
            auto res = ctrl.handle_command(running, cli::ControlRole::administrator, cmd, ops);
            require(res.has_value(), "switch to direct");
        }

        // Restart #2: restore direct.
        {
            cli::SelectorState state;
            require(state.open_route_mode_only(state_dir.string()).has_value(), "open state dir #3");
            cli::run_detail::RuntimeRouteModeController ctrl;
            ctrl.restore(state, *cfg);
            require(ctrl.mode_name() == "direct", "restored direct mode after restart");
        }

        // Tamper detection: corrupting 1 byte inside route-mode.state must fail NXST01 integrity check!
        auto snap_file = state_dir / "route-mode.state";
        {
            std::fstream f(snap_file, std::ios::binary | std::ios::in | std::ios::out);
            require(bool(f), "open route-mode.state for tamper test");
            f.seekg(0, std::ios::end);
            auto sz = static_cast<std::streamoff>(f.tellg());
            require(sz > 8, "snapshot non-empty");
            f.seekg(sz - 1);
            char c = 0;
            f.read(&c, 1);
            c ^= 0x5a;
            f.seekp(sz - 1);
            f.write(&c, 1);
            f.flush();
        }
        auto bad_inv = state::inspect_route_mode(state_dir);
        require(bad_inv.health == "damaged", "inspect_route_mode detects tampered snapshot");
        cli::SelectorState tampered;
        require(!tampered.open_route_mode_only(state_dir.string()).has_value(),
            "SelectorState rejects tampered route-mode.state");

        // Wrong payload magic inside a valid NXST01 envelope must also be flagged as damaged!
        auto bad_dir = dir.path / "bad_magic";
        require(state::ensure_private_directory(bad_dir).has_value(), "create bad_magic dir");
        auto inst = state::InstanceLock::open(bad_dir);
        require(inst.has_value(), "open bad_magic instance");
        constexpr std::string_view bad_pl{"BADMAG\0\0", 8};
        state::SnapshotSpec mspec{"route-mode.state", ".route-mode.next",
            {.max_payload = 263, .fingerprint = {std::byte{'R'}, std::byte{'M'}, std::byte{'D'}}}};
        require(state::commit_snapshot(*inst, mspec, 1, 0, std::as_bytes(std::span(bad_pl))).has_value(), "write bad magic");
        require(state::inspect_route_mode(bad_dir).health == "damaged", "inspect_route_mode rejects wrong NXMOD1 prefix");
        std::println("  [PASS] route-mode NXST01 persistence, restart restore & tamper rejection");
    }
}

int main() {
    std::println("Running Wave 33 Stage 2 routing/DNS/watcher/mode unit tests...");
    test_local_ruleset_watcher();
    test_logical_dns_rules();
    test_icmp_and_bypass_routing();
    test_route_mode_persistence();
    std::println("ALL WAVE 33 STAGE 2 UNIT TESTS PASSED");
    return 0;
}
