#include "../include/nexus/core_c_api.h"
#include <cassert>
#include <unistd.h>

import std;
import cli.proxy_group_health;
import config;
import corosio;
import logging;
import logging.cli;
import platform.network_state;
import platform.system_proxy;
import platform.service_manager;
import relay;
import rules;
import state.core;
import state.lock;

auto nexus_system_proxy(int argc, char** argv) -> int;
auto nexus_service(int argc, char** argv) -> int;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    auto call_cli(int (*fn)(int, char**), std::initializer_list<std::string_view> args) -> int {
        std::vector<std::string> owned;
        owned.reserve(args.size());
        for (auto a : args) owned.emplace_back(a);
        std::vector<char*> ptrs;
        ptrs.reserve(owned.size() + 1);
        for (auto& s : owned) ptrs.push_back(s.data());
        ptrs.push_back(nullptr);
        return fn(static_cast<int>(owned.size()), ptrs.data());
    }

    auto test_system_proxy() -> void {
        auto def = platform::default_bypass_list();
        require(def.size() >= 7 && std::ranges::contains(def, "localhost") &&
            std::ranges::contains(def, "*.local"), "default bypass list");

        auto parsed = platform::parse_bypass_csv("localhost, 127.0.0.1 ; *.lan,localhost");
        require(parsed.size() == 3 && parsed[0] == "localhost" && parsed[1] == "127.0.0.1" &&
            parsed[2] == "*.lan", "parse_bypass_csv dedup and trim");

        platform::SystemProxyConfig cfg{.host = "127.0.0.1", .http_port = 7890, .socks_port = 7891, .bypass = {"10.0.0.0/8", "localhost"}};
        require(platform::validate_system_proxy_config(cfg).has_value(), "valid system proxy config");
        require(!platform::validate_system_proxy_config({.host = "bad host", .http_port = 8080}).has_value(),
            "reject whitespace in host");
        require(!platform::validate_system_proxy_config({.pac_url = "ftp://x/a.pac"}).has_value(),
            "reject non-http pac_url");
        require(platform::validate_system_proxy_config({.pac_url = "https://127.0.0.1/proxy.pac"}).has_value(),
            "accept https pac_url");

        require(platform::format_windows_bypass(cfg.bypass) == "10.0.0.0/8;localhost;<local>",
            "windows bypass format");
        require(platform::format_gnome_ignore_hosts(cfg.bypass) == "['10.0.0.0/8', 'localhost']",
            "gnome ignore-hosts format");

        auto env_on = platform::format_shell_env_exports(cfg, true);
        require(env_on.contains("http_proxy=\"http://127.0.0.1:7890\"") &&
            env_on.contains("all_proxy=\"socks5h://127.0.0.1:7891\"") &&
            env_on.contains("no_proxy=\"10.0.0.0/8,localhost\""), "shell env export on");
        auto env_off = platform::format_shell_env_exports(cfg, false);
        require(env_off.starts_with("unset http_proxy https_proxy"), "shell env export off");

        require(call_cli(nexus_system_proxy, {"system-proxy", "status", "--json"}) == 0, "system-proxy status json");
        require(call_cli(nexus_system_proxy, {"system-proxy", "on", "--port", "8080", "--socks-port", "1080", "--shell-env"}) == 0,
            "system-proxy on shell-env");
        require(call_cli(nexus_system_proxy, {"system-proxy", "off", "--dry-run"}) == 0, "system-proxy off dry-run");
    }

    auto test_service_manager() -> void {
        platform::ServiceSpec sys_spec{
            .name = "nexus-test",
            .binary_path = "/usr/bin/nexus",
            .config_path = "/etc/nexus/config.kdl",
            .working_dir = "/var/lib/nexus",
            .description = "Nexus & Core <Test>",
            .log_path = "/var/log/nexus.log",
            .user_scope = false,
        };
        auto unit = platform::render_systemd_unit(sys_spec);
        require(unit.has_value() && unit->contains("DynamicUser=yes") &&
            unit->contains("AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN") &&
            unit->contains("ExecStartPre=\"/usr/bin/nexus\" check --config \"/etc/nexus/config.kdl\"") &&
            unit->contains("WantedBy=multi-user.target"), "systemd system unit rendered");

        auto user_spec = sys_spec;
        user_spec.user_scope = true;
        auto user_unit = platform::render_systemd_unit(user_spec);
        require(user_unit.has_value() && !user_unit->contains("DynamicUser=yes") &&
            user_unit->contains("WantedBy=default.target"), "systemd user unit rendered");

        auto plist = platform::render_launchd_plist(sys_spec);
        require(plist.has_value() && plist->contains("<string>io.nexus.nexus-test</string>") &&
            plist->contains("<string>/usr/bin/nexus</string>") &&
            plist->contains("<key>KeepAlive</key>"), "launchd plist rendered");

        auto wincmd = platform::render_windows_service_command(sys_spec);
        require(wincmd.has_value() && *wincmd == "\"/usr/bin/nexus\" run --config \"/etc/nexus/config.kdl\"",
            "windows service command rendered");

        require(!platform::validate_service_spec({.name = "bad/name", .binary_path = "/bin/x", .config_path = "/c.kdl"}).has_value(),
            "reject slash in service name");

        auto tmp = std::filesystem::temp_directory_path() / "nexus-batch190-svc-test";
        std::filesystem::remove_all(tmp);
        auto written = platform::install_service(sys_spec, tmp.string(), false);
        require(written.has_value() && std::filesystem::exists(*written), "install_service writes overridden unit dir");
        std::filesystem::remove_all(tmp);

        require(call_cli(nexus_service, {"service", "install", "--config", "/tmp/c.kdl", "--render-target", "launchd", "--dry-run"}) == 0,
            "service install dry-run launchd");
        require(call_cli(nexus_service, {"service", "status", "--json"}) == 0, "service status json");
    }

    auto test_c_api_parity() -> void {
        char const* feats = nexus_core_build_features();
        require(feats != nullptr, "build_features non-null");

        char err[256]{};
        char const* valid_kdl =
            "schema-version 1\nrole \"client\"\n"
            "inbounds { inbound \"s\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n"
            "outbounds { outbound \"direct\" type=\"direct\"; }\n"
            "routing { default-outbound \"direct\"; }\n";
        require(nexus_core_check_config_text(valid_kdl, err, sizeof(err)) == 0, "check_config_text valid");
        require(nexus_core_check_config_text("bad {", err, sizeof(err)) != 0 && std::string_view(err).size() > 0,
            "check_config_text invalid populates err_buf");

        char const* clash_yaml =
            "proxies:\n"
            "  - name: ss1\n"
            "    type: ss\n"
            "    server: 198.51.100.2\n"
            "    port: 8388\n"
            "    cipher: chacha20-ietf-poly1305\n"
            "    password: secret\n";
        std::size_t need = 0;
        int rc_sz = nexus_core_convert_config("clash", clash_yaml, nullptr, 0, &need, err, sizeof(err));
        require(rc_sz == -4 && need > 32, "convert_config size query");
        std::string kdl_out(need + 1, '\0');
        std::size_t actual = 0;
        int rc_ok = nexus_core_convert_config("clash", clash_yaml, kdl_out.data(), kdl_out.size(), &actual, err, sizeof(err));
        require(rc_ok == 0 && actual > 0, "convert_config Clash -> KDL succeeds");
        require(nexus_core_check_config_text(kdl_out.c_str(), err, sizeof(err)) == 0,
            "converted KDL passes check_config_text");

        char info_buf[512]{};
        std::size_t info_len = 0;
        require(nexus_core_runtime_info_json(info_buf, sizeof(info_buf), &info_len) == 0 && info_len > 20,
            "runtime_info_json fits");
        std::string_view info_sv(info_buf, info_len);
        require(info_sv.contains("\"version\":\"0.1.0\"") && info_sv.contains("\"os\":\"") &&
            info_sv.contains("\"arch\":\"") && info_sv.contains("\"features\":\""),
            "runtime_info_json native Nexus metadata");
    }

    auto test_batch169_runtime_resilience() -> void {
        // 1. init_multiplexed_child propagates full parent context uniformly (zero-copy + COW)
        corosio::io_context io;
        rules::RuntimeRouteMode mode;
        relay::Session empty_session(io);
        require(!empty_session.extras && !empty_session.network_metadata &&
            empty_session.process_path_view().empty() && !empty_session.direct_shaping_pending(),
            "default Session keeps cold metadata unallocated");
        relay::Session parent(io), child(io);
        parent.runtime_mode = &mode;
        parent.source_uid = 1000u;
        parent.source_gid = 1000u;
        parent.ensure_mutable_extras().process_path = "/usr/bin/curl";
        parent.reverse_view = 42u;
        parent.direct_connect_timeout_ms = 3456u;
        auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        relay::init_multiplexed_child(child, parent, dl);
        require(child.transport_owner == &parent && child.runtime_mode == &mode &&
            child.source_uid == 1000u && child.process_path_view() == "/usr/bin/curl" && child.reverse_view == 42u &&
            child.direct_connect_timeout_ms == 3456u && child.handshake_deadline == dl &&
            child.extras == parent.extras,
            "init_multiplexed_child shares parent SessionExtras in O(1)");
        child.ensure_mutable_extras().route_override_port = 8443;
        require(child.extras != parent.extras && child.process_path_view() == "/usr/bin/curl" &&
            child.route_override_port_val() == 8443 && parent.route_override_port_val() == 0,
            "SessionExtras copy-on-write isolates child mutations from parent");

        // 2. Multi-producer logging::Runtime: 24 threads x 50 messages -> 0 dropped
        logging::Config lcfg{};
        lcfg.level = logging::Level::info;
        lcfg.sinks.push_back({.kind = logging::SinkKind::off});
        lcfg.settings.ring_capacity = 2048;
        lcfg.ring_level = logging::Level::info;
        logging::Runtime runtime;
        require(runtime.start(lcfg).has_value(), "logging Runtime start multi-producer");
        {
            std::vector<std::jthread> writers;
            writers.reserve(24);
            for (int t = 0; t < 24; ++t) {
                writers.emplace_back([&, t] {
                    for (int m = 0; m < 50; ++m)
                        runtime.emit(logging::Level::info, logging::Domain::core, 1, {}, "t{} m{}", t, m);
                });
            }
        }
        auto diag = runtime.control(true, {});
        for (int i = 0; i < 50 && diag && !diag->contains("queued=0 "); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            diag = runtime.control(true, {});
        }
        auto snap = runtime.query_logs({.limit = 2048});
        require(diag && diag->contains("dropped=0 ") && snap.entries.size() == 1200,
            "24-thread logging::Runtime zero drops (1200 messages captured)");
        runtime.shutdown();

        // 3. state::InstanceLock brief backoff succeeds when transient lock releases within 50ms
        auto ldir = std::filesystem::temp_directory_path() / ("nexus-b169-lock-" + std::to_string(::getpid()));
        std::error_code ec;
        std::filesystem::remove_all(ldir, ec);
        std::filesystem::create_directories(ldir, ec);
        std::filesystem::permissions(ldir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
        auto held = state::InstanceLock::open(ldir);
        require(held.has_value(), "initial InstanceLock::open");
        std::optional<state::InstanceLock> holder = std::move(*held);
        std::jthread releaser([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            holder.reset();
        });
        {
            auto second = state::InstanceLock::open(ldir);
            require(second.has_value(), "second InstanceLock::open succeeds via backoff");
        }
        releaser.join();
        std::filesystem::remove_all(ldir, ec);
    }

    auto test_wave30b_groups_and_network() -> void {
        using Clock = std::chrono::steady_clock;
        // 1. KDL parsing for interrupt-exist-connections, idle-timeout-ms, probe-concurrency
        char const* valid_kdl = R"(
schema-version 1
role "client"
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "direct" type="direct"
    outbound "n1" type="socks5" { server host="127.0.0.1" port=2001; }
    outbound "n2" type="socks5" { server host="127.0.0.1" port=2002; }
    outbound "n3" type="socks5" { server host="127.0.0.1" port=2003; }
    outbound "n4" type="socks5" { server host="127.0.0.1" port=2004; }
    outbound "n5" type="socks5" { server host="127.0.0.1" port=2005; }
    outbound "n6" type="socks5" { server host="127.0.0.1" port=2006; }
    outbound "man" type="selector" {
        member "n1"; member "n2"; selected "n1";
        interrupt-exist-connections #true;
    }
    outbound "auto" type="url-test" {
        member "n1"; member "n2"; member "n3"; member "n4"; member "n5"; member "n6";
        probe-url "http://127.0.0.1:80/ping";
        probe-interval-ms 500;
        idle-timeout-ms 100;
        probe-concurrency 4;
        interrupt-exist-connections #true;
    }
    outbound "lb" type="load-balance" {
        member "n1"; member "n2"; member "n3";
        probe-url "http://127.0.0.1:80/ping";
        probe-interval-ms 500;
        probe-concurrency 2;
        interrupt-exist-connections #true;
    }
}
routing {
    rules {
        - domain "man.example" to="man"
        - domain "lb.example" to="lb"
    }
    default-outbound "auto"
}
)";
        auto parsed = config::parse_kdl(valid_kdl);
        if (!parsed) std::cerr << "parse error: " << parsed.error() << '\n';
        require(parsed.has_value(), "30B valid outbound groups KDL");
        auto cfg = std::move(*parsed);
        require(cfg.selectors.size() == 3 &&
            cfg.selectors[0].interrupt_exist_connections &&
            cfg.selectors[1].interrupt_exist_connections &&
            cfg.selectors[1].probe.idle_timeout_ms == 100 &&
            cfg.selectors[1].probe.probe_concurrency == 4 &&
            cfg.selectors[2].probe.probe_concurrency == 2,
            "30B parsed group options match");

        // Invalid probe-concurrency / idle-timeout-ms rejected
        auto bad1 = config::parse_kdl(R"(
schema-version 1
role "client"
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "direct" type="direct"
    outbound "g" type="url-test" { member "direct"; probe-url "http://127.0.0.1/p"; probe-concurrency 0; }
}
routing { default-outbound "g"; }
)");
        require(!bad1.has_value(), "30B reject probe-concurrency 0");
        auto bad2 = config::parse_kdl(R"(
schema-version 1
role "client"
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "direct" type="direct"
    outbound "g" type="url-test" { member "direct"; probe-url "http://127.0.0.1/p"; probe-concurrency 17; }
}
routing { default-outbound "g"; }
)");
        require(!bad2.has_value(), "30B reject probe-concurrency 17");
        auto bad3 = config::parse_kdl(R"(
schema-version 1
role "client"
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    outbound "direct" type="direct"
    outbound "g" type="selector" { member "direct"; idle-timeout-ms 1000; }
}
routing { default-outbound "g"; }
)");
        require(!bad3.has_value(), "30B reject idle-timeout-ms on selector");

        // 2. Concurrent member probing (4 at once on 6-member group)
        auto t0 = Clock::now();
        auto health_res = cli::run_detail::OutboundGroupHealth::create(cfg, t0);
        require(health_res.has_value(), "30B OutboundGroupHealth::create");
        auto health = std::move(*health_res);
        std::vector<std::shared_ptr<relay::OutboundProbe>> q;
        auto enqueue = [&](std::shared_ptr<relay::OutboundProbe> p) { q.push_back(std::move(p)); return true; };
        auto sel0 = health.poll(enqueue, cfg, std::uint64_t{1}, t0);
        require(!sel0.has_value() && q.size() == 4, "30B concurrent probe launches 4 members simultaneously");
        require(health.observe(cfg, 1, 0, std::uint64_t{1}).probing &&
            health.observe(cfg, 1, 3, std::uint64_t{1}).probing &&
            !health.observe(cfg, 1, 4, std::uint64_t{1}).probing,
            "30B observe reports all 4 concurrent probes active");
        // Complete first 2 probes (n1=50ms, n2=15ms) -> next poll launches remaining 2 (n5, n6)
        q[0]->result.store(52, std::memory_order_release);
        q[1]->result.store(17, std::memory_order_release);
        auto sel1 = health.poll(enqueue, cfg, std::uint64_t{1}, t0 + std::chrono::milliseconds(20));
        require(!sel1.has_value() && q.size() == 6, "30B concurrent probe refills window to finish remaining 2 members");
        q[2]->result.store(42, std::memory_order_release);
        q[3]->result.store(32, std::memory_order_release);
        q[4]->result.store(62, std::memory_order_release);
        q[5]->result.store(72, std::memory_order_release);
        auto sel2 = health.poll(enqueue, cfg, std::uint64_t{1}, t0 + std::chrono::milliseconds(40));
        require(sel2.has_value() && sel2->group == 1 && sel2->member == "n2", "30B concurrent round picks fastest member n2");

        // 3. idle-timeout-ms pauses probing after idle_timeout_ms and resumes immediately on group activity
        // Complete lb group round first so cursor returns to auto
        q.clear();
        (void)health.poll(enqueue, cfg, std::uint64_t{1}, t0 + std::chrono::milliseconds(40));
        require(q.size() == 2, "30B lb group respects probe-concurrency 2");
        q[0]->result.store(22, std::memory_order_release);
        q[1]->result.store(25, std::memory_order_release);
        (void)health.poll(enqueue, cfg, std::uint64_t{1}, t0 + std::chrono::milliseconds(45));
        require(q.size() == 3, "30B lb group probes 3rd member");
        q[2]->result.store(30, std::memory_order_release);
        (void)health.poll(enqueue, cfg, std::uint64_t{1}, t0 + std::chrono::milliseconds(50));

        q.clear();
        auto t_idle = t0 + std::chrono::milliseconds(600);
        auto idle_sel = health.poll(enqueue, cfg, std::uint64_t{1}, t_idle);
        require(!idle_sel.has_value() && q.empty() && health.is_idle_paused(1),
            "30B idle-timeout-ms pauses probing with no group traffic");
        health.note_group_activity("auto", t_idle + std::chrono::milliseconds(10));
        require(!health.is_idle_paused(1), "30B note_group_activity clears idle pause");
        // Advance cursor back to auto (past lb which is still within interval)
        (void)health.poll(enqueue, cfg, std::uint64_t{1}, t_idle + std::chrono::milliseconds(10));
        if (q.empty()) (void)health.poll(enqueue, cfg, std::uint64_t{1}, t_idle + std::chrono::milliseconds(10));
        require(!q.empty(), "30B probing resumes immediately after group activity");

        // 4. Dial-failure instant failover (url-test + load-balance + GroupRuntimeHooks wake)
        static std::atomic<int> wake_count{0};
        relay::GroupRuntimeHooks hooks(+[]() noexcept { wake_count.fetch_add(1, std::memory_order_relaxed); });
        hooks.mark_active(1);
        require(hooks.last_active_ms(1) > 0, "30B GroupRuntimeHooks records active timestamp");
        hooks.record_dial_failure("auto", 2);
        std::vector<relay::GroupDialFailure> drained;
        hooks.drain_dial_failures(drained);
        require(wake_count.load() == 1 && drained.size() == 1 && drained[0].group_tag == "auto" && drained[0].outbound == 2,
            "30B GroupRuntimeHooks queues dial failure & wakes host");
        auto failover = health.record_dial_failure(cfg, "auto", "n1", std::uint64_t{1}, t_idle + std::chrono::milliseconds(20));
        require(failover.has_value() && failover->group == 1 && failover->member == "n2",
            "30B url-test dial failure immediately fails over from n1 to healthy n2");
        auto obs_n1 = health.observe(cfg, 1, 0, std::uint64_t{1});
        require(obs_n1.state == "down" && obs_n1.breaker_open, "30B failed member marked down with breaker open");

        auto lb_fail = health.record_dial_failure(cfg, "lb", "n1", std::uint64_t{1}, t_idle + std::chrono::milliseconds(20));
        require(lb_fail.has_value() && lb_fail->balance_changed && lb_fail->demoted_members.size() == 1 && lb_fail->demoted_members[0] == 0,
            "30B load-balance dial failure demotes failed member immediately");

        // 5. TrafficRegistry group_tag tracking + close_group_sessions + concurrent Server probe queue
        auto srv = relay::Server::create();
        require(srv.has_value() && (*srv)->enable_traffic_stats(8), "30B Server with traffic stats");
        corosio::io_context io;
        relay::Session s1(io), s2(io), s3(io), s4(io);
        s1.traffic = (*srv)->track_traffic(relay::TrafficProtocol::socks5, relay::ConnectPath::tunnel, {}, 443, true);
        s2.traffic = (*srv)->track_traffic(relay::TrafficProtocol::socks5, relay::ConnectPath::tunnel, {}, 443, true);
        s3.traffic = (*srv)->track_traffic(relay::TrafficProtocol::socks5, relay::ConnectPath::tunnel, {}, 443, true);
        s4.traffic = (*srv)->track_traffic(relay::TrafficProtocol::socks5, relay::ConnectPath::tunnel, {}, 443, true);
        s1.set_traffic_group("auto"); s1.record_traffic_route({relay::TrafficRouteMode::indexed, 2, {}, {}, {}}, relay::ConnectPath::tunnel);
        s2.set_traffic_group("man");  s2.record_traffic_route({relay::TrafficRouteMode::indexed, 2, {}, {}, {}}, relay::ConnectPath::tunnel);
        s3.set_traffic_group("auto"); s3.record_traffic_route({relay::TrafficRouteMode::indexed, 3, {}, {}, {}}, relay::ConnectPath::tunnel);
        s4.record_traffic_route({relay::TrafficRouteMode::indexed, 2, {}, {}, {}}, relay::ConnectPath::tunnel);
        auto tsnap = (*srv)->traffic_snapshot();
        require(tsnap.active.size() == 4 && std::ranges::any_of(tsnap.active, [](auto const& c) { return c.group_tag == "auto"; }),
            "30B TrafficSnapshot carries group_tag");
        auto closed = (*srv)->close_group_sessions("auto", std::size_t{2});
        require(closed == 1 && s1.traffic.close_requested() && !s2.traffic.close_requested() &&
            !s3.traffic.close_requested() && !s4.traffic.close_requested(),
            "30B close_group_sessions closes only matching (group_tag, outbound) and skips untagged sessions");
        for (int i = 0; i < 16; ++i)
            require((*srv)->queue_outbound_probe(std::make_shared<relay::OutboundProbe>()), "30B Server queues up to 16 concurrent probes");
        require(!(*srv)->queue_outbound_probe(std::make_shared<relay::OutboundProbe>()), "30B Server bounds concurrent probe queue at 16");

        // 6. GroupTagMap + find_process propagation
        auto gtag = cli::run_detail::build_group_tag_map(cfg);
        require(gtag && gtag->default_group == std::size_t{1} && gtag->name(1) == "auto", "30B GroupTagMap maps default group");
        relay::Session p(io), c(io);
        p.find_process = true; p.group_hooks = &hooks; p.group_tag = "auto";
        relay::init_multiplexed_child(c, p, Clock::now() + std::chrono::seconds(5));
        require(c.find_process && c.group_hooks == &hooks && c.group_tag == "auto", "30B child inherits find_process & group hooks");
    }
}

int main() {
    test_system_proxy();
    test_service_manager();
    test_c_api_parity();
    test_batch169_runtime_resilience();
    test_wave30b_groups_and_network();
    std::cout << "BATCH 190 SYSTEM INTEGRATION & WAVE 30B TESTS PASSED\n";
    return 0;
}
