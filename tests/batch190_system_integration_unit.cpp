#include "../include/nexus/core_c_api.h"
#include <cassert>
#include <unistd.h>

import std;
import corosio;
import logging;
import logging.cli;
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
            "inbound \"s\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }\n"
            "outbound \"direct\" type=\"direct\"\n"
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
}

int main() {
    test_system_proxy();
    test_service_manager();
    test_c_api_parity();
    test_batch169_runtime_resilience();
    std::cout << "BATCH 190 SYSTEM INTEGRATION & PACKAGING TESTS PASSED\n";
    return 0;
}
