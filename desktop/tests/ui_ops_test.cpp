import std;
import desktop.core_supervisor;
import desktop.http_control;
import desktop.kdl_ops;
import desktop.system_proxy;
import desktop.ui_actions;
import desktop.ui_prefs;
import desktop.window_blur;

#include "../src/speed_wave.hpp"

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto test_inbound_kdl_ops() -> void {
        expect(!desktop::parse_port_u16("0").has_value(), "reject port 0");
        expect(!desktop::parse_port_u16("70000").has_value(), "reject port >65535");
        expect(!desktop::parse_port_u16("80x").has_value(), "reject non-numeric port");
        expect(desktop::parse_port_u16(" 7890 ").value_or(0) == 7890, "parse trimmed port");

        std::string cfg =
            "schema-version 1\n"
            "role \"client\"\n"
            "inbound \"local\" type=\"socks5\" {\n"
            "    listen host=\"127.0.0.1\" port=2080\n"
            "    authentication \"none\"\n"
            "}\n"
            "outbound \"direct\" type=\"direct\"\n"
            "outbound \"proxy\" type=\"selector\" { member \"direct\"; selected \"direct\"; }\n"
            "routing { default-outbound \"proxy\"; }\n";

        auto parsed0 = desktop::parse_inbound_endpoints(cfg);
        expect(!parsed0.mixed.enabled && parsed0.socks5.enabled && parsed0.socks5.port == 2080 && !parsed0.http.enabled,
            "initial socks5-only parse");

        std::string multi = cfg +
            "inbound \"m\" type=\"mixed\" {\n    listen host=\"127.0.0.1\" port=7891\n}\n"
            "inbound \"h\" type=\"http\" {\n    listen host=\"127.0.0.1\" port=8081\n}\n";
        auto parsed1 = desktop::parse_inbound_endpoints(multi);
        expect(parsed1.mixed.enabled && parsed1.mixed.port == 7891 &&
               parsed1.socks5.enabled && parsed1.socks5.port == 2080 &&
               parsed1.http.enabled && parsed1.http.port == 8081,
            "coexisting mixed+socks5+http parsed");

        auto sel1 = desktop::select_system_proxy_endpoint(parsed1);
        expect(sel1.has_value() && sel1->first == "127.0.0.1" && sel1->second == 7891, "prefer mixed for system proxy");

        desktop::CoexistingInbounds http_only = parsed1;
        http_only.mixed.enabled = false;
        auto sel2 = desktop::select_system_proxy_endpoint(http_only);
        expect(sel2.has_value() && sel2->second == 8081, "fallback to http when mixed disabled");

        desktop::CoexistingInbounds wild{};
        wild.http.enabled = true;
        wild.http.host = "0.0.0.0";
        wild.http.port = 8888;
        auto sel_w = desktop::select_system_proxy_endpoint(wild);
        expect(sel_w.has_value() && sel_w->first == "127.0.0.1" && sel_w->second == 8888, "normalize wildcard host");
    }

    auto test_outbound_mode_and_merge() -> void {
        std::string cfg =
            "schema-version 1\n"
            "role \"client\"\n"
            "outbound \"direct\" type=\"direct\"\n"
            "routing { default-outbound \"edge-grp\"; }\n";

        auto merged = desktop::merge_raw_kdl_snippet(cfg, "  outbound \"x\" type=\"direct\"  \n");
        expect(merged.ends_with("outbound \"x\" type=\"direct\"\n"), "clean snippet merge");

        // Route & DNS surgical insertion helpers
        auto r_ins = desktop::insert_route_rule_kdl(cfg, "rule action=\"route\" outbound=\"direct\" {\n    domain-suffix \"example.com\"\n}");
        expect(r_ins.first && r_ins.second.contains("routing {") &&
               r_ins.second.contains("tcp-program sniff-timeout-ms=300 unknown=\"skip\" {") &&
               r_ins.second.contains("domain-suffix \"example.com\""),
            "insert route rule inside routing { tcp-program sniff-timeout-ms=300 unknown=\"skip\" }");
        auto r_ins2 = desktop::insert_route_rule_kdl(r_ins.second, "rule action=\"reject\" {\n    port 25\n}");
        expect(r_ins2.first && r_ins2.second.find("tcp-program") == r_ins2.second.rfind("tcp-program") &&
               r_ins2.second.contains("port 25"), "second route rule reuses existing attributed tcp-program block");
        auto r_fresh = desktop::insert_route_rule_kdl(
            "schema-version 1\nrole \"client\"\n// routing { tcp-program { } }\noutbound \"direct\" type=\"direct\"\n",
            "rule action=\"route\" outbound=\"direct\" {\n    domain-suffix \"fresh.test\"\n}");
        expect(r_fresh.first && r_fresh.second.contains("default-outbound \"direct\"") &&
               r_fresh.second.contains("tcp-program sniff-timeout-ms=300 unknown=\"skip\" {"),
            "fresh routing creation includes default-outbound and valid tcp-program options");

        auto d_ins1 = desktop::insert_dns_rule_kdl(cfg, "rule domain-suffix=\"internal.corp\" action=\"route\" server=\"local\"");
        expect(d_ins1.first && d_ins1.second.contains("dns {") && d_ins1.second.contains("internal.corp"), "create dns block on first rule");
        auto d_ins2 = desktop::insert_dns_rule_kdl(d_ins1.second, "rule domain-suffix=\"ads.test\" action=\"reject\" reject-method=\"reply\"");
        expect(d_ins2.first && d_ins2.second.find("dns {") == d_ins2.second.rfind("dns {") &&
               d_ins2.second.contains("ads.test"), "second dns rule reuses single top-level dns block");
    }

    auto test_ui_prefs_and_locale() -> void {
        auto loc = desktop::detect_system_locale();
        expect(loc == "en-US" || loc == "zh-CN", "system locale normalized");

        desktop::UiPrefs def{};
        expect(std::abs(def.window_opacity - 0.88f) < 0.005f && std::abs(def.surface_opacity - 0.90f) < 0.005f,
            "default frosted opacity matches Theme.slint");

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-ui-prefs-test.conf";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);

        desktop::UiPrefs in{
            .theme_preference = "dark",
            .accent_preset = "violet",
            .material_preset = "crystal",
            .window_opacity = 0.75f,
            .surface_opacity = 0.55f,
            .blur_enabled = true,
            .ambient_glow = false,
            .reduced_motion = true,
            .language = "en-us",
            .outbound_mode = "global",
            .sidebar_width = 212.0f,
            .sidebar_collapsed = true,
        };
        expect(desktop::save_ui_prefs(tmp, in), "save ui prefs");
        auto out = desktop::load_ui_prefs(tmp);
        expect(out.theme_preference == "dark" && out.accent_preset == "violet" && out.material_preset == "crystal",
            "roundtrip enum strings");
        expect(std::abs(out.window_opacity - 0.75f) < 0.02f && std::abs(out.surface_opacity - 0.55f) < 0.02f &&
               out.blur_enabled && !out.ambient_glow && out.reduced_motion,
            "roundtrip sliders");
        expect(out.language == "en-us" && out.outbound_mode == "global" &&
               std::abs(out.sidebar_width - 212.0f) < 0.2f && out.sidebar_collapsed,
            "roundtrip layout and language");
        std::filesystem::remove(tmp, ec);
    }

    auto test_live_coexisting_inbounds_validate() -> void {
        char const* bin = std::getenv("NEXUS_CORE_BIN");
        if (!bin || !*bin) return;

        std::string cfg =
            "schema-version 1\n"
            "role \"client\"\n"
            "inbound \"local-mixed\" type=\"mixed\" { listen host=\"127.0.0.1\" port=17890; authentication \"none\"; }\n"
            "inbound \"local-socks5\" type=\"socks5\" { listen host=\"127.0.0.1\" port=11080; authentication \"none\"; }\n"
            "inbound \"local-http\" type=\"http\" { listen host=\"127.0.0.1\" port=18080; authentication \"none\"; }\n"
            "outbound \"direct\" type=\"direct\"\n"
            "routing { default-outbound \"direct\"; }\n";

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-live-coexist.kdl";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out << cfg;
        }
        desktop::CoreSupervisor sup(bin);
        auto val = sup.validate_config(tmp);
        expect(val.ok, "real nexus validates coexisting mixed+socks5+http inbounds: " + val.message);

        auto with_rule = desktop::insert_route_rule_kdl(cfg, "rule action=\"route\" outbound=\"direct\" {\n    domain-suffix \"example.com\"\n}");
        expect(with_rule.first, "insert valid tcp-program route rule");
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out << with_rule.second;
        }
        auto val_m = sup.validate_config(tmp);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        expect(val_m.ok, "real nexus validates tcp-program rule insertion: " + val_m.message);
    }

    auto test_system_proxy_controller() -> void {
        desktop::SystemProxyController ctrl;
        expect(!ctrl.active(), "system proxy initially inactive");
        expect(!ctrl.diagnostic_mode(), "diagnostic mode initially false");
        ctrl.set_diagnostic_mode(true);
        expect(ctrl.diagnostic_mode(), "diagnostic mode enabled");
        expect(!ctrl.enable("127.0.0.1", 7890), "diagnostic mode blocks proxy mutation");
        expect(!ctrl.active(), "system proxy stays inactive in diagnostic mode");
        expect(ctrl.restore(), "restore is safe no-op when inactive");
        (void)desktop::SystemProxyController::supported();
    }

    auto test_window_blur_helpers() -> void {
        auto s1 = desktop::compute_logical_blur_size(1920, 1280, 2.0f);
        expect(s1.width == 960 && s1.height == 640, "logical blur size divides by scale");
        auto s0 = desktop::compute_logical_blur_size(0, 640, 1.0f);
        expect(s0.width == 0 && s0.height == 0, "zero size stays empty");
        expect(desktop::should_enable_native_blur(true, 0.72f), "frosted blur enables native backdrop");
        expect(!desktop::should_enable_native_blur(false, 0.72f), "disabled blur disables native backdrop");
        expect(!desktop::should_enable_native_blur(true, 1.0f), "opaque window disables native backdrop");

        auto crystal_tmp = std::filesystem::temp_directory_path() / "nexus-desktop-crystal-prefs-test.conf";
        desktop::UiPrefs crystal_in{
            .material_preset = "crystal",
            .window_opacity = 0.20f,
            .surface_opacity = 0.20f,
            .blur_enabled = false,
        };
        expect(desktop::save_ui_prefs(crystal_tmp, crystal_in), "save crystal prefs");
        auto crystal_out = desktop::load_ui_prefs(crystal_tmp);
        std::error_code ec;
        std::filesystem::remove(crystal_tmp, ec);
        expect(std::abs(crystal_out.window_opacity - 0.20f) < 0.02f &&
               std::abs(crystal_out.surface_opacity - 0.20f) < 0.02f &&
               !crystal_out.blur_enabled,
            "crystal low-opacity and blur_enabled roundtrip");

        desktop::WindowBlurController blur;
        expect(!blur.active() && blur.backend_name().empty(), "blur initially detached");
        expect(!blur.attach_wayland(nullptr, nullptr), "null wayland pointers safely rejected");
        expect(!blur.attach_win32(nullptr), "null hwnd safely rejected");
        blur.sync(true, 960, 640, true);
        blur.detach();
        desktop::WindowBlurController moved = std::move(blur);
        expect(!blur.active() && blur.backend_name().empty(), "moved-from WindowBlurController safe");
        blur.sync(true, 960, 640, true);
        blur.detach();
        expect(!moved.active(), "moved-to WindowBlurController initially detached");
        desktop::WindowBlurController target;
        target = std::move(moved);
        expect(!moved.active() && !target.active(), "move-assigned WindowBlurController safe");
    }

    auto test_core_supervisor_lifecycle() -> void {
        char const* bin = std::getenv("NEXUS_CORE_BIN");
        auto missing_cfg = std::filesystem::temp_directory_path() / "nexus-nonexistent-cfg.kdl";
        std::error_code ec;
        std::filesystem::remove(missing_cfg, ec);
        desktop::CoreSupervisor sup_missing(bin && *bin ? bin : "/bin/sh");
        expect(!sup_missing.start(missing_cfg) && !sup_missing.last_error().empty(),
            "missing config rejected cleanly with last_error");

        if (!bin || !*bin) return;
        auto tmp_dir = std::filesystem::temp_directory_path() / "nexus-desktop-supervisor-test";
        std::filesystem::remove_all(tmp_dir, ec);
        std::filesystem::create_directories(tmp_dir, ec);

        auto bad_cfg = tmp_dir / "bad.kdl";
        {
            std::ofstream out(bad_cfg, std::ios::binary | std::ios::trunc);
            out << "invalid-kdl-keyword \"broken\"\n";
        }
        desktop::CoreSupervisor sup(bin);
        expect(!sup.start(bad_cfg) && !sup.running() && !sup.last_error().empty(),
            "invalid config fails start with captured error: " + sup.last_error());

        auto port = static_cast<std::uint16_t>(45000 + (std::chrono::steady_clock::now().time_since_epoch().count() % 10000));
        auto ok_cfg = tmp_dir / "good.kdl";
        {
            std::ofstream out(ok_cfg, std::ios::binary | std::ios::trunc);
            out << std::format(
                "schema-version 1\nrole \"client\"\n"
                "inbound \"local\" type=\"socks5\" {{ listen host=\"127.0.0.1\" port={}; authentication \"none\"; }}\n"
                "outbound \"direct\" type=\"direct\"\n"
                "routing {{ default-outbound \"direct\"; }}\n",
                port);
        }
        expect(sup.start(ok_cfg) && sup.running(), "valid config starts supervisor: " + sup.last_error());
        std::atomic<bool> polling{true};
        std::jthread reader([&] {
            while (polling.load(std::memory_order_acquire)) {
                (void)sup.running();
                (void)sup.last_error();
                std::this_thread::yield();
            }
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        sup.stop();
        polling.store(false, std::memory_order_release);
        reader.join();
        expect(!sup.running(), "supervisor stopped cleanly under concurrent running() polling");
        sup.stop();
        std::filesystem::remove_all(tmp_dir, ec);
    }

    auto test_ui_redesign_actions() -> void {
        // 1. Extract rule predicates from active connections (domain, IPv4, IPv6, port-only)
        auto d1 = desktop::extract_rule_match_from_connection("api.github.com:443", 443, "tcp/tls", "proxy/hk-01");
        expect(d1.kind == "domain-suffix" && d1.value == "api.github.com" && d1.outbound == "direct",
            "domain connection maps to domain-suffix with inverted outbound");
        auto d2 = desktop::extract_rule_match_from_connection("1.1.1.1:443", 443, "udp/quic", "direct");
        expect(d2.kind == "ip-cidr" && d2.value == "1.1.1.1/32" && d2.outbound == "proxy",
            "ipv4 connection maps to /32 ip-cidr and flips direct->proxy");
        auto d2_custom = desktop::extract_rule_match_from_connection("1.1.1.1:443", 443, "udp/quic", "direct", "Auto");
        expect(d2_custom.action == "route" && d2_custom.outbound == "Auto",
            "direct connection uses active group tag as fallback proxy outbound");
        auto d2_direct = desktop::extract_rule_match_from_connection("api.github.com:443", 443, "tcp/tls", "direct", "Auto", "direct");
        expect(d2_direct.action == "route" && d2_direct.outbound == "direct",
            "explicit direct rule action keeps direct outbound");
        auto d2_proxy = desktop::extract_rule_match_from_connection("api.github.com:443", 443, "tcp/tls", "proxy/hk-01", "Auto", "proxy");
        expect(d2_proxy.action == "route" && d2_proxy.outbound == "Auto",
            "explicit proxy rule action targets active proxy group");
        auto d2_reject = desktop::extract_rule_match_from_connection("ads.example.com:443", 443, "tcp/tls", "direct", "Auto", "reject");
        expect(d2_reject.action == "reject" && d2_reject.outbound.empty() && d2_reject.value == "ads.example.com",
            "explicit reject rule action sets reject action with empty outbound");
        auto d3 = desktop::extract_rule_match_from_connection("[2606:4700::1]:443", 443, "tcp", "proxy");
        expect(d3.kind == "ip-cidr" && d3.value == "2606:4700::1/128",
            "ipv6 bracketed connection maps to /128 ip-cidr");
        auto d4 = desktop::extract_rule_match_from_connection("", 8443, "tcp", "");
        expect(d4.kind == "port" && d4.value == "8443" && d4.outbound == "proxy",
            "empty target falls back to port rule");

        // 2. Sort outbound members with pinned favorites always first
        std::vector<desktop::OutboundMemberSnapshot> members = {
            {"us-west", "healthy", 240, false, false},
            {"de-dead", "timeout", -1, false, false},
            {"hk-fast", "healthy", 35, true, false},
            {"jp-mid", "healthy", 110, false, false},
        };
        std::unordered_set<std::string> pins = {"jp-mid"};
        auto by_lat = desktop::sort_outbound_members(members, "latency", pins);
        expect(by_lat.size() == 4 && by_lat[0].name == "jp-mid" && by_lat[1].name == "hk-fast" &&
               by_lat[2].name == "us-west" && by_lat[3].name == "de-dead",
            "latency sort keeps pinned first and timeout last");
        auto by_name = desktop::sort_outbound_members(members, "name", pins);
        expect(by_name[0].name == "jp-mid" && by_name[1].name == "de-dead" && by_name[2].name == "hk-fast",
            "name sort keeps pinned first then alphabetical");

        // 3. Quick-nodes selector (active first -> pinned -> fastest healthy, capped & deduped)
        std::vector<desktop::OutboundMemberSnapshot> more_members = {
            {"us-west", "healthy", 240, false, false},
            {"de-dead", "timeout", -1, false, false},
            {"hk-fast", "healthy", 35, true, false},
            {"jp-mid", "healthy", 110, false, false},
            {"sg-fast", "healthy", 52, false, false},
            {"uk-slow", "healthy", 310, false, false},
            {"kr-good", "healthy", 75, false, false},
        };
        auto picked = desktop::pick_quick_nodes(more_members, pins, 4);
        expect(picked.size() == 4 && picked[0].name == "hk-fast" && picked[1].name == "jp-mid" &&
               picked[2].name == "sg-fast" && picked[3].name == "kr-good",
            "pick_quick_nodes ranks active -> pinned -> fastest healthy and respects cap");

        // 5. Shell proxy export command builder & RFC 3986 host validation
        auto cmd_mixed = desktop::build_proxy_export_command("0.0.0.0", 7890, 7890);
        expect(cmd_mixed == "export http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890 all_proxy=socks5://127.0.0.1:7890",
            "mixed proxy export normalizes wildcard host and sets http/https/all_proxy");
        auto cmd_socks = desktop::build_proxy_export_command("127.0.0.1", 0, 1080);
        expect(cmd_socks == "export all_proxy=socks5://127.0.0.1:1080",
            "socks-only proxy export emits all_proxy");
        auto cmd_http = desktop::build_proxy_export_command("127.0.0.1", 8080, 0);
        expect(cmd_http == "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 all_proxy=http://127.0.0.1:8080",
            "http-only proxy export populates http/https/all_proxy");
        expect(desktop::build_proxy_export_command("127.0.0.1", 0, 0).empty(),
            "disabled ports produce empty proxy export command");
        auto cmd_ipv6 = desktop::build_proxy_export_command(" ::1 ", 7890, 7890);
        expect(cmd_ipv6 == "export http_proxy=http://[::1]:7890 https_proxy=http://[::1]:7890 all_proxy=socks5://[::1]:7890",
            "bare ipv6 host is trimmed and bracketed in proxy export");
        auto cmd_split = desktop::build_proxy_export_command("127.0.0.1", 8080, 1080, "2001:db8::1");
        expect(cmd_split == "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 all_proxy=socks5://[2001:db8::1]:1080",
            "distinct http and ipv6 socks hosts are preserved independently");
        expect(desktop::build_proxy_export_command("127.0.0.1; rm -rf /", 7890, 7890).empty(),
            "semicolon/space shell metacharacters rejected in proxy export");
        expect(desktop::build_proxy_export_command("$(whoami)", 7890, 0).empty(),
            "command substitution rejected in proxy export");
        expect(desktop::build_proxy_export_command("`id`", 0, 1080).empty(),
            "backticks rejected in proxy export");
        expect(desktop::build_proxy_export_command("127.0.0.1\"'|", 7890, 0).empty(),
            "quotes and pipe rejected in proxy export");
        expect(desktop::build_proxy_export_command("[::1", 7890, 0).empty() &&
               desktop::build_proxy_export_command("[127.0.0.1]", 7890, 0).empty(),
            "malformed bracketed hosts rejected in proxy export");
        expect(desktop::format_host_port("::1", "7890") == "[::1]:7890" &&
               desktop::format_host_port("2001:db8::2", "1080") == "[2001:db8::2]:1080" &&
               desktop::format_host_port("0.0.0.0", "7890") == "127.0.0.1:7890" &&
               desktop::format_host_port("bad;host", "7890").empty(),
            "format_host_port brackets ipv6 and rejects unsafe hosts");
    }

    auto test_speed_wave_paths() -> void {
        // 1. Split rate parts formatting
        auto r0 = desktop_ui_helpers::split_rate_parts(0.0);
        auto r1 = desktop_ui_helpers::split_rate_parts(512.4);
        auto r2 = desktop_ui_helpers::split_rate_parts(2048.0);
        expect(r0.value == "0.0" && r0.unit == "KB/s" && r1.value == "512.4" && r1.unit == "KB/s" &&
               r2.value == "2.0" && r2.unit == "MB/s",
            "split_rate_parts formats KB/s and MB/s cleanly");

        // 2. Idle samples remain strictly on baseline y=80.0 and close area cleanly
        std::vector<double> idle(24, 0.0);
        auto w_idle = desktop_ui_helpers::build_speed_wave_paths(idle, 24, 8.0, 240.0, 80.0);
        expect(w_idle.line_cmd.starts_with("M 0.0 80.0 C ") &&
               w_idle.area_cmd.ends_with(" L 240.0 84.0 L 0.0 84.0 Z"),
            "idle wave starts on baseline y=80.0 and closes area cleanly");
        expect(!w_idle.line_cmd.contains(" -"), "idle wave has no negative coordinates");

        // 3. Spiky samples + NaN/negative inputs: clamped non-negative Bezier control points + top headroom
        std::vector<double> spiky = {0.0, -10.0, std::numeric_limits<double>::quiet_NaN(), 500.0, 0.0, 1400.0, 40.0, 0.0, 900.0};
        auto w_spike = desktop_ui_helpers::build_speed_wave_paths(spiky, 24, 8.0, 240.0, 80.0);
        expect(w_spike.line_cmd.starts_with("M 0.0 "), "spiky wave starts with SVG M command");
        std::size_t c_count = 0;
        std::istringstream iss(w_spike.line_cmd);
        std::string tok;
        double min_y = 999.0, max_y = -999.0;
        while (iss >> tok) {
            if (tok == "M") {
                double x = 0.0, y = 0.0;
                expect(static_cast<bool>(iss >> x >> y), "M has x y");
                min_y = std::min(min_y, y); max_y = std::max(max_y, y);
            } else if (tok == "C") {
                double cx1 = 0.0, cy1 = 0.0, cx2 = 0.0, cy2 = 0.0, x1 = 0.0, y1 = 0.0;
                expect(static_cast<bool>(iss >> cx1 >> cy1 >> cx2 >> cy2 >> x1 >> y1), "C has 6 coords");
                ++c_count;
                for (double y : {cy1, cy2, y1}) {
                    min_y = std::min(min_y, y); max_y = std::max(max_y, y);
                }
            }
        }
        expect(c_count == 23, "capacity=24 wave emits exactly 23 cubic Bezier segments");
        expect(min_y >= 2.0 && max_y <= 80.0, "clamped Catmull-Rom Bezier keeps headroom >=2.0 and never dips below y=80.0");
        expect(min_y < 40.0, "spiky wave actually rises visibly above baseline");
    }

    auto test_dash_layout_reorder_and_prefs() -> void {
        std::array<int, 4> ord{0, 1, 2, 3};
        expect(desktop::reorder_dash_slots(ord, 0, 2) && ord == std::array<int, 4>{1, 2, 0, 3}, "forward reorder 0->2");
        expect(desktop::reorder_dash_slots(ord, 3, 1) && ord == std::array<int, 4>{3, 1, 2, 0}, "backward reorder 3->1");
        expect(!desktop::reorder_dash_slots(ord, 2, 2), "no-op same id");
        expect(!desktop::reorder_dash_slots(ord, -1, 2) && !desktop::reorder_dash_slots(ord, 0, 4), "out-of-range rejected");
        expect(ord == std::array<int, 4>{3, 1, 2, 0}, "order unchanged after rejected calls");
        expect(desktop::sanitize_dash_order({0, 0, 1, 2}) == std::array<int, 4>{0, 1, 2, 3}, "duplicate order sanitized");

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-dash-layout-test.conf";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        desktop::UiPrefs in{};
        in.dash_section_order = {3, 0, 2, 1};
        in.dash_info_order = {2, 3, 0, 1};
        in.dash_deck_swapped = true;
        expect(desktop::save_ui_prefs(tmp, in), "save custom dash layout");
        auto out = desktop::load_ui_prefs(tmp);
        expect(out.dash_section_order == std::array<int, 4>{3, 0, 2, 1} &&
               out.dash_info_order == std::array<int, 4>{2, 3, 0, 1} && out.dash_deck_swapped,
            "roundtrip custom dash section/info order and deck swap");

        {
            std::ofstream bad(tmp, std::ios::binary | std::ios::trunc);
            bad << "dash_section_order=0,0,1,2\ndash_info_order=0,1,2,9\ndash_deck_swapped=false\n";
        }
        auto rec = desktop::load_ui_prefs(tmp);
        std::filesystem::remove(tmp, ec);
        expect(rec.dash_section_order == std::array<int, 4>{0, 1, 2, 3} &&
               rec.dash_info_order == std::array<int, 4>{0, 1, 2, 3} && !rec.dash_deck_swapped,
            "corrupt/duplicate dash orders recover to {0,1,2,3}");
    }
}

auto main() -> int {
    try {
        test_inbound_kdl_ops();
        test_outbound_mode_and_merge();
        test_ui_prefs_and_locale();
        test_live_coexisting_inbounds_validate();
        test_system_proxy_controller();
        test_window_blur_helpers();
        test_core_supervisor_lifecycle();
        test_ui_redesign_actions();
        test_speed_wave_paths();
        test_dash_layout_reorder_and_prefs();
        std::println("nexus-desktop-ui-ops-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
