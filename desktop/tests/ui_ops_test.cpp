import std;
import desktop.core_supervisor;
import desktop.http_control;
import desktop.system_proxy;
import desktop.ui_actions;
import desktop.ui_prefs;
import desktop.window_blur;

#include "../src/speed_wave.hpp"
#include "../src/flagship_helpers.hpp"

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto test_inbound_port_and_endpoint_selection() -> void {
        expect(!desktop::parse_port_u16("0").has_value(), "reject port 0");
        expect(!desktop::parse_port_u16("70000").has_value(), "reject port >65535");
        expect(!desktop::parse_port_u16("80x").has_value(), "reject non-numeric port");
        expect(desktop::parse_port_u16(" 7890 ").value_or(0) == 7890, "parse trimmed port");

        desktop::CoexistingInbounds multi{};
        multi.mixed = {true, "127.0.0.1", 7891};
        multi.socks5 = {true, "127.0.0.1", 2080};
        multi.http = {true, "127.0.0.1", 8081};

        auto sel1 = desktop::select_system_proxy_endpoint(multi);
        expect(sel1.has_value() && sel1->first == "127.0.0.1" && sel1->second == 7891, "prefer mixed for system proxy");

        desktop::CoexistingInbounds http_only = multi;
        http_only.mixed.enabled = false;
        auto sel2 = desktop::select_system_proxy_endpoint(http_only);
        expect(sel2.has_value() && sel2->second == 8081, "fallback to http when mixed disabled");

        desktop::CoexistingInbounds socks_only = http_only;
        socks_only.http.enabled = false;
        auto sel3 = desktop::select_system_proxy_endpoint(socks_only);
        expect(sel3.has_value() && sel3->second == 2080, "fallback to socks5 when mixed & http disabled");

        desktop::CoexistingInbounds wild{};
        wild.http.enabled = true;
        wild.http.host = "0.0.0.0";
        wild.http.port = 8888;
        auto sel_w = desktop::select_system_proxy_endpoint(wild);
        expect(sel_w.has_value() && sel_w->first == "127.0.0.1" && sel_w->second == 8888, "normalize wildcard host");
    }

    auto test_ui_prefs_and_locale() -> void {
        auto loc = desktop::detect_system_locale();
        expect(loc == "en-US" || loc == "zh-CN", "system locale normalized");

        desktop::UiPrefs def{};
        expect(std::abs(def.window_opacity - 0.88f) < 0.005f,
            "default window opacity matches Theme.slint");

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-ui-prefs-test.conf";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);

        desktop::UiPrefs in{
            .theme_preference = "dark",
            .accent_preset = "violet",
            .window_opacity = 0.75f,
            .blur_enabled = true,
            .language = "en-us",
            .outbound_mode = "global",
            .sidebar_width = 212.0f,
            .sidebar_collapsed = true,
        };
        expect(desktop::save_ui_prefs(tmp, in), "save ui prefs");
        auto out = desktop::load_ui_prefs(tmp);
        expect(out.theme_preference == "obsidian" && out.accent_preset == "violet",
            "legacy dark migrates to obsidian and preserves accent");
        expect(std::abs(out.window_opacity - 0.75f) < 0.02f && out.blur_enabled,
            "roundtrip opacity and blur");
        expect(out.language == "en-us" && out.outbound_mode == "global" &&
               std::abs(out.sidebar_width - 212.0f) < 0.2f && out.sidebar_collapsed,
            "roundtrip layout and language");

        // Verify legacy removed keys in existing user configs are safely ignored
        {
            std::ofstream leg(tmp, std::ios::binary | std::ios::trunc);
            leg << "theme=light\nmaterial=crystal\nsurface_opacity=0.55\nambient_glow=false\n"
                   "reduced_motion=true\ndash_section_order=3,0,2,1\ndash_deck_swapped=true\n";
        }
        expect(desktop::load_ui_prefs(tmp).theme_preference == "paper", "legacy light migrates to paper and ignores removed keys");
        in.theme_preference = "amber";
        expect(desktop::save_ui_prefs(tmp, in) && desktop::load_ui_prefs(tmp).theme_preference == "amber",
            "studio amber preset roundtrips cleanly");
        auto j_leg = desktop::ui_prefs_from_json(R"({"theme":"dark","material":"crystal","dash_deck_swapped":true})");
        auto j_amb = desktop::ui_prefs_from_json(R"({"theme":"studio_amber"})");
        auto j_bad = desktop::ui_prefs_from_json(R"({"theme":"invalid"})");
        expect(j_leg && j_leg->theme_preference == "obsidian" &&
               j_amb && j_amb->theme_preference == "amber" &&
               j_bad && j_bad->theme_preference == "system",
            "JSON ui_prefs migrates legacy dark/studio_amber, ignores removed keys, and sanitizes invalid themes");
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
            "routing { final \"direct\"; }\n";

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-live-coexist.kdl";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out << cfg;
        }
        desktop::CoreSupervisor sup(bin);
        auto val = sup.validate_config(tmp);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        expect(val.ok, "real nexus validates coexisting mixed+socks5+http inbounds: " + val.message);
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

        auto low_tmp = std::filesystem::temp_directory_path() / "nexus-desktop-low-opacity-prefs-test.conf";
        desktop::UiPrefs low_in{
            .window_opacity = 0.20f,
            .blur_enabled = false,
        };
        expect(desktop::save_ui_prefs(low_tmp, low_in), "save low-opacity prefs");
        auto low_out = desktop::load_ui_prefs(low_tmp);
        std::error_code ec;
        std::filesystem::remove(low_tmp, ec);
        expect(std::abs(low_out.window_opacity - 0.40f) < 0.02f && !low_out.blur_enabled,
            "window_opacity clamps to 0.40 floor and blur_enabled roundtrips");

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
                "routing {{ final \"direct\"; }}\n",
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

    auto test_wave35_flagship_helpers() -> void {
        // 1. Dual-track wave paths share Y scale and emit pre-segmented dashed TX
        std::vector<double> rx = {10.0, 40.0, 220.0, 640.0, 380.0, 920.0, 500.0};
        std::vector<double> tx = {5.0, 20.0, 80.0, 140.0, 90.0, 210.0, 110.0};
        auto dual = desktop_ui_helpers::build_dual_speed_wave_paths(rx, tx, 24, 8.0, 560.0, 56.0);
        expect(dual.rx_line.starts_with("M 0.0 ") && dual.rx_area.ends_with(" L 560.0 60.0 L 0.0 60.0 Z"),
            "dual wave emits valid RX Bezier + area closing at y=60");
        expect(dual.scale_top_kib > 200.0, "dual wave shared scale reflects RX peak");
        expect(dual.tx_dashed_line.starts_with("M ") && dual.tx_dashed_line.contains(" L "),
            "dual wave emits pre-segmented dashed TX SVG commands");
        std::size_t dash_moves = 0;
        for (std::size_t p = 0; (p = dual.tx_dashed_line.find("M ", p)) != std::string::npos; p += 2) ++dash_moves;
        expect(dash_moves >= 15, "dashed TX produces >= 15 distinct dash segments across 320px");
        expect(!dual.tx_dashed_line.contains(" -"), "dashed TX has no negative coordinates");

        // 2. Onset marker tracker advances linearly and expires after 24 ticks
        desktop_ui_helpers::OnsetMarkerTracker onset;
        expect(!onset.active() && onset.ratio(24) < 0.0f, "onset starts inactive");
        onset.mark("HK-Edge-01");
        expect(onset.active() && std::abs(onset.ratio(24) - 1.0f) < 1e-4f, "fresh onset sits at rightmost slot (1.0)");
        for (int i = 0; i < 12; ++i) onset.advance(24);
        expect(onset.active() && onset.ratio(24) > 0.4f && onset.ratio(24) < 0.55f, "onset shifts left across 24-slot window");
        for (int i = 0; i < 12; ++i) onset.advance(24);
        expect(!onset.active() && onset.ratio(24) < 0.0f, "onset expires cleanly after slot 23");

        // 3. GroupLatencySpectrum 5-tier buckets + P50 median + max_ms
        std::vector<desktop::OutboundMemberSnapshot> members = {
            {.name = "n1", .state = "healthy", .latency_ms = 30},
            {.name = "n2", .state = "healthy", .latency_ms = 120},
            {.name = "n3", .state = "healthy", .latency_ms = 240},
            {.name = "n4", .state = "healthy", .latency_ms = 420},
            {.name = "n5", .state = "timeout", .latency_ms = 0},
        };
        auto spec = desktop_ui_helpers::compute_group_latency_spectrum(members);
        expect(spec.has_data && spec.p50_ms == 180 && spec.max_ms == 420,
            "even healthy count computes exact median (120+240)/2=180 and max=420");
        float sum = spec.fast_ratio + spec.good_ratio + spec.mid_ratio + spec.slow_ratio + spec.timeout_ratio;
        expect(std::abs(sum - 1.0f) < 1e-4f && std::abs(spec.fast_ratio - 0.2f) < 1e-4f && std::abs(spec.timeout_ratio - 0.2f) < 1e-4f,
            "5-tier spectrum buckets partition counted nodes cleanly");

        // 4. Command palette domain detection, fuzzy scorer, explain parser & FakeIP detector
        expect(desktop_ui_helpers::looks_like_domain_query("api.github.com") &&
               desktop_ui_helpers::looks_like_domain_query("https://example.org:443/path") &&
               !desktop_ui_helpers::looks_like_domain_query("> tun") &&
               !desktop_ui_helpers::looks_like_domain_query("hk edge"),
            "looks_like_domain_query accepts host/URL and rejects commands or spaced text");
        expect(desktop_ui_helpers::normalize_domain_candidate("HTTPS://API.GitHub.com:443/v1") == "api.github.com",
            "normalize_domain_candidate strips scheme/port/path and lowercases");
        expect(desktop_ui_helpers::palette_fuzzy_score("hk01", "HK-Edge-01") > 0 &&
               desktop_ui_helpers::palette_fuzzy_score("HK-Edge-01", "HK-Edge-01") >
               desktop_ui_helpers::palette_fuzzy_score("hk01", "HK-Edge-01") &&
               desktop_ui_helpers::palette_fuzzy_score("zzz", "HK-Edge-01") < 0,
            "palette_fuzzy_score ranks exact > subsequence and rejects non-matches");
        auto ex = desktop_ui_helpers::parse_explain_summary("matched-rule: geosite-dev\noutbound: HK-Edge-01\n");
        expect(ex.rule == "geosite-dev" && ex.outbound == "HK-Edge-01", "parse_explain_summary extracts rule and outbound");
        expect(desktop_ui_helpers::is_fakeip_address("198.18.0.42") && !desktop_ui_helpers::is_fakeip_address("1.1.1.1"),
            "is_fakeip_address identifies RFC2544 FakeIP pool");

        // 5. UTF-8-safe CJK truncation (never splits multi-byte codepoints)
        desktop_ui_helpers::OnsetMarkerTracker cjk_onset;
        cjk_onset.mark("香港-高速专线-01");
        expect(cjk_onset.label == "香港-高速" && cjk_onset.label.size() <= 14,
            "OnsetMarkerTracker::mark truncates CJK labels at valid UTF-8 boundaries");
        auto ex_cjk = desktop_ui_helpers::parse_explain_summary("香港高速专线节点规则匹配演示超长文本测试截断逻辑验证");
        expect(ex_cjk.rule.size() <= 48 && ex_cjk.rule.size() % 3 == 0,
            "parse_explain_summary truncates CJK fallback lines at valid UTF-8 boundaries");
    }
}

auto main() -> int {
    try {
        test_inbound_port_and_endpoint_selection();
        test_ui_prefs_and_locale();
        test_live_coexisting_inbounds_validate();
        test_system_proxy_controller();
        test_window_blur_helpers();
        test_core_supervisor_lifecycle();
        test_ui_redesign_actions();
        test_speed_wave_paths();
        test_wave35_flagship_helpers();
        std::println("nexus-desktop-ui-ops-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
