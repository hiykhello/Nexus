#include <stdlib.h>

import std;
import desktop.core_supervisor;
import desktop.tray_controller;
import desktop.ui_prefs;

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto set_env_var(char const* key, char const* val) -> void {
#ifdef _WIN32
        (void)_putenv_s(key, val);
#else
        (void)::setenv(key, val, 1);
#endif
    }

    auto find_by_label(std::vector<desktop::TrayMenuItem> const& items, std::string_view needle)
        -> desktop::TrayMenuItem const* {
        for (auto const& it : items) {
            if (it.label.contains(needle)) return &it;
            if (auto const* child = find_by_label(it.children, needle)) return child;
        }
        return nullptr;
    }

    auto collect_ids_and_check_no_jargon(
        std::vector<desktop::TrayMenuItem> const& items,
        std::unordered_set<std::int32_t>& ids) -> void {
        for (auto const& it : items) {
            expect(it.id > 0, "every menu item id must be strictly positive");
            expect(ids.insert(it.id).second, "every menu item id must be unique across tree");
            expect(!it.label.contains("增强") && !it.label.contains("Enhanced") && !it.label.contains("VpnService"),
                "tray menu must use TUN wording instead of Enhanced/VpnService: " + it.label);
            collect_ids_and_check_no_jargon(it.children, ids);
        }
    }

    auto make_rich_snapshot(bool is_en = false) -> desktop::TraySnapshot {
        desktop::TraySnapshot s{};
        s.state = desktop::TrayState::running;
        s.core_running = true;
        s.window_visible = true;
        s.system_proxy_enabled = true;
        s.tun_enabled = false;
        s.is_en = is_en;
        s.show_nodes = true;
        s.show_speed = true;
        s.click_action = "toggle";
        s.outbound_mode = "rule";
        s.active_group = "Auto";
        s.active_node = "hk-edge-01";
        s.active_latency = "36ms";
        s.download_rate = "12.4 MB/s";
        s.upload_rate = "1.2 MB/s";
        s.proxy_export_cmd = "export http_proxy=http://127.0.0.1:7890";
        s.quick_nodes = {
            {.group = "Auto", .name = "hk-edge-01", .latency_label = "36ms", .active = true},
            {.group = "Auto", .name = "jp-tokyo-02", .latency_label = "58ms", .active = false},
            {.group = "", .name = "sg-core-03", .latency_label = "49ms", .active = false},
        };
        s.profiles = {
            {.id = "default", .name = "Default", .active = true},
            {.id = "work", .name = "Work VPN", .active = false},
        };
        return s;
    }

    auto test_format_tray_tooltip() -> void {
        desktop::TraySnapshot off{};
        expect(desktop::format_tray_tooltip(off) == "Nexus · 未连接", "zh offline tooltip");
        off.is_en = true;
        expect(desktop::format_tray_tooltip(off) == "Nexus · Disconnected", "en offline tooltip");

        auto run_zh = make_rich_snapshot(false);
        auto tip_zh = desktop::format_tray_tooltip(run_zh);
        expect(tip_zh == "Nexus · 已连接 · hk-edge-01 (36ms)\n↓ 12.4 MB/s · ↑ 1.2 MB/s",
            "zh running tooltip with speed");

        run_zh.show_speed = false;
        expect(desktop::format_tray_tooltip(run_zh) == "Nexus · 已连接 · hk-edge-01 (36ms)",
            "show_speed=false hides speed line");

        auto tun_zh = make_rich_snapshot(false);
        tun_zh.state = desktop::TrayState::tun_active;
        tun_zh.tun_enabled = true;
        auto tip_tun = desktop::format_tray_tooltip(tun_zh);
        expect(tip_tun.contains("TUN 运行中") && !tip_tun.contains("增强"),
            "zh TUN tooltip uses 'TUN 运行中' with zero '增强'");

        auto tun_en = make_rich_snapshot(true);
        tun_en.state = desktop::TrayState::tun_active;
        tun_en.tun_enabled = true;
        auto tip_tun_en = desktop::format_tray_tooltip(tun_en);
        expect(tip_tun_en.contains("TUN Active") && !tip_tun_en.contains("Enhanced"),
            "en TUN tooltip uses 'TUN Active' with zero 'Enhanced'");

        auto deg_en = make_rich_snapshot(true);
        deg_en.state = desktop::TrayState::degraded;
        deg_en.active_latency.clear();
        deg_en.download_rate.clear();
        deg_en.upload_rate.clear();
        expect(desktop::format_tray_tooltip(deg_en) == "Nexus · Degraded · hk-edge-01",
            "en degraded tooltip without empty latency/speed");
    }

    auto test_build_tray_menu() -> void {
        auto snap = make_rich_snapshot(false);
        auto menu = desktop::build_tray_menu(snap);
        std::unordered_set<std::int32_t> ids;
        collect_ids_and_check_no_jargon(menu, ids);

        expect(menu.size() >= 12, "rich tray menu has all sections");
        expect(menu[0].kind == desktop::TrayMenuKind::header && !menu[0].enabled &&
               menu[0].label == "Nexus · 已连接 · hk-edge-01 (36ms)", "disabled status header");
        expect(menu[1].kind == desktop::TrayMenuKind::header && !menu[1].enabled &&
               menu[1].label == "↓ 12.4 MB/s · ↑ 1.2 MB/s", "disabled speed header");

        auto const* hide_it = find_by_label(menu, "隐藏主窗口");
        auto const* stop_it = find_by_label(menu, "停止连接");
        auto const* proxy_it = find_by_label(menu, "系统代理");
        auto const* tun_it = find_by_label(menu, "TUN 模式");
        auto const* mode_sub = find_by_label(menu, "分流模式");
        auto const* node_sub = find_by_label(menu, "快捷切换节点");
        auto const* prof_sub = find_by_label(menu, "配置档案");
        auto const* copy_it = find_by_label(menu, "复制终端代理");
        auto const* quit_it = find_by_label(menu, "退出 Nexus");
        expect(hide_it && stop_it && proxy_it && tun_it && mode_sub && node_sub && prof_sub && copy_it && quit_it,
            "all expected zh-CN tray items present");
        expect(proxy_it->kind == desktop::TrayMenuKind::checkbox && proxy_it->checked, "system proxy checked");
        expect(tun_it->kind == desktop::TrayMenuKind::checkbox && !tun_it->checked, "TUN mode unchecked");
        expect(mode_sub->children.size() == 3 && mode_sub->children[0].checked &&
               !mode_sub->children[1].checked && !mode_sub->children[2].checked, "rule radio checked");
        expect(node_sub->children.size() == 3 && node_sub->children[0].label == "hk-edge-01  36ms" &&
               node_sub->children[0].checked && !node_sub->children[1].checked, "quick nodes submenu");
        expect(prof_sub->children.size() == 2 && prof_sub->children[0].checked &&
               !prof_sub->children[1].checked, "profiles submenu");
        expect(copy_it->enabled, "copy proxy enabled when command present");

        // Cap at 8 quick nodes, hide profiles when <= 1, disable copy when cmd empty, flip visibility/core & en-US
        desktop::TraySnapshot en_snap = make_rich_snapshot(true);
        en_snap.window_visible = false;
        en_snap.core_running = false;
        en_snap.state = desktop::TrayState::offline;
        en_snap.outbound_mode = "global";
        en_snap.proxy_export_cmd.clear();
        en_snap.profiles.resize(1);
        en_snap.quick_nodes.clear();
        for (int i = 0; i < 12; ++i) {
            en_snap.quick_nodes.push_back({.group = "Auto", .name = std::format("node-{:02d}", i), .latency_label = "20ms", .active = (i == 0)});
        }
        auto en_menu = desktop::build_tray_menu(en_snap);
        std::unordered_set<std::int32_t> en_ids;
        collect_ids_and_check_no_jargon(en_menu, en_ids);
        expect(find_by_label(en_menu, "Show Window") != nullptr, "en Show Window when hidden");
        expect(find_by_label(en_menu, "Connect") != nullptr, "en Connect when offline");
        expect(find_by_label(en_menu, "TUN Mode") != nullptr, "en TUN Mode checkbox label");
        expect(find_by_label(en_menu, "↓") == nullptr, "speed header omitted when core offline");
        expect(find_by_label(en_menu, "Profiles") == nullptr, "profiles submenu omitted when <= 1 profile");
        auto const* en_copy = find_by_label(en_menu, "Copy Proxy Env");
        expect(en_copy && !en_copy->enabled, "copy proxy disabled when command empty");
        auto const* en_modes = find_by_label(en_menu, "Routing Mode");
        expect(en_modes && en_modes->children[1].checked, "global radio checked");
        auto const* en_nodes = find_by_label(en_menu, "Quick Nodes");
        expect(en_nodes && en_nodes->children.size() == 8, "quick nodes capped at 8");

        en_snap.show_nodes = false;
        auto hidden_nodes_menu = desktop::build_tray_menu(en_snap);
        expect(find_by_label(hidden_nodes_menu, "Quick Nodes") == nullptr, "show_nodes=false omits Quick Nodes submenu");
    }

    auto test_dispatch_and_clicks() -> void {
        int show_cnt = 0, toggle_win_cnt = 0, toggle_core_cnt = 0, probe_cnt = 0, copy_cnt = 0, reload_cnt = 0, quit_cnt = 0;
        std::string switched_mode, selected_group, selected_node, activated_profile;
        std::vector<bool> proxy_toggles, tun_toggles;

        desktop::TrayController tray({
            .on_show = [&] { ++show_cnt; },
            .on_toggle_window = [&] { ++toggle_win_cnt; },
            .on_toggle_core = [&] { ++toggle_core_cnt; },
            .on_switch_mode = [&](std::string m) { switched_mode = std::move(m); },
            .on_toggle_system_proxy = [&](bool on) { proxy_toggles.push_back(on); },
            .on_toggle_tun = [&](bool on) { tun_toggles.push_back(on); },
            .on_select_node = [&](std::string g, std::string n) { selected_group = std::move(g); selected_node = std::move(n); },
            .on_activate_profile = [&](std::string id) { activated_profile = std::move(id); },
            .on_probe_active_group = [&] { ++probe_cnt; },
            .on_copy_proxy_env = [&] { ++copy_cnt; },
            .on_reload = [&] { ++reload_cnt; },
            .on_quit = [&] { ++quit_cnt; },
        });
        expect(!tray.native_backend_active(), "native backend disabled under NEXUS_DISABLE_NATIVE_TRAY=1");

        auto snap = make_rich_snapshot(false);
        tray.update_snapshot(snap);
        expect(tray.state() == desktop::TrayState::running, "snapshot updates state");
        expect(tray.snapshot().active_node == "hk-edge-01", "snapshot getter returns latest snapshot");

        auto menu = tray.menu_items();
        expect(tray.dispatch_menu_id(find_by_label(menu, "隐藏主窗口")->id) && toggle_win_cnt == 1, "dispatch toggle window");
        expect(tray.dispatch_menu_id(find_by_label(menu, "停止连接")->id) && toggle_core_cnt == 1, "dispatch toggle core");
        expect(tray.dispatch_menu_id(find_by_label(menu, "系统代理")->id) && proxy_toggles.size() == 1 && !proxy_toggles.back(),
            "dispatch system proxy sends inverted bool (true -> false)");
        expect(tray.dispatch_menu_id(find_by_label(menu, "TUN 模式")->id) && tun_toggles.size() == 1 && tun_toggles.back(),
            "dispatch TUN mode sends inverted bool (false -> true)");

        auto const* mode_sub = find_by_label(menu, "分流模式");
        expect(tray.dispatch_menu_id(mode_sub->children[1].id) && switched_mode == "global", "dispatch global mode");
        expect(tray.dispatch_menu_id(mode_sub->children[2].id) && switched_mode == "direct", "dispatch direct mode");
        expect(tray.dispatch_menu_id(mode_sub->children[0].id) && switched_mode == "rule", "dispatch rule mode");

        auto const* node_sub = find_by_label(menu, "快捷切换节点");
        expect(tray.dispatch_menu_id(node_sub->children[1].id) && selected_group == "Auto" && selected_node == "jp-tokyo-02",
            "dispatch quick node selection");
        expect(tray.dispatch_menu_id(node_sub->children[2].id) && selected_group == "Auto" && selected_node == "sg-core-03",
            "empty node group falls back to active_group");

        auto const* prof_sub = find_by_label(menu, "配置档案");
        expect(tray.dispatch_menu_id(prof_sub->children[1].id) && activated_profile == "work",
            "dispatch profile activation");

        expect(tray.dispatch_menu_id(find_by_label(menu, "立即测速")->id) && probe_cnt == 1, "dispatch probe");
        expect(tray.dispatch_menu_id(find_by_label(menu, "复制终端代理")->id) && copy_cnt == 1, "dispatch copy proxy");
        expect(tray.dispatch_menu_id(find_by_label(menu, "重载配置")->id) && reload_cnt == 1, "dispatch reload");

        // Disabled / non-actionable / out-of-range IDs must return false
        expect(!tray.dispatch_menu_id(menu[0].id), "header id not actionable");
        expect(!tray.dispatch_menu_id(mode_sub->id), "submenu container id not actionable");
        expect(!tray.dispatch_menu_id(999999), "unknown menu id rejected");

        // Primary click actions: toggle, show, toggle_proxy + secondary click (middle-click)
        tray.trigger_primary_click();
        expect(toggle_win_cnt == 2, "primary click 'toggle' invokes on_toggle_window");

        snap.click_action = "show";
        snap.proxy_export_cmd.clear();
        tray.update_snapshot(snap);
        tray.trigger_primary_click();
        expect(show_cnt == 1, "primary click 'show' invokes on_show");
        expect(!tray.dispatch_menu_id(find_by_label(menu, "复制终端代理")->id) && copy_cnt == 1,
            "copy proxy ignored when proxy_export_cmd is empty");

        snap.click_action = "toggle_proxy";
        snap.system_proxy_enabled = false;
        tray.update_snapshot(snap);
        tray.trigger_primary_click();
        expect(proxy_toggles.size() == 2 && proxy_toggles.back(), "primary click 'toggle_proxy' toggles system proxy on");

        tray.trigger_secondary_click();
        expect(proxy_toggles.size() == 3 && proxy_toggles.back(), "secondary (middle) click toggles system proxy");

        // Quit is atomic-once
        auto const quit_id = find_by_label(menu, "退出 Nexus")->id;
        expect(tray.dispatch_menu_id(quit_id) && quit_cnt == 1 && tray.quit_requested(), "first quit fires once");
        expect(tray.dispatch_menu_id(quit_id) && quit_cnt == 1, "second quit does not refire callback");

        // Post-stop suppresses all callbacks
        tray.stop();
        tray.stop();
        expect(!tray.dispatch_menu_id(find_by_label(menu, "重载配置")->id) && reload_cnt == 1,
            "dispatch after stop is ignored");
        tray.trigger_primary_click();
        tray.trigger_secondary_click();
        expect(proxy_toggles.size() == 3, "clicks after stop are ignored");
    }

    auto test_ui_prefs_tray_persistence() -> void {
        desktop::UiPrefs def{};
        expect(def.close_to_tray && !def.start_minimized && def.tray_show_nodes &&
               def.tray_show_speed && def.tray_click_action == "toggle",
            "UiPrefs tray defaults match frozen contract");
        expect(def.dash_show_speed && def.dash_show_quick_nodes && def.dash_show_network &&
               def.dash_show_ports && def.dash_show_traffic && def.dash_show_memory,
            "UiPrefs dashboard widget visibility defaults all true");

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-tray-prefs-test.conf";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);

        desktop::UiPrefs custom{};
        custom.close_to_tray = false;
        custom.start_minimized = true;
        custom.tray_show_nodes = false;
        custom.tray_show_speed = false;
        custom.tray_click_action = "toggle_proxy";
        custom.dash_show_speed = false;
        custom.dash_show_quick_nodes = true;
        custom.dash_show_network = false;
        custom.dash_show_ports = false;
        custom.dash_show_traffic = true;
        custom.dash_show_memory = false;
        expect(desktop::save_ui_prefs(tmp, custom), "save tray & dashboard UiPrefs");

        auto loaded = desktop::load_ui_prefs(tmp);
        expect(!loaded.close_to_tray && loaded.start_minimized && !loaded.tray_show_nodes &&
               !loaded.tray_show_speed && loaded.tray_click_action == "toggle_proxy",
            "roundtrip all 5 tray UiPrefs fields");
        expect(!loaded.dash_show_speed && loaded.dash_show_quick_nodes && !loaded.dash_show_network &&
               !loaded.dash_show_ports && loaded.dash_show_traffic && !loaded.dash_show_memory,
            "roundtrip all 6 dashboard widget visibility UiPrefs fields");

        custom.tray_click_action = "show";
        expect(desktop::save_ui_prefs(tmp, custom), "save tray_click_action=show");
        expect(desktop::load_ui_prefs(tmp).tray_click_action == "show", "roundtrip tray_click_action=show");

        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out << "close_to_tray=false\ntray_click_action=invalid_action\n";
        }
        auto sanitized = desktop::load_ui_prefs(tmp);
        expect(!sanitized.close_to_tray && sanitized.tray_click_action == "toggle",
            "invalid tray_click_action falls back to 'toggle'");
        std::filesystem::remove(tmp, ec);
    }

    auto test_tray_lifecycle_and_move() -> void {
        int show_cnt = 0;
        desktop::TrayController a({.on_show = [&] { ++show_cnt; }});
        a.update_snapshot({.state = desktop::TrayState::tun_active, .core_running = true, .tun_enabled = true});
        expect(a.state() == desktop::TrayState::tun_active && a.tooltip().contains("TUN"),
            "update_snapshot sets state and tooltip cleanly");

        desktop::TrayController b = std::move(a);
        expect(b.state() == desktop::TrayState::tun_active && a.state() == desktop::TrayState::offline,
            "move-constructed TrayController transfers state");
        a.trigger_primary_click();
        a.trigger_show();
        expect(!a.dispatch_menu_id(1001) && show_cnt == 0, "moved-from TrayController is safely inert");

        b.trigger_primary_click();
        expect(show_cnt == 1, "primary click falls back to on_show when on_toggle_window unset");

        desktop::TrayController c;
        c = std::move(b);
        expect(c.state() == desktop::TrayState::tun_active && b.state() == desktop::TrayState::offline,
            "move-assigned TrayController transfers state cleanly");
        c.stop();

        desktop::CoreSupervisor stopped_sup("/nonexistent/nexus-core");
        expect(!stopped_sup.running() && stopped_sup.memory_bytes() == 0,
            "CoreSupervisor::memory_bytes returns 0 when stopped");
#if defined(__linux__) || defined(_WIN32)
        expect(desktop::current_process_memory_bytes() > 0,
            "current_process_memory_bytes reports live positive RSS/working set");
#endif
    }
}

auto main() -> int {
    set_env_var("NEXUS_DISABLE_NATIVE_TRAY", "1");
    try {
        test_format_tray_tooltip();
        test_build_tray_menu();
        test_dispatch_and_clicks();
        test_ui_prefs_tray_persistence();
        test_tray_lifecycle_and_move();
        std::println("nexus-desktop-tray-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
