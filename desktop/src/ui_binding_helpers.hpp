// Slint C++ UI global & inbound synchronization helpers included by desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    template <class Fn>
    inline auto on_ui_thread(slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui, Fn&& fn) -> void {
        slint::invoke_from_event_loop([weak_ui = std::move(weak_ui), fn = std::forward<Fn>(fn)]() mutable {
            if (auto strong = weak_ui.lock()) fn(*strong);
        });
    }

    inline auto is_en_ui(nexus_ui::AppWindow const& ui) -> bool {
        return ui.global<nexus_ui::I18n>().get_is_en();
    }

    inline auto resolve_core_binary(char const* argv0) -> std::filesystem::path {
        if (char const* env_bin = std::getenv("NEXUS_CORE_BIN"); env_bin && *env_bin) {
            return std::filesystem::path(env_bin);
        }
        return std::filesystem::path(argv0).parent_path() /
#ifdef _WIN32
            "nexus.exe";
#else
            "nexus";
#endif
    }

    inline auto make_dash_order_model(std::array<int, 4> o) -> std::shared_ptr<slint::VectorModel<int>> {
        auto s = desktop::sanitize_dash_order(o);
        return std::make_shared<slint::VectorModel<int>>(std::vector<int>(s.begin(), s.end()));
    }
    inline auto read_dash_order_model(std::shared_ptr<slint::Model<int>> const& m) -> std::array<int, 4> {
        std::array<int, 4> out{0, 1, 2, 3};
        if (!m || m->row_count() != 4) return out;
        for (std::size_t i = 0; i < 4; ++i) out[i] = m->row_data(i).value_or(static_cast<int>(i));
        return desktop::sanitize_dash_order(out);
    }

    inline auto apply_prefs_to_ui(nexus_ui::AppWindow& ui, desktop::UiPrefs const& p, std::string const& sys_locale) -> void {
        auto const& i18n = ui.global<nexus_ui::I18n>();
        i18n.set_system_locale(slint::SharedString(sys_locale));
        i18n.set_preference(
            p.language == "zh-cn" ? nexus_ui::LanguagePreference::ZhCn
            : p.language == "en-us" ? nexus_ui::LanguagePreference::EnUs
            : nexus_ui::LanguagePreference::System);

        auto const& theme = ui.global<nexus_ui::Theme>();
        theme.invoke_apply_preference(
            p.theme_preference == "light" ? nexus_ui::ThemePreference::Light
            : p.theme_preference == "dark" ? nexus_ui::ThemePreference::Dark
            : nexus_ui::ThemePreference::System);
        theme.set_accent_preset(
            p.accent_preset == "emerald" ? nexus_ui::AccentPreset::Emerald
            : p.accent_preset == "violet" ? nexus_ui::AccentPreset::Violet
            : p.accent_preset == "amber" ? nexus_ui::AccentPreset::Amber
            : p.accent_preset == "rose" ? nexus_ui::AccentPreset::Rose
            : nexus_ui::AccentPreset::Ocean);
        theme.set_material_preset(
            p.material_preset == "solid" ? nexus_ui::MaterialPreset::Solid
            : p.material_preset == "crystal" ? nexus_ui::MaterialPreset::Crystal
            : nexus_ui::MaterialPreset::Frosted);
        theme.set_window_opacity(p.window_opacity);
        theme.set_surface_opacity(p.surface_opacity);
        theme.set_blur_enabled(p.blur_enabled);
        theme.set_ambient_glow(p.ambient_glow);
        ui.global<nexus_ui::Motion>().set_reduced(p.reduced_motion);

        ui.set_outbound_mode(slint::SharedString(p.outbound_mode));
        ui.set_sidebar_width(p.sidebar_width);
        ui.set_sidebar_collapsed(p.sidebar_collapsed);
        ui.set_close_to_tray(p.close_to_tray);
        ui.set_start_minimized(p.start_minimized);
        ui.set_tray_show_nodes(p.tray_show_nodes);
        ui.set_tray_show_speed(p.tray_show_speed);
        ui.set_tray_click_action(slint::SharedString(p.tray_click_action));
        ui.set_tun_elevate_persistent(p.tun_elevate_persistent);
        ui.set_dash_show_speed(p.dash_show_speed); ui.set_dash_show_quick_nodes(p.dash_show_quick_nodes);
        ui.set_dash_show_network(p.dash_show_network); ui.set_dash_show_ports(p.dash_show_ports);
        ui.set_dash_show_traffic(p.dash_show_traffic); ui.set_dash_show_memory(p.dash_show_memory);
        ui.set_dash_show_connectivity(p.dash_show_connectivity);
        ui.set_dash_section_order(make_dash_order_model(p.dash_section_order)); ui.set_dash_info_order(make_dash_order_model(p.dash_info_order)); ui.set_dash_deck_swapped(p.dash_deck_swapped);
    }

    inline auto capture_prefs_from_ui(nexus_ui::AppWindow const& ui) -> desktop::UiPrefs {
        desktop::UiPrefs p{};
        auto lang = ui.global<nexus_ui::I18n>().get_preference();
        p.language = lang == nexus_ui::LanguagePreference::ZhCn ? "zh-cn" : lang == nexus_ui::LanguagePreference::EnUs ? "en-us" : "system";
        auto const& theme = ui.global<nexus_ui::Theme>();
        auto pref = theme.get_preference();
        p.theme_preference = pref == nexus_ui::ThemePreference::Light ? "light" : pref == nexus_ui::ThemePreference::Dark ? "dark" : "system";
        auto accent = theme.get_accent_preset();
        p.accent_preset = accent == nexus_ui::AccentPreset::Emerald ? "emerald" : accent == nexus_ui::AccentPreset::Violet ? "violet"
            : accent == nexus_ui::AccentPreset::Amber ? "amber" : accent == nexus_ui::AccentPreset::Rose ? "rose" : "ocean";
        auto mat = theme.get_material_preset();
        p.material_preset = mat == nexus_ui::MaterialPreset::Solid ? "solid" : mat == nexus_ui::MaterialPreset::Crystal ? "crystal" : "frosted";
        p.window_opacity = theme.get_window_opacity();
        p.surface_opacity = theme.get_surface_opacity();
        p.blur_enabled = theme.get_blur_enabled();
        p.ambient_glow = theme.get_ambient_glow();
        p.reduced_motion = ui.global<nexus_ui::Motion>().get_reduced();
        p.outbound_mode = std::string(ui.get_outbound_mode());
        p.sidebar_width = ui.get_sidebar_width();
        p.sidebar_collapsed = ui.get_sidebar_collapsed();
        p.close_to_tray = ui.get_close_to_tray();
        p.start_minimized = ui.get_start_minimized();
        p.tray_show_nodes = ui.get_tray_show_nodes();
        p.tray_show_speed = ui.get_tray_show_speed();
        p.tray_click_action = std::string(ui.get_tray_click_action());
        p.tun_elevate_persistent = ui.get_tun_elevate_persistent();
        p.dash_show_speed = ui.get_dash_show_speed(); p.dash_show_quick_nodes = ui.get_dash_show_quick_nodes();
        p.dash_show_network = ui.get_dash_show_network(); p.dash_show_ports = ui.get_dash_show_ports();
        p.dash_show_traffic = ui.get_dash_show_traffic(); p.dash_show_memory = ui.get_dash_show_memory();
        p.dash_show_connectivity = ui.get_dash_show_connectivity();
        p.dash_section_order = read_dash_order_model(ui.get_dash_section_order()); p.dash_info_order = read_dash_order_model(ui.get_dash_info_order()); p.dash_deck_swapped = ui.get_dash_deck_swapped();
        return p;
    }

    inline auto sync_inbounds_to_ui(nexus_ui::AppWindow& ui, desktop::CoexistingInbounds const& inb) -> void {
        ui.set_mixed_proxy_enabled(inb.mixed.enabled);
        ui.set_mixed_proxy_host(slint::SharedString(inb.mixed.host));
        ui.set_mixed_proxy_port(slint::SharedString(std::to_string(inb.mixed.port)));
        ui.set_socks_proxy_enabled(inb.socks5.enabled);
        ui.set_socks_proxy_host(slint::SharedString(inb.socks5.host));
        ui.set_socks_proxy_port(slint::SharedString(std::to_string(inb.socks5.port)));
        ui.set_http_proxy_enabled(inb.http.enabled);
        ui.set_http_proxy_host(slint::SharedString(inb.http.host));
        ui.set_http_proxy_port(slint::SharedString(std::to_string(inb.http.port)));
    }

    inline auto read_inbounds_from_ui(nexus_ui::AppWindow const& ui) -> desktop::CoexistingInbounds {
        desktop::CoexistingInbounds inb;
        inb.mixed.enabled = ui.get_mixed_proxy_enabled();
        inb.mixed.host = std::string(ui.get_mixed_proxy_host());
        inb.mixed.port = desktop::parse_port_u16(std::string_view(ui.get_mixed_proxy_port())).value_or(0);
        inb.socks5.enabled = ui.get_socks_proxy_enabled();
        inb.socks5.host = std::string(ui.get_socks_proxy_host());
        inb.socks5.port = desktop::parse_port_u16(std::string_view(ui.get_socks_proxy_port())).value_or(0);
        inb.http.enabled = ui.get_http_proxy_enabled();
        inb.http.host = std::string(ui.get_http_proxy_host());
        inb.http.port = desktop::parse_port_u16(std::string_view(ui.get_http_proxy_port())).value_or(0);
        return inb;
    }

    inline auto setup_native_window_blur(
        nexus_ui::AppWindow& ui,
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui,
        std::shared_ptr<desktop::WindowBlurController> blur) -> void {
        auto attempted = std::make_shared<bool>(false);
        auto try_attach = [blur, attempted](nexus_ui::AppWindow& win_ui) mutable {
            if (!blur->active() && !*attempted) {
                *attempted = true;
#ifdef _WIN32
                (void)blur->attach_win32(win_ui.window().win32_hwnd());
#elif !defined(__APPLE__)
                (void)blur->attach_wayland(win_ui.window().wayland_display(), win_ui.window().wayland_surface());
#else
                (void)win_ui;
#endif
            }
        };
        (void)ui.window().set_rendering_notifier([weak_ui, try_attach = std::move(try_attach), blur, attempted](
            slint::RenderingState state, slint::GraphicsAPI) mutable {
            if (state == slint::RenderingState::RenderingSetup) {
                *attempted = false;
                if (auto strong = weak_ui.lock()) try_attach(**strong);
            } else if (state == slint::RenderingState::BeforeRendering) {
                auto strong = weak_ui.lock();
                if (!strong) return;
                if (!blur->active() && !*attempted) try_attach(**strong);
                if (!blur->active()) return;
                auto phys = (**strong).window().size();
                auto sz = desktop::compute_logical_blur_size(phys.width, phys.height, (**strong).window().scale_factor());
                auto const& theme = (**strong).global<nexus_ui::Theme>();
                bool en = desktop::should_enable_native_blur(theme.get_blur_enabled(), theme.get_window_opacity());
                blur->sync(en, sz.width, sz.height, theme.get_dark());
            } else if (state == slint::RenderingState::RenderingTeardown) {
                *attempted = false;
                blur->detach();
            }
        });
    }

    inline auto is_failed_node_state(std::string_view st) -> bool {
        return st == "timeout" || st == "unreachable" || st == "error" || st == "failed";
    }

    inline auto effective_node_latency(desktop::OutboundMemberSnapshot const& m) -> int {
        if (m.latency_ms > 0) return static_cast<int>(m.latency_ms);
        return is_failed_node_state(m.state) ? 0 : -1;
    }

    inline auto sync_active_node_to_ui(
        nexus_ui::AppWindow& ui,
        std::vector<desktop::OutboundGroupSnapshot> const& groups,
        std::string_view active_tag) -> void {
        if (groups.empty()) {
            ui.set_active_node(slint::SharedString(""));
            ui.set_active_node_latency_ms(-1);
            return;
        }
        desktop::OutboundGroupSnapshot const* grp = &groups.front();
        for (auto const& g : groups) {
            if (g.tag == active_tag) { grp = &g; break; }
        }
        std::string node = grp->active;
        int lat = -1;
        for (auto const& m : grp->members) {
            if (m.name == grp->active || (node.empty() && m.selected)) {
                node = m.name;
                lat = effective_node_latency(m);
                break;
            }
        }
        ui.set_active_node(slint::SharedString(node));
        ui.set_active_node_latency_ms(lat);
    }

    inline auto apply_metrics_to_ui(
        nexus_ui::AppWindow& ui,
        desktop::MetricsSnapshot const& m,
        RateTracker::Update const& rate) -> void {
        ui.set_active_sessions(static_cast<int>(m.active_sessions));
        ui.set_upload_rate(slint::SharedString(rate.up_rate));
        ui.set_download_rate(slint::SharedString(rate.down_rate));
        ui.set_upload_total(slint::SharedString(format_bytes_human(m.upload_bytes)));
        ui.set_download_total(slint::SharedString(format_bytes_human(m.download_bytes)));
        double tot = static_cast<double>(m.upload_bytes) + static_cast<double>(m.download_bytes);
        ui.set_total_down_ratio(tot > 0.0 ? static_cast<float>(std::clamp(static_cast<double>(m.download_bytes) / tot, 0.0, 1.0)) : 0.5f);
        ui.set_down_speed_value(slint::SharedString(rate.down_value)); ui.set_down_speed_unit(slint::SharedString(rate.down_unit));
        ui.set_down_speed_peak(slint::SharedString(rate.down_peak)); ui.set_down_wave_area(slint::SharedString(rate.down_wave_area)); ui.set_down_wave_line(slint::SharedString(rate.down_wave_line));
        ui.set_up_speed_value(slint::SharedString(rate.up_value)); ui.set_up_speed_unit(slint::SharedString(rate.up_unit));
        ui.set_up_speed_peak(slint::SharedString(rate.up_peak)); ui.set_up_wave_area(slint::SharedString(rate.up_wave_area)); ui.set_up_wave_line(slint::SharedString(rate.up_wave_line));
    }

    inline auto clear_telemetry_ui(nexus_ui::AppWindow& ui) -> void {
        ui.set_core_uptime(slint::SharedString("")); ui.set_core_memory_text(slint::SharedString("--"));
        ui.set_active_sessions(0);
        ui.set_upload_rate(slint::SharedString("0.0 KB/s")); ui.set_download_rate(slint::SharedString("0.0 KB/s"));
        ui.set_upload_total(slint::SharedString("0 B")); ui.set_download_total(slint::SharedString("0 B"));
        ui.set_total_down_ratio(0.5f);
        ui.set_down_speed_value(slint::SharedString("0.0")); ui.set_down_speed_unit(slint::SharedString("KB/s")); ui.set_down_speed_peak(slint::SharedString("0.0 KB/s"));
        ui.set_down_wave_area(slint::SharedString("")); ui.set_down_wave_line(slint::SharedString(""));
        ui.set_up_speed_value(slint::SharedString("0.0")); ui.set_up_speed_unit(slint::SharedString("KB/s")); ui.set_up_speed_peak(slint::SharedString("0.0 KB/s"));
        ui.set_up_wave_area(slint::SharedString("")); ui.set_up_wave_line(slint::SharedString(""));
    }

    inline auto push_toast(nexus_ui::AppWindow const& ui, std::string const& msg, std::string_view tone = "info") -> void {
        if (msg.empty()) return;
        ui.global<nexus_ui::ToastState>().invoke_push(slint::SharedString(msg), slint::SharedString(tone));
    }

    inline auto push_group_snapshot_to_ui(
        nexus_ui::AppWindow& ui,
        std::vector<desktop::OutboundGroupSnapshot>& cached_groups,
        std::vector<desktop::OutboundGroupSnapshot> snapshot,
        std::string active_tag,
        MemberModelPipeline& member_models,
        std::string_view member_filter = {},
        std::string_view sort_mode = "default",
        std::unordered_set<std::string> const* pinned_members = nullptr) -> void {
        cached_groups = std::move(snapshot);
        std::vector<nexus_ui::OutboundGroupItem> ui_groups;
        ui_groups.reserve(cached_groups.size());
        for (auto const& g : cached_groups) {
            int active_lat = -1;
            for (auto const& m : g.members) {
                if (m.name == g.active || m.selected) { active_lat = effective_node_latency(m); break; }
            }
            ui_groups.push_back({
                slint::SharedString(g.tag),
                slint::SharedString(g.mode),
                slint::SharedString(g.active),
                !g.manual_override,
                active_lat,
                static_cast<int>(g.members.size()),
            });
        }
        if (active_tag.empty() && !cached_groups.empty()) active_tag = cached_groups.front().tag;
        auto group_pins = extract_group_pins(active_tag, pinned_members);
        std::vector<nexus_ui::OutboundMemberItem> ui_members;
        std::string active_mode;
        bool active_auto = false;
        int healthy_cnt = 0;
        int total_cnt = 0;
        for (auto const& g : cached_groups) {
            if (g.tag == active_tag) {
                active_mode = g.mode;
                active_auto = !g.manual_override;
                total_cnt = static_cast<int>(g.members.size());
                ui_members.reserve(g.members.size());
                for (auto const& m : g.members) {
                    if (m.latency_ms > 0) ++healthy_cnt;
                    ui_members.push_back({slint::SharedString(m.name), slint::SharedString(m.state),
                                          static_cast<int>(m.latency_ms), static_cast<int>(m.ewma_ms), m.breaker_open,
                                          m.selected, m.overridden, group_pins.contains(m.name)});
                }
                break;
            }
        }
        ui.set_selected_group(slint::SharedString(active_tag));
        ui.set_active_group_mode(slint::SharedString(active_mode));
        ui.set_active_group_auto(active_auto);
        ui.set_active_group_healthy(healthy_cnt);
        ui.set_active_group_total(total_cnt);
        ui.set_groups(std::make_shared<slint::VectorModel<nexus_ui::OutboundGroupItem>>(std::move(ui_groups)));
        member_models.replace(ui_members, member_filter, sort_mode);
        ui.set_active_group_fastest_ms(member_models.fastest_latency_ms());
        ui.set_quick_nodes(std::make_shared<slint::VectorModel<nexus_ui::OutboundMemberItem>>(
            build_ui_quick_nodes(cached_groups, active_tag, pinned_members)));
        sync_active_node_to_ui(ui, cached_groups, active_tag);
    }

    inline auto count_kdl_lines(std::string_view kdl) -> int {
        if (kdl.empty()) return 0;
        int lines = 1;
        for (char c : kdl) { if (c == '\n') ++lines; }
        if (kdl.back() == '\n' && lines > 1) --lines;
        return lines;
    }

    inline auto apply_kdl_to_ui_state(nexus_ui::AppWindow& ui, std::string const& kdl) -> void {
        ui.set_kdl_text(slint::SharedString(kdl));
        ui.set_kdl_line_count(count_kdl_lines(kdl));
        ui.set_tun_enabled(kdl_has_tun_inbound(kdl));
        if (!kdl.empty()) {
            sync_inbounds_to_ui(ui, desktop::parse_inbound_endpoints(kdl));
        }
    }

    inline auto sync_tray_state(
        desktop::TrayController& tray,
        desktop::CoreSupervisor const& supervisor,
        nexus_ui::AppWindow& ui,
        std::vector<desktop::OutboundGroupSnapshot> const& cached_groups,
        std::unordered_set<std::string> const& pinned_members,
        desktop::WorkspaceDocument const& workspace_doc,
        std::string_view active_profile_id,
        bool window_visible) -> void {
        tray.update_snapshot(build_tray_snapshot(
            ui, supervisor, cached_groups, pinned_members, workspace_doc, active_profile_id,
            read_inbounds_from_ui(ui), window_visible, is_en_ui(ui)));
        ui.set_tray_native_active(tray.native_backend_active());
    }

    inline auto sync_profiles_to_ui(
        nexus_ui::AppWindow& ui,
        desktop::WorkspaceDocument const& doc,
        std::string_view active_profile_id) -> void {
        std::vector<nexus_ui::ProfileItem> items;
        items.reserve(doc.profiles.size());
        for (auto const& p : doc.profiles) {
            items.push_back({slint::SharedString(p.id), slint::SharedString(p.remarks.empty() ? p.id : p.remarks),
                             p.id == active_profile_id});
        }
        ui.set_profiles(std::make_shared<slint::VectorModel<nexus_ui::ProfileItem>>(std::move(items)));
    }

    inline auto poll_telemetry_async(
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui,
        desktop::AsyncWorker& worker,
        desktop::HttpControlClient const& http_ctrl,
        std::vector<desktop::OutboundGroupSnapshot>& cached_groups,
        std::unordered_set<std::string> const& pinned_members,
        MemberModelPipeline& member_models,
        RateTracker& rate_tracker,
        std::atomic<bool>& in_flight,
        bool refresh_groups_too,
        std::function<void()> on_tray_sync = {},
        std::function<void(std::uint64_t, std::uint64_t)> on_traffic_totals = {}) -> void {
        if (in_flight.exchange(true, std::memory_order_acq_rel)) return;
        bool posted = worker.post([&, weak_ui, refresh_groups_too,
                                   on_tray_sync = std::move(on_tray_sync),
                                   on_traffic_totals = std::move(on_traffic_totals)]() mutable {
            auto reply = http_ctrl.metrics();
            std::optional<std::vector<desktop::OutboundGroupSnapshot>> grp_snap;
            if (refresh_groups_too) {
                if (auto gr = http_ctrl.outbounds(); gr.ok) grp_snap = desktop::parse_outbounds_json(gr.body);
            }
            in_flight.store(false, std::memory_order_release);
            if (!reply.ok && !grp_snap) return;
            std::optional<desktop::MetricsSnapshot> m;
            if (reply.ok) m = desktop::parse_openmetrics_summary(reply.body);
            on_ui_thread(weak_ui, [&cached_groups, &pinned_members, &member_models, &rate_tracker, m, grp_snap = std::move(grp_snap),
                                   on_tray_sync = std::move(on_tray_sync),
                                   on_traffic_totals = std::move(on_traffic_totals)](auto& s) mutable {
                if (m) {
                    apply_metrics_to_ui(*s, *m, rate_tracker.record(m->upload_bytes, m->download_bytes));
                    if (on_traffic_totals) on_traffic_totals(m->upload_bytes, m->download_bytes);
                }
                if (grp_snap) {
                    push_group_snapshot_to_ui(*s, cached_groups, std::move(*grp_snap), std::string(s->get_selected_group()),
                                              member_models, std::string_view(s->get_member_filter()), std::string_view(s->get_member_sort()), &pinned_members);
                }
                if (on_tray_sync && (grp_snap || (m && s->get_tray_show_speed()))) on_tray_sync();
            });
        });
        if (!posted) in_flight.store(false, std::memory_order_release);
    }
}
