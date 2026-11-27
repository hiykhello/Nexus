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

    inline auto apply_prefs_to_ui(nexus_ui::AppWindow& ui, desktop::UiPrefs const& p, std::string const& sys_locale) -> void {
        auto const& i18n = ui.global<nexus_ui::I18n>();
        i18n.set_system_locale(slint::SharedString(sys_locale));
        i18n.set_preference(
            p.language == "zh-cn" ? nexus_ui::LanguagePreference::ZhCn
            : p.language == "en-us" ? nexus_ui::LanguagePreference::EnUs
            : nexus_ui::LanguagePreference::System);

        auto const& theme = ui.global<nexus_ui::Theme>();
        theme.invoke_apply_preference(
            (p.theme_preference == "paper" || p.theme_preference == "light" || p.theme_preference == "daylight")
                ? nexus_ui::ThemePreference::Paper
            : (p.theme_preference == "obsidian" || p.theme_preference == "dark")
                ? nexus_ui::ThemePreference::Obsidian
            : (p.theme_preference == "amber" || p.theme_preference == "studio_amber")
                ? nexus_ui::ThemePreference::Amber
            : nexus_ui::ThemePreference::System);
        theme.set_accent_preset(
            p.accent_preset == "emerald" ? nexus_ui::AccentPreset::Emerald
            : p.accent_preset == "violet" ? nexus_ui::AccentPreset::Violet
            : p.accent_preset == "amber" ? nexus_ui::AccentPreset::Amber
            : p.accent_preset == "rose" ? nexus_ui::AccentPreset::Rose
            : nexus_ui::AccentPreset::Ocean);
        theme.set_blur_enabled(p.blur_enabled);
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
    }

    inline auto capture_prefs_from_ui(nexus_ui::AppWindow const& ui) -> desktop::UiPrefs {
        desktop::UiPrefs p{};
        auto lang = ui.global<nexus_ui::I18n>().get_preference();
        p.language = lang == nexus_ui::LanguagePreference::ZhCn ? "zh-cn" : lang == nexus_ui::LanguagePreference::EnUs ? "en-us" : "system";
        auto const& theme = ui.global<nexus_ui::Theme>();
        auto pref = theme.get_preference();
        p.theme_preference = pref == nexus_ui::ThemePreference::Paper ? "paper"
            : pref == nexus_ui::ThemePreference::Obsidian ? "obsidian"
            : pref == nexus_ui::ThemePreference::Amber ? "amber"
            : "system";
        auto accent = theme.get_accent_preset();
        p.accent_preset = accent == nexus_ui::AccentPreset::Emerald ? "emerald" : accent == nexus_ui::AccentPreset::Violet ? "violet"
            : accent == nexus_ui::AccentPreset::Amber ? "amber" : accent == nexus_ui::AccentPreset::Rose ? "rose" : "ocean";
        p.blur_enabled = theme.get_blur_enabled();
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
        return p;
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
            if (blur->active() || *attempted) return;
#ifdef _WIN32
            void* hwnd = win_ui.window().win32_hwnd();
            if (!hwnd) return;
            *attempted = true;
            (void)blur->attach_win32(hwnd);
#elif !defined(__APPLE__)
            void* dpy = win_ui.window().wayland_display();
            void* surf = win_ui.window().wayland_surface();
            if (!dpy || !surf) return;
            *attempted = true;
            (void)blur->attach_wayland(dpy, surf);
#else
            (void)win_ui;
            *attempted = true;
#endif
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
                bool const blur_on = theme.get_blur_enabled();
                bool const en = desktop::should_enable_native_blur(blur_on, blur_on ? 0.88f : 1.0f);
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
        ui.set_down_speed_value(slint::SharedString(rate.down_value));
        ui.set_down_speed_unit(slint::SharedString(rate.down_unit));
        ui.set_up_speed_value(slint::SharedString(rate.up_value));
        ui.set_up_speed_unit(slint::SharedString(rate.up_unit));
        auto const& wave = ui.global<nexus_ui::TelemetryWaveState>();
        wave.set_rx_area(slint::SharedString(rate.rx_area));
        wave.set_rx_line(slint::SharedString(rate.rx_line));
        wave.set_tx_dashed_line(slint::SharedString(rate.tx_dashed_line));
        wave.set_scale_peak_text(slint::SharedString(rate.scale_peak));
        wave.set_has_onset(rate.has_onset);
        wave.set_onset_ratio(rate.onset_ratio);
        wave.set_onset_label(slint::SharedString(rate.onset_label));
    }

    inline auto clear_telemetry_ui(nexus_ui::AppWindow& ui) -> void {
        ui.set_core_uptime(slint::SharedString(""));
        ui.set_core_pid_text(slint::SharedString(""));
        ui.set_core_cpu_text(slint::SharedString("--"));
        ui.set_core_cpu_ratio(0.0f);
        ui.set_core_memory_text(slint::SharedString("--"));
        ui.set_active_sessions(0);
        ui.set_upload_rate(slint::SharedString("0.0 KB/s")); ui.set_download_rate(slint::SharedString("0.0 KB/s"));
        ui.set_upload_total(slint::SharedString("0 B")); ui.set_download_total(slint::SharedString("0 B"));
        ui.set_down_speed_value(slint::SharedString("0.0")); ui.set_down_speed_unit(slint::SharedString("KB/s"));
        ui.set_up_speed_value(slint::SharedString("0.0")); ui.set_up_speed_unit(slint::SharedString("KB/s"));
        auto const& wave = ui.global<nexus_ui::TelemetryWaveState>();
        wave.set_rx_area(slint::SharedString(""));
        wave.set_rx_line(slint::SharedString(""));
        wave.set_tx_dashed_line(slint::SharedString(""));
        wave.set_scale_peak_text(slint::SharedString("8.0 KB/s"));
        wave.set_has_onset(false);
        wave.set_onset_ratio(-1.0f);
        wave.set_onset_label(slint::SharedString(""));
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
        GroupLatencySpectrum spec{};
        for (auto const& g : cached_groups) {
            if (g.tag == active_tag) {
                active_mode = g.mode;
                active_auto = !g.manual_override;
                total_cnt = static_cast<int>(g.members.size());
                spec = compute_group_latency_spectrum(g.members);
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
        ui.global<nexus_ui::TelemetryWaveState>().set_spectrum({
            spec.fast_ratio, spec.good_ratio, spec.mid_ratio, spec.slow_ratio, spec.timeout_ratio,
            spec.p50_ms, spec.max_ms, spec.has_data,
        });
        sync_active_node_to_ui(ui, cached_groups, active_tag);
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
