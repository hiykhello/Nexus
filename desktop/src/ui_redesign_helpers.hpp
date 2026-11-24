// Connection formatting, quick-nodes & tray snapshot builders included by desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    inline auto lower_ascii(std::string_view s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) out.push_back(static_cast<char>(std::tolower(c)));
        return out;
    }

    // Slint 1.19 live FilterModel + SortModel pipeline for proxy group members (zero full-snapshot rebuilds on search/sort)
    struct MemberModelPipeline {
        std::shared_ptr<slint::VectorModel<nexus_ui::OutboundMemberItem>> raw =
            std::make_shared<slint::VectorModel<nexus_ui::OutboundMemberItem>>();
        std::shared_ptr<std::string> filter_lc = std::make_shared<std::string>();
        std::shared_ptr<std::string> sort_mode = std::make_shared<std::string>("default");
        std::shared_ptr<slint::FilterModel<nexus_ui::OutboundMemberItem>> filtered;
        std::shared_ptr<slint::SortModel<nexus_ui::OutboundMemberItem>> sorted;

        MemberModelPipeline() {
            auto f_lc = filter_lc;
            filtered = std::make_shared<slint::FilterModel<nexus_ui::OutboundMemberItem>>(
                raw, [f_lc](nexus_ui::OutboundMemberItem const& m) {
                    if (f_lc->empty()) return true;
                    return lower_ascii(std::string_view(m.name)).contains(*f_lc);
                });
            auto s_mode = sort_mode;
            sorted = std::make_shared<slint::SortModel<nexus_ui::OutboundMemberItem>>(
                filtered, [s_mode](nexus_ui::OutboundMemberItem const& a, nexus_ui::OutboundMemberItem const& b) {
                    if (a.pinned != b.pinned) return a.pinned > b.pinned;
                    if (*s_mode == "latency") {
                        bool ha = a.latency_ms > 0, hb = b.latency_ms > 0;
                        if (ha != hb) return ha > hb;
                        if (ha && a.latency_ms != b.latency_ms) return a.latency_ms < b.latency_ms;
                        return lower_ascii(std::string_view(a.name)) < lower_ascii(std::string_view(b.name));
                    }
                    if (*s_mode == "name") {
                        return lower_ascii(std::string_view(a.name)) < lower_ascii(std::string_view(b.name));
                    }
                    return false;
                });
        }

        auto replace(std::vector<nexus_ui::OutboundMemberItem> items, std::string_view filter, std::string_view sort) -> void {
            *filter_lc = lower_ascii(filter);
            *sort_mode = sort.empty() ? "default" : std::string(sort);
            raw->set_vector(std::move(items));
        }

        auto set_filter(std::string_view filter) -> void {
            *filter_lc = lower_ascii(filter);
            filtered->reset();
        }

        auto set_sort(std::string_view sort) -> void {
            *sort_mode = sort.empty() ? "default" : std::string(sort);
            sorted->reset();
        }
    };

    inline auto format_duration_human(std::uint64_t ms) -> std::string {
        if (ms == 0) return {};
        if (ms < 1000) return std::format("{} ms", ms);
        if (ms < 60'000) return std::format("{:.1f} s", static_cast<double>(ms) / 1000.0);
        auto total_sec = ms / 1000;
        if (total_sec < 3600) return std::format("{}m {}s", total_sec / 60, total_sec % 60);
        auto total_min = total_sec / 60;
        if (total_min < 1440) return std::format("{}h {}m", total_min / 60, total_min % 60);
        auto total_hr = total_min / 60;
        return std::format("{}d {}h", total_hr / 24, total_hr % 24);
    }

    inline auto format_connection_detail(desktop::ActiveConnectionSnapshot const& c, bool is_en = false) -> std::string {
        auto inb = c.inbound.empty() ? std::string_view(c.protocol) : std::string_view(c.inbound);
        auto src = c.source.empty() ? std::string_view("-") : std::string_view(c.source);
        auto dst = c.target.empty() ? std::format(":{}", c.destination_port) : c.target;
        auto outb = c.outbound.empty() ? std::string_view(c.path) : std::string_view(c.outbound);
        auto mode = c.route_mode.empty() ? std::string_view("-") : std::string_view(c.route_mode);
        auto rule = c.route_rule.empty() ? std::string_view("-") : std::string_view(c.route_rule);
        auto proc = c.process_path.empty() ? std::string_view("-") : std::string_view(c.process_path);
        if (is_en) {
            return std::format("#{} [{}] {} → {} · Outbound: {} · Mode: {} · Rule: {} · Duration: {}ms · Process: {}",
                c.id, inb, src, dst, outb, mode, rule, c.duration_ms, proc);
        }
        return std::format("#{} [{}] {} → {} · 出站: {} · 模式: {} · 规则: {} · 耗时: {}ms · 进程: {}",
            c.id, inb, src, dst, outb, mode, rule, c.duration_ms, proc);
    }

    inline auto build_ui_connection_items(std::vector<desktop::ActiveConnectionSnapshot> const& parsed, std::string filter)
        -> std::vector<nexus_ui::ActiveConnectionItem> {
        for (char& ch : filter) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        std::vector<nexus_ui::ActiveConnectionItem> items;
        for (auto const& c : parsed) {
            auto hay = std::format("{} {} {} {} {} {} {} {}", c.id, c.protocol, c.path, c.outbound, c.target,
                c.route_rule, c.process_path, c.destination_port);
            for (char& ch : hay) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (!filter.empty() && !hay.contains(filter)) continue;
            double total = static_cast<double>(c.upload_bytes) + static_cast<double>(c.download_bytes);
            float ratio = total > 0.0 ? static_cast<float>(std::clamp(static_cast<double>(c.upload_bytes) / total, 0.0, 1.0)) : 0.0f;
            items.push_back({
                slint::SharedString(std::to_string(c.id)),
                slint::SharedString(c.protocol),
                slint::SharedString(c.path),
                slint::SharedString(c.target),
                slint::SharedString(c.inbound),
                slint::SharedString(c.outbound),
                slint::SharedString(c.route_rule),
                slint::SharedString(c.process_path),
                slint::SharedString(c.source),
                slint::SharedString(format_duration_human(c.duration_ms)),
                static_cast<int>(c.destination_port),
                slint::SharedString(format_bytes_human(c.upload_bytes)),
                slint::SharedString(format_bytes_human(c.download_bytes)),
                ratio,
                total > 0.0,
            });
        }
        return items;
    }

    inline auto extract_group_pins(
        std::string_view group_tag,
        std::unordered_set<std::string> const* pinned_members) -> std::unordered_set<std::string> {
        std::unordered_set<std::string> group_pins;
        if (!pinned_members || group_tag.empty()) return group_pins;
        std::string prefix = std::string(group_tag) + "::";
        for (auto const& k : *pinned_members) {
            if (k.starts_with(prefix)) group_pins.insert(k.substr(prefix.size()));
        }
        return group_pins;
    }

    inline auto build_ui_quick_nodes(
        std::vector<desktop::OutboundGroupSnapshot> const& cached_groups,
        std::string_view active_tag,
        std::unordered_set<std::string> const* pinned_members) -> std::vector<nexus_ui::OutboundMemberItem> {
        std::vector<nexus_ui::OutboundMemberItem> out;
        for (auto const& g : cached_groups) {
            if (g.tag != active_tag) continue;
            auto group_pins = extract_group_pins(g.tag, pinned_members);
            auto picked = desktop::pick_quick_nodes(g.members, group_pins, 9);
            out.reserve(picked.size());
            for (auto const& m : picked) {
                out.push_back({
                    slint::SharedString(m.name),
                    slint::SharedString(m.state),
                    static_cast<int>(m.latency_ms),
                    m.selected,
                    m.overridden,
                    group_pins.contains(m.name),
                });
            }
            break;
        }
        return out;
    }

    inline auto build_proxy_env_from_inbounds(desktop::CoexistingInbounds const& inb) -> std::string {
        std::string http_host = "127.0.0.1";
        std::string socks_host;
        std::uint16_t http_port = 0;
        std::uint16_t socks_port = 0;
        if (inb.mixed.enabled && inb.mixed.port > 0) {
            http_host = inb.mixed.host;
            socks_host = inb.mixed.host;
            http_port = inb.mixed.port;
            socks_port = inb.mixed.port;
        } else {
            if (inb.http.enabled && inb.http.port > 0) {
                http_host = inb.http.host;
                http_port = inb.http.port;
            }
            if (inb.socks5.enabled && inb.socks5.port > 0) {
                socks_host = inb.socks5.host;
                socks_port = inb.socks5.port;
            }
        }
        return desktop::build_proxy_export_command(http_host, http_port, socks_port, socks_host);
    }

    inline auto build_tray_snapshot(
        nexus_ui::AppWindow const& ui,
        desktop::CoreSupervisor const& supervisor,
        std::vector<desktop::OutboundGroupSnapshot> const& cached_groups,
        std::unordered_set<std::string> const& pinned_members,
        desktop::ProfileStore& profile_store,
        desktop::CoexistingInbounds const& inbounds,
        bool window_visible,
        bool is_en) -> desktop::TraySnapshot {
        desktop::TraySnapshot snap{};
        bool running = supervisor.running();
        bool tun = ui.get_tun_enabled();
        int active_lat = ui.get_active_node_latency_ms();
        std::string active_node(ui.get_active_node());
        bool degraded = running && (!ui.get_diagnostic_ok() || (!active_node.empty() && active_lat == 0));

        snap.state = !running ? desktop::TrayState::offline
            : degraded ? desktop::TrayState::degraded
            : tun ? desktop::TrayState::tun_active
            : desktop::TrayState::running;
        snap.core_running = running;
        snap.window_visible = window_visible;
        snap.system_proxy_enabled = ui.get_system_proxy_enabled();
        snap.tun_enabled = tun;
        snap.is_en = is_en;
        snap.show_nodes = ui.get_tray_show_nodes();
        snap.show_speed = ui.get_tray_show_speed();
        snap.click_action = std::string(ui.get_tray_click_action());
        snap.outbound_mode = std::string(ui.get_outbound_mode());
        snap.active_group = std::string(ui.get_selected_group());
        snap.active_node = std::move(active_node);
        if (active_lat > 0) snap.active_latency = std::format("{}ms", active_lat);
        else if (active_lat == 0 && running) snap.active_latency = is_en ? "timeout" : "超时";
        snap.download_rate = std::string(ui.get_download_rate());
        snap.upload_rate = std::string(ui.get_upload_rate());
        snap.proxy_export_cmd = build_proxy_env_from_inbounds(inbounds);

        if (snap.show_nodes && !cached_groups.empty()) {
            std::string_view grp_tag = snap.active_group.empty() ? std::string_view(cached_groups.front().tag) : std::string_view(snap.active_group);
            for (auto const& g : cached_groups) {
                if (g.tag != grp_tag) continue;
                auto group_pins = extract_group_pins(g.tag, &pinned_members);
                auto picked = desktop::pick_quick_nodes(g.members, group_pins, 8);
                snap.quick_nodes.reserve(picked.size());
                for (auto const& m : picked) {
                    std::string lat_lbl = m.latency_ms > 0 ? std::format("{}ms", m.latency_ms)
                        : (m.state == "timeout" || m.state == "unreachable" || m.state == "error" || m.state == "failed")
                            ? (is_en ? "timeout" : "超时") : "--";
                    snap.quick_nodes.push_back({g.tag, m.name, std::move(lat_lbl), m.selected});
                }
                break;
            }
        }

        auto active_pid = profile_store.active_id();
        auto entries = profile_store.list();
        snap.profiles.reserve(entries.size());
        for (auto const& e : entries) {
            snap.profiles.push_back({e.id, e.name, e.id == active_pid});
        }
        return snap;
    }
}
