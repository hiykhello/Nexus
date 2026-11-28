// Wave 35 Global Ctrl+K Command Palette & Inline Route/DNS Diagnostic callbacks included by desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    struct CommandPaletteController {
        nexus_ui::AppWindow& ui;
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui;
        desktop::AsyncWorker& probe_worker;
        desktop::CoreSupervisor& supervisor;
        desktop::HttpControlClient& http_ctrl;
        WorkspaceUiContext& ws_ctx;
        std::filesystem::path const& cfg_dir;
        std::filesystem::path const& config_path;
        std::vector<desktop::OutboundGroupSnapshot>& cached_groups;
        std::function<void()> const& persist_prefs;

        std::shared_ptr<slint::VectorModel<nexus_ui::PaletteItem>> model =
            std::make_shared<slint::VectorModel<nexus_ui::PaletteItem>>();
        std::atomic<std::uint64_t> diag_seq{0};

        static auto latency_tone(int ms, std::string_view state) -> std::string_view {
            if (ms <= 0) return is_timeout_member_state(state) ? "error" : "muted";
            if (ms < 80) return "fast";
            if (ms < 180) return "good";
            if (ms < 350) return "mid";
            return "slow";
        }

        auto build_items(std::string_view raw_query) -> std::vector<nexus_ui::PaletteItem> {
            bool const en = is_en_ui(ui);
            auto q = trim_palette_ws(raw_query);
            bool const cmd_only = !q.empty() && q.front() == '>';
            auto filter_q = cmd_only ? trim_palette_ws(q.substr(1)) : q;

            struct Scored {
                int score = 0;
                nexus_ui::PaletteItem item;
            };
            std::vector<Scored> scored;
            auto cur_mode = std::string(ui.get_outbound_mode());
            auto cur_theme = ui.global<nexus_ui::Theme>().get_preference();
            std::string cur_grp(ui.get_selected_group());
            if (cur_grp.empty() && !cached_groups.empty()) cur_grp = cached_groups.front().tag;

            auto consider_action = [&](std::string id, std::string kind, std::string grp, std::string title,
                                       std::string subtitle, std::string badge, std::string tone,
                                       bool active, std::string_view keywords, int base_boost = 0) {
                int s = filter_q.empty() ? (100 + base_boost)
                    : std::max(palette_fuzzy_score(filter_q, title), palette_fuzzy_score(filter_q, keywords));
                if (s < 0) return;
                scored.push_back({s + base_boost, {
                    slint::SharedString(id), slint::SharedString(kind), slint::SharedString(grp),
                    slint::SharedString(title), slint::SharedString(subtitle),
                    slint::SharedString(badge), slint::SharedString(tone), active,
                }});
            };

            std::string const cmd_tag = en ? "CMD" : "命令";
            std::string const nav_tag = en ? "NAV" : "页面";
            std::string const thm_tag = en ? "THEME" : "主题";

            consider_action("mode:rule", "action", cmd_tag, tr(en, "出站模式：规则分流", "Outbound Mode: Rule"),
                            "rule", tr(en, "规则", "Rule"), "accent", cur_mode == "rule", "mode rule 出站 规则 分流", 40);
            consider_action("mode:global", "action", cmd_tag, tr(en, "出站模式：全局代理", "Outbound Mode: Global"),
                            "global", tr(en, "全局", "Global"), "accent", cur_mode == "global", "mode global 全局 代理", 38);
            consider_action("mode:direct", "action", cmd_tag, tr(en, "出站模式：直连绕过", "Outbound Mode: Direct"),
                            "direct", tr(en, "直连", "Direct"), "emerald", cur_mode == "direct", "mode direct 直连 绕过", 36);
            consider_action("toggle:tun", "action", cmd_tag,
                            ui.get_tun_enabled() ? tr(en, "关闭 TUN 模式", "Disable TUN Mode") : tr(en, "开启 TUN 模式", "Enable TUN Mode"),
                            "tun", ui.get_tun_enabled() ? "ON" : "OFF", ui.get_tun_enabled() ? "emerald" : "muted",
                            ui.get_tun_enabled(), "tun vpn toggle 虚拟网卡", 34);
            consider_action("toggle:sysproxy", "action", cmd_tag,
                            ui.get_system_proxy_enabled() ? tr(en, "关闭系统代理", "Disable System Proxy") : tr(en, "开启系统代理", "Enable System Proxy"),
                            "proxy", ui.get_system_proxy_enabled() ? "ON" : "OFF", ui.get_system_proxy_enabled() ? "emerald" : "muted",
                            ui.get_system_proxy_enabled(), "system proxy 系统代理", 32);
            consider_action("probe:group", "action", cmd_tag, tr(en, "测速当前策略组", "Probe Active Group"),
                            cur_grp, tr(en, "测速", "Probe"), "accent", false, "probe latency test 测速 延迟", 30);
            consider_action("flush:fakeip", "action", cmd_tag, tr(en, "清空 FakeIP 映射", "Flush FakeIP Pool"),
                            "dns", "FakeIP", "muted", false, "flush fakeip 清空 刷新", 28);
            consider_action("flush:dns", "action", cmd_tag, tr(en, "清除 DNS 缓存", "Clear DNS Cache"),
                            "dns", "DNS", "muted", false, "flush clear dns cache 缓存", 26);
            consider_action("reload", "action", cmd_tag, tr(en, "热重载代理配置", "Reload Core Config"),
                            "Ctrl+R", tr(en, "重载", "Reload"), "muted", false, "reload config 重载 配置", 24);
            consider_action("open:rules", "action", cmd_tag, tr(en, "打开路由与 DNS 诊断", "Open Routing & DNS"),
                            "Ctrl+Shift+R", "DNS", "muted", false, "rules dns explain 规则 诊断", 22);
            consider_action("open:outbound", "action", cmd_tag, tr(en, "新增出站节点向导", "New Outbound Node"),
                            "", "+ Node", "accent", false, "add outbound node 新增 节点", 20);

            consider_action("theme:obsidian", "theme", thm_tag, tr(en, "主题：曜石深色", "Theme: Dark Card"),
                            "obsidian", tr(en, "深色", "Dark"), "muted", cur_theme == nexus_ui::ThemePreference::Obsidian, "theme obsidian dark 曜石 深色", 10);
            consider_action("theme:paper", "theme", thm_tag, tr(en, "主题：雾白卡片", "Theme: Light Card"),
                            "paper", tr(en, "浅色", "Light"), "muted", cur_theme == nexus_ui::ThemePreference::Paper, "theme paper daylight light 雾白 浅色", 9);
            consider_action("theme:amber", "theme", thm_tag, tr(en, "主题：暖金深色", "Theme: Warm Amber"),
                            "amber", tr(en, "琥珀", "Amber"), "mid", cur_theme == nexus_ui::ThemePreference::Amber, "theme amber studio 琥珀", 8);
            consider_action("theme:system", "theme", thm_tag, tr(en, "主题：跟随系统", "Theme: Follow System"),
                            "system", "Auto", "muted", cur_theme == nexus_ui::ThemePreference::System, "theme system auto 跟随系统", 7);

            consider_action("tab:0", "nav", nav_tag, tr(en, "跳转：仪表盘", "Go to Dashboard"), "", "Ctrl+1", "muted", ui.get_active_tab() == 0, "overview dashboard 仪表盘 概览", 5);
            consider_action("tab:1", "nav", nav_tag, tr(en, "跳转：配置文件与订阅", "Go to Profiles & Subs"), "", "Ctrl+2", "muted", ui.get_active_tab() == 1, "profiles servers subscriptions 配置文件 服务器 订阅", 5);
            consider_action("tab:2", "nav", nav_tag, tr(en, "跳转：代理策略组", "Go to Proxy Groups"), "", "Ctrl+3", "muted", ui.get_active_tab() == 2, "proxies groups nodes 代理组 策略组", 4);
            consider_action("tab:3", "nav", nav_tag, tr(en, "跳转：路由与规则集", "Go to Routing & Rules"), "", "Ctrl+4", "muted", ui.get_active_tab() == 3, "routing rules ruleset 路由 规则集", 4);
            consider_action("tab:4", "nav", nav_tag, tr(en, "跳转：DNS 与核心入站", "Go to DNS & Inbounds"), "", "Ctrl+5", "muted", ui.get_active_tab() == 4, "dns inbounds tun ports 入站 端口", 4);
            consider_action("tab:5", "nav", nav_tag, tr(en, "跳转：实时连接", "Go to Connections"), "", "Ctrl+6", "muted", ui.get_active_tab() == 5, "connections sessions 连接", 4);
            consider_action("tab:6", "nav", nav_tag, tr(en, "跳转：运行日志", "Go to Logs"), "", "Ctrl+7", "muted", ui.get_active_tab() == 6, "logs stream 日志", 4);
            consider_action("tab:7", "nav", nav_tag, tr(en, "跳转：软件设置", "Go to Settings"), "", "Ctrl+8", "muted", ui.get_active_tab() == 7, "settings appearance shortcuts 设置", 4);

            // Fuzzy node matching across all cached groups (skipped when '>' command prefix active)
            if (!cmd_only) {
                for (auto const& g : cached_groups) {
                    bool const is_cur_grp = (g.tag == cur_grp);
                    int shown_in_empty = 0;
                    for (auto const& m : g.members) {
                        if (filter_q.empty()) {
                            if (!is_cur_grp || shown_in_empty >= 6) continue;
                            ++shown_in_empty;
                        }
                        int ms = effective_node_latency(m);
                        int s = filter_q.empty() ? (m.selected ? 160 : 120)
                            : std::max(palette_fuzzy_score(filter_q, m.name),
                                       palette_fuzzy_score(filter_q, g.tag + " " + m.name));
                        if (s < 0) continue;
                        std::string badge = ms > 0 ? std::format("{} ms", ms)
                            : (ms == 0 ? tr(en, "超时", "Timeout") : "--");
                        scored.push_back({s + (is_cur_grp ? 25 : 0) + (m.selected ? 15 : 0), {
                            slint::SharedString(g.tag + "::" + m.name),
                            slint::SharedString("node"),
                            slint::SharedString(g.tag),
                            slint::SharedString(m.name),
                            slint::SharedString(m.selected ? tr(en, "当前节点", "Active") : ""),
                            slint::SharedString(badge),
                            slint::SharedString(latency_tone(ms, m.state)),
                            m.selected,
                        }});
                    }
                }
            }

            std::ranges::stable_sort(scored, [](auto const& a, auto const& b) { return a.score > b.score; });
            std::vector<nexus_ui::PaletteItem> out;
            std::size_t const cap = std::min<std::size_t>(scored.size(), 24);
            out.reserve(cap);
            for (std::size_t i = 0; i < cap; ++i) out.push_back(std::move(scored[i].item));
            return out;
        }

        auto refresh_list(std::string_view q) -> void {
            sync_vector_model(*model, build_items(q));
            auto const& ps = ui.global<nexus_ui::CommandPaletteState>();
            ps.set_selected_index(0);
            if (!looks_like_domain_query(q)) {
                diag_seq.fetch_add(1, std::memory_order_acq_rel);
                ps.set_diag_active(false);
                ps.set_diag_busy(false);
            }
        }

        auto run_domain_diag(std::string_view raw_query) -> void {
            auto const& ps = ui.global<nexus_ui::CommandPaletteState>();
            if (!looks_like_domain_query(raw_query)) {
                diag_seq.fetch_add(1, std::memory_order_acq_rel);
                ps.set_diag_active(false);
                ps.set_diag_busy(false);
                return;
            }
            auto domain = normalize_domain_candidate(raw_query);
            auto seq = diag_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
            bool const en = is_en_ui(ui);
            bool const core_up = supervisor.running();
            auto doc_snap = ws_ctx.doc;
            auto host_snap = ws_ctx.host;
            auto active_id = resolve_effective_active_profile_id(ws_ctx);

            ps.set_diag_active(true);
            ps.set_diag_busy(true);
            ps.set_diag_domain(slint::SharedString(domain));
            ps.set_diag_rule(slint::SharedString(""));
            ps.set_diag_outbound(slint::SharedString(""));
            ps.set_diag_dns_ip(slint::SharedString(""));
            ps.set_diag_dns_rcode(slint::SharedString(""));
            ps.set_diag_dns_fakeip(false);
            ps.set_diag_latency_ms(-1);
            ps.set_diag_note(slint::SharedString(core_up ? "" : tr(en, "核心未运行 · 仅本地规则匹配", "Core stopped · static rule match only")));
            ps.set_diag_error(slint::SharedString(""));

            bool posted = probe_worker.post([this, seq, en, core_up, domain = std::move(domain),
                                             doc_snap = std::move(doc_snap), host_snap = std::move(host_snap),
                                             active_id = std::move(active_id)] {
                if (diag_seq.load(std::memory_order_acquire) != seq) return;
                auto draft = cfg_dir / ".palette-explain.kdl";
                bool use_draft = false;
                if (!doc_snap.profiles.empty()) {
                    auto composed = compose_workspace_with_overlay(
                        cfg_dir, supervisor.binary_path(), ws_ctx.secrets_dir, doc_snap, host_snap, active_id, en);
                    if (composed && write_file_atomic(draft, composed->kdl)) use_draft = true;
                }
                if (diag_seq.load(std::memory_order_acquire) != seq) {
                    if (use_draft) { std::error_code ec; std::filesystem::remove(draft, ec); }
                    return;
                }
                auto const eff_inb = select_active_inbound_tag(host_snap);
                auto target_cfg = use_draft ? draft : config_path;
                auto explain = supervisor.explain_rule(target_cfg, eff_inb, "tcp", domain + ":443", "");
                if (use_draft) { std::error_code ec; std::filesystem::remove(draft, ec); }

                auto summary = explain.ok ? parse_explain_summary(explain.message) : ExplainSummary{};
                std::string dns_ip, dns_rcode;
                bool dns_fakeip = false;
                int dns_ms = -1;
                if (core_up) {
                    if (diag_seq.load(std::memory_order_acquire) != seq) return;
                    auto rep = http_ctrl.dns_query(domain, "A", "");
                    if (rep.ok) {
                        auto parsed = desktop::parse_dns_query_json(rep.body);
                        if (parsed.ok) {
                            dns_rcode = parsed.rcode_name.empty() ? std::to_string(parsed.rcode) : parsed.rcode_name;
                            dns_ms = static_cast<int>(parsed.elapsed_ms);
                            if (!parsed.answers.empty()) {
                                dns_ip = parsed.answers.front().data;
                                dns_fakeip = is_fakeip_address(dns_ip);
                            }
                        }
                    }
                }
                std::string err = (!explain.ok && dns_ip.empty() && dns_rcode.empty()) ? explain.message : std::string{};
                on_ui_thread(weak_ui, [this, seq, summary = std::move(summary), dns_ip = std::move(dns_ip),
                                       dns_rcode = std::move(dns_rcode), dns_fakeip, dns_ms, err = std::move(err)](auto& s) {
                    if (diag_seq.load(std::memory_order_acquire) != seq) return;
                    auto const& st = s->template global<nexus_ui::CommandPaletteState>();
                    st.set_diag_busy(false);
                    st.set_diag_rule(slint::SharedString(summary.rule));
                    st.set_diag_outbound(slint::SharedString(summary.outbound));
                    st.set_diag_dns_ip(slint::SharedString(dns_ip));
                    st.set_diag_dns_rcode(slint::SharedString(dns_rcode));
                    st.set_diag_dns_fakeip(dns_fakeip);
                    st.set_diag_latency_ms(dns_ms);
                    st.set_diag_error(slint::SharedString(err));
                });
            });
            if (!posted) ps.set_diag_busy(false);
        }

        auto bind() -> void {
            auto const& ps = ui.global<nexus_ui::CommandPaletteState>();
            ps.set_items(model);
            ps.on_opened([this] {
                refresh_list(std::string_view(ui.global<nexus_ui::CommandPaletteState>().get_query()));
            });
            ps.on_query_changed([this](slint::SharedString q) {
                refresh_list(std::string_view(q));
            });
            ps.on_run_domain_diag([this](slint::SharedString q) {
                run_domain_diag(std::string_view(q));
            });
            ps.on_create_rule_for_domain([this](slint::SharedString dom) {
                ui.global<nexus_ui::CommandPaletteState>().invoke_close_palette();
                ui.set_route_rule_kind(slint::SharedString("domain-suffix"));
                ui.set_route_match_value(dom);
                ui.set_route_rule_action(slint::SharedString("route"));
                ui.set_rule_modal_tab(0);
                ui.set_rule_modal_open(true);
            });
            ps.on_flush_fakeip_requested([this] {
                ui.global<nexus_ui::ControlInspectState>().invoke_flush_fakeip();
            });
            ps.on_execute_item([this](slint::SharedString kind_s, slint::SharedString id_s) {
                std::string_view kind(kind_s), id(id_s);
                ui.global<nexus_ui::CommandPaletteState>().invoke_close_palette();
                if (kind == "node") {
                    if (auto sep = id.find("::"); sep != std::string_view::npos) {
                        ui.invoke_select_member(slint::SharedString(id.substr(0, sep)), slint::SharedString(id.substr(sep + 2)));
                    }
                    return;
                }
                if (kind == "theme") {
                    auto const& th = ui.global<nexus_ui::Theme>();
                    if (id == "theme:obsidian") th.invoke_apply_preference(nexus_ui::ThemePreference::Obsidian);
                    else if (id == "theme:paper") th.invoke_apply_preference(nexus_ui::ThemePreference::Paper);
                    else if (id == "theme:amber") th.invoke_apply_preference(nexus_ui::ThemePreference::Amber);
                    else th.invoke_apply_preference(nexus_ui::ThemePreference::System);
                    if (persist_prefs) persist_prefs();
                    return;
                }
                if (kind == "nav" && id.starts_with("tab:") && id.size() == 5) {
                    int tab = id[4] - '0';
                    ui.set_active_tab(tab);
                    if (tab == 1 || tab == 3 || tab == 4) ui.invoke_refresh_profiles();
                    else if (tab == 2) ui.invoke_refresh_groups();
                    else if (tab == 5) ui.invoke_refresh_connections();
                    else if (tab == 6) ui.invoke_refresh_logs();
                    return;
                }
                if (id == "mode:rule") ui.invoke_switch_outbound_mode(slint::SharedString("rule"));
                else if (id == "mode:global") ui.invoke_switch_outbound_mode(slint::SharedString("global"));
                else if (id == "mode:direct") ui.invoke_switch_outbound_mode(slint::SharedString("direct"));
                else if (id == "toggle:tun") ui.invoke_toggle_tun(!ui.get_tun_enabled());
                else if (id == "toggle:sysproxy") ui.invoke_toggle_system_proxy(!ui.get_system_proxy_enabled());
                else if (id == "probe:group") {
                    if (auto g = ui.get_selected_group(); !g.empty()) ui.invoke_probe_group(g);
                } else if (id == "flush:fakeip") ui.global<nexus_ui::ControlInspectState>().invoke_flush_fakeip();
                else if (id == "flush:dns") ui.global<nexus_ui::ControlInspectState>().invoke_clear_dns_cache();
                else if (id == "reload") ui.invoke_reload_config();
                else if (id == "open:rules") { ui.set_outbound_modal_open(false); ui.set_rule_modal_tab(0); ui.set_rule_modal_open(true); }
                else if (id == "open:outbound") { ui.set_rule_modal_open(false); ui.set_outbound_modal_open(true); }
            });
        }
    };
}
