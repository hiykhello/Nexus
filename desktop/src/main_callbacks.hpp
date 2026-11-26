// Secondary UI callback wiring (groups, connections, profiles, logs, rules) included by desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    struct DesktopCallbacksContext {
        nexus_ui::AppWindow& ui;
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui;
        desktop::AsyncWorker& worker;
        desktop::AsyncWorker& probe_worker;
        desktop::CoreSupervisor& supervisor;
        desktop::IpcClient& ipc;
        desktop::HttpControlClient& http_ctrl;
        desktop::ClientDatabase* client_db;
        desktop::TelemetryStoreData& telemetry;
        std::filesystem::path const& cfg_dir;
        std::filesystem::path const& config_path;
        std::string const& fallback_sock;
        std::vector<desktop::OutboundGroupSnapshot>& cached_groups;
        std::unordered_set<std::string>& pinned_members;
        MemberModelPipeline& member_models;
        ConnectionsModelPipeline& conn_models;
        LogsModelPipeline& log_models;
        std::vector<desktop::LogEntrySnapshot>& cached_logs;
        std::mutex& logs_mu;
        std::atomic<std::uint64_t>& last_log_seq;
        std::function<void()> sync_tray;
    };

    inline auto make_tray_callbacks(
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui,
        bool& window_visible,
        std::function<void()>& sync_tray,
        std::function<void()>& on_window_shown,
        std::function<void()>& on_window_hidden,
        std::atomic<bool>& quit_once) -> desktop::TrayCallbacks {
        return {
            .on_show = [weak_ui, &window_visible, &sync_tray, &on_window_shown] {
                on_ui_thread(weak_ui, [&window_visible, &sync_tray, &on_window_shown](auto& s) {
                    s->window().show();
                    window_visible = true;
                    if (on_window_shown) on_window_shown();
                    if (sync_tray) sync_tray();
                });
            },
            .on_toggle_window = [weak_ui, &window_visible, &sync_tray, &on_window_shown, &on_window_hidden] {
                on_ui_thread(weak_ui, [&window_visible, &sync_tray, &on_window_shown, &on_window_hidden](auto& s) {
                    if (window_visible && s->window().is_visible()) {
                        s->window().hide();
                        window_visible = false;
                        if (on_window_hidden) on_window_hidden();
                    } else {
                        s->window().show();
                        window_visible = true;
                        if (on_window_shown) on_window_shown();
                    }
                    if (sync_tray) sync_tray();
                });
            },
            .on_toggle_core = [weak_ui] { on_ui_thread(weak_ui, [](auto& s) { s->invoke_toggle_core(); }); },
            .on_switch_mode = [weak_ui](std::string mode) {
                on_ui_thread(weak_ui, [mode = std::move(mode)](auto& s) { s->invoke_switch_outbound_mode(slint::SharedString(mode)); });
            },
            .on_toggle_system_proxy = [weak_ui](bool on) {
                on_ui_thread(weak_ui, [on](auto& s) { s->invoke_toggle_system_proxy(on); });
            },
            .on_toggle_tun = [weak_ui](bool on) {
                on_ui_thread(weak_ui, [on](auto& s) { s->invoke_toggle_tun(on); });
            },
            .on_select_node = [weak_ui](std::string group, std::string member) {
                on_ui_thread(weak_ui, [group = std::move(group), member = std::move(member)](auto& s) {
                    s->invoke_select_member(slint::SharedString(group), slint::SharedString(member));
                });
            },
            .on_activate_profile = [weak_ui](std::string id) {
                on_ui_thread(weak_ui, [id = std::move(id)](auto& s) { s->invoke_activate_profile(slint::SharedString(id)); });
            },
            .on_probe_active_group = [weak_ui] {
                on_ui_thread(weak_ui, [](auto& s) {
                    if (auto g = s->get_selected_group(); !g.empty()) s->invoke_probe_group(g);
                });
            },
            .on_copy_proxy_env = [weak_ui] { on_ui_thread(weak_ui, [](auto& s) { s->invoke_copy_proxy_env(); }); },
            .on_reload = [weak_ui] { on_ui_thread(weak_ui, [](auto& s) { s->invoke_reload_config(); }); },
            .on_quit = [&quit_once] {
                if (!quit_once.exchange(true, std::memory_order_acq_rel))
                    slint::invoke_from_event_loop([] { slint::quit_event_loop(); });
            },
            .on_flush_fakeip = [weak_ui] {
                on_ui_thread(weak_ui, [](auto& s) { s->template global<nexus_ui::ControlInspectState>().invoke_flush_fakeip(); });
            },
            .on_clear_dns_cache = [weak_ui] {
                on_ui_thread(weak_ui, [](auto& s) { s->template global<nexus_ui::ControlInspectState>().invoke_clear_dns_cache(); });
            },
        };
    }

    inline auto bind_secondary_callbacks(DesktopCallbacksContext& ctx) -> void {
        auto push_group_models = [&ctx](std::vector<desktop::OutboundGroupSnapshot> snapshot, std::string active_tag) {
            on_ui_thread(ctx.weak_ui, [&ctx, snapshot = std::move(snapshot), active_tag = std::move(active_tag)](auto& s) mutable {
                push_group_snapshot_to_ui(
                    *s, ctx.cached_groups, std::move(snapshot), std::move(active_tag), ctx.member_models,
                    std::string_view(s->get_member_filter()), std::string_view(s->get_member_sort()), &ctx.pinned_members);
                if (ctx.sync_tray) ctx.sync_tray();
            });
        };

        ctx.ui.on_filter_members([&ctx](slint::SharedString q) {
            ctx.member_models.set_filter(std::string_view(q));
        });
        ctx.ui.on_sort_members([&ctx](slint::SharedString mode) {
            ctx.member_models.set_sort(std::string_view(mode));
        });
        ctx.ui.on_hide_timeout_changed([&ctx](bool hide) {
            ctx.member_models.set_hide_timeout(hide);
        });
        ctx.ui.on_toggle_pin_member([&ctx, push_group_models](slint::SharedString group, slint::SharedString member) {
            std::string key = std::string(group) + "::" + std::string(member);
            if (!ctx.pinned_members.erase(key)) ctx.pinned_members.insert(std::move(key));
            push_group_models(ctx.cached_groups, std::string(group));
        });
        ctx.ui.on_refresh_groups([&ctx, push_group_models] {
            ctx.worker.post([&ctx, push_group_models] {
                if (auto reply = ctx.http_ctrl.outbounds(); reply.ok)
                    push_group_models(desktop::parse_outbounds_json(reply.body), "");
            });
        });
        ctx.ui.on_choose_group([&ctx, push_group_models](slint::SharedString tag) {
            push_group_models(ctx.cached_groups, std::string(tag));
        });
        ctx.ui.on_select_member([&ctx, push_group_models](slint::SharedString group, slint::SharedString member) {
            std::string g(group), m(member);
            ctx.worker.post([&ctx, push_group_models, g = std::move(g), m = std::move(m)] {
                if (!ctx.http_ctrl.select_group(g, m).ok) (void)ctx.ipc.select_outbound(g, m);
                if (auto reply = ctx.http_ctrl.outbounds(); reply.ok)
                    push_group_models(desktop::parse_outbounds_json(reply.body), g);
            });
        });
        ctx.ui.on_reset_group_auto([&ctx, push_group_models](slint::SharedString group) {
            std::string g(group);
            ctx.worker.post([&ctx, push_group_models, g = std::move(g)] {
                (void)ctx.http_ctrl.reset_group_auto(g);
                if (auto reply = ctx.http_ctrl.outbounds(); reply.ok)
                    push_group_models(desktop::parse_outbounds_json(reply.body), g);
            });
        });
        ctx.ui.on_probe_group([&ctx, push_group_models](slint::SharedString group) {
            std::string g(group);
            ctx.ui.set_groups_probing(true);
            bool posted = ctx.worker.post([&ctx, push_group_models, g = std::move(g)] {
                (void)ctx.http_ctrl.probe_group(g);
                if (auto reply = ctx.http_ctrl.outbounds(); reply.ok)
                    push_group_models(desktop::parse_outbounds_json(reply.body), g);
                on_ui_thread(ctx.weak_ui, [](auto& s) { s->set_groups_probing(false); });
            });
            if (!posted) ctx.ui.set_groups_probing(false);
        });

        auto push_connections = [&ctx](std::vector<desktop::ActiveConnectionSnapshot> parsed) {
            on_ui_thread(ctx.weak_ui, [&ctx, parsed = std::move(parsed)](auto&) mutable {
                ctx.conn_models.replace(std::move(parsed));
            });
        };
        ctx.ui.on_filter_connections([&ctx](slint::SharedString q) {
            ctx.conn_models.set_filter(std::string(q));
        });
        ctx.ui.on_route_filter_changed([&ctx](int rf) {
            ctx.conn_models.set_route_filter(rf);
        });
        ctx.ui.on_refresh_connections([&ctx, push_connections] {
            ctx.worker.post([&ctx, push_connections] {
                if (auto reply = ctx.http_ctrl.connections(); reply.ok)
                    push_connections(desktop::parse_connections_json(reply.body));
            });
        });
        auto inspect_seq = std::make_shared<std::atomic<std::uint64_t>>(0);
        ctx.ui.on_inspect_connection([&ctx, inspect_seq](slint::SharedString id_str) {
            auto seq = inspect_seq->fetch_add(1, std::memory_order_acq_rel) + 1;
            std::string_view sv(id_str);
            if (sv.empty()) return;
            std::uint64_t id = 0;
            auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), id);
            if (ec != std::errc{} || id == 0) return;
            bool en = is_en_ui(ctx.ui);
            ctx.worker.post([&ctx, inspect_seq, seq, id, en] {
                auto reply = ctx.http_ctrl.connection_detail(id);
                std::string detail;
                if (reply.ok) {
                    if (auto c = desktop::parse_connection_detail_json(reply.body))
                        detail = format_connection_detail(*c, en);
                } else {
                    detail = tr(en, "查询连接详情失败: ", "Connection detail error: ") + reply.body;
                }
                on_ui_thread(ctx.weak_ui, [inspect_seq, seq, detail = std::move(detail)](auto& s) {
                    if (inspect_seq->load(std::memory_order_acquire) != seq) return;
                    s->set_selected_connection_detail(slint::SharedString(detail));
                });
            });
        });
        ctx.ui.on_close_connection([&ctx, push_connections, inspect_seq](slint::SharedString id_str) {
            inspect_seq->fetch_add(1, std::memory_order_acq_rel);
            std::uint64_t id = 0;
            std::string_view sv(id_str);
            auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), id);
            if (ec != std::errc{} || id == 0) return;
            ctx.worker.post([&ctx, push_connections, id] {
                (void)ctx.http_ctrl.close_connection(id);
                if (auto reply = ctx.http_ctrl.connections(); reply.ok)
                    push_connections(desktop::parse_connections_json(reply.body));
            });
        });
        ctx.ui.on_close_all_connections([&ctx, push_connections, inspect_seq] {
            inspect_seq->fetch_add(1, std::memory_order_acq_rel);
            ctx.worker.post([&ctx, push_connections] {
                (void)ctx.http_ctrl.close_all_connections();
                if (auto reply = ctx.http_ctrl.connections(); reply.ok)
                    push_connections(desktop::parse_connections_json(reply.body));
            });
        });

        // Wave 25 ad-hoc endpoint connectivity probe via POST /v1/outbounds/{tag}/probe (runs on dedicated probe_worker)
        ctx.ui.on_probe_connectivity([&ctx] {
            if (!ctx.supervisor.running() || ctx.ui.get_conn_probe_busy()) return;
            std::string tag(ctx.ui.get_selected_group());
            if (tag.empty()) tag = "proxy";
            std::string active_pid = ctx.telemetry.active_profile_id;
            ctx.ui.set_conn_probe_busy(true);
            bool posted = ctx.probe_worker.post([&ctx, tag = std::move(tag), active_pid = std::move(active_pid)]() mutable {
                auto run_one = [&](std::string_view url, bool& used_direct) -> desktop::OutboundProbeResult {
                    auto rep = ctx.http_ctrl.probe_outbound(tag, url, 4000, "http");
                    if (!rep.ok && rep.status_code == 404 && tag != "direct") {
                        used_direct = true;
                        rep = ctx.http_ctrl.probe_outbound("direct", url, 4000, "http");
                    }
                    return rep.ok ? desktop::parse_outbound_probe_json(rep.body) : desktop::OutboundProbeResult{};
                };
                bool g_direct = false, c_direct = false, h_direct = false;
                auto r_google = run_one("https://www.gstatic.com/generate_204", g_direct);
                auto r_cf = run_one("https://cp.cloudflare.com/generate_204", c_direct);
                auto r_gh = run_one("https://api.github.com", h_direct);
                int g_ms = r_google.ok ? static_cast<int>(std::max<std::int64_t>(1, r_google.latency_ms)) : 0;
                int c_ms = r_cf.ok ? static_cast<int>(std::max<std::int64_t>(1, r_cf.latency_ms)) : 0;
                int h_ms = r_gh.ok ? static_cast<int>(std::max<std::int64_t>(1, r_gh.latency_ms)) : 0;
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                bool const record_active = !g_direct && tag != "direct" && !active_pid.empty();
                if (record_active && ctx.client_db) {
                    std::int64_t prev_ewma = -1;
                    if (auto rows = ctx.client_db->load_node_telemetry(); rows) {
                        for (auto const& r : *rows) {
                            if (r.profile_id == active_pid) { prev_ewma = r.ewma_ms; break; }
                        }
                    }
                    std::int64_t const next_ewma = g_ms > 0
                        ? (prev_ewma > 0 ? (prev_ewma * 7 + static_cast<std::int64_t>(g_ms) * 3) / 10 : static_cast<std::int64_t>(g_ms))
                        : prev_ewma;
                    (void)ctx.client_db->upsert_node_telemetry({
                        active_pid, static_cast<std::int64_t>(g_ms), next_ewma, r_google.status_code,
                        r_google.ok ? "healthy" : (r_google.state.empty() ? "timeout" : r_google.state), now_ms,
                    });
                }
                on_ui_thread(ctx.weak_ui, [&ctx, record_active, active_pid = std::move(active_pid), now_ms, g_ms, c_ms, h_ms](auto& s) {
                    if (record_active) {
                        bool updated = false;
                        for (auto& e : ctx.telemetry.entries) {
                            if (e.profile_id == active_pid) { e.delay_ms = g_ms; e.last_tested_ms = now_ms; updated = true; break; }
                        }
                        if (!updated) ctx.telemetry.entries.push_back({.profile_id = active_pid, .delay_ms = g_ms, .last_tested_ms = now_ms});
                    }
                    s->set_conn_google_ms(g_ms);
                    s->set_conn_cf_ms(c_ms);
                    s->set_conn_github_ms(h_ms);
                    s->set_conn_probe_busy(false);
                });
            });
            if (!posted) ctx.ui.set_conn_probe_busy(false);
        });

        ctx.ui.on_reload_config_from_disk([&ctx] {
            bool en = is_en_ui(ctx.ui);
            ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "正在从磁盘读取并校验...", "Reading & validating config from disk...")));
            ctx.worker.post([&ctx, en] {
                auto disk_kdl = read_file_text(ctx.config_path);
                if (disk_kdl.empty()) {
                    auto msg = tr(en, "无法读取磁盘配置文件", "Failed to read config file from disk");
                    on_ui_thread(ctx.weak_ui, [msg = std::move(msg)](auto& s) {
                        s->set_diagnostic_ok(false);
                        s->set_diagnostic_message(slint::SharedString(msg));
                        push_toast(*s, msg, "error");
                    });
                    return;
                }
                auto val = validate_draft_config(ctx.cfg_dir, ctx.supervisor, disk_kdl, en);
                if (!val.ok) {
                    auto msg = tr(en, "磁盘配置校验失败: ", "Disk config invalid: ") + val.message;
                    on_ui_thread(ctx.weak_ui, [msg = std::move(msg)](auto& s) {
                        s->set_diagnostic_ok(false);
                        s->set_diagnostic_message(slint::SharedString(msg));
                        push_toast(*s, msg, "error");
                    });
                    return;
                }
                bool was_running = ctx.supervisor.running();
                desktop::IpcReply reply{true, "OK"};
                if (was_running) {
                    reply = ctx.ipc.reload();
                    if (!reply.ok && ctx.http_ctrl.reload().ok) reply = {true, "OK"};
                }
                if (!was_running || reply.ok) {
                    auto next_ctl = parse_control_config(disk_kdl, ctx.fallback_sock, ctx.cfg_dir);
                    ctx.ipc.set_endpoint(next_ctl.socket);
                    ctx.http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                    ctx.http_ctrl.set_bearer_token(next_ctl.bearer_token);
                }
                auto msg = reply.ok
                    ? tr(en, "已从磁盘校验并重载配置", "Reloaded config from disk")
                    : (tr(en, "磁盘配置已读取，但热重载失败: ", "Read disk config; reload failed: ") + reply.body);
                on_ui_thread(ctx.weak_ui, [&ctx, ok = reply.ok, disk_kdl = std::move(disk_kdl), msg = std::move(msg)](auto& s) {
                    apply_kdl_to_ui_state(*s, disk_kdl);
                    s->set_diagnostic_ok(ok);
                    s->set_diagnostic_message(slint::SharedString(msg));
                    if (ctx.sync_tray) ctx.sync_tray();
                    push_toast(*s, msg, ok ? "success" : "error");
                });
            });
        });

        ctx.ui.on_apply_log_level([&ctx](slint::SharedString level) {
            bool en = is_en_ui(ctx.ui);
            std::string lvl(level);
            std::string dom(ctx.ui.get_log_domain_filter());
            if (dom.empty() || dom == "all") dom = "global";
            ctx.worker.post([&ctx, en, lvl = std::move(lvl), dom = std::move(dom)] {
                auto http_res = ctx.http_ctrl.set_log_level(lvl, dom);
                bool ok = http_res.ok || (dom == "global" && ctx.ipc.set_log_level(lvl).ok);
                auto msg = ok ? tr(en, "日志级别已更新", "Log level updated") : http_res.body;
                on_ui_thread(ctx.weak_ui, [ok, msg = std::move(msg)](auto& s) {
                    push_toast(*s, msg, ok ? "success" : "error");
                    if (ok) s->invoke_refresh_logs();
                });
            });
        });
        ctx.ui.on_log_sev_filter_changed([&ctx](slint::SharedString sev) {
            ctx.log_models.set_sev_filter(std::string(sev));
        });
        ctx.ui.on_filter_logs_search([&ctx](slint::SharedString q) {
            ctx.log_models.set_search(std::string_view(q));
        });
        ctx.ui.on_refresh_logs([&ctx] {
            std::string domain(ctx.ui.get_log_domain_filter()), search(ctx.ui.get_log_search()), level(ctx.ui.get_log_level());
            ctx.log_models.set_domain_filter(domain);
            ctx.log_models.set_search(search);
            ctx.worker.post([&ctx, level = std::move(level), domain = std::move(domain), search = std::move(search)] {
                auto reply = ctx.http_ctrl.logs(level, domain, search, 0, 200);
                if (!reply.ok) return;
                auto snap = desktop::parse_logs_json(reply.body);
                std::uint64_t latest = snap.latest_seq;
                if (latest == 0 && !snap.entries.empty()) latest = snap.entries.back().seq;
                if (latest > 0) {
                    auto prev = ctx.last_log_seq.load(std::memory_order_acquire);
                    while (latest > prev &&
                           !ctx.last_log_seq.compare_exchange_weak(prev, latest, std::memory_order_acq_rel)) {}
                }
                { std::lock_guard lock(ctx.logs_mu); ctx.cached_logs = snap.entries; }
                on_ui_thread(ctx.weak_ui, [&ctx, entries = std::move(snap.entries)](auto&) mutable {
                    ctx.log_models.replace(std::move(entries));
                });
            });
        });
        ctx.ui.on_export_logs([&ctx] {
            bool en = is_en_ui(ctx.ui);
            ctx.worker.post([&ctx, en] {
                std::string body;
                { std::lock_guard lock(ctx.logs_mu); body = format_logs_snapshot(ctx.cached_logs); }
                auto out_path = ctx.cfg_dir / "logs-snapshot.txt";
                bool ok = !body.empty() && write_file_atomic(out_path, body);
                auto msg = ok ? (tr(en, "已导出日志快照: ", "Exported logs: ") + out_path.string())
                              : tr(en, "暂无可导出的日志快照", "No logs to export");
                on_ui_thread(ctx.weak_ui, [ok, msg = std::move(msg)](auto& s) {
                    s->set_log_export_ok(ok);
                    s->set_log_export_status(slint::SharedString(msg));
                });
            });
        });
        ctx.ui.on_clear_logs([&ctx] {
            { std::lock_guard lock(ctx.logs_mu); ctx.cached_logs.clear(); }
            ctx.log_models.clear();
        });
        ctx.ui.on_run_rule_explain([&ctx](slint::SharedString inb, slint::SharedString net, slint::SharedString tgt, slint::SharedString extra) {
            std::string i(inb), n(net), t(tgt), e(extra), kdl(ctx.ui.get_kdl_text());
            ctx.worker.post([&ctx, i = std::move(i), n = std::move(n), t = std::move(t), e = std::move(e), kdl = std::move(kdl)] {
                auto draft = ctx.cfg_dir / ".explain-draft.kdl";
                auto target_cfg = (!kdl.empty() && write_file_atomic(draft, kdl)) ? draft : ctx.config_path;
                auto res = ctx.supervisor.explain_rule(target_cfg, i, n, t, e);
                if (target_cfg == draft) { std::error_code ec; std::filesystem::remove(draft, ec); }
                on_ui_thread(ctx.weak_ui, [ok = res.ok, msg = std::move(res.message)](auto& s) {
                    s->set_explain_ok(ok);
                    s->set_explain_result(slint::SharedString(msg));
                });
            });
        });

        auto apply_kdl_edit = [&ctx](std::pair<bool, std::string> res, std::string_view label) {
            bool en = is_en_ui(ctx.ui);
            ctx.ui.set_diagnostic_ok(res.first);
            if (!res.first) {
                ctx.ui.set_diagnostic_message(slint::SharedString(res.second));
                push_toast(ctx.ui, res.second, "error");
                return;
            }
            ctx.ui.set_kdl_text(slint::SharedString(res.second));
            ctx.ui.set_kdl_line_count(count_kdl_lines(res.second));
            ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "已写入规则片段到配置: ", "Inserted snippet: ") + std::string(label)));
            ctx.ui.invoke_save_and_reload(slint::SharedString(res.second));
        };
        ctx.ui.on_append_route_rule_kdl([&ctx, apply_kdl_edit](slint::SharedString rule_block) {
            apply_kdl_edit(desktop::insert_route_rule_kdl(std::string_view(ctx.ui.get_kdl_text()), std::string_view(rule_block)), "route");
        });
        ctx.ui.on_append_dns_rule_kdl([&ctx, apply_kdl_edit](slint::SharedString rule_line) {
            apply_kdl_edit(desktop::insert_dns_rule_kdl(std::string_view(ctx.ui.get_kdl_text()), std::string_view(rule_line)), "dns");
        });
        ctx.ui.on_append_raw_kdl([&ctx, apply_kdl_edit](slint::SharedString snippet) {
            apply_kdl_edit({true, desktop::merge_raw_kdl_snippet(std::string_view(ctx.ui.get_kdl_text()), std::string_view(snippet))}, "outbound");
        });

        ctx.ui.on_create_rule_from_connection([&ctx](slint::SharedString target, int port, slint::SharedString proto, slint::SharedString outbound, slint::SharedString rule_action) {
            std::string active_proxy(ctx.ui.get_selected_group());
            if (active_proxy.empty() && !ctx.cached_groups.empty()) active_proxy = ctx.cached_groups.front().tag;
            if (active_proxy.empty()) active_proxy = "proxy";
            auto draft = desktop::extract_rule_match_from_connection(
                std::string_view(target), port, std::string_view(proto), std::string_view(outbound), active_proxy, std::string_view(rule_action));
            ctx.ui.set_route_rule_kind(slint::SharedString(draft.kind));
            ctx.ui.set_route_match_value(slint::SharedString(draft.value));
            ctx.ui.set_route_rule_action(slint::SharedString(draft.action));
            if (!draft.outbound.empty()) ctx.ui.set_route_target_outbound(slint::SharedString(draft.outbound));
            ctx.ui.set_rule_modal_tab(0);
            ctx.ui.set_rule_modal_open(true);
            push_toast(ctx.ui,
                tr(is_en_ui(ctx.ui), "已带入连接目标到分流规则编辑器: ", "Pre-filled rule editor for: ") + draft.value,
                "info");
        });
    }

    inline auto bind_dash_layout_callbacks(nexus_ui::AppWindow& ui, std::function<void()> persist) -> void {
        ui.on_dash_prefs_changed(persist);
        ui.on_reorder_dash_section([&ui, persist](int from_id, int to_id) {
            auto ord = read_dash_order_model(ui.get_dash_section_order());
            if (desktop::reorder_dash_slots(ord, from_id, to_id)) {
                ui.set_dash_section_order(make_dash_order_model(ord));
                persist();
            }
        });
        ui.on_reorder_dash_info([&ui, persist](int from_id, int to_id) {
            auto ord = read_dash_order_model(ui.get_dash_info_order());
            if (desktop::reorder_dash_slots(ord, from_id, to_id)) {
                ui.set_dash_info_order(make_dash_order_model(ord));
                persist();
            }
        });
        ui.on_swap_dash_deck([&ui, persist] {
            ui.set_dash_deck_swapped(!ui.get_dash_deck_swapped());
            persist();
        });
        ui.on_reset_dash_layout([&ui, persist] {
            ui.set_dash_show_speed(true); ui.set_dash_show_quick_nodes(true);
            ui.set_dash_show_network(true); ui.set_dash_show_memory(true);
            ui.set_dash_show_traffic(true); ui.set_dash_show_ports(true);
            ui.set_dash_show_connectivity(true);
            ui.set_dash_section_order(make_dash_order_model({0, 1, 2, 3}));
            ui.set_dash_info_order(make_dash_order_model({0, 1, 2, 3}));
            ui.set_dash_deck_swapped(false);
            persist();
            push_toast(ui, tr(is_en_ui(ui), "已恢复默认概览布局", "Dashboard layout reset"), "info");
        });
    }
}
