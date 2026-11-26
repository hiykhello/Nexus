// Wave 30-33 Live Control API inspection callbacks (GET /v1/rules, GET /v1/dns/query, FakeIP/DNS flush,
// per-node POST /v1/outbounds/{tag}/probe, and multiplexed RFC 6455 /v1/ws with transparent SSE fallback).
#pragma once

namespace desktop_ui_helpers {
    struct LiveInspectController {
        nexus_ui::AppWindow& ui;
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui;
        desktop::AsyncWorker& worker;
        desktop::AsyncWorker& probe_worker;
        desktop::CoreSupervisor& supervisor;
        desktop::HttpControlClient& http_ctrl;
        desktop::TrayController& tray;
        std::vector<desktop::OutboundGroupSnapshot>& cached_groups;
        std::unordered_set<std::string>& pinned_members;
        MemberModelPipeline& member_models;
        ConnectionsModelPipeline& conn_models;
        LogsModelPipeline& log_models;
        RateTracker& rate_tracker;
        std::vector<desktop::LogEntrySnapshot>& cached_logs;
        std::mutex& logs_mu;
        std::atomic<std::uint64_t>& last_log_seq;
        std::function<void()>& sync_tray;
        std::function<void(std::uint64_t, std::uint64_t)> on_traffic_totals;

        std::vector<desktop::RuleEntrySnapshot> cached_rules;
        std::shared_ptr<slint::VectorModel<nexus_ui::LiveRuleRow>> rules_model =
            std::make_shared<slint::VectorModel<nexus_ui::LiveRuleRow>>();
        std::shared_ptr<slint::VectorModel<nexus_ui::DnsAnswerRow>> dns_answers_model =
            std::make_shared<slint::VectorModel<nexus_ui::DnsAnswerRow>>();

        std::mutex stream_mu;
        std::stop_source stream_stop;
        std::thread stream_thread;
        bool stream_active = false;
        std::atomic<bool> ws_connected{false};
        std::atomic<bool> ws_rejected{false};
        std::atomic<std::uint64_t> last_endpoint_gen{0};
        std::atomic<bool> logs_stream_enabled{true};

        ~LiveInspectController() { stop_log_stream(); }

        [[nodiscard]] auto ws_live() const noexcept -> bool {
            return ws_connected.load(std::memory_order_acquire);
        }

        auto reset_ws_fallback() -> void {
            ws_rejected.store(false, std::memory_order_release);
            last_endpoint_gen.store(http_ctrl.endpoint_generation(), std::memory_order_release);
        }

        auto ingest_live_log(desktop::LogEntrySnapshot entry) -> void {
            if (entry.seq > 0) {
                auto prev = last_log_seq.load(std::memory_order_acquire);
                while (entry.seq > prev &&
                       !last_log_seq.compare_exchange_weak(prev, entry.seq, std::memory_order_acq_rel)) {}
            }
            bool inserted = false;
            {
                std::lock_guard lk_logs(logs_mu);
                bool const dup = entry.seq > 0 && std::ranges::any_of(cached_logs, [&](auto const& existing) {
                    return existing.seq == entry.seq;
                });
                if (!dup) {
                    cached_logs.push_back(entry);
                    if (cached_logs.size() > LogsModelPipeline::kMaxLogs) cached_logs.erase(cached_logs.begin());
                    inserted = true;
                }
            }
            if (inserted) {
                on_ui_thread(weak_ui, [this, entry = std::move(entry)](auto&) mutable {
                    log_models.append_live(std::move(entry));
                });
            }
        }

        auto apply_rules_filter(std::string_view query) -> void {
            auto q = lower_ascii(query);
            std::vector<nexus_ui::LiveRuleRow> rows;
            rows.reserve(cached_rules.size());
            for (auto const& r : cached_rules) {
                if (!q.empty()) {
                    auto hay = lower_ascii(r.type) + " " + lower_ascii(r.action) + " " + lower_ascii(r.target) + " " + lower_ascii(r.summary);
                    if (!hay.contains(q)) continue;
                }
                rows.push_back({
                    static_cast<int>(r.index),
                    slint::SharedString(r.type),
                    slint::SharedString(r.action),
                    slint::SharedString(r.target),
                    slint::SharedString(r.summary),
                });
            }
            sync_vector_model(*rules_model, rows);
        }

        auto stop_log_stream() -> void {
            std::thread to_join;
            {
                std::lock_guard lk(stream_mu);
                if (!stream_active && !stream_thread.joinable()) return;
                stream_active = false;
                stream_stop.request_stop();
                to_join = std::move(stream_thread);
            }
            if (to_join.joinable()) to_join.join();
            ws_connected.store(false, std::memory_order_release);
            on_ui_thread(weak_ui, [](auto& s) {
                s->template global<nexus_ui::ControlInspectState>().set_logs_stream_connected(false);
            });
        }

        auto sync_log_stream(bool core_up) -> void {
            auto const cur_gen = http_ctrl.endpoint_generation();
            auto const prev_gen = last_endpoint_gen.exchange(cur_gen, std::memory_order_acq_rel);
            bool const endpoint_changed = (cur_gen != prev_gen);
            if (!core_up) {
                ws_rejected.store(false, std::memory_order_release);
                stop_log_stream();
                return;
            }
            if (endpoint_changed) {
                ws_rejected.store(false, std::memory_order_release);
                stop_log_stream();
            }
            bool const should_run = !ws_rejected.load(std::memory_order_acquire)
                                 || logs_stream_enabled.load(std::memory_order_acquire);
            if (!should_run) {
                stop_log_stream();
                return;
            }
            std::lock_guard lk(stream_mu);
            if (stream_active) return;
            if (stream_thread.joinable()) stream_thread.join();
            stream_stop = std::stop_source{};
            auto stoken = stream_stop.get_token();
            stream_active = true;
            stream_thread = std::thread([this, stoken] {
                int backoff_ms = 1000;
                while (!stoken.stop_requested()) {
                    auto since = last_log_seq.load(std::memory_order_acquire);
                    bool connected_this_round = false;
                    if (!ws_rejected.load(std::memory_order_acquire)) {
                        auto on_ws_up = [&] {
                            connected_this_round = true;
                            backoff_ms = 1000;
                            ws_connected.store(true, std::memory_order_release);
                            on_ui_thread(weak_ui, [this](auto& s) {
                                s->template global<nexus_ui::ControlInspectState>().set_logs_stream_connected(true);
                                bool const want_rules = !cached_rules.empty() || s->get_rule_modal_open();
                                worker.post([this, want_rules] {
                                    auto gr = http_ctrl.outbounds();
                                    auto groups = gr.ok ? desktop::parse_outbounds_json(gr.body)
                                                        : std::vector<desktop::OutboundGroupSnapshot>{};
                                    std::optional<std::vector<desktop::RuleEntrySnapshot>> rules;
                                    if (want_rules) {
                                        auto rr = http_ctrl.rules();
                                        if (rr.ok) rules = desktop::parse_rules_json(rr.body);
                                    }
                                    on_ui_thread(weak_ui, [this, gr_ok = gr.ok, groups = std::move(groups),
                                                           rules = std::move(rules)](auto& s2) mutable {
                                        if (gr_ok) {
                                            push_group_snapshot_to_ui(*s2, cached_groups, std::move(groups),
                                                std::string(s2->get_selected_group()), member_models,
                                                std::string_view(s2->get_member_filter()),
                                                std::string_view(s2->get_member_sort()), &pinned_members);
                                            if (sync_tray) sync_tray();
                                        }
                                        if (rules) {
                                            cached_rules = std::move(*rules);
                                            auto const& st = s2->template global<nexus_ui::ControlInspectState>();
                                            apply_rules_filter(std::string_view(st.get_rules_filter()));
                                        }
                                    });
                                });
                            });
                        };
                        auto ws_res = http_ctrl.stream_ws({"logs", "connections", "metrics"}, [&](desktop::WsEvent const& ev) -> bool {
                            if (stoken.stop_requested()) return false;
                            if (ev.type == "log" && logs_stream_enabled.load(std::memory_order_acquire)) {
                                if (auto entry = desktop::parse_log_entry_json(ev.data_json)) ingest_live_log(std::move(*entry));
                            } else if (ev.type == "connections") {
                                auto parsed = desktop::parse_connections_json(ev.data_json);
                                on_ui_thread(weak_ui, [this, parsed = std::move(parsed)](auto& s) mutable {
                                    if (!s->get_connections_paused()) conn_models.replace(std::move(parsed));
                                });
                            } else if (ev.type == "metrics") {
                                if (auto m = desktop::parse_status_metrics_json(ev.data_json)) {
                                    on_ui_thread(weak_ui, [this, m = *m](auto& s) {
                                        apply_metrics_to_ui(*s, m, rate_tracker.record(m.upload_bytes, m.download_bytes));
                                        if (on_traffic_totals) on_traffic_totals(m.upload_bytes, m.download_bytes);
                                        if (sync_tray && s->get_tray_show_speed()) sync_tray();
                                    });
                                }
                            }
                            return !stoken.stop_requested();
                        }, stoken, since, 1000, std::chrono::milliseconds{3000}, std::chrono::milliseconds{100}, on_ws_up);
                        ws_connected.store(false, std::memory_order_release);
                        if (!ws_res && !connected_this_round &&
                            (ws_res.error().contains("404") || ws_res.error().contains("426") || ws_res.error().contains("405"))) {
                            ws_rejected.store(true, std::memory_order_release);
                        }
                    }
                    if (ws_rejected.load(std::memory_order_acquire) && !stoken.stop_requested()) {
                        if (!logs_stream_enabled.load(std::memory_order_acquire)) break;
                        auto on_sse_up = [&] {
                            backoff_ms = 1000;
                            on_ui_thread(weak_ui, [](auto& s) {
                                s->template global<nexus_ui::ControlInspectState>().set_logs_stream_connected(true);
                            });
                        };
                        (void)http_ctrl.stream_logs_sse([&](desktop::SseEvent const& ev) -> bool {
                            if (stoken.stop_requested()) return false;
                            if ((ev.event == "log" || ev.event == "message") && logs_stream_enabled.load(std::memory_order_acquire)) {
                                if (auto entry = desktop::parse_log_entry_json(ev.data)) ingest_live_log(std::move(*entry));
                            }
                            return !stoken.stop_requested();
                        }, stoken, {}, {}, {}, since, on_sse_up);
                    }
                    on_ui_thread(weak_ui, [](auto& s) {
                        s->template global<nexus_ui::ControlInspectState>().set_logs_stream_connected(false);
                    });
                    if (stoken.stop_requested()) break;
                    int slept = 0;
                    while (slept < backoff_ms && !stoken.stop_requested()) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        slept += 100;
                    }
                    backoff_ms = std::min(8000, backoff_ms * 2);
                }
                std::lock_guard lk(stream_mu);
                if (stream_stop.get_token() == stoken) stream_active = false;
            });
        }

        auto bind() -> void {
            auto const& g = ui.global<nexus_ui::ControlInspectState>();
            g.set_live_rules(rules_model);
            g.set_dns_answers(dns_answers_model);

            g.on_filter_live_rules([this](slint::SharedString q) {
                apply_rules_filter(std::string_view(q));
            });

            g.on_refresh_live_rules([this] {
                bool const en = is_en_ui(ui);
                auto const& cs = ui.global<nexus_ui::ControlInspectState>();
                if (!supervisor.running()) {
                    cs.set_rules_error(slint::SharedString(tr(en, "核心未运行", "Core is not running")));
                    return;
                }
                cs.set_rules_loading(true);
                cs.set_rules_error(slint::SharedString(""));
                bool posted = worker.post([this, en] {
                    auto rep = http_ctrl.rules();
                    auto parsed = rep.ok ? desktop::parse_rules_json(rep.body) : std::vector<desktop::RuleEntrySnapshot>{};
                    std::string err = rep.ok ? std::string{} : (tr(en, "读取运行规则失败: ", "Failed to fetch live rules: ") + rep.body);
                    on_ui_thread(weak_ui, [this, parsed = std::move(parsed), err = std::move(err)](auto& s) mutable {
                        auto const& st = s->template global<nexus_ui::ControlInspectState>();
                        st.set_rules_loading(false);
                        st.set_rules_error(slint::SharedString(err));
                        if (err.empty()) {
                            cached_rules = std::move(parsed);
                            apply_rules_filter(std::string_view(st.get_rules_filter()));
                        }
                    });
                });
                if (!posted) cs.set_rules_loading(false);
            });

            g.on_run_dns_query([this] {
                bool const en = is_en_ui(ui);
                auto const& cs = ui.global<nexus_ui::ControlInspectState>();
                std::string name(trim_ascii_ws(std::string_view(cs.get_dns_query_name())));
                std::string qtype(trim_ascii_ws(std::string_view(cs.get_dns_query_type())));
                std::string server(trim_ascii_ws(std::string_view(cs.get_dns_query_server())));
                if (name.empty()) return;
                if (!supervisor.running()) {
                    cs.set_dns_query_error(slint::SharedString(tr(en, "核心未运行", "Core is not running")));
                    return;
                }
                cs.set_dns_query_busy(true);
                cs.set_dns_query_error(slint::SharedString(""));
                bool posted = probe_worker.post([this, en, name = std::move(name), qtype = std::move(qtype), server = std::move(server)] {
                    auto rep = http_ctrl.dns_query(name, qtype.empty() ? "A" : qtype, server);
                    auto res = desktop::parse_dns_query_json(rep.body);
                    if (!rep.ok && res.error.empty()) res.error = rep.body.empty() ? std::format("HTTP {}", rep.status_code) : rep.body;
                    on_ui_thread(weak_ui, [this, en, ok = rep.ok && res.ok, res = std::move(res)](auto& s) mutable {
                        auto const& st = s->template global<nexus_ui::ControlInspectState>();
                        st.set_dns_query_busy(false);
                        if (!ok) {
                            st.set_dns_query_error(slint::SharedString(
                                res.error.empty() ? tr(en, "DNS 查询失败", "DNS query failed") : res.error));
                            st.set_dns_query_rcode(slint::SharedString(""));
                            st.set_dns_query_elapsed_ms(-1);
                            sync_vector_model(*dns_answers_model, {});
                            return;
                        }
                        st.set_dns_query_error(slint::SharedString(""));
                        st.set_dns_query_rcode(slint::SharedString(res.rcode_name.empty() ? std::to_string(res.rcode) : res.rcode_name));
                        st.set_dns_query_elapsed_ms(static_cast<int>(res.elapsed_ms));
                        st.set_dns_query_ttl(static_cast<int>(res.ttl));
                        std::vector<nexus_ui::DnsAnswerRow> rows;
                        rows.reserve(res.answers.size());
                        for (auto const& a : res.answers) {
                            rows.push_back({slint::SharedString(a.name), slint::SharedString(a.type),
                                            static_cast<int>(a.ttl), slint::SharedString(a.data)});
                        }
                        sync_vector_model(*dns_answers_model, rows);
                    });
                });
                if (!posted) cs.set_dns_query_busy(false);
            });

            g.on_flush_fakeip([this] {
                bool const en = is_en_ui(ui);
                auto const& cs = ui.global<nexus_ui::ControlInspectState>();
                if (!supervisor.running()) {
                    push_toast(ui, tr(en, "核心未运行", "Core is not running"), "warn");
                    return;
                }
                cs.set_cache_action_busy(true);
                bool posted = worker.post([this, en] {
                    auto rep = http_ctrl.flush_fakeip();
                    auto parsed = desktop::parse_fakeip_flush_json(rep.body);
                    bool const ok = rep.ok && parsed.ok;
                    std::string msg = ok
                        ? (en ? std::format("Flushed {} FakeIP entries", parsed.flushed)
                              : std::format("已清空 {} 条 FakeIP 映射", parsed.flushed))
                        : (tr(en, "清空 FakeIP 失败: ", "Flush FakeIP failed: ") + (parsed.error.empty() ? rep.body : parsed.error));
                    on_ui_thread(weak_ui, [this, ok, msg = std::move(msg)](auto& s) {
                        auto const& st = s->template global<nexus_ui::ControlInspectState>();
                        st.set_cache_action_busy(false);
                        st.set_cache_action_ok(ok);
                        st.set_cache_action_status(slint::SharedString(msg));
                        push_toast(*s, msg, ok ? "success" : "error");
                        (void)tray.notify_if_hidden("Nexus", msg,
                            ok ? desktop::TrayNotificationUrgency::info : desktop::TrayNotificationUrgency::warning);
                    });
                });
                if (!posted) cs.set_cache_action_busy(false);
            });

            g.on_clear_dns_cache([this] {
                bool const en = is_en_ui(ui);
                auto const& cs = ui.global<nexus_ui::ControlInspectState>();
                if (!supervisor.running()) {
                    push_toast(ui, tr(en, "核心未运行", "Core is not running"), "warn");
                    return;
                }
                cs.set_cache_action_busy(true);
                bool posted = worker.post([this, en] {
                    auto rep = http_ctrl.clear_cache("dns");
                    std::string msg = rep.ok
                        ? tr(en, "DNS 缓存已清除", "DNS cache cleared")
                        : (tr(en, "清除 DNS 缓存失败: ", "Clear DNS cache failed: ") + rep.body);
                    on_ui_thread(weak_ui, [this, ok = rep.ok, msg = std::move(msg)](auto& s) {
                        auto const& st = s->template global<nexus_ui::ControlInspectState>();
                        st.set_cache_action_busy(false);
                        st.set_cache_action_ok(ok);
                        st.set_cache_action_status(slint::SharedString(msg));
                        push_toast(*s, msg, ok ? "success" : "error");
                        (void)tray.notify_if_hidden("Nexus", msg,
                            ok ? desktop::TrayNotificationUrgency::info : desktop::TrayNotificationUrgency::warning);
                    });
                });
                if (!posted) cs.set_cache_action_busy(false);
            });

            g.on_probe_member([this](slint::SharedString grp_s, slint::SharedString mem_s) {
                bool const en = is_en_ui(ui);
                std::string grp(grp_s), mem(mem_s);
                if (mem.empty()) return;
                if (!supervisor.running()) {
                    push_toast(ui, tr(en, "核心未运行", "Core is not running"), "warn");
                    return;
                }
                auto const& cs = ui.global<nexus_ui::ControlInspectState>();
                cs.set_probing_member_name(slint::SharedString(mem));
                bool posted = probe_worker.post([this, en, grp = std::move(grp), mem = std::move(mem)] {
                    auto rep = http_ctrl.probe_outbound(mem, "https://www.gstatic.com/generate_204", 4000, "http");
                    auto res = desktop::parse_outbound_probe_json(rep.body);
                    on_ui_thread(weak_ui, [this, en, grp, mem, ok = rep.ok && res.ok, res](auto& s) {
                        auto const& st = s->template global<nexus_ui::ControlInspectState>();
                        if (std::string_view(st.get_probing_member_name()) == mem) {
                            st.set_probing_member_name(slint::SharedString(""));
                        }
                        auto updated = cached_groups;
                        for (auto& g_item : updated) {
                            for (auto& m_item : g_item.members) {
                                if (m_item.name != mem) continue;
                                m_item.latency_ms = ok ? std::max<std::int64_t>(1, res.latency_ms) : 0;
                                m_item.state = ok ? "healthy" : (res.state.empty() ? "timeout" : res.state);
                                m_item.last_status = res.status_code;
                            }
                        }
                        push_group_snapshot_to_ui(*s, cached_groups, std::move(updated),
                            grp.empty() ? std::string(s->get_selected_group()) : grp, member_models,
                            std::string_view(s->get_member_filter()), std::string_view(s->get_member_sort()), &pinned_members);
                        if (sync_tray) sync_tray();
                        auto msg = ok
                            ? std::format("{}: {} ms", mem, std::max<std::int64_t>(1, res.latency_ms))
                            : std::format("{}: {}", mem, res.error.empty() ? tr(en, "测速超时", "Probe timed out") : res.error);
                        push_toast(*s, msg, ok ? "success" : "warn");
                    });
                });
                if (!posted) cs.set_probing_member_name(slint::SharedString(""));
            });

            g.on_toggle_logs_stream([this](bool enabled) {
                logs_stream_enabled.store(enabled, std::memory_order_release);
                if (!ws_live()) sync_log_stream(supervisor.running());
            });
        }
    };
}
