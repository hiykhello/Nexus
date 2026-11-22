#include "app_window.h"

#ifdef _WIN32
#include <shellapi.h>
#else
#include <unistd.h>
#endif

import std;
import desktop.async_worker;
import desktop.core_supervisor;
import desktop.http_control;
import desktop.ipc_client;
import desktop.profile_store;
import desktop.share_link;
import desktop.single_instance;
import desktop.system_proxy;
import desktop.tray_controller;

#include "main_helpers.hpp"

using desktop_ui_helpers::default_config_dir;
using desktop_ui_helpers::default_control_endpoint;
using desktop_ui_helpers::open_with_system_editor;
using desktop_ui_helpers::read_file_text;
using desktop_ui_helpers::write_file_atomic;

auto main(int argc, char** argv) -> int {
    (void)argc;
    auto cfg_dir = default_config_dir();
    std::filesystem::create_directories(cfg_dir);
    auto config_path = cfg_dir / "config.kdl";
    auto binary_path = std::filesystem::path(argv[0]).parent_path() /
#ifdef _WIN32
        "nexus.exe";
#else
        "nexus";
#endif

    auto ui = nexus_ui::AppWindow::create();
    auto weak_ui = ui->as_weak();

    auto instance = desktop::SingleInstanceGuard::acquire("nexus-desktop", [weak_ui] {
        slint::invoke_from_event_loop([weak_ui] {
            if (auto strong = weak_ui.lock()) strong->show();
        });
    });
    if (!instance) return 0;

    desktop::CoreSupervisor supervisor(binary_path);
    desktop::IpcClient ipc(default_control_endpoint(cfg_dir));
    desktop::HttpControlClient http_ctrl("127.0.0.1", 9090);
    desktop::SystemProxyController sys_proxy;
    desktop::AsyncWorker worker;
    desktop::ProfileStore profile_store(cfg_dir);
    std::vector<desktop::OutboundGroupSnapshot> cached_groups;
    std::vector<desktop::LogRingEntry> cached_logs;
    std::mutex logs_mu;
    desktop_ui_helpers::RateTracker rate_tracker;

    ui->set_system_proxy_supported(desktop::SystemProxyController::supported());
    ui->set_control_endpoint(slint::SharedString(ipc.endpoint()));
    ui->set_config_path(slint::SharedString(config_path.string()));
    auto initial_kdl = read_file_text(config_path);
    ui->set_kdl_text(slint::SharedString(initial_kdl));
    ui->set_tun_enabled(desktop_ui_helpers::kdl_has_tun_inbound(initial_kdl));

    std::atomic<bool> quit_once{false};
    desktop::TrayController tray({
        .on_show = [weak_ui] { slint::invoke_from_event_loop([weak_ui] { if (auto s = weak_ui.lock()) s->show(); }); },
        .on_reload = [weak_ui] { slint::invoke_from_event_loop([weak_ui] { if (auto s = weak_ui.lock()) s->invoke_reload_config(); }); },
        .on_quit = [&quit_once] {
            if (!quit_once.exchange(true, std::memory_order_acq_rel))
                slint::invoke_from_event_loop([] { slint::quit_event_loop(); });
        },
    });
    auto sync_tray = [&] {
        bool running = supervisor.running(), tun = ui->get_tun_enabled();
        tray.set_status(running ? (tun ? desktop::TrayState::tun_active : desktop::TrayState::running)
                                : desktop::TrayState::offline,
                        std::string_view(ui->get_status_summary()));
    };

    ui->on_toggle_core([&] {
        ui->set_status_summary("正在切换核心状态...");
        worker.post([&, weak_ui] {
            bool running = false;
            std::string summary;
            if (supervisor.running()) {
                (void)sys_proxy.restore();
                supervisor.stop();
                running = false;
                summary = "已停止";
            } else if (supervisor.start(config_path)) {
                running = true;
                summary = "运行中";
            } else {
                running = false;
                summary = "启动失败：请检查 nexus 二进制与配置";
            }
            slint::invoke_from_event_loop([weak_ui, running, summary = std::move(summary)] {
                if (auto strong = weak_ui.lock()) {
                    strong->set_core_running(running);
                    if (!running) strong->set_system_proxy_enabled(false);
                    strong->set_status_summary(slint::SharedString(summary));
                    sync_tray();
                }
            });
        });
    });

    ui->on_toggle_system_proxy([&](bool on) {
        worker.post([&, weak_ui, on] {
            bool ok = on ? sys_proxy.enable("127.0.0.1", 7890) : sys_proxy.restore();
            slint::invoke_from_event_loop([weak_ui, active = ok && on] {
                if (auto strong = weak_ui.lock()) strong->set_system_proxy_enabled(active);
            });
        });
    });

    ui->on_toggle_tun([&](bool on) {
        auto res = desktop_ui_helpers::toggle_tun_in_kdl(std::string_view(ui->get_kdl_text()), on);
        if (!res.first) { ui->set_status_summary(slint::SharedString(res.second)); ui->set_tun_enabled(!on); return; }
        ui->set_kdl_text(slint::SharedString(res.second));
        ui->set_tun_enabled(on);
        ui->invoke_save_and_reload(slint::SharedString(res.second));
        sync_tray();
    });

    ui->on_reload_config([&] {
        ui->set_status_summary("正在热重载...");
        worker.post([&, weak_ui] {
            auto reply = ipc.reload();
            auto msg = reply.ok ? std::string("热重载成功") : ("热重载失败: " + reply.body);
            slint::invoke_from_event_loop([weak_ui, msg = std::move(msg)] {
                if (auto strong = weak_ui.lock()) strong->set_status_summary(slint::SharedString(msg));
            });
        });
    });

    ui->on_validate_kdl([&](slint::SharedString text) {
        std::string payload(text);
        ui->set_diagnostic_message("正在调用内核校验...");
        worker.post([&, weak_ui, payload = std::move(payload)] {
            auto tmp = cfg_dir / ".validate-draft.kdl";
            desktop::ValidationResult res{false, "无法写入临时校验文件"};
            if (write_file_atomic(tmp, payload)) {
                res = supervisor.validate_config(tmp);
                std::error_code ec;
                std::filesystem::remove(tmp, ec);
            }
            slint::invoke_from_event_loop([weak_ui, ok = res.ok, msg = std::move(res.message)] {
                if (auto s = weak_ui.lock()) { s->set_diagnostic_ok(ok); s->set_diagnostic_message(slint::SharedString(msg)); }
            });
        });
    });

    ui->on_save_and_reload([&](slint::SharedString text) {
        std::string payload(text);
        ui->set_diagnostic_message("正在校验并保存...");
        worker.post([&, weak_ui, payload = std::move(payload)] {
            auto tmp = cfg_dir / ".validate-draft.kdl";
            if (!write_file_atomic(tmp, payload)) {
                slint::invoke_from_event_loop([weak_ui] {
                    if (auto s = weak_ui.lock()) { s->set_diagnostic_ok(false); s->set_diagnostic_message("保存临时文件失败"); }
                });
                return;
            }
            auto res = supervisor.validate_config(tmp);
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            if (!res.ok) {
                slint::invoke_from_event_loop([weak_ui, msg = "拒绝下发无效配置: " + res.message] {
                    if (auto s = weak_ui.lock()) { s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(msg)); }
                });
                return;
            }
            bool saved = write_file_atomic(config_path, payload);
            auto reply = saved && supervisor.running() ? ipc.reload() : desktop::IpcReply{saved, saved ? "已保存" : "写入失败"};
            std::string msg = !saved ? "写入 config.kdl 失败"
                : (reply.ok ? "校验通过，已保存并热重载" : ("已保存，但重载失败: " + reply.body));
            slint::invoke_from_event_loop([weak_ui, ok = saved && reply.ok, msg = std::move(msg)] {
                if (auto strong = weak_ui.lock()) {
                    strong->set_diagnostic_ok(ok);
                    strong->set_diagnostic_message(slint::SharedString(msg));
                }
            });
        });
    });

    ui->on_open_external_editor([&] { open_with_system_editor(config_path); });

    ui->on_refresh_metrics([&] {
        worker.post([&, weak_ui] {
            auto reply = http_ctrl.metrics();
            if (!reply.ok) return;
            auto m = desktop::parse_openmetrics_summary(reply.body);
            auto text = std::format("代次: {} · 活跃会话: {} · 上行: {} KiB · 下行: {} KiB",
                m.control_generation, m.active_sessions, m.upload_bytes / 1024, m.download_bytes / 1024);
            auto rate = rate_tracker.record(m.upload_bytes, m.download_bytes);
            slint::invoke_from_event_loop([weak_ui, text = std::move(text), rate = std::move(rate)] {
                if (auto strong = weak_ui.lock()) {
                    strong->set_metrics_summary(slint::SharedString(text));
                    strong->set_rate_summary(slint::SharedString(rate.summary));
                    strong->set_rate_bars(std::make_shared<slint::VectorModel<float>>(rate.bars));
                }
            });
        });
    });

    ui->on_clear_cache([&] {
        worker.post([&, weak_ui] {
            auto reply = http_ctrl.clear_cache();
            auto msg = reply.ok ? std::string("缓存已清空") : ("清空缓存失败: " + reply.body);
            slint::invoke_from_event_loop([weak_ui, msg = std::move(msg)] {
                if (auto strong = weak_ui.lock()) strong->set_status_summary(slint::SharedString(msg));
            });
        });
    });

    ui->on_import_share_link([&](slint::SharedString raw_uri) {
        auto parsed = desktop::parse_share_link(std::string_view(raw_uri));
        if (!parsed) {
            ui->set_diagnostic_ok(false);
            ui->set_diagnostic_message(slint::SharedString("分享链接解析失败: " + parsed.error()));
            return;
        }
        auto secrets_dir = cfg_dir / "secrets";
        std::filesystem::create_directories(secrets_dir);
        auto secret_file = secrets_dir / (parsed->tag + ".secret");
        if (!write_file_atomic(secret_file, parsed->secret + "\n")) {
            ui->set_diagnostic_ok(false);
            ui->set_diagnostic_message("写入私密凭据文件失败");
            return;
        }
        std::error_code ec;
        std::filesystem::permissions(secret_file,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, ec);
        auto block = desktop::render_kdl_outbound(*parsed, secret_file.string());
        std::string merged(ui->get_kdl_text());
        if (!merged.empty() && merged.back() != '\n') merged.push_back('\n');
        merged += "\n" + block;
        ui->set_kdl_text(slint::SharedString(merged));
        ui->set_diagnostic_ok(true);
        ui->set_diagnostic_message(slint::SharedString("已导入节点 " + parsed->tag + "（凭据已写入 0600 文件，请校验并保存）"));
    });

    auto push_group_models = [&](std::vector<desktop::OutboundGroupSnapshot> snapshot, std::string active_tag) {
        slint::invoke_from_event_loop([weak_ui, &cached_groups, snapshot = std::move(snapshot), active_tag = std::move(active_tag)] mutable {
            auto strong = weak_ui.lock();
            if (!strong) return;
            cached_groups = std::move(snapshot);
            std::vector<nexus_ui::OutboundGroupItem> ui_groups;
            for (auto const& g : cached_groups) {
                ui_groups.push_back({
                    slint::SharedString(g.tag),
                    slint::SharedString(g.mode),
                    slint::SharedString(g.active),
                    !g.manual_override,
                });
            }
            if (active_tag.empty() && !cached_groups.empty()) active_tag = cached_groups.front().tag;
            std::vector<nexus_ui::OutboundMemberItem> ui_members;
            for (auto const& g : cached_groups) {
                if (g.tag == active_tag) {
                    for (auto const& m : g.members) {
                        ui_members.push_back({
                            slint::SharedString(m.name),
                            slint::SharedString(m.state),
                            static_cast<int>(m.latency_ms),
                            m.selected,
                            m.overridden,
                        });
                    }
                    break;
                }
            }
            strong->set_selected_group(slint::SharedString(active_tag));
            strong->set_groups(std::make_shared<slint::VectorModel<nexus_ui::OutboundGroupItem>>(std::move(ui_groups)));
            strong->set_members(std::make_shared<slint::VectorModel<nexus_ui::OutboundMemberItem>>(std::move(ui_members)));
        });
    };

    ui->on_refresh_groups([&] {
        worker.post([&, weak_ui] {
            auto reply = http_ctrl.outbounds();
            if (reply.ok) push_group_models(desktop::parse_outbounds_json(reply.body), "");
        });
    });
    ui->on_choose_group([&](slint::SharedString tag) {
        push_group_models(cached_groups, std::string(tag));
    });
    ui->on_select_member([&](slint::SharedString group, slint::SharedString member) {
        std::string g(group), m(member);
        worker.post([&, g = std::move(g), m = std::move(m)] {
            auto res = http_ctrl.select_group(g, m);
            if (!res.ok) (void)ipc.select_outbound(g, m);
            auto reply = http_ctrl.outbounds();
            if (reply.ok) push_group_models(desktop::parse_outbounds_json(reply.body), g);
        });
    });
    ui->on_reset_group_auto([&](slint::SharedString group) {
        std::string g(group);
        worker.post([&, g = std::move(g)] {
            (void)http_ctrl.reset_group_auto(g);
            auto reply = http_ctrl.outbounds();
            if (reply.ok) push_group_models(desktop::parse_outbounds_json(reply.body), g);
        });
    });
    ui->on_probe_group([&](slint::SharedString group) {
        std::string g(group);
        worker.post([&, g = std::move(g)] {
            (void)http_ctrl.probe_group(g);
            auto reply = http_ctrl.outbounds();
            if (reply.ok) push_group_models(desktop::parse_outbounds_json(reply.body), g);
        });
    });

    auto push_connections = [weak_ui](std::vector<desktop::ActiveConnectionSnapshot> parsed, std::string filter) {
        auto items = desktop_ui_helpers::build_ui_connection_items(parsed, std::move(filter));
        slint::invoke_from_event_loop([weak_ui, items = std::move(items)] mutable {
            if (auto strong = weak_ui.lock())
                strong->set_connections(std::make_shared<slint::VectorModel<nexus_ui::ActiveConnectionItem>>(std::move(items)));
        });
    };
    ui->on_refresh_connections([&] {
        std::string filter(ui->get_connection_filter());
        worker.post([&, push_connections, filter = std::move(filter)] {
            if (auto reply = http_ctrl.connections(); reply.ok)
                push_connections(desktop::parse_connections_json(reply.body), filter);
        });
    });
    ui->on_inspect_connection([&](slint::SharedString id_str) {
        std::uint64_t id = 0;
        std::string_view sv(id_str);
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), id);
        if (ec != std::errc{} || id == 0) return;
        worker.post([&, weak_ui, id] {
            auto reply = http_ctrl.connection_detail(id);
            std::string detail;
            if (reply.ok) {
                if (auto c = desktop::parse_connection_detail_json(reply.body))
                    detail = desktop_ui_helpers::format_connection_detail(*c);
            } else {
                detail = "查询连接详情失败: " + reply.body;
            }
            slint::invoke_from_event_loop([weak_ui, detail = std::move(detail)] {
                if (auto strong = weak_ui.lock()) strong->set_selected_connection_detail(slint::SharedString(detail));
            });
        });
    });
    ui->on_close_connection([&](slint::SharedString id_str) {
        std::uint64_t id = 0;
        std::string_view sv(id_str);
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), id);
        if (ec != std::errc{} || id == 0) return;
        std::string filter(ui->get_connection_filter());
        worker.post([&, push_connections, id, filter = std::move(filter)] {
            (void)http_ctrl.close_connection(id);
            if (auto reply = http_ctrl.connections(); reply.ok)
                push_connections(desktop::parse_connections_json(reply.body), filter);
        });
    });
    ui->on_close_all_connections([&] {
        std::string filter(ui->get_connection_filter());
        worker.post([&, push_connections, filter = std::move(filter)] {
            (void)http_ctrl.close_all_connections();
            if (auto reply = http_ctrl.connections(); reply.ok)
                push_connections(desktop::parse_connections_json(reply.body), filter);
        });
    });

    auto push_profiles = [&] {
        auto entries = profile_store.list();
        auto active = profile_store.active_id();
        std::vector<nexus_ui::ProfileItem> items;
        for (auto const& e : entries) {
            items.push_back({slint::SharedString(e.id), slint::SharedString(e.name), e.id == active});
        }
        ui->set_profiles(std::make_shared<slint::VectorModel<nexus_ui::ProfileItem>>(std::move(items)));
    };
    ui->on_refresh_profiles([&] { push_profiles(); });
    ui->on_create_profile([&](slint::SharedString name) {
        if (auto saved = profile_store.save_profile(std::string_view(name), std::string_view(ui->get_kdl_text()))) {
            push_profiles();
            ui->set_status_summary(slint::SharedString("已保存配置档案: " + saved->id));
        }
    });
    ui->on_activate_profile([&](slint::SharedString id) {
        std::string target(id);
        for (auto const& e : profile_store.list()) {
            if (e.id == target) {
                (void)profile_store.set_active(target);
                auto text = read_file_text(e.kdl_path);
                ui->set_kdl_text(slint::SharedString(text));
                ui->set_active_profile(slint::SharedString(e.id));
                push_profiles();
                break;
            }
        }
    });
    ui->on_delete_profile([&](slint::SharedString id) {
        if (profile_store.remove_profile(std::string_view(id))) push_profiles();
    });

    ui->on_apply_log_level([&](slint::SharedString level) {
        std::string lvl(level);
        worker.post([&, weak_ui, lvl = std::move(lvl)] {
            auto http_res = http_ctrl.set_log_level(lvl);
            auto ok = http_res.ok || ipc.set_log_level(lvl).ok;
            auto msg = ok ? std::string("日志级别已更新") : http_res.body;
            slint::invoke_from_event_loop([weak_ui, msg = std::move(msg)] {
                if (auto strong = weak_ui.lock()) strong->set_status_summary(slint::SharedString(msg));
            });
        });
    });
    ui->on_refresh_logs([&] {
        std::string domain(ui->get_log_domain_filter()), search(ui->get_log_search());
        worker.post([&, weak_ui, domain = std::move(domain), search = std::move(search)] {
            auto reply = http_ctrl.logs("trace", domain, search, 0, 200);
            if (!reply.ok) return;
            auto snap = desktop::parse_logs_json(reply.body);
            { std::lock_guard lock(logs_mu); cached_logs = snap.entries; }
            slint::invoke_from_event_loop([weak_ui, entries = std::move(snap.entries)] {
                auto strong = weak_ui.lock();
                if (!strong) return;
                std::vector<nexus_ui::LogLineItem> items;
                items.reserve(entries.size());
                for (auto const& e : entries)
                    items.push_back({slint::SharedString(e.level), slint::SharedString(e.domain), slint::SharedString(e.message)});
                strong->set_logs(std::make_shared<slint::VectorModel<nexus_ui::LogLineItem>>(std::move(items)));
            });
        });
    });
    ui->on_export_logs([&] {
        worker.post([&, weak_ui] {
            std::string body;
            { std::lock_guard lock(logs_mu); body = desktop_ui_helpers::format_logs_snapshot(cached_logs); }
            auto out_path = cfg_dir / "logs-snapshot.txt";
            bool ok = !body.empty() && write_file_atomic(out_path, body);
            auto msg = ok ? ("已导出日志快照: " + out_path.string()) : std::string("暂无可导出的日志快照");
            slint::invoke_from_event_loop([weak_ui, msg = std::move(msg)] {
                if (auto strong = weak_ui.lock()) strong->set_log_export_status(slint::SharedString(msg));
            });
        });
    });
    ui->on_clear_logs([&] {
        { std::lock_guard lock(logs_mu); cached_logs.clear(); }
        ui->set_logs(std::make_shared<slint::VectorModel<nexus_ui::LogLineItem>>());
    });
    ui->on_run_rule_explain([&](slint::SharedString inb, slint::SharedString net, slint::SharedString tgt, slint::SharedString extra) {
        std::string i(inb), n(net), t(tgt), e(extra), kdl(ui->get_kdl_text());
        worker.post([&, weak_ui, i = std::move(i), n = std::move(n), t = std::move(t), e = std::move(e), kdl = std::move(kdl)] {
            auto draft = cfg_dir / ".explain-draft.kdl";
            auto target_cfg = (!kdl.empty() && write_file_atomic(draft, kdl)) ? draft : config_path;
            auto res = supervisor.explain_rule(target_cfg, i, n, t, e);
            if (target_cfg == draft) { std::error_code ec; std::filesystem::remove(draft, ec); }
            slint::invoke_from_event_loop([weak_ui, ok = res.ok, msg = std::move(res.message)] {
                if (auto strong = weak_ui.lock()) {
                    strong->set_explain_ok(ok);
                    strong->set_explain_result(slint::SharedString(msg));
                }
            });
        });
    });
    auto append_kdl_snippet = [&](std::string const& snippet, std::string_view label) {
        std::string merged(ui->get_kdl_text());
        if (!merged.empty() && merged.back() != '\n') merged.push_back('\n');
        ui->set_kdl_text(slint::SharedString(merged + "\n" + snippet));
        ui->set_diagnostic_ok(true);
        ui->set_diagnostic_message(slint::SharedString(std::string("已追加规则片段到配置: ") + std::string(label)));
    };
    ui->on_append_rule_snippet([&](slint::SharedString k, slint::SharedString v, slint::SharedString out) {
        append_kdl_snippet(desktop_ui_helpers::format_route_rule_kdl(k, v, out), "route");
    });
    ui->on_append_dns_rule_snippet([&](slint::SharedString k, slint::SharedString v, slint::SharedString srv) {
        append_kdl_snippet(desktop_ui_helpers::format_dns_rule_kdl(k, v, srv), "dns");
    });

    ui->on_quit_requested([&] {
        if (!quit_once.exchange(true, std::memory_order_acq_rel)) slint::quit_event_loop();
    });

    ui->run();
    quit_once.store(true, std::memory_order_release);
    tray.stop();
    worker.stop();
    (void)sys_proxy.restore();
    supervisor.stop();
    return 0;
}
