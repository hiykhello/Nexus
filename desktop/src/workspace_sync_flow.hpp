// Wave 23 UI callback wiring: nexus:// portable share, E2EE WebDAV sync w/ conflict resolution, and UDP probes.
#pragma once

namespace desktop_ui_helpers {
    inline auto sync_webdav_fields_to_ui(WorkspaceUiContext& ctx) -> void {
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        ws.set_sync_webdav_url(slint::SharedString(ctx.host.webdav_url));
        ws.set_sync_webdav_user(slint::SharedString(ctx.host.webdav_username));
        ws.set_sync_webdav_pass(slint::SharedString(ctx.host.webdav_password));
        ws.set_sync_passphrase(slint::SharedString(ctx.host.sync_passphrase));
        ws.set_sync_device_label(slint::SharedString(
            ctx.host.sync_device_label.empty() ? ctx.host.platform : ctx.host.sync_device_label));
    }

    inline auto capture_webdav_fields_from_ui(WorkspaceUiContext& ctx) -> void {
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        ctx.host.webdav_url = std::string(trim_ascii_ws(std::string_view(ws.get_sync_webdav_url())));
        ctx.host.webdav_username = std::string(trim_ascii_ws(std::string_view(ws.get_sync_webdav_user())));
        ctx.host.webdav_password = std::string(ws.get_sync_webdav_pass());
        ctx.host.sync_passphrase = std::string(ws.get_sync_passphrase());
        ctx.host.sync_device_label = std::string(trim_ascii_ws(std::string_view(ws.get_sync_device_label())));
        if (ctx.host.sync_device_label.empty()) ctx.host.sync_device_label = ctx.host.platform;
    }

    inline auto normalize_socks5_probe_endpoint(std::string_view listen) -> std::string {
        auto sv = trim_ascii_ws(listen);
        if (sv.starts_with("0.0.0.0:")) return "127.0.0.1:" + std::string(sv.substr(8));
        if (sv.starts_with("[::]:")) return "[::1]:" + std::string(sv.substr(5));
        return std::string(sv);
    }

    inline auto import_share_bundle_async(WorkspaceUiContext& ctx, std::string uri) -> void {
        bool const en = is_en_ui(ctx.ui);
        uri = std::string(trim_ascii_ws(uri));
        if (!uri.starts_with("nexus://")) {
            auto msg = tr(en, "请输入有效的 nexus://share/v1/... 分享链接", "Enter a valid nexus://share/v1/... URI");
            push_toast(ctx.ui, msg, "error");
            return;
        }
        auto doc_snap = ctx.doc;
        ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "正在导入 nexus:// 便携分享包...", "Importing nexus:// share bundle...")));
        ctx.worker.post([&ctx, doc_snap = std::move(doc_snap), uri = std::move(uri), en]() mutable {
            auto ws_tmp = make_temp_compose_workspace(ctx.cfg_dir, doc_snap);
            desktop::ShareImportResult res{};
            if (ws_tmp.ok) {
                res = desktop::import_share_via_core(
                    ctx.supervisor.binary_path(), ws_tmp.path, uri, "manual", {}, ctx.secrets_dir);
            } else {
                res.errors.push_back(tr(en, "写入临时工作区文件失败", "Failed to write temporary workspace input"));
            }
            ws_tmp.wipe_and_remove();
            for (volatile char& ch : uri) ch = '\0';
            uri.clear();
            on_ui_thread(ctx.weak_ui, [&ctx, res = std::move(res), en](auto& s) mutable {
                if (!res.ok || res.workspace_json.empty()) {
                    auto err = res.errors.empty() ? tr(en, "导入 nexus:// 分享包失败", "Failed to import nexus:// bundle") : res.errors.front();
                    s->set_diagnostic_ok(false);
                    s->set_diagnostic_message(slint::SharedString(err));
                    push_toast(*s, err, "error");
                    return;
                }
                auto parsed = desktop::workspace_from_json(res.workspace_json);
                if (!parsed) {
                    push_toast(*s, parsed.error(), "error");
                    return;
                }
                ctx.doc = std::move(*parsed);
                ++ctx.doc.revision;
                ctx.doc.updated_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                if (!res.imported_ids.empty()) ctx.telemetry.active_profile_id = res.imported_ids.front();
                (void)persist_workspace_db(ctx);
                (void)persist_telemetry_db(ctx);
                s->set_share_link_input(slint::SharedString(""));
                sync_workspace_to_ui(ctx);
                if (ctx.sync_tray) ctx.sync_tray();
                auto msg = tr(en, "已导入便携分享包 (", "Imported share bundle (") + std::to_string(res.imported_ids.size()) + ")";
                push_toast(*s, msg, "success");
                recompose_active_workspace(ctx);
            });
        });
    }

    inline auto bind_workspace_sync_callbacks(WorkspaceUiContext& ctx) -> void {
        sync_webdav_fields_to_ui(ctx);
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();

        ws.on_export_profile_share([&ctx](slint::SharedString id_s) {
            bool const en = is_en_ui(ctx.ui);
            std::string id(id_s);
            if (id.empty()) return;
            auto doc_snap = ctx.doc;
            ctx.worker.post([&ctx, doc_snap = std::move(doc_snap), id = std::move(id), en]() mutable {
                auto ws_tmp = make_temp_compose_workspace(ctx.cfg_dir, doc_snap);
                desktop::ShareExportResult res{};
                if (ws_tmp.ok) {
                    std::array<std::string, 1> ids{id};
                    res = desktop::export_share_via_core(ctx.supervisor.binary_path(), ws_tmp.path, ids);
                } else {
                    res.errors.push_back(tr(en, "写入临时工作区文件失败", "Failed to write temporary workspace input"));
                }
                ws_tmp.wipe_and_remove();
                bool copied = (res.ok && !res.uri.empty()) && copy_text_to_clipboard(res.uri);
                on_ui_thread(ctx.weak_ui, [res = std::move(res), copied, en](auto& s) {
                    if (res.ok && !res.uri.empty()) {
                        auto msg = copied
                            ? (tr(en, "已复制 nexus:// 分享链接 (", "Copied nexus:// share URI (") +
                               std::to_string(res.exported_count) + tr(en, " 项)", " items)"))
                            : tr(en, "已生成 nexus:// 分享链接，但复制到剪贴板失败", "Exported nexus:// URI, but clipboard copy failed");
                        s->set_diagnostic_ok(copied);
                        s->set_diagnostic_message(slint::SharedString(msg));
                        push_toast(*s, msg, copied ? "success" : "warn");
                    } else {
                        auto err = res.errors.empty() ? tr(en, "导出 nexus:// 分享失败", "Export nexus:// share failed") : res.errors.front();
                        s->set_diagnostic_ok(false);
                        s->set_diagnostic_message(slint::SharedString(err));
                        push_toast(*s, err, "error");
                    }
                });
            });
        });

        ws.on_import_profile_share([&ctx](slint::SharedString uri_s) {
            import_share_bundle_async(ctx, std::string(uri_s));
        });

        ws.on_save_sync_settings([&ctx] {
            bool const en = is_en_ui(ctx.ui);
            capture_webdav_fields_from_ui(ctx);
            if (!ctx.host.webdav_url.empty()) {
                if (auto v = desktop::validate_webdav_url(ctx.host.webdav_url); !v) {
                    auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
                    g.set_sync_status_ok(false);
                    g.set_sync_status(slint::SharedString(v.error()));
                    push_toast(ctx.ui, v.error(), "error");
                    return;
                }
            }
            bool ok = persist_host_db(ctx);
            auto msg = ok ? tr(en, "已保存同步配置（凭据隔离存于 0600 密钥文件）", "Saved sync settings (credentials isolated in 0600 secret file)")
                          : tr(en, "保存同步凭据失败", "Failed to save sync settings");
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            g.set_sync_status_ok(ok);
            g.set_sync_status(slint::SharedString(msg));
            push_toast(ctx.ui, msg, ok ? "success" : "error");
        });

        ws.on_dismiss_sync_conflict([&ctx] {
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            g.set_sync_conflict_active(false);
            g.set_sync_conflict_detail(slint::SharedString(""));
        });

        ws.on_sync_push([&ctx](bool force_overwrite) {
            bool const en = is_en_ui(ctx.ui);
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            if (g.get_sync_busy()) return;
            capture_webdav_fields_from_ui(ctx);
            if (ctx.host.webdav_url.empty() || ctx.host.sync_passphrase.empty()) {
                auto msg = tr(en, "请填写 WebDAV 地址与同步口令", "WebDAV URL and sync passphrase are required");
                g.set_sync_status_ok(false); g.set_sync_status(slint::SharedString(msg));
                push_toast(ctx.ui, msg, "error");
                return;
            }
            if (auto v = desktop::validate_webdav_url(ctx.host.webdav_url); !v) {
                g.set_sync_status_ok(false); g.set_sync_status(slint::SharedString(v.error()));
                push_toast(ctx.ui, v.error(), "error");
                return;
            }
            (void)persist_workspace_db(ctx);
            (void)persist_host_db(ctx);
            auto doc_snap = ctx.doc;
            g.set_sync_busy(true);
            g.set_sync_conflict_active(false);
            desktop::WebDavConfig dav{ctx.host.webdav_url, ctx.host.webdav_username, ctx.host.webdav_password,
                                      ctx.host.webdav_last_etag, ctx.host.webdav_last_revision};
            std::string pass = ctx.host.sync_passphrase, dev = ctx.host.sync_device_label;
            std::int64_t rev = ctx.doc.revision;
            bool posted = ctx.worker.post([&ctx, doc_snap = std::move(doc_snap), dav = std::move(dav), pass = std::move(pass), dev = std::move(dev), rev, force_overwrite, en]() mutable {
                auto ws_tmp = make_temp_compose_workspace(ctx.cfg_dir, doc_snap);
                desktop::SyncSealResult sealed{};
                if (ws_tmp.ok) {
                    sealed = desktop::seal_sync_via_core(ctx.supervisor.binary_path(), ws_tmp.path, pass, dev, ctx.secrets_dir);
                } else {
                    sealed.errors.push_back(tr(en, "写入临时工作区文件失败", "Failed to write temporary workspace input"));
                }
                ws_tmp.wipe_and_remove();
                for (volatile char& ch : pass) ch = '\0';
                pass.clear();
                if (!sealed.ok || sealed.envelope_json.empty()) {
                    auto err = sealed.errors.empty() ? tr(en, "加密封装工作区失败", "Failed to encrypt workspace") : sealed.errors.front();
                    on_ui_thread(ctx.weak_ui, [err = std::move(err)](auto& s) {
                        auto const& st = s->template global<nexus_ui::WorkspaceState>();
                        st.set_sync_busy(false); st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(err));
                        push_toast(*s, err, "error");
                    });
                    return;
                }
                auto pushed = desktop::webdav_push_envelope(dav, sealed.envelope_json, sealed.revision > 0 ? sealed.revision : rev, force_overwrite);
                on_ui_thread(ctx.weak_ui, [&ctx, pushed = std::move(pushed), en](auto& s) {
                    auto const& st = s->template global<nexus_ui::WorkspaceState>();
                    st.set_sync_busy(false);
                    if (pushed.status == desktop::WebDavSyncStatus::ok) {
                        ctx.host.webdav_last_etag = pushed.remote_etag;
                        ctx.host.webdav_last_revision = pushed.remote_revision;
                        (void)persist_host_db(ctx);
                        auto msg = tr(en, "已加密上传工作区快照 (rev ", "Uploaded E2EE snapshot (rev ") + std::to_string(pushed.remote_revision) + ")";
                        st.set_sync_status_ok(true); st.set_sync_status(slint::SharedString(msg));
                        st.set_sync_conflict_active(false);
                        push_toast(*s, msg, "success");
                    } else if (pushed.status == desktop::WebDavSyncStatus::conflict) {
                        auto detail = std::format("{} (remote rev {}, device: {})",
                            tr(en, "远端版本已更新，请决定保留远端或强制覆盖", "Remote snapshot diverged; keep remote or force overwrite"),
                            pushed.remote_revision, pushed.remote_device_label.empty() ? "unknown" : pushed.remote_device_label);
                        st.set_sync_conflict_active(true); st.set_sync_conflict_detail(slint::SharedString(detail));
                        st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(pushed.message));
                        push_toast(*s, detail, "warn");
                    } else {
                        st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(pushed.message));
                        push_toast(*s, pushed.message, "error");
                    }
                });
            });
            if (!posted) g.set_sync_busy(false);
        });

        ws.on_sync_pull([&ctx](bool force_pull) {
            bool const en = is_en_ui(ctx.ui);
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            if (g.get_sync_busy()) return;
            capture_webdav_fields_from_ui(ctx);
            if (ctx.host.webdav_url.empty() || ctx.host.sync_passphrase.empty()) {
                auto msg = tr(en, "请填写 WebDAV 地址与同步口令", "WebDAV URL and sync passphrase are required");
                g.set_sync_status_ok(false); g.set_sync_status(slint::SharedString(msg));
                push_toast(ctx.ui, msg, "error");
                return;
            }
            if (auto v = desktop::validate_webdav_url(ctx.host.webdav_url); !v) {
                g.set_sync_status_ok(false); g.set_sync_status(slint::SharedString(v.error()));
                push_toast(ctx.ui, v.error(), "error");
                return;
            }
            (void)persist_host_db(ctx);
            g.set_sync_busy(true);
            g.set_sync_conflict_active(false);
            desktop::WebDavConfig dav{ctx.host.webdav_url, ctx.host.webdav_username, ctx.host.webdav_password,
                                      ctx.host.webdav_last_etag, ctx.host.webdav_last_revision};
            std::string pass = ctx.host.sync_passphrase;
            std::int64_t local_rev = ctx.doc.revision;
            auto backups_dir = ctx.cfg_dir / "backups";
            bool posted = ctx.worker.post([&ctx, dav = std::move(dav), pass = std::move(pass), local_rev, backups_dir = std::move(backups_dir), force_pull, en]() mutable {
                // Download & verify passphrase/JSON BEFORE creating a rotated 0600 local backup (avoids clutter on bad passphrase).
                auto pulled = desktop::webdav_pull_envelope(dav, {}, {}, local_rev, force_pull);
                if (pulled.status != desktop::WebDavSyncStatus::ok) {
                    for (volatile char& ch : pass) ch = '\0';
                    pass.clear();
                    on_ui_thread(ctx.weak_ui, [pulled = std::move(pulled), en](auto& s) {
                        auto const& st = s->template global<nexus_ui::WorkspaceState>();
                        st.set_sync_busy(false);
                        if (pulled.status == desktop::WebDavSyncStatus::conflict) {
                            auto detail = std::format("{} (remote rev {}, device: {})",
                                tr(en, "本地工作区存在未同步修改，确认拉取将先自动备份本地", "Local workspace has unsynced edits; pulling creates a local backup first"),
                                pulled.remote_revision, pulled.remote_device_label.empty() ? "unknown" : pulled.remote_device_label);
                            st.set_sync_conflict_active(true); st.set_sync_conflict_detail(slint::SharedString(detail));
                            st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(pulled.message));
                            push_toast(*s, detail, "warn");
                        } else {
                            st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(pulled.message));
                            push_toast(*s, pulled.message, "error");
                        }
                    });
                    return;
                }
                auto opened = desktop::open_sync_via_core(ctx.supervisor.binary_path(), pulled.envelope_json, pass, ctx.secrets_dir);
                for (volatile char& ch : pass) ch = '\0';
                pass.clear();
                on_ui_thread(ctx.weak_ui, [&ctx, pulled = std::move(pulled), opened = std::move(opened), backups_dir = std::move(backups_dir), en](auto& s) mutable {
                    auto const& st = s->template global<nexus_ui::WorkspaceState>();
                    st.set_sync_busy(false);
                    if (!opened.ok || opened.workspace_json.empty()) {
                        auto err = opened.errors.empty() ? tr(en, "解密远端快照失败（口令错误或文件损坏）", "Failed to decrypt remote snapshot") : opened.errors.front();
                        st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(err));
                        push_toast(*s, err, "error");
                        return;
                    }
                    auto parsed = desktop::workspace_from_json(opened.workspace_json);
                    if (!parsed) {
                        st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(parsed.error()));
                        push_toast(*s, parsed.error(), "error");
                        return;
                    }
                    if (!ctx.doc.profiles.empty()) {
                        auto ws_tmp = make_temp_compose_workspace(ctx.cfg_dir, ctx.doc);
                        bool backed_up = ws_tmp.ok && !desktop::backup_workspace_file_0600(ws_tmp.path, backups_dir, 5).empty();
                        ws_tmp.wipe_and_remove();
                        if (!backed_up) {
                            auto err = tr(en, "创建本地备份失败，已中止覆盖", "Failed to create local backup; pull aborted");
                            st.set_sync_status_ok(false); st.set_sync_status(slint::SharedString(err));
                            push_toast(*s, err, "error");
                            return;
                        }
                    }
                    ctx.doc = std::move(*parsed);
                    std::unordered_set<std::string> live;
                    for (auto const& p : ctx.doc.profiles) live.insert(p.id);
                    (void)desktop::prune_telemetry_entries(ctx.telemetry, live);
                    if (ctx.telemetry.active_profile_id.empty() && !ctx.doc.profiles.empty()) ctx.telemetry.active_profile_id = ctx.doc.profiles.front().id;
                    ctx.host.webdav_last_etag = pulled.remote_etag;
                    ctx.host.webdav_last_revision = ctx.doc.revision;
                    (void)persist_workspace_db(ctx);
                    (void)persist_host_db(ctx);
                    (void)persist_telemetry_db(ctx);
                    sync_workspace_to_ui(ctx);
                    if (ctx.sync_tray) ctx.sync_tray();
                    auto msg = tr(en, "已解密并恢复远端工作区 (rev ", "Restored E2EE workspace (rev ") +
                               std::to_string(ctx.host.webdav_last_revision) + ")";
                    st.set_sync_status_ok(true); st.set_sync_status(slint::SharedString(msg));
                    st.set_sync_conflict_active(false);
                    push_toast(*s, msg, "success");
                    recompose_active_workspace(ctx);
                });
            });
            if (!posted) g.set_sync_busy(false);
        });

        ws.on_run_udp_probe([&ctx](slint::SharedString kind_s) {
            bool const en = is_en_ui(ctx.ui);
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            if (g.get_udp_probe_busy()) return;
            std::string kind(kind_s);
            std::string socks5 = (ctx.supervisor.running() && ctx.host.enable_mixed && !ctx.host.mixed_listen.empty())
                ? normalize_socks5_probe_endpoint(ctx.host.mixed_listen) : std::string{};
            g.set_udp_probe_busy(true);
            g.set_udp_probe_result(slint::SharedString(tr(en, "正在探测 UDP...", "Running UDP probe...")));
            g.set_udp_probe_ok(true);
            bool posted = ctx.worker.post([&ctx, kind = std::move(kind), socks5 = std::move(socks5), en]() mutable {
                auto res = desktop::run_udp_probe_via_core(ctx.supervisor.binary_path(), kind, "", socks5, 3000, 2);
                on_ui_thread(ctx.weak_ui, [res = std::move(res), en](auto& s) {
                    auto const& st = s->template global<nexus_ui::WorkspaceState>();
                    st.set_udp_probe_busy(false);
                    st.set_udp_probe_ok(res.ok);
                    std::string line = res.ok
                        ? std::format("[{}] OK · {} ms · {} · {}", res.kind, res.rtt_ms,
                                      res.via_socks5 ? "SOCKS5 UDP" : "Direct UDP", res.detail)
                        : std::format("[{}] {}: {}", res.kind, tr(en, "失败", "FAILED"),
                                      res.error.empty() ? "timeout" : res.error);
                    st.set_udp_probe_result(slint::SharedString(line));
                    push_toast(*s, line, res.ok ? "success" : "error");
                });
            });
            if (!posted) g.set_udp_probe_busy(false);
        });
    }
}
