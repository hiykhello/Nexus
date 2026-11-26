module desktop.client_db;

import std;
import desktop.desktop_host_config;
import desktop.mini_json;
import desktop.telemetry_store;
import desktop.ui_prefs;
import desktop.workspace_models;
import desktop.workspace_store;

namespace desktop {
    auto load_host_config_from_db(
        ClientDatabase& db,
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& secrets_dir,
        std::string_view control_socket) -> DesktopHostConfig {
        auto fallback = make_default_desktop_host_config(cfg_dir, control_socket);
        DesktopHostConfig cfg = fallback;
        if (auto raw = db.get_host_kv("desktop_host"); raw && *raw) {
            if (auto parsed = desktop_host_from_json(**raw); parsed) {
                cfg = std::move(*parsed);
                if (cfg.state_dir.empty()) cfg.state_dir = fallback.state_dir;
                if (cfg.cache_dir.empty()) cfg.cache_dir = fallback.cache_dir;
                if (cfg.control_socket.empty()) cfg.control_socket = fallback.control_socket;
                if (cfg.control_bearer_file.empty()) cfg.control_bearer_file = fallback.control_bearer_file;
            }
        }
        // WebDAV password, E2EE sync passphrase, and LAN password ALWAYS come from 0600 secret files, NEVER SQLite!
        auto secrets = load_sync_secrets(secrets_dir);
        cfg.webdav_password = std::move(secrets.webdav_password);
        cfg.sync_passphrase = std::move(secrets.sync_passphrase);
        if (!secrets.lan_password.empty()) cfg.lan_password = std::move(secrets.lan_password);
        return cfg;
    }

    auto save_host_config_to_db(
        ClientDatabase& db,
        std::filesystem::path const& secrets_dir,
        DesktopHostConfig const& cfg) -> bool {
        // Persist secrets exclusively to 0600 secret file outside SQLite; fail closed before updating SQLite.
        if (!save_sync_secrets(secrets_dir, {cfg.webdav_password, cfg.sync_passphrase, cfg.lan_password})) {
            return false;
        }
        // Strip all secrets before storing non-secret host fields into SQLite host_kv.
        auto const nonsecret_json = desktop_host_to_nonsecret_json(cfg);
        return db.set_host_kv("desktop_host", nonsecret_json).has_value();
    }

    auto load_ui_prefs_from_db(ClientDatabase& db) -> std::optional<UiPrefs> {
        auto raw = db.get_host_kv("ui_prefs");
        if (!raw || !*raw) return std::nullopt;
        auto parsed = ui_prefs_from_json(**raw);
        if (!parsed) return std::nullopt;
        if (auto sc = db.get_host_kv("sidebar_collapsed"); sc && *sc) {
            if (auto p = json_parse(**sc); p && std::holds_alternative<bool>(p->data)) {
                parsed->sidebar_collapsed = std::get<bool>(p->data);
            }
        }
        return *parsed;
    }

    auto save_ui_prefs_to_db(ClientDatabase& db, UiPrefs const& prefs) -> bool {
        auto r1 = db.set_host_kv("ui_prefs", ui_prefs_to_json(prefs));
        auto r2 = db.set_host_kv("sidebar_collapsed", prefs.sidebar_collapsed ? "true" : "false");
        return r1.has_value() && r2.has_value();
    }

    auto import_legacy_json_if_empty(
        ClientDatabase& db,
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& secrets_dir,
        std::string_view control_socket) -> std::expected<LegacyImportReport, std::string> {
        LegacyImportReport rep{};
        if (auto flag = db.get_host_kv("legacy_json_imported"); flag && *flag && **flag == "true") {
            return rep;
        }

        std::error_code ec;
        auto has_ws = db.has_workspace_data();
        if (!has_ws) return std::unexpected(has_ws.error());
        auto const ws_path = cfg_dir / "workspace.json";
        if (!*has_ws && std::filesystem::is_regular_file(ws_path, ec) && !ec) {
            if (auto doc = load_workspace(ws_path); doc) {
                if (auto sr = db.save_workspace(*doc); !sr) return std::unexpected(sr.error());
                rep.imported_workspace = true;
            }
        }

        auto const host_path = cfg_dir / "host.json";
        auto existing_host = db.get_host_kv("desktop_host");
        if (existing_host && !*existing_host && std::filesystem::is_regular_file(host_path, ec) && !ec) {
            auto host = load_desktop_host_config(host_path, cfg_dir, control_socket);
            if (!save_host_config_to_db(db, secrets_dir, host)) {
                return std::unexpected("failed to import legacy host.json into sqlite");
            }
            if (!host.webdav_password.empty() || !host.sync_passphrase.empty() || !host.lan_password.empty()) {
                DesktopHostConfig scrubbed = host;
                scrubbed.webdav_password.clear();
                scrubbed.sync_passphrase.clear();
                scrubbed.lan_password.clear();
                (void)save_desktop_host_config(host_path, scrubbed);
            }
            rep.imported_host = true;
        }

        auto const tel_path = cfg_dir / "telemetry.json";
        auto has_tel = db.has_telemetry_data();
        if (!has_tel) return std::unexpected(has_tel.error());
        if (!*has_tel && std::filesystem::is_regular_file(tel_path, ec) && !ec) {
            auto tel = load_telemetry_store(tel_path);
            if (auto sr = db.save_telemetry(tel); !sr) return std::unexpected(sr.error());
            rep.imported_telemetry = true;
        }

        auto const prefs_path = cfg_dir / "ui-prefs.conf";
        auto existing_prefs = db.get_host_kv("ui_prefs");
        if (existing_prefs && !*existing_prefs && std::filesystem::is_regular_file(prefs_path, ec) && !ec) {
            auto prefs = load_ui_prefs(prefs_path);
            if (!save_ui_prefs_to_db(db, prefs)) {
                return std::unexpected("failed to import legacy ui-prefs.conf into sqlite");
            }
            rep.imported_ui_prefs = true;
        }

        if (auto mr = db.set_host_kv("legacy_json_imported", "true"); !mr) return std::unexpected(mr.error());
        return rep;
    }
}
