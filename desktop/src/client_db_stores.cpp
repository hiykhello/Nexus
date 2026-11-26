module desktop.client_db;

import std;
import desktop.desktop_host_config;
import desktop.mini_json;
import desktop.ui_prefs;

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
}
