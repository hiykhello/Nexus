export module desktop.desktop_host_config;

import std;

export namespace desktop {
    struct DesktopHostConfig {
        std::int64_t schema_version = 1;
        std::string platform; // "desktop-linux" | "desktop-windows" | "desktop-macos"
        std::string log_level = "info";
        std::string log_file;
        std::int64_t workers = 0;
        std::string state_dir;
        std::string cache_dir;
        std::string control_socket;
        std::string control_http_listen = "127.0.0.1:19090";
        std::string control_bearer_file;
        std::string ca_file;
        bool include_sibling_nodes_in_selector = true;
        std::int64_t max_selector_members = 128;

        // Desktop-specific runtime adapter fields
        bool enable_mixed = true;
        std::string mixed_listen = "127.0.0.1:7890";
        std::string second_local_listen;
        std::string lan_listen;
        std::string lan_username;
        std::string lan_password;
        bool enable_tun = false;
        std::string tun_interface_name = "nexus-tun0";
        std::int64_t tun_mtu = 1400;
        std::string tun_inet4 = "172.19.0.1/30";
        std::string tun_inet6;
        bool tun_auto_route = true;
        bool tun_strict_route = false;
        std::vector<std::string> tun_route_exclude;
        bool tun_route_exclude_private = true;
        std::string bind_interface;
        std::string inet4_bind_address;
        std::string inet6_bind_address;

        // Desktop OS/UI keys (ignored by Core compiler; kept strictly in Layer 3 host.json)
        std::string tun_elevation_mode = "persistent"; // "persistent" | "session_only"
        std::string system_proxy_mode = "off"; // "off" | "manual" | "pac"
        std::string system_proxy_exceptions;
        std::string custom_pac_path;
        bool auto_launch = false;
        bool start_minimized = false;
        std::string theme = "system";
        std::string language = "system";

        // Local-only E2EE WebDAV sync credentials & state (NEVER written to workspace.json or sync envelope)
        std::string webdav_url;
        std::string webdav_username;
        std::string webdav_password;
        std::string sync_passphrase;
        std::string sync_device_label;
        std::string webdav_last_etag;
        std::int64_t webdav_last_revision = 0;
    };

    [[nodiscard]] auto current_desktop_platform_id() noexcept -> std::string_view;

    [[nodiscard]] auto make_default_desktop_host_config(
        std::filesystem::path const& cfg_dir,
        std::string_view control_socket) -> DesktopHostConfig;

    // Enforces host invariants (e.g. Linux strict_route disables enable_mixed because Core forbids a 2nd inbound).
    // Returns human-readable notices when fields were adjusted.
    [[nodiscard]] auto normalize_desktop_host_config(DesktopHostConfig& cfg, bool is_en = false)
        -> std::vector<std::string>;

    struct SyncSecrets {
        std::string webdav_password;
        std::string sync_passphrase;
        std::string lan_password;
    };

    [[nodiscard]] auto desktop_host_to_json(DesktopHostConfig const& cfg) -> std::string;
    // Serializes DesktopHostConfig with all secrets stripped (safe for SQLite host_kv).
    [[nodiscard]] auto desktop_host_to_nonsecret_json(DesktopHostConfig const& cfg) -> std::string;
    // Serializes DesktopHostConfig for Core composer (strips WebDAV/E2EE secrets, keeps LAN auth if configured).
    [[nodiscard]] auto desktop_host_to_core_json(DesktopHostConfig const& cfg) -> std::string;
    [[nodiscard]] auto desktop_host_from_json(std::string_view text) -> std::expected<DesktopHostConfig, std::string>;

    [[nodiscard]] auto load_sync_secrets(std::filesystem::path const& secrets_dir) -> SyncSecrets;
    [[nodiscard]] auto save_sync_secrets(std::filesystem::path const& secrets_dir, SyncSecrets const& secrets) -> bool;

    [[nodiscard]] auto load_desktop_host_config(
        std::filesystem::path const& path,
        std::filesystem::path const& cfg_dir,
        std::string_view control_socket) -> DesktopHostConfig;

    [[nodiscard]] auto save_desktop_host_config(
        std::filesystem::path const& path,
        DesktopHostConfig const& cfg) -> bool;

    // Atomically provisions a 0600 random 32-byte hex bearer token file if missing or empty.
    [[nodiscard]] auto ensure_control_bearer_token(std::filesystem::path const& token_path) -> bool;
}
