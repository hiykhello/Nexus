export module desktop.workspace_sync;

import std;

export namespace desktop {
    struct ShareExportResult {
        bool ok = false;
        std::string uri;
        std::int64_t exported_count = 0;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };

    struct ShareImportResult {
        bool ok = false;
        std::vector<std::string> imported_ids;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::string workspace_json;
    };

    struct SyncSealResult {
        bool ok = false;
        std::int64_t revision = 0;
        std::int64_t updated_at_ms = 0;
        std::string envelope_sha256;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::string envelope_json;
    };

    struct SyncOpenResult {
        bool ok = false;
        std::int64_t revision = 0;
        std::int64_t updated_at_ms = 0;
        std::string device_label;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::string workspace_json;
    };

    struct SyncEnvelopeMeta {
        bool valid = false;
        std::string format;
        std::int64_t revision = 0;
        std::int64_t updated_at_ms = 0;
        std::string device_label;
    };

    struct UdpProbeResult {
        bool ok = false;
        std::string kind;
        bool via_socks5 = false;
        std::int64_t rtt_ms = 0;
        std::int64_t attempts = 0;
        std::string detail;
        std::string error;
    };

    struct WebDavConfig {
        std::string url;
        std::string username;
        std::string password;
        std::string last_etag;
        std::int64_t last_revision = 0;
    };

    struct WebDavResponse {
        bool transport_ok = false;
        int status_code = 0;
        std::string etag;
        std::string body;
        std::string error;
    };

    enum class WebDavSyncStatus { ok, conflict, not_found, error };

    struct WebDavSyncOutcome {
        WebDavSyncStatus status = WebDavSyncStatus::error;
        std::string remote_etag;
        std::int64_t remote_revision = 0;
        std::int64_t remote_updated_at_ms = 0;
        std::string remote_device_label;
        std::string envelope_json;
        std::string backup_path;
        std::string message;
    };

    // Pure JSON parsers & argv builders (unit-tested independently)
    [[nodiscard]] auto parse_share_export_json(std::string_view json_text) -> ShareExportResult;
    [[nodiscard]] auto parse_share_import_json(std::string_view json_text) -> ShareImportResult;
    [[nodiscard]] auto parse_sync_seal_json(std::string_view json_text) -> SyncSealResult;
    [[nodiscard]] auto parse_sync_open_json(std::string_view json_text) -> SyncOpenResult;
    [[nodiscard]] auto parse_sync_envelope_meta(std::string_view json_text) -> SyncEnvelopeMeta;
    [[nodiscard]] auto parse_udp_probe_json(std::string_view json_text) -> UdpProbeResult;

    [[nodiscard]] auto build_export_share_argv(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::span<std::string const> profile_ids) -> std::vector<std::string>;

    [[nodiscard]] auto build_import_share_argv(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::filesystem::path const& uri_file,
        std::string_view subscription_id = {},
        std::filesystem::path const& out_workspace = {}) -> std::vector<std::string>;

    [[nodiscard]] auto build_udp_probe_argv(
        std::filesystem::path const& core_binary,
        std::string_view kind,
        std::string_view target = {},
        std::string_view socks5 = {},
        int timeout_ms = 3000,
        int attempts = 2) -> std::vector<std::string>;

    // Core CLI bridge helpers (15s bounded execution; secrets/URIs ALWAYS via transient 0600 file, wiped immediately)
    [[nodiscard]] auto export_share_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::span<std::string const> profile_ids) -> ShareExportResult;

    [[nodiscard]] auto import_share_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::string_view uri,
        std::string_view subscription_id = {},
        std::filesystem::path const& out_workspace = {},
        std::filesystem::path const& secrets_dir = {}) -> ShareImportResult;

    [[nodiscard]] auto seal_sync_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::string_view passphrase,
        std::string_view device_label,
        std::filesystem::path const& secrets_dir) -> SyncSealResult;

    [[nodiscard]] auto open_sync_via_core(
        std::filesystem::path const& core_binary,
        std::string_view envelope_json,
        std::string_view passphrase,
        std::filesystem::path const& secrets_dir) -> SyncOpenResult;

    [[nodiscard]] auto run_udp_probe_via_core(
        std::filesystem::path const& core_binary,
        std::string_view kind,
        std::string_view target = {},
        std::string_view socks5 = {},
        int timeout_ms = 3000,
        int attempts = 2) -> UdpProbeResult;

    // Cross-platform WebDAV HTTPS client (strict HTTPS except loopback for tests)
    [[nodiscard]] auto validate_webdav_url(std::string_view url) -> std::expected<std::string, std::string>;

    [[nodiscard]] auto webdav_request(
        std::string_view method,
        std::string_view url,
        std::string_view username,
        std::string_view password,
        std::span<std::pair<std::string, std::string> const> extra_headers = {},
        std::string_view body = {}) -> WebDavResponse;

    [[nodiscard]] auto webdav_push_envelope(
        WebDavConfig const& cfg,
        std::string_view envelope_json,
        std::int64_t local_revision,
        bool force_overwrite = false) -> WebDavSyncOutcome;

    [[nodiscard]] auto webdav_pull_envelope(
        WebDavConfig const& cfg,
        std::filesystem::path const& local_workspace_path,
        std::filesystem::path const& backups_dir,
        std::int64_t local_revision = 0,
        bool force_pull = false) -> WebDavSyncOutcome;

    // Creates a timestamped 0600 backup of local_workspace_path in backups_dir and prunes oldest beyond max_keep.
    [[nodiscard]] auto backup_workspace_file_0600(
        std::filesystem::path const& local_workspace_path,
        std::filesystem::path const& backups_dir,
        std::size_t max_keep = 5) -> std::string;
}
