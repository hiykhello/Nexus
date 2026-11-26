export module desktop.client_db;

import std;
import desktop.desktop_host_config;
import desktop.telemetry_store;
import desktop.ui_prefs;
import desktop.workspace_models;

export namespace desktop {
    struct ProfileSummary {
        std::string id;
        std::string kind;
        std::string subscription_id;
        std::string name;
        std::string protocol;
        std::string server;
        std::int64_t port = 0;
        std::int64_t sort_order = 0;
        bool pinned = false;
        std::int64_t updated_at = 0;
    };

    struct NodeTelemetryRow {
        std::string profile_id;
        std::int64_t latency_ms = -1;
        std::int64_t ewma_ms = -1;
        std::int64_t status_code = 0;
        std::string state;
        std::int64_t tested_at = 0;
    };

    struct TrafficLedgerRow {
        std::int64_t bucket_hour = 0;
        std::string profile_id;
        std::int64_t upload_bytes = 0;
        std::int64_t download_bytes = 0;
    };

    struct LegacyImportReport {
        bool imported_workspace = false;
        bool imported_host = false;
        bool imported_telemetry = false;
        bool imported_ui_prefs = false;
    };

    // Unified cross-platform SQLite 3 (WAL) Client Database (Schema v1, nexus-client.db).
    class ClientDatabase {
        struct Impl;
        std::unique_ptr<Impl> impl_;

        explicit ClientDatabase(std::unique_ptr<Impl> impl) noexcept;

    public:
        ~ClientDatabase();
        ClientDatabase(ClientDatabase const&) = delete;
        auto operator=(ClientDatabase const&) -> ClientDatabase& = delete;
        ClientDatabase(ClientDatabase&&) noexcept;
        auto operator=(ClientDatabase&&) noexcept -> ClientDatabase&;

        [[nodiscard]] static auto open(std::filesystem::path const& db_path)
            -> std::expected<ClientDatabase, std::string>;

        [[nodiscard]] auto path(this ClientDatabase const& self) noexcept -> std::filesystem::path const&;
        [[nodiscard]] auto user_version(this ClientDatabase& self) -> std::expected<int, std::string>;
        [[nodiscard]] auto has_workspace_data(this ClientDatabase& self) -> std::expected<bool, std::string>;
        [[nodiscard]] auto has_telemetry_data(this ClientDatabase& self) -> std::expected<bool, std::string>;

        // Workspace persistence (transactional, vertical split across profiles + profile_payloads).
        [[nodiscard]] auto load_workspace(this ClientDatabase& self)
            -> std::expected<WorkspaceDocument, std::string>;
        [[nodiscard]] auto save_workspace(this ClientDatabase& self, WorkspaceDocument const& doc)
            -> std::expected<void, std::string>;

        // Fast index-only profile listing (never reads profile_payloads).
        [[nodiscard]] auto list_profile_summaries(
            this ClientDatabase& self,
            std::string_view subscription_id = {},
            std::string_view kind = {}) -> std::expected<std::vector<ProfileSummary>, std::string>;
        [[nodiscard]] auto load_profile_payload(this ClientDatabase& self, std::string_view profile_id)
            -> std::expected<std::optional<WorkspaceProfileItem>, std::string>;
        [[nodiscard]] auto delete_profile(this ClientDatabase& self, std::string_view profile_id)
            -> std::expected<bool, std::string>;
        [[nodiscard]] auto set_profile_pinned(this ClientDatabase& self, std::string_view profile_id, bool pinned)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto count_profile_payloads(this ClientDatabase& self)
            -> std::expected<std::int64_t, std::string>;

        // Ephemeral node telemetry (never synced).
        [[nodiscard]] auto load_telemetry(this ClientDatabase& self)
            -> std::expected<TelemetryStoreData, std::string>;
        [[nodiscard]] auto save_telemetry(this ClientDatabase& self, TelemetryStoreData const& data)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto upsert_node_telemetry(this ClientDatabase& self, NodeTelemetryRow const& row)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto load_node_telemetry(this ClientDatabase& self)
            -> std::expected<std::vector<NodeTelemetryRow>, std::string>;

        // Hourly traffic ledger.
        [[nodiscard]] auto record_traffic_delta(
            this ClientDatabase& self,
            std::int64_t bucket_hour,
            std::string_view profile_id,
            std::int64_t upload_delta,
            std::int64_t download_delta) -> std::expected<void, std::string>;
        [[nodiscard]] auto query_traffic_ledger(
            this ClientDatabase& self,
            std::int64_t from_hour = 0,
            std::int64_t to_hour = std::numeric_limits<std::int64_t>::max(),
            std::string_view profile_id = {}) -> std::expected<std::vector<TrafficLedgerRow>, std::string>;

        // Host-only KV store (NEVER synced; WebDAV/E2EE credentials MUST stay in 0600 secret files).
        [[nodiscard]] auto get_host_kv(this ClientDatabase& self, std::string_view key)
            -> std::expected<std::optional<std::string>, std::string>;
        [[nodiscard]] auto set_host_kv(this ClientDatabase& self, std::string_view key, std::string_view value_json)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto delete_host_kv(this ClientDatabase& self, std::string_view key)
            -> std::expected<void, std::string>;

        // Reclaims SQLite page cache and performs a passive WAL checkpoint.
        [[nodiscard]] auto shrink_memory(this ClientDatabase& self) -> std::expected<void, std::string>;
    };

    // High-level Desktop stores backed by ClientDatabase + 0600 secret file isolation.
    [[nodiscard]] auto load_host_config_from_db(
        ClientDatabase& db,
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& secrets_dir,
        std::string_view control_socket) -> DesktopHostConfig;
    [[nodiscard]] auto save_host_config_to_db(
        ClientDatabase& db,
        std::filesystem::path const& secrets_dir,
        DesktopHostConfig const& cfg) -> bool;

    [[nodiscard]] auto load_ui_prefs_from_db(ClientDatabase& db) -> std::optional<UiPrefs>;
    [[nodiscard]] auto save_ui_prefs_to_db(ClientDatabase& db, UiPrefs const& prefs) -> bool;

    // One-shot idempotent import of legacy workspace.json / host.json / telemetry.json / ui-prefs.conf when DB is empty.
    [[nodiscard]] auto import_legacy_json_if_empty(
        ClientDatabase& db,
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& secrets_dir,
        std::string_view control_socket) -> std::expected<LegacyImportReport, std::string>;

    // Shrinks SQLite caches + OS heap/working-set when hiding to tray.
    auto reclaim_process_memory(ClientDatabase* db) noexcept -> void;
}
