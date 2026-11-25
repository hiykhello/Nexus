export module desktop.telemetry_store;

import std;

export namespace desktop {
    struct ProfileTelemetryEntry {
        std::string profile_id;
        std::int64_t delay_ms = -1;
        std::int64_t speed_bps = 0;
        std::int64_t up_bytes = 0;
        std::int64_t down_bytes = 0;
        std::int64_t last_tested_ms = 0;
        std::int64_t sort_order = 0;
    };

    // Layer 4 ephemeral host-local telemetry (NEVER synced inside workspace.json).
    struct TelemetryStoreData {
        std::int64_t schema_version = 1;
        std::string active_profile_id;
        std::vector<ProfileTelemetryEntry> entries;
    };

    [[nodiscard]] auto telemetry_to_json(TelemetryStoreData const& data) -> std::string;
    [[nodiscard]] auto telemetry_from_json(std::string_view text) -> std::expected<TelemetryStoreData, std::string>;
    [[nodiscard]] auto load_telemetry_store(std::filesystem::path const& path) -> TelemetryStoreData;
    [[nodiscard]] auto save_telemetry_store(std::filesystem::path const& path, TelemetryStoreData const& data) -> bool;
    auto prune_telemetry_entries(TelemetryStoreData& data, std::unordered_set<std::string> const& live_profile_ids) -> std::size_t;
}
