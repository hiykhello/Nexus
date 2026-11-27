export module state.ruleset_storage;
import std;
import state.core;
export import state.file;
import state.lock;
import state.ruleset_cache;

export namespace state {
    inline constexpr std::uint32_t max_rule_blob = 32u * 1024u * 1024u;
    inline constexpr std::size_t max_rule_entries = 4096;

    struct RulesetRow {
        RulesetKey key;
        RulesetMetadata metadata;
    };

    struct RulesetIndex {
        std::uint64_t revision = 0, epoch = 0;
        std::vector<RulesetRow> rows;
    };

    auto valid_rule_key(RulesetKey const& key) noexcept -> bool;
    auto valid_rule_metadata(RulesetMetadata const& metadata) noexcept -> bool;
    auto decode_rulesets(std::span<std::byte const> bytes) -> std::expected<std::vector<RulesetRow>, StateError>;
    auto encode_rulesets(std::span<RulesetRow const> rows) -> Bytes;
    auto inspect_rulesets(NativeHandle directory) -> std::expected<std::optional<std::size_t>,StateError>;
    auto load_rulesets(InstanceLock const& directory) -> std::expected<RulesetIndex, StateError>;
    auto save_rulesets(InstanceLock const& directory, RulesetIndex& index) -> std::expected<void, StateError>;
    auto rule_blake3(std::string_view body) noexcept -> Fingerprint;
    auto rule_sha256(std::string_view body) -> std::expected<Fingerprint, StateError>;
    auto read_rule_blob(NativeHandle directory, RulesetMetadata const& metadata) -> std::expected<std::string, StateError>;
    auto write_rule_blob(NativeHandle directory, Fingerprint const& hash, std::string_view body) -> std::expected<void, StateError>;
    auto remove_rule_blob(NativeHandle directory, Fingerprint const& hash) -> std::expected<void, StateError>;
    auto sweep_rule_blobs(NativeHandle directory, std::span<RulesetRow const> rows) -> std::expected<void, StateError>;
}
