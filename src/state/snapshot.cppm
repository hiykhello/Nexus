export module state.snapshot;
import std;
export import state.core;
export import state.lock;

export namespace state {
    enum class DamagePolicy { preserve, isolate };

    struct SnapshotSpec {
        std::string name;
        std::string staging_name;
        EnvelopeSpec envelope{};
        std::optional<Magic> legacy_magic;
    };

    struct SnapshotData {
        EnvelopeHeader header;
        Bytes payload;
        bool legacy = false;
    };

    [[nodiscard]] auto validate_snapshot(SnapshotSpec const& spec) noexcept -> std::expected<void, StateError>;

    auto inspect_snapshot(int directory, SnapshotSpec const& spec)
        -> std::expected<std::optional<SnapshotData>, StateError>;

    // Missing files return an empty optional. A damaged file remains an error
    // even after successful isolation. A Tier 3 caller can then cold-start.
    [[nodiscard]] auto load_snapshot(InstanceLock const& instance, SnapshotSpec const& spec,
                                     DamagePolicy policy = DamagePolicy::preserve)
        -> std::expected<std::optional<SnapshotData>, StateError>;

    // Callers serialize snapshot access within their instance lock. The
    // publication callback runs after rename and before directory fsync.
    using OnVisible = std::function_ref<void() noexcept>;
    [[nodiscard]] auto commit_snapshot(InstanceLock const& instance, SnapshotSpec const& spec,
                                       std::uint64_t revision, std::uint64_t epoch,
                                       std::span<std::byte const> payload, ClearEpoch* barrier = nullptr,
                                       std::optional<OnVisible> visible = {})
        -> std::expected<CommitReceipt, StateError>;
}
