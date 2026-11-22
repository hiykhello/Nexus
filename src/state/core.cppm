export module state.core;
import std;

export namespace state {
    enum class Tier : std::uint8_t { authority = 1, lease, cache, secret };
    enum class CommitState : std::uint8_t { accepted, visible, committed, uncertain };
    enum class Stage : std::uint8_t {
        validate, directory, lock_file, lock, open, read, format, version, checksum, revision,
        stale_epoch, remove_stage, create_stage, write, sync_stage, close_stage, replace, sync_directory,
        isolate, capacity, stopped, worker, remove_blob, remove_index, scan, digest
    };

    struct StateError {
        Stage stage;
        std::error_code os{};
        bool replaced = false;
        std::optional<Stage> preceding;
        std::error_code preceding_os{};
    };

    using Clock = std::chrono::steady_clock;
    using Bytes = std::vector<std::byte>;
    using Magic = std::array<char, 6>;
    using Fingerprint = std::array<std::byte, 32>;
    inline constexpr Magic snapshot_magic{'N', 'X', 'S', 'T', '0', '1'};
    inline constexpr std::size_t header_bytes = 64;
    auto fingerprint(std::span<std::byte const> bytes) noexcept -> Fingerprint;
    using EncodedHeader = std::array<std::byte, header_bytes>;

    struct EnvelopeHeader {
        Magic magic = snapshot_magic;
        std::uint16_t schema_version = 1;
        Tier tier = Tier::authority;
        std::uint8_t flags = 0;
        std::uint32_t payload_bytes = 0;
        std::uint64_t revision = 0;
        std::uint64_t clear_epoch = 0;
        Fingerprint checksum{};
    };

    struct EnvelopeSpec {
        Magic magic = snapshot_magic;
        std::uint16_t schema_version = 1;
        Tier tier = Tier::authority;
        std::uint32_t max_payload = 1024 * 1024;
        Fingerprint fingerprint{};
    };

    struct CommitReceipt {
        CommitState state;
        std::optional<StateError> error;
    };

    [[nodiscard]] auto encode_header(EnvelopeHeader header, std::span<std::byte const> payload,
                                    Fingerprint const& fingerprint = {}) noexcept
        -> std::expected<EncodedHeader, StateError>;
    [[nodiscard]] auto decode_header(std::span<std::byte const> wire, EnvelopeSpec const& spec) noexcept
        -> std::expected<EnvelopeHeader, StateError>;
    [[nodiscard]] auto verify_payload(std::span<std::byte const> wire, EnvelopeHeader const& header,
                                      std::span<std::byte const> payload, Fingerprint const& fingerprint = {}) noexcept
        -> std::expected<void, StateError>;
    [[nodiscard]] auto describe(Stage stage) noexcept -> std::string_view;

    class ClearEpoch {
        std::atomic<std::uint64_t> epoch_;
        std::mutex gate_;
    public:
        explicit ClearEpoch(std::uint64_t initial = 0) noexcept : epoch_(initial) {}
        auto current(this ClearEpoch const& self) noexcept -> std::uint64_t {
            return self.epoch_.load(std::memory_order_acquire);
        }
        // Serializes epoch advancement with publication. Clear/delete work
        // can be queued for the returned epoch after this call.
        [[nodiscard]] auto advance(this ClearEpoch& self) -> std::expected<std::uint64_t, StateError>;
        auto publish(this ClearEpoch& self, std::uint64_t expected,
                     std::function_ref<std::expected<void, StateError>()> action) -> std::expected<void, StateError>;
    };
}
