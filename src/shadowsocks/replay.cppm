export module shadowsocks.replay;
import std;
export namespace shadowsocks {
    enum class ReplayError { invalid_salt, time_reversed, duplicate, full, invalid_timestamp };
    // Thread-safe; share one table across every worker using the same server key.
    // Admit only after authenticating the fixed header and checking its timestamp.
    // Supply paired samples; wall_seconds is the same Unix time used for that check.
    // Wall clock regressions or excessive slowdowns fail closed until time catches up.
    // Out-of-order samples from concurrent callers are rejected as time reversed.
    class ReplayTable {
        static constexpr std::size_t kShards = 16;
        static constexpr std::int64_t kEmptyTs = std::numeric_limits<std::int64_t>::max();
        struct Salt {
            std::array<std::uint8_t,32> bytes{};
            std::uint8_t size=0;
            [[nodiscard]] auto operator==(Salt const& other) const noexcept -> bool {
                return size==other.size && std::memcmp(bytes.data(),other.bytes.data(),size)==0;
            }
        };
        struct Entry {
            Salt salt;
            std::chrono::steady_clock::time_point admitted{};
            std::uint32_t hash=0;
        };
        struct alignas(64) Shard {
            mutable std::mutex mutex;
            std::vector<Entry> ring;
            std::vector<std::uint32_t> buckets;
            std::size_t head=0, count=0;
            std::optional<std::chrono::steady_clock::time_point> last_admitted;
            std::atomic<std::int64_t> oldest_ns{kEmptyTs};
            auto expire_locked(std::chrono::steady_clock::time_point now) noexcept -> std::size_t;
            [[nodiscard]] auto contains_locked(Salt const& key, std::uint32_t hash) const noexcept -> bool;
            auto insert_locked(Salt const& key, std::uint32_t hash, std::chrono::steady_clock::time_point admitted) -> void;
            auto grow_locked() -> void;
        };
        mutable std::mutex clock_mutex_;
        std::size_t capacity_;
        std::optional<std::chrono::steady_clock::time_point> last_;
        std::chrono::steady_clock::time_point anchor_mono_{};
        std::uint64_t anchor_wall_=0;
        std::optional<std::pair<std::chrono::steady_clock::time_point, std::uint64_t>> recovery_anchor_;
        mutable std::atomic<std::size_t> total_size_{0};
        mutable std::array<Shard, kShards> shards_{};
        auto check_clock_locked(std::chrono::steady_clock::time_point now, std::uint64_t wall_seconds) -> std::expected<void,ReplayError>;
        auto insert_salt(std::span<std::uint8_t const> salt, std::chrono::steady_clock::time_point now) -> std::expected<void,ReplayError>;
        auto sweep_expired(std::chrono::steady_clock::time_point now) const noexcept -> void;
    public:
        explicit ReplayTable(std::size_t capacity) noexcept : capacity_(capacity) {}
        ReplayTable(ReplayTable const&) = delete;
        auto operator=(ReplayTable const&) -> ReplayTable& = delete;
        ReplayTable(ReplayTable&&) = delete;
        auto operator=(ReplayTable&&) -> ReplayTable& = delete;
        [[nodiscard]] auto admit(std::span<std::uint8_t const> salt, std::chrono::steady_clock::time_point now, std::uint64_t wall_seconds)
            -> std::expected<void,ReplayError>;
        // Sample clocks and recheck the authenticated timestamp under the table lock.
        [[nodiscard]] auto admit_current(std::span<std::uint8_t const> salt, std::uint64_t timestamp) -> std::expected<void,ReplayError>;
        [[nodiscard]] auto size() const -> std::size_t;
    };
}
