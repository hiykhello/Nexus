export module nexus.shadowsocks.replay;
import std;
export namespace nexus::shadowsocks {
    enum class ReplayError { invalid_salt, time_reversed, duplicate, full, invalid_timestamp };
    // Thread-safe; share one table across every worker using the same server key.
    // Admit only after authenticating the fixed header and checking its timestamp.
    // Supply paired samples; wall_seconds is the same Unix time used for that check.
    // Wall clock regressions or excessive slowdowns fail closed until time catches up.
    // Out-of-order samples from concurrent callers are rejected as time reversed.
    class ReplayTable {
        struct Salt {
            std::array<std::uint8_t,32> bytes{};
            std::size_t size=0;
            auto operator<=>(Salt const&) const = default;
        };
        struct Entry {
            Salt salt;
            std::chrono::steady_clock::time_point admitted;
        };
        mutable std::mutex mutex_;
        std::deque<Entry> entries_;
        std::set<Salt> index_;
        std::size_t capacity_;
        std::optional<std::chrono::steady_clock::time_point> last_;
        std::chrono::steady_clock::time_point anchor_mono_{};
        std::uint64_t anchor_wall_=0;
        auto admit_locked(std::span<std::uint8_t const> salt, std::chrono::steady_clock::time_point now, std::uint64_t wall_seconds) -> std::expected<void,ReplayError>;
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
