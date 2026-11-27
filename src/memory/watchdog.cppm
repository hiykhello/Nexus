export module memory.watchdog;
import std;
import functional;

export namespace memory {
    enum class PressureLevel : std::uint8_t { normal, soft, hard, emergency };

    struct WatchdogPolicy {
        std::uint64_t soft_bytes = 36ull * 1024 * 1024;
        std::uint64_t hard_bytes = 44ull * 1024 * 1024;
        std::uint64_t emergency_bytes = 48ull * 1024 * 1024;
        std::uint32_t cooldown_ms = 5000;

        static constexpr auto ios_ne_50mib() noexcept -> WatchdogPolicy {
            return {36ull * 1024 * 1024, 44ull * 1024 * 1024, 48ull * 1024 * 1024, 2000};
        }
        static constexpr auto router_128mib() noexcept -> WatchdogPolicy {
            return {64ull * 1024 * 1024, 88ull * 1024 * 1024, 104ull * 1024 * 1024, 5000};
        }
    };

    struct MemorySample {
        std::uint64_t process_rss_bytes = 0;
        std::uint64_t cgroup_bytes = 0;
        std::uint64_t cgroup_limit_bytes = 0;
        bool cgroup_is_root = true;
    };

    struct WatchdogStats {
        std::uint64_t evaluations = 0;
        std::uint64_t soft_reclaims = 0;
        std::uint64_t hard_reclaims = 0;
        std::uint64_t emergency_sheds = 0;
        std::uint64_t last_rss_bytes = 0;
        std::uint64_t peak_rss_bytes = 0;
        PressureLevel level = PressureLevel::normal;
        std::uint64_t last_cgroup_bytes = 0;
        std::uint64_t last_cgroup_limit_bytes = 0;
    };

    [[nodiscard]] auto parse_cgroup_v2_path(std::string_view proc_cgroup_content) -> std::optional<std::string>;
    [[nodiscard]] auto sample_process_rss_bytes() noexcept -> std::uint64_t;
    [[nodiscard]] auto sample_memory_usage() noexcept -> MemorySample;
    [[nodiscard]] auto classify_pressure(MemorySample const& sample, WatchdogPolicy const& policy) noexcept -> PressureLevel;

    class MemoryWatchdog {
        WatchdogPolicy policy_;
        WatchdogStats stats_{};
        std::uint64_t last_action_ms_ = 0;
        bool has_acted_ = false;
    public:
        explicit MemoryWatchdog(WatchdogPolicy policy = WatchdogPolicy::ios_ne_50mib()) noexcept : policy_(policy) {}
        auto evaluate(MemorySample const& sample, std::uint64_t now_ms,
                      functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel;
        auto evaluate(std::uint64_t rss_bytes, std::uint64_t now_ms,
                      functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel;
        auto sample_and_evaluate(std::uint64_t now_ms,
                                 functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel;
        [[nodiscard]] auto should_admit_new_session() const noexcept -> bool {
            return stats_.level != PressureLevel::emergency;
        }
        [[nodiscard]] auto stats() const noexcept -> WatchdogStats const& { return stats_; }
        [[nodiscard]] auto policy() const noexcept -> WatchdogPolicy const& { return policy_; }
    };
}
