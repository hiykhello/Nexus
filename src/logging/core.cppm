export module logging.core;
import std;
export import logging.options;

export namespace logging {
    inline constexpr std::size_t message_capacity = 512;
    using DropCounts = std::array<std::array<std::uint64_t, level_count>, domain_count>;

    template<class T>
    struct Redacted { T value; };

    struct Context {
        std::uint32_t worker_id = 0;
        std::uint64_t session_id = 0;
        std::uint64_t generation = 0;
    };

    struct LogSlot {
        std::int64_t monotonic_ns = 0;
        std::int64_t wall_epoch_ns = 0;
        Level level = Level::info;
        Domain domain = Domain::core;
        std::uint32_t event_code = 0;
        Context context;
        bool truncated = false;
        std::uint16_t message_size = 0;
        std::array<char, message_capacity> message;
    };

    using Clock = std::chrono::steady_clock;

    auto set_level(Level level) noexcept -> void;
    auto set_level(Domain domain, Level level) noexcept -> void;
    auto get_level(Domain domain) noexcept -> Level;
    auto set_ring_level(Level level) noexcept -> void;
    auto get_ring_level() noexcept -> Level;
    inline auto enabled(Domain domain, Level level) noexcept -> bool {
        return level < Level::off && level >= get_level(domain);
    }
    inline auto enabled_any(Domain domain, Level level) noexcept -> bool {
        return level < Level::off && (level >= get_level(domain) || level >= get_ring_level());
    }

    auto stamp(LogSlot& slot) noexcept -> void;
}
