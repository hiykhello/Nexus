module logging.core;
import std;

namespace logging {
    namespace {
        constexpr auto default_level = std::to_underlying(Level::info);
        alignas(64) constinit std::array<std::atomic<std::uint8_t>, domain_count> watermarks{
            default_level, default_level, default_level, default_level, default_level,
            default_level, default_level, default_level, default_level, default_level
        };
        alignas(64) constinit std::atomic<std::uint8_t> ring_watermark{std::to_underlying(Level::off)};
        static_assert(std::atomic<std::uint8_t>::is_always_lock_free);
    }

    auto set_level(Level level) noexcept -> void {
        for (auto& watermark : watermarks)
            watermark.store(std::to_underlying(level), std::memory_order_relaxed);
    }

    auto set_level(Domain domain, Level level) noexcept -> void {
        watermarks[std::to_underlying(domain)].store(std::to_underlying(level), std::memory_order_relaxed);
    }

    auto get_level(Domain domain) noexcept -> Level {
        return static_cast<Level>(watermarks[std::to_underlying(domain)].load(std::memory_order_relaxed));
    }

    auto set_ring_level(Level level) noexcept -> void {
        ring_watermark.store(std::to_underlying(level), std::memory_order_relaxed);
    }

    auto get_ring_level() noexcept -> Level {
        return static_cast<Level>(ring_watermark.load(std::memory_order_relaxed));
    }

    auto stamp(LogSlot& slot) noexcept -> void {
        using namespace std::chrono;
        slot.monotonic_ns = duration_cast<nanoseconds>(Clock::now().time_since_epoch()).count();
        slot.wall_epoch_ns = duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
    }
}
