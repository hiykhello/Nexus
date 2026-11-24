module platform.wall_clock;
import std;

namespace platform {
    namespace {
        std::atomic<std::int64_t> g_wall_offset_ms{0};
    }

    auto set_wall_clock_offset_ms(std::int64_t offset_ms) noexcept -> void {
        g_wall_offset_ms.store(offset_ms, std::memory_order_release);
    }

    auto wall_clock_offset_ms() noexcept -> std::int64_t {
        return g_wall_offset_ms.load(std::memory_order_acquire);
    }

    auto calibrated_wall_seconds() noexcept -> std::int64_t {
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto adjusted = now_ms + g_wall_offset_ms.load(std::memory_order_acquire);
        return adjusted >= 0 ? adjusted / 1000 : -1;
    }
}
