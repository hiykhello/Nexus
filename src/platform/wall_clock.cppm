export module platform.wall_clock;
import std;

export namespace platform {
    auto set_wall_clock_offset_ms(std::int64_t offset_ms) noexcept -> void;
    [[nodiscard]] auto wall_clock_offset_ms() noexcept -> std::int64_t;
    [[nodiscard]] auto calibrated_wall_seconds() noexcept -> std::int64_t;
}
