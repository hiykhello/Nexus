export module ntp;
import std;
import platform.wall_clock;

export namespace ntp {
    inline constexpr std::size_t packet_size = 48;
    // Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
    inline constexpr std::uint64_t ntp_unix_epoch_delta = 2208988800ULL;

    enum class SntpError : std::uint8_t {
        invalid_length,
        invalid_version,
        invalid_mode,
        unsynchronized,
        kiss_of_death,
        origin_mismatch,
        io_error,
        timeout,
    };

    struct Timestamp {
        std::uint32_t seconds = 0;
        std::uint32_t fraction = 0;
        auto operator==(Timestamp const&) const -> bool = default;
    };

    struct SyncSample {
        std::int64_t offset_ms = 0;
        std::int64_t delay_ms = 0;
        std::uint8_t stratum = 0;
    };

    [[nodiscard]] auto unix_ms_to_ntp(std::int64_t unix_ms) noexcept -> Timestamp;
    [[nodiscard]] auto ntp_to_unix_ms(Timestamp ts) noexcept -> std::int64_t;
    [[nodiscard]] auto encode_request(Timestamp transmit_ts) noexcept -> std::array<std::uint8_t, packet_size>;
    [[nodiscard]] auto decode_response(
        std::span<std::uint8_t const> packet,
        Timestamp expected_origin,
        std::int64_t t1_unix_ms,
        std::int64_t t4_unix_ms) noexcept -> std::expected<SyncSample, SntpError>;

    // Performs one bounded UDP SNTPv4 query against numeric IP or hostname.
    [[nodiscard]] auto sync_once(std::string_view host, std::uint16_t port = 123,
        std::uint32_t timeout_ms = 5000, std::stop_token stop = {}) -> std::expected<SyncSample, SntpError>;

    [[nodiscard]] auto global_calibrator() noexcept -> class ClockCalibrator&;

    class ClockCalibrator {
        std::atomic<std::int64_t> offset_ms_{0};
        std::atomic<std::uint64_t> sync_count_{0};
    public:
        auto apply(this ClockCalibrator& self, SyncSample sample) noexcept -> void {
            self.offset_ms_.store(sample.offset_ms, std::memory_order_release);
            self.sync_count_.fetch_add(1, std::memory_order_relaxed);
            if (&self == &global_calibrator()) platform::set_wall_clock_offset_ms(sample.offset_ms);
        }
        [[nodiscard]] auto offset_ms(this ClockCalibrator const& self) noexcept -> std::int64_t {
            return self.offset_ms_.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto sync_count(this ClockCalibrator const& self) noexcept -> std::uint64_t {
            return self.sync_count_.load(std::memory_order_relaxed);
        }
        [[nodiscard]] auto calibrated_unix_seconds(this ClockCalibrator const& self) noexcept -> std::int64_t {
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            return (now_ms + self.offset_ms()) / 1000;
        }
    };
}
