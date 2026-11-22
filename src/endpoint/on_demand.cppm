export module endpoint.on_demand;
import std;

export namespace endpoint::on_demand {
    enum class State { sleeping, waking, active, cooldown };
    enum class WakeAction { pass, initiate_wake, queued, dropped };

    struct Config {
        std::chrono::seconds idle_timeout{120};
        std::chrono::seconds wake_backoff{3};
        std::uint32_t max_queued_packets{64};
        bool wake_on_outbound{true};
        bool keepalive_prevents_sleep{false};
    };

    struct Stats {
        std::uint64_t sleep_transitions{0};
        std::uint64_t wake_transitions{0};
        std::uint64_t queued_packets{0};
        std::uint64_t dropped_packets{0};
    };

    class Controller {
        Config config_{};
        State state_{State::sleeping};
        std::int64_t state_entered_ms_{0};
        std::int64_t last_activity_ms_{0};
        std::uint32_t queued_count_{0};
        Stats stats_{};

    public:
        explicit Controller(Config cfg = {}, std::int64_t initial_now_ms = 0) noexcept
            : config_(cfg), state_entered_ms_(initial_now_ms), last_activity_ms_(initial_now_ms) {}

        [[nodiscard]] auto on_outbound_packet(std::int64_t now_ms, std::size_t packet_size) noexcept -> WakeAction;
        auto on_inbound_packet(std::int64_t now_ms) noexcept -> void;
        [[nodiscard]] auto on_tunnel_up(std::int64_t now_ms) noexcept -> std::uint32_t;
        auto on_tunnel_down(std::int64_t now_ms, bool error = true) noexcept -> void;
        auto on_keepalive(std::int64_t now_ms) noexcept -> void;
        auto tick(std::int64_t now_ms) noexcept -> State;

        [[nodiscard]] auto state() const noexcept -> State { return state_; }
        [[nodiscard]] auto queued_count() const noexcept -> std::uint32_t { return queued_count_; }
        [[nodiscard]] auto stats() const noexcept -> Stats const& { return stats_; }
        [[nodiscard]] auto config() const noexcept -> Config const& { return config_; }
    };
}
