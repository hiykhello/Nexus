export module relay.reverse_tunnel;
import std;

export namespace relay::reverse_tunnel {
    inline constexpr std::uint16_t protocol_magic = 0x4E52; // "NR"
    inline constexpr std::uint8_t protocol_version = 1;
    inline constexpr std::size_t max_frame_payload = 65536;

    enum class FrameKind : std::uint8_t {
        register_req = 1,
        register_ack = 2,
        open_stream = 3,
        stream_data = 4,
        half_close = 5,
        reset_stream = 6,
        ping = 7,
        pong = 8,
    };

    struct Frame {
        FrameKind kind = FrameKind::ping;
        std::uint32_t stream_id = 0;
        std::vector<std::uint8_t> payload;
        auto operator==(Frame const&) const -> bool = default;
    };

    struct StreamState {
        std::uint32_t id = 0;
        bool local_fin = false;
        bool remote_fin = false;
        std::uint64_t bytes_relayed = 0;
    };

    [[nodiscard]] auto encode_frame(Frame const& f) -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto decode_frame(std::span<std::uint8_t const> wire)
        -> std::expected<std::pair<Frame, std::size_t>, std::string>;

    class TunnelSession {
        std::string expected_token_;
        std::size_t max_streams_;
        bool registered_{false};
        std::uint32_t generation_{0};
        std::int64_t last_heartbeat_ms_{0};
        std::map<std::uint32_t, StreamState> streams_;

    public:
        explicit TunnelSession(std::string token, std::size_t max_streams = 256)
            : expected_token_(std::move(token)), max_streams_(max_streams) {}

        [[nodiscard]] auto handle_register(std::string_view presented_token, std::int64_t now_ms) -> Frame;
        [[nodiscard]] auto open_stream(std::uint32_t stream_id) -> std::expected<Frame, std::string>;
        [[nodiscard]] auto on_data(std::uint32_t stream_id, std::size_t bytes) -> std::expected<void, std::string>;
        [[nodiscard]] auto close_local(std::uint32_t stream_id) -> std::expected<Frame, std::string>;
        [[nodiscard]] auto on_remote_half_close(std::uint32_t stream_id) -> std::expected<bool, std::string>;
        auto on_heartbeat(std::int64_t now_ms) noexcept -> Frame;
        [[nodiscard]] auto heartbeat_expired(std::int64_t now_ms, std::chrono::milliseconds timeout) const noexcept -> bool;
        auto reset_all_for_reconnect() noexcept -> void;

        [[nodiscard]] auto registered() const noexcept -> bool { return registered_; }
        [[nodiscard]] auto active_streams() const noexcept -> std::size_t { return streams_.size(); }
        [[nodiscard]] auto generation() const noexcept -> std::uint32_t { return generation_; }
    };
}
