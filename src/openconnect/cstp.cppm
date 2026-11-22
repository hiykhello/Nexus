export module openconnect.cstp;
import std;
export import openconnect.types;

export namespace openconnect {
    [[nodiscard]] auto encode_cstp_frame(CstpType type, std::span<std::uint8_t const> payload)
        -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto decode_cstp_frame(std::span<std::uint8_t const> buffer)
        -> std::expected<std::pair<CstpFrame, std::size_t>, std::string>;

    class Session {
    public:
        enum class State { disconnected, connected, reconnecting };
    private:
        State state_{State::disconnected};
        bool dtls_active_{false};
        std::uint64_t tx_frames_{0};
        std::uint64_t rx_frames_{0};
        std::uint32_t generation_{0};
    public:
        auto on_connected(bool has_dtls_session) noexcept -> void;
        [[nodiscard]] auto handle_frame(CstpFrame const& frame) -> std::optional<CstpFrame>;
        [[nodiscard]] auto make_dpd_req() -> CstpFrame;
        [[nodiscard]] auto make_keepalive() -> CstpFrame;
        auto trigger_reconnect() noexcept -> void;
        auto fallback_to_cstp() noexcept -> void { dtls_active_ = false; }

        [[nodiscard]] auto state() const noexcept -> State { return state_; }
        [[nodiscard]] auto dtls_active() const noexcept -> bool { return dtls_active_; }
        [[nodiscard]] auto tx_frames() const noexcept -> std::uint64_t { return tx_frames_; }
        [[nodiscard]] auto rx_frames() const noexcept -> std::uint64_t { return rx_frames_; }
        [[nodiscard]] auto generation() const noexcept -> std::uint32_t { return generation_; }
    };
}
