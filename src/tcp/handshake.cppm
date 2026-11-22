export module tcp.handshake;
import packet;
import std;

export namespace tcp {
    // ECE and CWR on SYN request ECN; this stack replies without ECN negotiation.
    [[nodiscard]] constexpr auto is_initial_syn(std::uint16_t flags) noexcept -> bool {
        return (flags & ~std::uint16_t{0xc0}) == 0x02;
    }
    enum class HandshakeError { invalid_syn, invalid_options, wrong_peer, invalid_sequence, invalid_ack, unsupported_segment };
    // One tuple, no timers or socket ownership. ISS is supplied by the caller.
    class PassiveHandshake {
        packet::Address4 local_, remote_;
        std::uint16_t local_port_, remote_port_;
        std::uint16_t peer_mss_;
        std::uint32_t iss_, irs_;
        std::optional<std::uint8_t> peer_wscale_;
        std::uint8_t local_wscale_ = 0;
        bool sack_permitted_ = false;
        std::array<std::uint8_t, 8> syn_ack_opts_{};
        std::size_t syn_ack_opts_len_ = 0;
        bool established_ = false;
        PassiveHandshake(packet::Tcp4View syn, std::uint32_t iss, std::uint16_t peer_mss,
            std::optional<std::uint8_t> peer_wscale, std::uint8_t local_wscale, bool sack_permitted);
    public:
        [[nodiscard]] static auto accept(packet::Tcp4View syn, std::uint32_t iss, std::uint16_t default_mss = 536,
            std::uint8_t local_wscale = 0)
            -> std::expected<PassiveHandshake, HandshakeError>;
        [[nodiscard]] auto syn_ack(std::uint16_t window) const -> packet::Tcp4View;
        // On true, caller must process the same segment's payload and FIN with receive_next().
        // receive_window is the currently advertised window in bytes.
        [[nodiscard]] auto input(packet::Tcp4View segment, std::size_t receive_window) -> std::expected<bool, HandshakeError>;
        [[nodiscard]] auto established() const noexcept -> bool { return established_; }
        [[nodiscard]] auto send_next() const noexcept -> std::uint32_t { return iss_ + 1; }
        [[nodiscard]] auto receive_next() const noexcept -> std::uint32_t { return irs_ + 1; }
        [[nodiscard]] auto peer_mss() const noexcept -> std::uint16_t { return peer_mss_; }
        [[nodiscard]] auto peer_window_scale() const noexcept -> std::uint8_t { return peer_wscale_.value_or(0); }
        [[nodiscard]] auto local_window_scale() const noexcept -> std::uint8_t { return peer_wscale_ ? local_wscale_ : 0; }
        [[nodiscard]] auto window_scaling_enabled() const noexcept -> bool { return peer_wscale_.has_value(); }
        [[nodiscard]] auto sack_permitted() const noexcept -> bool { return sack_permitted_; }
    };
    // IPv6 tuple validation is separate from the address-independent handshake state.
    class PassiveHandshake6 {
        packet::Address6 local_, remote_;
        std::uint16_t local_port_, remote_port_;
        PassiveHandshake core_;
        PassiveHandshake6(packet::Tcp6View syn, PassiveHandshake core)
            : local_(syn.destination), remote_(syn.source), local_port_(syn.destination_port),
              remote_port_(syn.source_port), core_(std::move(core)) {}
    public:
        [[nodiscard]] static auto accept(packet::Tcp6View syn, std::uint32_t iss, std::uint8_t local_wscale = 0)
            -> std::expected<PassiveHandshake6, HandshakeError>;
        [[nodiscard]] auto syn_ack(std::uint16_t window) const -> packet::Tcp6View;
        [[nodiscard]] auto input(packet::Tcp6View segment, std::size_t receive_window) -> std::expected<bool, HandshakeError>;
        [[nodiscard]] auto established() const noexcept -> bool { return core_.established(); }
        [[nodiscard]] auto send_next() const noexcept -> std::uint32_t { return core_.send_next(); }
        [[nodiscard]] auto receive_next() const noexcept -> std::uint32_t { return core_.receive_next(); }
        [[nodiscard]] auto peer_mss() const noexcept -> std::uint16_t { return core_.peer_mss(); }
    };
    enum class HandshakeTimerError { time_reversed, not_due, stopped };
    enum class HandshakeTimerEvent { waiting, retransmit, expired };
    // Initial SYN-ACK is sent before construction. Four retransmissions at most.
    class HandshakeTimer {
        std::uint64_t now_, deadline_, interval_ = 1000;
        unsigned retries_ = 0;
        bool stopped_ = false;
        static auto add(std::uint64_t a, std::uint64_t b) noexcept -> std::uint64_t;
    public:
        explicit HandshakeTimer(std::uint64_t now) noexcept : now_(now), deadline_(add(now, 1000)) {}
        [[nodiscard]] auto poll(std::uint64_t now) noexcept -> std::expected<HandshakeTimerEvent, HandshakeTimerError>;
        [[nodiscard]] auto retransmitted(std::uint64_t now) noexcept -> std::expected<void, HandshakeTimerError>;
        auto stop() noexcept -> void { stopped_ = true; }
        [[nodiscard]] auto deadline() const noexcept -> std::uint64_t { return deadline_; }
    };
}
