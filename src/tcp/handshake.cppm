export module nexus.tcp.handshake;
import nexus.packet;
import std;

export namespace nexus::tcp {
    enum class HandshakeError { invalid_syn, invalid_options, wrong_peer, invalid_ack, unsupported_segment };
    // One tuple, no timers or socket ownership. ISS is supplied by the caller.
    class PassiveHandshake {
        packet::Address4 local_, remote_;
        std::uint16_t local_port_, remote_port_;
        std::uint16_t peer_mss_;
        std::uint32_t iss_, irs_;
        bool established_ = false;
        PassiveHandshake(packet::Tcp4View syn, std::uint32_t iss, std::uint16_t peer_mss);
    public:
        [[nodiscard]] static auto accept(packet::Tcp4View syn, std::uint32_t iss)
            -> std::expected<PassiveHandshake, HandshakeError>;
        [[nodiscard]] auto syn_ack(std::uint16_t window) const -> packet::Tcp4View;
        // On true, caller must process the same segment's payload and FIN with receive_next().
        [[nodiscard]] auto input(packet::Tcp4View segment) -> std::expected<bool, HandshakeError>;
        [[nodiscard]] auto established() const noexcept -> bool { return established_; }
        [[nodiscard]] auto send_next() const noexcept -> std::uint32_t { return iss_ + 1; }
        [[nodiscard]] auto receive_next() const noexcept -> std::uint32_t { return irs_ + 1; }
        [[nodiscard]] auto peer_mss() const noexcept -> std::uint16_t { return peer_mss_; }
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
