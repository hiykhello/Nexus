export module tcp.connection;
export import packet;
export import tcp.handshake;
import tcp.receive;
export import tcp.send;
import std;

export namespace tcp {
    enum class ConnectionError { invalid_capacity, invalid_packet, invalid_ack, wrong_peer, unsupported, expired, time_reversed, capacity, unacceptable, challenge_ack, reset };
    enum class ConnectionState { handshake, established, peer_closed, expired, reset };
    // Experimental single passive flow. Caller sends the initial SYN-ACK on creation.
    class PassiveConnection {
        PassiveHandshake handshake_;
        HandshakeTimer timer_;
        ReceiveBuffer receive_;
        TimedSend send_;
        mutable std::uint64_t now_;
        std::uint8_t initial_dscp_=0;
        std::uint32_t peer_window_ = 0, max_peer_window_ = 0;
        std::uint16_t effective_mss_ = 536;
        std::uint32_t window_sequence_ = 0, window_ack_ = 0;
        mutable std::array<std::uint8_t, 28> ack_opts_{};
        mutable std::size_t ack_opts_len_ = 0;
        bool close_requested_ = false, fin_sent_ = false, fin_acked_ = false;
        bool active_close_ = false, retired_ = false, reader_detached_ = false;
        std::optional<std::uint64_t> time_wait_deadline_, detach_deadline_;
        std::uint64_t time_wait_time_ = 0;
        std::uint32_t fin_sequence_ = 0;
        std::uint64_t fin_time_ = 0, fin_deadline_ = 0, fin_rto_ = 1000;
        std::optional<std::uint64_t> probe_deadline_;
        std::uint64_t probe_time_ = 0, probe_rto_ = 1000;
        unsigned probe_retries_ = 0, fin_retries_ = 0;
        ConnectionState state_ = ConnectionState::handshake;
        static constexpr unsigned kMaxProbeRetries = 8, kMaxFinRetries = 8;
        static constexpr std::uint64_t kFinWait2TimeoutMs = 60000;
        PassiveConnection(PassiveHandshake handshake, ReceiveBuffer receive, TimedSend send, std::uint64_t now);
        auto advance(std::uint64_t now) const noexcept -> bool;
        auto drain_receive() noexcept -> void;
        auto update_close(std::uint64_t now, bool duplicate_fin) noexcept -> void;
    public:
        [[nodiscard]] static auto accept(packet::Tcp4View syn, std::uint32_t iss, std::size_t capacity, std::uint64_t now,
                                         std::uint16_t default_mss = 536)
            -> std::expected<PassiveConnection, ConnectionError>;
        [[nodiscard]] auto initial_dscp() const noexcept -> std::uint8_t { return initial_dscp_; }
        [[nodiscard]] auto syn_ack() const -> packet::Tcp4View;
        [[nodiscard]] auto input(packet::Tcp4View segment, std::uint64_t now = 0) -> std::expected<bool, ConnectionError>;
        [[nodiscard]] auto poll(std::uint64_t now) -> std::expected<HandshakeTimerEvent, ConnectionError>;
        [[nodiscard]] auto retransmitted(std::uint64_t now) -> std::expected<void, ConnectionError>;
        [[nodiscard]] auto read(std::span<std::uint8_t> output) noexcept -> std::size_t {
            if (state_ == ConnectionState::reset) return 0;
            auto n = receive_.read(output);
            if (time_wait_deadline_ && receive_.ready() == 0 && send_.queued() == 0) {
                receive_.release_storage();
                send_.release_storage();
            }
            return n;
        }
        auto detach_reader() noexcept -> void;
        [[nodiscard]] auto reader_detached() const noexcept -> bool { return reader_detached_; }
        [[nodiscard]] auto eof() const noexcept -> bool { return state_ != ConnectionState::reset && receive_.finished() && receive_.ready() == 0; }
        [[nodiscard]] auto ack(std::size_t max_options = 28) const -> packet::Tcp4View;
        // Preview the window after reading up to maximum bytes; no data is consumed.
        [[nodiscard]] auto ack_after_read(std::size_t maximum, std::size_t max_options = 28) const -> packet::Tcp4View {
            auto result = ack(max_options);
            if (state_ != ConnectionState::reset && !receive_.finished()) {
                auto win = receive_.window() + std::min(maximum, receive_.ready());
                auto shift = handshake_.local_window_scale();
                result.window = static_cast<std::uint16_t>(std::min<std::size_t>(65535, win >> shift));
            }
            return result;
        }
        auto set_pmtu(std::uint16_t mtu, bool ipv6 = false) noexcept -> void;
        [[nodiscard]] auto effective_mss() const noexcept -> std::uint16_t { return effective_mss_; }
        [[nodiscard]] auto peer_window() const noexcept -> std::uint32_t { return peer_window_; }
        [[nodiscard]] auto window_scaling_enabled() const noexcept -> bool { return handshake_.window_scaling_enabled(); }
        [[nodiscard]] auto srtt_ms() const noexcept -> std::optional<std::uint64_t> { return send_.srtt_ms(); }
        [[nodiscard]] auto enqueue(std::span<std::uint8_t const> data) -> std::expected<void, ConnectionError>;
        [[nodiscard]] auto send_capacity() const noexcept -> std::size_t {
            return (state_ == ConnectionState::established || state_ == ConnectionState::peer_closed) && !close_requested_
                ? send_.available() : 0;
        }
        [[nodiscard]] auto unsent(std::size_t maximum) const -> SendSlice;
        [[nodiscard]] auto sent(std::size_t count, std::uint64_t now) -> std::expected<void, ConnectionError>;
        [[nodiscard]] auto send_due(std::uint64_t now, std::size_t maximum) -> std::expected<std::optional<SendSlice>, ConnectionError>;
        [[nodiscard]] auto send_retransmitted(std::uint64_t now) -> std::expected<void, ConnectionError>;
        // Poll arms the timer; commit only after the returned probe is actually sent.
        [[nodiscard]] auto probe_due(std::uint64_t now) -> std::expected<std::optional<SendSlice>, ConnectionError>;
        [[nodiscard]] auto probe_sent(std::uint64_t now) -> std::expected<void, ConnectionError>;
        [[nodiscard]] auto close_send() noexcept -> std::expected<void, ConnectionError>;
        [[nodiscard]] auto fin_ready() const noexcept -> bool;
        [[nodiscard]] auto fin(std::size_t max_options = 28) const -> packet::Tcp4View;
        [[nodiscard]] auto fin_sent(std::uint64_t now) noexcept -> std::expected<void, ConnectionError>;
        [[nodiscard]] auto fin_due(std::uint64_t now) const noexcept -> std::expected<bool, ConnectionError>;
        [[nodiscard]] auto fin_retransmitted(std::uint64_t now) noexcept -> std::expected<void, ConnectionError>;
        [[nodiscard]] auto send_closed() const noexcept -> bool { return fin_acked_; }
        [[nodiscard]] auto fin_pending() const noexcept -> bool { return fin_sent_ && !fin_acked_; }
        // Caller drives time and must retain the tuple while this returns false.
        [[nodiscard]] auto reclaimable(std::uint64_t now) noexcept -> std::expected<bool, ConnectionError>;
        [[nodiscard]] auto time_wait_deadline() const noexcept -> std::optional<std::uint64_t> { return time_wait_deadline_; }
        [[nodiscard]] auto state() const noexcept -> ConnectionState { return state_; }
        [[nodiscard]] auto abort(std::uint64_t now) noexcept -> std::expected<void, ConnectionError>;
    };
    // IPv6 tuple ownership and validation surround the shared TCP state machine.
    class PassiveConnection6 {
        packet::Address6 local_, remote_;
        std::uint16_t local_port_, remote_port_;
        PassiveConnection core_;
        PassiveConnection6(packet::Tcp6View syn, PassiveConnection core)
            : local_(syn.destination), remote_(syn.source), local_port_(syn.destination_port),
              remote_port_(syn.source_port), core_(std::move(core)) {}
        [[nodiscard]] auto as_ipv6(packet::Tcp4View segment) const -> packet::Tcp6View;
    public:
        [[nodiscard]] static auto accept(packet::Tcp6View syn, std::uint32_t iss, std::size_t capacity, std::uint64_t now)
            -> std::expected<PassiveConnection6, ConnectionError>;
        [[nodiscard]] auto input(packet::Tcp6View segment, std::uint64_t now = 0) -> std::expected<bool, ConnectionError>;
        [[nodiscard]] auto initial_dscp() const noexcept -> std::uint8_t { return core_.initial_dscp(); }
        [[nodiscard]] auto syn_ack() const -> packet::Tcp6View { return as_ipv6(core_.syn_ack()); }
        [[nodiscard]] auto ack(std::size_t max_options = 28) const -> packet::Tcp6View { return as_ipv6(core_.ack(max_options)); }
        [[nodiscard]] auto ack_after_read(std::size_t n, std::size_t max_options = 28) const -> packet::Tcp6View { return as_ipv6(core_.ack_after_read(n, max_options)); }
        [[nodiscard]] auto fin(std::size_t max_options = 28) const -> packet::Tcp6View { return as_ipv6(core_.fin(max_options)); }
        [[nodiscard]] auto poll(std::uint64_t now) { return core_.poll(now); }
        [[nodiscard]] auto retransmitted(std::uint64_t now) { return core_.retransmitted(now); }
        [[nodiscard]] auto read(std::span<std::uint8_t> output) noexcept -> std::size_t { return core_.read(output); }
        auto detach_reader() noexcept -> void { core_.detach_reader(); }
        [[nodiscard]] auto reader_detached() const noexcept -> bool { return core_.reader_detached(); }
        [[nodiscard]] auto eof() const noexcept -> bool { return core_.eof(); }
        [[nodiscard]] auto enqueue(std::span<std::uint8_t const> data) { return core_.enqueue(data); }
        [[nodiscard]] auto send_capacity() const noexcept -> std::size_t { return core_.send_capacity(); }
        [[nodiscard]] auto unsent(std::size_t maximum) const { return core_.unsent(maximum); }
        [[nodiscard]] auto sent(std::size_t count, std::uint64_t now) { return core_.sent(count,now); }
        [[nodiscard]] auto send_due(std::uint64_t now,std::size_t maximum) { return core_.send_due(now,maximum); }
        [[nodiscard]] auto send_retransmitted(std::uint64_t now) { return core_.send_retransmitted(now); }
        [[nodiscard]] auto probe_due(std::uint64_t now) { return core_.probe_due(now); }
        [[nodiscard]] auto probe_sent(std::uint64_t now) { return core_.probe_sent(now); }
        [[nodiscard]] auto close_send() noexcept { return core_.close_send(); }
        [[nodiscard]] auto fin_ready() const noexcept -> bool { return core_.fin_ready(); }
        [[nodiscard]] auto fin_sent(std::uint64_t now) noexcept { return core_.fin_sent(now); }
        [[nodiscard]] auto fin_due(std::uint64_t now) const noexcept { return core_.fin_due(now); }
        [[nodiscard]] auto fin_retransmitted(std::uint64_t now) noexcept { return core_.fin_retransmitted(now); }
        [[nodiscard]] auto send_closed() const noexcept -> bool { return core_.send_closed(); }
        [[nodiscard]] auto fin_pending() const noexcept -> bool { return core_.fin_pending(); }
        [[nodiscard]] auto reclaimable(std::uint64_t now) noexcept { return core_.reclaimable(now); }
        [[nodiscard]] auto time_wait_deadline() const noexcept { return core_.time_wait_deadline(); }
        [[nodiscard]] auto state() const noexcept -> ConnectionState { return core_.state(); }
        [[nodiscard]] auto abort(std::uint64_t now) noexcept { return core_.abort(now); }
    };
}
