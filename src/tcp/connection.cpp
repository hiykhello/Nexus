module nexus.tcp.connection;
import nexus.packet;
import nexus.tcp.handshake;
import nexus.tcp.receive;
import nexus.tcp.send;
import std;

namespace nexus::tcp {
    PassiveConnection::PassiveConnection(PassiveHandshake handshake, ReceiveBuffer receive, TimedSend send, std::uint64_t now)
        : handshake_(std::move(handshake)), timer_(now), receive_(std::move(receive)), send_(std::move(send)), now_(now) {}
    auto PassiveConnection::advance(std::uint64_t now) const noexcept -> bool {
        if (now < now_) return false;
        now_ = now;
        return true;
    }
    auto PassiveConnection::accept(packet::Tcp4View syn, std::uint32_t iss, std::size_t capacity, std::uint64_t now)
        -> std::expected<PassiveConnection, ConnectionError> {
        if (!capacity || capacity > 65535) return std::unexpected(ConnectionError::invalid_capacity);
        auto handshake = PassiveHandshake::accept(syn, iss);
        if (!handshake) return std::unexpected(ConnectionError::invalid_packet);
        auto receive = ReceiveBuffer::create(handshake->receive_next(), capacity);
        if (!receive) return std::unexpected(ConnectionError::invalid_capacity);
        auto send = TimedSend::create(handshake->send_next(), capacity);
        if (!send) return std::unexpected(ConnectionError::invalid_capacity);
        return PassiveConnection(std::move(*handshake), std::move(*receive), std::move(*send), now);
    }
    auto PassiveConnection::syn_ack() const -> packet::Tcp4View {
        return handshake_.syn_ack(static_cast<std::uint16_t>(receive_.window()));
    }
    auto PassiveConnection::input(packet::Tcp4View segment, std::uint64_t now) -> std::expected<bool, ConnectionError> {
        if (state_ == ConnectionState::expired) return std::unexpected(ConnectionError::expired);
        if (state_ == ConnectionState::reset) return std::unexpected(ConnectionError::reset);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        if (time_wait_deadline_ && now < time_wait_time_) return std::unexpected(ConnectionError::time_reversed);
        if (retired_) return std::unexpected(ConnectionError::expired);
        if (time_wait_deadline_ && now >= *time_wait_deadline_) {
            time_wait_time_ = now; retired_ = true;
            return std::unexpected(ConnectionError::expired);
        }
        auto outgoing = syn_ack();
        if (segment.source != outgoing.destination || segment.destination != outgoing.source ||
            segment.source_port != outgoing.destination_port || segment.destination_port != outgoing.source_port)
            return std::unexpected(ConnectionError::wrong_peer);
        if (state_ == ConnectionState::handshake) {
            auto event = timer_.poll(now);
            if (!event) return std::unexpected(ConnectionError::time_reversed);
            if (*event == HandshakeTimerEvent::expired) {
                state_ = ConnectionState::expired;
                return std::unexpected(ConnectionError::expired);
            }
        } else {
            if (fin_sent_ && now < fin_time_) return std::unexpected(ConnectionError::time_reversed);
            if (!send_.due(now, 0)) return std::unexpected(ConnectionError::time_reversed);
        }
        if (segment.flags & 0x04) {
            auto next = receive_.next();
            if (segment.sequence == next) {
                timer_.stop(); state_ = ConnectionState::reset;
                return std::unexpected(ConnectionError::reset);
            }
            if (static_cast<std::uint32_t>(segment.sequence - next) < receive_.window())
                return std::unexpected(ConnectionError::challenge_ack);
            return std::unexpected(ConnectionError::unacceptable);
        }
        bool duplicate_fin = false;
        if (state_ == ConnectionState::handshake) {
            auto result = handshake_.input(segment);
            if (!result) return std::unexpected(result.error() == HandshakeError::invalid_ack
                ? ConnectionError::invalid_ack : ConnectionError::invalid_packet);
            if (!*result) return false;
            timer_.stop(); state_ = ConnectionState::established; peer_window_ = segment.window;
            window_sequence_ = segment.sequence; window_ack_ = segment.acknowledgement;
            (void)send_.due(now, 0);
        } else {
            if (segment.flags != 0x10 && segment.flags != 0x18 && segment.flags != 0x11 && segment.flags != 0x19)
                return std::unexpected(ConnectionError::unsupported);
            if (!packet::parse_tcp_options(segment.options)) return std::unexpected(ConnectionError::invalid_packet);
            // Validate sequence space before accepting ACK or window updates.
            if (segment.payload.size() > 65535) return std::unexpected(ConnectionError::unacceptable);
            auto length = static_cast<std::uint32_t>(segment.payload.size()) + ((segment.flags & 1) ? 1u : 0u);
            auto next = receive_.next();
            auto window = receive_.window();
            auto in_window = [&](std::uint32_t sequence) { return static_cast<std::uint32_t>(sequence - next) < window; };
            bool acceptable = length == 0 ? (window ? in_window(segment.sequence) : segment.sequence == next)
                : window && (in_window(segment.sequence) || in_window(segment.sequence + length - 1));
            // The retransmission may include the data that originally preceded FIN.
            if (!acceptable && state_ == ConnectionState::peer_closed && (segment.flags & 1) &&
                segment.sequence + static_cast<std::uint32_t>(segment.payload.size()) + 1 == next) {
                acceptable = true; duplicate_fin = true;
            }
            if (!acceptable) return std::unexpected(ConnectionError::unacceptable);
            auto ack_before = [](std::uint32_t a, std::uint32_t b) {
                return a != b && static_cast<std::uint32_t>(b - a) < 0x80000000u;
            };
            auto stale_ack = ack_before(segment.acknowledgement, send_.una());
            if (!stale_ack && fin_sent_ && segment.acknowledgement == fin_sequence_ + 1) {
                fin_time_ = now; fin_acked_ = true;
            } else if (!stale_ack) {
                auto acknowledged = send_.acknowledge(segment.acknowledgement, now);
                if (!acknowledged) return std::unexpected(acknowledged.error() == SendError::time_reversed
                    ? ConnectionError::time_reversed : ConnectionError::invalid_ack);
            }
            auto newer_sequence = ack_before(window_sequence_, segment.sequence);
            auto same_sequence = window_sequence_ == segment.sequence;
            if (!stale_ack && (newer_sequence || (same_sequence && !ack_before(segment.acknowledgement, window_ack_)))) {
                peer_window_ = segment.window;
                window_sequence_ = segment.sequence; window_ack_ = segment.acknowledgement;
                if (peer_window_) { probe_deadline_.reset(); probe_rto_ = 1000; }
            }
        }
        (void)receive_.insert(segment.sequence, segment.payload);
        if (segment.flags & 1) {
            auto fin_sequence = segment.sequence + static_cast<std::uint32_t>(segment.payload.size());
            (void)receive_.insert_fin(fin_sequence);
        }
        if (receive_.finished()) state_ = ConnectionState::peer_closed;
        update_close(now, duplicate_fin);
        return true;
    }
    auto PassiveConnection::poll(std::uint64_t now) -> std::expected<HandshakeTimerEvent, ConnectionError> {
        if (state_ == ConnectionState::expired) return std::unexpected(ConnectionError::expired);
        if (state_ != ConnectionState::handshake) return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        auto event = timer_.poll(now);
        if (!event) return std::unexpected(ConnectionError::time_reversed);
        if (*event == HandshakeTimerEvent::expired) state_ = ConnectionState::expired;
        return *event;
    }
    auto PassiveConnection::retransmitted(std::uint64_t now) -> std::expected<void, ConnectionError> {
        if (state_ != ConnectionState::handshake) return std::unexpected(ConnectionError::unsupported);
        auto event = poll(now);
        if (!event) return std::unexpected(event.error());
        if (*event == HandshakeTimerEvent::expired) return std::unexpected(ConnectionError::expired);
        if (*event != HandshakeTimerEvent::retransmit) return std::unexpected(ConnectionError::unsupported);
        auto result = timer_.retransmitted(now);
        if (!result) return std::unexpected(result.error() == HandshakeTimerError::time_reversed
            ? ConnectionError::time_reversed : ConnectionError::unsupported);
        return {};
    }
    auto PassiveConnection::ack() const -> packet::Tcp4View {
        auto result = syn_ack(); result.sequence = send_.next() + (fin_sent_ ? 1u : 0u);
        result.acknowledgement = receive_.next(); result.flags = 0x10; return result;
    }
    auto PassiveConnection::abort(std::uint64_t now) noexcept -> std::expected<void, ConnectionError> {
        if (state_ != ConnectionState::established && state_ != ConnectionState::peer_closed)
            return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        state_ = ConnectionState::reset;
        return {};
    }
    auto PassiveConnection::enqueue(std::span<std::uint8_t const> data) -> std::expected<void, ConnectionError> {
        if ((state_ != ConnectionState::established && state_ != ConnectionState::peer_closed) || close_requested_)
            return std::unexpected(ConnectionError::unsupported);
        if (!send_.enqueue(data)) return std::unexpected(ConnectionError::capacity);
        return {};
    }
    auto PassiveConnection::unsent(std::size_t maximum) const -> SendSlice {
        if (state_ != ConnectionState::established && state_ != ConnectionState::peer_closed) return send_.unsent(0);
        auto allowance = peer_window_ > send_.in_flight() ? peer_window_ - send_.in_flight() : 0;
        return send_.unsent(std::min({maximum, allowance, static_cast<std::size_t>(handshake_.peer_mss())}));
    }
    auto PassiveConnection::sent(std::size_t count, std::uint64_t now) -> std::expected<void, ConnectionError> {
        if (state_ != ConnectionState::established && state_ != ConnectionState::peer_closed) return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        auto allowance = peer_window_ > send_.in_flight() ? peer_window_ - send_.in_flight() : 0;
        auto available = std::min({allowance, send_.queued() - send_.in_flight(),
                                   static_cast<std::size_t>(handshake_.peer_mss())});
        if (count > available) return std::unexpected(ConnectionError::unsupported);
        auto result = send_.sent(count, now);
        if (!result) return std::unexpected(result.error() == SendError::time_reversed ? ConnectionError::time_reversed : ConnectionError::unsupported);
        return {};
    }
    auto PassiveConnection::send_due(std::uint64_t now, std::size_t maximum) -> std::expected<std::optional<SendSlice>, ConnectionError> {
        if (state_ != ConnectionState::established && state_ != ConnectionState::peer_closed) return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        auto result = send_.due(now, std::min({maximum, static_cast<std::size_t>(peer_window_),
                                               static_cast<std::size_t>(handshake_.peer_mss())}));
        if (!result) return std::unexpected(ConnectionError::time_reversed);
        return std::move(*result);
    }
    auto PassiveConnection::send_retransmitted(std::uint64_t now) -> std::expected<void, ConnectionError> {
        if (state_ != ConnectionState::established && state_ != ConnectionState::peer_closed) return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        if (!peer_window_) return std::unexpected(ConnectionError::unsupported);
        auto result = send_.retransmitted(now);
        if (!result) return std::unexpected(result.error() == SendError::time_reversed ? ConnectionError::time_reversed : ConnectionError::unsupported);
        return {};
    }
    auto PassiveConnection::probe_due(std::uint64_t now) -> std::expected<std::optional<SendSlice>, ConnectionError> {
        if (state_ != ConnectionState::established && state_ != ConnectionState::peer_closed)
            return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        if (!send_.due(now, 0)) return std::unexpected(ConnectionError::time_reversed);
        if (probe_deadline_ && now < probe_time_) return std::unexpected(ConnectionError::time_reversed);
        if (peer_window_ || (!send_.queued() && (!close_requested_ || fin_sent_))) {
            probe_deadline_.reset(); probe_rto_ = 1000;
            return std::optional<SendSlice>{};
        }
        probe_time_ = now;
        if (!probe_deadline_) {
            probe_deadline_ = now > std::numeric_limits<std::uint64_t>::max() - probe_rto_
                ? std::numeric_limits<std::uint64_t>::max() : now + probe_rto_;
            return std::optional<SendSlice>{};
        }
        if (now < *probe_deadline_) return std::optional<SendSlice>{};
        if (send_.in_flight()) return std::optional<SendSlice>{send_.retransmit(1)};
        if (send_.queued()) return std::optional<SendSlice>{send_.unsent(1)};
        return std::optional<SendSlice>{SendSlice{send_.next() - 1, {}}};
    }
    auto PassiveConnection::probe_sent(std::uint64_t now) -> std::expected<void, ConnectionError> {
        auto probe = probe_due(now);
        if (!probe) return std::unexpected(probe.error());
        if (!*probe) return std::unexpected(ConnectionError::unsupported);
        if (!send_.in_flight() && !(**probe).bytes.empty()) {
            if (!send_.sent(1, now)) return std::unexpected(ConnectionError::time_reversed);
        }
        probe_rto_ = std::min<std::uint64_t>(probe_rto_ * 2, 60000);
        probe_deadline_ = now > std::numeric_limits<std::uint64_t>::max() - probe_rto_
            ? std::numeric_limits<std::uint64_t>::max() : now + probe_rto_;
        return {};
    }
    auto PassiveConnection::close_send() noexcept -> std::expected<void, ConnectionError> {
        if (state_ != ConnectionState::established && state_ != ConnectionState::peer_closed)
            return std::unexpected(ConnectionError::unsupported);
        close_requested_ = true;
        return {};
    }
    auto PassiveConnection::fin_ready() const noexcept -> bool {
        return (state_ == ConnectionState::established || state_ == ConnectionState::peer_closed) &&
               close_requested_ && !fin_sent_ && send_.queued() == 0 && peer_window_ != 0;
    }
    auto PassiveConnection::fin() const -> packet::Tcp4View {
        auto result = ack(); result.sequence = fin_sent_ ? fin_sequence_ : send_.next(); result.flags = 0x11;
        return result;
    }
    auto PassiveConnection::fin_sent(std::uint64_t now) noexcept -> std::expected<void, ConnectionError> {
        if (!fin_ready()) return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        if (!send_.due(now, 0)) return std::unexpected(ConnectionError::time_reversed);
        fin_sequence_ = send_.next(); active_close_ = !receive_.finished(); fin_sent_ = true; fin_time_ = now;
        fin_deadline_ = now > std::numeric_limits<std::uint64_t>::max() - fin_rto_
            ? std::numeric_limits<std::uint64_t>::max() : now + fin_rto_;
        return {};
    }
    auto PassiveConnection::fin_due(std::uint64_t now) const noexcept -> std::expected<bool, ConnectionError> {
        if (!fin_sent_ || fin_acked_ || state_ == ConnectionState::reset) return std::unexpected(ConnectionError::unsupported);
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        if (now < fin_time_) return std::unexpected(ConnectionError::time_reversed);
        return now >= fin_deadline_;
    }
    auto PassiveConnection::fin_retransmitted(std::uint64_t now) noexcept -> std::expected<void, ConnectionError> {
        auto due = fin_due(now);
        if (!due) return std::unexpected(due.error());
        if (!*due) return std::unexpected(ConnectionError::unsupported);
        fin_time_ = now; fin_rto_ = std::min<std::uint64_t>(fin_rto_ * 2, 60000);
        fin_deadline_ = now > std::numeric_limits<std::uint64_t>::max() - fin_rto_
            ? std::numeric_limits<std::uint64_t>::max() : now + fin_rto_;
        return {};
    }
    auto PassiveConnection::update_close(std::uint64_t now, bool duplicate_fin) noexcept -> void {
        if (!active_close_ || !fin_acked_ || !receive_.finished()) return;
        if (!time_wait_deadline_ || duplicate_fin) {
            constexpr std::uint64_t wait_ms = 120000;
            time_wait_deadline_ = now > std::numeric_limits<std::uint64_t>::max() - wait_ms
                ? std::numeric_limits<std::uint64_t>::max() : now + wait_ms;
        }
        time_wait_time_ = now;
    }
    auto PassiveConnection::reclaimable(std::uint64_t now) noexcept -> std::expected<bool, ConnectionError> {
        if (!advance(now)) return std::unexpected(ConnectionError::time_reversed);
        if (time_wait_deadline_) {
            if (now < time_wait_time_) return std::unexpected(ConnectionError::time_reversed);
            time_wait_time_ = now;
        }
        if (!fin_acked_ || !receive_.finished() || receive_.ready()) return false;
        bool ready = !active_close_ || (time_wait_deadline_ && now >= *time_wait_deadline_);
        if (ready) retired_ = true;
        return ready;
    }
}
