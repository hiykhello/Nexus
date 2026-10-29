module nexus.tcp.handshake;
import nexus.packet;
import std;

namespace nexus::tcp {
    PassiveHandshake::PassiveHandshake(packet::Tcp4View syn, std::uint32_t iss, std::uint16_t peer_mss)
        : local_(syn.destination), remote_(syn.source), local_port_(syn.destination_port),
          remote_port_(syn.source_port), peer_mss_(peer_mss), iss_(iss), irs_(syn.sequence) {}
    auto PassiveHandshake::accept(packet::Tcp4View syn, std::uint32_t iss)
        -> std::expected<PassiveHandshake, HandshakeError> {
        if (syn.flags != 0x02 || !syn.payload.empty()) return std::unexpected(HandshakeError::invalid_syn);
        auto options = packet::parse_tcp_syn_options(syn.options);
        if (!options || options->mss == 0) return std::unexpected(HandshakeError::invalid_options);
        return PassiveHandshake(syn, iss, options->mss.value_or(536));
    }
    auto PassiveHandshake::syn_ack(std::uint16_t window) const -> packet::Tcp4View {
        return {.source=local_, .destination=remote_, .source_port=local_port_, .destination_port=remote_port_,
                .sequence=iss_, .acknowledgement=irs_ + 1, .flags=0x12, .window=window};
    }
    auto PassiveHandshake::input(packet::Tcp4View segment, std::uint16_t receive_window) -> std::expected<bool, HandshakeError> {
        if (segment.source != remote_ || segment.destination != local_ || segment.source_port != remote_port_ ||
            segment.destination_port != local_port_) return std::unexpected(HandshakeError::wrong_peer);
        if (established_) return std::unexpected(HandshakeError::unsupported_segment);
        if (segment.flags == 0x02 && segment.sequence == irs_ && segment.payload.empty()) {
            if (!packet::parse_tcp_syn_options(segment.options)) return std::unexpected(HandshakeError::invalid_options);
            return false; // Caller may retransmit syn_ack.
        }
        if (segment.flags != 0x10 && segment.flags != 0x18 && segment.flags != 0x11 && segment.flags != 0x19)
            return std::unexpected(HandshakeError::unsupported_segment);
        if (segment.payload.size() > 65535) return std::unexpected(HandshakeError::invalid_sequence);
        auto length=static_cast<std::uint32_t>(segment.payload.size()) + ((segment.flags & 1) ? 1u : 0u);
        auto next=receive_next();
        auto in_window=[&](std::uint32_t sequence) { return static_cast<std::uint32_t>(sequence-next)<receive_window; };
        auto acceptable=length==0 ? (receive_window ? in_window(segment.sequence) : segment.sequence==next)
            : receive_window && (in_window(segment.sequence) || in_window(segment.sequence+length-1));
        if (!acceptable) return std::unexpected(HandshakeError::invalid_sequence);
        if (!packet::parse_tcp_options(segment.options)) return std::unexpected(HandshakeError::invalid_options);
        if (segment.acknowledgement != iss_ + 1) return std::unexpected(HandshakeError::invalid_ack);
        established_ = true;
        return true;
    }
    auto HandshakeTimer::add(std::uint64_t a, std::uint64_t b) noexcept -> std::uint64_t {
        return a > std::numeric_limits<std::uint64_t>::max() - b ? std::numeric_limits<std::uint64_t>::max() : a + b;
    }
    auto HandshakeTimer::poll(std::uint64_t now) noexcept -> std::expected<HandshakeTimerEvent, HandshakeTimerError> {
        if (now < now_) return std::unexpected(HandshakeTimerError::time_reversed);
        if (stopped_) return std::unexpected(HandshakeTimerError::stopped);
        now_ = now;
        if (now < deadline_) return HandshakeTimerEvent::waiting;
        if (retries_ == 4) { stopped_ = true; return HandshakeTimerEvent::expired; }
        return HandshakeTimerEvent::retransmit;
    }
    auto HandshakeTimer::retransmitted(std::uint64_t now) noexcept -> std::expected<void, HandshakeTimerError> {
        auto event = poll(now);
        if (!event) return std::unexpected(event.error());
        if (*event != HandshakeTimerEvent::retransmit) return std::unexpected(HandshakeTimerError::not_due);
        ++retries_; interval_ *= 2; deadline_ = add(now, interval_);
        return {};
    }
}
