module tcp.handshake;
import packet;
import std;

namespace tcp {
    PassiveHandshake::PassiveHandshake(packet::Tcp4View syn, std::uint32_t iss, std::uint16_t peer_mss,
        std::optional<std::uint8_t> peer_wscale, std::uint8_t local_wscale, bool sack_permitted)
        : local_(syn.destination), remote_(syn.source), local_port_(syn.destination_port),
          remote_port_(syn.source_port), peer_mss_(peer_mss), iss_(iss), irs_(syn.sequence),
          peer_wscale_(peer_wscale), local_wscale_(std::min<std::uint8_t>(local_wscale, 14)),
          sack_permitted_(sack_permitted) {
        // RFC 7323: emit Window Scale in SYN-ACK only when peer offered Window Scale in SYN.
        if (peer_wscale_) {
            syn_ack_opts_[syn_ack_opts_len_++] = 3;
            syn_ack_opts_[syn_ack_opts_len_++] = 3;
            syn_ack_opts_[syn_ack_opts_len_++] = local_wscale_;
            syn_ack_opts_[syn_ack_opts_len_++] = 1; // NOP pad to 4 bytes
        }
        if (sack_permitted_) {
            syn_ack_opts_[syn_ack_opts_len_++] = 4;
            syn_ack_opts_[syn_ack_opts_len_++] = 2;
            syn_ack_opts_[syn_ack_opts_len_++] = 1;
            syn_ack_opts_[syn_ack_opts_len_++] = 1;
        }
    }
    auto PassiveHandshake::accept(packet::Tcp4View syn, std::uint32_t iss, std::uint16_t default_mss,
        std::uint8_t local_wscale)
        -> std::expected<PassiveHandshake, HandshakeError> {
        if (!is_initial_syn(syn.flags) || !syn.payload.empty()) return std::unexpected(HandshakeError::invalid_syn);
        auto options = packet::parse_tcp_syn_options(syn.options);
        if (!options || options->mss == 0 || !default_mss) return std::unexpected(HandshakeError::invalid_options);
        return PassiveHandshake(syn, iss, options->mss.value_or(default_mss),
            options->window_scale, local_wscale, options->sack_permitted);
    }
    auto PassiveHandshake::syn_ack(std::uint16_t window) const -> packet::Tcp4View {
        return {.source=local_, .destination=remote_, .source_port=local_port_, .destination_port=remote_port_,
                .sequence=iss_, .acknowledgement=irs_ + 1, .flags=0x12, .window=window,
                .options=std::span<std::uint8_t const>(syn_ack_opts_.data(), syn_ack_opts_len_)};
    }
    auto PassiveHandshake::input(packet::Tcp4View segment, std::size_t receive_window) -> std::expected<bool, HandshakeError> {
        if (segment.source != remote_ || segment.destination != local_ || segment.source_port != remote_port_ ||
            segment.destination_port != local_port_) return std::unexpected(HandshakeError::wrong_peer);
        if (established_) return std::unexpected(HandshakeError::unsupported_segment);
        if (is_initial_syn(segment.flags) && segment.sequence == irs_ && segment.payload.empty()) {
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
    namespace {
        auto core_segment(packet::Tcp6View v) -> packet::Tcp4View {
            return {.source_port=v.source_port,.destination_port=v.destination_port,.sequence=v.sequence,
                    .acknowledgement=v.acknowledgement,.flags=v.flags,.window=v.window,.urgent=v.urgent,
                    .options=v.options,.payload=v.payload};
        }
    }
    auto PassiveHandshake6::accept(packet::Tcp6View syn, std::uint32_t iss, std::uint8_t local_wscale)
        -> std::expected<PassiveHandshake6, HandshakeError> {
        auto core=PassiveHandshake::accept(core_segment(syn),iss,1220,local_wscale);
        if (!core) return std::unexpected(core.error());
        return PassiveHandshake6(syn,std::move(*core));
    }
    auto PassiveHandshake6::syn_ack(std::uint16_t window) const -> packet::Tcp6View {
        auto v=core_.syn_ack(window);
        return {.source=local_,.destination=remote_,.source_port=v.source_port,.destination_port=v.destination_port,
                .sequence=v.sequence,.acknowledgement=v.acknowledgement,.flags=v.flags,.window=v.window,
                .options=v.options};
    }
    auto PassiveHandshake6::input(packet::Tcp6View segment, std::size_t receive_window) -> std::expected<bool,HandshakeError> {
        if (segment.source!=remote_ || segment.destination!=local_ || segment.source_port!=remote_port_ ||
            segment.destination_port!=local_port_) return std::unexpected(HandshakeError::wrong_peer);
        return core_.input(core_segment(segment),receive_window);
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
