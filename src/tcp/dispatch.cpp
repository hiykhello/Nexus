module tcp.dispatch;
import std;

namespace tcp {
    auto valid_syn_endpoints(packet::Tcp4View segment) noexcept -> bool {
        auto usable=[](packet::Address4 const& address) { return address[0]!=0 && address[0]<224; };
        return segment.source_port && segment.destination_port && usable(segment.source) && usable(segment.destination);
    }
    auto valid_syn_endpoints(packet::Tcp6View segment) noexcept -> bool {
        auto usable=[](packet::Address6 const& address) {
            bool link_local=address[0]==0xfe && (address[1]&0xc0)==0x80;
            bool mapped=std::ranges::all_of(std::span(address).first<10>(),[](auto byte) { return byte==0; }) &&
                        address[10]==255 && address[11]==255;
            if (mapped && (address[12]==0 || address[12]>=224)) return false;
            return address[0]!=0xff && !link_local &&
                   !std::ranges::all_of(address,[](auto byte) { return byte==0; });
        };
        return segment.source_port && segment.destination_port && usable(segment.source) && usable(segment.destination);
    }
    namespace {
        struct SynAckOptions {
            std::array<std::uint8_t, 12> bytes{};
            std::size_t length = 0;
            [[nodiscard]] auto span() const noexcept -> std::span<std::uint8_t const> { return {bytes.data(), length}; }
        };
        auto build_syn_ack_options(std::size_t mtu, std::size_t overhead, std::span<std::uint8_t const> existing) noexcept -> SynAckOptions {
            SynAckOptions out;
            auto mss = static_cast<std::uint16_t>(std::min<std::size_t>(mtu - overhead, 65535 - overhead));
            out.bytes[0] = 2; out.bytes[1] = 4;
            out.bytes[2] = static_cast<std::uint8_t>(mss >> 8); out.bytes[3] = static_cast<std::uint8_t>(mss);
            out.length = 4;
            auto extra = std::min(existing.size(), out.bytes.size() - out.length);
            extra -= extra % 4;
            std::copy_n(existing.data(), extra, out.bytes.data() + out.length);
            out.length += extra;
            return out;
        }
    }
    auto dispatch(ConnectionTable& table, std::span<std::uint8_t const> bytes,
                  std::uint32_t iss, std::uint64_t now, std::size_t mtu)
        -> std::expected<DispatchResult, DispatchFailure> {
        auto segment = packet::parse_tcp4(bytes);
        if (!segment) return std::unexpected(DispatchFailure{DispatchError::invalid_packet, segment.error(), {}});
        if (is_initial_syn(segment->flags) && !valid_syn_endpoints(*segment))
            return std::unexpected(DispatchFailure{DispatchError::invalid_target, {}, {}});
        // ACK and RST require 40 bytes; SYN-ACK also carries MSS + negotiated options.
        if (mtu < 40) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
        auto id = table.find(*segment);
        if (!id) {
            if (!is_initial_syn(segment->flags)) {
                auto unicast=[](packet::Address4 const& a) {
                    return a[0]!=0 && a[0]<224 && !std::ranges::all_of(a,[](auto b) { return b==255; });
                };
                if ((segment->flags & 4) || !segment->source_port || !segment->destination_port ||
                    !unicast(segment->source) || !unicast(segment->destination))
                    return std::unexpected(DispatchFailure{DispatchError::unknown_flow, {}, {}});
                if (!table.stateless_reset_available(now)) return DispatchResult{.reset_suppressed=true};
                packet::Tcp4View reset{.source=segment->destination,.destination=segment->source,
                    .source_port=segment->destination_port,.destination_port=segment->source_port};
                if (segment->flags & 0x10) { reset.sequence=segment->acknowledgement; reset.flags=4; }
                else {
                    reset.acknowledgement=segment->sequence+static_cast<std::uint32_t>(segment->payload.size())+
                        ((segment->flags & 2) ? 1u : 0u)+((segment->flags & 1) ? 1u : 0u);
                    reset.flags=0x14;
                }
                auto reply=packet::make_tcp4(reset,mtu);
                if (!reply) return std::unexpected(DispatchFailure{DispatchError::output_error,reply.error(),{}});
                if (!table.claim_stateless_reset(now)) return DispatchResult{.reset_suppressed=true};
                return DispatchResult{.reply=std::move(*reply)};
            }
            if (mtu < 44) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
            auto opened = table.open(*segment, iss, now);
            if (!opened) return std::unexpected(DispatchFailure{DispatchError::table_error, {}, opened.error()});
            try {
                auto view = table.get(*opened)->syn_ack();
                auto options = build_syn_ack_options(mtu, 40, view.options);
                view.options = options.span();
                auto reply = packet::make_tcp4(view, mtu);
                if (!reply) {
                    (void)table.abort(*opened);
                    return std::unexpected(DispatchFailure{DispatchError::output_error, reply.error(), {}});
                }
                return DispatchResult{.id=*opened, .opened=true, .reply=std::move(*reply)};
            } catch (...) {
                (void)table.abort(*opened);
                throw;
            }
        }
        auto* connection = table.get(*id);
        auto syn_options = build_syn_ack_options(std::max<std::size_t>(mtu, 40), 40, connection->syn_ack().options);
        auto const min_mtu = 40u + ((connection->state() == ConnectionState::handshake && is_initial_syn(segment->flags)) ? syn_options.length : 0u);
        if (mtu < min_mtu) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
        packet::Bytes reply_storage;
        reply_storage.reserve(68);
        auto previous = connection->state();
        auto result = connection->input(*segment, now);
        DispatchResult outcome{.id=*id};
        if (!result) outcome.input_error = result.error();
        bool answer = result && ((!*result && previous == ConnectionState::handshake) ||
                                 !segment->payload.empty() || (segment->flags & 1));
        if (!result && !(segment->flags & 4) &&
            (result.error() == ConnectionError::unacceptable || result.error() == ConnectionError::challenge_ack ||
             result.error() == ConnectionError::invalid_ack)) answer = true;
        if (!result && (segment->flags & 4) && result.error() == ConnectionError::challenge_ack) answer = true;
        if (answer) {
            bool challenge = !result && (result.error() == ConnectionError::challenge_ack ||
                (previous != ConnectionState::handshake && result.error() == ConnectionError::invalid_ack));
            if (challenge && !table.claim_challenge_ack(now)) { outcome.challenge_suppressed=true; return outcome; }
            bool is_syn_ack = previous == ConnectionState::handshake && result && !*result;
            auto max_ack_opts = mtu > 40 ? std::min<std::size_t>(28, mtu - 40) : 0;
            auto view = is_syn_ack ? connection->syn_ack() : connection->ack(max_ack_opts);
            if (is_syn_ack) view.options = syn_options.span();
            if (previous == ConnectionState::handshake && !result && result.error() == ConnectionError::invalid_ack) {
                view.sequence = segment->acknowledgement; view.acknowledgement = 0;
                view.flags = 4; view.window = 0; view.options = {}; outcome.reply_reset = true;
            }
            auto reply = packet::make_tcp4(view, mtu, std::move(reply_storage));
            if (!reply) return std::unexpected(DispatchFailure{DispatchError::output_error, reply.error(), {}});
            outcome.reply = std::move(*reply);
        }
        return outcome;
    }
    auto dispatch(ConnectionTable6& table, std::span<std::uint8_t const> bytes,
                  std::uint32_t iss, std::uint64_t now, std::size_t mtu)
        -> std::expected<DispatchResult, DispatchFailure> {
        auto segment = packet::parse_tcp6(bytes);
        if (!segment) return std::unexpected(DispatchFailure{DispatchError::invalid_packet, segment.error(), {}});
        if (is_initial_syn(segment->flags) && !valid_syn_endpoints(*segment))
            return std::unexpected(DispatchFailure{DispatchError::invalid_target, {}, {}});
        // ACK and RST require 60 bytes; SYN-ACK also carries MSS + negotiated options.
        if (mtu < 60) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
        auto id = table.find(*segment);
        if (!id) {
            if (!is_initial_syn(segment->flags)) {
                auto unicast=[](packet::Address6 const& a) {
                    bool mapped=std::ranges::all_of(std::span(a).first<10>(),[](auto b) { return b==0; }) && a[10]==255 && a[11]==255;
                    bool link_local=a[0]==0xfe && (a[1]&0xc0)==0x80;
                    return a[0]!=0xff && !link_local && !mapped && !std::ranges::all_of(a,[](auto b) { return b==0; });
                };
                if ((segment->flags & 4) || !segment->source_port || !segment->destination_port ||
                    !unicast(segment->source) || !unicast(segment->destination))
                    return std::unexpected(DispatchFailure{DispatchError::unknown_flow, {}, {}});
                if (!table.stateless_reset_available(now)) return DispatchResult{.reset_suppressed=true};
                packet::Tcp6View reset{.source=segment->destination,.destination=segment->source,
                    .source_port=segment->destination_port,.destination_port=segment->source_port};
                if (segment->flags & 0x10) { reset.sequence=segment->acknowledgement; reset.flags=4; }
                else {
                    reset.acknowledgement=segment->sequence+static_cast<std::uint32_t>(segment->payload.size())+
                        ((segment->flags & 2) ? 1u : 0u)+((segment->flags & 1) ? 1u : 0u);
                    reset.flags=0x14;
                }
                auto reply=packet::make_tcp6(reset,mtu);
                if (!reply) return std::unexpected(DispatchFailure{DispatchError::output_error,reply.error(),{}});
                if (!table.claim_stateless_reset(now)) return DispatchResult{.reset_suppressed=true};
                return DispatchResult{.reply=std::move(*reply)};
            }
            if (mtu < 64) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
            auto opened = table.open(*segment, iss, now);
            if (!opened) return std::unexpected(DispatchFailure{DispatchError::table_error, {}, opened.error()});
            try {
                auto view = table.get(*opened)->syn_ack();
                auto options = build_syn_ack_options(mtu, 60, view.options);
                view.options = options.span();
                auto reply = packet::make_tcp6(view, mtu);
                if (!reply) {
                    (void)table.abort(*opened);
                    return std::unexpected(DispatchFailure{DispatchError::output_error, reply.error(), {}});
                }
                return DispatchResult{.id=*opened, .opened=true, .reply=std::move(*reply)};
            } catch (...) {
                (void)table.abort(*opened);
                throw;
            }
        }
        auto* connection = table.get(*id);
        auto syn_options = build_syn_ack_options(std::max<std::size_t>(mtu, 60), 60, connection->syn_ack().options);
        auto const min_mtu = 60u + ((connection->state() == ConnectionState::handshake && is_initial_syn(segment->flags)) ? syn_options.length : 0u);
        if (mtu < min_mtu) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
        packet::Bytes reply_storage;
        reply_storage.reserve(88);
        auto previous = connection->state();
        auto result = connection->input(*segment, now);
        DispatchResult outcome{.id=*id};
        if (!result) outcome.input_error = result.error();
        bool answer = result && ((!*result && previous == ConnectionState::handshake) ||
                                 !segment->payload.empty() || (segment->flags & 1));
        if (!result && !(segment->flags & 4) &&
            (result.error() == ConnectionError::unacceptable || result.error() == ConnectionError::challenge_ack ||
             result.error() == ConnectionError::invalid_ack)) answer = true;
        if (!result && (segment->flags & 4) && result.error() == ConnectionError::challenge_ack) answer = true;
        if (answer) {
            bool challenge = !result && (result.error() == ConnectionError::challenge_ack ||
                (previous != ConnectionState::handshake && result.error() == ConnectionError::invalid_ack));
            if (challenge && !table.claim_challenge_ack(now)) { outcome.challenge_suppressed=true; return outcome; }
            bool is_syn_ack = previous == ConnectionState::handshake && result && !*result;
            auto max_ack_opts = mtu > 60 ? std::min<std::size_t>(28, mtu - 60) : 0;
            auto view = is_syn_ack ? connection->syn_ack() : connection->ack(max_ack_opts);
            if (is_syn_ack) view.options = syn_options.span();
            if (previous == ConnectionState::handshake && !result && result.error() == ConnectionError::invalid_ack) {
                view.sequence = segment->acknowledgement; view.acknowledgement = 0;
                view.flags = 4; view.window = 0; view.options = {}; outcome.reply_reset = true;
            }
            auto reply = packet::make_tcp6(view, mtu, std::move(reply_storage));
            if (!reply) return std::unexpected(DispatchFailure{DispatchError::output_error, reply.error(), {}});
            outcome.reply = std::move(*reply);
        }
        return outcome;
    }
}
