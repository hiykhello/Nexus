module nexus.tcp.dispatch;
import std;

namespace nexus::tcp {
    namespace {
        auto mss_option(std::size_t mtu, std::size_t overhead) noexcept -> std::array<std::uint8_t,4> {
            auto mss=static_cast<std::uint16_t>(std::min<std::size_t>(mtu-overhead,65535-overhead));
            return {2,4,static_cast<std::uint8_t>(mss>>8),static_cast<std::uint8_t>(mss)};
        }
    }
    auto dispatch(ConnectionTable& table, std::span<std::uint8_t const> bytes,
                  std::uint32_t iss, std::uint64_t now, std::size_t mtu)
        -> std::expected<DispatchResult, DispatchFailure> {
        auto segment = packet::parse_tcp4(bytes);
        if (!segment) return std::unexpected(DispatchFailure{DispatchError::invalid_packet, segment.error(), {}});
        // ACK and RST require 40 bytes; SYN-ACK also carries an MSS option.
        if (mtu < 40) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
        auto id = table.find(*segment);
        if (!id) {
            if (!is_initial_syn(segment->flags)) return std::unexpected(DispatchFailure{DispatchError::unknown_flow, {}, {}});
            if (mtu < 44) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
            auto opened = table.open(*segment, iss, now);
            if (!opened) return std::unexpected(DispatchFailure{DispatchError::table_error, {}, opened.error()});
            try {
                auto option=mss_option(mtu,40);
                auto view=table.get(*opened)->syn_ack(); view.options=option;
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
        // Reserve response storage before mutating connection state.
        auto option=mss_option(std::max<std::size_t>(mtu,40),40);
        auto reserve_view=connection->ack();
        if (connection->state()==ConnectionState::handshake && is_initial_syn(segment->flags)) reserve_view.options=option;
        auto reply_storage = packet::make_tcp4(reserve_view, mtu);
        if (!reply_storage) return std::unexpected(DispatchFailure{DispatchError::output_error, reply_storage.error(), {}});
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
            auto view = previous == ConnectionState::handshake && result && !*result ? connection->syn_ack() : connection->ack();
            if (previous == ConnectionState::handshake && result && !*result) view.options=option;
            if (previous == ConnectionState::handshake && !result && result.error() == ConnectionError::invalid_ack) {
                view.sequence = segment->acknowledgement; view.acknowledgement = 0;
                view.flags = 4; view.window = 0;
            }
            auto reply = packet::make_tcp4(view, mtu, std::move(*reply_storage));
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
        // ACK and RST require 60 bytes; SYN-ACK also carries an MSS option.
        if (mtu < 60) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
        auto id = table.find(*segment);
        if (!id) {
            if (!is_initial_syn(segment->flags)) return std::unexpected(DispatchFailure{DispatchError::unknown_flow, {}, {}});
            if (mtu < 64) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
            auto opened = table.open(*segment, iss, now);
            if (!opened) return std::unexpected(DispatchFailure{DispatchError::table_error, {}, opened.error()});
            try {
                auto option=mss_option(mtu,60);
                auto view=table.get(*opened)->syn_ack(); view.options=option;
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
        // Reserve response storage before mutating connection state.
        auto option=mss_option(std::max<std::size_t>(mtu,60),60);
        auto reserve_view=connection->ack();
        if (connection->state()==ConnectionState::handshake && is_initial_syn(segment->flags)) reserve_view.options=option;
        auto reply_storage = packet::make_tcp6(reserve_view, mtu);
        if (!reply_storage) return std::unexpected(DispatchFailure{DispatchError::output_error, reply_storage.error(), {}});
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
            auto view = previous == ConnectionState::handshake && result && !*result ? connection->syn_ack() : connection->ack();
            if (previous == ConnectionState::handshake && result && !*result) view.options=option;
            if (previous == ConnectionState::handshake && !result && result.error() == ConnectionError::invalid_ack) {
                view.sequence = segment->acknowledgement; view.acknowledgement = 0;
                view.flags = 4; view.window = 0;
            }
            auto reply = packet::make_tcp6(view, mtu, std::move(*reply_storage));
            if (!reply) return std::unexpected(DispatchFailure{DispatchError::output_error, reply.error(), {}});
            outcome.reply = std::move(*reply);
        }
        return outcome;
    }
}
