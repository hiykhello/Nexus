module nexus.tcp.dispatch;
import std;

namespace nexus::tcp {
    auto dispatch(ConnectionTable& table, std::span<std::uint8_t const> bytes,
                  std::uint32_t iss, std::uint64_t now, std::size_t mtu)
        -> std::expected<DispatchResult, DispatchFailure> {
        auto segment = packet::parse_tcp4(bytes);
        if (!segment) return std::unexpected(DispatchFailure{DispatchError::invalid_packet, segment.error(), {}});
        // All responses in this path are fixed 40-byte ACK or SYN-ACK packets.
        if (mtu < 40) return std::unexpected(DispatchFailure{DispatchError::output_error, packet::PacketError::too_large, {}});
        auto id = table.find(*segment);
        if (!id) {
            if (segment->flags != 2) return std::unexpected(DispatchFailure{DispatchError::unknown_flow, {}, {}});
            auto opened = table.open(*segment, iss, now);
            if (!opened) return std::unexpected(DispatchFailure{DispatchError::table_error, {}, opened.error()});
            try {
                auto reply = packet::make_tcp4(table.get(*opened)->syn_ack(), mtu);
                if (!reply) {
                    (void)table.abort(*opened);
                    return std::unexpected(DispatchFailure{DispatchError::output_error, reply.error(), {}});
                }
                return DispatchResult{*opened, true, {}, std::move(*reply)};
            } catch (...) {
                (void)table.abort(*opened);
                throw;
            }
        }
        auto* connection = table.get(*id);
        // Reserve the fixed-size response before mutating connection state.
        auto reply_storage = packet::make_tcp4(connection->ack(), mtu);
        if (!reply_storage) return std::unexpected(DispatchFailure{DispatchError::output_error, reply_storage.error(), {}});
        auto previous = connection->state();
        auto result = connection->input(*segment, now);
        DispatchResult outcome{.id=*id};
        if (!result) outcome.input_error = result.error();
        bool answer = result && ((!*result && previous == ConnectionState::handshake) ||
                                 !segment->payload.empty() || (segment->flags & 1));
        if (!result && !(segment->flags & 4) &&
            (result.error() == ConnectionError::unacceptable || result.error() == ConnectionError::challenge_ack)) answer = true;
        if (!result && (segment->flags & 4) && result.error() == ConnectionError::challenge_ack) answer = true;
        if (answer) {
            auto view = previous == ConnectionState::handshake && result && !*result ? connection->syn_ack() : connection->ack();
            auto reply = packet::make_tcp4(view, mtu, std::move(*reply_storage));
            if (!reply) return std::unexpected(DispatchFailure{DispatchError::output_error, reply.error(), {}});
            outcome.reply = std::move(*reply);
        }
        return outcome;
    }
}
