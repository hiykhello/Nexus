module udp;
import std;

namespace udp {
    auto Bridge4::prepare(std::span<std::uint8_t const> input, std::uint64_t now)
        -> std::expected<OutboundDatagram, BridgeError> {
        auto parsed = packet::parse_udp4(input);
        if (!parsed) return std::unexpected(BridgeError{parsed.error()});
        Endpoint4 local{parsed->source, parsed->source_port}, remote{parsed->destination, parsed->destination_port};
        packet::Bytes payload(parsed->payload.begin(), parsed->payload.end());
        auto send = flows_.open_send(local, remote, now);
        if (!send) return std::unexpected(BridgeError{send.error()});
        return OutboundDatagram{send->first, send->second, remote, std::move(payload)};
    }
    auto Bridge4::reply(FlowId id, Endpoint4 remote, std::span<std::uint8_t const> payload, std::uint64_t now)
        -> std::expected<packet::Bytes, BridgeError> {
        if (payload.size() > 65535 - 28 || mtu_ < 28 || payload.size() > mtu_ - 28)
            return std::unexpected(BridgeError{packet::PacketError::too_large});
        auto local = flows_.accept_reply(id, remote, now);
        if (!local) return std::unexpected(BridgeError{local.error()});
        auto result = packet::make_udp4(remote.address, local->address, remote.port, local->port, payload, mtu_);
        if (!result) return std::unexpected(BridgeError{result.error()});
        return std::move(*result);
    }
    auto Bridge6::prepare(std::span<std::uint8_t const> input, std::uint64_t now)
        -> std::expected<OutboundDatagram6, BridgeError> {
        auto parsed = packet::parse_udp6(input);
        if (!parsed) return std::unexpected(BridgeError{parsed.error()});
        Endpoint6 local{parsed->source, parsed->source_port}, remote{parsed->destination, parsed->destination_port};
        packet::Bytes payload(parsed->payload.begin(), parsed->payload.end());
        auto send = flows_.open_send(local, remote, now);
        if (!send) return std::unexpected(BridgeError{send.error()});
        return OutboundDatagram6{send->first, send->second, remote, std::move(payload)};
    }
    auto Bridge6::reply(FlowId id, Endpoint6 remote, std::span<std::uint8_t const> payload, std::uint64_t now)
        -> std::expected<packet::Bytes, BridgeError> {
        if (payload.size() > 65535 - 8 || mtu_ < 48 || payload.size() > mtu_ - 48)
            return std::unexpected(BridgeError{packet::PacketError::too_large});
        auto local = flows_.accept_reply(id, remote, now);
        if (!local) return std::unexpected(BridgeError{local.error()});
        auto result = packet::make_udp6(remote.address, local->address, remote.port, local->port, payload, mtu_);
        if (!result) return std::unexpected(BridgeError{result.error()});
        return std::move(*result);
    }

}
