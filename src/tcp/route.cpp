module nexus.tcp.dispatch;
import std;

namespace nexus::tcp {
    auto dispatch_routed(ConnectionTable& table, rules::Matcher const& policy,
                         std::span<std::uint8_t const> bytes, std::uint32_t iss,
                         std::uint64_t now, std::size_t mtu)
        -> std::expected<DispatchResult, DispatchFailure> {
        auto segment = packet::parse_tcp4(bytes);
        if (!segment) return std::unexpected(DispatchFailure{DispatchError::invalid_packet, segment.error(), {}});
        if (segment->flags == 2 && !table.find(*segment)) {
            auto const& ip = segment->destination;
            if (!segment->destination_port || std::ranges::all_of(ip,[](auto b) { return b==0; }))
                return std::unexpected(DispatchFailure{DispatchError::invalid_target, {}, {}});
            auto address = std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            auto match = policy.match({.ip=address});
            if (!match) return std::unexpected(DispatchFailure{DispatchError::policy_error, {}, {}});
            if (match->has_value()) return std::unexpected(DispatchFailure{DispatchError::blocked, {}, {}});
        }
        return dispatch(table, bytes, iss, now, mtu);
    }
}
