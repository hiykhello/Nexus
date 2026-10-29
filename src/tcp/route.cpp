module nexus.tcp.dispatch;
import std;

namespace nexus::tcp {
    auto dispatch_routed(ConnectionTable& table, rules::Matcher const& policy,
                         std::span<std::uint8_t const> bytes, std::uint32_t iss,
                         std::uint64_t now, std::size_t mtu)
        -> std::expected<DispatchResult, DispatchFailure> {
        auto segment = packet::parse_tcp4(bytes);
        if (!segment) return std::unexpected(DispatchFailure{DispatchError::invalid_packet, segment.error(), {}});
        if (is_initial_syn(segment->flags) && !table.find(*segment)) {
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
    auto dispatch_routed(ConnectionTable6& table, rules::Matcher const& policy,
                         std::span<std::uint8_t const> bytes, std::uint32_t iss,
                         std::uint64_t now, std::size_t mtu)
        -> std::expected<DispatchResult, DispatchFailure> {
        auto segment=packet::parse_tcp6(bytes);
        if (!segment) return std::unexpected(DispatchFailure{DispatchError::invalid_packet,segment.error(),{}});
        if (is_initial_syn(segment->flags) && !table.find(*segment)) {
            auto const& ip=segment->destination;
            bool mapped=std::ranges::all_of(std::span(ip).first<10>(),[](auto b) { return b==0; }) &&
                        ip[10]==255 && ip[11]==255;
            if (!segment->destination_port || std::ranges::all_of(ip,[](auto b) { return b==0; }) ||
                (mapped && std::ranges::all_of(std::span(ip).last<4>(),[](auto b) { return b==0; })))
                return std::unexpected(DispatchFailure{DispatchError::invalid_target,{},{}});
            auto word=[&](std::size_t i) { return (static_cast<unsigned>(ip[i])<<8)|ip[i+1]; };
            auto address=std::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                     word(0),word(2),word(4),word(6),word(8),word(10),word(12),word(14));
            auto match=policy.match({.ip=address});
            if (!match) return std::unexpected(DispatchFailure{DispatchError::policy_error,{},{}});
            if (match->has_value()) return std::unexpected(DispatchFailure{DispatchError::blocked,{},{}});
            if (mapped) {
                auto ipv4=std::format("{}.{}.{}.{}",ip[12],ip[13],ip[14],ip[15]);
                auto match4=policy.match({.ip=ipv4});
                if (!match4) return std::unexpected(DispatchFailure{DispatchError::policy_error,{},{}});
                if (match4->has_value()) return std::unexpected(DispatchFailure{DispatchError::blocked,{},{}});
            }
        }
        return dispatch(table,bytes,iss,now,mtu);
    }
}
