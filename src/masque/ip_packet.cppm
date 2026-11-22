export module masque.ip_packet;
import std;
import masque.ip_control;

export namespace masque {
    enum class IpPacketError { malformed, checksum, unsupported, fragment_protocol_unknown };
    struct IpPacketView {
        std::uint8_t version=0,protocol=0,hop_limit=0;
        std::array<std::uint8_t,16> source{},destination{};
        bool routed=false,source_override=false,fragmented=false,noninitial_fragment=false;
        // The packet borrows the input supplied to inspect_ip_packet.
        std::span<std::uint8_t const> packet;
    };
    inline auto ipv6_extension(std::uint8_t next) noexcept -> bool {
        return next==0 || next==43 || next==44 || next==51 || next==60 || next==135 || next==139 || next==140 || next==253 || next==254;
    }
    // Checks the framing needed for address/protocol policy, not transport
    // checksums or all IP option semantics. Rejects IPv6 jumbograms and
    // experimental extension types that cannot be interpreted safely.
    auto inspect_ip_packet(std::span<std::uint8_t const> input) noexcept -> std::expected<IpPacketView,IpPacketError>;

    // These predicates implement only the advertised address/route portion of
    // policy. A caller must also enforce authenticated peer, request scope,
    // local destination/source policy, link-local handling, and shared-IP
    // ICMP demultiplexing. Do not use a received assignment as a peer source
    // grant: pass the assignments actually granted to that packet's sender.
    inline auto ip_prefix_contains(AddressEntry const& prefix,std::uint8_t version,std::array<std::uint8_t,16> const& address) noexcept -> bool {
        auto size=ip_address_bytes(version);
        if(!size || prefix.version!=version || !valid_prefix(std::span(prefix.address).first(size),prefix.prefix_length))return false;
        auto whole=prefix.prefix_length/8,partial=prefix.prefix_length%8;
        if(!std::ranges::equal(std::span(prefix.address).first(whole),std::span(address).first(whole)))return false;
        return !partial || !((prefix.address[whole]^address[whole]) & static_cast<std::uint8_t>(0xffu<<(8-partial)));
    }
    inline auto ip_source_assigned(IpPacketView const& packet,std::span<AddressEntry const> assignments) noexcept -> bool {
        if(packet.routed || packet.source_override)return false;
        return std::ranges::any_of(assignments,[&](auto const& prefix) {return !address_rejection(prefix) && ip_prefix_contains(prefix,packet.version,packet.source);});
    }
    inline auto ip_destination_advertised(IpPacketView const& packet,std::span<RouteEntry const> routes) noexcept -> bool {
        auto size=ip_address_bytes(packet.version);if(!size || packet.routed || packet.source_override)return false;
        bool icmp=(packet.version==4 && packet.protocol==1) || (packet.version==6 && packet.protocol==58);
        auto address=std::span(packet.destination).first(size);
        for(auto const& route:routes) {
            // IPv6 reassembly uses the first fragment's Next Header, not
            // this fragment's value. Without a reassembly binding, a later
            // fragment cannot establish a protocol-specific grant.
            if(packet.version==6 && packet.noninitial_fragment && route.protocol)continue;
            if(route.version!=packet.version || (route.protocol && route.protocol!=packet.protocol && !icmp))continue;
            auto first=std::span(route.first).first(size),last=std::span(route.last).first(size);
            if(std::lexicographical_compare(last.begin(),last.end(),first.begin(),first.end()))continue;
            if(!std::lexicographical_compare(address.begin(),address.end(),first.begin(),first.end()) &&
               !std::lexicographical_compare(last.begin(),last.end(),address.begin(),address.end()))return true;
        }
        return false;
    }
    enum class IpScopeSide { source, destination };
    struct IpRequestScope {
        // Empty resolved targets do not mean wildcard: DNS failure must not
        // accidentally broaden scope. The caller owns the target span.
        std::span<AddressEntry const> targets;
        bool any_target=false;
        std::optional<std::uint8_t> protocol;
    };
    inline auto ip_matches_scope(IpPacketView const& packet,IpRequestScope scope,IpScopeSide side) noexcept -> bool {
        if(packet.routed || packet.source_override || !ip_address_bytes(packet.version))return false;
        if(scope.protocol && ipv6_extension(*scope.protocol))return false;
        if(scope.protocol && packet.version==6 && packet.noninitial_fragment)return false;
        auto icmp=(packet.version==4 && packet.protocol==1) || (packet.version==6 && packet.protocol==58);
        if(scope.protocol && *scope.protocol!=packet.protocol && !icmp)return false;
        if(scope.any_target)return scope.targets.empty();
        auto const& address=side==IpScopeSide::source ? packet.source : packet.destination;
        return std::ranges::any_of(scope.targets,[&](auto const& prefix) {return ip_prefix_contains(prefix,packet.version,address);});
    }
    struct IpAdvertisedPolicy {
        std::span<AddressEntry const> sender_assignments;
        std::span<RouteEntry const> receiver_routes;
        IpRequestScope scope;
        IpScopeSide target_side=IpScopeSide::destination;
    };
    // The caller supplies the advertisements for this direction; local ACL,
    // authentication and special ICMP demultiplexing still apply separately.
    // Later fragments require a binding to an authorized first fragment;
    // without that state, even wildcard protocol can hide address-rewriting
    // options present only in the first fragment, so fail closed.
    inline auto ip_permitted_by_advertisements(IpPacketView const& packet,IpAdvertisedPolicy policy) noexcept -> bool {
        return !packet.noninitial_fragment && ip_source_assigned(packet,policy.sender_assignments) &&
            ip_destination_advertised(packet,policy.receiver_routes) && ip_matches_scope(packet,policy.scope,policy.target_side);
    }
}
