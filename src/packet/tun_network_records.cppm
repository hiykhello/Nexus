export module packet.tun_network_records;
import std;
import platform.netlink_abi;
import platform.netlink_codec;
import packet.tun_network_types;

export namespace packet::tun_network_detail {
    namespace nl = ::platform::netlink;
    namespace abi = ::platform::netlink_abi;
    inline auto native_family(std::uint8_t family) noexcept -> std::uint8_t { return family == 4 ? abi::AF_INET : family == 6 ? abi::AF_INET6 : abi::AF_UNSPEC; }
    inline auto ip_family(std::uint8_t family) noexcept -> std::uint8_t { return family == abi::AF_INET ? 4 : family == abi::AF_INET6 ? 6 : 0; }
    struct LinkRecord {
        std::int32_t index = 0;
        std::uint16_t type = 0;
        std::uint32_t flags = 0, mtu = 0;
        std::array<char, 16> name{};
        std::array<char, 64> alias{};
        std::optional<std::uint8_t> ipv6_generation;
    };
    struct AddressRecord {
        TunAddress address;
        std::array<std::uint8_t, 16> peer{};
        std::array<char, 16> label{};
        std::uint32_t index = 0, flags = 0;
        std::uint8_t scope = 0;
        bool complex = false;
        auto operator==(AddressRecord const &) const -> bool = default;
    };
    struct RouteRecord {
        TunAddress destination;
        std::uint32_t table = 0, index = 0, priority = 0, flags = 0;
        std::uint8_t protocol = 0, scope = 0, type = 0, preference = 0;
        std::optional<std::array<std::uint8_t, 16>> source;
        bool complex = false;
        auto operator==(RouteRecord const &) const -> bool = default;
    };
    using nl::scalar;
    inline auto parse_link(nl::Message message) -> std::expected<LinkRecord, nl::Failure> {
        auto header = nl::native<abi::ifinfomsg>(message.payload);
        if (message.header.nlmsg_type != abi::RTM_NEWLINK || !header || header->ifi_index <= 0) return nl::fail(nl::Error::protocol);
        LinkRecord result{.index = header->ifi_index, .type = header->ifi_type, .flags = header->ifi_flags};
        bool name = false, mtu = false, alias = false, af = false;
        auto parsed = nl::attributes(message.payload.subspan(sizeof(*header)), [&](nl::Attribute attribute) -> std::expected<void, nl::Failure> {
            if (attribute.type == abi::IFLA_IFNAME) {
                auto value = nl::text(attribute, 15);
                if (name || !value || value->empty()) return nl::fail(nl::Error::protocol);
                std::ranges::copy(*value, result.name.begin());
                name = true;
            } else if (attribute.type == abi::IFLA_MTU) {
                auto value = scalar<std::uint32_t>(attribute);
                if (mtu || !value) return nl::fail(nl::Error::protocol);
                result.mtu = *value;
                mtu = true;
            } else if (attribute.type == abi::IFLA_IFALIAS) {
                auto value = nl::text(attribute, 63);
                if (alias || !value) return nl::fail(nl::Error::protocol);
                std::ranges::copy(*value, result.alias.begin());
                alias = true;
            } else if (attribute.type == abi::IFLA_AF_SPEC) {
                if (af || (attribute.flags && attribute.flags != abi::NLA_F_NESTED)) return nl::fail(nl::Error::protocol);
                af = true;
                bool ipv6 = false;
                return nl::attributes(attribute.bytes, [&](nl::Attribute family) -> std::expected<void, nl::Failure> {
                    if (family.type != abi::AF_INET6) return {};
                    if (ipv6 || (family.flags && family.flags != abi::NLA_F_NESTED)) return nl::fail(nl::Error::protocol);
                    ipv6 = true;
                    return nl::attributes(family.bytes, [&](nl::Attribute field) -> std::expected<void, nl::Failure> {
                        if (field.type != abi::IFLA_INET6_ADDR_GEN_MODE) return {};
                        auto value = scalar<std::uint8_t>(field);
                        if (result.ipv6_generation || !value) return nl::fail(nl::Error::protocol);
                        result.ipv6_generation = *value;
                        return {};
                    });
                });
            }
            return {};
        });
        if (!parsed) return std::unexpected(parsed.error());
        if (!name || !mtu) return nl::fail(nl::Error::protocol);
        return result;
    }
    inline auto parse_address(nl::Message message) -> std::expected<AddressRecord, nl::Failure> {
        auto header = nl::native<abi::ifaddrmsg>(message.payload);
        if (message.header.nlmsg_type != abi::RTM_NEWADDR || !header || !ip_family(header->ifa_family) || !header->ifa_index ||
            header->ifa_prefixlen > ip_bytes(ip_family(header->ifa_family)) * 8)
            return nl::fail(nl::Error::protocol);
        AddressRecord result{
            .address = {ip_family(header->ifa_family), {}, header->ifa_prefixlen}, .index = header->ifa_index, .flags = header->ifa_flags, .scope = header->ifa_scope};
        bool local = false, peer = false, flags = false, label = false, proto = false, cache = false;
        auto parsed = nl::attributes(message.payload.subspan(sizeof(*header)), [&](nl::Attribute attribute) -> std::expected<void, nl::Failure> {
            if (attribute.type == abi::IFA_LOCAL || attribute.type == abi::IFA_ADDRESS) {
                bool &seen = attribute.type == abi::IFA_LOCAL ? local : peer;
                if (seen || attribute.flags || attribute.bytes.size() != ip_bytes(result.address.family)) return nl::fail(nl::Error::protocol);
                seen = true;
                auto &target = attribute.type == abi::IFA_LOCAL ? result.address.bytes : result.peer;
                std::ranges::copy(attribute.bytes, target.begin());
            } else if (attribute.type == abi::IFA_FLAGS) {
                auto value = scalar<std::uint32_t>(attribute);
                if (flags || !value) return nl::fail(nl::Error::protocol);
                result.flags = *value;
                flags = true;
            } else if (attribute.type == abi::IFA_LABEL) {
                auto value = nl::text(attribute, 15);
                if (label || !value) return nl::fail(nl::Error::protocol);
                std::ranges::copy(*value, result.label.begin());
                label = true;
            } else if (attribute.type == abi::IFA_CACHEINFO) {
                auto value=scalar<abi::ifa_cacheinfo>(attribute);
                if (cache || !value) return nl::fail(nl::Error::protocol);
                cache=true;
                result.complex |= value->ifa_prefered!=std::numeric_limits<std::uint32_t>::max() || value->ifa_valid!=std::numeric_limits<std::uint32_t>::max();
            } else if (attribute.type == abi::IFA_PROTO) {
                auto value = scalar<std::uint8_t>(attribute);
                if (proto || !value) return nl::fail(nl::Error::protocol);
                result.complex |= *value != 0;
                proto = true;
            } else result.complex = true;
            return {};
        });
        if (!parsed) return std::unexpected(parsed.error());
        if (!peer && !local) return nl::fail(nl::Error::protocol);
        if (!local) result.address.bytes = result.peer;
        if (!peer) result.peer = result.address.bytes;
        return result;
    }
    struct GatewayRouteRecord : RouteRecord {
        std::optional<std::array<std::uint8_t,16>> gateway;
        auto operator==(GatewayRouteRecord const&) const -> bool = default;
    };
    template<class Record=RouteRecord>
    inline auto parse_route(nl::Message message) -> std::expected<Record, nl::Failure> {
        auto header = nl::native<abi::rtmsg>(message.payload);
        if (message.header.nlmsg_type != abi::RTM_NEWROUTE || !header || !ip_family(header->rtm_family) || header->rtm_dst_len > ip_bytes(ip_family(header->rtm_family)) * 8 ||
            header->rtm_src_len > ip_bytes(ip_family(header->rtm_family)) * 8)
            return nl::fail(nl::Error::protocol);
        RouteRecord core{.destination = {ip_family(header->rtm_family), {}, header->rtm_dst_len},
                           .table = header->rtm_table,
                           .flags = header->rtm_flags & ~std::uint32_t(abi::RTNH_F_LINKDOWN),
                           .protocol = header->rtm_protocol,
                           .scope = header->rtm_scope,
                           .type = header->rtm_type,
                           .complex = header->rtm_src_len != 0 || header->rtm_tos != 0};
        Record result{};static_cast<RouteRecord&>(result)=core;
        bool destination = false, index = false, table = false, priority = false, source = false, preference = false, cache = false, expires = false,gateway=false;
        auto parsed = nl::attributes(message.payload.subspan(sizeof(*header)), [&](nl::Attribute attribute) -> std::expected<void, nl::Failure> {
            if (attribute.type == abi::RTA_DST || attribute.type == abi::RTA_PREFSRC) {
                bool &seen = attribute.type == abi::RTA_DST ? destination : source;
                if (seen || attribute.flags || attribute.bytes.size() != ip_bytes(result.destination.family)) return nl::fail(nl::Error::protocol);
                seen = true;
                if (attribute.type == abi::RTA_PREFSRC) {
                    result.source.emplace();
                    std::ranges::copy(attribute.bytes, result.source->begin());
                } else std::ranges::copy(attribute.bytes, result.destination.bytes.begin());
            } else if (attribute.type == abi::RTA_OIF || attribute.type == abi::RTA_TABLE || attribute.type == abi::RTA_PRIORITY) {
                bool &seen = attribute.type == abi::RTA_OIF ? index : attribute.type == abi::RTA_TABLE ? table : priority;
                auto value = scalar<std::uint32_t>(attribute);
                if (seen || !value) return nl::fail(nl::Error::protocol);
                seen = true;
                if (attribute.type == abi::RTA_OIF) result.index = *value;
                else if (attribute.type == abi::RTA_TABLE) {
                    if (result.table && result.table != *value && !(result.table==abi::RT_TABLE_COMPAT && *value>255)) return nl::fail(nl::Error::protocol);
                    result.table = *value;
                } else result.priority = *value;
            } else if (attribute.type == abi::RTA_GATEWAY) {
                if(gateway || attribute.flags || attribute.bytes.size()!=ip_bytes(result.destination.family))return nl::fail(nl::Error::protocol);
                gateway=true;
                if constexpr(requires {result.gateway;}) {
                    result.gateway.emplace();std::ranges::copy(attribute.bytes,result.gateway->begin());
                } else result.complex=true;
            } else if (attribute.type == abi::RTA_PREF) {
                auto value = scalar<std::uint8_t>(attribute);
                if (preference || !value) return nl::fail(nl::Error::protocol);
                result.preference = *value;
                preference = true;
            } else if (attribute.type == abi::RTA_CACHEINFO) {
                auto value=scalar<abi::rta_cacheinfo>(attribute);
                if (cache || !value) return nl::fail(nl::Error::protocol);
                cache=true;
                result.complex |= value->rta_expires!=0 || value->rta_error!=0;
            } else if (attribute.type == abi::RTA_EXPIRES) {
                if (expires || !scalar<std::uint32_t>(attribute)) return nl::fail(nl::Error::protocol);
                expires=true;
                result.complex = true;
            } else result.complex = true;
            return {};
        });
        if (!parsed) return std::unexpected(parsed.error());
        if (!destination && result.destination.prefix) return nl::fail(nl::Error::protocol);
        return result;
    }
} // namespace packet::tun_network_detail
