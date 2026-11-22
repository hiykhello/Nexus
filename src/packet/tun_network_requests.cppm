export module packet.tun_network_requests;
import std;
import platform.netlink_abi;
import platform.netlink_codec;
import packet.tun_network_types;
import packet.tun_network_records;

export namespace packet::tun_network_detail {
    inline auto link_request(std::int32_t index, std::optional<std::uint32_t> mtu = {}, std::optional<std::string_view> alias = {}, std::optional<bool> up = {},
                             bool disable_generation = false) -> nl::Request {
        abi::ifinfomsg header{};
        header.ifi_index = index;
        if (up) {
            header.ifi_change = abi::IFF_UP;
            if (*up) header.ifi_flags = abi::IFF_UP;
        }
        nl::Request request(abi::RTM_NEWLINK, abi::NLM_F_REQUEST | abi::NLM_F_ACK, header);
        if (mtu) request.scalar(abi::IFLA_MTU, *mtu);
        if (alias) request.string(abi::IFLA_IFALIAS, *alias);
        if (disable_generation) {
            nl::Request settings(0, 0), families(0, 0);
            settings.scalar(abi::IFLA_INET6_ADDR_GEN_MODE, std::uint8_t(abi::IN6_ADDR_GEN_MODE_NONE));
            families.append(abi::AF_INET6 | abi::NLA_F_NESTED, settings.bytes().subspan(sizeof(abi::nlmsghdr)));
            request.append(abi::IFLA_AF_SPEC | abi::NLA_F_NESTED, families.bytes().subspan(sizeof(abi::nlmsghdr)));
        }
        return request;
    }
    inline auto address_request(std::int32_t index, TunAddress const &address, bool add) -> nl::Request {
        abi::ifaddrmsg header{};
        header.ifa_family = native_family(address.family);
        header.ifa_prefixlen = address.prefix;
        header.ifa_index = index;
        std::uint32_t flags = abi::IFA_F_PERMANENT | abi::IFA_F_NOPREFIXROUTE;
        if (address.family == 6) flags |= abi::IFA_F_NODAD;
        header.ifa_flags = static_cast<std::uint8_t>(flags);
        nl::Request request(add ? abi::RTM_NEWADDR : abi::RTM_DELADDR, abi::NLM_F_REQUEST | abi::NLM_F_ACK | (add ? abi::NLM_F_CREATE | abi::NLM_F_EXCL : 0), header);
        request.append(abi::IFA_ADDRESS, std::span(address.bytes).first(ip_bytes(address.family)));
        request.append(abi::IFA_LOCAL, std::span(address.bytes).first(ip_bytes(address.family)));
        request.scalar(abi::IFA_FLAGS, flags);
        return request;
    }
    template<bool Exclusive=true,class Record>
    inline auto route_record_request(Record const& route,bool add) -> nl::Request {
        abi::rtmsg header{};
        header.rtm_family=native_family(route.destination.family);
        header.rtm_dst_len=route.destination.prefix;
        header.rtm_table=route.table<256?static_cast<std::uint8_t>(route.table):std::uint8_t{0};
        header.rtm_protocol=route.protocol;header.rtm_scope=route.scope;header.rtm_type=route.type;header.rtm_flags=route.flags;
        nl::Request request(add?abi::RTM_NEWROUTE:abi::RTM_DELROUTE,abi::NLM_F_REQUEST|abi::NLM_F_ACK|(add?abi::NLM_F_CREATE|(Exclusive?abi::NLM_F_EXCL:abi::NLM_F_APPEND):0),header);
        if(route.destination.prefix)request.append(abi::RTA_DST,std::span(route.destination.bytes).first(ip_bytes(route.destination.family)));
        request.scalar(abi::RTA_TABLE,route.table);
        if(route.index)request.scalar(abi::RTA_OIF,route.index);
        request.scalar(abi::RTA_PRIORITY,route.priority);
        if(route.source)request.append(abi::RTA_PREFSRC,std::span(*route.source).first(ip_bytes(route.destination.family)));
        if(route.preference)request.scalar(abi::RTA_PREF,route.preference);
        if constexpr(requires {route.gateway;})if(route.gateway)request.append(abi::RTA_GATEWAY,std::span(*route.gateway).first(ip_bytes(route.destination.family)));
        return request;
    }
    inline auto route_request(std::int32_t index,TunAddress const& destination,bool add,std::optional<std::array<std::uint8_t,16>> source={}) -> nl::Request {
        RouteRecord record{.destination=destination,.table=abi::RT_TABLE_MAIN,.index=static_cast<std::uint32_t>(index),.priority=1024,
            .protocol=abi::RTPROT_STATIC,.scope=destination.family==6?std::uint8_t(abi::RT_SCOPE_UNIVERSE):std::uint8_t(abi::RT_SCOPE_LINK),.type=abi::RTN_UNICAST,.source=source};
        return route_record_request(record,add);
    }
} // namespace packet::tun_network_detail
