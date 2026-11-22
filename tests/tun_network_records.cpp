import std;
import platform.netlink_abi;
import platform.netlink_codec;
import packet.tun_network_types;
import packet.tun_network_records;
import packet.tun_network_requests;
namespace a = ::platform::netlink_abi;
namespace n = ::platform::netlink;
namespace p = ::packet;
namespace d = ::packet::tun_network_detail;
namespace {
    auto require(bool value,std::source_location where=std::source_location::current()) -> void {
        if (!value) { std::println("TUN record validation failed line {}",where.line()); throw 1; }
    }
    auto message(n::Request const& request) -> n::Message { return {request.header(),request.bytes().subspan(sizeof(a::nlmsghdr))}; }
    auto addresses() -> void {
        p::TunAddress address{4,{10,42,0,1},24};
        auto base=d::address_request(42,address,true);
        auto plain=d::parse_address(message(base)); require(plain && plain->address==address && plain->peer==address.bytes && !plain->complex);
        for (unsigned fault=0;fault<10;++fault) {
            auto request=base;
            if (!fault) request.scalar(a::IFA_FLAGS,std::uint32_t{0});
            if (fault==1) request.append(a::IFA_LOCAL,std::span(address.bytes).first(4));
            if (fault==2) request.append(a::IFA_ADDRESS,std::span(address.bytes).first(4));
            if (fault==3) request.scalar(a::IFA_CACHEINFO,std::uint32_t{0});
            if (fault==4) { request.string(a::IFA_LABEL,"nx"); request.string(a::IFA_LABEL,"nx"); }
            if (fault==5) { std::array<std::uint8_t,4> malformed{'a',0,'b',0}; request.append(a::IFA_LABEL,malformed); }
            if (fault==6) request.scalar(a::IFA_PROTO,std::uint32_t{0});
            if (fault==7) request.scalar(a::IFA_LABEL,std::uint32_t{0});
            if (fault==8) { request.scalar(a::IFA_PROTO,std::uint8_t{0}); request.scalar(a::IFA_PROTO,std::uint8_t{0}); }
            if (fault==9) { request.scalar(a::IFA_CACHEINFO,a::ifa_cacheinfo{}); request.scalar(a::IFA_CACHEINFO,a::ifa_cacheinfo{}); }
            require(!d::parse_address(message(request)));
        }
        auto permanent=base;
        a::ifa_cacheinfo cache{.ifa_prefered=std::numeric_limits<std::uint32_t>::max(),.ifa_valid=std::numeric_limits<std::uint32_t>::max()};
        require(permanent.scalar(a::IFA_CACHEINFO,cache) && permanent.string(a::IFA_LABEL,"nx-lease"));
        auto exact=d::parse_address(message(permanent)); require(exact && !exact->complex && std::string_view(exact->label.data())=="nx-lease");
        cache.ifa_prefered=60; auto finite=base; finite.scalar(a::IFA_CACHEINFO,cache);
        auto changed=d::parse_address(message(finite)); require(changed && changed->complex);
        auto foreign=base; foreign.scalar(0x3fff,std::uint8_t{1});
        auto unknown=d::parse_address(message(foreign)); require(unknown && unknown->complex);
    }
    auto routes() -> void {
        p::TunAddress route{6,{0xfd,0x42},128}; route.bytes[15]=2;
        auto base=d::route_request(42,route,true);
        auto plain=d::parse_route(message(base)); require(plain && plain->destination==route && plain->index==42 && !plain->complex);
        for (unsigned fault=0;fault<10;++fault) {
            auto request=base;
            if (!fault) request.scalar(a::RTA_OIF,std::uint32_t{42});
            if (fault==1) request.scalar(a::RTA_PRIORITY,std::uint32_t{1024});
            if (fault==2) request.scalar(a::RTA_TABLE,std::uint32_t{a::RT_TABLE_LOCAL});
            if (fault==3) request.append(a::RTA_DST,route.bytes);
            if (fault==4) request.scalar(a::RTA_PREFSRC,std::uint32_t{0});
            if (fault==5) request.scalar(a::RTA_CACHEINFO,std::uint32_t{0});
            if (fault==6) { request.scalar(a::RTA_PREF,std::uint8_t{0}); request.scalar(a::RTA_PREF,std::uint8_t{0}); }
            if (fault==7) { request.scalar(a::RTA_EXPIRES,std::uint32_t{60}); request.scalar(a::RTA_EXPIRES,std::uint32_t{60}); }
            if (fault==8) { request.scalar(a::RTA_CACHEINFO,a::rta_cacheinfo{}); request.scalar(a::RTA_CACHEINFO,a::rta_cacheinfo{}); }
            if (fault==9) request.scalar(a::RTA_OIF|a::NLA_F_NESTED,std::uint32_t{1});
            require(!d::parse_route(message(request)));
        }
        auto cache=base; cache.scalar(a::RTA_CACHEINFO,a::rta_cacheinfo{});
        auto ordinary=d::parse_route(message(cache)); require(ordinary && !ordinary->complex);
        a::rta_cacheinfo changed{}; changed.rta_expires=1; auto finite=base; finite.scalar(a::RTA_CACHEINFO,changed);
        auto expires=d::parse_route(message(finite)); require(expires && expires->complex);
        auto gateway=base; gateway.append(a::RTA_GATEWAY,route.bytes);
        auto indirect=d::parse_route(message(gateway)); require(indirect && indirect->complex);
    }
    auto links_and_options() -> void {
        n::Request link(a::RTM_NEWLINK,0,a::ifinfomsg{.ifi_type=a::ARPHRD_NONE,.ifi_index=42});
        require(!d::parse_link(message(link)));
        link.string(a::IFLA_IFNAME,"nx-lease"); link.scalar(a::IFLA_MTU,std::uint32_t{1420});
        require(d::parse_link(message(link)).has_value());
        auto repeated=link; repeated.string(a::IFLA_IFNAME,"nx-lease"); require(!d::parse_link(message(repeated)));
        auto repeated_mtu=link; repeated_mtu.scalar(a::IFLA_MTU,std::uint32_t{1420}); require(!d::parse_link(message(repeated_mtu)));
        p::TunNetworkOptions options; options.address_count=1; options.addresses[0]={4,{10,42,0,1},24};
        require(d::validate(options)); options.addresses[0].bytes[4]=1; require(!d::validate(options)); options.addresses[0].bytes[4]=0;
        options.route_count=1; options.routes[0]={6,{0xfd,0x42},64}; require(!d::validate(options));
        options.routes[0]={4,{10,43},16}; require(d::validate(options)); options.routes[0].bytes[3]=1; require(!d::validate(options));
    }
}
auto main() -> int {
    try { addresses(); routes(); links_and_options(); } catch (int value) { return value; }
    std::println("TUN readback rejects duplicate/short/flagged identity attributes, classifies finite lifetimes/gateway as foreign, and preserves exact address/route semantics");
}
