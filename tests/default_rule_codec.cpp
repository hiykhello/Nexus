import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.routing_rule;
import packet.tun_network_types;
import packet.tun_network_records;
import packet.tun_network_requests;
namespace {
    namespace a = ::platform::netlink_abi;
    namespace n = ::platform::netlink;
    namespace r = ::platform::routing;
    namespace p = ::packet::tun_network_detail;
    auto require(bool value,unsigned line) -> void {if(!value){std::println("default codec failure {}",line);throw 1;}}
    auto message(n::Request const& request) -> n::Message {return {request.header(),request.bytes().subspan(sizeof(a::nlmsghdr))};}
}
auto main() -> int {
    try {
        for(auto family:{4,6})for(bool capture:{false,true}) {
            r::Rule rule{.family=static_cast<std::uint8_t>(family),.action=a::FR_ACT_TO_TBL,.protocol=186,.table=60000,.priority=10000,.mark=0x6e780001,.mask=0xffffffffU,.flags=capture?std::uint32_t(a::FIB_RULE_INVERT):0};
            auto request=r::rule_request(rule,true);require(request.valid(),1);auto parsed=r::parse_rule(message(request));require(parsed && *parsed==rule,2);
            require(r::selects_mark(rule,rule.mark)==!capture && r::selects_mark(rule,0)==capture,3);
            auto duplicate=request;duplicate.scalar(a::FRA_PRIORITY,rule.priority);require(!r::parse_rule(message(duplicate)),4);
            auto flagged=request;flagged.scalar(a::FRA_FWMASK|a::NLA_F_NESTED,rule.mask);require(!r::parse_rule(message(flagged)),5);
            r::Rule guard=rule;guard.action=a::FR_ACT_UNREACHABLE;guard.table=0;guard.flags=0;
            auto guarded=r::parse_rule(message(r::rule_request(guard,true)));require(guarded && *guarded==guard,6);
            p::GatewayRouteRecord route;route.destination.family=family;route.table=60001;route.index=42;route.priority=12;route.protocol=186;route.scope=a::RT_SCOPE_UNIVERSE;route.type=a::RTN_UNICAST;
            route.gateway.emplace();(*route.gateway)[family==4?3:15]=1;
            if(family==4)(*route.gateway)[0]=192;else(*route.gateway)[0]=0x20;
            auto wire=p::route_record_request(route,true);auto rich=p::parse_route<p::GatewayRouteRecord>(message(wire));auto narrow=p::parse_route(message(wire));
            require(rich && *rich==route && narrow && narrow->complex && narrow->destination.prefix==0,7);
        }
    }catch(int code){return code;}
    std::println("default routing codec: exact dual-family lookup/inverse/guard rule fields, duplicate/flag rejection, native private-table gateway/default roundtrip; RouteRecord={} extended={} TunOptions={}",sizeof(p::RouteRecord),sizeof(p::GatewayRouteRecord),sizeof(::packet::TunNetworkOptions));
}
