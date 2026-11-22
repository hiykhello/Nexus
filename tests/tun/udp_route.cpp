import std;
import udp.route;
import rules;

namespace u = udp;
namespace p = ::packet;
namespace r = ::rules;

template<class Bridge, class Address, class Make>
auto source_route(Address source, Address destination, Make make, std::string_view cidr) -> bool {
    auto rules=r::Matcher::compile({{{"source-ip-cidr",std::string(cidr)},{"source-port","1234"}},2});
    if (!rules) return false;
    Bridge bridge(std::move(*rules),u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{2,2,100});
    p::Bytes body{1};
    auto packet=make(source,destination,1234,53,body);
    if (!packet) return false;
    auto blocked=bridge.prepare(*packet,0);
    if (blocked || std::get<u::RouteError>(blocked.error())!=u::RouteError::blocked || bridge.size()) return false;
    source.back()=2;
    packet=make(source,destination,1234,53,body);
    blocked=bridge.prepare(*packet,0);
    if (blocked || std::get<u::RouteError>(blocked.error())!=u::RouteError::blocked || bridge.size()) return false;
    source.back()=1;
    packet=make(source,destination,4321,53,body);
    blocked=bridge.prepare(*packet,0);
    if (blocked || std::get<u::RouteError>(blocked.error())!=u::RouteError::blocked || bridge.size()) return false;
    source.back()=2;
    packet=make(source,destination,4321,53,body);
    return bridge.prepare(*packet,0).has_value() && bridge.size()==1;
}

auto route6() -> bool {
    auto rules = r::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}, {"ip-cidr", "2001:db8:1::/48"},
                                       {"ip-cidr", "::ffff:198.51.100.0/120"}}});
    if (!rules) return false;
    u::RoutedBridge6 bridge(std::move(*rules), u::Mapping::endpoint_independent,
                            u::Filtering::address_port_dependent, {1, 2, 100});
    constexpr u::Endpoint6 local{{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}, 1234};
    constexpr p::Address6 blocked6{0x20,1,0x0d,0xb8,0,1,0,0,0,0,0,0,0,0,0,2};
    constexpr p::Address6 mapped4{0,0,0,0,0,0,0,0,0,0,0xff,0xff,192,0,2,5};
    constexpr p::Address6 mapped6{0,0,0,0,0,0,0,0,0,0,0xff,0xff,198,51,100,5};
    constexpr p::Address6 mapped_allowed{0,0,0,0,0,0,0,0,0,0,0xff,0xff,203,0,113,5};
    constexpr p::Address6 allowed{0x20,1,0x0d,0xb8,0,2,0,0,0,0,0,0,0,0,0,2};
    p::Bytes body{1, 2, 3};
    auto make = [&](p::Address6 address) { return p::make_udp6(local.address, address, local.port, 53, body); };
    auto invalid = make(allowed);
    if (!invalid) return false;
    invalid->back() ^= 1;
    auto bad = bridge.prepare(*invalid, 0);
    if (bad || std::get<u::RouteError>(bad.error()) != u::RouteError::invalid_packet || bridge.size() != 0) return false;
    for (auto address : {p::Address6{}, p::Address6{0,0,0,0,0,0,0,0,0,0,0xff,0xff}}) {
        auto packet = make(address);
        if (!packet) return false;
        auto denied = bridge.prepare(*packet, 0);
        if (denied || std::get<u::RouteError>(denied.error()) != u::RouteError::invalid_target || bridge.size() != 0) return false;
    }
    auto zero_port = p::make_udp6(local.address, allowed, local.port, 0, body);
    if (!zero_port) return false;
    auto bad_port = bridge.prepare(*zero_port, 0);
    if (bad_port || std::get<u::RouteError>(bad_port.error()) != u::RouteError::invalid_target || bridge.size() != 0) return false;
    for (auto address : {blocked6, mapped4, mapped6}) {
        auto packet = make(address);
        if (!packet) return false;
        auto denied = bridge.prepare(*packet, 0);
        if (denied || std::get<u::RouteError>(denied.error()) != u::RouteError::blocked || bridge.size() != 0) return false;
    }
    auto packet = make(allowed);
    if (!packet) return false;
    auto send = bridge.prepare(*packet, 1);
    if (!send || bridge.size() != 1 || !bridge.complete(send->flow, send->token, true, 2)) return false;
    auto denied_packet = make(mapped4);
    if (!denied_packet) return false;
    auto denied = bridge.prepare(*denied_packet, 3);
    if (denied || std::get<u::RouteError>(denied.error()) != u::RouteError::blocked || bridge.size() != 1) return false;
    auto reply = bridge.reply(send->flow, send->remote, body, 4);
    if (!reply || !p::parse_udp6(*reply)) return false;
    auto expired = bridge.expire(104);
    if (!expired || *expired != 1) return false;
    auto mapped_packet = make(mapped_allowed);
    if (!mapped_packet) return false;
    auto mapped_send = bridge.prepare(*mapped_packet, 105);
    return mapped_send && mapped_send->remote.address == mapped_allowed &&
           bridge.complete(mapped_send->flow, mapped_send->token, true, 106).has_value();
}

int main() {
    if (!source_route<u::RoutedBridge4>(p::Address4{10,0,0,1},p::Address4{198,51,100,1},
        [](auto a,auto b,auto sp,auto dp,auto const& body) { return p::make_udp4(a,b,sp,dp,body); },"10.0.0.1/32")) return 1;
    if (!source_route<u::RoutedBridge6>(p::Address6{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
        p::Address6{0,0,0,0,0,0,0,0,0,0,0xff,0xff,203,0,113,1},
        [](auto a,auto b,auto sp,auto dp,auto const& body) { return p::make_udp6(a,b,sp,dp,body); },"2001:db8::1/128")) return 1;
    if (!route6()) { std::cerr << "IPv6 UDP routing failed\n"; return 1; }
    auto rules = r::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}}});
    if (!rules) return 1;
    u::RoutedBridge4 bridge(std::move(*rules), u::Mapping::endpoint_independent,
                            u::Filtering::address_port_dependent, {1, 2, 100});
    constexpr u::Endpoint4 local{{10, 0, 0, 1}, 1234}, blocked{{192, 0, 2, 5}, 53}, allowed{{198, 51, 100, 2}, 53};
    p::Bytes body{1, 2, 3};
    auto denied = p::make_udp4(local.address, blocked.address, local.port, blocked.port, body);
    auto permit = p::make_udp4(local.address, allowed.address, local.port, allowed.port, body);
    if (!denied || !permit) return 1;
    auto invalid = *denied; invalid.back() ^= 1;
    auto bad = bridge.prepare(invalid, 0);
    if (bad || std::get<u::RouteError>(bad.error()) != u::RouteError::invalid_packet || bridge.size() != 0) return 1;
    for (auto endpoint : {u::Endpoint4{{0,0,0,0},53}, u::Endpoint4{allowed.address,0}}) {
        auto packet = p::make_udp4(local.address, endpoint.address, local.port, endpoint.port, body);
        if (!packet) return 1;
        auto rejected = bridge.prepare(*packet, 0);
        if (rejected || std::get<u::RouteError>(rejected.error()) != u::RouteError::invalid_target || bridge.size() != 0) return 1;
    }
    auto no = bridge.prepare(*denied, 0);
    if (no || std::get<u::RouteError>(no.error()) != u::RouteError::blocked || bridge.size() != 0) return 1;
    auto yes = bridge.prepare(*permit, 1);
    if (!yes || yes->remote != allowed || bridge.size() != 1 || !bridge.complete(yes->flow, yes->token, true, 2)) return 1;
    no = bridge.prepare(*denied, 3);
    if (no || std::get<u::RouteError>(no.error()) != u::RouteError::blocked || bridge.size() != 1) return 1;
    auto reply = bridge.reply(yes->flow, allowed, body, 4);
    if (!reply || !p::parse_udp4(*reply)) return 1;
    auto expired = bridge.expire(104);
    if (!expired || *expired != 1) return 1;
    std::cout << "UDP routed bridge blocks before allocation and allows direct packets\n";
}
