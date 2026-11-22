import std;
import masque.ip_control;
import masque.ip_packet;
import masque.ip_receiver;
namespace m=masque;

auto checksum(std::span<std::uint8_t> packet) -> void {
    auto length=std::size_t(packet[0]&15)*4;packet[10]=packet[11]=0;
    std::uint32_t sum=0;for(std::size_t i=0;i<length;i+=2)sum+=(std::uint32_t(packet[i])<<8)|packet[i+1];
    while(sum>>16)sum=(sum&0xffff)+(sum>>16);auto value=static_cast<std::uint16_t>(~sum);
    packet[10]=value>>8;packet[11]=value;
}
auto ipv4(std::uint8_t proto=17,bool options=false) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> packet(options ? 24 : 20);packet[0]=options ? 0x46 : 0x45;packet[3]=packet.size();
    packet[8]=64;packet[9]=proto;packet[12]=192;packet[14]=2;packet[15]=11;
    packet[16]=198;packet[17]=51;packet[18]=100;packet[19]=42;
    if(options) {packet[20]=131;packet[21]=4;packet[22]=4;}
    checksum(packet);return packet;
}
auto ipv6() -> std::array<std::uint8_t,64> {
    std::array<std::uint8_t,64> packet{};packet[0]=0x60;packet[5]=24;packet[6]=0;packet[7]=64;
    packet[8]=0x20;packet[9]=1;packet[10]=0x0d;packet[11]=0xb8;packet[23]=11;
    packet[24]=0x20;packet[25]=1;packet[26]=0x0d;packet[27]=0xb8;packet[29]=1;packet[39]=42;
    packet[40]=60;packet[48]=17;return packet;
}
auto check_ipv4() -> int {
    m::AddressEntry source{0,4,24,{192,0,2,0}};
    m::RouteEntry route{4,17,{198,51,100,0},{198,51,100,255}};
    auto packet=ipv4();auto view=m::inspect_ip_packet(packet);
    if(!view || view->version!=4 || view->protocol!=17 || view->hop_limit!=64 ||
       !m::ip_source_assigned(*view,std::span(&source,1)) || !m::ip_destination_advertised(*view,std::span(&route,1)))return 1;
    auto outside=packet;outside[14]=3;checksum(outside);auto other=m::inspect_ip_packet(outside);
    if(!other || m::ip_source_assigned(*other,std::span(&source,1)))return 2;
    outside=packet;outside[19]=1;outside[18]=101;checksum(outside);other=m::inspect_ip_packet(outside);
    if(!other || m::ip_destination_advertised(*other,std::span(&route,1)))return 3;
    auto tcp=ipv4(6);auto tcp_view=m::inspect_ip_packet(tcp);
    if(!tcp_view || m::ip_destination_advertised(*tcp_view,std::span(&route,1)))return 4;
    auto icmp=ipv4(1);auto icmp_view=m::inspect_ip_packet(icmp);
    if(!icmp_view || !m::ip_destination_advertised(*icmp_view,std::span(&route,1)))return 5;
    m::AddressEntry target{0,4,24,{198,51,100,0}};
    m::IpRequestScope scope{std::span(&target,1),false,17};
    if(!m::ip_matches_scope(*view,scope,m::IpScopeSide::destination) || m::ip_matches_scope(*view,scope,m::IpScopeSide::source) ||
       m::ip_matches_scope(*tcp_view,scope,m::IpScopeSide::destination) || !m::ip_matches_scope(*icmp_view,scope,m::IpScopeSide::destination))return 28;
    m::IpRequestScope unresolved{{},false,17},wildcard{{},true,17},bad{{},true,0};
    if(m::ip_matches_scope(*view,unresolved,m::IpScopeSide::destination) || !m::ip_matches_scope(*view,wildcard,m::IpScopeSide::destination) ||
       m::ip_matches_scope(*view,bad,m::IpScopeSide::destination))return 29;
    auto later=ipv4();later[7]=1;checksum(later);auto later_view=m::inspect_ip_packet(later);
    if(!later_view || !later_view->noninitial_fragment || m::ip_permitted_by_advertisements(*later_view,{std::span(&source,1),std::span(&route,1),wildcard}))return 32;
    auto routed=ipv4(17,true);auto routed_view=m::inspect_ip_packet(routed);
    if(!routed_view || !routed_view->routed || m::ip_source_assigned(*routed_view,std::span(&source,1)) ||
       m::ip_destination_advertised(*routed_view,std::span(&route,1)))return 6;
    packet[8]^=1;if(m::inspect_ip_packet(packet).error()!=m::IpPacketError::checksum)return 7;
    packet=ipv4();packet.push_back(0);if(m::inspect_ip_packet(packet))return 8;
    auto malformed=ipv4(17,true);malformed[21]=1;checksum(malformed);if(m::inspect_ip_packet(malformed))return 9;
    m::AddressEntry rejected{1,4,32,{}};auto zero=ipv4();zero[12]=zero[13]=zero[14]=zero[15]=0;checksum(zero);auto zero_view=m::inspect_ip_packet(zero);
    if(!zero_view || !m::address_rejection(rejected) || m::ip_source_assigned(*zero_view,std::span(&rejected,1)))return 10;
    return 0;
}
auto check_ipv6() -> int {
    auto packet=ipv6();m::AddressEntry source{0,6,32,{0x20,1,0x0d,0xb8}};
    m::RouteEntry route{6,17,{0x20,1,0x0d,0xb8,0,1},{0x20,1,0x0d,0xb8,0,1,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}};
    auto view=m::inspect_ip_packet(packet);
    if(!view || view->version!=6 || view->protocol!=17 || !m::ip_source_assigned(*view,std::span(&source,1)) ||
       !m::ip_destination_advertised(*view,std::span(&route,1)))return 11;
    packet[48]=58;view=m::inspect_ip_packet(packet);
    if(!view || !m::ip_destination_advertised(*view,std::span(&route,1)))return 12;
    packet=ipv6();packet[40]=43;packet[48]=17;packet[51]=1;view=m::inspect_ip_packet(packet);
    if(!view || !view->routed || m::ip_destination_advertised(*view,std::span(&route,1)))return 13;
    packet[51]=0;view=m::inspect_ip_packet(packet);if(!view || view->routed)return 14;
    packet=ipv6();packet[6]=44;packet[40]=17;packet[42]=0;packet[43]=8;
    view=m::inspect_ip_packet(packet);if(!view || !view->fragmented || !view->noninitial_fragment || view->protocol!=17)return 15;
    auto any_route=route;any_route.protocol=0;
    m::IpRequestScope any_scope{{},true,{}},udp_scope{{},true,17};
    if(m::ip_destination_advertised(*view,std::span(&route,1)) || !m::ip_destination_advertised(*view,std::span(&any_route,1)) ||
       m::ip_matches_scope(*view,udp_scope,m::IpScopeSide::destination) || !m::ip_matches_scope(*view,any_scope,m::IpScopeSide::destination))return 30;
    if(m::ip_permitted_by_advertisements(*view,{std::span(&source,1),std::span(&any_route,1),any_scope}))return 33;
    packet[40]=58;view=m::inspect_ip_packet(packet);
    if(!view || m::ip_destination_advertised(*view,std::span(&route,1)) || m::ip_matches_scope(*view,udp_scope,m::IpScopeSide::destination))return 31;
    packet[40]=60;auto unknown=m::inspect_ip_packet(packet);
    if(unknown || unknown.error()!=m::IpPacketError::fragment_protocol_unknown)return 16;
    packet[42]=packet[43]=0;packet[48]=17;view=m::inspect_ip_packet(packet);
    if(!view || !view->fragmented || view->noninitial_fragment || view->protocol!=17)return 17;
    packet=ipv6();packet[41]=8;if(m::inspect_ip_packet(packet))return 18;
    packet=ipv6();packet[40]=0;if(m::inspect_ip_packet(packet))return 19;
    packet=ipv6();packet[6]=253;auto experimental=m::inspect_ip_packet(packet);
    if(experimental || experimental.error()!=m::IpPacketError::unsupported)return 20;
    packet=ipv6();packet[6]=50;view=m::inspect_ip_packet(packet);if(!view || view->protocol!=50)return 21;
    std::array<std::uint8_t,80> mobile{};auto base=ipv6();std::copy_n(base.begin(),48,mobile.begin());
    mobile[5]=40;mobile[48]=17;mobile[49]=2;mobile[50]=0xc9;mobile[51]=16;
    auto home=m::inspect_ip_packet(mobile);
    if(!home || !home->source_override || m::ip_source_assigned(*home,std::span(&source,1)) || m::ip_destination_advertised(*home,std::span(&route,1)))return 26;
    mobile[51]=23;if(m::inspect_ip_packet(mobile))return 27;
    return 0;
}
struct PolicySink {
    m::AddressEntry source{0,4,24,{192,0,2,0}};
    m::AddressEntry target{0,4,24,{198,51,100,0}};
    m::RouteEntry route{4,17,{198,51,100,0},{198,51,100,255}};
    unsigned allowed=0,dropped=0;
    auto assigned(std::span<m::AddressEntry const>) noexcept -> bool {return true;}
    auto routes(std::span<m::RouteEntry const>) noexcept -> bool {return true;}
    auto requested(std::span<m::AddressEntry const>) noexcept -> bool {return true;}
    auto packet(std::span<std::uint8_t const> input) noexcept -> void {
        auto view=m::inspect_ip_packet(input);
        m::IpRequestScope scope{std::span(&target,1),false,17};
        if(view && m::ip_permitted_by_advertisements(*view,{std::span(&source,1),std::span(&route,1),scope}))++allowed;else ++dropped;
    }
};
auto check_receiver_policy() -> int {
    PolicySink sink;m::IpReceiver<PolicySink,1500,4,4,4> receiver(sink);
    auto packet=ipv4();std::vector<std::uint8_t> wire{0};wire.insert(wire.end(),packet.begin(),packet.end());
    if(receiver.datagram(wire)!=m::IpReceiveStatus::active || sink.allowed!=1)return 22;
    packet[14]=3;checksum(packet);std::copy(packet.begin(),packet.end(),wire.begin()+1);
    if(receiver.datagram(wire)!=m::IpReceiveStatus::active || sink.allowed!=1 || sink.dropped!=1)return 23;
    packet=ipv4(6);std::copy(packet.begin(),packet.end(),wire.begin()+1);
    if(receiver.datagram(wire)!=m::IpReceiveStatus::active || sink.dropped!=2)return 24;
    wire[1+8]^=1;
    if(receiver.datagram(wire)!=m::IpReceiveStatus::active || sink.dropped!=3)return 25;
    return 0;
}
auto main() -> int {
    if(auto result=check_ipv4())return result;
    if(auto result=check_ipv6())return result;
    if(auto result=check_receiver_policy())return result;
    std::println("CONNECT-IP packet framing and advertised policy passed");
}
