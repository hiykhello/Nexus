import std;
import nexus.shadowsocks.udp_packet;
import nexus.shadowsocks.udp_cipher;
import nexus.shadowsocks.udp_replay;
namespace s = nexus::shadowsocks;

int main() {
    std::array<std::uint8_t,32> key{};
    std::iota(key.begin(),key.end(),0);
    std::array<std::uint8_t,8> client{0,1,2,3,4,5,6,7};
    std::array<std::uint8_t,8> server{8,9,10,11,12,13,14,15};
    std::vector<std::vector<std::uint8_t>> addresses{
        {1,127,0,0,1,0x1f,0x90},
        {4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,53},
        {3,3,'a','b','c',0,80}};
    for (std::size_t size : {16u,32u}) {
        auto psk=std::span{key}.first(size);
        for (auto direction : {s::UdpDirection::client,s::UdpDirection::server}) {
            for (auto const& address : addresses) {
                s::UdpPacket packet{direction==s::UdpDirection::client ? client : server,
                    0x0102030405060708ULL,1000,direction==s::UdpDirection::server ? std::optional{client} : std::nullopt,
                    address,{1,2,3,4}};
                std::array<std::uint8_t,3> padding{5,6,7};
                auto encoded=s::encode_udp_packet(psk,direction,packet,padding);
                if (!encoded) return 1;
                auto expected=direction==s::UdpDirection::server ? std::optional{client} : std::nullopt;
                auto decoded=s::decode_udp_packet(psk,direction,*encoded,1000,expected);
                if (!decoded || decoded->session_id!=packet.session_id || decoded->packet_id!=packet.packet_id ||
                    decoded->timestamp!=packet.timestamp || decoded->client_session!=packet.client_session ||
                    decoded->address!=address || decoded->payload!=packet.payload) return 2;
                auto opened=s::open_udp(psk,*encoded);
                std::array<std::uint8_t,8> id{1,2,3,4,5,6,7,8};
                if (!opened || !std::ranges::equal(std::span{opened->separate_header}.first<8>(),packet.session_id) ||
                    !std::ranges::equal(std::span{opened->separate_header}.last<8>(),id)) return 3;
                if (!s::decode_udp_packet(psk,direction,*encoded,970,expected) ||
                    !s::decode_udp_packet(psk,direction,*encoded,1030,expected) ||
                    s::decode_udp_packet(psk,direction,*encoded,969,expected).error()!=s::UdpPacketError::invalid_timestamp ||
                    s::decode_udp_packet(psk,direction,*encoded,1031,expected).error()!=s::UdpPacketError::invalid_timestamp ||
                    s::decode_udp_packet(psk,direction,*encoded,std::numeric_limits<std::uint64_t>::max(),expected).error()!=s::UdpPacketError::invalid_timestamp) return 4;
                for (std::size_t i=0;i<encoded->size();++i) {
                    auto corrupt=*encoded; corrupt[i]^=1;
                    if (s::decode_udp_packet(psk,direction,corrupt,1000,expected).error()!=s::UdpPacketError::authentication) return 5;
                }
                auto body=opened->body;
                auto seal=[&](std::vector<std::uint8_t> const& b) { return *s::seal_udp(psk,opened->separate_header,b); };
                body[0]^=1;
                if (s::decode_udp_packet(psk,direction,seal(body),1000,expected).error()!=s::UdpPacketError::invalid_type) return 6;
                body=opened->body; body.resize(direction==s::UdpDirection::server ? 18 : 10);
                if (s::decode_udp_packet(psk,direction,seal(body),1000,expected).error()!=s::UdpPacketError::invalid_length) return 7;
                body=opened->body; auto offset=direction==s::UdpDirection::server ? 17u : 9u;
                body[offset]=255; body[offset+1]=255;
                if (s::decode_udp_packet(psk,direction,seal(body),1000,expected).error()!=s::UdpPacketError::invalid_length) return 8;
                body=opened->body; body[offset+2+padding.size()]=0;
                if (s::decode_udp_packet(psk,direction,seal(body),1000,expected).error()!=s::UdpPacketError::invalid_address) return 9;
                if (direction==s::UdpDirection::server &&
                    (s::decode_udp_packet(psk,direction,*encoded,1000,server).error()!=s::UdpPacketError::invalid_session ||
                     s::decode_udp_packet(psk,direction,*encoded,1000).error()!=s::UdpPacketError::invalid_session)) return 10;
            }
        }
        s::UdpPacket packet{client,1,1000,{},addresses[0],{}};
        auto wire=*s::encode_udp_packet(psk,s::UdpDirection::client,packet,{});
        s::UdpReplayWindow replay;
        auto receive=[&](std::vector<std::uint8_t> const& input, std::uint64_t now) {
            auto decoded=s::decode_udp_packet(psk,s::UdpDirection::client,input,now);
            return decoded && replay.commit(decoded->packet_id)==s::UdpReplayResult::fresh;
        };
        auto forged=wire; forged.back()^=1;
        if (receive(forged,1000) || receive(wire,1031) || !receive(wire,1000) || receive(wire,1000)) return 11;
        packet.address={3,0,0,0};
        if (s::encode_udp_packet(psk,s::UdpDirection::client,packet,{}).error()!=s::UdpPacketError::invalid_address) return 12;
    }
    std::println("SS-2022 UDP packet and replay integration passed");
}
