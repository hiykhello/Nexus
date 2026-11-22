import std;
import masque.udp_session;
import quic.varint;
namespace m=masque;
namespace q=quic;
auto main() -> int {
    m::UdpRequests<2> requests;
    auto first=requests.open(0,true);if(!first || requests.can_send(*first) || requests.can_receive(*first))return 1;
    requests.receive_close(*first);if(requests.approve(*first) || !requests.close(*first))return 2;
    auto next=requests.open(4,true);if(!next || requests.approve(*first) || !requests.approve(*next) || !requests.can_send(*next) || !requests.can_receive(*next))return 3;
    requests.send_close(*next);if(requests.can_send(*next) || !requests.can_receive(*next))return 4;
    requests.receive_close(*next);if(requests.can_receive(*next) || !requests.close(*next))return 5;
    auto reused=requests.open(4,true);if(!reused || *reused==*next || requests.approve(*next) || !requests.close(*reused))return 6;
    std::vector<std::uint8_t> wire{0,4,0,1,2,3, 0x21,2,8,9, 0,2,2,42};
    for(std::size_t chunk=1;chunk<=wire.size();++chunk) {
        m::UdpCapsules<16> parser;std::vector<std::vector<std::uint8_t>> received;
        auto emit=[&](auto bytes){received.emplace_back(bytes.begin(),bytes.end());};
        for(std::size_t offset=0;offset<wire.size();) {
            auto n=std::min(chunk,wire.size()-offset);
            auto result=parser.feed(std::span(wire).subspan(offset,n),emit);
            if(result==m::UdpInput::malformed || result==m::UdpInput::too_large)return 7;
            offset+=n;
        }
        if(parser.finish(emit)==m::UdpInput::malformed || received.size()!=1 || received[0]!=std::vector<std::uint8_t>{1,2,3})return 8;
        if(parser.feed({},emit)!=m::UdpInput::closed)return 9;
    }
    auto ignore=[](auto){};
    {m::UdpCapsules<8> parser;std::array<std::uint8_t,2> empty{0,0};if(parser.feed(empty,ignore)!=m::UdpInput::malformed)return 10;}
    {m::UdpCapsules<8> parser;std::array<std::uint8_t,3> truncated{0,2,0};(void)parser.feed(truncated,ignore);if(parser.finish(ignore)!=m::UdpInput::malformed)return 11;}
    {m::UdpCapsules<8> parser;std::vector<std::uint8_t> oversized{0};q::append_varint(oversized,65529);oversized.push_back(0);if(parser.feed(oversized,ignore)!=m::UdpInput::too_large || parser.feed({},ignore)!=m::UdpInput::too_large || parser.finish(ignore)!=m::UdpInput::too_large)return 12;}
    {m::UdpCapsules<8> parser;std::vector<std::uint8_t> unknown{0};q::append_varint(unknown,65529);unknown.push_back(2);if(parser.feed(unknown,ignore)==m::UdpInput::too_large)return 13;}
    std::println("CONNECT-UDP authorization lifetime and Capsule boundaries passed");
}
