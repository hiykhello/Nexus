import std;
import trojan;

namespace {
    using namespace trojan;
    auto address(Family family,std::string_view text,std::uint16_t port=443) -> Address {
        Address result{family,{},static_cast<std::uint8_t>(text.size()),port};
        std::ranges::copy(text,result.bytes.begin()); return result;
    }
}
auto main() -> int {
    Key key; std::ranges::fill(key,'a');
    auto ipv4=address(Family::ipv4,std::string_view("\x7f\x00\x00\x01",4));
    auto ipv6=address(Family::ipv6,std::string_view("\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",16));
    auto domain=address(Family::domain,"example.test");
    std::array<std::uint8_t,4> payload{0,1,2,255};
    for (auto const& destination:{ipv4,ipv6,domain,address(Family::domain,std::string(255,'x'))}) {
        for (auto command:{Command::tcp,Command::udp}) {
            auto encoded=encode_request(key,{command,destination});
            if (!encoded || encoded->size()>320) return 1;
            auto wire=*encoded; wire.insert(wire.end(),payload.begin(),payload.end());
            auto parsed=parse_request(wire);
            if (parsed.status!=Status::accepted || parsed.consumed!=encoded->size() || parsed.key!=key ||
                parsed.request.command!=command || parsed.request.destination!=destination) return 2;
            for (std::size_t split=0;split<=encoded->size();++split) {
                RequestDecoder decoder;
                auto first=decoder.feed(std::span(wire).first(split));
                auto next=decoder.feed(std::span(wire).subspan(split));
                if ((split<encoded->size() && first.status!=Status::incomplete) || next.status!=Status::accepted ||
                    first.consumed+next.consumed!=encoded->size() || !decoder.request() ||
                    decoder.request()->request.destination!=destination) return 3;
                if (decoder.feed(payload).consumed) return 4;
            }
            RequestDecoder bytewise;
            for (std::size_t i=0;i<encoded->size();++i) {
                auto fed=bytewise.feed(std::span(wire).subspan(i,1));
                if (fed.consumed!=1 || fed.status!=(i+1==encoded->size() ? Status::accepted : Status::incomplete)) return 5;
            }
        }
    }
    auto header=*encode_request(key,{Command::tcp,ipv4});
    std::vector<std::uint8_t> expected(56,'a');
    for (auto value:{13,10,1,1,127,0,0,1,1,187,13,10}) expected.push_back(static_cast<std::uint8_t>(value));
    if (header!=expected) return 6;
    for (auto offset:{0u,56u,57u,58u,59u,66u,67u}) {
        auto bad=header; bad[offset]=255;
        if (parse_request(bad).status==Status::accepted || parse_request(bad).status==Status::incomplete) return 7;
    }
    auto no_port=ipv4; no_port.port=0;
    if (encode_request(key,{Command::tcp,no_port}) || !encode_request(key,{Command::udp,no_port}) ||
        encode_request(key,{static_cast<Command>(127),ipv4})) return 8;
    auto bad=domain; bad.bytes[0]=0;
    if (encode_request(key,{Command::tcp,bad})) return 9;
    for (auto const& destination:{ipv4,ipv6,domain}) for (auto size:{0u,1u,4096u,65535u}) {
        std::vector<std::uint8_t> data(size,173);
        auto frame=net::encode_datagram(datagram_framing,destination,data);
        if (!frame) return 10;
        auto pair=*frame; pair.insert(pair.end(),frame->begin(),frame->end());
        net::DatagramDecoder decoder(datagram_framing);
        std::size_t consumed=0;
        while (consumed<frame->size()) {
            auto fed=decoder.feed(std::span(pair).subspan(consumed,std::min(std::size_t{7},pair.size()-consumed)));
            consumed+=fed.consumed;
            if (fed.status!=net::DatagramStatus::incomplete && fed.status!=net::DatagramStatus::accepted) return 11;
            if (!fed.consumed) return 12;
        }
        auto packet=decoder.packet();
        if (consumed!=frame->size() || !packet || packet->destination!=destination ||
            !std::ranges::equal(packet->payload,data) || decoder.feed(pair).consumed) return 13;
        if (!decoder.consume() || !decoder.at_boundary() || decoder.feed(*frame).status!=net::DatagramStatus::accepted) return 14;
    }
    auto frame=*net::encode_datagram(datagram_framing,ipv4,payload);
    std::vector<std::uint8_t> expected_frame{1,127,0,0,1,1,187,0,4,13,10,0,1,2,255};
    if (frame!=expected_frame) return 15;
    frame[9]=0;
    net::DatagramDecoder malformed(datagram_framing);
    if (malformed.feed(frame).status!=net::DatagramStatus::invalid_frame || malformed.at_boundary()) return 16;
    net::DatagramDecoder limited(datagram_framing,{},3);
    if (limited.feed(expected_frame).status!=net::DatagramStatus::too_large) return 17;
    std::println("Trojan request vectors, fragmented headers, UDP framing, boundaries and limits passed");
}
