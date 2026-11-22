import std;
import quic.varint;
import hysteria2.wire;
namespace h=hysteria2;
namespace q=quic;
template<class Decoder>
auto split_headers(std::span<std::uint8_t const> header,bool request,std::string_view text) -> bool {
    std::vector<std::uint8_t> input(header.begin(),header.end()); input.insert(input.end(),{'d','a','t','a'});
    for (std::size_t split=0;split<=header.size();++split) {
        Decoder decoder;
        auto first=decoder.feed(std::span(input).first(split)),second=decoder.feed(std::span(input).subspan(split));
        if ((split<header.size() && first.status!=h::WireStatus::incomplete) || second.status!=h::WireStatus::accepted ||
            first.consumed+second.consumed!=header.size() || decoder.feed(input).consumed) return false;
        if constexpr (requires { decoder.request(); }) {
            if (!request || !decoder.request() || decoder.request()->address!=text) return false;
        } else if (request || !decoder.response() || decoder.response()->message!=text) return false;
        decoder.close(); if (decoder.feed(input).status!=h::WireStatus::closed) return false;
    }
    Decoder bytewise;
    for (std::size_t i=0;i<header.size();++i) {
        auto fed=bytewise.feed(header.subspan(i,1));
        if (fed.consumed!=1 || fed.status!=(i+1==header.size() ? h::WireStatus::accepted : h::WireStatus::incomplete)) return false;
    }
    for (std::size_t size=0;size<header.size();++size) {
        Decoder truncated;
        (void)truncated.feed(header.first(size));
        if (truncated.finish()!=h::WireStatus::truncated || truncated.feed(header).consumed) return false;
    }
    return true;
}
auto main() -> int {
    for (auto address:{"example.test:443","127.0.0.1:1","[2001:db8::1]:65535"}) {
        for (auto padding:{0u,1u,64u,4096u}) {
            auto wire=h::encode_tcp_request(address,std::vector<std::uint8_t>(padding,0xa5));
            if (!wire || !split_headers<h::TcpRequestDecoder>(*wire,true,address)) return 1;
        }
    }
    for (auto status:{h::TcpStatus::success,h::TcpStatus::error}) for (auto size:{0u,1u,64u,2048u}) {
        std::string message(size,'m');
        for (auto padding:{0u,1u,128u,4096u}) {
            auto wire=h::encode_tcp_response(status,message,std::vector<std::uint8_t>(padding,0xa5));
            if (!wire || !split_headers<h::TcpResponseDecoder>(*wire,false,message)) return 2;
            h::TcpResponseDecoder decoder;
            if (decoder.feed(*wire).status!=h::WireStatus::accepted || decoder.response()->status!=status) return 3;
        }
    }
    auto request=h::encode_tcp_request("example.test:443",std::array<std::uint8_t,3>{0,1,2});
    std::vector<std::uint8_t> fixed{0x44,0x01,16,'e','x','a','m','p','l','e','.','t','e','s','t',':','4','4','3',3,0,1,2};
    if (!request || *request!=fixed || *h::encode_tcp_response(h::TcpStatus::success)!=std::vector<std::uint8_t>{0,0,0}) return 4;
    if (h::encode_tcp_request("") || h::encode_tcp_request(std::string(2049,'a')) ||
        h::encode_tcp_request("x:1",std::vector<std::uint8_t>(4097)) ||
        h::encode_tcp_response(static_cast<h::TcpStatus>(2)) || h::encode_tcp_response(h::TcpStatus::error,std::string(2049,'x'))) return 5;
    for (auto width:{2u,4u,8u}) {
        std::array<std::uint8_t,8> bytes{};
        std::vector<std::uint8_t> wire;
        auto append=[&](std::uint64_t value) {
            auto size=q::write_varint(bytes,value,width); wire.insert(wire.end(),bytes.begin(),bytes.begin()+*size);
        };
        append(h::tcp_request_type); append(3); wire.insert(wire.end(),{'x',':','1'}); append(0);
        if (!split_headers<h::TcpRequestDecoder>(wire,true,"x:1")) return 6;
    }
    for (auto bad:std::vector<std::vector<std::uint8_t>>{{0x44,0x02},{0x44,1,0},{0x44,1,0x48,1},{0x44,1,1,'x',0x50,1}}) {
        h::TcpRequestDecoder decoder;
        auto fed=decoder.feed(bad);
        if (fed.status!=h::WireStatus::invalid_type && fed.status!=h::WireStatus::invalid_length && fed.status!=h::WireStatus::too_large) return 7;
    }
    h::TcpResponseDecoder status;
    if (status.feed(std::array<std::uint8_t,1>{2}).status!=h::WireStatus::invalid_status) return 8;
    std::println("Hy2 TCP fixed vectors, arbitrary fragments, legal varints, bounded padding skip and payload suffix passed");
}

