import std;
import quic.varint;
import hysteria2.wire;
import hysteria2.udp;
namespace h=hysteria2;
namespace q=quic;
auto emit(std::string_view name,std::span<std::uint8_t const> bytes) -> void {
    constexpr std::string_view digits="0123456789abcdef";
    std::cout<<name<<' ';
    for (auto byte:bytes) std::cout<<digits[byte>>4]<<digits[byte&15];
    std::cout<<'\n';
}
auto main() -> int {
    for (auto value:std::array<std::uint64_t,9>{0,37,63,64,16383,16384,1073741823,1073741824,q::max_varint}) {
        std::vector<std::uint8_t> bytes;
        if (!q::append_varint(bytes,value)) return 1;
        emit(std::format("varint-{}",value),bytes);
    }
    for (auto address:{"example.test:443","[2001:db8::1]:53"}) {
        auto bytes=h::encode_tcp_request(address,std::array<std::uint8_t,3>{0,1,255});
        if (!bytes) return 2; emit(std::string("request-")+address,*bytes);
    }
    auto success=h::encode_tcp_response(h::TcpStatus::success);
    auto failure=h::encode_tcp_response(h::TcpStatus::error,"connection refused",std::array<std::uint8_t,3>{1,2,3});
    if (!success || !failure) return 3;
    emit("response-success",*success); emit("response-error",*failure);
    std::array<std::uint8_t,5> payload{0,1,127,128,255};
    auto udp=h::encode_udp_packet({0x01020304,0x0506,127,1,"example.test:53",payload});
    auto fragmented=h::encode_udp_packet({0x01020304,0xffff,2,3,"[2001:db8::1]:53",payload});
    if (!udp || !fragmented) return 4;
    emit("udp-single",*udp); emit("udp-fragment",*fragmented);
}

