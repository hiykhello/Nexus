import std;
import nexus.shadowsocks.udp_cipher;
namespace s=nexus::shadowsocks;

auto hex(std::string_view text) -> std::vector<std::uint8_t> {
    auto digit=[](char c) { return c<='9' ? c-'0' : c-'a'+10; };
    std::vector<std::uint8_t> result;
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(static_cast<std::uint8_t>(digit(text[i])*16+digit(text[i+1])));
    return result;
}
int main() {
    auto separate=hex("00112233445566770000000000000001");
    auto body=hex("000000006553f1000000017f0000011f9068656c6c6f");
    auto header=std::span<std::uint8_t const,16>{separate.data(),16};
    for (std::size_t size : {16u,32u}) {
        std::array<std::uint8_t,32> key{};
        std::iota(key.begin(),key.end(),0);
        auto psk=std::span{key}.first(size);
        auto expected=hex(size==16 ? "6b53a031bb9802f8718cf48f2637595d133c1bb830fb2f40fb5ef2ba69be59720f9c3ebec368882ea3243a5888e24131d54f488ee3b2" :
            "c9942f30306784d0e9ea87ffd1d33a822e1ad3ae7d79ebfd04ed5c19201a3a6d254419f3135a0d23832369438c8f5f0252867a87d487");
        auto sealed=s::seal_udp(psk,header,body);
        if (!sealed || *sealed!=expected) return 1;
        auto opened=s::open_udp(psk,*sealed);
        if (!opened || !std::ranges::equal(opened->separate_header,separate) || opened->body!=body) return 2;
        for (std::size_t i=0;i<sealed->size();++i) {
            auto corrupt=*sealed; corrupt[i]^=1;
            auto bad=s::open_udp(psk,corrupt);
            if (bad || bad.error()!=s::UdpCipherError::authentication) return 3;
        }
        for (std::size_t n=0;n<32;++n)
            if (s::open_udp(psk,std::span{*sealed}.first(n)).error()!=s::UdpCipherError::invalid_length) return 4;
        auto empty=s::seal_udp(psk,header,{});
        if (!empty || empty->size()!=32 || !s::open_udp(psk,*empty) || !s::open_udp(psk,*empty)->body.empty()) return 5;
        std::vector<std::uint8_t> max(65535-32,0xa5);
        auto big=s::seal_udp(psk,header,max);
        if (!big || big->size()!=65535 || !s::open_udp(psk,*big) || s::open_udp(psk,*big)->body!=max) return 6;
        max.push_back(0);
        if (s::seal_udp(psk,header,max).error()!=s::UdpCipherError::invalid_length) return 7;
        big->push_back(0);
        if (s::open_udp(psk,*big).error()!=s::UdpCipherError::invalid_length) return 8;
    }
    std::array<std::uint8_t,15> invalid{};
    if (s::seal_udp(invalid,header,body).error()!=s::UdpCipherError::invalid_key ||
        s::open_udp(invalid,body).error()!=s::UdpCipherError::invalid_key) return 9;
    std::println("SS-2022 UDP AES cipher vectors and authentication passed");
}
