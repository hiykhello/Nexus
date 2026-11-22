import std;
import packet;
namespace p = ::packet;
auto hex(std::string_view text) -> p::Bytes {
    auto digit=[](char c) { return c<='9' ? c-'0' : c-'a'+10; };
    p::Bytes bytes;
    for (std::size_t i=0;i<text.size();i+=2) bytes.push_back(static_cast<std::uint8_t>(16*digit(text[i])+digit(text[i+1])));
    return bytes;
}
int main() {
    auto v4=hex("4500001f0000400040014ea7c0000201c63364020800216a1234fffe616263");
    auto v6=hex("60000000000b3a4020010db800000000000000000000000120010db800000000000000000000000280004daf1234fffe616263");
    auto a=p::parse_icmp_echo4(v4); auto b=p::parse_icmp_echo6(v6);
    p::Bytes payload{'a','b','c'};
    if (!a || !b || a->kind!=p::EchoKind::request || b->kind!=p::EchoKind::request ||
        a->identifier!=0x1234 || b->identifier!=0x1234 || a->sequence!=0xfffe || b->sequence!=0xfffe ||
        !std::ranges::equal(a->payload,payload) || !std::ranges::equal(b->payload,payload)) return 1;
    auto made4=p::make_icmp_echo4(*a); auto made6=p::make_icmp_echo6(*b);
    if (!made4 || *made4!=v4 || !made6 || *made6!=v6 || p::make_icmp_echo4(*a,30) || p::make_icmp_echo6(*b,50)) return 2;
    std::swap(a->source,a->destination); a->kind=p::EchoKind::reply;
    std::swap(b->source,b->destination); b->kind=p::EchoKind::reply;
    made4=p::make_icmp_echo4(*a); made6=p::make_icmp_echo6(*b);
    auto reply4=p::parse_icmp_echo4(*made4); auto reply6=p::parse_icmp_echo6(*made6);
    if (!reply4 || !reply6 || reply4->kind!=p::EchoKind::reply || reply6->kind!=p::EchoKind::reply ||
        reply4->source!=a->source || reply6->source!=b->source || !std::ranges::equal(reply4->payload,payload) ||
        !std::ranges::equal(reply6->payload,payload)) return 3;
    auto damaged=v4; damaged.back()^=1;
    if (p::parse_icmp_echo4(damaged).error()!=p::PacketError::invalid_checksum) return 4;
    damaged=v6; damaged[8]^=1;
    if (p::parse_icmp_echo6(damaged).error()!=p::PacketError::invalid_checksum) return 5;
    damaged=v4; damaged.resize(27);
    if (p::parse_icmp_echo4(damaged).error()!=p::PacketError::invalid_length) return 6;
    damaged=v6; damaged[6]=44;
    if (p::parse_icmp_echo6(damaged).error()!=p::PacketError::unsupported_fragment) return 7;
    damaged=v6; damaged[6]=60;
    if (p::parse_icmp_echo6(damaged).error()!=p::PacketError::invalid_length) return 8;
    damaged=v4; damaged[21]=1;
    if (p::parse_icmp_echo4(damaged).error()!=p::PacketError::unsupported_header) return 9;
    damaged=v4; damaged[6]=0x20; damaged[10]=0; damaged[11]=0;
    auto header_checksum=p::internet_checksum(std::span(damaged).first(20));
    damaged[10]=static_cast<std::uint8_t>(header_checksum>>8); damaged[11]=static_cast<std::uint8_t>(header_checksum);
    if (p::parse_icmp_echo4(damaged).error()!=p::PacketError::unsupported_fragment) return 10;
    auto empty4=*a; empty4.payload={}; auto empty6=*b; empty6.payload={};
    auto empty4wire=p::make_icmp_echo4(empty4,28); auto empty6wire=p::make_icmp_echo6(empty6,48);
    if (!empty4wire || !empty6wire || !p::parse_icmp_echo4(*empty4wire) || !p::parse_icmp_echo6(*empty6wire)) return 11;
    p::Bytes max4(65535-28,0xff), max6(65535-8,0xff);
    auto full4=empty4; full4.payload=max4; auto full6=empty6; full6.payload=max6;
    auto full4wire=p::make_icmp_echo4(full4,65535); auto full6wire=p::make_icmp_echo6(full6,65575);
    if (!full4wire || !full6wire || !p::parse_icmp_echo4(*full4wire) || !p::parse_icmp_echo6(*full6wire)) return 12;
    max4.push_back(0); full4.payload=max4; max6.push_back(0); full6.payload=max6;
    if (p::make_icmp_echo4(full4,65536) || p::make_icmp_echo6(full6,65576)) return 13;
    auto options4=v4; options4.insert(options4.begin()+20,{1,1,0,0});
    options4[0]=0x46; options4[3]=static_cast<std::uint8_t>(options4.size()); options4[10]=0; options4[11]=0;
    header_checksum=p::internet_checksum(std::span(options4).first(24));
    options4[10]=static_cast<std::uint8_t>(header_checksum>>8); options4[11]=static_cast<std::uint8_t>(header_checksum);
    auto parsed4=p::parse_icmp_echo4(options4);
    if (!parsed4 || !std::ranges::equal(parsed4->payload,payload)) return 14;
    auto bad4=options4; bad4[20]=7; bad4[10]=0; bad4[11]=0;
    header_checksum=p::internet_checksum(std::span(bad4).first(24));
    bad4[10]=static_cast<std::uint8_t>(header_checksum>>8); bad4[11]=static_cast<std::uint8_t>(header_checksum);
    if (p::parse_icmp_echo4(bad4).error()!=p::PacketError::unsupported_header) return 15;
    auto options6=v6; options6.insert(options6.begin()+40,{60,0,1,4,0,0,0,0,58,0,0x1e,2,0xaa,0xbb,1,0});
    options6[6]=0; options6[5]=static_cast<std::uint8_t>(options6.size()-40);
    auto parsed6=p::parse_icmp_echo6(options6);
    if (!parsed6 || parsed6->identifier!=0x1234 || !std::ranges::equal(parsed6->payload,payload)) return 16;
    auto bad6=options6; bad6[42]=0x80;
    if (p::parse_icmp_echo6(bad6).error()!=p::PacketError::unsupported_header) return 17;
    bad6=options6; bad6[48]=0;
    if (p::parse_icmp_echo6(bad6).error()!=p::PacketError::unsupported_header) return 18;
    bad6=options6; bad6[41]=0xff;
    if (p::parse_icmp_echo6(bad6).error()!=p::PacketError::invalid_length) return 19;
    bad6=options6; bad6.back()^=1;
    if (p::parse_icmp_echo6(bad6).error()!=p::PacketError::invalid_checksum) return 20;
    std::println("ICMPv4 and ICMPv6 echo codec fixed vectors and validation passed");
}
