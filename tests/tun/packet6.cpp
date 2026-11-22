import std;
import packet;
namespace p = ::packet;

int main() {
    constexpr p::Address6 src{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    constexpr p::Address6 dst{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    p::Bytes expected{0x60,0,0,0,0,13,17,64, 0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1,
                      0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2, 0x30,0x39,0,53,0,13,0x30,0x1f,'h','e','l','l','o'};
    p::Bytes payload{'h','e','l','l','o'};
    auto packet = p::make_udp6(src, dst, 12345, 53, payload);
    if (!packet || *packet != expected) return 1;
    auto parsed = p::parse_udp6(*packet);
    if (!parsed || parsed->source != src || parsed->destination != dst || parsed->source_port != 12345 ||
        parsed->destination_port != 53 || !std::ranges::equal(parsed->payload, payload)) return 1;
    for (std::size_t i = 0; i < packet->size(); ++i) if (p::parse_udp6(std::span(*packet).first(i))) return 1;
    for (auto i : {8, 24, 48}) { auto bad = *packet; bad[i] ^= 1; if (p::parse_udp6(bad)) return 1; }
    auto bad = *packet; bad[46] = bad[47] = 0;
    if (p::parse_udp6(bad)) return 1;
    for (auto next : {0, 43, 44, 50, 51, 60, 6}) {
        bad = *packet; bad[6] = next;
        if (p::parse_udp6(bad)) return 1;
    }
    bad = *packet; ++bad[5]; if (p::parse_udp6(bad)) return 1;
    bad = *packet; --bad[45]; if (p::parse_udp6(bad)) return 1;
    bad = *packet; bad.push_back(0); if (p::parse_udp6(bad)) return 1;
    // The UDP pseudo-header length excludes both extension headers.
    auto extended=*packet;
    constexpr std::array<std::uint8_t,16> options{60,0,1,4,0,0,0,0, 17,0,0,0,1,2,0,0};
    extended.insert(extended.begin()+40,options.begin(),options.end());
    extended[6]=0; extended[5]+=16;
    auto with_options=p::parse_udp6(extended);
    if (!with_options || with_options->source_port!=12345 || with_options->destination_port!=53 ||
        !std::ranges::equal(with_options->payload,payload)) return 1;
    for (std::size_t i=0;i<extended.size();++i) if (p::parse_udp6(std::span(extended).first(i))) return 1;
    bad=extended; bad[41]=2; if (p::parse_udp6(bad)) return 1;
    bad=extended; bad[43]=7; if (p::parse_udp6(bad)) return 1;
    bad=extended; bad[44]=1; if (p::parse_udp6(bad)) return 1;
    auto unknown=extended; unknown[42]=0x1e; unknown[44]=0xaa; unknown[45]=0xbb;
    if (!p::parse_udp6(unknown)) return 1;
    unknown[50]=0x20; unknown[51]=2; unknown[52]=0x55; unknown[53]=0xaa;
    if (!p::parse_udp6(unknown)) return 1;
    for (auto type : {0x40,0x80,0xc0}) {
        bad=unknown; bad[42]=type; if (p::parse_udp6(bad)) return 1;
        bad=unknown; bad[50]=type; if (p::parse_udp6(bad)) return 1;
    }
    bad=unknown; bad[43]=7; if (p::parse_udp6(bad)) return 1;
    bad=extended; bad[48]=0; if (p::parse_udp6(bad)) return 1;
    bad=extended; bad[48]=44; if (p::parse_udp6(bad)) return 1;
    bad=extended; bad[64]^=1; if (p::parse_udp6(bad)) return 1;
    if (p::make_udp6(src, dst, 1, 2, payload, 52) || p::make_udp6(src, dst, 1, 2, p::Bytes(65528), 70000)) return 1;
    auto max = p::make_udp6(src, dst, 1, 2, p::Bytes(65527, 7), 65575);
    if (!max || !p::parse_udp6(*max)) return 1;
    p::MemoryLink link;
    if (!link.send(p::Side::first, *packet)) return 1;
    auto received = link.receive(p::Side::second);
    if (!received || !*received || !p::parse_udp6(**received)) return 1;
    auto reply = p::make_udp6(dst, src, 53, 12345, payload);
    if (!reply || !link.send(p::Side::second, *reply)) return 1;
    auto returned = link.receive(p::Side::first);
    if (!returned || !*returned || !p::parse_udp6(**returned)) return 1;
    std::cout << "IPv6 UDP packet validation and memory roundtrip passed\n";
}
