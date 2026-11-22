import std;
import shadowsocks.header;
namespace s=shadowsocks;
int main() {
    std::array<std::uint8_t,7> address{1,127,0,0,1,0x1f,0x90};
    std::array<std::uint8_t,2> padding{0xaa,0xbb};
    std::array<std::uint8_t,3> payload{1,2,3};
    std::vector<std::uint8_t> expected{1,127,0,0,1,0x1f,0x90,0,2,0xaa,0xbb,1,2,3};
    auto variable=s::make_request_header(address,padding,payload);
    if (!variable || *variable!=expected) return 1;
    auto parsed=s::parse_request_header(*variable);
    if (!parsed || !std::ranges::equal(parsed->address,address) || !std::ranges::equal(parsed->payload,payload)) return 2;
    for (std::size_t i=0;i<11;++i) if (s::parse_request_header(std::span{expected}.first(i))) return 3;
    if (s::make_request_header(address,{},{})) return 4;
    std::array<std::uint8_t,6> domain{3,2,'a','b',0,80};
    if (!s::make_request_header(domain,{},payload)) return 5;
    domain[1]=0; if (s::make_request_header(domain,{},payload)) return 6;
    std::array<std::uint8_t,19> ipv6{}; ipv6[0]=4; ipv6[18]=80;
    if (!s::make_request_header(ipv6,padding,{})) return 17;
    auto bad=expected; bad[7]=3; bad[8]=0x85;
    if (s::parse_request_header(bad)) return 18;
    bad=expected; bad[7]=0; bad[8]=8;
    if (s::parse_request_header(bad)) return 19;
    bad=expected; bad.resize(9); bad[7]=0; bad[8]=0;
    if (s::parse_request_header(bad)) return 20;
    std::vector<std::uint8_t> max_payload(65535-address.size()-2,1);
    auto max=s::make_request_header(address,{},max_payload);
    if (!max || max->size()!=65535 || !s::parse_request_header(*max)) return 7;
    max_payload.push_back(1); if (s::make_request_header(address,{},max_payload)) return 8;
    std::vector<std::uint8_t> excess_padding(901); if (s::make_request_header(address,excess_padding,payload)) return 9;
    auto fixed=s::make_fixed_header(false,0x0102030405060708ULL,0xabcd);
    std::vector<std::uint8_t> fixed_expected{0,1,2,3,4,5,6,7,8,0xab,0xcd};
    if (!fixed || *fixed!=fixed_expected) return 10;
    auto decoded=s::parse_fixed_header(*fixed,false,0x0102030405060708ULL+30);
    if (!decoded || decoded->length!=0xabcd || decoded->timestamp!=0x0102030405060708ULL) return 11;
    if (s::parse_fixed_header(*fixed,false,0x0102030405060708ULL+31) ||
        s::parse_fixed_header(*fixed,false,0x0102030405060708ULL-31)) return 12;
    for (std::size_t size:{16u,32u}) {
        std::vector<std::uint8_t> salt(size,0x42);
        auto response=s::make_fixed_header(true,42,5,salt);
        if (!response || !s::parse_fixed_header(*response,true,12,salt)) return 13;
        salt[0]^=1; if (s::parse_fixed_header(*response,true,42,salt)) return 14;
        (*response)[0]=0; if (s::parse_fixed_header(*response,true,42,salt)) return 15;
    }
    if (s::parse_fixed_header(fixed_expected,true,0,{})) return 16;
    std::cout << "Shadowsocks 2022 headers passed\n";
}
