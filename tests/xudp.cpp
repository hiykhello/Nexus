import std;
import xudp;
namespace x=xudp;
using Bytes=std::vector<std::uint8_t>;
auto hex(std::string_view text) -> Bytes {
    auto digit=[](char c) { return c<='9' ? c-'0' : c-'a'+10; }; Bytes result;
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(digit(text[i])*16+digit(text[i+1])); return result;
}
int main(int argc,char** argv) {
    x::Address ipv4; ipv4.length=4; ipv4.port=443; std::ranges::copy(std::array<std::uint8_t,4>{192,0,2,1},ipv4.bytes.begin());
    x::Address ipv6; ipv6.family=x::Family::ipv6; ipv6.length=16; ipv6.port=5353;
    std::ranges::copy(std::array<std::uint8_t,16>{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},ipv6.bytes.begin());
    Bytes hello{'h','e','l','l','o'},world{'w','o','r','l','d'},end{'e','n','d'};
    x::Frame first{0,x::Kind::open,true,false,ipv4,std::array<std::uint8_t,8>{1,2,3,4,5,6,7,8},hello};
    x::Frame second{0,x::Kind::data,true,false,ipv6,{},world};
    x::Frame third{0,x::Kind::data,true,false,{},{},end};
    std::array vectors{hex("0014000001010201bb01c00002010102030405060708000568656c6c6f"),hex("0018000002010214e90320010db80000000000000000000000010005776f726c64"),hex("0004000002010003656e64")};
    auto a=x::encode(first),b=x::encode(second),c=x::encode(third);
    if (!a || !b || !c || *a!=vectors[0] || *b!=vectors[1] || *c!=vectors[2]) return 1;
    if (argc==2 && std::string_view(argv[1])=="--vectors") {
        constexpr char digits[]="0123456789abcdef";
        for (auto const* wire : {&*a,&*b,&*c}) { for (auto byte:*wire) std::cout << digits[byte>>4] << digits[byte&15]; std::cout << '\n'; }
        return 0;
    }
    for (auto const& wire:vectors) {
        auto parsed=x::parse(wire); if (parsed.status!=x::Status::ready || parsed.consumed!=wire.size()) return 2;
        for (std::size_t split=0;split<wire.size();++split) {
            if (x::parse(std::span(wire).first(split)).status!=x::Status::incomplete) return 3;
            x::Decoder decoder; auto head=decoder.feed(std::span(wire).first(split));
            auto tail=decoder.feed(std::span(wire).subspan(split));
            if (head.consumed!=split || tail.consumed!=wire.size()-split || tail.status!=x::Status::ready || !decoder.frame() || !decoder.consume() || !decoder.at_boundary()) return 4;
        }
    }
    Bytes merged=vectors[0]; merged.insert(merged.end(),vectors[1].begin(),vectors[1].end());
    x::Decoder decoder; auto one=decoder.feed(merged);
    if (one.status!=x::Status::ready || one.consumed!=vectors[0].size() || one.frame.address!=ipv4 || !std::ranges::equal(one.frame.payload,hello)) return 5;
    if (decoder.feed(std::span(merged).subspan(one.consumed)).consumed || !decoder.consume()) return 6;
    auto two=decoder.feed(std::span(merged).subspan(one.consumed));
    if (two.status!=x::Status::ready || two.frame.address!=ipv6 || !std::ranges::equal(two.frame.payload,world)) return 7;
    x::Address domain; domain.family=x::Family::domain; domain.length=11; domain.port=53; std::ranges::copy(std::string_view("example.org"),domain.bytes.begin());
    x::Frame f{42,x::Kind::open,true,false,domain,{}, {}}; auto domain_wire=x::encode(f); if (!domain_wire) return 8;
    auto parsed=x::parse(*domain_wire); if (parsed.status!=x::Status::ready || parsed.frame.address!=domain || !parsed.frame.has_data || !parsed.frame.payload.empty() || parsed.frame.session!=42) return 9;
    x::Frame no_data_id{42,x::Kind::open,false,false,ipv4,std::array<std::uint8_t,8>{1,2,3,4,5,6,7,8}};
    if (x::encode(no_data_id)) return 18;
    x::Frame control{42,x::Kind::end,false,true}; auto control_wire=x::encode(control); if (!control_wire || x::parse(*control_wire).frame.kind!=x::Kind::end || !x::parse(*control_wire).frame.error) return 10;
    auto invalid=vectors[0]; invalid[1]=3; if (x::parse(invalid).status!=x::Status::invalid) return 11;
    invalid=vectors[0]; invalid[6]=1; if (x::parse(invalid).status!=x::Status::invalid) return 12;
    invalid=vectors[0]; invalid[5]=0x80; if (x::parse(invalid).status!=x::Status::invalid) return 13;
    if (x::parse(vectors[0],4).status!=x::Status::too_large) return 14;
    x::Decoder limited(4); if (limited.feed(vectors[0]).status!=x::Status::too_large) return 15;
    x::Frame large{1,x::Kind::data,true,false}; Bytes max(65535,7); large.payload=max;
    auto max_wire=x::encode(large); if (!max_wire || x::parse(*max_wire).frame.payload.size()!=max.size()) return 16;
    decoder.close(); if (decoder.feed(vectors[0]).status!=x::Status::closed) return 17;
    std::cout << "XUDP frame vectors, boundaries, limits and invalid metadata passed\n";
}
