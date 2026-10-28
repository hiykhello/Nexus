import std;
import nexus.dns.fakeip_history;
import nexus.dns.fakeip_recovery;
import nexus.crypto;
using namespace std::chrono_literals;
namespace d=nexus::dns;
auto main() -> int {
    std::array<std::uint8_t,16> instance{}; instance[0]=42;
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),std::uint8_t{0});
    std::array ranges{d::FakeIpHistoricalRange{0,3,12s},d::FakeIpHistoricalRange{10,20,45s}};
    auto wire=d::encode_fakeip_history({7,std::vector<d::FakeIpHistoricalRange>(ranges.begin(),ranges.end())},instance,key);
    if (!wire || wire->size()!=96) return 1;
    auto decoded=d::decode_fakeip_history(*wire,instance,key);
    if (!decoded || decoded->generation!=7 || decoded->ranges.size()!=2 || decoded->ranges[0].first!=0 || decoded->ranges[0].last!=3 ||
        decoded->ranges[0].protection!=12s || decoded->ranges[1].first!=10 || decoded->ranges[1].last!=20 || decoded->ranges[1].protection!=45s) return 2;
    for (std::size_t i=0;i<wire->size();++i) {
        auto corrupt=*wire; corrupt[i]^=1;
        if (d::decode_fakeip_history(corrupt,instance,key)) return 3;
    }
    for (std::size_t size=0;size<wire->size();++size)
        if (d::decode_fakeip_history(std::span{*wire}.first(size),instance,key)) return 4;
    auto extra=*wire; extra.push_back(0);
    if (d::decode_fakeip_history(extra,instance,key)) return 5;
    auto wrong_key=key; ++wrong_key[0]; auto wrong_instance=instance; ++wrong_instance[0];
    if (d::decode_fakeip_history(*wire,instance,wrong_key) || d::decode_fakeip_history(*wire,wrong_instance,key)) return 6;
    auto bad=ranges; bad[1].first=4;
    if (d::encode_fakeip_history({7,std::vector<d::FakeIpHistoricalRange>(bad.begin(),bad.end())},instance,key) ||
        d::encode_fakeip_history({0,std::vector<d::FakeIpHistoricalRange>(ranges.begin(),ranges.end())},instance,key)) return 7;
    // Forge valid tags over semantically invalid records to test validation independently of authentication.
    auto malformed=*wire; malformed[24+16+3]=4;
    auto mac=nexus::crypto::hmac(nexus::crypto::Hash::sha256,key,std::span{malformed}.first(malformed.size()-32));
    if (!mac) return 8;
    std::ranges::copy(*mac,malformed.end()-32);
    if (d::decode_fakeip_history(malformed,instance,key)) return 9;
    std::vector<d::FakeIpHistoricalRange> maximum;
    for (std::uint32_t i=0;i<256;++i) maximum.push_back({i*2,i*2,1s});
    auto large=d::encode_fakeip_history({1,maximum},instance,key);
    if (!large || !d::decode_fakeip_history(*large,instance,key)) return 10;
    maximum.push_back({1000,1000,1s});
    if (d::encode_fakeip_history({1,maximum},instance,key)) return 11;
    std::println("FakeIP authenticated history format and strict validation passed");
}
