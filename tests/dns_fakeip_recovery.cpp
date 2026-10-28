import std;
import nexus.dns.fakeip_recovery;
import nexus.dns.fakeip_shared;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
import nexus.dns.message;
using namespace std::chrono_literals;
namespace d=nexus::dns;
auto main() -> int {
    constexpr std::uint32_t base=0xc6120000;
    auto start=std::chrono::steady_clock::time_point{};
    d::FakeIpRecoveryPool pool{base,base+3,base+1,base+2,10s,2s};
    std::array history{d::FakeIpHistoricalRange{base-4,base+1,40s},
                       d::FakeIpHistoricalRange{base+2,base+8,20s},
                       d::FakeIpHistoricalRange{base+7,base+10,30s},
                       d::FakeIpHistoricalRange{0,1,1s},
                       d::FakeIpHistoricalRange{std::numeric_limits<std::uint32_t>::max(),std::numeric_limits<std::uint32_t>::max(),1s}};
    auto next=d::update_fakeip_history(pool,history);
    if (!next || next->size()!=3 || (*next)[1].first!=base-4 || (*next)[1].last!=base+10 ||
        (*next)[1].protection!=40s) return 12;
    d::FakeIpRecoveryPool moved{base+20,base+23,base+21,base+21,2s,1s};
    auto later=d::update_fakeip_history(moved,*next);
    if (!later || later->size()!=4 || (*later)[1].protection!=40s || (*later)[2].first!=base+20 ||
        (*later)[2].protection!=3s || !d::recover_fakeip(moved,*later,5s,start)) return 13;
    auto raised=pool; raised.ttl=60s;
    auto retained=d::update_fakeip_history(raised,*next);
    if (!retained || (*retained)[1].protection!=62s) return 14;
    auto lowered=d::update_fakeip_history(pool,*retained);
    if (!lowered || (*lowered)[1].protection!=62s) return 14;
    auto result=d::recover_fakeip(pool,history,5s,start);
    if (!result || !(*result)->sealed()) return 1;
    auto& owner=**result;
    for (auto address:{0u,1u,base-4,base-1,base,base+3,base+4,base+10,std::numeric_limits<std::uint32_t>::max()})
        if (!owner.contains(address).value_or(false)) return 2;
    for (auto address:{2u,base-5,base+11,std::numeric_limits<std::uint32_t>::max()-1})
        if (owner.contains(address).value_or(true)) return 3;
    auto query=d::make_query(1,{"example.test",1});
    if (!query) return 4;
    auto early=owner.respond(base,*query,7,start+45s-1ns);
    if (early || early.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::quarantine}) return 5;
    auto response=owner.respond(base,*query,7,start+45s);
    if (!response || !(*response)->finish(true,start+45s)) return 6;
    auto reserved=owner.acquire(base+4,7,start+45s);
    if (reserved || reserved.error()!=d::FakeIpRegistryError::unknown) return 7;
    auto target=owner.acquire(base+1,7,start+45s);
    if (!target || !*target || (*target)->mapping().domain!="example.test" || !(*target)->release(start+45s)) return 8;
    auto invalid=history; invalid[0].first=base; invalid[0].last=base-1;
    if (d::recover_fakeip(pool,invalid,5s,start).error()!=d::FakeIpRecoveryError::invalid ||
        d::recover_fakeip(pool,history,-1s,start).error()!=d::FakeIpRecoveryError::invalid ||
        d::recover_fakeip(pool,history,std::chrono::seconds::max(),start).error()!=d::FakeIpRecoveryError::interval_overflow ||
        d::recover_fakeip(pool,history,5s,std::chrono::steady_clock::time_point::max()).error()!=d::FakeIpRecoveryError::registry) return 9;
    std::vector<d::FakeIpHistoricalRange> excessive(257,{0,1,1s});
    if (d::recover_fakeip(pool,excessive,0s,start).error()!=d::FakeIpRecoveryError::too_many_ranges ||
        d::update_fakeip_history(pool,excessive).error()!=d::FakeIpRecoveryError::too_many_ranges) return 10;
    std::vector<d::FakeIpHistoricalRange> full;
    for (std::uint32_t i=0;i<256;++i) full.push_back({i*2,i*2,1s});
    if (d::update_fakeip_history(pool,full).error()!=d::FakeIpRecoveryError::too_many_ranges) return 15;
    auto invalid_pool=pool; invalid_pool.alloc_last=invalid_pool.first+65536;
    if (d::update_fakeip_history(invalid_pool,{}).error()!=d::FakeIpRecoveryError::invalid ||
        d::update_fakeip_history(pool,invalid).error()!=d::FakeIpRecoveryError::invalid) return 16;
    auto cold=d::recover_fakeip(pool,{},0s,start);
    if (!cold || (*cold)->respond(base,*query,7,start+12s-1ns)) return 11;
    auto cold_response=(*cold)->respond(base,*query,7,start+12s);
    if (!cold_response || !(*cold_response)->finish(false,start+12s)) return 11;
    std::println("FakeIP recovery history union and quarantine passed");
}
