import std;
import nexus.dns.fakeip;
import nexus.dns.fakeip_target;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
import nexus.dns.message;
namespace d=nexus::dns;
using namespace std::chrono_literals;
int main() {
    auto t=std::chrono::steady_clock::time_point{};
    constexpr std::uint32_t base=0xc6120000;
    d::FakeIpRegistry registry(3);
    auto pool=d::FakeIpPool::create(base+1,base+2,10s,2s);
    if (!pool) return 1;
    auto added=registry.add(base,base+3,std::move(*pool));
    if (!added) return 2;
    auto other=d::FakeIpPool::create(base+5,base+5,10s,2s);
    if (!other) return 3;
    if (registry.add(base+6,base+7,std::move(*other)).error()!=d::FakeIpRegistryError::invalid) return 4;
    if (registry.add(base+3,base+4,nullptr).error()!=d::FakeIpRegistryError::overlap) return 5;
    if (registry.add(base+4,base+3,nullptr).error()!=d::FakeIpRegistryError::invalid) return 6;
    if (!registry.add(base+4,base+4,nullptr)) return 7;
    auto second=d::FakeIpPool::create(base+5,base+5,10s,2s);
    if (!second) return 8;
    auto added2=registry.add(base+5,base+6,std::move(*second));
    if (!added2 || registry.add(base+7,base+7,nullptr).error()!=d::FakeIpRegistryError::full) return 9;
    auto outside=registry.acquire(base+7,1,t);
    if (!outside || *outside) return 10;
    for (auto address:{base,base+1,base+3,base+4,base+6}) {
        auto result=registry.acquire(address,1,t);
        if (result || result.error()!=d::FakeIpRegistryError::unknown) return 11;
    }
    auto query=d::make_query(1,{"example.com",1});
    auto query2=d::make_query(2,{"other.example",1});
    if (!query || !query2) return 12;
    auto response=registry.respond(base,*query,1,t);
    auto response2=registry.respond(base+5,*query2,2,t);
    if (!response || !response2) return 12;
    auto wrong=registry.acquire(base+1,2,t);
    if (wrong || wrong.error()!=d::FakeIpRegistryError::wrong_view) return 13;
    auto target=registry.acquire(base+1,1,t);
    auto target2=registry.acquire(base+5,2,t);
    if (!target || !*target || (*target)->mapping().domain!="example.com" ||
        !target2 || !*target2 || (*target2)->mapping().domain!="other.example") return 14;
    if (!registry.retire(base) || registry.retire(base).error()!=d::FakeIpRegistryError::inactive ||
        registry.retire(base+7).error()!=d::FakeIpRegistryError::missing) return 15;
    auto retired=registry.acquire(base+1,1,t);
    if (retired || retired.error()!=d::FakeIpRegistryError::unknown ||
        registry.add(base,base+3,nullptr).error()!=d::FakeIpRegistryError::overlap) return 16;
    auto denied=registry.respond(base,*query,1,t);
    auto absent=registry.respond(base+7,*query,1,t);
    auto malformed=registry.respond(base+5,std::span<std::uint8_t const>{},2,t);
    if (denied || denied.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::inactive} ||
        absent || absent.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::missing} ||
        malformed || malformed.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::malformed}) return 19;
    if (!(*response)->finish(true,t+12s) || !(*response2)->finish(false,t+12s) ||
        !(*target)->release(t+12s) || !(*target2)->release(t+12s)) return 17;
    auto clock=registry.acquire(base+5,2,t+11s);
    if (clock || clock.error()!=d::FakeIpRegistryError::clock) return 18;
    d::FakeIpRegistry restart(1);
    if (restart.add_quarantined(base,base+3,base+1,base+2,10s,2s,t,0s).error()!=d::FakeIpRegistryError::invalid ||
        restart.add_quarantined(base,base+3,base+1,base+2,10s,2s,t,12s-1ns).error()!=d::FakeIpRegistryError::invalid ||
        restart.add_quarantined(base,base+3,base+1,base+2,10s,2s,
            std::chrono::steady_clock::time_point::max(),12s).error()!=d::FakeIpRegistryError::invalid ||
        !restart.add_quarantined(base,base+3,base+1,base+2,10s,2s,t,30s)) return 20;
    d::FakeIpRegistry minimum(1);
    if (!minimum.add_quarantined(base,base+3,base+1,base+2,10s,2s,t,12s)) return 24;
    auto before_minimum=minimum.respond(base,*query,1,t+12s-1ns);
    if (before_minimum || before_minimum.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::quarantine}) return 25;
    auto at_minimum=minimum.respond(base,*query,1,t+12s);
    if (!at_minimum || !(*at_minimum)->finish(false,t+12s)) return 26;
    auto early=restart.respond(base,*query,1,t+29s);
    auto reversed=restart.respond(base,*query,1,t-1s);
    auto unknown=restart.acquire(base+1,1,t+29s);
    if (early || early.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::quarantine} ||
        reversed || reversed.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::clock} ||
        unknown || unknown.error()!=d::FakeIpRegistryError::unknown) return 21;
    auto resumed=restart.respond(base,*query,1,t+30s);
    if (!resumed) return 22;
    auto fresh=restart.acquire(base+1,1,t+30s);
    if (!fresh || !*fresh || (*fresh)->mapping().domain!="example.com" ||
        !(*resumed)->finish(true,t+30s) || !(*fresh)->release(t+30s)) return 23;
    std::println("FakeIP registry ranges and target lifetime passed");
}
