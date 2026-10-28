import std;
import nexus.dns.fakeip_shared;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
import nexus.dns.message;
using namespace std::chrono_literals;
namespace d=nexus::dns;
auto main() -> int {
    constexpr std::uint32_t base=0xc6120000;
    auto t=std::chrono::steady_clock::time_point{};
    auto owner=std::make_unique<d::FakeIpShared>(1);
    auto query=d::make_query(1,{"example.com",1});
    auto other=d::make_query(2,{"other.example",1});
    if (!query || !other || !owner->add(base,base+3,base+1,base+1,10s,2s)) return 1;
    auto unsealed=owner->respond(base,*query,7,t);
    if (unsealed || unsealed.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::unsealed} ||
        owner->contains(base).error()!=d::FakeIpRegistryError::unsealed || !owner->seal() ||
        owner->add(base+4,base+5,base+4,base+4,10s,2s).error()!=d::FakeIpRegistryError::sealed) return 13;
    auto initial=owner->respond(base,*query,7,t);
    if (!initial || !(*initial)->finish(true,t)) return 2;
    std::barrier start(8);
    std::atomic<bool> failed=false;
    std::vector<std::thread> workers;
    for (int i=0;i<8;++i) workers.emplace_back([&] {
        start.arrive_and_wait();
        for (int j=0;j<100;++j) {
            auto response=owner->respond(base,*query,7,t);
            auto target=owner->acquire(base+1,7,t);
            if (!response || !target || !*target || (*target)->mapping().domain!="example.com" ||
                !(*response)->finish(true,t) || !(*target)->release(t)) { failed=true; return; }
        }
    });
    for (auto& worker:workers) worker.join();
    if (failed || !owner->contains(base).value_or(false) || owner->contains(base+4).value_or(true)) return 3;
    auto pending=owner->respond(base,*query,7,t);
    auto held=owner->acquire(base+1,7,t);
    if (!pending || !held || !*held) return 4;
    auto full=owner->respond(base,*other,7,t+12s);
    if (full || full.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::full}) return 5;
    if (!owner->retire(base)) return 6;
    owner.reset(); // Both handles retain the registry and pool.
    if ((*pending)->wire().empty() || !(*pending)->finish(true,t+12s) ||
        !(*held)->release(t+12s)) return 7;
    d::FakeIpShared live(1);
    if (!live.add(base,base+3,base+1,base+1,10s,2s) || !live.seal()) return 8;
    auto published=live.respond(base,*query,7);
    if (!published || !(*published)->finish(true)) return 9;
    std::barrier live_start(8);
    failed=false;
    workers.clear();
    for (int i=0;i<8;++i) workers.emplace_back([&] {
        live_start.arrive_and_wait();
        for (int j=0;j<1000;++j) {
            auto response=live.respond(base,*query,7);
            auto target=live.acquire(base+1,7);
            if (!response || !target || !*target || !(*response)->finish(true) || !(*target)->release()) {
                failed=true; return;
            }
        }
    });
    for (auto& worker:workers) worker.join();
    if (failed) return 10;
    d::FakeIpShared quarantine(1);
    if (!quarantine.add_quarantined(base,base+3,base+1,base+1,10s,2s,30s) || !quarantine.seal()) return 11;
    auto denied=quarantine.respond(base,*query,7);
    if (denied || denied.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpRegistryError::quarantine}) return 12;
    d::FakeIpShared race(2);
    if (race.seal().error()!=d::FakeIpRegistryError::invalid || !race.add(base,base+3,base+1,base+1,10s,2s)) return 14;
    std::barrier race_start(2);
    std::atomic<int> added=0;
    std::thread adder([&] {
        race_start.arrive_and_wait();
        auto result=race.add(base+4,base+7,base+5,base+5,10s,2s);
        added=result ? 1 : result.error()==d::FakeIpRegistryError::sealed ? 2 : 3;
    });
    race_start.arrive_and_wait();
    auto sealed=race.seal();
    adder.join();
    if (!sealed || added==3 || !added || race.contains(base+5).value_or(added!=1)!=(added==1)) return 15;
    d::FakeIpShared history(2);
    if (!history.reserve(0x0a000000,0x0affffff) ||
        history.reserve(0x0affffff,0x0b000000).error()!=d::FakeIpRegistryError::overlap ||
        !history.add(base,base+3,base+1,base+1,10s,2s) || !history.seal() ||
        history.reserve(0x0b000000,0x0bffffff).error()!=d::FakeIpRegistryError::sealed) return 16;
    for (auto address:{0x0a000000u,0x0a123456u,0x0affffffu}) {
        auto is_reserved=history.contains(address);
        auto target=history.acquire(address,7);
        if (!is_reserved || !*is_reserved || target || target.error()!=d::FakeIpRegistryError::unknown) return 17;
    }
    if (history.contains(0x0b000000).value_or(true)) return 18;
    std::println("FakeIP shared owner concurrent access and handle lifetime passed");
}
