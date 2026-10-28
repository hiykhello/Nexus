import std;
import nexus.dns.fakeip;
import nexus.dns.fakeip_target;
import nexus.dns.fakeip_response;
import nexus.dns.message;
namespace d=nexus::dns;
using namespace std::chrono_literals;
int main() {
    auto t=std::chrono::steady_clock::time_point{};
    auto pool=d::FakeIpPool::create(0xc6120001,0xc6120001,10s,2s);
    if (!pool) return 1;
    auto outside=d::acquire_fakeip_target(**pool,0x7f000001,42,t);
    if (!outside || *outside) return 2;
    if (d::acquire_fakeip_target(**pool,0xc6120001,42,t).error()!=d::FakeIpTargetError::unknown) return 3;
    d::Question q{"example.com",1};
    auto query=d::make_query(123,q);
    if (!query) return 4;
    auto response=d::fakeip_response(**pool,*query,42,t);
    if (!response || !(*response)->finish(true,t)) return 5;
    if (d::acquire_fakeip_target(**pool,0xc6120001,43,t).error()!=d::FakeIpTargetError::wrong_view) return 6;
    auto target=d::acquire_fakeip_target(**pool,0xc6120001,42,t);
    if (!target || !*target || (*target)->mapping().domain!="example.com" || (*target)->mapping().view!=42) return 7;
    auto second=d::acquire_fakeip_target(**pool,0xc6120001,42,t);
    if (!second || !*second || !(*target)->release(t+12s)) return 8;
    if ((**pool).publish("another.example",42,t+12s).error()!=d::FakeIpError::full) return 9;
    if ((*second)->release(t+11s).error()!=d::FakeIpTargetError::clock ||
        (**pool).publish("another.example",42,t+12s).error()!=d::FakeIpError::full) return 10;
    if (!(*second)->release(t+12s) || (*second)->release(t+12s).error()!=d::FakeIpTargetError::stale) return 11;
    auto reused=(**pool).publish("another.example",42,t+12s);
    if (!reused || reused->address!=0xc6120001 || reused->generation==(*target)->mapping().lease.generation) return 12;
    auto mapped=d::acquire_fakeip_target(**pool,0xc6120001,42,t+12s);
    if (!mapped || !*mapped || (*mapped)->mapping().domain!="another.example") return 13;
    // Forgotten release fails closed even after TTL expires.
    mapped->reset();
    if ((**pool).publish("third.example",42,t+30s).error()!=d::FakeIpError::full) return 14;
    std::println("FakeIP target ownership and fail-closed lookup passed");
}
