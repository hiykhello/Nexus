import std;
import dns.fakeip;
using namespace std::chrono_literals;
namespace d=dns;
int main() {
    using Clock=std::chrono::steady_clock;
    auto t=Clock::time_point{};
    if (d::FakeIpPool::create(2,1,60s,5s) || d::FakeIpPool::create(0,65536,60s,5s) ||
        d::FakeIpPool::create(0,0,0s,5s)) return 1;
    auto pool=d::FakeIpPool::create(100,101,60s,5s);
    auto other=d::FakeIpPool::create(100,101,60s,5s);
    if (!pool || !other) return 2;
    auto& p=**pool;
    if (p.publish("a..b",1,t).error()!=d::FakeIpError::invalid_name ||
        p.publish("é.example",1,t).error()!=d::FakeIpError::invalid_name) return 3;
    auto a=p.publish("Example.COM.",1,t), same=p.publish("example.com",1,t+10s);
    auto b=p.publish("example.com",2,t+10s);
    if (!a || !same || !b || *a!=*same || a->address==b->address) return 4;
    auto found=p.lookup(a->address,t+10s);
    if (!found || !*found || (*found)->domain!="example.com" || (*found)->view!=1 || (*found)->lease!=*a) return 5;
    if (p.pin(*a,t+10s).has_value()==false || (**other).pin(*a,t).error()!=d::FakeIpError::stale ||
        p.publish("new.example",1,t+74s).error()!=d::FakeIpError::full) return 6;
    auto c=p.publish("new.example",1,t+75s);
    if (!c || c->address!=b->address || p.pin(*b,t+75s).error()!=d::FakeIpError::stale) return 7;
    if (p.unpin(*a,t+75s).has_value()==false || p.unpin(*a,t+75s).error()!=d::FakeIpError::pinned) return 8;
    auto fresh=p.publish("another.example",1,t+75s);
    if (!fresh || fresh->address!=a->address || p.pin(*a,t+75s).error()!=d::FakeIpError::stale) return 9;
    if (p.lookup(99,t+75s).value().has_value() || p.lookup(100,t+74s).error()!=d::FakeIpError::time_reversed) return 10;
    auto limit=d::FakeIpPool::create(0xffffffff,0xffffffff,1s,0s);
    if (!limit || (**limit).publish("a",0,Clock::time_point::max()).error()!=d::FakeIpError::time_overflow) return 11;
    std::println("FakeIP IPv4 pool safety tests passed");
}
