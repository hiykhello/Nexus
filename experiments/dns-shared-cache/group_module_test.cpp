import std;
import dns.message;
import dns.cache;
import dns.shared_cache;

int main() {
    namespace d=dns;
    std::array<std::size_t,2> capacities{4,4};
    dns_hp_experiment::GroupSnapshot cache(capacities,1,5000,1024*1024);
    dns_hp_experiment::GroupBinding first(cache,0),second(cache,1);
    auto reader=cache.reader(0);
    d::CacheKey key{1,"module.example.test",1};
    d::Address address{}; address.size=4; address.bytes[3]=7;
    auto token=first.begin_query(key);
    if (!token || !first.publish(key,d::AddressAnswer{key.name,{key.name},{address},30},1000,*token)) return 1;
    auto hit=second.lookup(key,1000,reader);
    if (!hit || !*hit || (**hit).addresses.size()!=1 || (**hit).addresses[0].bytes[3]!=7) return 2;
    std::puts("experimental group module: cross-group answer passed");
}
