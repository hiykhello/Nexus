import std;
import dns.cache;
import dns.message;
namespace d=dns;
int main() {
    d::AddressCache cache(256,10000,true);
    d::CacheKey key{1,"shared.test",1};
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
    d::AddressAnswer answer{key.name,{key.name},{address},60};
    auto older=cache.begin_query(key), newer=cache.begin_query(key);
    if (!older || !newer || !cache.publish(key,answer,1000,*newer) || cache.publish(key,answer,1000,*older)) return 1;
    std::atomic<bool> failed=false;
    std::vector<std::thread> readers;
    for (int i=0;i<8;++i) readers.emplace_back([&] {
        for (int j=0;j<10000;++j) {
            auto hit=cache.lookup(key,1000);
            if (!hit || !*hit || (**hit).addresses[0].bytes[3]!=1) failed=true;
        }
    });
    for (auto& reader:readers) reader.join();
    if (failed || cache.size()!=1) return 2;
    auto stale=cache.begin_query(key);
    if (!stale || !cache.clear(2000) || cache.publish(key,answer,1000,*stale)) return 3;
    if (auto hit=cache.lookup(key,1000); !hit || *hit) return 4;
    std::puts("shared DNS cache concurrent hits, query order and clear barrier passed");
}
