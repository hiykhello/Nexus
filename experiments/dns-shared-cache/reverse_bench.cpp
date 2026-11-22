import std;
import dns.message;
import dns.reverse;

int main() {
    using namespace dns;
    constexpr unsigned capacity=4096, iterations=50000;
    auto address=[](unsigned i) { return Address{{10,static_cast<std::uint8_t>(i>>16),
                                                static_cast<std::uint8_t>(i>>8),static_cast<std::uint8_t>(i)},4}; };
    ReverseCache cache(capacity,1,{0x12345678,0x87654321});
    auto token=cache.token();
    for (unsigned i=0;i<capacity;++i) {
        auto ip=address(i);
        if (cache.record(1,"bench.example",std::span(&ip,1),600,1000,token)!=ReverseRecord::stored) return 1;
    }
    auto run=[&](bool hits) {
        auto start=std::chrono::steady_clock::now();
        for (unsigned i=0;i<iterations;++i) {
            auto ip=address(hits ? i%capacity : capacity+i%capacity);
            auto result=cache.record(1,"bench.example",std::span(&ip,1),600,1000,token);
            if (result!=(hits ? ReverseRecord::stored : ReverseRecord::unavailable)) std::terminate();
        }
        return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count()/iterations;
    };
    std::cout << "capacity=" << capacity << " storage_bytes=" << cache.storage_bytes()
              << " update_ns=" << run(true) << " full_miss_ns=" << run(false) << '\n';
}
