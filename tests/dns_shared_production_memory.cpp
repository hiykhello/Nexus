import std;
import dns.cache;
import dns.message;
import proxy;

namespace {
    auto require(bool condition,std::string_view message) -> void {
        if (!condition) throw std::runtime_error(std::string(message));
    }
    auto memory(std::string_view field) -> std::size_t {
        std::ifstream input("/proc/self/status");
        std::string line;
        while (std::getline(input,line)) if (line.starts_with(field)) {
            auto first=line.find_first_of("0123456789");
            std::size_t value=0;
            if (first==std::string::npos || std::from_chars(line.data()+first,line.data()+line.size(),value).ec!=std::errc{})
                throw std::runtime_error("invalid process memory field");
            return value;
        }
        throw std::runtime_error("missing process memory field");
    }
    auto name(unsigned group,unsigned index) -> std::string {
        auto result=std::format("g{:02}n{:04}.",group,index)+std::string(63,'a')+"."+
            std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(52,'d');
        require(result.size()==253,"incorrect maximum name size");
        return result;
    }
}

auto main() -> int {
    try {
        constexpr std::size_t groups=17,readers=258,per_group=256,budget=32*1024*1024;
        auto initial=memory("VmRSS:");
        proxy::SharedDnsGeneration generation(groups,readers);
        auto& cache=generation.cache();
        require(cache.supports_binding(groups-1,readers-1,1),"last production reader unavailable");
        std::vector<decltype(cache.reader(0))> claimed;
        claimed.reserve(readers);
        for (std::size_t i=0;i<readers;++i) claimed.push_back(cache.reader(i));
        dns::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
        std::size_t published=0;
        bool exhausted=false;
        for (unsigned group=0;group<groups && !exhausted;++group) {
            for (unsigned index=0;index<per_group;++index) {
                dns::CacheKey key{1,name(group,index),1};
                auto token=cache.begin_query(group,key);
                require(token.has_value(),"cache registration failed before the budget boundary");
                dns::AddressAnswer answer{key.name,std::vector<std::string>(16,key.name),
                    std::vector<dns::Address>(128,address),3600};
                auto result=cache.publish(group,key,std::move(answer),1000,*token);
                if (!result) {
                    require(result.error()==dns::CacheError::disabled,"unexpected publication error");
                    exhausted=true; break;
                }
                ++published;
                require(cache.charged_bytes()<=budget && cache.peak_charged_bytes()<=budget,"snapshot budget exceeded");
            }
        }
        auto after_entries=memory("VmRSS:");
        require(!exhausted && published==groups*per_group,"production membership capacity not filled");
        for (std::size_t group=0;group<groups;++group)
            require(cache.size(group)==per_group,"group membership capacity not filled");

        // A slow reader keeps the old full snapshot alive while the writer
        // replaces maximum-size answers. The byte budget must fail closed.
        std::binary_semaphore entered(0),release(0);
        std::exception_ptr reader_error;
        bool reader_rejected=false;
        std::jthread pinned([&] {
            try {
                auto result=cache.lookup_with_hook(0,{1,name(0,0),1},1000,claimed[0],[&] {
                    entered.release(); release.acquire();
                });
                reader_rejected=result && !*result;
            } catch (...) { reader_error=std::current_exception(); entered.release(); }
        });
        struct ReleaseReader {
            std::binary_semaphore& semaphore;
            bool armed=true;
            ~ReleaseReader() { if (armed) semaphore.release(); }
        } release_reader{release};
        entered.acquire();
        unsigned replacements=0;
        for (unsigned index=0;index<per_group;++index) {
            dns::CacheKey key{1,name(0,index),1};
            auto token=cache.begin_query(0,key);
            require(token.has_value(),"replacement registration failed before the budget boundary");
            dns::AddressAnswer answer{key.name,std::vector<std::string>(16,key.name),
                std::vector<dns::Address>(128,address),3600};
            auto result=cache.publish(0,key,std::move(answer),1000,*token);
            if (!result) {
                require(result.error()==dns::CacheError::disabled,"unexpected replacement error");
                exhausted=true; break;
            }
            ++replacements;
        }
        require(exhausted && replacements>0,"pinned snapshot did not reach the budget boundary");
        require(cache.charged_bytes()<=budget && cache.peak_charged_bytes()<=budget,"snapshot budget exceeded");
        release.release(); release_reader.armed=false; pinned.join();
        if (reader_error) std::rethrow_exception(reader_error);
        require(reader_rejected,"disabled cache returned a stale pinned answer");
        auto peak_charge=cache.peak_charged_bytes();
        // Clear also resets pending registrations after a fail-closed budget event.
        require(cache.clear(2000).has_value(),"cache clear failed");
        std::vector<dns::CacheToken> pending;
        pending.reserve(4096);
        for (unsigned i=0;i<4096;++i) {
            auto token=cache.begin_query(i%groups,2,name(i%groups,i),1);
            require(token.has_value(),"pending registration failed before limit");
            pending.push_back(*token);
        }
        auto after_pending=memory("VmRSS:");
        auto denied=cache.begin_query(0,2,name(0,4096),1);
        require(!denied && denied.error()==dns::CacheError::query_limit,"pending limit not enforced");
        for (auto token:pending) {
            auto canceled=cache.cancel_query(token);
            require(!canceled && canceled.error()==dns::CacheError::stale_query,"pending token not invalidated");
        }
        require(cache.clear(3000).has_value(),"cache did not recover after pending limit");
        auto retry=cache.begin_query(0,2,name(0,4096),1);
        require(retry && cache.cancel_query(*retry),"pending capacity did not recover");
        std::println("published={} replacements={} budget_exhausted={} peak_charged_bytes={} initial_rss_kib={} entries_rss_kib={} pending_rss_kib={} hwm_kib={}",
            published,replacements,exhausted,peak_charge,initial,after_entries,after_pending,memory("VmHWM:"));
    } catch (std::exception const& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
