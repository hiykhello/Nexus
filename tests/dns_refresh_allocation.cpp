#include <cstdlib>
#include <new>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.corosio_cached;

namespace { int remaining=-1; }
void* operator new(std::size_t size) {
    if (remaining>0 && --remaining==0) { remaining=-1; throw std::bad_alloc(); }
    if (auto* pointer=std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer,std::size_t) noexcept { std::free(pointer); }
namespace d=dns;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;

auto budget_failure_preserves_backoff() -> bool {
    d::detail::RefreshBudget budget(1);
    d::CacheKey old{1,"old-refresh-long-name.example.test",1};
    d::CacheKey next{1,"new-refresh-long-name.example.test",1};
    auto lease=budget.acquire(old);
    if (!lease) return false;
    lease->delay_until(Clock::now()+10s); lease.reset();
    bool caught=false;
    remaining=1;
    try { (void)budget.acquire(next); } catch (std::bad_alloc const&) { caught=true; }
    remaining=-1;
    if (!caught || budget.active() || budget.acquire(old)) return false;
    return budget.acquire(next).has_value();
}

int test(bool uring,bool shared_budget) {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if (uring) return 77; io::io_context context(io::epoll);
#endif
    {
        d::AddressCache warm_cache(1, 10000);
        d::Address addr{}; addr.size=4; addr.bytes[0]=127; addr.bytes[3]=1;
        d::CacheKey warm_key{1, "refresh-warm-trampoline.example.test", 1};
        d::AddressAnswer warm_ans{warm_key.name, {warm_key.name}, {addr}, 1};
        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        if (auto tok=warm_cache.begin_query(warm_key); tok && warm_cache.publish(warm_key, std::move(warm_ans), now-1200, *tok)) {
            d::detail::RefreshOwner warm_owner(context, warm_cache, 1, 1s, 100ms, nullptr);
            (void)warm_owner.start(warm_key, io::endpoint(io::ipv4_address::loopback(), 9));
            warm_owner.stop();
            context.restart(); (void)context.run_for(100ms);
        }
    }
    unsigned faults=0;
    for (int position=1;position<=50;++position) {
        d::AddressCache cache(1,10000);
        d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
        d::CacheKey key{1,"refresh-allocation-budget.example.test",1};
        d::AddressAnswer answer{key.name,{key.name},{address},1};
        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        auto token=cache.begin_query(key);
        if (!token || !cache.publish(key,std::move(answer),now-1200,*token)) return 1;
        d::detail::RefreshBudget budget(1);
        d::detail::RefreshOwner owner(context,cache,1,1s,100ms,shared_budget ? &budget : nullptr);
        io::endpoint upstream(io::ipv4_address::loopback(),9);
        bool caught=false,started=false;
        remaining=position;
        try { started=owner.start(key,upstream); } catch (std::bad_alloc const&) { caught=true; }
        remaining=-1;
        if (caught) ++faults;
        else if (!started) return 2;
        if (shared_budget && budget.active()!=(started ? 1U : 0U)) return 7;
        owner.stop();
        context.restart(); (void)context.run_for(100ms);
        if (!owner.drained() || budget.active()) return 3;
        auto current=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        auto stale=cache.lookup_stale(key,current);
        if (!stale || !*stale || (**stale).answer.addresses[0].bytes[3]!=1) return 4;
        auto retry=cache.begin_refresh(key,current,1);
        if (!retry || !*retry || !cache.cancel_query(**retry)) return 5;
        if (!caught) break;
    }
    std::printf("%s %s: %u refresh start allocation failures recovered\n",uring ? "io_uring" : "epoll",
                shared_budget ? "shared budget" : "local",faults);
    if (faults<3) return 6;
    return 0;
}
int main() {
    if (!budget_failure_preserves_backoff()) return 8;
    for (bool uring:{false,true}) {
        for (bool shared_budget:{false,true}) {
            auto result=test(uring,shared_budget); if (result==77) continue;
            if (result) { std::fprintf(stderr,"refresh allocation %s: %d\n",uring ? "io_uring" : "epoll",result); return result; }
        }
    }
}
