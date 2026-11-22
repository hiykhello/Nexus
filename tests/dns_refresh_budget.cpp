import std;
import dns.cache;

namespace d=dns;

int main() {
    constexpr unsigned workers=8,rounds=100;
    d::detail::RefreshBudget budget(4);
    std::barrier phase(workers+1);
    std::atomic<unsigned> acquired=0;
    std::vector<std::thread> threads;
    for (unsigned index=0;index<workers;++index) threads.emplace_back([&,index] {
        d::CacheKey distinct{1,"worker-"+std::to_string(index)+".test",1};
        d::CacheKey common{1,"common.test",1};
        for (unsigned round=0;round<rounds;++round) {
            phase.arrive_and_wait();
            auto lease=budget.acquire(round%2 ? common : distinct);
            if (lease) ++acquired;
            phase.arrive_and_wait();
            phase.arrive_and_wait();
            lease.reset();
            phase.arrive_and_wait();
        }
    });
    bool valid=true;
    for (unsigned round=0;round<rounds;++round) {
        acquired=0;
        phase.arrive_and_wait();
        phase.arrive_and_wait();
        auto expected=round%2 ? 1U : 4U;
        valid=valid && acquired==expected && budget.active()==expected;
        phase.arrive_and_wait();
        phase.arrive_and_wait();
        valid=valid && budget.active()==0;
    }
    for (auto& thread:threads) thread.join();
    if (!valid) return 1;
    d::detail::RefreshBudget empty(0);
    if (empty.acquire({1,"zero.test",1})) return 2;
    auto first=budget.acquire({1,"same.test",1});
    auto second=budget.acquire({2,"same.test",1});
    auto third=budget.acquire({1,"same.test",28});
    if (!first || !second || !third || budget.active()!=3 || budget.acquire({1,"same.test",1})) return 3;
    first=std::move(second);
    if (budget.active()!=2) return 4;
    second.reset();
    if (budget.active()!=2) return 4;
    first.reset(); third.reset();
    if (budget.active()!=0) return 5;
    using namespace std::chrono_literals;
    auto retry=budget.acquire({1,"retry.test",1});
    if (!retry) return 6;
    retry->delay_until(std::chrono::steady_clock::now()+100ms);
    retry.reset();
    if (budget.active()!=0 || budget.acquire({1,"retry.test",1})) return 7;
    std::this_thread::sleep_for(120ms);
    if (!budget.acquire({1,"retry.test",1})) return 8;
    d::detail::RefreshBudget small(1);
    auto old=small.acquire({1,"old.test",1});
    if (!old) return 9;
    old->delay_until(std::chrono::steady_clock::now()+10s);
    old.reset();
    // A bounded backoff must not prevent unrelated work from using capacity.
    auto replacement=small.acquire({1,"new.test",1});
    if (!replacement || small.active()!=1) return 10;
    replacement.reset();
    if (!small.acquire({1,"old.test",1})) return 11;
    if (budget.acquire({1,std::string(255,'a'),1}) || budget.active()) return 12;
    std::puts("DNS refresh budget bounds and deduplicates concurrent leases");
}
