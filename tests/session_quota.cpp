import std;
import relay.session_quota;
using relay::SessionQuota;

auto main() -> int {
    SessionQuota quota(7);
    std::atomic<unsigned> inside=0, peak=0, acquired=0;
    std::barrier sync(16);
    std::vector<std::thread> threads;
    for (int i=0;i<16;++i) threads.emplace_back([&] {
        sync.arrive_and_wait();
        for (int n=0;n<4000;++n) {
            auto lease=quota.try_acquire();
            if (!lease) { std::this_thread::yield(); continue; }
            ++acquired;
            auto current=inside.fetch_add(1)+1;
            auto old=peak.load();
            while (old<current && !peak.compare_exchange_weak(old,current)) {}
            std::this_thread::yield();
            --inside;
        }
    });
    for (auto& thread : threads) thread.join();
    if (!acquired || peak>7 || inside || quota.used()) return 1;
    auto first=quota.try_acquire();
    auto second=quota.try_acquire();
    if (!first || !second || quota.used()!=2) return 2;
    *first=std::move(*second);
    if (quota.used()!=1) return 3;
    first.reset(); second.reset();
    if (quota.used()) return 4;
    SessionQuota zero(0);
    if (zero.try_acquire()) return 5;
    std::optional<SessionQuota::Lease> survives;
    { SessionQuota temporary(1); survives=temporary.try_acquire(); }
    survives.reset();
    SessionQuota shared(3);
    auto transport=shared.try_acquire();
    auto child=transport->try_acquire();
    auto grandchild=child->try_acquire();
    if (!transport || !child || !grandchild || transport->try_acquire() || shared.try_acquire() || shared.used()!=3) return 6;
    transport.reset();
    if (shared.used()!=2) return 7;
    auto sibling=child->try_acquire();
    if (!sibling || shared.used()!=3 || grandchild->try_acquire()) return 8;
    child.reset(); grandchild.reset(); sibling.reset();
    if (shared.used()) return 9;
    std::println("concurrent session quota and lease lifetime passed");
}
