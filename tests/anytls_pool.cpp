import std;
import anytls.pool;

namespace {
    struct Connection {
        static inline unsigned destroyed=0;
        unsigned id;
        bool good=true,canceled=false,done=false;
        explicit Connection(unsigned value) : id(value) {}
        ~Connection() { ++destroyed; }
        auto usable() const noexcept -> bool { return good && !canceled; }
        auto cancel() noexcept -> void { canceled=true; }
        auto drained() const noexcept -> bool { return done; }
    };
}
auto main() -> int {
    using namespace anytls;
    using namespace std::chrono_literals;
    ClientPool<Connection> pool({.max_sessions=3,.min_idle=1,.idle_timeout=100ms});
    auto now=PoolClock::now();
    if (pool.prewarm_needed()!=1 || pool.acquire() || !pool.drained()) return 1;
    auto first_creation=pool.reserve();
    if (!first_creation || pool.prewarm_needed()) return 2;
    auto first=first_creation->commit(std::make_unique<Connection>(1),now);
    if (!first || first->connection().id!=1 || pool.size()!=1 || pool.idle_count() || pool.prewarm_needed()!=1) return 3;
    first->reset(now);
    auto second_creation=pool.reserve(); if (!second_creation) return 4;
    auto second=second_creation->commit(std::make_unique<Connection>(2),now); if (!second) return 5;
    second->reset(now);
    auto newest=pool.acquire();
    if (!newest || newest->connection().id!=2 || newest->sequence()!=2) return 6;
    auto older=pool.acquire();
    if (!older || older->connection().id!=1 || older->sequence()!=1 || pool.acquire()) return 7;
    auto pending=pool.reserve();
    if (!pending || pool.reserve()) return 8;
    pending->reset();
    if (!pool.reserve()) return 9;
    newest->reset(now); older->reset(now+1ms);
    // Creation sequence takes precedence over idle release order.
    auto reused=pool.acquire();
    if (!reused || reused->connection().id!=2) return 10;
    reused->reset(now);
    auto stale=pool.acquire(); if (!stale) return 11;
    auto& failed=stale->connection(); failed.good=false; stale->reset(now);
    pool.reap(now+200ms);
    if (!failed.canceled || pool.idle_count()!=1 || pool.size()!=2 || Connection::destroyed) return 12;
    failed.done=true; pool.reap(now+200ms);
    if (pool.size()!=1 || Connection::destroyed!=1 || pool.prewarm_needed()) return 13;
    auto held=pool.acquire(); if (!held) return 14;
    held->connection().done=true;
    auto creation=pool.reserve(); if (!creation) return 15;
    pool.stop();
    if (pool.acquire() || pool.reserve() || !held->connection().canceled || pool.drained()) return 16;
    creation->reset(); held->reset(now); pool.reap(now);
    if (!pool.drained() || pool.size() || Connection::destroyed!=2 || pool.prewarm_needed()) return 17;
    std::println("AnyTLS latest-session reuse, bounded creation, minimum idle, retirement/drain and stop ownership passed");
}
