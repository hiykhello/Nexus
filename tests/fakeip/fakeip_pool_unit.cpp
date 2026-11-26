import std;
import dns.fakeip;

namespace {
    using Clock = std::chrono::steady_clock;
    using namespace std::chrono_literals;

    auto check(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto case_and_view_isolation() -> void {
        constexpr std::uint32_t base = 0xc6120000u;
        auto pool = dns::FakeIpPool::create(base, base + 7, 10s, 0s);
        check(pool.has_value(), "create pool");
        auto t0 = Clock::now();
        auto a = (*pool)->publish("Example.COM.", 1, t0);
        check(a.has_value(), "publish first");
        auto a_hit = (*pool)->publish("example.com", 1, t0 + 1s);
        check(a_hit && *a_hit == *a, "case-insensitive & trailing-dot O(1) hit");
        auto b = (*pool)->publish("example.com", 2, t0 + 1s);
        check(b && b->address != a->address, "distinct views allocate distinct FakeIPs");
        auto b_hit = (*pool)->publish("EXAMPLE.COM", 2, t0 + 2s);
        check(b_hit && *b_hit == *b, "view 2 O(1) hit");
        auto invalid = (*pool)->publish("bad_domain..test", 1, t0 + 2s);
        check(!invalid && invalid.error() == dns::FakeIpError::invalid_name, "invalid name rejected");
    }

    auto eviction_and_backward_shift_invariants() -> void {
        constexpr std::uint32_t base = 0xc6120100u;
        auto pool_exp = dns::FakeIpPool::create(base, base + 15, 1s, 0s);
        check(pool_exp.has_value(), "create eviction pool");
        auto& pool = **pool_exp;
        auto t = Clock::now();
        std::vector<dns::FakeIpLease> initial;
        for (int i = 0; i < 16; ++i) {
            auto lease = pool.publish("d" + std::to_string(i) + ".test", 7, t);
            check(lease.has_value(), "fill slot");
            initial.push_back(*lease);
        }
        auto full = pool.publish("overflow.test", 7, t);
        check(!full && full.error() == dns::FakeIpError::full, "full pool rejects new domain");
        check(pool.pin(initial[3], t).has_value(), "pin d3.test");

        // Advance past ttl+grace so 15 unpinned slots become reusable and get evicted.
        t += 2s;
        std::vector<dns::FakeIpLease> replaced;
        for (int i = 0; i < 15; ++i) {
            auto lease = pool.publish("n" + std::to_string(i) + ".test", 7, t);
            check(lease.has_value(), "evict unpinned slot");
            check(lease->address != initial[3].address, "pinned slot not evicted");
            replaced.push_back(*lease);
        }
        // Pinned entry and all 15 replacements must still hit in O(1) forward index.
        auto d3_hit = pool.publish("D3.TEST.", 7, t);
        check(d3_hit && *d3_hit == initial[3], "pinned slot survives backward-shift erasures");
        for (int i = 0; i < 15; ++i) {
            auto hit = pool.publish("n" + std::to_string(i) + ".test", 7, t);
            check(hit && *hit == replaced[i], "replacement hits forward index");
            auto rev = pool.lookup(replaced[i].address, t);
            check(rev && *rev && (*rev)->domain == "n" + std::to_string(i) + ".test", "reverse matches forward");
        }
        // Unpin d3, advance time, and verify evicted d0 gets a new generation.
        check(pool.unpin(initial[3], t).has_value(), "unpin d3");
        t += 2s;
        auto d0_reborn = pool.publish("d0.test", 7, t);
        check(d0_reborn && d0_reborn->generation > initial[0].generation, "evicted domain removed from forward index");

        // Heavy churn on a small pool (8 slots, 200 rounds) to stress linear-probe backward shift.
        auto small_exp = dns::FakeIpPool::create(0xc6120200u, 0xc6120207u, 1s, 0s);
        check(small_exp.has_value(), "create small churn pool");
        auto& small = **small_exp;
        std::array<std::string, 8> live_names{};
        std::array<dns::FakeIpLease, 8> live_leases{};
        for (int round = 0; round < 200; ++round) {
            t += 2s;
            for (int i = 0; i < 8; ++i) {
                auto name = "r" + std::to_string(round) + "-s" + std::to_string(i) + ".churn.test";
                auto lease = small.publish(name, static_cast<std::uint64_t>(round % 3), t);
                check(lease.has_value(), "churn publish");
                live_names[i] = name;
                live_leases[i] = *lease;
            }
            for (int i = 0; i < 8; ++i) {
                auto hit = small.publish(live_names[i], static_cast<std::uint64_t>(round % 3), t);
                check(hit && *hit == live_leases[i], "churn forward hit invariant");
            }
        }
    }

    auto restore_sync() -> void {
        constexpr std::uint32_t base = 0xc6120300u;
        auto pool_exp = dns::FakeIpPool::create(base, base + 3, 1s, 0s);
        check(pool_exp.has_value(), "create restore pool");
        auto& pool = **pool_exp;
        check(pool.restore(base + 2, 5, "restored.test"), "restore mapping");
        check(!pool.restore(base + 2, 5, "dup.test"), "reject duplicate restore slot");
        auto t = Clock::now();
        auto hit = pool.publish("RESTORED.TEST.", 5, t);
        check(hit && hit->address == base + 2 && hit->generation == 1, "restored mapping indexed for O(1) hit");
        t += 2s;
        for (int i = 0; i < 4; ++i) {
            auto lease = pool.publish("fresh" + std::to_string(i) + ".test", 5, t);
            check(lease.has_value(), "evict restored mapping after expiry");
        }
        t += 2s;
        auto republished = pool.publish("restored.test", 5, t);
        check(republished && republished->generation > 1, "evicted restored mapping cleanly cleared from index");
    }
}

int main() {
    case_and_view_isolation();
    eviction_and_backward_shift_invariants();
    restore_sync();
    std::cout << "PASS FakeIpPool O(1) forward hash index, backward-shift eviction, view isolation and restore sync\n";
}
