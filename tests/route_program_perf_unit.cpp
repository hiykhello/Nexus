import std;
import rules;

namespace {
    std::atomic<bool> g_deny_alloc{false};
    std::atomic<std::size_t> g_alloc_count{0};
}
void* operator new(std::size_t size) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    if (g_deny_alloc.load(std::memory_order_relaxed)) throw std::bad_alloc{};
    if (auto* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

namespace {
    using namespace ::rules;
    unsigned g_failures = 0;

    auto check(bool ok, std::string_view label) -> void {
        if (!ok) {
            ++g_failures;
            std::cerr << "FAIL [route_program_perf]: " << label << '\n';
        }
    }

    auto v4_addr(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> ProgramAddress {
        return ProgramAddress{{a, b, c, d}, 4};
    }

    auto v4_mapped(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) -> ProgramAddress {
        return ProgramAddress{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d}, 16};
    }

    auto v6_addr(std::uint16_t hi, std::uint16_t lo) -> ProgramAddress {
        return ProgramAddress{{
            static_cast<std::uint8_t>(hi >> 8), static_cast<std::uint8_t>(hi & 0xff),
            0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            static_cast<std::uint8_t>(lo >> 8), static_cast<std::uint8_t>(lo & 0xff)}, 16};
    }

    // Brute-force per-instruction single-root Matcher oracle (no IndexedRun, no local_any_index).
    struct Oracle {
        struct Inst {
            std::vector<Matcher> single_roots;
            std::shared_ptr<MmapMatcher const> mmap;
            ProgramAction action;
            DomainSource source;
            bool unconditional = false;
        };
        std::vector<Inst> insts;

        static auto build(std::span<ProgramRule const> rules) -> Oracle {
            Oracle o;
            for (auto const& r : rules) {
                Inst inst{};
                inst.action = r.action;
                inst.source = r.domain_source;
                inst.mmap = r.mmap;
                inst.unconditional = !r.mmap && r.predicates.rules.empty();
                for (auto const& pred : r.predicates.rules) {
                    auto cm = Matcher::compile(RuleSet{{pred}, 2});
                    check(bool(cm), "oracle compile root");
                    inst.single_roots.push_back(std::move(*cm));
                }
                o.insts.push_back(std::move(inst));
            }
            return o;
        }

        auto eval_inst(Inst const& inst, ProgramInput const& in) const -> Matcher::Truth {
            if (inst.unconditional) return Matcher::Truth::yes;
            std::optional<std::string_view> dom;
            auto src_idx = static_cast<std::size_t>(inst.source);
            switch (inst.source) {
            case DomainSource::explicit_target: dom = in.explicit_domain; break;
            case DomainSource::fakeip: dom = in.fakeip_domain; break;
            case DomainSource::reverse_dns: dom = in.reverse_domain; break;
            case DomainSource::sniffed: dom = in.sniffed_domain; break;
            }
            MatchInput mi{.domain = dom, .ip = in.ip, .port = in.port, .network = in.network};
            if (inst.mmap) {
                auto mm = Matcher::compile_nxmm(inst.mmap);
                // Delegate mmap check via single-instruction RouteProgram (never triggers IndexedRun/local_any_index).
                std::array<ProgramRule, 1> one{ProgramRule{{}, inst.action, inst.source, inst.mmap}};
                auto p = RouteProgram::compile(one, 8);
                auto r = p->preflight(in);
                return r->kind == ProgramPreflightKind::step ? Matcher::Truth::yes :
                    r->kind == ProgramPreflightKind::uncertain ? Matcher::Truth::unknown : Matcher::Truth::no;
            }
            bool unk = false;
            for (auto const& m : inst.single_roots) {
                auto t = m.match_truth_mapped(mi, in.candidates);
                check(bool(t), "oracle truth");
                auto val = *t;
                if (val == Matcher::Truth::unknown && !dom && in.domain_absent[src_idx]) {
                    // Check if replacing missing domain with non-matching sentinel turns unknown -> no.
                    MatchInput mi2 = mi;
                    mi2.domain = "zz-absent-sentinel-9999.invalid";
                    auto t2 = m.match_truth_mapped(mi2, in.candidates);
                    if (t2 && *t2 != Matcher::Truth::unknown) val = *t2;
                }
                if (val == Matcher::Truth::yes) return Matcher::Truth::yes;
                if (val == Matcher::Truth::unknown) unk = true;
            }
            return unk ? Matcher::Truth::unknown : Matcher::Truth::no;
        }

        auto preflight(ProgramInput const& in, std::size_t start) const -> ProgramPreflight {
            for (std::size_t i = start; i < insts.size(); ++i) {
                auto t = eval_inst(insts[i], in);
                if (t == Matcher::Truth::yes)
                    return {ProgramPreflightKind::step, i, ProgramStep{i, i + 1, insts[i].action}};
                if (t == Matcher::Truth::unknown)
                    return {ProgramPreflightKind::uncertain, i, {}};
            }
            return {ProgramPreflightKind::exhausted, insts.size(), {}};
        }

        auto next(ProgramInput const& in, std::size_t start) const -> std::optional<ProgramStep> {
            for (std::size_t i = start; i < insts.size(); ++i) {
                if (eval_inst(insts[i], in) == Matcher::Truth::yes)
                    return ProgramStep{i, i + 1, insts[i].action};
            }
            return std::nullopt;
        }
    };

    auto test_differential_and_zero_alloc() -> void {
        std::vector<ProgramRule> rules;
        // 1. 40 consecutive pure-indexed rules (IndexedRun #1, explicit_target):
        //    mix of domain, suffix, IPv4, IPv6, and dual domain+ip rules!
        for (int i = 0; i < 15; ++i)
            rules.push_back({RuleSet{{{"domain", std::format("host{}.run.test", i), {}}}, 2},
                {ProgramActionKind::route, static_cast<std::size_t>(1 + (i % 3))}});
        for (int i = 0; i < 10; ++i)
            rules.push_back({RuleSet{{{"domain-suffix", std::format("suf{}.test", i), {}}}, 2},
                {i % 2 ? ProgramActionKind::reject : ProgramActionKind::route, i % 2 ? 0u : 2u}});
        // Mixed domain + ip in one instruction inside IndexedRun: tests OR(yes, unknown) == yes!
        rules.push_back({RuleSet{{{"domain", "dual-hit.test", {}}, {"ip-cidr", "198.51.100.0/24", {}}}, 2},
            {ProgramActionKind::route, 3}});
        for (int i = 0; i < 10; ++i)
            rules.push_back({RuleSet{{{"ip-cidr", std::format("10.{}.0.0/16", i + 10), {}}}, 2},
                {ProgramActionKind::route, 4}});
        for (int i = 0; i < 5; ++i)
            rules.push_back({RuleSet{{{"ip-cidr", std::format("2001:db8:{:x}::/48", i + 1), {}}}, 2},
                {ProgramActionKind::route, 5}});

        // 2. Large in-memory instruction (>= 8 predicates -> local_any_index) with IPv4, IPv6, domains, suffixes + port remainder.
        RuleSet big_local{.version = 2};
        for (int i = 0; i < 64; ++i)
            big_local.rules.push_back({"ip-cidr", std::format("172.{}.{}.0/24", 16 + (i / 8), (i % 8) * 2), {}});
        for (int i = 0; i < 16; ++i)
            big_local.rules.push_back({"ip-cidr", std::format("2001:db8:cafe:{:x}::/64", i), {}});
        for (int i = 0; i < 32; ++i)
            big_local.rules.push_back({"domain-suffix", std::format("big{}.example", i), {}});
        big_local.rules.push_back({"domain", "exact-big.example", {}});
        big_local.rules.push_back({"port", "8443", {}});
        rules.push_back({big_local, {ProgramActionKind::route, 6}});

        // 3. Sniffed-domain IndexedRun #2 (5 rules):
        for (int i = 0; i < 5; ++i)
            rules.push_back({RuleSet{{{"domain-suffix", std::format("snf{}.org", i), {}}}, 2},
                {ProgramActionKind::route, 7}, DomainSource::sniffed});

        // 4. NXMM mmap rule:
        RuleSet mm_set{.version = 2};
        mm_set.rules.push_back({"domain-suffix", "mmap-hit.net", {}});
        mm_set.rules.push_back({"ip-cidr", "203.0.113.0/24", {}});
        auto nxmm_bytes = compile_nxmm(mm_set);
        check(bool(nxmm_bytes), "compile_nxmm");
        auto mm_matcher = MmapMatcher::open_bytes(std::move(*nxmm_bytes));
        check(bool(mm_matcher), "MmapMatcher::open_bytes");
        rules.push_back({{}, {ProgramActionKind::route, 1}, DomainSource::explicit_target,
            std::make_shared<MmapMatcher const>(std::move(*mm_matcher))});

        // 5. Unindexed NOT/AND rule + unconditional fallback:
        rules.push_back({RuleSet{{{"and", "", {{"port", "443", {}}, {"domain-keyword", "kw-hit", {}}}}}, 2},
            {ProgramActionKind::reject, 0}});

        auto prog = RouteProgram::compile(rules, 8);
        check(bool(prog), "compile differential RouteProgram");
        auto oracle = Oracle::build(rules);

        std::array<ProgramAddress, 2> cands_hit_run{v4_addr(1, 1, 1, 1), v4_addr(10, 15, 2, 3)};
        std::array<ProgramAddress, 2> cands_hit_big{v4_addr(1, 1, 1, 1), v4_mapped(172, 18, 4, 9)};
        std::array<ProgramAddress, 2> cands_hit_mm{v6_addr(0x2001, 0x0001), v4_addr(203, 0, 113, 42)};
        std::array<ProgramAddress, 0> cands_empty{};

        std::vector<ProgramInput> inputs{
            // Domain hits inside IndexedRun (mixed case + trailing dot)
            {.explicit_domain = "HOST7.RUN.TEST.", .port = 80, .network = Network::tcp},
            {.explicit_domain = "sub.SUF4.Test", .port = 80, .network = Network::tcp},
            // Dual domain+ip rule in IndexedRun: domain hits even with IP missing (OR(yes, unknown) == yes!)
            {.explicit_domain = "DUAL-HIT.TEST", .port = 80, .network = Network::tcp},
            // Missing IP -> stops at uncertain on dual rule (index 25)
            {.explicit_domain = "miss.test", .port = 80, .network = Network::tcp},
            // Missing domain (absent=false) -> uncertain at 0; (absent=true) -> skips domains, hits IP!
            {.ip = "10.14.1.1", .port = 80, .network = Network::tcp},
            {.ip = "10.14.1.1", .port = 80, .network = Network::tcp, .domain_absent = {true, false, false, false}},
            // IPv4-mapped IPv6 hitting IPv4 inside IndexedRun and local_any_index
            {.ip = "::ffff:10.12.9.9", .port = 80, .network = Network::tcp, .domain_absent = {true, false, false, false}},
            {.ip = "::ffff:172.17.6.1", .port = 80, .network = Network::tcp, .domain_absent = {true, false, false, false}},
            // Multi-candidate DNS IPs hitting IndexedRun, local_any_index, mmap, and empty candidates
            {.explicit_domain = "miss.test", .port = 80, .network = Network::tcp, .candidates = std::span<ProgramAddress const>(cands_hit_run)},
            {.explicit_domain = "miss.test", .port = 80, .network = Network::tcp, .candidates = std::span<ProgramAddress const>(cands_hit_big)},
            {.explicit_domain = "miss.test", .port = 80, .network = Network::tcp, .candidates = std::span<ProgramAddress const>(cands_hit_mm)},
            {.explicit_domain = "miss.test", .port = 80, .network = Network::tcp, .candidates = std::span<ProgramAddress const>(cands_empty)},
            // local_any_index domain, suffix, and unindexed port remainder
            {.explicit_domain = "sub.BIG19.EXAMPLE", .ip = "1.1.1.1", .port = 80, .network = Network::tcp},
            {.explicit_domain = "EXACT-BIG.example", .ip = "1.1.1.1", .port = 80, .network = Network::tcp},
            {.explicit_domain = "miss.test", .ip = "1.1.1.1", .port = 8443, .network = Network::tcp},
            // Sniffed run, mmap domain, unindexed AND rule
            {.explicit_domain = "miss.test", .sniffed_domain = "x.SNF3.ORG", .ip = "1.1.1.1", .port = 80, .network = Network::tcp},
            {.explicit_domain = "a.MMAP-HIT.NET", .ip = "1.1.1.1", .port = 80, .network = Network::tcp, .domain_absent = {false, false, false, true}},
            {.explicit_domain = "my-kw-hit.test", .ip = "1.1.1.1", .port = 443, .network = Network::tcp, .domain_absent = {false, false, false, true}},
        };

        auto same_step = [](std::optional<ProgramStep> const& a, std::optional<ProgramStep> const& b) -> bool {
            if (a.has_value() != b.has_value()) return false;
            if (!a) return true;
            return a->rule_index == b->rule_index && a->next_index == b->next_index && a->action == b->action;
        };

        // Differential check across multiple start cursors (0, mid-run 10, 25, 26, local_any 41).
        for (std::size_t q = 0; q < inputs.size(); ++q) {
            for (std::size_t start : {std::size_t{0}, std::size_t{10}, std::size_t{25}, std::size_t{26}, std::size_t{41}}) {
                auto got_n = prog->next(inputs[q], start);
                auto exp_n = oracle.next(inputs[q], start);
                check(got_n && same_step(*got_n, exp_n), std::format("next mismatch q={} start={}", q, start));
                auto got_p = prog->preflight(inputs[q], start);
                auto exp_p = oracle.preflight(inputs[q], start);
                check(got_p && got_p->kind == exp_p.kind && got_p->rule_index == exp_p.rule_index && same_step(got_p->step, exp_p.step),
                    std::format("preflight mismatch q={} start={}", q, start));
            }
        }

        // Strict zero-heap-allocation verification across all optimized fast paths.
        auto before = g_alloc_count.load(std::memory_order_relaxed);
        g_deny_alloc.store(true, std::memory_order_relaxed);
        bool alloc_ok = true;
        try {
            for (auto const& in : inputs) {
                (void)prog->next(in, 0);
                (void)prog->preflight(in, 0);
                (void)prog->preflight(in, 26);
            }
        } catch (...) {
            alloc_ok = false;
        }
        g_deny_alloc.store(false, std::memory_order_relaxed);
        check(alloc_ok && g_alloc_count.load(std::memory_order_relaxed) == before,
            "RouteProgram next/preflight must perform zero heap allocations");
    }

    auto run_benchmark() -> void {
        using Clock = std::chrono::steady_clock;
        auto bench = [](std::string_view name, std::size_t iters, auto&& fn) {
            volatile std::size_t sink = 0;
            for (std::size_t i = 0; i < 1000; ++i) sink = sink + fn(i);
            auto t0 = Clock::now();
            for (std::size_t i = 0; i < iters; ++i) sink = sink + fn(i);
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - t0).count();
            std::println("  [BENCH] {:<44} {:6.1f} ns/op ({} iters)", name, double(ns) / double(iters), iters);
        };

        // Scenario A: 500 individual main rules (250 domain-suffix + 250 ip-cidr).
        std::vector<ProgramRule> prog_rules_500;
        for (int i = 0; i < 250; ++i) {
            RuleSet rs{{{"domain-suffix", std::format("site{:04d}.example.com", i), {}}}, 2};
            prog_rules_500.push_back({rs, {ProgramActionKind::route, 1}});
        }
        for (int i = 0; i < 250; ++i) {
            RuleSet rs{{{"ip-cidr", std::format("10.{}.{}.0/{}", i / 16, (i % 16) * 16, 20 + (i % 12)), {}}}, 2};
            prog_rules_500.push_back({rs, {ProgramActionKind::route, 2}});
        }
        auto prog500 = *RouteProgram::compile_policy(prog_rules_500, 0, 4);

        // Scenario B: 50,000 GeoSite + 50,000 GeoIP (100,000 total predicates in 2 rulesets).
        RuleSet geosite{.version = 2}, geoip{.version = 2};
        geosite.rules.reserve(50000);
        geoip.rules.reserve(50000);
        for (int i = 0; i < 50000; ++i) {
            geosite.rules.push_back({"domain-suffix", std::format("d{:05d}.cn-site.net", i), {}});
            unsigned a = 11u + (static_cast<unsigned>(i) / 16384u);
            unsigned b = (static_cast<unsigned>(i) / 64u) & 0xffu;
            unsigned c = (static_cast<unsigned>(i) & 63u) * 4u;
            unsigned pfx = 22u + (static_cast<unsigned>(i) % 10u);
            geoip.rules.push_back({"ip-cidr", std::format("{}.{}.{}.0/{}", a, b, c, pfx), {}});
        }
        std::vector<ProgramRule> prog_rules_100k{
            {geosite, {ProgramActionKind::route, 1}},
            {geoip, {ProgramActionKind::route, 2}},
        };
        auto prog100k = *RouteProgram::compile_policy(prog_rules_100k, 0, 4);

        std::array<ProgramAddress, 8> dns_cands{
            v4_addr(1, 1, 1, 1), v4_addr(8, 8, 8, 8), v4_addr(9, 9, 9, 9), v4_addr(142, 250, 1, 1),
            v4_addr(151, 101, 1, 1), v4_addr(104, 16, 1, 1), v4_addr(13, 107, 1, 1), v4_addr(12, 100, 80, 1)
        };

        std::println("Unified RouteProgram micro-benchmark:");
        bench("500-rules RouteProgram next (domain hit)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog500.next({.explicit_domain = "api.site0249.example.com", .ip = "1.1.1.1"});
            return r && *r ? (**r).rule_index : 999;
        });
        bench("500-rules RouteProgram match (domain hit)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog500.match({.domain = "api.site0249.example.com", .ip = "1.1.1.1"});
            return r ? *r : 999;
        });
        bench("500-rules RouteProgram next (miss)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog500.next({.explicit_domain = "miss.unknown.org", .ip = "1.1.1.1"});
            return r && *r ? (**r).rule_index : 999;
        });
        bench("500-rules RouteProgram match (miss)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog500.match({.domain = "miss.unknown.org", .ip = "1.1.1.1"});
            return r ? *r : 999;
        });
        bench("100k-rules RouteProgram next (IPv4 hit)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog100k.next({.explicit_domain = "miss.unknown.org", .ip = "12.100.80.1"});
            return r && *r ? (**r).rule_index : 999;
        });
        bench("100k-rules RouteProgram match (IPv4 hit)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog100k.match({.domain = "miss.unknown.org", .ip = "12.100.80.1"});
            return r ? *r : 999;
        });
        bench("100k-rules RouteProgram next (8 DNS cands)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog100k.next({.explicit_domain = "miss.unknown.org", .candidates = std::span<ProgramAddress const>(dns_cands)});
            return r && *r ? (**r).rule_index : 999;
        });
        bench("100k-rules RouteProgram preflight (dom hit)", 100000, [&](std::size_t) -> std::size_t {
            auto r = prog100k.preflight({.explicit_domain = "a.d49999.cn-site.net"});
            return r ? r->rule_index : 999;
        });
    }
}

int main() {
    test_differential_and_zero_alloc();
    if (g_failures) {
        std::cerr << "route_program_perf_unit: FAIL (" << g_failures << " failures)\n";
        return 1;
    }
    run_benchmark();
    std::println("route_program_perf_unit: PASS");
    return 0;
}
