#include <zlib.h>
import std;
import rules;
import rules.rule_input;
import rules.srs_file;
import relay;

namespace {
    std::atomic<bool> g_deny_alloc{false};
    std::atomic<std::size_t> g_alloc_count{0};
    int failures = 0;
    auto check(bool ok, std::string_view msg) -> void {
        if (!ok) {
            g_deny_alloc.store(false, std::memory_order_relaxed);
            ++failures;
            std::cerr << "FAIL: " << msg << '\n';
        }
    }
    struct ZeroAllocScope {
        std::size_t before;
        std::string_view label;
        explicit ZeroAllocScope(std::string_view lbl) noexcept
            : before(g_alloc_count.load(std::memory_order_relaxed)), label(lbl) {
            g_deny_alloc.store(true, std::memory_order_relaxed);
        }
        ~ZeroAllocScope() {
            g_deny_alloc.store(false, std::memory_order_relaxed);
            check(g_alloc_count.load(std::memory_order_relaxed) == before, label);
        }
    };
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

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view prefix) {
            auto stamp = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            path = std::filesystem::temp_directory_path() / std::format("{}-{}", prefix, stamp);
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
            std::filesystem::create_directories(path, ec);
        }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    };

    auto write_le32(std::string& out, std::uint32_t v) -> void {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((v >> (i * 8)) & 0xffu));
    }
    auto write_le64(std::string& out, std::uint64_t v) -> void {
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<char>((v >> (i * 8)) & 0xffu));
    }

    auto compress_srs(std::uint8_t version, std::span<std::uint8_t const> payload) -> std::vector<std::uint8_t> {
        uLongf bound = compressBound(static_cast<uLong>(payload.size()));
        std::vector<std::uint8_t> out(4 + bound);
        out[0] = 'S'; out[1] = 'R'; out[2] = 'S'; out[3] = version;
        uLongf out_len = bound;
        int rc = compress2(out.data() + 4, &out_len, payload.data(), static_cast<uLong>(payload.size()), Z_BEST_COMPRESSION);
        check(rc == Z_OK, "zlib compress2 helper succeeds");
        out.resize(4 + out_len);
        return out;
    }

    // 1. Scale > 300,000 rules compiled to NXMM and opened via zero-copy MmapMatcher::open_file.
    auto test_nxmm_300k_zero_copy(TempDir const& tmp) -> void {
        using namespace rules;
        static_assert(max_rules == 4000000u);
        static_assert(max_input_bytes == 268435456u);
        static_assert(max_rule_depth == 32u);

        constexpr unsigned n_exact = 150000;
        constexpr unsigned n_suffix = 100000;
        constexpr unsigned n_v4 = 50000;
        constexpr unsigned n_v6 = 10000;
        RuleSet big{.version = 2};
        big.rules.reserve(n_exact + n_suffix + n_v4 + n_v6);
        for (unsigned i = 0; i < n_exact; ++i)
            big.rules.push_back({"domain", std::format("d{}.nxmm.test", i), {}});
        for (unsigned i = 0; i < n_suffix; ++i)
            big.rules.push_back({"domain-suffix", std::format("s{}.suf.test", i), {}});
        for (unsigned i = 0; i < n_v4; ++i) {
            // Even host octets prevent adjacent /32 merging so all 50,000 intervals remain distinct.
            unsigned ip_idx = i * 2u;
            unsigned a = (ip_idx >> 16) & 0xffu;
            unsigned b = (ip_idx >> 8) & 0xffu;
            unsigned c = ip_idx & 0xffu;
            big.rules.push_back({"ip-cidr", std::format("10.{}.{}.{}/32", a, b, c), {}});
        }
        for (unsigned i = 0; i < n_v6; ++i) {
            // Even /64 subnets prevent interval coalescing so all 10,000 IPv6 ranges remain distinct.
            big.rules.push_back({"ip-cidr", std::format("2001:db8:{:x}:{:x}::/64", (i * 2u) >> 16, (i * 2u) & 0xffffu), {}});
        }

        auto compiled = compile_nxmm(big);
        check(bool(compiled), compiled ? "310k NXMM compiles" : ("310k NXMM compile error: " + compiled.error().message));
        if (!compiled) return;

        auto nxmm_path = tmp.path / "scale310k.nxmm";
        {
            std::ofstream out(nxmm_path, std::ios::binary | std::ios::trunc);
            out.write(compiled->data(), static_cast<std::streamsize>(compiled->size()));
            check(out.good(), "write 310k NXMM fixture");
        }

        auto mm = MmapMatcher::open_file(nxmm_path.string());
        check(bool(mm), mm ? "MmapMatcher::open_file loads 310k NXMM" : ("open_file error: " + mm.error()));
        if (!mm) return;

        check(mm->exact_count() == n_exact && mm->suffix_count() == n_suffix &&
              mm->v4_count() == n_v4 && mm->v6_count() == n_v6,
              "MmapMatcher exposes all 310,000 indexed entries");

        // Last IPv4: i = 49999 -> ip_idx = 99998 = 0x01869e -> 10.1.134.158
        std::array<std::uint8_t, 16> v4_last{10, 1, 134, 158};
        std::array<std::uint8_t, 16> v4_gap{10, 1, 134, 159};
        // Last IPv6: i = 9999 -> i*2 = 19998 = 0x4e1e -> 2001:db8:0:4e1e::42
        std::array<std::uint8_t, 16> v6_last{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0x4e, 0x1e, 0, 0, 0, 0, 0, 0, 0, 0x42};
        std::array<std::uint8_t, 16> v6_gap{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0x4e, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0x42};
        {
            ZeroAllocScope za("310k NXMM zero-alloc hot-path binary search");
            check(mm->match_domain("d0.nxmm.test") && mm->match_domain("d75000.nxmm.test") &&
                  mm->match_domain("d149999.nxmm.test") && !mm->match_domain("d150000.nxmm.test"),
                  "310k NXMM exact domain binary search matches first/mid/last and rejects miss");
            check(mm->match_domain("s0.suf.test") && mm->match_domain("a.b.s99999.suf.test") &&
                  !mm->match_domain("s100000.suf.test"),
                  "310k NXMM suffix domain binary search matches apex/sub and rejects miss");
            check(mm->match_ip(v4_last, 4) && !mm->match_ip(v4_gap, 4),
                  "310k NXMM IPv4 range binary search matches 50,000th entry and rejects adjacent gap");
            check(mm->match_ip(v6_last, 6) && !mm->match_ip(v6_gap, 6),
                  "310k NXMM IPv6 range binary search matches 10,000th entry and rejects adjacent gap");
        }

        // Explicit budget override enforcement on open_file & compile_nxmm
        check(!MmapMatcher::open_file(nxmm_path.string(), 1024u * 1024u),
              "MmapMatcher::open_file enforces explicit byte budget override");
        check(!MmapMatcher::open_file(nxmm_path.string(), max_input_bytes, 200000u),
              "MmapMatcher::open_file enforces explicit rule-count budget override");
        check(!compile_nxmm(big, false, 1024u * 1024u),
              "compile_nxmm enforces explicit byte budget override");

        // Zero-copy RouteProgram execution against 310k MmapMatcher
        auto mm_ptr = std::make_shared<MmapMatcher const>(std::move(*mm));
        std::vector<ProgramRule> prules{
            {RuleSet{.version = 2}, {ProgramActionKind::route, 1}, DomainSource::explicit_target, mm_ptr, false},
            {RuleSet{.version = 2}, {ProgramActionKind::route, 0}},
        };
        auto prog = RouteProgram::compile(prules, 2);
        check(bool(prog), "RouteProgram compiles with 310k zero-copy MmapMatcher");
        if (prog) {
            ZeroAllocScope za("RouteProgram 310k NXMM zero-alloc hot path");
            auto hit_d = prog->next({.explicit_domain = "deep.s99999.suf.test", .port = 443, .network = Network::tcp});
            auto hit_ip = prog->next({.ip = "10.1.134.158", .port = 443, .network = Network::tcp});
            auto miss = prog->next({.explicit_domain = "miss.other.test", .ip = "10.1.134.159", .port = 443, .network = Network::tcp});
            check(hit_d && *hit_d && (*hit_d)->action.outbound == 1, "RouteProgram 310k NXMM matches last suffix");
            check(hit_ip && *hit_ip && (*hit_ip)->action.outbound == 1, "RouteProgram 310k NXMM matches last IPv4");
            check(miss && *miss && (*miss)->action.outbound == 0, "RouteProgram 310k NXMM falls through on miss");
        }

        // Crafted NXMM header claiming > max_rules entries is rejected cleanly without overflow
        std::string bogus;
        bogus.append("NXMM\0\0\0\1", 8);
        write_le32(bogus, 1u);
        write_le32(bogus, 0u);
        write_le64(bogus, 64u);
        write_le32(bogus, max_rules + 1u);
        write_le32(bogus, 0u); write_le32(bogus, 0u); write_le32(bogus, 0u);
        write_le32(bogus, 0u); write_le32(bogus, 0u);
        write_le64(bogus, 0u); write_le64(bogus, 0u);
        check(!MmapMatcher::open_bytes(bogus), "NXMM header claiming max_rules + 1 rejected");

        std::cout << "  [PASS] 310,000-rule zero-copy NXMM scale & budget checks\n";
    }

    // 2. Query context with > 128 interface addresses / process paths and > 300 candidates (zero truncation).
    auto test_unbounded_query_context() -> void {
        using namespace rules;
        RuleSet set{{
            {"default-interface-address", "10.99.0.0/16", {}},
            {"network-interface-address", "wifi:192.168.250.0/24", {}},
            {"process-name", "final-daemon", {}},
            {"process-path", "/opt/nexus/bin/final-daemon", {}},
            {"process-path-regex", "^/opt/nexus/bin/final-[a-z]+$", {}},
            {"ip-cidr", "198.51.100.200/32", {}},
        }, 2};
        auto m = Matcher::compile(set);
        check(bool(m), "compile query-context matcher");
        if (!m) return;

        // > 128 default_interface_addresses: target at final index 149 (zero hot-path heap allocs)
        std::vector<ProgramAddress> def_addrs(150, ProgramAddress{{172, 16, 0, 1}, 4});
        def_addrs.back() = ProgramAddress{{10, 99, 7, 42}, 4};
        {
            ZeroAllocScope za(">128 default_interface_addresses zero-alloc hot path");
            auto r_def = m->match({.default_interface_addresses = std::span<ProgramAddress const>(def_addrs)});
            check(r_def && *r_def == std::optional<std::size_t>(0), ">128 default_interface_addresses matches last entry");
        }

        // Invalid element at final index 149 is still validated
        def_addrs.back().size = 3;
        auto r_def_bad = m->match({.default_interface_addresses = std::span<ProgramAddress const>(def_addrs)});
        check(!r_def_bad && r_def_bad.error().code == ErrorCode::invalid_query, "invalid entry at tail of >128 default_interface_addresses rejected");

        // > 128 network_interface_addresses: target at final index 149 (zero hot-path heap allocs)
        std::vector<NetworkInterfaceAddress> net_addrs(150, NetworkInterfaceAddress{NetworkType::ethernet, ProgramAddress{{172, 16, 1, 1}, 4}});
        net_addrs.back() = NetworkInterfaceAddress{NetworkType::wifi, ProgramAddress{{192, 168, 250, 9}, 4}};
        {
            ZeroAllocScope za(">128 network_interface_addresses zero-alloc hot path");
            auto r_net = m->match({.network_interface_addresses = std::span<NetworkInterfaceAddress const>(net_addrs)});
            check(r_net && *r_net == std::optional<std::size_t>(1), ">128 network_interface_addresses matches last entry");
        }

        // > 128 process_paths: target at final index 149 (zero hot-path heap allocs)
        std::vector<std::string> procs(150, "/usr/bin/filler");
        procs.back() = "/opt/nexus/bin/final-daemon";
        auto m_path = Matcher::compile(RuleSet{{{"process-path", "/opt/nexus/bin/final-daemon", {}}}, 2});
        auto m_rx = Matcher::compile(RuleSet{{{"process-path-regex", "^/opt/nexus/bin/final-[a-z]+$", {}}}, 2});
        check(bool(m_path) && bool(m_rx), "compile process-path and process-path-regex matchers");
        if (m_path && m_rx) {
            ZeroAllocScope za(">128 process_paths zero-alloc hot path");
            auto r_proc = m->match({.process_paths = std::span<std::string const>(procs)});
            auto r_path = m_path->match({.process_paths = std::span<std::string const>(procs)});
            auto r_rx = m_rx->match({.process_paths = std::span<std::string const>(procs)});
            check(r_proc && *r_proc == std::optional<std::size_t>(2), ">128 process_paths matches last entry");
            check(r_path && *r_path == std::optional<std::size_t>(0), ">128 process_paths matches process-path at final index");
            check(r_rx && *r_rx == std::optional<std::size_t>(0), ">128 process_paths matches process-path-regex at final index");
        }

        // > 300 candidates in RouteProgram::next & > 16384 in Matcher::match_truth_mapped (zero hot-path heap allocs)
        std::vector<ProgramAddress> cands(350, ProgramAddress{{203, 0, 113, 1}, 4});
        cands.back() = ProgramAddress{{198, 51, 100, 200}, 4};
        std::vector<ProgramRule> prules{
            {RuleSet{{{"ip-cidr", "198.51.100.200/32", {}}}, 2}, {ProgramActionKind::route, 1}},
            {RuleSet{.version = 2}, {ProgramActionKind::route, 0}},
        };
        auto prog = RouteProgram::compile(prules, 2);
        check(bool(prog), "compile candidate RouteProgram");
        if (prog) {
            ZeroAllocScope za(">300 RouteProgram candidates zero-alloc hot path");
            auto step = prog->next({.port = 443, .network = Network::tcp, .candidates = std::span<ProgramAddress const>(cands)});
            check(step && *step && (*step)->action.outbound == 1, ">300 RouteProgram candidates matches last entry without truncation");
        }

        auto single_ip = Matcher::compile(RuleSet{{{"ip-cidr", "198.51.100.200/32", {}}}, 2});
        check(bool(single_ip), "compile single-root CIDR matcher");
        if (single_ip) {
            std::vector<ProgramAddress> huge_cands(16500, ProgramAddress{{203, 0, 113, 2}, 4});
            huge_cands.back() = ProgramAddress{{198, 51, 100, 200}, 4};
            ZeroAllocScope za(">16384 match_truth_mapped candidates zero-alloc hot path");
            auto truth = single_ip->match_truth_mapped({}, std::span<ProgramAddress const>(huge_cands));
            check(truth && *truth == Matcher::Truth::yes, ">16384 match_truth_mapped candidates matches last entry");
        }

        std::cout << "  [PASS] Unbounded query-context spans (>128 interfaces/procs, >300 & >16384 candidates)\n";
    }

    // 3. Indexed routes > 256 in relay::compile_routes (lifted from old 256 cap).
    auto test_indexed_routes_over_256() -> void {
        constexpr std::size_t count = 300;
        std::vector<std::string> payloads;
        payloads.reserve(count);
        std::vector<relay::IndexedRouteRule> indexed;
        indexed.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            payloads.push_back(std::format("r{}.indexed.test\n", i));
            indexed.push_back({payloads.back(), relay::RuleFormat::domain_list, i == count - 1 ? 1u : 0u});
        }
        auto snap = relay::compile_routes(indexed, 0, 2, "socks", std::nullopt);
        check(bool(snap), snap ? "compile_routes accepts 300 indexed rules (>256)" : ("compile_routes error: " + snap.error()));
        if (snap) {
            auto hit = snap->matcher.match({.domain = "r299.indexed.test"});
            auto miss = snap->matcher.match({.domain = "r0.indexed.test"});
            check(hit && *hit == 1, "300th indexed route matches cleanly");
            check(miss && *miss == 0, "1st indexed route matches cleanly");
        }
        std::cout << "  [PASS] >256 indexed route rules compile and match\n";
    }

    // 4. Anti-DoS guards strictly preserved: SRS bomb ratio, max_rule_depth=32, JSON depth 64, regex states 2048.
    auto test_anti_dos_guards_preserved() -> void {
        using namespace rules;

        // 4a. SRS decompression bomb expansion ratio (8 MiB zeros -> ~8 KiB zlib = ~1000x ratio, well under 256 MiB!)
        std::vector<std::uint8_t> zeros(8u * 1024u * 1024u, 0);
        auto bomb = compress_srs(2, zeros);
        check(bomb.size() < 32u * 1024u, "SRS bomb fixture compresses tightly");
        auto bomb_res = decode_srs_file(bomb);
        check(!bomb_res && bomb_res.error().code == ErrorCode::limit,
              "SRS decompression expansion-ratio bomb rejected with ErrorCode::limit");

        // Valid normal SRS rule-set still decodes cleanly under the ratio guard
        std::vector<std::uint8_t> valid_srs{1, 0, 19, 255, 0}; // 1 rule: network_is_expensive
        auto valid_file = compress_srs(3, valid_srs);
        auto valid_res = decode_srs_file(valid_file);
        check(bool(valid_res) && valid_res->rules.size() == 1, "valid SRS v3 rule-set decodes cleanly");

        // 4b. max_rule_depth = 32 preserved
        Rule deep{"port", "443", {}};
        for (unsigned i = 0; i < max_rule_depth; ++i)
            deep = Rule{"not", {}, {std::move(deep)}};
        auto deep_res = normalize_set(RuleSet{{std::move(deep)}, 2});
        check(!deep_res && deep_res.error().code == ErrorCode::limit, "max_rule_depth=32 still enforced");

        // 4c. JSON nesting depth 64 preserved
        std::string deep_json = R"({"version":3,"rules":[{"domain":"ok.test","extra":)";
        for (int i = 0; i < 66; ++i) deep_json.push_back('[');
        deep_json.push_back('1');
        for (int i = 0; i < 66; ++i) deep_json.push_back(']');
        deep_json += "}]}";
        auto json_res = parse_rule_input(deep_json, InputFormat::json, false, true);
        check(!json_res, "JSON nesting depth 64 still enforced");

        // 4d. Regex total state limit 2048 preserved
        RuleSet many_rx{.version = 2};
        for (int i = 0; i < 120; ++i)
            many_rx.rules.push_back({"domain-regex", "^[a-z]{10}-[0-9]{10}\\.example\\.com$", {}});
        auto rx_res = Matcher::compile(many_rx);
        check(!rx_res && rx_res.error().code == ErrorCode::limit, "total regex state limit 2048 still enforced");

        std::cout << "  [PASS] Anti-DoS guards preserved (SRS bomb ratio, depth=32, JSON depth=64, regex states=2048)\n";
    }
}

int main() {
    TempDir tmp("nexus-wave37-track2");
    test_nxmm_300k_zero_copy(tmp);
    test_unbounded_query_context();
    test_indexed_routes_over_256();
    test_anti_dos_guards_preserved();
    if (!failures) std::cout << "Wave 37 Track 2 rules & NXMM scale tests passed\n";
    return failures ? 1 : 0;
}
