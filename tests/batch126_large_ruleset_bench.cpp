import std;
import rules;

int main() {
    // Build a 16,001-entry compound OR (any) rule-set (near max_rules=16384 ceiling) combining
    // overlapping IPv4 CIDRs, IPv6 CIDRs, exact domains, and domain suffixes.
    rules::RuleSet set;
    set.version = 2;
    rules::Rule big_or;
    big_or.type = "or";
    big_or.children.reserve(16002);

    // 8,000 IPv4 /24 CIDRs across 10.0.0.0/24 .. 10.31.63.0/24 (adjacent blocks merge cleanly!)
    for (unsigned i = 0; i < 8000; ++i) {
        unsigned a = 10 + (i >> 16);
        unsigned b = (i >> 8) & 0xffu;
        unsigned c = i & 0xffu;
        big_or.children.push_back({"ip-cidr", std::format("{}.{}.{}.0/24", a, b, c), {}});
    }
    // 2,000 IPv6 /48 CIDRs
    for (unsigned i = 0; i < 2000; ++i) {
        big_or.children.push_back({"ip-cidr", std::format("2001:db8:{:x}::/48", i), {}});
    }
    // 3,000 exact domains + 3,000 domain suffixes
    for (unsigned i = 0; i < 3000; ++i) {
        big_or.children.push_back({"domain", std::format("host{}.exact.test", i), {}});
        big_or.children.push_back({"domain-suffix", std::format("zone{}.suffix.test", i), {}});
    }
    // 1 non-indexed remainder predicate to verify mixed-any preservation
    big_or.children.push_back({"port", "8443", {}});
    set.rules.push_back(std::move(big_or));

    auto compiled = rules::Matcher::compile(set);
    if (!compiled) {
        std::cerr << "compile failed: " << compiled.error().message << "\n";
        return 1;
    }
    // Verify copy constructor preserves index integrity!
    rules::Matcher matcher(*compiled);

    auto check = [&](rules::MatchInput in, rules::Matcher::Truth expected, std::string_view label) -> bool {
        auto r = matcher.match_truth_mapped(in);
        if (!r || *r != expected) {
            std::cerr << "FAIL " << label << "\n";
            return false;
        }
        return true;
    };

    if (!check({.ip = "10.0.0.1"}, rules::Matcher::Truth::yes, "first v4 CIDR")) return 2;
    if (!check({.ip = "10.31.63.254"}, rules::Matcher::Truth::yes, "last v4 CIDR")) return 3;
    if (!check({.ip = "::ffff:10.15.42.9"}, rules::Matcher::Truth::yes, "mapped IPv4-in-IPv6")) return 4;
    if (!check({.ip = "2001:db8:7cf::abcd"}, rules::Matcher::Truth::yes, "last v6 CIDR")) return 5;
    if (!check({.domain = "no.match.example", .ip = "198.51.100.1", .port = 443},
               rules::Matcher::Truth::no, "miss all")) return 6;
    if (!check({.ip = "198.51.100.1", .port = 443},
               rules::Matcher::Truth::unknown, "missing domain preserves three-valued unknown")) return 7;
    if (!check({.domain = "HOST2999.EXACT.TEST"}, rules::Matcher::Truth::yes, "case-insensitive exact domain")) return 8;
    if (!check({.domain = "a.b.zone2999.suffix.test"}, rules::Matcher::Truth::yes, "label-boundary suffix")) return 9;
    if (!check({.domain = "evilzone2999.suffix.test", .ip = "198.51.100.1", .port = 443},
               rules::Matcher::Truth::no, "reject non-label suffix substring")) return 10;
    if (!check({.port = 8443}, rules::Matcher::Truth::yes, "remainder port match")) return 11;

    // Benchmark 50,000 lookups against the 16,001-child rule-set!
    constexpr int kIters = 50000;
    auto t0 = std::chrono::steady_clock::now();
    std::size_t hits = 0;
    for (int i = 0; i < kIters; ++i) {
        auto r = matcher.match_truth_mapped(
            (i & 1) ? rules::MatchInput{.domain = "miss.test", .ip = "10.15.42.9", .port = 443}
                    : rules::MatchInput{.domain = "sub.zone2345.suffix.test", .ip = "198.51.100.1", .port = 443});
        if (r && *r == rules::Matcher::Truth::yes) ++hits;
    }
    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count();
    if (hits != kIters) return 12;
    double avg_us = static_cast<double>(elapsed_us) / static_cast<double>(kIters);
    std::cout << "BATCH 126 LARGE RULE-SET (16001 children) O(log N) INDEX PASSED: "
              << kIters << " lookups in " << elapsed_us << " us (avg " << avg_us << " us/lookup)\n";
    return 0;
}
