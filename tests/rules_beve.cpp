import std;
import rules;

namespace {
    int failures = 0;

    auto check(bool passed, std::string_view description) -> void {
        if (!passed) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
    }

    auto count(std::uint64_t value) -> std::string {
        unsigned width = value < 64 ? 1 : value < 16384 ? 2 : value < 1073741824 ? 4 : 8;
        auto encoded = (value << 2) | (width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3);
        std::string result;
        for (unsigned i = 0; i < width; ++i) result.push_back(static_cast<char>(encoded >> (8 * i)));
        return result;
    }

    auto key(std::string_view value) -> std::string { return count(value.size()) + std::string(value); }
    auto str(std::string_view value) -> std::string { return std::string(1, '\2') + key(value); }
    auto version() -> std::string { return key("schema_version") + std::string("\x51\x02\0\0\0", 5); }
    auto kind() -> std::string { return key("kind") + str("predicate"); }
    auto entry(std::string_view type, std::string_view value) -> std::string {
        return std::string(1, '\3') + count(3) + key("type") + str(type) + key("value") + str(value) +
               key("children") + std::string(1, '\5') + count(0);
    }
    auto container(std::string const& payload) -> std::string {
        std::string result("NXRULES\0\0\1\0\0", 12);
        auto size = static_cast<std::uint32_t>(payload.size());
        for (int shift = 24; shift >= 0; shift -= 8) result.push_back(static_cast<char>(size >> shift));
        return result + payload;
    }
    auto document(std::string const& rule) -> std::string {
        return container(std::string(1, '\3') + count(3) + version() + kind() + key("rules") +
                         std::string(1, '\5') + count(1) + rule);
    }
}

int main() {
    using namespace ::rules;
    // Legacy v1 wire format (2-field rule, schema_version=1) must be rejected.
    auto legacy_v1 = container(std::string(1, '\3') + count(3) +
                               key("schema_version") + std::string("\x51\x01\0\0\0", 5) + kind() + key("rules") +
                               std::string(1, '\5') + count(1) +
                               std::string(1, '\3') + count(2) + key("type") + str("domain-suffix") + key("value") + str("example.com"));
    check(!parse_beve(legacy_v1), "legacy v1 BEVE fixture rejected");
    // A hand-built fixture fixes the v2 wire names and BEVE tags independently of the writer.
    auto fixture = document(entry("domain-suffix", "Example.COM"));
    auto parsed = parse_beve(fixture);
    check(parsed && parsed->rules.size() == 1 && parsed->rules[0].value == "example.com", "v2 fixture decodes");
    if (parsed) {
        auto text = write_kdl(*parsed);
        check(bool(text), "fixture writes KDL");
        if (text) {
            auto read_text = parse_kdl(*text);
            check(bool(read_text), "converted KDL parses");
            if (read_text) {
                auto binary = write_beve(*read_text);
                check(bool(binary), "converted KDL writes BEVE");
                if (binary) {
                    auto decoded = parse_beve(*binary);
                    check(decoded && *decoded == *parsed, "BEVE to KDL to BEVE preserves semantics");
                }
            }
        }
    }
    auto reordered_rule = std::string(1, '\3') + count(3) + key("children") + std::string(1, '\5') + count(0) +
                          key("value") + str("example.com") + key("type") + str("domain-suffix");
    auto reordered = container(std::string(1, '\3') + count(3) + key("rules") + std::string(1, '\5') +
                               count(1) + reordered_rule + kind() + version());
    check(bool(parse_beve(reordered)), "field order is not significant");
    auto duplicate_rule = std::string(1, '\3') + count(3) + key("type") + str("domain-suffix") +
                          key("type") + str("domain-suffix") + key("children") + std::string(1, '\5') + count(0);
    check(!parse_beve(document(duplicate_rule)), "duplicate rule field rejected");
    auto duplicate_top = container(std::string(1, '\3') + count(3) + version() + kind() + kind());
    check(!parse_beve(duplicate_top), "duplicate top-level field rejected");
    auto document2 = document;
    auto nested = [&](std::string_view type, std::string_view value, std::string const& children, unsigned n) {
        return std::string(1, '\3') + count(3) + key("type") + str(type) + key("value") + str(value) +
               key("children") + std::string(1, '\5') + count(n) + children;
    };
    auto leaf = nested("port","443",{},0);
    auto v2 = document2(nested("not","",leaf,1));
    check(bool(parse_beve(v2)), "hand-built v2 nested profile accepted");
    auto duplicate_child = std::string(1, '\3') + count(3) + key("type") + str("port") +
        key("children") + std::string(1, '\5') + count(0) + key("children") + std::string(1, '\5') + count(0);
    check(!parse_beve(document2(duplicate_child)), "v2 duplicate child field rejected");
    auto unknown_field = std::string(1, '\3') + count(3) + key("type") + str("port") +
        key("value") + str("443") + key("unknown") + std::string(1, '\5') + count(0);
    check(!parse_beve(document2(unknown_field)), "v2 unknown child field rejected");
    auto deep = leaf;
    for (unsigned i=0;i<max_rule_depth;++i) deep=nested("not","",deep,1);
    check(!parse_beve(document2(deep)), "v2 BEVE nesting limit enforced before decode");
    for (std::size_t length=0;length<v2.size();++length)
        check(!parse_beve(std::string_view(v2).substr(0,length)), "truncated v2 container rejected");
    auto too_many = container(std::string(1, '\3') + count(3) + version() + kind() + key("rules") +
                              std::string(1, '\5') + count(max_rules + 1));
    check(!parse_beve(too_many), "oversized declared array rejected");
    auto huge_length = container(std::string("\3\xff\xff\xff\xff\xff\xff\xff\xff\xff", 9));
    check(!parse_beve(huge_length), "oversized count rejected");
    auto long_value = document(entry("domain-suffix", std::string(256, 'a')));
    check(!parse_beve(long_value), "oversized string rejected");
    auto bad_nul = document(entry("ip-cidr", std::string("1.2.3.4\0evil/8", 14)));
    check(!parse_beve(bad_nul), "embedded NUL rejected in BEVE CIDR");
    for (std::size_t length = 0; length < fixture.size(); ++length) {
        check(!parse_beve(std::string_view(fixture).substr(0, length)), "truncated container rejected");
    }
    auto payload = std::string_view(fixture).substr(16);
    for (std::size_t length = 0; length < payload.size(); ++length) {
        check(!parse_beve(container(std::string(payload.substr(0, length)))), "truncated payload with adjusted length rejected");
    }
    check(!parse_beve(std::string(max_input_bytes + 1, 'x')), "input byte limit enforced");
    RuleSet empty{.version = 2};
    auto empty_binary = write_beve(empty);
    check(bool(empty_binary), "empty set encodes");
    if (empty_binary) {
        auto decoded = parse_beve(*empty_binary);
        check(decoded && *decoded == empty, "empty set roundtrips");
    }
    RuleSet high_scale{.version = 2};
    high_scale.rules.resize(300000, Rule{"domain-suffix", "example.com"});
    auto encoded = write_beve(high_scale);
    check(bool(encoded), "high-scale (>262144) rule count encodes");
    if (encoded) {
        auto decoded = parse_beve(*encoded);
        check(decoded && *decoded == high_scale, "high-scale (>262144) rule count roundtrips");
    }
    auto long_domain = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                       std::string(63, 'c') + "." + std::string(61, 'd');
    RuleSet large{.version = 2};
    large.rules.resize(1020000, Rule{"domain-suffix", long_domain});
    check(!write_beve(large), "BEVE output budget enforced");
    check(!write_kdl(large), "KDL output budget enforced");
    if (!failures) std::cout << "BEVE rule tests passed\n";
    return failures ? 1 : 0;
}
