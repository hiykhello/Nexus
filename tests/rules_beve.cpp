import std;
import nexus.rules;

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
    auto version() -> std::string { return key("schema_version") + std::string("\x51\x01\0\0\0", 5); }
    auto kind() -> std::string { return key("kind") + str("predicate"); }
    auto entry(std::string_view type, std::string_view value) -> std::string {
        return std::string(1, '\3') + count(2) + key("type") + str(type) + key("value") + str(value);
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
    using namespace nexus::rules;
    // A hand-built fixture fixes the v1 wire names and BEVE tags independently of the writer.
    auto fixture = document(entry("domain-suffix", "Example.COM"));
    auto parsed = parse_beve(fixture);
    check(parsed && parsed->rules.size() == 1 && parsed->rules[0].value == "example.com", "v1 fixture decodes");
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
    auto reordered_rule = std::string(1, '\3') + count(2) + key("value") + str("example.com") +
                          key("type") + str("domain-suffix");
    auto reordered = container(std::string(1, '\3') + count(3) + key("rules") + std::string(1, '\5') +
                               count(1) + reordered_rule + kind() + version());
    check(bool(parse_beve(reordered)), "field order is not significant");
    auto duplicate_rule = std::string(1, '\3') + count(2) + key("type") + str("domain-suffix") +
                          key("type") + str("domain-suffix");
    check(!parse_beve(document(duplicate_rule)), "duplicate rule field rejected");
    auto duplicate_top = container(std::string(1, '\3') + count(3) + version() + kind() + kind());
    check(!parse_beve(duplicate_top), "duplicate top-level field rejected");
    auto too_many = container(std::string(1, '\3') + count(3) + version() + kind() + key("rules") +
                              std::string(1, '\5') + count(max_rules + 1));
    check(!parse_beve(too_many), "oversized declared array rejected");
    auto huge_length = container(std::string("\3\xff\xff\xff\xff\xff\xff\xff\xff\xff", 9));
    check(!parse_beve(huge_length), "oversized count rejected");
    auto long_value = document(entry("domain-suffix", std::string(254, 'a')));
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
    RuleSet empty;
    auto empty_binary = write_beve(empty);
    check(bool(empty_binary), "empty set encodes");
    if (empty_binary) {
        auto decoded = parse_beve(*empty_binary);
        check(decoded && *decoded == empty, "empty set roundtrips");
    }
    RuleSet maximum;
    maximum.rules.resize(max_rules, Rule{"domain-suffix", "example.com"});
    auto encoded = write_beve(maximum);
    check(bool(encoded), "maximum rule count encodes");
    if (encoded) {
        auto decoded = parse_beve(*encoded);
        check(decoded && *decoded == maximum, "maximum rule count roundtrips");
    }
    maximum.rules.push_back({"domain-suffix", "example.com"});
    check(!write_beve(maximum), "excess rule count rejected on write");
    auto long_domain = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                       std::string(63, 'c') + "." + std::string(61, 'd');
    RuleSet large;
    large.rules.resize(4000, Rule{"domain-suffix", long_domain});
    check(!write_beve(large), "BEVE output budget enforced");
    check(!write_kdl(large), "KDL output budget enforced");
    if (!failures) std::cout << "BEVE rule tests passed\n";
    return failures ? 1 : 0;
}
