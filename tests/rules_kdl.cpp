import std;
import rules;
import nexus.thirdparty.glaze;

namespace g = nex::glaze;

struct WireExtra {
    std::uint32_t schema_version = 1;
    std::string kind = "predicate";
    std::vector<::rules::Rule> rules;
    std::string extra = "not-allowed";
};

struct WireMissing {
    std::uint32_t schema_version = 1;
    std::string kind = "predicate";
};

namespace {
    int failures = 0;

    auto check(bool passed, std::string_view description) -> void {
        if (!passed) {
            ++failures;
            std::cerr << "FAIL: " << description << '\n';
        }
    }

    auto fails(std::string_view text) -> bool {
        return !::rules::parse_kdl(text);
    }

    auto read(std::string_view path) -> std::string {
        std::ifstream input(std::string(path), std::ios::binary);
        if (!input) return {};
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }

    template<class T>
    auto malformed_container(T const& wire) -> std::string {
        std::string payload;
        if (auto error = g::write_beve(wire, payload); error) return {};
        std::string data("NXRULES\0\0\1\0\0", 12);
        auto size = static_cast<std::uint32_t>(payload.size());
        for (int shift = 24; shift >= 0; shift -= 8) data.push_back(static_cast<char>((size >> shift) & 0xffU));
        return data + payload;
    }
}

int main() {
    using namespace ::rules;
    constexpr auto source = R"(schema-version 1
kind "predicate"
rule type="domain-suffix" value="Example.COM"
rule type="ip-cidr" value="2001:db8::/32"
)";
    auto parsed = parse_kdl(source);
    check(bool(parsed), "valid KDL should parse");
    if (parsed) {
        check(parsed->rules.size() == 2, "rule order and count are retained");
        check(parsed->rules[0].value == "example.com", "domain normalization");
        auto encoded = write_kdl(*parsed);
        check(bool(encoded), "valid rules should serialize");
        if (encoded) {
            auto roundtrip = parse_kdl(*encoded);
            check(roundtrip && *roundtrip == *parsed, "KDL roundtrip preserves rule semantics");
        }
        auto binary = write_beve(*parsed);
        check(bool(binary), "BEVE encoding succeeds");
        if (binary) {
            auto decoded = parse_beve(*binary);
            check(decoded && *decoded == *parsed, "KDL to BEVE preserves rule order and values");
            if (decoded) {
                auto text = write_kdl(*decoded);
                auto decoded_text = text ? parse_kdl(*text) : std::expected<RuleSet, Error>{std::unexpected(Error{ErrorCode::syntax, "encode"})};
                check(decoded_text && *decoded_text == *parsed, "BEVE to KDL preserves semantics");
            }
            auto truncated = *binary; truncated.pop_back();
            check(!parse_beve(truncated), "truncated BEVE rejected");
            auto bad_flags = *binary; bad_flags[11] = 1;
            check(!parse_beve(bad_flags), "unknown container flags rejected");
            auto trailing = *binary; trailing.push_back('\0');
            std::uint32_t size = static_cast<std::uint32_t>(trailing.size() - 16);
            for (int i = 0; i < 4; ++i) trailing[12 + i] = static_cast<char>((size >> (24 - 8 * i)) & 0xffU);
            check(!parse_beve(trailing), "trailing BEVE item rejected");
        }
    }
    check(!parse_beve(malformed_container(WireExtra{})), "unknown BEVE field rejected");
    check(!parse_beve(malformed_container(WireMissing{})), "missing BEVE field rejected");
    check(fails(""), "empty document is not a rule set");
    check(fails("schema-version 1\nkind \"predicate\"\nrule {"), "malformed KDL fails");
    check(fails("schema-version 1\nschema-version 1\nkind \"predicate\""), "duplicate version fails");
    check(fails("schema-version 3\nkind \"predicate\""), "unsupported version fails");
    check(fails("schema-version 1\nkind \"predicate\"\nunknown 1"), "unknown node fails");
    check(fails("schema-version 1\nkind \"predicate\"\nrule type=\"domain-suffix\" value=\"bad..name\""), "invalid domain fails");
    check(fails("schema-version 1\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"1.2.3.4/33\""), "invalid CIDR fails");
    check(!normalize_rule(Rule{"ip-cidr", std::string("1.2.3.4\0evil/8", 14)}), "embedded NUL in CIDR fails");
    check(fails("schema-version 1\nkind \"predicate\"\nrule type=\"unknown\" value=\"x\""), "unknown rule fails");
    auto duplicate_property = parse_kdl("schema-version 1\nkind \"predicate\"\nrule type=\"unknown\" type=\"domain-suffix\" value=\"example.com\"");
    check(duplicate_property && duplicate_property->rules[0].type == "domain-suffix", "KDL duplicate property uses its final value");
    check(fails(std::string(max_input_bytes + 1, ' ')), "input budget enforced");
    for (auto path : {"docs/configuration/examples/paired/rules/blocked.kdl", "docs/configuration/examples/paired/rules/private.kdl"}) {
        auto content = read(path);
        check(!content.empty() && bool(parse_kdl(content)), "documented example rule sets parse");
    }
    if (!failures) std::cout << "KDL rule tests passed\n";
    return failures ? 1 : 0;
}
