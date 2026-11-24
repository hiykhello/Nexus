export module rules.convert_external;
import std;
export import rules;

export namespace rules {
    [[nodiscard]] auto parse_json_ruleset(std::string_view input, bool lenient = false)
        -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto parse_domain_list(std::string_view input, bool lenient = false)
        -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto parse_ipcidr_list(std::string_view input, bool lenient = false)
        -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto parse_classical_list(std::string_view input, bool lenient = false)
        -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto parse_adguard_list(std::string_view input, bool lenient = false)
        -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto merge_rule_sets(std::span<RuleSet const> sets)
        -> std::expected<RuleSet, Error>;
}
