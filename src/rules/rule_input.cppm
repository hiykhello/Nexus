export module rules.rule_input;
import std;
import rules;

export namespace rules {
    enum class InputFormat { kdl,beve,srs };
    [[nodiscard]] auto parse_rule_input(std::string_view data,InputFormat format,bool ip_cidr_match_source=false) -> std::expected<RuleSet,Error>;
}
