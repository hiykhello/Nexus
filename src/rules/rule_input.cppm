export module rules.rule_input;
import std;
import rules;

export namespace rules {
    enum class InputFormat { kdl,beve,srs,nxmm,json,domain_list,ipcidr_list,classical,adguard };
    [[nodiscard]] auto parse_rule_input(std::string_view data,InputFormat format,bool ip_cidr_match_source=false,
        bool lenient=false) -> std::expected<RuleSet,Error>;
}
