module rules.rule_input;
import std;
import rules;
import rules.srs_file;
namespace rules {
    auto parse_srs_input(std::string_view data,bool ip_cidr_match_source) -> std::expected<RuleSet,Error> {
        return decode_srs_file(std::span(reinterpret_cast<std::uint8_t const*>(data.data()),data.size()),ip_cidr_match_source);
    }
}
