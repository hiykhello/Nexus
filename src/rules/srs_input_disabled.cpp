module rules.rule_input;
import std;
import rules;
namespace rules {
    auto parse_srs_input(std::string_view,bool) -> std::expected<RuleSet,Error> {
        return std::unexpected(Error{ErrorCode::schema,"SRS rule sets require the srs build feature"});
    }
}
