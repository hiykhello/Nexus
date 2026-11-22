module rules.rule_input;
import std;
import rules;

namespace rules {
    auto parse_srs_input(std::string_view data,bool ip_cidr_match_source) -> std::expected<RuleSet,Error>;
    auto parse_rule_input(std::string_view data,InputFormat format,bool ip_cidr_match_source) -> std::expected<RuleSet,Error> {
        if(ip_cidr_match_source && format!=InputFormat::srs)
            return std::unexpected(Error{ErrorCode::schema,"IP CIDR source matching requires SRS format"});
        switch(format) {
        case InputFormat::kdl: return parse_kdl(data);
        case InputFormat::beve: return parse_beve(data);
        case InputFormat::srs: return parse_srs_input(data,ip_cidr_match_source);
        }
        return std::unexpected(Error{ErrorCode::schema,"invalid rule format"});
    }
}
