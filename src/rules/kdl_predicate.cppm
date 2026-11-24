export module rules.kdl_predicate;
import std;
import rules;
import glaze;

export namespace rules {
    auto decode_kdl_predicate(glaze::KdlNode const& node,unsigned depth,std::size_t& count)
        -> std::expected<Rule,Error> {
        if (depth>max_rule_depth || ++count>max_rules)
            return std::unexpected(Error{ErrorCode::limit,"rule nesting or count exceeds limit"});
        auto invalid=[](std::string text) -> std::unexpected<Error> {
            return std::unexpected(Error{ErrorCode::schema,std::move(text)});
        };
        auto value_string=[](glaze::KdlValue const& value,bool typed) -> std::optional<std::string> {
            if (value.tag) return {};
            if (auto text=std::get_if<std::string>(&value.data)) return *text;
            if (typed) {
                if (auto boolean=std::get_if<bool>(&value.data)) return *boolean ? "true" : "false";
                if (auto number=std::get_if<std::uint64_t>(&value.data)) return std::to_string(*number);
                if (auto number=std::get_if<std::int64_t>(&value.data)) return std::to_string(*number);
            }
            return {};
        };
        Rule rule;
        if (node.tag) return invalid("tagged predicate node");
        bool has_value=false;
        if (node.name=="rule") {
            if (!node.arguments.empty() || node.properties.empty() || node.properties.size()>2)
                return invalid("invalid rule properties");
            for (auto const& [key,value]:node.properties) {
                if (key=="type") {
                    auto type=value_string(value,false);
                    if (!type) return invalid("rule type must be an untagged string");
                    rule.type=std::move(*type);
                } else if (key=="value") has_value=true;
                else return invalid("unknown rule property: "+key);
            }
            if (rule.type.empty()) return invalid("rule requires type");
            if (has_value) for (auto const& [key,value]:node.properties) if (key=="value") {
                auto allow_typed = rule.type=="tls-ech" || rule.type=="dscp" ||
                    rule.type=="ip-accept-any" || rule.type=="source-ip-accept-any" ||
                    rule.type=="ip-is-private" || rule.type=="source-ip-is-private" ||
                    rule.type=="ip-is-cgnat" || rule.type=="source-ip-is-cgnat" ||
                    rule.type=="network-is-expensive" || rule.type=="network-is-constrained" ||
                    rule.type=="source-uid" || rule.type=="source-gid" ||
                    rule.type=="port" || rule.type=="source-port" || rule.type=="ip-version";
                auto text=value_string(value, allow_typed);
                if (!text) return invalid("invalid predicate value");
                rule.value=std::move(*text);
            }
        } else {
            if (!node.properties.empty() || (node.name!="dscp" && node.arguments.size()>1)) return invalid("invalid inline predicate");
            rule.type=node.name;
            for (auto const& argument:node.arguments) {
                auto value=value_string(argument,rule.type!="rule-set" && rule.type!="protocol" &&
                    rule.type!="source-mac" && rule.type!="gateway-mac" && rule.type!="wifi-bssid" &&
                    rule.type!="wifi-ssid" && rule.type!="source-user" && rule.type!="package-name" &&
                    rule.type!="client" && rule.type!="network-type" && rule.type!="default-interface-address");
                if (!value) return invalid("invalid inline predicate value");
                if (has_value) rule.value.push_back(',');
                rule.value+=*value;
                has_value=true;
            }
        }
        if (rule.type=="all") rule.type="and";
        if (rule.type=="any") rule.type="or";
        bool logical=rule.type=="and" || rule.type=="or" || rule.type=="not";
        if (logical) {
            if (has_value || node.children.empty()) return invalid("logical rule requires children and no value");
            for (auto const& child:node.children) {
                auto decoded=decode_kdl_predicate(child,depth+1,count);
                if (!decoded) return std::unexpected(std::move(decoded.error()));
                rule.children.push_back(std::move(*decoded));
            }
        } else if (!has_value || !node.children.empty()) return invalid("predicate requires value and no children");
        return rule;
    }
}
