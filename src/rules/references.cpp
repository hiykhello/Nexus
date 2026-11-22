module rules;
import std;

namespace rules {
    auto expand_rule_sets(RuleSet const& source,RuleSetLookup lookup,std::size_t& remaining)
        -> std::expected<RuleSet,Error> {
        std::vector<std::string_view> chain;
        auto budget=std::min(remaining,static_cast<std::size_t>(max_rules));
        auto limit=std::unexpected(Error{ErrorCode::limit,"expanded rule nesting or count exceeds limit"});
        auto expand=[&](auto&& self,Rule const& rule,unsigned depth) -> std::expected<Rule,Error> {
            if (depth>max_rule_depth || !budget) return limit;
            --budget;
            if (rule.type=="rule-set") {
                auto tag=std::string_view(rule.value);
                if (!rule.children.empty() || tag.empty() || tag.size()>255 || tag.contains('\0'))
                    return std::unexpected(Error{ErrorCode::invalid_rule,"invalid rule-set reference"});
                if (std::ranges::find(chain,tag)!=chain.end())
                    return std::unexpected(Error{ErrorCode::invalid_rule,"cyclic rule-set reference: "+rule.value});
                auto* source=lookup(tag);
                if (!source || source->rules.empty())
                    return std::unexpected(Error{ErrorCode::invalid_rule,"unknown or empty rule-set: "+rule.value});
                chain.push_back(tag);
                Rule expanded{"or",{},{}};
                for (auto const& operand:source->rules) {
                    auto child=self(self,operand,depth+1);
                    if (!child) return child;
                    expanded.children.push_back(std::move(*child));
                }
                chain.pop_back();
                if (expanded.children.size()==1) return std::move(expanded.children.front());
                return expanded;
            }
            Rule result{rule.type,rule.value,{}};
            for (auto const& operand:rule.children) {
                auto child=self(self,operand,depth+1);
                if (!child) return child;
                result.children.push_back(std::move(*child));
            }
            return result;
        };
        RuleSet result{.version=source.version};
        for (auto const& rule:source.rules) {
            auto item=expand(expand,rule,1);
            if (!item) return std::unexpected(std::move(item.error()));
            result.rules.push_back(std::move(*item));
        }
        remaining=budget;
        return result;
    }
}
