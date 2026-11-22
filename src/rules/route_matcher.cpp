module rules;
import std;

namespace rules {
    auto RouteMatcher::compile(std::span<RouteRule const> rules, std::size_t default_outbound,
                               std::size_t outbound_count,SourceMetadata source,std::optional<std::string_view> inbound,AuthMetadata auth) -> std::expected<RouteMatcher, Error> {
        if (!outbound_count || default_outbound>=outbound_count || rules.size()>max_rules)
            return std::unexpected(Error{ErrorCode::invalid_rule,"invalid route action or rule count"});
        RuleSet flattened;
        RouteMatcher result;
        result.default_outbound_=default_outbound;
        if (inbound) {
            if (inbound->empty() || inbound->size()>255 || inbound->find('\0')!=std::string_view::npos)
                return std::unexpected(Error{ErrorCode::invalid_rule,"invalid inbound metadata"});
            result.inbound_=std::string(*inbound);
        }
        for (std::size_t index=0;index<rules.size();++index) {
            auto const& rule=rules[index];
            bool needs_source=false,needs_auth=false,needs_inbound=false,needs_protocol=false;
            auto visit=[&](auto&& self,Rule const& node) -> void {
                needs_source |= (node.type.starts_with("source-") && node.type!="source-mac") || node.type=="process-name" || node.type=="process-path" || node.type=="process-path-regex";
                needs_auth |= node.type=="auth-user";
                needs_inbound |= node.type=="inbound";
                needs_protocol |= node.type=="protocol" || node.type=="tls-ech";
                for(auto const& child:node.children)self(self,child);
            };
            for(auto const& node:rule.predicates.rules)visit(visit,node);
            if (needs_protocol)
                return std::unexpected(Error{ErrorCode::invalid_rule,"protocol rules require an ordered routing program"});
            if (source!=SourceMetadata::provided && needs_source)
                return std::unexpected(Error{ErrorCode::invalid_rule,"source metadata is not yet available in production routing"});
            if (auth!=AuthMetadata::provided && needs_auth)
                return std::unexpected(Error{ErrorCode::invalid_rule,"authenticated user metadata is not available"});
            if (needs_inbound && !inbound)
                return std::unexpected(Error{ErrorCode::invalid_rule,"inbound metadata is not available"});
            result.needs_source_ |= needs_source;
            result.needs_auth_user_ |= needs_auth;
            if (rule.outbound>=outbound_count || rule.predicates.rules.empty() ||
                rule.predicates.rules.size()>max_rules-flattened.rules.size())
                return std::unexpected(Error{ErrorCode::invalid_rule,"invalid route rule or action"});
            auto validated=normalize_set(rule.predicates);
            if (!validated) return std::unexpected(std::move(validated.error()));
            flattened.version=std::max(flattened.version,validated->version);
            auto source_index=rule.source_index.value_or(index);
            for (std::size_t predicate=0;predicate<validated->rules.size();++predicate) {
                result.actions_.push_back({rule.outbound,source_index,predicate});
                flattened.rules.push_back(std::move(validated->rules[predicate]));
            }
        }
        auto matcher=Matcher::compile(flattened);
        if (!matcher) return std::unexpected(std::move(matcher.error()));
        result.matcher_=std::move(*matcher);
        return result;
    }
    auto RouteMatcher::preflight(std::string_view domain) const -> std::expected<std::optional<std::size_t>, Error> {
        return preflight(MatchInput{.domain=domain});
    }
    auto RouteMatcher::preflight(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error> {
        if (inbound_) {
            if (input.inbound && *input.inbound!=*inbound_) return std::unexpected(Error{ErrorCode::invalid_query,"conflicting inbound name"});
            input.inbound=*inbound_;
        }
        auto prepared=Matcher::prepare(input);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        prepared->match_mapped_ipv4=true;
        std::optional<std::size_t> uncertain;
        for (std::size_t i=0;i<matcher_.roots_.size();++i) {
            auto value=matcher_.evaluate(matcher_.roots_[i],*prepared);
            if (value==Matcher::Truth::no) continue;
            auto outbound=actions_[i].outbound;
            if (uncertain && *uncertain!=outbound) return std::optional<std::size_t>{};
            if (value==Matcher::Truth::unknown) {
                uncertain=outbound;
            } else {
                return std::optional<std::size_t>(choose_outbound(outbound,input.domain.value_or(input.ip.value_or(""))));
            }
        }
        if (uncertain && *uncertain!=default_outbound_) return std::optional<std::size_t>{};
        return std::optional<std::size_t>(choose_outbound(default_outbound_,input.domain.value_or(input.ip.value_or(""))));
    }
    auto RouteMatcher::match_with_rule(MatchInput input) const -> std::expected<MatchedRoute,Error> {
        if (inbound_) {
            if (input.inbound && *input.inbound!=*inbound_) return std::unexpected(Error{ErrorCode::invalid_query,"conflicting inbound name"});
            input.inbound=*inbound_;
        }
        auto prepared=Matcher::prepare(input);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        prepared->match_mapped_ipv4=true;
        auto matched=matcher_.first_match(*prepared);
        auto host=input.domain.value_or(input.ip.value_or(""));
        if (!matched) return MatchedRoute{choose_outbound(default_outbound_,host),{},{}};
        auto const& action=actions_[*matched];
        return MatchedRoute{choose_outbound(action.outbound,host),action.rule,action.predicate};
    }
}
