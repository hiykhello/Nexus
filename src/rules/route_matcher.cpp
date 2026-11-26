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
        bool has_mmap = std::ranges::any_of(rules, [](auto const& r) { return r.mmap != nullptr; });
        std::size_t total_predicates = 0;
        for (std::size_t index=0;index<rules.size();++index) {
            auto const& rule=rules[index];
            if (rule.outbound>=outbound_count)
                return std::unexpected(Error{ErrorCode::invalid_rule,"invalid route rule or action"});
            if (rule.mmap) {
                bool match_src = rule.mmap_match_source || rule.mmap->ip_cidr_match_source();
                if (source!=SourceMetadata::provided && match_src && rule.mmap->has_ip())
                    return std::unexpected(Error{ErrorCode::invalid_rule,"source metadata is not yet available in production routing"});
                result.needs_source_ |= match_src && rule.mmap->has_ip();
                std::optional<Matcher> tail;
                if (rule.mmap->tail_beve_bytes() > 0) {
                    auto dec = parse_beve(rule.mmap->tail_beve());
                    if (!dec) return std::unexpected(std::move(dec.error()));
                    bool ns = false, na = false, ni = false, np = false;
                    auto visit=[&](auto&& self,Rule const& node) -> void {
                        ns |= (node.type.starts_with("source-") && node.type!="source-mac") ||
                            node.type=="process-name" || node.type=="process-path" ||
                            node.type=="process-path-regex" || node.type=="package-name" ||
                            node.type=="package-name-regex";
                        na |= node.type=="auth-user"; ni |= node.type=="inbound";
                        np |= node.type=="protocol" || node.type=="tls-ech" || node.type=="client";
                        for (auto const& c : node.children) self(self, c);
                    };
                    for (auto const& n : dec->rules) visit(visit, n);
                    if (np) return std::unexpected(Error{ErrorCode::invalid_rule,"protocol rules require an ordered routing program"});
                    if (source!=SourceMetadata::provided && ns) return std::unexpected(Error{ErrorCode::invalid_rule,"source metadata is not yet available in production routing"});
                    if (auth!=AuthMetadata::provided && na) return std::unexpected(Error{ErrorCode::invalid_rule,"authenticated user metadata is not available"});
                    if (ni && !inbound) return std::unexpected(Error{ErrorCode::invalid_rule,"inbound metadata is not available"});
                    result.needs_source_ |= ns; result.needs_auth_user_ |= na;
                    auto cm = Matcher::compile(*dec);
                    if (!cm) return std::unexpected(std::move(cm.error()));
                    result.matcher_.uses_process_ |= cm->uses_process_;
                    result.matcher_.uses_source_uid_ |= cm->uses_source_uid_;
                    tail.emplace(std::move(*cm));
                }
                auto source_index=rule.source_index.value_or(index);
                result.stages_.push_back({true, rule.outbound, source_index, rule.mmap, std::move(tail), match_src, 0, 0});
                continue;
            }
            bool needs_source=false,needs_auth=false,needs_inbound=false,needs_protocol=false;
            auto visit=[&](auto&& self,Rule const& node) -> void {
                needs_source |= (node.type.starts_with("source-") && node.type!="source-mac") ||
                    node.type=="process-name" || node.type=="process-path" ||
                    node.type=="process-path-regex" || node.type=="package-name" ||
                    node.type=="package-name-regex";
                needs_auth |= node.type=="auth-user";
                needs_inbound |= node.type=="inbound";
                needs_protocol |= node.type=="protocol" || node.type=="tls-ech" || node.type=="client";
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
            if (rule.predicates.rules.empty() || rule.predicates.rules.size()>max_rules-total_predicates)
                return std::unexpected(Error{ErrorCode::invalid_rule,"invalid route rule or action"});
            total_predicates += rule.predicates.rules.size();
            auto validated=normalize_set(rule.predicates);
            if (!validated) return std::unexpected(std::move(validated.error()));
            flattened.version=std::max(flattened.version,validated->version);
            auto first = result.actions_.size();
            auto source_index=rule.source_index.value_or(index);
            for (std::size_t predicate=0;predicate<validated->rules.size();++predicate) {
                result.actions_.push_back({rule.outbound,source_index,predicate});
                flattened.rules.push_back(std::move(validated->rules[predicate]));
            }
            if (has_mmap) {
                if (!result.stages_.empty() && !result.stages_.back().is_mmap && result.stages_.back().last == first)
                    result.stages_.back().last = result.actions_.size();
                else
                    result.stages_.push_back({false, 0, 0, {}, {}, false, first, result.actions_.size()});
            }
        }
        auto matcher=Matcher::compile(flattened);
        if (!matcher) return std::unexpected(std::move(matcher.error()));
        if (has_mmap) {
            matcher->uses_process_ |= result.matcher_.uses_process_;
            matcher->uses_source_uid_ |= result.matcher_.uses_source_uid_;
        }
        result.matcher_=std::move(*matcher);
        auto build_runs = [&](std::vector<std::size_t> const& roots, std::vector<UnknownRun>& runs) {
            for (auto idx : roots) {
                auto outbound = result.actions_[idx].outbound;
                if (!runs.empty() && runs.back().outbound == outbound &&
                    result.actions_[idx].rule == result.actions_[runs.back().last - 1].rule)
                    runs.back().last = idx + 1;
                else if (!runs.empty() && runs.back().outbound == outbound && runs.back().last == idx &&
                         result.stages_.empty())
                    runs.back().last = idx + 1;
                else
                    runs.push_back({idx, idx + 1, outbound});
            }
        };
        build_runs(result.matcher_.ip_roots_, result.ip_runs_);
        build_runs(result.matcher_.domain_roots_, result.domain_runs_);
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
        if (mode_state_) {
            auto m=mode_state_->mode.load(std::memory_order_acquire);
            if (!input.route_mode) input.route_mode=m;
            if (m==RouteMode::direct) return std::optional<std::size_t>{0};
            if (m==RouteMode::global) {
                auto target=mode_state_->global_outbound.load(std::memory_order_acquire);
                auto host=input.domain.value_or(input.ip.value_or(""));
                if (distribution_ && target>=distribution_->physical_count && host.empty()) return std::optional<std::size_t>{};
                return std::optional<std::size_t>(choose_outbound(target,host));
            }
        }
        auto prepared=Matcher::prepare(input);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        if (empty_rules()) {
            auto host = input.domain.value_or(input.ip.value_or(""));
            if (distribution_ && default_outbound_ >= distribution_->physical_count && host.empty())
                return std::optional<std::size_t>{};
            return std::optional<std::size_t>(choose_outbound(default_outbound_, host));
        }
        prepared->match_mapped_ipv4=true;
        std::optional<std::size_t> uncertain;
        auto host = input.domain.value_or(input.ip.value_or(""));
        auto scan_range = [&](std::size_t first, std::size_t last) -> std::expected<std::optional<std::size_t>, bool> {
            // std::unexpected(false) means uncertain conflict -> return nullopt immediately; std::nullopt means continue next stage.
            if (last - first <= 4) {
                for (std::size_t i = first; i < last; ++i) {
                    auto value = matcher_.evaluate(matcher_.roots_[i], *prepared);
                    if (value == Matcher::Truth::no) continue;
                    auto outbound = actions_[i].outbound;
                    if (uncertain && *uncertain != outbound) return std::unexpected(false);
                    if (value == Matcher::Truth::unknown) uncertain = outbound;
                    else return std::optional<std::size_t>(choose_outbound(outbound, host));
                }
                return std::optional<std::size_t>{};
            }
            auto best_yes = matcher_.first_indexed_match(*prepared, first, last);
            for (auto it = std::lower_bound(matcher_.unindexed_.begin(), matcher_.unindexed_.end(), first);
                 it != matcher_.unindexed_.end() && *it < best_yes; ++it) {
                auto value = matcher_.evaluate(matcher_.roots_[*it], *prepared);
                if (value == Matcher::Truth::no) continue;
                auto outbound = actions_[*it].outbound;
                if (uncertain && *uncertain != outbound) return std::unexpected(false);
                if (value == Matcher::Truth::unknown) uncertain = outbound;
                else { best_yes = *it; break; }
            }
            auto merge_runs = [&](std::vector<UnknownRun> const& runs) noexcept -> bool {
                auto it = std::lower_bound(runs.begin(), runs.end(), first,
                    [](UnknownRun const& run, std::size_t f) { return run.last <= f; });
                for (; it != runs.end() && it->first < best_yes; ++it) {
                    if (uncertain && *uncertain != it->outbound) return false;
                    uncertain = it->outbound;
                }
                return true;
            };
            if (!prepared->input.ip && !prepared->candidates && !merge_runs(ip_runs_))
                return std::unexpected(false);
            if (!prepared->input.domain && !prepared->domain_absent && !merge_runs(domain_runs_))
                return std::unexpected(false);
            if (best_yes < last) {
                auto outbound = actions_[best_yes].outbound;
                if (uncertain && *uncertain != outbound) return std::unexpected(false);
                return std::optional<std::size_t>(choose_outbound(outbound, host));
            }
            return std::optional<std::size_t>{};
        };
        if (!stages_.empty()) {
            for (auto const& st : stages_) {
                if (st.is_mmap) {
                    auto value = Matcher::eval_mmap(*st.mmap, st.tail ? &*st.tail : nullptr, *prepared, st.match_source);
                    if (value == Matcher::Truth::no) continue;
                    if (uncertain && *uncertain != st.outbound) return std::optional<std::size_t>{};
                    if (value == Matcher::Truth::unknown) uncertain = st.outbound;
                    else return std::optional<std::size_t>(choose_outbound(st.outbound, host));
                } else {
                    auto stepped = scan_range(st.first, st.last);
                    if (!stepped) return std::optional<std::size_t>{};
                    if (*stepped) return *stepped;
                }
            }
        } else {
            auto stepped = scan_range(0, matcher_.roots_.size());
            if (!stepped) return std::optional<std::size_t>{};
            if (*stepped) return *stepped;
        }
        if (uncertain && *uncertain != default_outbound_) return std::optional<std::size_t>{};
        return std::optional<std::size_t>(choose_outbound(default_outbound_, host));
    }
    auto RouteMatcher::match_with_rule(MatchInput input) const -> std::expected<MatchedRoute,Error> {
        if (inbound_) {
            if (input.inbound && *input.inbound!=*inbound_) return std::unexpected(Error{ErrorCode::invalid_query,"conflicting inbound name"});
            input.inbound=*inbound_;
        }
        if (mode_state_) {
            auto m=mode_state_->mode.load(std::memory_order_acquire);
            if (!input.route_mode) input.route_mode=m;
            if (m==RouteMode::direct) return MatchedRoute{0,{},{}};
            if (m==RouteMode::global) {
                auto host=input.domain.value_or(input.ip.value_or(""));
                return MatchedRoute{choose_outbound(mode_state_->global_outbound.load(std::memory_order_acquire),host),{},{}};
            }
        }
        auto prepared=Matcher::prepare(input);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        auto host=input.domain.value_or(input.ip.value_or(""));
        if (empty_rules()) return MatchedRoute{choose_outbound(default_outbound_, host), {}, {}};
        prepared->match_mapped_ipv4=true;
        if (!stages_.empty()) {
            for (auto const& st : stages_) {
                if (st.is_mmap) {
                    if (Matcher::eval_mmap(*st.mmap, st.tail ? &*st.tail : nullptr, *prepared, st.match_source) == Matcher::Truth::yes)
                        return MatchedRoute{choose_outbound(st.outbound, host), st.rule, 0};
                } else if (auto m = matcher_.first_match(*prepared, st.first, st.last)) {
                    auto const& action = actions_[*m];
                    return MatchedRoute{choose_outbound(action.outbound, host), action.rule, action.predicate};
                }
            }
            return MatchedRoute{choose_outbound(default_outbound_, host), {}, {}};
        }
        auto matched=matcher_.first_match(*prepared);
        if (!matched) return MatchedRoute{choose_outbound(default_outbound_,host),{},{}};
        auto const& action=actions_[*matched];
        return MatchedRoute{choose_outbound(action.outbound,host),action.rule,action.predicate};
    }
}
