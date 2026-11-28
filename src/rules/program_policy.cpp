// Stateless policy compilation and direct outbound resolution on unified RouteProgram.
module rules;
import std;

namespace rules {
    namespace {
        auto to_program_input(MatchInput const& in) noexcept -> ProgramInput {
            return ProgramInput{
                .explicit_domain = in.domain,
                .ip = in.ip,
                .port = in.port,
                .network = in.network,
                .source_ip = in.source_ip,
                .source_port = in.source_port,
                .source_ip_bytes = in.source_ip_bytes,
                .inbound = in.inbound,
                .auth_user = in.auth_user,
                .protocol = in.protocol,
                .source_uid = in.source_uid,
                .process_path = in.process_path,
                .source_interface = in.source_interface,
                .tls_ech = in.tls_ech,
                .dscp = in.dscp,
                .source_mac = in.source_mac,
                .gateway_mac = in.gateway_mac,
                .route_mode = in.route_mode,
                .network_type = in.network_type,
                .network_is_expensive = in.network_is_expensive,
                .network_is_constrained = in.network_is_constrained,
                .wifi_ssid = in.wifi_ssid,
                .wifi_bssid = in.wifi_bssid,
                .default_interface_addresses = in.default_interface_addresses,
                .network_interface_addresses = in.network_interface_addresses,
                .source_gid = in.source_gid,
                .source_user = in.source_user,
                .package_name = in.package_name,
                .client = in.client,
                .ip_bytes = in.ip_bytes,
                .process_paths = in.process_paths,
            };
        }

        auto action_outbound(ProgramAction const& action) noexcept -> std::size_t {
            return action.kind == ProgramActionKind::reject ? std::size_t{1} : action.outbound;
        }
    }

    auto RouteProgram::compile_policy(std::span<ProgramRule const> rules, std::size_t default_outbound,
        std::size_t outbound_count, SourceMetadata source, std::optional<std::string_view> inbound,
        AuthMetadata auth) -> std::expected<RouteProgram, Error> {
        if (!outbound_count || default_outbound >= outbound_count || rules.size() > max_rules)
            return std::unexpected(Error{ErrorCode::invalid_rule, "invalid route action or rule count"});
        std::optional<std::string> bound_inbound;
        if (inbound) {
            if (inbound->empty() || inbound->size() > 255 || inbound->find('\0') != std::string_view::npos)
                return std::unexpected(Error{ErrorCode::invalid_rule, "invalid inbound metadata"});
            bound_inbound = std::string(*inbound);
        }
        bool needs_source = false, needs_auth = false;
        auto scan_tree = [&](RuleSet const& set) -> std::expected<void, Error> {
            bool ns = false, na = false, ni = false;
            auto visit = [&](auto&& self, Rule const& node) -> void {
                ns |= (node.type.starts_with("source-") && node.type != "source-mac") ||
                    node.type == "process-name" || node.type == "process-path" ||
                    node.type == "process-path-regex" || node.type == "package-name" ||
                    node.type == "package-name-regex";
                na |= node.type == "auth-user";
                ni |= node.type == "inbound";
                for (auto const& c : node.children) self(self, c);
            };
            for (auto const& n : set.rules) visit(visit, n);
            if (source != SourceMetadata::provided && ns)
                return std::unexpected(Error{ErrorCode::invalid_rule, "source metadata is not yet available in production routing"});
            if (auth != AuthMetadata::provided && na)
                return std::unexpected(Error{ErrorCode::invalid_rule, "authenticated user metadata is not available"});
            if (ni && !bound_inbound)
                return std::unexpected(Error{ErrorCode::invalid_rule, "inbound metadata is not available"});
            needs_source |= ns;
            needs_auth |= na;
            return {};
        };
        for (auto const& rule : rules) {
            if (rule.mmap) {
                bool match_src = rule.mmap_match_source || rule.mmap->ip_cidr_match_source();
                if (source != SourceMetadata::provided && match_src && rule.mmap->has_ip())
                    return std::unexpected(Error{ErrorCode::invalid_rule, "source metadata is not yet available in production routing"});
                needs_source |= match_src && rule.mmap->has_ip();
                if (rule.mmap->tail_beve_bytes() > 0) {
                    auto dec = parse_beve(rule.mmap->tail_beve());
                    if (!dec) return std::unexpected(std::move(dec.error()));
                    if (auto ok = scan_tree(*dec); !ok) return std::unexpected(std::move(ok.error()));
                }
            } else {
                if (auto ok = scan_tree(rule.predicates); !ok) return std::unexpected(std::move(ok.error()));
            }
        }
        auto compiled = compile(rules, outbound_count);
        if (!compiled) return std::unexpected(std::move(compiled.error()));
        compiled->default_outbound_ = default_outbound;
        compiled->inbound_ = std::move(bound_inbound);
        compiled->needs_source_ = needs_source;
        compiled->needs_auth_user_ = needs_auth;
        return compiled;
    }

    auto RouteProgram::preflight(std::string_view domain) const
        -> std::expected<std::optional<std::size_t>, Error> {
        return preflight(MatchInput{.domain = domain});
    }

    auto RouteProgram::preflight(MatchInput input) const
        -> std::expected<std::optional<std::size_t>, Error> {
        if (inbound_) {
            if (input.inbound && *input.inbound != *inbound_)
                return std::unexpected(Error{ErrorCode::invalid_query, "conflicting inbound name"});
            input.inbound = *inbound_;
        }
        auto host = input.domain.value_or(input.ip.value_or(""));
        if (mode_state_) {
            auto m = mode_state_->mode.load(std::memory_order_acquire);
            if (!input.route_mode) input.route_mode = m;
            if (m == RouteMode::direct) return std::optional<std::size_t>{0};
            if (m == RouteMode::global) {
                auto target = mode_state_->global_outbound.load(std::memory_order_acquire);
                if (distribution_ && target >= distribution_->physical_count && host.empty())
                    return std::optional<std::size_t>{};
                return std::optional<std::size_t>(choose_outbound(target, host));
            }
        }
        if (empty_rules()) {
            auto valid = Matcher::prepare(input);
            if (!valid) return std::unexpected(std::move(valid.error()));
            if (distribution_ && default_outbound_ >= distribution_->physical_count && host.empty())
                return std::optional<std::size_t>{};
            return std::optional<std::size_t>(choose_outbound(default_outbound_, host));
        }
        auto prog_in = to_program_input(input);
        std::optional<std::size_t> uncertain;
        for (std::size_t pos = 0; pos < instructions_.size();) {
            auto pf = preflight(prog_in, pos);
            if (!pf) return std::unexpected(std::move(pf.error()));
            if (pf->kind == ProgramPreflightKind::exhausted) break;
            if (pf->kind == ProgramPreflightKind::uncertain) {
                auto const& act = instructions_[pf->rule_index].action;
                if (act.kind != ProgramActionKind::route && act.kind != ProgramActionKind::bypass &&
                    act.kind != ProgramActionKind::reject)
                    return std::optional<std::size_t>{};
                auto out = action_outbound(act);
                if (uncertain && *uncertain != out) return std::optional<std::size_t>{};
                uncertain = out;
                pos = pf->rule_index + 1;
                continue;
            }
            auto const& step = *pf->step;
            if (step.action.kind != ProgramActionKind::route && step.action.kind != ProgramActionKind::bypass &&
                step.action.kind != ProgramActionKind::reject)
                return std::optional<std::size_t>{};
            auto out = action_outbound(step.action);
            if (uncertain && *uncertain != out) return std::optional<std::size_t>{};
            if (distribution_ && out >= distribution_->physical_count && host.empty())
                return std::optional<std::size_t>{};
            return std::optional<std::size_t>(choose_outbound(out, host));
        }
        if (uncertain && *uncertain != default_outbound_) return std::optional<std::size_t>{};
        if (distribution_ && default_outbound_ >= distribution_->physical_count && host.empty())
            return std::optional<std::size_t>{};
        return std::optional<std::size_t>(choose_outbound(default_outbound_, host));
    }

    auto RouteProgram::match_with_rule(MatchInput input) const -> std::expected<MatchedRoute, Error> {
        if (inbound_) {
            if (input.inbound && *input.inbound != *inbound_)
                return std::unexpected(Error{ErrorCode::invalid_query, "conflicting inbound name"});
            input.inbound = *inbound_;
        }
        auto host = input.domain.value_or(input.ip.value_or(""));
        if (mode_state_) {
            auto m = mode_state_->mode.load(std::memory_order_acquire);
            if (!input.route_mode) input.route_mode = m;
            if (m == RouteMode::direct) return MatchedRoute{0, {}, {}};
            if (m == RouteMode::global) {
                return MatchedRoute{
                    choose_outbound(mode_state_->global_outbound.load(std::memory_order_acquire), host), {}, {}};
            }
        }
        if (empty_rules()) {
            auto valid = Matcher::prepare(input);
            if (!valid) return std::unexpected(std::move(valid.error()));
            return MatchedRoute{choose_outbound(default_outbound_, host), {}, {}};
        }
        auto prog_in = to_program_input(input);
        for (std::size_t pos = 0; pos < instructions_.size();) {
            auto step = next(prog_in, pos);
            if (!step) return std::unexpected(std::move(step.error()));
            if (!*step) break;
            auto const& act = (*step)->action;
            if (act.kind == ProgramActionKind::route || act.kind == ProgramActionKind::bypass ||
                act.kind == ProgramActionKind::reject) {
                auto out = action_outbound(act);
                return MatchedRoute{choose_outbound(out, host), instructions_[(*step)->rule_index].source_index, 0};
            }
            pos = (*step)->next_index;
        }
        return MatchedRoute{choose_outbound(default_outbound_, host), {}, {}};
    }
}
