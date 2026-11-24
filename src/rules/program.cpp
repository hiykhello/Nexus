module rules;
import std;

namespace rules {
    auto valid_domain(std::string_view) -> bool;
    auto normalize_set(RuleSet) -> std::expected<RuleSet, Error>;
    namespace {
        auto valid_candidates(ProgramInput const& input) noexcept -> bool {
            if ((input.explicit_domain && input.domain_absent[0]) || (input.fakeip_domain && input.domain_absent[1]) ||
                (input.reverse_domain && input.domain_absent[2]) || (input.sniffed_domain && input.domain_absent[3])) return false;
            if (!input.candidates) return true;
            if (input.ip || input.candidates->size() > 256) return false;
            return std::ranges::all_of(*input.candidates, [](auto const& value) {
                return (value.size == 4 && std::ranges::all_of(std::span(value.bytes).subspan(4), [](auto byte) { return byte == 0; })) ||
                       value.size == 16;
            });
        }

        auto valid_subnet_prefix(SubnetPrefix const& subnet) noexcept -> bool {
            if ((subnet.size != 4 && subnet.size != 16) || subnet.bits > subnet.size * 8) return false;
            auto bytes = (std::size_t(subnet.bits) + 7) / 8;
            if (subnet.bits % 8 && (subnet.address[bytes - 1] & ((1u << (8 - subnet.bits % 8)) - 1u))) return false;
            return std::ranges::all_of(std::span(subnet.address).subspan(bytes), [](auto c) { return c == 0; });
        }

        auto to_match_input(ProgramInput const& input, std::optional<std::string_view> domain = {}, bool include_route_mode = true) noexcept -> MatchInput {
            return {
                .domain = domain,
                .ip = input.ip,
                .port = input.port,
                .network = input.network,
                .source_ip = input.source_ip,
                .source_port = input.source_port,
                .source_ip_bytes = input.source_ip_bytes,
                .inbound = input.inbound,
                .auth_user = input.auth_user,
                .protocol = input.protocol,
                .source_uid = input.source_uid,
                .process_path = input.process_path,
                .source_interface = input.source_interface,
                .tls_ech = input.tls_ech,
                .dscp = input.dscp,
                .source_mac = input.source_mac,
                .gateway_mac = input.gateway_mac,
                .route_mode = include_route_mode ? input.route_mode : std::nullopt,
                .network_type = input.network_type,
                .network_is_expensive = input.network_is_expensive,
                .network_is_constrained = input.network_is_constrained,
                .wifi_ssid = input.wifi_ssid,
                .wifi_bssid = input.wifi_bssid,
                .default_interface_addresses = input.default_interface_addresses,
                .source_gid = input.source_gid,
                .source_user = input.source_user,
                .package_name = input.package_name,
                .client = input.client,
            };
        }

        auto strip_root(ProgramInput& input) noexcept -> void {
            for (auto* field : {&input.explicit_domain, &input.fakeip_domain, &input.reverse_domain, &input.sniffed_domain})
                if (*field && (*field)->ends_with('.')) (*field)->remove_suffix(1);
        }

        auto skip_action(ProgramInput const& input, ProgramActionKind kind, bool constrained) noexcept -> bool {
            if (kind == ProgramActionKind::bypass) return true;
            if (kind != ProgramActionKind::hijack_dns) return false;
            if (input.network == Network::udp)
                return input.dns_query == false || (input.port != 53 && !constrained);
            return input.network != Network::tcp || !input.dns_hijack_tcp;
        }
    }

    auto Matcher::match(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error> {
        auto prepared = prepare(input);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        return first_match(*prepared);
    }

    auto Matcher::match_mapped(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error> {
        auto prepared = prepare(input);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        prepared->match_mapped_ipv4 = true;
        return first_match(*prepared);
    }

    auto Matcher::match_truth_mapped(MatchInput input, std::optional<std::span<ProgramAddress const>> candidates) const -> std::expected<Truth, Error> {
        if (roots_.size() != 1) return std::unexpected(Error{ErrorCode::invalid_query, "truth requires one root"});
        if (candidates && (input.ip || candidates->size() > 16384 || !std::ranges::all_of(*candidates, [](auto const& value) {
            return (value.size == 4 && std::ranges::all_of(std::span(value.bytes).subspan(4), [](auto byte) { return byte == 0; })) || value.size == 16;
        }))) return std::unexpected(Error{ErrorCode::invalid_query, "invalid candidate addresses"});
        auto prepared = prepare(input);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        prepared->match_mapped_ipv4 = true;
        prepared->candidates = candidates;
        return evaluate(roots_[0], *prepared);
    }

    auto RouteProgram::compile(std::span<ProgramRule const> rules, std::size_t outbound_count)
        -> std::expected<RouteProgram, Error> {
        if (!outbound_count || rules.size() > max_rules)
            return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program size or outbound count"});
        std::size_t nodes = 0;
        auto count = [&](auto&& self, Rule const& rule, unsigned depth) -> bool {
            if (depth > max_rule_depth || ++nodes > max_rules) return false;
            for (auto const& child : rule.children) if (!self(self, child, depth + 1)) return false;
            return true;
        };
        RouteProgram program;
        RuleSet flattened{.version = 2};
        program.instructions_.reserve(rules.size());
        for (auto const& rule : rules) {
            auto const& act = rule.action;
            auto kind = act.kind;
            auto timeout = act.connect_timeout_ms;
            bool has_evasion = act.tls_record_fragment || act.tcp_prefix_len > 0;
            bool has_udp_opt = act.udp_timeout_ms > 0 || act.udp_adaptive_timeout || act.udp_disable_domain_unmapping;
            bool has_override = act.override_address.has_value() || act.override_port > 0;
            bool has_reject_opts = act.reject_method != RejectMethod::default_rst || act.reject_no_drop;
            bool has_resolve_opts = act.route_only || act.resolve_strategy.has_value() ||
                act.resolve_server.has_value() || act.resolve_disable_cache.has_value() ||
                act.resolve_rewrite_ttl.has_value() || act.resolve_client_subnet.has_value();
            bool has_sniff_opts = act.sniff_protocols != 0 || act.sniff_override_destination || act.sniff_timeout_ms > 0;
            if (has_resolve_opts && kind != ProgramActionKind::resolve)
                return std::unexpected(Error{ErrorCode::invalid_rule, "resolve options require resolve action"});
            if (act.resolve_client_subnet && !valid_subnet_prefix(*act.resolve_client_subnet))
                return std::unexpected(Error{ErrorCode::invalid_rule, "invalid resolve client-subnet"});
            if (has_sniff_opts && kind != ProgramActionKind::sniff)
                return std::unexpected(Error{ErrorCode::invalid_rule, "sniff options require sniff action"});
            if (act.sniff_timeout_ms > 10000)
                return std::unexpected(Error{ErrorCode::invalid_rule, "sniff-timeout-ms must be <= 10000"});
            if (has_reject_opts && kind != ProgramActionKind::reject)
                return std::unexpected(Error{ErrorCode::invalid_rule, "reject options require reject action"});
            if (act.tcp_prefix_len > act.tcp_prefix.size())
                return std::unexpected(Error{ErrorCode::invalid_rule, "tcp-prefix exceeds 64 bytes"});
            if (act.tls_fragment_fallback_delay_ms > 10000 ||
                (act.tls_fragment_fallback_delay_ms && !act.tls_record_fragment))
                return std::unexpected(Error{ErrorCode::invalid_rule, "invalid tls-fragment-fallback-delay-ms"});
            if ((has_evasion || has_udp_opt || has_override) && kind != ProgramActionKind::route_options && kind != ProgramActionKind::route)
                return std::unexpected(Error{ErrorCode::invalid_rule, "route options require route-options or route"});
            if (act.udp_timeout_ms && (act.udp_timeout_ms < 1000 || act.udp_timeout_ms > 3600000))
                return std::unexpected(Error{ErrorCode::invalid_rule, "udp-timeout-ms must be 1000..3600000"});
            if ((kind == ProgramActionKind::route_options && !timeout && !has_evasion && !has_udp_opt && !has_override) ||
                (timeout && kind != ProgramActionKind::route_options && kind != ProgramActionKind::route) ||
                timeout > 3600000)
                return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program connection timeout"});
            switch (kind) {
            case ProgramActionKind::route:
                if (act.outbound >= outbound_count)
                    return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program outbound"});
                break;
            case ProgramActionKind::hijack_dns:
                program.has_dns_hijack_ = true;
                [[fallthrough]];
            case ProgramActionKind::sniff:
            case ProgramActionKind::resolve:
            case ProgramActionKind::bypass:
            case ProgramActionKind::route_options:
            case ProgramActionKind::reject:
                if (act.outbound != 0)
                    return std::unexpected(Error{ErrorCode::invalid_rule, "unexpected program outbound"});
                break;
            default:
                return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program action"});
            }
            if (rule.domain_source != DomainSource::explicit_target && rule.domain_source != DomainSource::fakeip &&
                rule.domain_source != DomainSource::reverse_dns && rule.domain_source != DomainSource::sniffed)
                return std::unexpected(Error{ErrorCode::invalid_rule, "invalid domain source"});
            for (auto const& predicate : rule.predicates.rules)
                if (!count(count, predicate, 1)) return std::unexpected(Error{ErrorCode::limit, "program rule count exceeds limit"});
            auto normalized = normalize_set(rule.predicates);
            if (!normalized) return std::unexpected(std::move(normalized.error()));
            auto first = flattened.rules.size();
            flattened.version = std::max(flattened.version, normalized->version);
            for (auto& predicate : normalized->rules) flattened.rules.push_back(std::move(predicate));
            program.instructions_.push_back({first, flattened.rules.size(), act, rule.domain_source});
        }
        auto compiled = Matcher::compile(flattened);
        if (!compiled) return std::unexpected(std::move(compiled.error()));
        program.matcher_ = std::move(*compiled);
        return program;
    }

    auto RouteProgram::next(ProgramInput input, std::size_t start) const
        -> std::expected<std::optional<ProgramStep>, Error> {
        if (start > instructions_.size() || !valid_candidates(input))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid program cursor"});
        auto prepared = Matcher::prepare(to_match_input(input));
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        strip_root(input);
        for (auto domain : {input.explicit_domain, input.fakeip_domain, input.reverse_domain, input.sniffed_domain})
            if (domain && !valid_domain(*domain))
                return std::unexpected(Error{ErrorCode::invalid_query, "invalid ASCII domain"});
        prepared->match_mapped_ipv4 = true;
        prepared->candidates = input.candidates;
        for (auto i = start; i < instructions_.size(); ++i) {
            auto const& instruction = instructions_[i];
            if (skip_action(input, instruction.action.kind, instruction.first != instruction.last || instruction.mmap != nullptr)) continue;
            switch (instruction.domain_source) {
            case DomainSource::explicit_target: prepared->input.domain = input.explicit_domain; break;
            case DomainSource::fakeip: prepared->input.domain = input.fakeip_domain; break;
            case DomainSource::reverse_dns: prepared->input.domain = input.reverse_domain; break;
            case DomainSource::sniffed: prepared->input.domain = input.sniffed_domain; break;
            }
            prepared->domain_absent = input.domain_absent[static_cast<std::size_t>(instruction.domain_source)];
            bool matches = false;
            if (instruction.mmap) {
                matches = Matcher::eval_mmap(*instruction.mmap, instruction.mmap_tail.get(), *prepared, instruction.mmap_match_source) == Matcher::Truth::yes;
            } else {
                matches = instruction.first == instruction.last;
                if (input.candidates) {
                    for (auto index = instruction.first; index < instruction.last && !matches; ++index)
                        matches = matcher_.evaluate(matcher_.roots_[index], *prepared) == Matcher::Truth::yes;
                } else matches |= matcher_.first_match(*prepared, instruction.first, instruction.last).has_value();
            }
            if (matches)
                return std::optional<ProgramStep>(ProgramStep{i, i + 1, instruction.action});
        }
        return std::optional<ProgramStep>{};
    }

    auto RouteProgram::preflight(ProgramInput input, std::size_t start) const -> std::expected<ProgramPreflight, Error> {
        if (start > instructions_.size() || !valid_candidates(input))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid program cursor or candidates"});
        auto prepared = Matcher::prepare(to_match_input(input));
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        strip_root(input);
        for (auto domain : {input.explicit_domain, input.fakeip_domain, input.reverse_domain, input.sniffed_domain})
            if (domain && !valid_domain(*domain)) return std::unexpected(Error{ErrorCode::invalid_query, "invalid ASCII domain"});
        prepared->match_mapped_ipv4 = true;
        prepared->candidates = input.candidates;
        for (auto i = start; i < instructions_.size(); ++i) {
            auto const& instruction = instructions_[i];
            if (skip_action(input, instruction.action.kind, instruction.first != instruction.last || instruction.mmap != nullptr)) continue;
            switch (instruction.domain_source) {
            case DomainSource::explicit_target: prepared->input.domain = input.explicit_domain; break;
            case DomainSource::fakeip: prepared->input.domain = input.fakeip_domain; break;
            case DomainSource::reverse_dns: prepared->input.domain = input.reverse_domain; break;
            case DomainSource::sniffed: prepared->input.domain = input.sniffed_domain; break;
            }
            prepared->domain_absent = input.domain_absent[static_cast<std::size_t>(instruction.domain_source)];
            bool yes = false, unknown = false;
            if (instruction.mmap) {
                auto value = Matcher::eval_mmap(*instruction.mmap, instruction.mmap_tail.get(), *prepared, instruction.mmap_match_source);
                yes = value == Matcher::Truth::yes; unknown = value == Matcher::Truth::unknown;
            } else if (instruction.first == instruction.last) {
                yes = true;
            } else if (input.candidates || instruction.last - instruction.first <= 4) {
                for (auto index = instruction.first; index < instruction.last && !yes; ++index) {
                    auto value = matcher_.evaluate(matcher_.roots_[index], *prepared);
                    yes = value == Matcher::Truth::yes; unknown |= value == Matcher::Truth::unknown;
                }
            } else {
                auto best_yes = matcher_.first_indexed_match(*prepared, instruction.first, instruction.last);
                if (best_yes < instruction.last) yes = true;
                else {
                    for (auto it = std::lower_bound(matcher_.unindexed_.begin(), matcher_.unindexed_.end(), instruction.first);
                         it != matcher_.unindexed_.end() && *it < instruction.last; ++it) {
                        auto value = matcher_.evaluate(matcher_.roots_[*it], *prepared);
                        if (value == Matcher::Truth::yes) { yes = true; break; }
                        unknown |= value == Matcher::Truth::unknown;
                    }
                    if (!yes && !unknown) {
                        unknown = (!prepared->input.ip && matcher_.has_ip_root(instruction.first, instruction.last)) ||
                                  (!prepared->input.domain && !prepared->domain_absent && matcher_.has_domain_root(instruction.first, instruction.last));
                    }
                }
            }
            if (yes) return ProgramPreflight{ProgramPreflightKind::step, i, ProgramStep{i, i + 1, instruction.action}};
            if (unknown) return ProgramPreflight{ProgramPreflightKind::uncertain, i, {}};
        }
        return ProgramPreflight{ProgramPreflightKind::exhausted, instructions_.size(), {}};
    }

    auto ProgramCursor::poll(RouteProgram const& program, ProgramInput input, bool wait_unknown) -> std::expected<ProgramPreflight, Error> {
        if (terminal_ || pending_) return std::unexpected(Error{ErrorCode::invalid_query, "program cursor is not ready"});
        if (program_ && program_ != &program) return std::unexpected(Error{ErrorCode::invalid_query, "program cursor belongs to another program"});
        program_ = &program;
        uncertain_.reset();
        ProgramPreflight result{};
        if (wait_unknown) {
            auto next = program.preflight(input, index_); if (!next) return std::unexpected(std::move(next.error())); result = *next;
        } else {
            auto next = program.next(input, index_); if (!next) return std::unexpected(std::move(next.error()));
            result = *next ? ProgramPreflight{ProgramPreflightKind::step, (**next).rule_index, **next} :
                ProgramPreflight{ProgramPreflightKind::exhausted, program.size(), {}};
        }
        if (result.kind == ProgramPreflightKind::uncertain) uncertain_ = result.rule_index;
        if (result.kind == ProgramPreflightKind::step) {
            if (result.step->terminal()) terminal_ = true;
            else pending_ = *result.step;
        } else if (result.kind == ProgramPreflightKind::exhausted) terminal_ = true;
        return result;
    }

    auto ProgramCursor::complete(ProgramStep const& step) noexcept -> std::expected<void, ProgramCursorError> {
        if (terminal_) return std::unexpected(ProgramCursorError::terminal);
        if (!pending_) return std::unexpected(ProgramCursorError::awaiting_action);
        if (step.rule_index != pending_->rule_index || step.next_index != pending_->next_index ||
            step.action != pending_->action)
            return std::unexpected(ProgramCursorError::stale_action);
        index_ = pending_->next_index; pending_.reset(); return {};
    }

    auto ProgramCursor::skip_unknown(std::size_t rule_index) noexcept -> std::expected<void, ProgramCursorError> {
        if (terminal_) return std::unexpected(ProgramCursorError::terminal);
        if (pending_) return std::unexpected(ProgramCursorError::awaiting_action);
        if (!uncertain_ || *uncertain_ != rule_index) return std::unexpected(ProgramCursorError::stale_uncertainty);
        index_ = rule_index + 1; uncertain_.reset(); return {};
    }

    auto RouteProgram::compile_legacy(std::span<RouteRule const> rules, std::size_t outbound_count)
        -> std::expected<RouteProgram, Error> {
        if (!outbound_count || rules.size() > max_rules)
            return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program size or outbound count"});
        RouteProgram program;
        RuleSet flattened{.version = 2};
        program.instructions_.reserve(rules.size());
        bool tail_proc = false, tail_uid = false;
        for (auto const& rule : rules) {
            if (rule.outbound >= outbound_count) return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program outbound"});
            if (rule.mmap) {
                std::shared_ptr<Matcher const> tail;
                if (rule.mmap->tail_beve_bytes() > 0) {
                    auto dec = parse_beve(rule.mmap->tail_beve());
                    if (!dec) return std::unexpected(std::move(dec.error()));
                    auto cm = Matcher::compile(*dec);
                    if (!cm) return std::unexpected(std::move(cm.error()));
                    tail_proc |= cm->uses_process_; tail_uid |= cm->uses_source_uid_;
                    tail = std::make_shared<Matcher const>(std::move(*cm));
                }
                auto off = flattened.rules.size();
                program.instructions_.push_back({off, off, {ProgramActionKind::route, rule.outbound},
                    DomainSource::explicit_target, rule.mmap, std::move(tail), rule.mmap_match_source || rule.mmap->ip_cidr_match_source()});
                continue;
            }
            auto norm = normalize_set(rule.predicates);
            if (!norm) return std::unexpected(std::move(norm.error()));
            auto first = flattened.rules.size();
            flattened.version = std::max(flattened.version, norm->version);
            for (auto& pred : norm->rules) flattened.rules.push_back(std::move(pred));
            program.instructions_.push_back({first, flattened.rules.size(), {ProgramActionKind::route, rule.outbound}, DomainSource::explicit_target});
        }
        auto compiled = Matcher::compile(flattened);
        if (!compiled) return std::unexpected(std::move(compiled.error()));
        compiled->uses_process_ |= tail_proc; compiled->uses_source_uid_ |= tail_uid;
        program.matcher_ = std::move(*compiled);
        return program;
    }

    auto LegacyRouteProgram::compile(std::span<RouteRule const> rules, std::size_t default_outbound,
        std::size_t outbound_count, SourceMetadata source, std::optional<std::string_view> inbound, AuthMetadata auth)
        -> std::expected<LegacyRouteProgram, Error> {
        auto matcher = RouteMatcher::compile(rules, default_outbound, outbound_count, source, inbound, auth);
        if (!matcher) return std::unexpected(std::move(matcher.error()));
        auto program = RouteProgram::compile_legacy(rules, outbound_count);
        if (!program) return std::unexpected(std::move(program.error()));
        LegacyRouteProgram result;
        result.matcher_ = std::move(*matcher); result.program_ = std::move(*program); result.default_outbound_ = default_outbound;
        return result;
    }

    auto LegacyRouteProgram::preflight_program(ProgramInput input) const -> std::expected<std::optional<std::size_t>, Error> {
        if (input.candidates) return std::unexpected(Error{ErrorCode::invalid_query, "legacy preflight requires one address"});
        return matcher_.preflight(to_match_input(input, input.explicit_domain, false));
    }

    auto LegacyRouteProgram::match(MatchInput input) const -> std::expected<std::size_t, Error> {
        ProgramInput pin{
            .explicit_domain = input.domain, .ip = input.ip, .port = input.port, .network = input.network,
            .source_ip = input.source_ip, .source_port = input.source_port, .source_ip_bytes = input.source_ip_bytes,
            .inbound = input.inbound, .auth_user = input.auth_user, .protocol = input.protocol,
            .source_uid = input.source_uid, .process_path = input.process_path,
            .source_interface = input.source_interface, .tls_ech = input.tls_ech,
            .dscp = input.dscp, .source_mac = input.source_mac, .gateway_mac = input.gateway_mac,
            .network_type = input.network_type, .network_is_expensive = input.network_is_expensive,
            .network_is_constrained = input.network_is_constrained, .wifi_ssid = input.wifi_ssid,
            .wifi_bssid = input.wifi_bssid, .default_interface_addresses = input.default_interface_addresses,
            .source_gid = input.source_gid, .source_user = input.source_user,
            .package_name = input.package_name, .client = input.client
        };
        auto step = next(pin);
        if (!step) return std::unexpected(std::move(step.error()));
        return step->action.outbound;
    }

    auto LegacyRouteProgram::next(ProgramInput input, std::size_t start) const -> std::expected<ProgramStep, Error> {
        if (input.candidates) return std::unexpected(Error{ErrorCode::invalid_query, "legacy routing requires one address"});
        if (auto inbound = matcher_.inbound()) {
            if (input.inbound && *input.inbound != *inbound) return std::unexpected(Error{ErrorCode::invalid_query, "conflicting inbound name"});
            input.inbound = *inbound;
        }
        input.fakeip_domain.reset(); input.reverse_domain.reset(); input.sniffed_domain.reset();
        auto step = program_.next(input, start);
        if (!step) return std::unexpected(std::move(step.error()));
        if (*step) return **step;
        return ProgramStep{program_.size(), program_.size(), {ProgramActionKind::route, default_outbound_}};
    }
}
