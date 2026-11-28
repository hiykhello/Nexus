module rules;
import std;
import rules.any_index;

namespace rules {
    auto valid_domain(std::string_view) -> bool;
    auto normalize_set(RuleSet) -> std::expected<RuleSet, Error>;
    namespace {
        auto valid_candidates(ProgramInput const& input) noexcept -> bool {
            if ((input.explicit_domain && input.domain_absent[0]) || (input.fakeip_domain && input.domain_absent[1]) ||
                (input.reverse_domain && input.domain_absent[2]) || (input.sniffed_domain && input.domain_absent[3])) return false;
            if (!input.candidates) return true;
            if (input.ip) return false;
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

        auto to_match_input(ProgramInput const& input, std::optional<std::string_view> domain = {}) noexcept -> MatchInput {
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
                .route_mode = input.route_mode,
                .network_type = input.network_type,
                .network_is_expensive = input.network_is_expensive,
                .network_is_constrained = input.network_is_constrained,
                .wifi_ssid = input.wifi_ssid,
                .wifi_bssid = input.wifi_bssid,
                .default_interface_addresses = input.default_interface_addresses,
                .network_interface_addresses = input.network_interface_addresses,
                .source_gid = input.source_gid,
                .source_user = input.source_user,
                .package_name = input.package_name,
                .client = input.client,
                .ip_bytes = input.ip_bytes,
                .process_paths = input.process_paths,
            };
        }

        struct NormalizedDomains {
            std::array<std::array<char, 253>, 4> storage;
            std::array<std::optional<std::string_view>, 4> views{};
        };

        auto normalize_domains(ProgramInput const& input, NormalizedDomains& out) -> bool {
            std::array<std::optional<std::string_view>, 4> raw{
                input.explicit_domain, input.fakeip_domain, input.reverse_domain, input.sniffed_domain};
            for (std::size_t idx = 0; idx < 4; ++idx) {
                if (!raw[idx]) continue;
                auto d = *raw[idx];
                if (d.ends_with('.')) d.remove_suffix(1);
                if (!valid_domain(d)) return false;
                if (std::ranges::any_of(d, [](char c) { return c >= 'A' && c <= 'Z'; })) {
                    for (std::size_t j = 0; j < d.size(); ++j) {
                        char c = d[j];
                        out.storage[idx][j] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
                    }
                    out.views[idx] = std::string_view(out.storage[idx].data(), d.size());
                } else {
                    out.views[idx] = d;
                }
            }
            return true;
        }

        auto skip_action(ProgramInput const& input, ProgramAction const& action, bool constrained) noexcept -> bool {
            if (action.kind == ProgramActionKind::bypass)
                return !constrained && action.outbound == 0 && !action.bypass_explicit;
            if (action.kind != ProgramActionKind::hijack_dns) return false;
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
        if (candidates && (input.ip || !std::ranges::all_of(*candidates, [](auto const& value) {
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
        bool tail_proc = false, tail_uid = false;
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
            if ((has_evasion || has_udp_opt || has_override) && kind != ProgramActionKind::route_options &&
                kind != ProgramActionKind::route && kind != ProgramActionKind::bypass)
                return std::unexpected(Error{ErrorCode::invalid_rule, "route options require route-options, route or bypass"});
            if (act.udp_timeout_ms && (act.udp_timeout_ms < 1000 || act.udp_timeout_ms > 3600000))
                return std::unexpected(Error{ErrorCode::invalid_rule, "udp-timeout-ms must be 1000..3600000"});
            if ((kind == ProgramActionKind::route_options && !timeout && !has_evasion && !has_udp_opt && !has_override) ||
                (timeout && kind != ProgramActionKind::route_options && kind != ProgramActionKind::route && kind != ProgramActionKind::bypass) ||
                timeout > 3600000)
                return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program connection timeout"});
            switch (kind) {
            case ProgramActionKind::route:
            case ProgramActionKind::bypass:
                if (act.outbound >= outbound_count)
                    return std::unexpected(Error{ErrorCode::invalid_rule, "invalid program outbound"});
                break;
            case ProgramActionKind::hijack_dns:
                program.has_dns_hijack_ = true;
                [[fallthrough]];
            case ProgramActionKind::sniff:
            case ProgramActionKind::resolve:
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
            if (rule.mmap) {
                if (!rule.predicates.rules.empty())
                    return std::unexpected(Error{ErrorCode::invalid_rule, "mmap program rule cannot also carry inline predicates"});
                std::shared_ptr<Matcher const> tail;
                if (rule.mmap->tail_beve_bytes() > 0) {
                    auto dec = parse_beve(rule.mmap->tail_beve());
                    if (!dec) return std::unexpected(std::move(dec.error()));
                    auto cm = Matcher::compile(*dec);
                    if (!cm) return std::unexpected(std::move(cm.error()));
                    tail_proc |= cm->uses_process_;
                    tail_uid |= cm->uses_source_uid_;
                    tail = std::make_shared<Matcher const>(std::move(*cm));
                }
                auto off = flattened.rules.size();
                auto src_idx = rule.source_index.value_or(program.instructions_.size());
                program.instructions_.push_back({off, off, act, rule.domain_source, rule.mmap, std::move(tail),
                    rule.mmap_match_source || rule.mmap->ip_cidr_match_source(), 0, 0, no_index, no_index, 0, src_idx});
                continue;
            }
            for (auto const& predicate : rule.predicates.rules)
                if (!count(count, predicate, 1)) return std::unexpected(Error{ErrorCode::limit, "program rule count exceeds limit"});
            auto normalized = normalize_set(rule.predicates);
            if (!normalized) return std::unexpected(std::move(normalized.error()));
            auto first = flattened.rules.size();
            flattened.version = std::max(flattened.version, normalized->version);
            for (auto& predicate : normalized->rules) flattened.rules.push_back(std::move(predicate));
            auto src_idx = rule.source_index.value_or(program.instructions_.size());
            program.instructions_.push_back({first, flattened.rules.size(), act, rule.domain_source, {}, {}, false,
                0, 0, no_index, no_index, 0, src_idx});
        }
        auto compiled = Matcher::compile(flattened);
        if (!compiled) return std::unexpected(std::move(compiled.error()));
        compiled->uses_process_ |= tail_proc;
        compiled->uses_source_uid_ |= tail_uid;
        program.matcher_ = std::move(*compiled);
        auto const& m = program.matcher_;
        std::size_t unidx_pos = 0;
        for (std::size_t idx = 0; idx < program.instructions_.size(); ++idx) {
            auto& inst = program.instructions_[idx];
            if (inst.mmap || inst.first == inst.last) continue;
            while (unidx_pos < m.unindexed_.size() && m.unindexed_[unidx_pos] < inst.first) ++unidx_pos;
            inst.unindexed_begin = static_cast<std::uint32_t>(unidx_pos);
            while (unidx_pos < m.unindexed_.size() && m.unindexed_[unidx_pos] < inst.last) ++unidx_pos;
            inst.unindexed_end = static_cast<std::uint32_t>(unidx_pos);
            if (inst.unindexed_begin < inst.unindexed_end) inst.flags |= flag_unindexed;
            for (std::size_t r = inst.first; r < inst.last; ++r) {
                auto const& e = m.entries_[m.roots_[r]];
                if (e.kind == Matcher::Kind::domain) inst.flags |= flag_domain_idx | flag_domain_root;
                else if (e.kind == Matcher::Kind::suffix) inst.flags |= flag_suffix_idx | flag_domain_root;
                else if (e.kind == Matcher::Kind::ip) {
                    inst.flags |= flag_ip_root | (e.ip.family == 4 ? flag_ipv4_idx : flag_ipv6_idx);
                }
            }
            if (inst.last - inst.first >= 8) {
                if (auto built = any_detail::build_any_index<Matcher::AnyIndex>(
                        m.entries_, inst.last - inst.first,
                        [&](std::size_t k) { return m.roots_[inst.first + k]; },
                        Matcher::Kind::ip, Matcher::Kind::domain, Matcher::Kind::suffix)) {
                    inst.local_any_index = static_cast<std::uint32_t>(program.local_any_indexes_.size());
                    program.local_any_indexes_.push_back(std::move(*built));
                }
            }
        }
        auto run_eligible = [](Instruction const& inst) noexcept {
            return !inst.mmap && inst.first < inst.last && inst.local_any_index == no_index &&
                !(inst.flags & flag_unindexed) &&
                (inst.action.kind == ProgramActionKind::route || inst.action.kind == ProgramActionKind::reject);
        };
        for (std::size_t i = 0; i < program.instructions_.size();) {
            if (!run_eligible(program.instructions_[i])) { ++i; continue; }
            std::size_t j = i + 1;
            auto src = program.instructions_[i].domain_source;
            while (j < program.instructions_.size() && run_eligible(program.instructions_[j]) &&
                   program.instructions_[j].domain_source == src) ++j;
            if (j - i >= 2) {
                IndexedRun run{i, j, program.instructions_[i].first, program.instructions_[j - 1].last, j, j, src, 0};
                auto run_id = static_cast<std::uint32_t>(program.runs_.size());
                if (program.root_to_instr_.empty()) program.root_to_instr_.resize(m.roots_.size(), no_index);
                for (std::size_t k = i; k < j; ++k) {
                    auto& inst = program.instructions_[k];
                    inst.run_index = run_id;
                    run.flags |= inst.flags;
                    if (run.first_ip_instr == j && (inst.flags & flag_ip_root)) run.first_ip_instr = k;
                    if (run.first_domain_instr == j && (inst.flags & flag_domain_root)) run.first_domain_instr = k;
                    for (std::size_t r = inst.first; r < inst.last; ++r)
                        program.root_to_instr_[r] = static_cast<std::uint32_t>(k);
                }
                program.runs_.push_back(run);
            }
            i = j;
        }
        return program;
    }

    auto RouteProgram::next(ProgramInput input, std::size_t start) const
        -> std::expected<std::optional<ProgramStep>, Error> {
        if (start > instructions_.size() || !valid_candidates(input))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid program cursor"});
        auto prepared = Matcher::prepare(to_match_input(input));
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        NormalizedDomains norm;
        if (!normalize_domains(input, norm))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid ASCII domain"});
        prepared->match_mapped_ipv4 = true;
        prepared->domain_normalized = true;
        prepared->candidates = input.candidates;
        bool const has_ip_value = prepared->input.ip.has_value() ||
            (prepared->candidates && !prepared->candidates->empty());
        for (auto i = start; i < instructions_.size(); ++i) {
            auto const& instruction = instructions_[i];
            if (instruction.run_index != no_index) {
                auto const& run = runs_[instruction.run_index];
                auto src = static_cast<std::size_t>(run.domain_source);
                prepared->input.domain = norm.views[src];
                prepared->domain_absent = input.domain_absent[src];
                std::uint8_t mask = static_cast<std::uint8_t>(run.flags & 0x0fu);
                if (!prepared->input.domain) mask = static_cast<std::uint8_t>(mask & ~0x03u);
                if (!has_ip_value) mask = static_cast<std::uint8_t>(mask & ~0x0cu);
                if (mask) {
                    auto hit = matcher_.first_indexed_match(*prepared, instruction.first, run.root_last, mask);
                    if (hit < run.root_last) {
                        auto win = static_cast<std::size_t>(root_to_instr_[hit]);
                        return std::optional<ProgramStep>(ProgramStep{win, win + 1, instructions_[win].action});
                    }
                }
                i = run.end_instr - 1;
                continue;
            }
            if (skip_action(input, instruction.action, instruction.first != instruction.last || instruction.mmap != nullptr)) continue;
            auto src = static_cast<std::size_t>(instruction.domain_source);
            prepared->input.domain = norm.views[src];
            prepared->domain_absent = input.domain_absent[src];
            bool matches = false;
            if (instruction.mmap) {
                matches = Matcher::eval_mmap(*instruction.mmap, instruction.mmap_tail.get(), *prepared, instruction.mmap_match_source) == Matcher::Truth::yes;
            } else if (instruction.first == instruction.last) {
                matches = true;
            } else if (instruction.local_any_index != no_index) {
                matches = matcher_.eval_any_index(local_any_indexes_[instruction.local_any_index], *prepared) == Matcher::Truth::yes;
            } else if (instruction.last - instruction.first <= 4) {
                for (auto index = instruction.first; index < instruction.last && !matches; ++index)
                    matches = matcher_.evaluate(matcher_.roots_[index], *prepared) == Matcher::Truth::yes;
            } else {
                std::uint8_t mask = static_cast<std::uint8_t>(instruction.flags & 0x0fu);
                if (!prepared->input.domain) mask = static_cast<std::uint8_t>(mask & ~0x03u);
                if (!has_ip_value) mask = static_cast<std::uint8_t>(mask & ~0x0cu);
                auto best = mask ? matcher_.first_indexed_match(*prepared, instruction.first, instruction.last, mask) : instruction.last;
                if (best < instruction.last) matches = true;
                else if (instruction.flags & flag_unindexed) {
                    for (auto u = instruction.unindexed_begin; u < instruction.unindexed_end; ++u) {
                        if (matcher_.evaluate(matcher_.roots_[matcher_.unindexed_[u]], *prepared) == Matcher::Truth::yes) {
                            matches = true;
                            break;
                        }
                    }
                }
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
        NormalizedDomains norm;
        if (!normalize_domains(input, norm))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid ASCII domain"});
        prepared->match_mapped_ipv4 = true;
        prepared->domain_normalized = true;
        prepared->candidates = input.candidates;
        bool const has_ip_value = prepared->input.ip.has_value() ||
            (prepared->candidates && !prepared->candidates->empty());
        bool const ip_unknown = !prepared->input.ip && !prepared->candidates;
        for (auto i = start; i < instructions_.size(); ++i) {
            auto const& instruction = instructions_[i];
            if (instruction.run_index != no_index) {
                auto const& run = runs_[instruction.run_index];
                auto src = static_cast<std::size_t>(run.domain_source);
                prepared->input.domain = norm.views[src];
                prepared->domain_absent = input.domain_absent[src];
                std::size_t earliest_unk = run.end_instr;
                if (ip_unknown && run.first_ip_instr < run.end_instr) {
                    if (i <= run.first_ip_instr) earliest_unk = std::min(earliest_unk, run.first_ip_instr);
                    else {
                        auto it = std::lower_bound(matcher_.ip_roots_.begin(), matcher_.ip_roots_.end(), instruction.first);
                        if (it != matcher_.ip_roots_.end() && *it < run.root_last)
                            earliest_unk = std::min(earliest_unk, static_cast<std::size_t>(root_to_instr_[*it]));
                    }
                }
                if (!prepared->input.domain && !prepared->domain_absent && run.first_domain_instr < run.end_instr) {
                    if (i <= run.first_domain_instr) earliest_unk = std::min(earliest_unk, run.first_domain_instr);
                    else {
                        auto it = std::lower_bound(matcher_.domain_roots_.begin(), matcher_.domain_roots_.end(), instruction.first);
                        if (it != matcher_.domain_roots_.end() && *it < run.root_last)
                            earliest_unk = std::min(earliest_unk, static_cast<std::size_t>(root_to_instr_[*it]));
                    }
                }
                std::uint8_t mask = static_cast<std::uint8_t>(run.flags & 0x0fu);
                if (!prepared->input.domain) mask = static_cast<std::uint8_t>(mask & ~0x03u);
                if (!has_ip_value) mask = static_cast<std::uint8_t>(mask & ~0x0cu);
                auto search_last = earliest_unk < run.end_instr ? instructions_[earliest_unk].last : run.root_last;
                if (mask) {
                    auto hit = matcher_.first_indexed_match(*prepared, instruction.first, search_last, mask);
                    if (hit < search_last) {
                        auto win = static_cast<std::size_t>(root_to_instr_[hit]);
                        return ProgramPreflight{ProgramPreflightKind::step, win, ProgramStep{win, win + 1, instructions_[win].action}};
                    }
                }
                if (earliest_unk < run.end_instr)
                    return ProgramPreflight{ProgramPreflightKind::uncertain, earliest_unk, {}};
                i = run.end_instr - 1;
                continue;
            }
            if (skip_action(input, instruction.action, instruction.first != instruction.last || instruction.mmap != nullptr)) continue;
            auto src = static_cast<std::size_t>(instruction.domain_source);
            prepared->input.domain = norm.views[src];
            prepared->domain_absent = input.domain_absent[src];
            bool yes = false, unknown = false;
            if (instruction.mmap) {
                auto value = Matcher::eval_mmap(*instruction.mmap, instruction.mmap_tail.get(), *prepared, instruction.mmap_match_source);
                yes = value == Matcher::Truth::yes; unknown = value == Matcher::Truth::unknown;
            } else if (instruction.first == instruction.last) {
                yes = true;
            } else if (instruction.local_any_index != no_index) {
                auto value = matcher_.eval_any_index(local_any_indexes_[instruction.local_any_index], *prepared);
                yes = value == Matcher::Truth::yes; unknown = value == Matcher::Truth::unknown;
            } else if (instruction.last - instruction.first <= 4) {
                for (auto index = instruction.first; index < instruction.last && !yes; ++index) {
                    auto value = matcher_.evaluate(matcher_.roots_[index], *prepared);
                    yes = value == Matcher::Truth::yes; unknown |= value == Matcher::Truth::unknown;
                }
            } else {
                std::uint8_t mask = static_cast<std::uint8_t>(instruction.flags & 0x0fu);
                if (!prepared->input.domain) mask = static_cast<std::uint8_t>(mask & ~0x03u);
                if (!has_ip_value) mask = static_cast<std::uint8_t>(mask & ~0x0cu);
                auto best_yes = mask ? matcher_.first_indexed_match(*prepared, instruction.first, instruction.last, mask) : instruction.last;
                if (best_yes < instruction.last) yes = true;
                else {
                    for (auto u = instruction.unindexed_begin; u < instruction.unindexed_end; ++u) {
                        auto value = matcher_.evaluate(matcher_.roots_[matcher_.unindexed_[u]], *prepared);
                        if (value == Matcher::Truth::yes) { yes = true; break; }
                        unknown |= value == Matcher::Truth::unknown;
                    }
                    if (!yes && !unknown) {
                        unknown = (ip_unknown && (instruction.flags & flag_ip_root)) ||
                                  (!prepared->input.domain && !prepared->domain_absent && (instruction.flags & flag_domain_root));
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
}
