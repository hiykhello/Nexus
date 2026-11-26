// Automatic .srs -> .nxmm sidecar compilation cache and zero-copy ordered-program loader.
export module cli.route_files_nxmm;
import std;
import blake3;
import config;
import rules;
import rules.rule_input;
import cli.tun_route_sets;

export namespace cli::nxmm_detail {
    inline constexpr std::uint32_t kNxmmSidecarVersion = 1u;

    [[nodiscard]] inline auto blake3_hex(std::string_view data) -> std::string {
        blake3::blake3_hasher hasher{};
        blake3::blake3_hasher_init(&hasher);
        blake3::blake3_hasher_update(&hasher, data.data(), data.size());
        std::array<std::uint8_t, 32> digest{};
        blake3::blake3_hasher_finalize(&hasher, digest.data(), digest.size());
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (auto b : digest) {
            out.push_back(kHex[b >> 4]);
            out.push_back(kHex[b & 0x0fu]);
        }
        return out;
    }

    [[nodiscard]] inline auto sidecar_path(std::filesystem::path const& cache_dir,
        std::string_view srs_bytes, bool ip_cidr_match_source) -> std::filesystem::path {
        return cache_dir / "nxmm" / std::format("{}-v{}-{}.nxmm",
            blake3_hex(srs_bytes), kNxmmSidecarVersion, ip_cidr_match_source ? "src" : "dst");
    }

    [[nodiscard]] inline auto verify_mmap_usable(rules::MmapMatcher const& mm) -> bool {
        if (!mm.has_domain() && !mm.has_ip() && mm.tail_beve_bytes() == 0) return false;
        if (mm.tail_beve_bytes() > 0 && !rules::parse_beve(mm.tail_beve())) return false;
        return true;
    }

    inline auto write_sidecar_atomic(std::filesystem::path const& path, std::string_view data) noexcept -> bool {
        try {
            std::error_code ec;
            auto dir = path.parent_path();
            if (dir.empty()) return false;
            std::filesystem::create_directories(dir, ec);
            if (ec) return false;
            static std::atomic<std::uint64_t> counter{0};
            auto seq = counter.fetch_add(1, std::memory_order_relaxed);
            auto stamp = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
            auto tmp = dir / std::format("{}.tmp.{}.{}.{}", path.filename().string(), stamp, tid, seq);
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out) return false;
                out.write(data.data(), static_cast<std::streamsize>(data.size()));
                out.flush();
                if (!out.good()) {
                    out.close();
                    std::filesystem::remove(tmp, ec);
                    return false;
                }
            }
            std::filesystem::rename(tmp, path, ec);
            if (ec) {
                std::error_code rm_ec;
                std::filesystem::remove(tmp, rm_ec);
                return std::filesystem::is_regular_file(path, rm_ec) && !rm_ec;
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    // Attempt to open or compile+persist a content-addressed .nxmm sidecar for an .srs blob.
    // Returns nullptr cleanly on read-only/unavailable cache dirs or compilation failure so callers
    // transparently fall back to in-memory RuleSet parsing.
    [[nodiscard]] inline auto try_mmap_srs_sidecar(std::filesystem::path const& cache_dir,
        std::string_view srs_bytes, bool ip_cidr_match_source) -> std::shared_ptr<rules::MmapMatcher const> {
        if (cache_dir.empty() || srs_bytes.empty()) return {};
        auto path = sidecar_path(cache_dir, srs_bytes, ip_cidr_match_source);
        if (auto existing = rules::MmapMatcher::open_file(path.string()); existing && verify_mmap_usable(*existing))
            return std::make_shared<rules::MmapMatcher const>(std::move(*existing));
        auto parsed = rules::parse_rule_input(srs_bytes, rules::InputFormat::srs, ip_cidr_match_source);
        if (!parsed || parsed->rules.empty()) return {};
        auto nxmm = rules::compile_nxmm(*parsed, ip_cidr_match_source);
        if (!nxmm) return {};
        auto check = rules::MmapMatcher::open_bytes(*nxmm);
        if (!check || !verify_mmap_usable(*check)) return {};
        if (!write_sidecar_atomic(path, *nxmm)) return {};
        auto mapped = rules::MmapMatcher::open_file(path.string());
        if (!mapped || !verify_mmap_usable(*mapped)) return {};
        return std::make_shared<rules::MmapMatcher const>(std::move(*mapped));
    }

    inline auto prewarm_srs_sidecar(std::filesystem::path const& cache_dir, std::string_view srs_bytes) noexcept -> void {
        try { (void)try_mmap_srs_sidecar(cache_dir, srs_bytes, false); } catch (...) {}
    }

    inline auto action_for_rule(config::OrderedTcpRule const& rule) noexcept -> rules::ProgramActionKind {
        using A = config::OrderedTcpAction; using K = rules::ProgramActionKind;
        switch (rule.action) {
        case A::sniff: return K::sniff; case A::resolve: return K::resolve; case A::route: return K::route;
        case A::bypass: return rule.outbound_name ? K::route : K::bypass;
        case A::route_options: return K::route_options; case A::hijack_dns: return K::hijack_dns; case A::reject: return K::reject;
        }
        std::unreachable();
    }

    inline auto domain_source_for(config::OrderedTcpDomain domain) noexcept -> rules::DomainSource {
        using D = config::OrderedTcpDomain; using S = rules::DomainSource;
        switch (domain) {
        case D::explicit_target: return S::explicit_target; case D::sniffed: return S::sniffed;
        case D::fakeip: return S::fakeip; case D::reverse_dns: return S::reverse_dns;
        }
        std::unreachable();
    }

    inline auto input_format_for(config::RuleFormat format) noexcept -> rules::InputFormat {
        using C = config::RuleFormat; using I = rules::InputFormat;
        switch (format) {
        case C::kdl: return I::kdl; case C::beve: return I::beve; case C::srs: return I::srs;
        case C::nxmm: return I::nxmm; case C::json: return I::json; case C::domain_list: return I::domain_list;
        case C::ipcidr_list: return I::ipcidr_list; case C::classical: return I::classical; case C::adguard: return I::adguard;
        }
        std::unreachable();
    }

    template<class ReadFn, class HasSeedFn>
    inline auto load_ordered_program(config::Config const& config, bool allows_unfetched_remote,
        ReadFn&& read_file, HasSeedFn&& has_seed,
        std::vector<std::string>& data, std::vector<std::shared_ptr<rules::MmapMatcher const>>& data_mmaps,
        std::vector<rules::ProgramRule>& ordered,
        std::vector<std::pair<std::string, std::vector<std::string>>>& tun_cidrs) -> std::expected<void, std::string> {
        auto try_mmap = [&](config::BlockRules const& file)
            -> std::expected<std::shared_ptr<rules::MmapMatcher const>, std::string> {
            if (file.inline_rules) return std::shared_ptr<rules::MmapMatcher const>{};
            if (file.format != config::RuleFormat::nxmm && file.format != config::RuleFormat::srs)
                return std::shared_ptr<rules::MmapMatcher const>{};
            if (!file.url.empty() && allows_unfetched_remote && !has_seed(file.url))
                return std::shared_ptr<rules::MmapMatcher const>{};
            auto index = read_file(file, true);
            if (!index) return std::unexpected(std::move(index.error()));
            auto mm = data_mmaps[*index];
            if (mm && !mm->has_domain() && !mm->has_ip() && mm->tail_beve_bytes() == 0)
                return std::unexpected("tcp-program rule-set must not be empty");
            return mm;
        };
        auto load = [&](config::BlockRules const& file) -> std::expected<rules::RuleSet, std::string> {
            if (file.inline_rules) {
                if (file.inline_rules->rules.empty()) return std::unexpected("tcp-program rule-set must not be empty");
                return *file.inline_rules;
            }
            if (!file.url.empty() && allows_unfetched_remote && !has_seed(file.url)) {
                rules::RuleSet placeholder{.version = 2};
                placeholder.rules.push_back({"domain", "remote-placeholder.invalid", {}});
                return placeholder;
            }
            auto index = read_file(file, true);
            if (!index) return std::unexpected(std::move(index.error()));
            auto set = data_mmaps[*index]
                ? rules::nxmm_to_ruleset(*data_mmaps[*index])
                : rules::parse_rule_input(data[*index], input_format_for(file.format), file.ip_cidr_match_source);
            if (!set) return std::unexpected(std::move(set.error().message));
            if (set->rules.empty()) return std::unexpected("tcp-program rule-set must not be empty");
            return std::move(*set);
        };
        std::map<std::string_view, rules::RuleSet> loaded;
        std::set<std::string_view> used;
        std::optional<std::string> load_error;
        std::size_t budget = rules::max_rules;
        auto const& sets = config.ordered_tcp->sets;
        auto find_entry = [&](std::string_view tag) {
            return std::ranges::find_if(sets, [&](auto const& item) { return item.first == tag; });
        };
        auto lookup = [&](std::string_view tag) -> rules::RuleSet const* {
            used.insert(tag);
            if (auto previous = loaded.find(tag); previous != loaded.end()) return &previous->second;
            auto found = find_entry(tag);
            if (found == sets.end()) return nullptr;
            auto parsed = load(found->second);
            if (!parsed) { load_error = std::move(parsed.error()); return nullptr; }
            return &loaded.emplace(found->first, std::move(*parsed)).first->second;
        };
        for (auto const& rule : config.ordered_tcp->rules) {
            rules::ProgramAction action{action_for_rule(rule), rule.outbound, rule.connect_timeout_ms, rule.route_only,
                rule.reject_method, rule.reject_no_drop, rule.tls_record_fragment,
                rule.tls_fragment_min, rule.tls_fragment_max, rule.tcp_prefix, rule.tcp_prefix_len,
                rule.udp_timeout_ms, rule.udp_adaptive_timeout, rule.override_address,
                rule.override_port, rule.tls_fragment_fallback_delay_ms,
                rule.extra.resolve_strategy, rule.extra.resolve_server, rule.extra.resolve_disable_cache,
                rule.extra.resolve_rewrite_ttl, rule.extra.resolve_client_subnet,
                rule.extra.sniff_protocols, rule.extra.sniff_override_destination,
                rule.extra.sniff_timeout_ms, rule.extra.udp_disable_domain_unmapping};
            std::shared_ptr<rules::MmapMatcher const> direct_mmap;
            bool direct_mmap_src = false;
            if (rule.file) {
                if (rule.set_tag) used.insert(*rule.set_tag);
                auto mm = try_mmap(*rule.file);
                if (!mm) return std::unexpected(std::move(mm.error()));
                if (*mm) { direct_mmap = std::move(*mm); direct_mmap_src = rule.file->ip_cidr_match_source; }
            } else if (rule.predicates.rules.size() == 1 && rule.predicates.rules[0].type == "rule-set") {
                if (auto found = find_entry(rule.predicates.rules[0].value); found != sets.end()) {
                    auto mm = try_mmap(found->second);
                    if (!mm) return std::unexpected(std::move(mm.error()));
                    if (*mm) {
                        used.insert(found->first);
                        direct_mmap = std::move(*mm);
                        direct_mmap_src = found->second.ip_cidr_match_source;
                    }
                }
            }
            if (direct_mmap) {
                ordered.push_back({rules::RuleSet{.version = 2}, std::move(action),
                    domain_source_for(rule.domain), std::move(direct_mmap), direct_mmap_src});
                continue;
            }
            auto source = &rule.predicates;
            std::optional<rules::RuleSet> mapped;
            if (rule.file) {
                if (rule.set_tag && !rule.file->ip_cidr_match_source) {
                    source = lookup(*rule.set_tag);
                    if (!source) return std::unexpected(load_error.value_or("unknown ordered rule-set"));
                } else {
                    auto parsed = load(*rule.file);
                    if (!parsed) return std::unexpected(std::move(parsed.error()));
                    mapped.emplace(std::move(*parsed));
                    source = &*mapped;
                }
            }
            auto predicates = rules::expand_rule_sets(*source, lookup, budget);
            if (!predicates) return std::unexpected(load_error.value_or(predicates.error().message));
            ordered.push_back({std::move(*predicates), std::move(action), domain_source_for(rule.domain)});
        }
        for (auto const& in : config.inbounds) {
            if (!in.tun) continue;
            for (auto const* list : {&in.tun->route_address_sets, &in.tun->route_exclude_address_sets}) {
                for (auto const& tag : *list) {
                    if (std::ranges::contains(tun_cidrs, tag, &std::pair<std::string, std::vector<std::string>>::first))
                        continue;
                    std::vector<std::string> cidrs;
                    if (auto found = find_entry(tag); found != sets.end()) {
                        auto mm = try_mmap(found->second);
                        if (!mm) return std::unexpected(std::move(mm.error()));
                        if (*mm) {
                            used.insert(found->first);
                            if (auto ok = detail::collect_ip_cidrs_mmap(**mm, cidrs, true, true); !ok)
                                return std::unexpected(std::move(ok.error()));
                            tun_cidrs.emplace_back(tag, std::move(cidrs));
                            continue;
                        }
                    }
                    auto const* src = lookup(tag);
                    if (!src) return std::unexpected(load_error.value_or("unknown TUN rule-set: " + tag));
                    detail::collect_ip_cidrs(*src, cidrs, true, true);
                    tun_cidrs.emplace_back(tag, std::move(cidrs));
                }
            }
        }
        for (auto const& [tag, file] : sets)
            if (!used.contains(tag)) return std::unexpected("unreferenced rule-set: " + tag);
        data.clear();
        data_mmaps.clear();
        return {};
    }

    inline auto apply_tun_route_sets_impl(config::TunInbound& tun,
        std::vector<std::pair<std::string, std::vector<std::string>>> const& tun_cidrs)
        -> std::expected<void, std::string> {
        auto add_from = [&](std::vector<std::string> const& tags, std::vector<std::string>& dst, std::size_t cap)
            -> std::expected<void, std::string> {
            std::unordered_set<std::string> seen(dst.begin(), dst.end());
            for (auto const& tag : tags) {
                auto it = std::ranges::find(tun_cidrs, tag, &std::pair<std::string, std::vector<std::string>>::first);
                if (it == tun_cidrs.end()) continue;
                for (auto const& cidr : it->second) {
                    if (dst.size() >= cap) break;
                    if (!(cidr.contains(':') ? tun.inet6_address : tun.inet4_address)) continue;
                    if (seen.insert(cidr).second) dst.push_back(cidr);
                }
            }
            return {};
        };
        if (auto ok = add_from(tun.route_address_sets, tun.route_includes, detail::max_tun_route_cidrs); !ok) return ok;
        if (auto ok = add_from(tun.route_exclude_address_sets, tun.route_excludes, detail::max_tun_route_cidrs); !ok) return ok;
        return {};
    }
}
