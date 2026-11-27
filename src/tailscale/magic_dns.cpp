module tailscale.magic_dns;
import std;
import glaze;
import tailscale.control_messages;
import tailscale.snapshot;

namespace tailscale::magic_dns {
    namespace detail {
        struct ResolverWire {
            std::string Addr;
            std::vector<std::string> BootstrapResolution;
            bool UseWithExitNode = false;
        };

        struct DnsConfigWire {
            std::vector<ResolverWire> Resolvers;
            std::vector<ResolverWire> FallbackResolvers;
            std::vector<std::string> Nameservers;
            std::vector<std::string> Domains;
            std::unordered_map<std::string, std::vector<ResolverWire>> Routes;
            bool Proxied = false;
        };
    }

    namespace {
        using detail::ResolverWire;
        using detail::DnsConfigWire;

        inline constexpr auto lenient_opts = [] {
            glaze::opts o{};
            o.null_terminated = false;
            o.error_on_unknown_keys = false;
            return o;
        }();

        auto parse_port_str(std::string_view ps) noexcept -> std::optional<std::uint16_t> {
            unsigned p = 0;
            auto [end, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), p);
            if (ec != std::errc{} || end != ps.data() + ps.size() || !p || p > 65535) return std::nullopt;
            return static_cast<std::uint16_t>(p);
        }

        auto parse_endpoint(std::string_view raw, bool use_with_exit_node) -> std::optional<ResolverEndpoint> {
            while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t')) raw.remove_prefix(1);
            while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t')) raw.remove_suffix(1);
            if (raw.empty()) return std::nullopt;
            if (raw.starts_with("https://") || raw.starts_with("http://") || raw.starts_with("tls://")) {
                std::uint16_t port = raw.starts_with("http://") ? 80u : (raw.starts_with("tls://") ? 853u : 443u);
                auto rest = raw.substr(raw.find("://") + 3);
                auto slash = rest.find('/');
                auto auth = (slash == std::string_view::npos) ? rest : rest.substr(0, slash);
                if (auth.empty()) return std::nullopt;
                if (auth.front() == '[') {
                    auto close = auth.find(']');
                    if (close == std::string_view::npos) return std::nullopt;
                    if (close + 1 < auth.size()) {
                        if (auth[close + 1] != ':') return std::nullopt;
                        auto p = parse_port_str(auth.substr(close + 2));
                        if (!p) return std::nullopt;
                        port = *p;
                    }
                } else if (auto colon = auth.rfind(':'); colon != std::string_view::npos && auth.find(':') == colon) {
                    auto p = parse_port_str(auth.substr(colon + 1));
                    if (!p) return std::nullopt;
                    port = *p;
                }
                return ResolverEndpoint{std::string(raw), port, false, use_with_exit_node};
            }
            std::uint16_t port = 53;
            std::string host;
            if (raw.front() == '[') {
                auto close = raw.find(']');
                if (close == std::string_view::npos) return std::nullopt;
                host = std::string(raw.substr(1, close - 1));
                if (close + 1 < raw.size()) {
                    if (raw[close + 1] != ':') return std::nullopt;
                    auto p = parse_port_str(raw.substr(close + 2));
                    if (!p) return std::nullopt;
                    port = *p;
                }
            } else {
                auto first_colon = raw.find(':');
                auto last_colon = raw.rfind(':');
                if (first_colon != std::string_view::npos && first_colon == last_colon) {
                    host = std::string(raw.substr(0, first_colon));
                    auto p = parse_port_str(raw.substr(first_colon + 1));
                    if (!p) return std::nullopt;
                    port = *p;
                } else {
                    host = std::string(raw);
                }
            }
            if (host.empty()) return std::nullopt;
            return ResolverEndpoint{std::move(host), port, false, use_with_exit_node};
        }

        auto label_suffix_match(std::string_view name, std::string_view suffix) noexcept -> bool {
            if (suffix.empty() || name.size() < suffix.size()) return false;
            if (name == suffix) return true;
            if (!name.ends_with(suffix)) return false;
            return name[name.size() - suffix.size() - 1] == '.';
        }

        auto short_label(std::string_view fqdn) -> std::string {
            auto dot = fqdn.find('.');
            return std::string(dot == std::string_view::npos ? fqdn : fqdn.substr(0, dot));
        }

        auto append_peer_records(snapshot::Peer const& peer, std::string_view suffix,
                                 std::unordered_map<std::string, HostRecord>& by_fqdn,
                                 std::unordered_map<std::string, std::string>& by_short) -> void {
            if (!peer.machine_authorized || peer.expired || peer.dns_name.empty()) return;
            auto fqdn = normalize_name(peer.dns_name);
            if (fqdn.empty()) return;
            if (!fqdn.contains('.') && !suffix.empty()) {
                fqdn.push_back('.');
                fqdn.append(suffix);
            }
            HostRecord rec;
            rec.fqdn = fqdn;
            rec.short_name = short_label(fqdn);
            for (auto const& addr : peer.addresses) {
                if (addr.family == 4 && addr.bits == 32) {
                    std::array<std::uint8_t, 4> v4{};
                    std::copy_n(addr.address.begin(), 4, v4.begin());
                    rec.ipv4.push_back(v4);
                } else if (addr.family == 6 && addr.bits == 128) {
                    rec.ipv6.push_back(addr.address);
                }
            }
            if (rec.ipv4.empty() && rec.ipv6.empty()) return;
            if (!rec.short_name.empty()) by_short.try_emplace(rec.short_name, rec.fqdn);
            by_fqdn.insert_or_assign(rec.fqdn, std::move(rec));
        }

        auto filter_answers(HostRecord const& rec, QueryType qtype, ResolveResult& out) -> void {
            out.authoritative_local = true;
            if (qtype == QueryType::a || qtype == QueryType::any) out.ipv4 = rec.ipv4;
            if (qtype == QueryType::aaaa || qtype == QueryType::any) out.ipv6 = rec.ipv6;
        }

        auto select_from_config(DnsConfig const& cfg, std::string_view norm, bool via_exit_node)
            -> std::vector<ResolverEndpoint> {
            std::vector<ResolverEndpoint> const* best = nullptr;
            std::size_t best_len = 0;
            for (auto const& [domain, eps] : cfg.split_routes) {
                if (eps.empty()) continue;
                if (label_suffix_match(norm, domain) && domain.size() > best_len) {
                    best = &eps;
                    best_len = domain.size();
                }
            }
            auto filter_exit = [&](std::vector<ResolverEndpoint> const& list) {
                std::vector<ResolverEndpoint> out;
                for (auto const& ep : list) {
                    if (!via_exit_node || ep.use_with_exit_node) out.push_back(ep);
                }
                return out;
            };
            if (best) {
                if (!via_exit_node) return *best;
                auto filtered = filter_exit(*best);
                if (!filtered.empty()) return filtered;
                return *best;
            }
            if (!cfg.resolvers.empty()) {
                if (!via_exit_node) return cfg.resolvers;
                auto filtered = filter_exit(cfg.resolvers);
                if (!filtered.empty()) return filtered;
                auto fb = filter_exit(cfg.fallback_resolvers);
                if (!fb.empty()) return fb;
                if (!cfg.fallback_resolvers.empty()) return cfg.fallback_resolvers;
                return cfg.resolvers;
            }
            if (via_exit_node) {
                auto fb = filter_exit(cfg.fallback_resolvers);
                if (!fb.empty()) return fb;
            }
            return cfg.fallback_resolvers;
        }
    }

    auto normalize_name(std::string_view name) -> std::string {
        while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) name.remove_prefix(1);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t' || name.back() == '.'))
            name.remove_suffix(1);
        std::string out(name.size(), '\0');
        for (std::size_t i = 0; i < name.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(name[i]);
            out[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
        }
        return out;
    }

    auto apply_dns_delta(std::optional<DnsConfig>& target, cm::JsonField dns_config,
                         cm::JsonField domain) noexcept -> std::expected<void, cm::Failure> {
        if (dns_config.presence == cm::Presence::missing && domain.presence == cm::Presence::missing)
            return {};
        try {
            std::optional<std::string> parsed_domain;
            if (domain.presence == cm::Presence::value) {
                std::string dom;
                if (glaze::read<lenient_opts>(dom, domain.json))
                    return std::unexpected(cm::Failure{cm::Error::schema});
                parsed_domain = normalize_name(dom);
            }

            if (dns_config.presence == cm::Presence::value) {
                DnsConfigWire wire;
                if (glaze::read<lenient_opts>(wire, dns_config.json))
                    return std::unexpected(cm::Failure{cm::Error::schema});
                DnsConfig next;
                next.proxied = wire.Proxied;
                for (auto const& d : wire.Domains) {
                    auto norm = normalize_name(d);
                    if (!norm.empty()) next.search_domains.push_back(std::move(norm));
                }
                if (parsed_domain) {
                    next.magic_dns_suffix = *parsed_domain;
                } else if (domain.presence == cm::Presence::missing && target && !target->magic_dns_suffix.empty()) {
                    next.magic_dns_suffix = target->magic_dns_suffix;
                }
                if (next.magic_dns_suffix.empty() && !next.search_domains.empty())
                    next.magic_dns_suffix = next.search_domains.front();
                for (auto const& r : wire.Resolvers) {
                    if (auto ep = parse_endpoint(r.Addr, r.UseWithExitNode))
                        next.resolvers.push_back(std::move(*ep));
                }
                for (auto const& ns : wire.Nameservers) {
                    if (auto ep = parse_endpoint(ns, false)) {
                        if (std::ranges::find(next.resolvers, *ep) == next.resolvers.end())
                            next.resolvers.push_back(std::move(*ep));
                    }
                }
                for (auto const& r : wire.FallbackResolvers) {
                    if (auto ep = parse_endpoint(r.Addr, r.UseWithExitNode))
                        next.fallback_resolvers.push_back(std::move(*ep));
                }
                for (auto const& [route_domain, resolvers] : wire.Routes) {
                    auto norm = normalize_name(route_domain);
                    if (norm.empty()) continue;
                    std::vector<ResolverEndpoint> eps;
                    for (auto const& r : resolvers) {
                        if (auto ep = parse_endpoint(r.Addr, r.UseWithExitNode))
                            eps.push_back(std::move(*ep));
                    }
                    next.split_routes.insert_or_assign(std::move(norm), std::move(eps));
                }
                target = std::move(next);
            } else if (dns_config.presence == cm::Presence::null_value) {
                if (parsed_domain) {
                    DnsConfig cleared;
                    cleared.magic_dns_suffix = std::move(*parsed_domain);
                    target = std::move(cleared);
                } else {
                    target.reset();
                }
            } else {
                // DNSConfig omitted: preserve existing resolvers/routes/search_domains/proxied.
                if (parsed_domain) {
                    if (!target) target.emplace();
                    target->magic_dns_suffix = std::move(*parsed_domain);
                } else if (domain.presence == cm::Presence::null_value && target) {
                    target->magic_dns_suffix = target->search_domains.empty()
                        ? std::string{} : target->search_domains.front();
                }
            }
            return {};
        } catch (...) {
            return std::unexpected(cm::Failure{cm::Error::limit});
        }
    }

    auto parse_dns_config(cm::JsonField dns_config, cm::JsonField domain) noexcept
        -> std::expected<std::optional<DnsConfig>, cm::Failure> {
        if (dns_config.presence != cm::Presence::value && domain.presence != cm::Presence::value)
            return std::nullopt;
        std::optional<DnsConfig> out;
        auto applied = apply_dns_delta(out, dns_config, domain);
        if (!applied) return std::unexpected(applied.error());
        return out;
    }

    auto Resolver::update(DnsConfig config, std::span<snapshot::Peer const> peers,
                          snapshot::Peer const* self) -> std::uint64_t {
        auto snap = std::make_shared<Snapshot>();
        snap->config = std::move(config);
        if (self) append_peer_records(*self, snap->config.magic_dns_suffix, snap->by_fqdn, snap->by_short);
        for (auto const& peer : peers)
            append_peer_records(peer, snap->config.magic_dns_suffix, snap->by_fqdn, snap->by_short);
        std::lock_guard lock(mutex_);
        snap->generation = ++generation_;
        current_ = std::move(snap);
        return generation_;
    }

    auto Resolver::clear() noexcept -> void {
        std::lock_guard lock(mutex_);
        current_.reset();
    }

    auto Resolver::ready() const noexcept -> bool {
        std::lock_guard lock(mutex_);
        return current_ != nullptr;
    }

    auto Resolver::generation() const noexcept -> std::uint64_t {
        std::lock_guard lock(mutex_);
        return current_ ? current_->generation : 0;
    }

    auto Resolver::magic_dns_suffix() const -> std::string {
        std::shared_ptr<Snapshot const> snap;
        { std::lock_guard lock(mutex_); snap = current_; }
        return snap ? snap->config.magic_dns_suffix : std::string{};
    }

    auto Resolver::proxied() const noexcept -> bool {
        std::lock_guard lock(mutex_);
        return current_ && current_->config.proxied;
    }

    auto Resolver::resolve(std::string_view qname, QueryType qtype) const -> ResolveResult {
        std::shared_ptr<Snapshot const> snap;
        { std::lock_guard lock(mutex_); snap = current_; }
        ResolveResult out;
        if (!snap) return out;
        auto norm = normalize_name(qname);
        if (norm.empty()) return out;

        if (auto it = snap->by_fqdn.find(norm); it != snap->by_fqdn.end()) {
            filter_answers(it->second, qtype, out);
            return out;
        }
        if (snap->config.proxied && !norm.contains('.')) {
            if (auto sit = snap->by_short.find(norm); sit != snap->by_short.end()) {
                if (auto fit = snap->by_fqdn.find(sit->second); fit != snap->by_fqdn.end()) {
                    filter_answers(fit->second, qtype, out);
                    return out;
                }
            }
        }
        if (snap->config.proxied && !snap->config.magic_dns_suffix.empty() &&
            label_suffix_match(norm, snap->config.magic_dns_suffix)) {
            out.authoritative_local = true;
            out.nxdomain = true;
            return out;
        }
        out.upstreams = select_from_config(snap->config, norm, false);
        return out;
    }

    auto Resolver::select_upstreams(std::string_view qname, bool via_exit_node) const
        -> std::vector<ResolverEndpoint> {
        std::shared_ptr<Snapshot const> snap;
        { std::lock_guard lock(mutex_); snap = current_; }
        if (!snap) return {};
        auto norm = normalize_name(qname);
        if (norm.empty()) return {};
        return select_from_config(snap->config, norm, via_exit_node);
    }
}
