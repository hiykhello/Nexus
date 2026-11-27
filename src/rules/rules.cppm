export module rules;
import std;
import functional;
import rules.regex;
export import :mmap;
export import :types;

export namespace rules {
    [[nodiscard]] auto parse_protocol(std::string_view) noexcept -> std::optional<Protocol>;
    [[nodiscard]] auto parse_protocol_list(std::string_view) noexcept -> std::optional<std::uint32_t>;
    // Domain predicates accept ASCII hostnames, a stricter subset than DNS
    // wire labels. Metadata outside this subset remains unknown.
    [[nodiscard]] auto valid_domain(std::string_view name) -> bool;
    [[nodiscard]] auto valid_source_interface(std::string_view) noexcept -> bool;
    [[nodiscard]] auto valid_client_name(std::string_view) noexcept -> bool;
    [[nodiscard]] auto parse_source_uid(std::string_view) noexcept -> std::optional<std::uint32_t>;
    [[nodiscard]] auto is_private_address(std::span<std::uint8_t const> address) noexcept -> bool;
    [[nodiscard]] auto parse_mac(std::string_view) noexcept -> std::optional<MacAddress>;
    [[nodiscard]] auto parse_dscp(std::string_view) noexcept -> std::optional<std::uint8_t>;
    [[nodiscard]] auto parse_dscp_list(std::string_view) noexcept -> std::optional<std::uint64_t>;

    class Matcher {
    public:
        enum class Truth { no, yes, unknown };
    private:
        enum class Kind {
            suffix, domain, keyword, wildcard, inbound, auth_user, process_name, process_path,
            domain_regex, process_path_regex, package_name_regex, source_interface, ip, source_ip, ip_version,
            ip_is_private, source_private, ip_is_cgnat, source_cgnat, ip_accept_any, source_ip_accept_any,
            port, source_port, source_uid, source_gid, source_user, package_name,
            network, network_type, network_is_expensive, network_is_constrained,
            wifi_ssid, wifi_bssid, default_interface_ip, network_interface_ip,
            query_type, protocol, client, tls_ech, dscp, source_mac, gateway_mac, route_mode,
            all, any, negate
        };
        struct IpPredicate { std::array<std::uint8_t, 16> address; unsigned prefix, family; };
        struct NetworkInterfaceIp { std::array<std::uint8_t, 16> address; std::uint8_t prefix, family; NetworkType type; };
        struct PortPredicate { std::uint16_t first, last; };
        struct ChildRange { std::uint32_t first, count, any_index = std::numeric_limits<std::uint32_t>::max(); };
        struct Entry {
            Kind kind = Kind::suffix;
            // Only trivial payloads share storage; kind selects the active one.
            union {
                IpPredicate ip{};
                NetworkInterfaceIp net_if_ip;
                PortPredicate port;
                Network network;
                Protocol protocol;
                ChildRange children;
                std::string_view text;
                std::uint8_t ip_version;
                std::uint16_t query_type;
                std::uint32_t source_uid;
                std::uint32_t regex;
                bool offered;
                std::uint64_t dscp_mask;
                MacAddress mac;
                RouteMode route_mode;
                NetworkType network_type;
            };
        };
        struct Prepared {
            MatchInput input;
            std::array<std::uint8_t, 16> address{};
            unsigned family = 0;
            std::array<std::uint8_t, 16> source_address{};
            unsigned source_family = 0;
            bool match_mapped_ipv4 = false;
            bool domain_absent = false;
            std::optional<std::span<ProgramAddress const>> candidates;
        };
        struct IndexedDomain { std::string_view text; std::size_t rule; };
        struct IndexedIp { std::array<std::uint8_t, 16> address; std::size_t rule; };
        struct IpGroup { unsigned prefix; std::vector<IndexedIp> entries; };
        using IpIndex = std::vector<IpGroup>;
        struct Ipv4Interval { std::uint32_t first, last; };
        struct Ipv6Interval { std::array<std::uint8_t, 16> first, last; };
        struct AnyIndex {
            std::vector<Ipv4Interval> ipv4;
            std::vector<Ipv6Interval> ipv6;
            std::vector<std::uint32_t> domains, suffixes, remainder;
            bool has_ip = false, has_domain = false;
        };
        static constexpr auto is_text_kind(Kind kind) noexcept -> bool {
            return kind == Kind::domain || kind == Kind::suffix || kind == Kind::keyword ||
                kind == Kind::wildcard || kind == Kind::inbound || kind == Kind::auth_user ||
                kind == Kind::process_name || kind == Kind::process_path || kind == Kind::source_interface ||
                kind == Kind::wifi_ssid || kind == Kind::source_user || kind == Kind::package_name ||
                kind == Kind::client;
        }
        bool uses_source_uid_ = false, uses_process_ = false;
        std::vector<Entry> entries_;
        std::string text_arena_;
        std::vector<std::pair<std::uint32_t, std::uint32_t>> text_spans_;
        std::vector<BoundedRegex> regexes_;
        std::vector<std::uint32_t> children_;
        std::vector<std::size_t> roots_;
        std::vector<IndexedDomain> domains_, suffixes_;
        IpIndex ipv4_, ipv6_;
        std::vector<AnyIndex> any_indexes_;
        std::vector<std::size_t> unindexed_, ip_roots_, domain_roots_;
        std::shared_ptr<MmapMatcher const> mmap_;
        [[nodiscard]] static auto text_rule_kind(std::string_view type) noexcept -> std::optional<Kind>;
        [[nodiscard]] static auto parse_cidr_entry(std::string_view value) noexcept -> IpPredicate;
        [[nodiscard]] static auto parse_net_if_cidr(std::string_view value) noexcept -> NetworkInterfaceIp;
        [[nodiscard]] static auto prepare(MatchInput) -> std::expected<Prepared, Error>;
        [[nodiscard]] auto evaluate(std::size_t, Prepared const&) const noexcept -> Truth;
        [[nodiscard]] static auto eval_mmap(MmapMatcher const&, Matcher const*, Prepared const&, bool) noexcept -> Truth;
        [[nodiscard]] auto first_indexed_match(Prepared const&, std::size_t, std::size_t) const noexcept -> std::size_t;
        [[nodiscard]] auto has_ip_root(std::size_t, std::size_t) const noexcept -> bool;
        [[nodiscard]] auto has_domain_root(std::size_t, std::size_t) const noexcept -> bool;
        [[nodiscard]] auto first_match(Prepared const&) const noexcept -> std::optional<std::size_t>;
        [[nodiscard]] auto first_match(Prepared const&, std::size_t, std::size_t) const noexcept -> std::optional<std::size_t>;
        auto rebind_text_views() noexcept -> void;
        friend class RouteMatcher;
        friend class RouteProgram;

    public:
        Matcher();
        Matcher(Matcher const&);
        Matcher(Matcher&&) noexcept;
        auto operator=(Matcher const&) -> Matcher&;
        auto operator=(Matcher&&) noexcept -> Matcher&;
        ~Matcher();

        [[nodiscard]] static auto compile(RuleSet const& set) -> std::expected<Matcher, Error>;
        [[nodiscard]] static auto compile_nxmm(std::shared_ptr<MmapMatcher const> mmap) -> std::expected<Matcher, Error>;
        [[nodiscard]] auto empty() const noexcept -> bool { return roots_.empty() && !mmap_; }
        [[nodiscard]] auto match(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error>;
        // Evaluate a mapped IPv6 address against both IPv6 and IPv4 predicates.
        [[nodiscard]] auto match_mapped(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error>;
        // A one-root expression can expose unknown without turning NOT unknown
        // into a match. Multiple roots are not a single logical condition.
        [[nodiscard]] auto match_truth_mapped(MatchInput input,
            std::optional<std::span<ProgramAddress const>> candidates = {}) const -> std::expected<Truth, Error>;
    };

    // Ordered rule sets choose an opaque outbound index; all predicates in one
    // set share its action. The caller owns and validates the outbound table.
    struct RouteRule {
        RuleSet predicates;
        std::size_t outbound;
        std::optional<std::size_t> source_index{};
        std::shared_ptr<MmapMatcher const> mmap{};
        bool mmap_match_source = false;
    };
    // Callers may enable source predicates only after their routing paths
    // supply the actual source or deliberately leave it unknown.
    enum class SourceMetadata { unavailable, provided };
    enum class AuthMetadata { unavailable, provided };
    struct OutboundDistribution {
        std::size_t physical_count = 2;
        std::vector<std::vector<std::size_t>> groups;

        [[nodiscard]] auto choose(std::size_t outbound, std::string_view host) const noexcept -> std::size_t {
            if (outbound < physical_count) return outbound;
            std::uint64_t hash = 14695981039346656037ull;
            if (host.ends_with('.')) host.remove_suffix(1);
            for (unsigned char byte : host) {
                if (byte >= 'A' && byte <= 'Z') byte = static_cast<unsigned char>(byte + ('a' - 'A'));
                hash = (hash ^ byte) * 1099511628211ull;
            }
            for (std::size_t depth = 0; outbound >= physical_count; ++depth) {
                if (depth == groups.size()) return 1;
                auto index = outbound - physical_count;
                if (index >= groups.size() || groups[index].empty()) return 1;
                auto const& members = groups[index];
                hash = (hash ^ outbound) * 1099511628211ull;
                outbound = members[hash % members.size()];
            }
            return outbound;
        }
    };
    struct MatchedRoute {
        std::size_t outbound;
        std::optional<std::size_t> rule;
        std::optional<std::size_t> predicate;
    };
    class RouteMatcher {
        struct Action {
            std::size_t outbound, rule, predicate;
        };
        struct Stage {
            bool is_mmap = false;
            std::size_t outbound = 0, rule = 0;
            std::shared_ptr<MmapMatcher const> mmap;
            std::optional<Matcher> tail;
            bool match_source = false;
            std::size_t first = 0, last = 0;
        };
        struct UnknownRun {
            std::size_t first, last, outbound;
        };
        Matcher matcher_;
        std::vector<Action> actions_;
        std::vector<Stage> stages_;
        std::vector<UnknownRun> ip_runs_, domain_runs_;
        std::size_t default_outbound_ = 0;
        std::shared_ptr<OutboundDistribution const> distribution_;
        std::shared_ptr<RuntimeRouteMode const> mode_state_;
        bool needs_source_ = false;
        bool needs_auth_user_ = false;
        std::optional<std::string> inbound_;
    public:
        [[nodiscard]] static auto compile(std::span<RouteRule const> rules, std::size_t default_outbound,
                                          std::size_t outbound_count, SourceMetadata source = SourceMetadata::unavailable,
                                          std::optional<std::string_view> inbound = {}, AuthMetadata auth = AuthMetadata::unavailable)
            -> std::expected<RouteMatcher, Error>;
        auto set_distribution(std::shared_ptr<OutboundDistribution const> value) noexcept -> void {
            distribution_ = std::move(value);
        }
        auto set_runtime_mode(std::shared_ptr<RuntimeRouteMode const> value) noexcept -> void {
            mode_state_ = std::move(value);
        }
        [[nodiscard]] auto runtime_mode() const noexcept -> std::shared_ptr<RuntimeRouteMode const> const& {
            return mode_state_;
        }
        [[nodiscard]] auto mode_override(std::string_view host) const noexcept -> std::optional<std::size_t> {
            if (!mode_state_) return {};
            auto m = mode_state_->mode.load(std::memory_order_acquire);
            if (m == RouteMode::direct) return std::size_t{0};
            if (m == RouteMode::global) return choose_outbound(mode_state_->global_outbound.load(std::memory_order_acquire), host);
            return {};
        }
        [[nodiscard]] auto choose_outbound(std::size_t outbound, std::string_view host) const noexcept -> std::size_t {
            return distribution_ ? distribution_->choose(outbound, host) : outbound;
        }
        [[nodiscard]] auto empty_rules() const noexcept -> bool {
            return stages_.empty() && matcher_.empty();
        }
        [[nodiscard]] auto has_distribution() const noexcept -> bool {
            return static_cast<bool>(distribution_);
        }
        [[nodiscard]] auto distribution() const noexcept -> std::shared_ptr<OutboundDistribution const> const& {
            return distribution_;
        }
        [[nodiscard]] auto default_outbound_fast() const noexcept -> std::optional<std::size_t> {
            if (!empty_rules() || distribution_) return {};
            if (mode_state_) {
                auto m = mode_state_->mode.load(std::memory_order_acquire);
                if (m == RouteMode::direct) return std::size_t{0};
                if (m == RouteMode::global) return mode_state_->global_outbound.load(std::memory_order_acquire);
            }
            return default_outbound_;
        }
        [[nodiscard]] auto uses_source_uid() const noexcept -> bool { return matcher_.uses_source_uid_; }
        [[nodiscard]] auto uses_process() const noexcept -> bool { return matcher_.uses_process_; }
        [[nodiscard]] auto needs_source() const noexcept -> bool { return needs_source_; }
        [[nodiscard]] auto needs_auth_user() const noexcept -> bool { return needs_auth_user_; }
        [[nodiscard]] auto inbound() const noexcept -> std::optional<std::string_view> {
            if (inbound_) return *inbound_;
            return {};
        }
        // A missing result means an earlier IP predicate requires resolution.
        // A result determines the action only, not the endpoint to dial.
        [[nodiscard]] auto preflight(std::string_view domain) const
            -> std::expected<std::optional<std::size_t>, Error>;
        [[nodiscard]] auto preflight(MatchInput input) const
            -> std::expected<std::optional<std::size_t>, Error>;
        // A mapped IPv6 target is evaluated as both families. The earliest
        // matching predicate wins across domain, IPv6 and mapped IPv4.
        [[nodiscard]] auto match(MatchInput input) const -> std::expected<std::size_t, Error> {
            return match_with_rule(input).transform([](MatchedRoute const& route) { return route.outbound; });
        }
        [[nodiscard]] auto match_with_rule(MatchInput input) const -> std::expected<MatchedRoute, Error>;
    };

    class RouteProgram {
        struct Instruction {
            std::size_t first, last;
            ProgramAction action;
            DomainSource domain_source;
            std::shared_ptr<MmapMatcher const> mmap{};
            std::shared_ptr<Matcher const> mmap_tail{};
            bool mmap_match_source = false;
        };
        Matcher matcher_;
        std::vector<Instruction> instructions_;
        bool has_dns_hijack_ = false;
    public:
        [[nodiscard]] static auto compile(std::span<ProgramRule const>, std::size_t outbound_count)
            -> std::expected<RouteProgram, Error>;
        // Returns one action, or no result after the last instruction. Even
        // unconditional and exhausted programs validate supplied input.
        [[nodiscard]] auto next(ProgramInput, std::size_t start = 0) const
            -> std::expected<std::optional<ProgramStep>, Error>;
        // Unlike next(), stop on the first instruction whose predicates are
        // unknown, so the caller can supply missing context before proceeding.
        [[nodiscard]] auto preflight(ProgramInput, std::size_t start = 0) const -> std::expected<ProgramPreflight, Error>;
        [[nodiscard]] auto uses_source_uid() const noexcept -> bool { return matcher_.uses_source_uid_; }
        [[nodiscard]] auto uses_process() const noexcept -> bool { return matcher_.uses_process_; }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return instructions_.size(); }
        [[nodiscard]] auto has_dns_hijack() const noexcept -> bool { return has_dns_hijack_; }
    };
    enum class ProgramCursorError { awaiting_action, terminal, stale_action, stale_uncertainty };
    // A single request owns this cursor. Continuing actions must be explicitly
    // acknowledged after their I/O completes; failed actions do not advance.
    class ProgramCursor {
        std::size_t index_ = 0;
        std::optional<ProgramStep> pending_;
        std::optional<std::size_t> uncertain_;
        RouteProgram const* program_ = nullptr;
        bool terminal_ = false;
    public:
        ProgramCursor() = default;
        ProgramCursor(ProgramCursor const&) = delete;
        auto operator=(ProgramCursor const&) -> ProgramCursor& = delete;
        [[nodiscard]] auto index() const noexcept -> std::size_t { return index_; }
        [[nodiscard]] auto terminal() const noexcept -> bool { return terminal_; }
        [[nodiscard]] auto pending() const noexcept -> std::optional<ProgramStep> const& { return pending_; }
        [[nodiscard]] auto poll(RouteProgram const&, ProgramInput, bool wait_unknown = true)
            -> std::expected<ProgramPreflight, Error>;
        [[nodiscard]] auto complete(ProgramStep const&) noexcept -> std::expected<void, ProgramCursorError>;
        // Skip only the uncertainty returned by the most recent poll. A later
        // poll may still pause at another rule after a continuing action.
        [[nodiscard]] auto skip_unknown(std::size_t rule_index) noexcept -> std::expected<void, ProgramCursorError>;
    };
    inline constexpr unsigned max_rules = 4000000;
    inline constexpr unsigned max_rule_depth = 32;
    inline constexpr unsigned max_input_bytes = 268435456;

    // The lookup borrows the loaded sets for compilation only.
    using RuleSetLookup = functional::function_ref<RuleSet const*(std::string_view)>;
    [[nodiscard]] auto expand_rule_sets(RuleSet const&, RuleSetLookup, std::size_t& remaining) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto normalize_rule(Rule rule) -> std::expected<Rule, Error>;
    [[nodiscard]] auto normalize_set(RuleSet set) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto parse_kdl(std::string_view input) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto write_kdl(RuleSet const& set) -> std::expected<std::string, Error>;
    [[nodiscard]] auto parse_beve(std::string_view input) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto write_beve(RuleSet const& set) -> std::expected<std::string, Error>;
    [[nodiscard]] auto compile_nxmm(RuleSet const& set, bool ip_cidr_match_source = false,
        std::size_t max_bytes = max_input_bytes) -> std::expected<std::string, Error>;
    [[nodiscard]] auto parse_nxmm(std::string_view input) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto nxmm_to_ruleset(MmapMatcher const& matcher) -> std::expected<RuleSet, Error>;
}

export namespace policy {
    // An edge points from a consumer to a prerequisite. The returned order
    // places every prerequisite before its consumers; repeated edges are valid.
    struct DependencyEdge { std::size_t consumer, prerequisite; };
    enum class DependencyError { limit, invalid_edge, cycle };
    inline constexpr std::size_t max_dependency_nodes = 131072;
    inline constexpr std::size_t max_dependency_edges = 2097152;

    [[nodiscard]] inline auto dependency_order(std::size_t count, std::span<DependencyEdge const> edges)
        -> std::expected<std::vector<std::size_t>, DependencyError> {
        if (count > max_dependency_nodes || edges.size() > max_dependency_edges)
            return std::unexpected(DependencyError::limit);
        std::vector<std::size_t> offsets(count + 1), indegree(count);
        for (auto edge : edges) {
            if (edge.consumer >= count || edge.prerequisite >= count)
                return std::unexpected(DependencyError::invalid_edge);
            ++offsets[edge.consumer + 1]; ++indegree[edge.prerequisite];
        }
        for (std::size_t i = 0; i < count; ++i) offsets[i + 1] += offsets[i];
        auto cursor = offsets;
        std::vector<std::size_t> adjacent(edges.size());
        for (auto edge : edges) adjacent[cursor[edge.consumer]++] = edge.prerequisite;
        std::vector<std::size_t> order;
        order.reserve(count);
        for (std::size_t i = 0; i < count; ++i) if (!indegree[i]) order.push_back(i);
        for (std::size_t next = 0; next < order.size(); ++next) {
            auto node = order[next];
            for (auto i = offsets[node]; i < offsets[node + 1]; ++i)
                if (--indegree[adjacent[i]] == 0) order.push_back(adjacent[i]);
        }
        if (order.size() != count) return std::unexpected(DependencyError::cycle);
        std::ranges::reverse(order);
        return order;
    }
}
