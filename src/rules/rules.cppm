export module rules;
import std;
import rules.regex;

export namespace rules {
    enum class ErrorCode { syntax, schema, limit, invalid_rule, invalid_query };

    struct Error {
        ErrorCode code;
        std::string message;
    };

    struct Rule {
        std::string type;
        std::string value;
        std::vector<Rule> children;
        auto operator==(Rule const&) const -> bool;
    };

    struct RuleSet {
        std::vector<Rule> rules;
        unsigned version = 1;
        auto operator==(RuleSet const&) const -> bool;
    };

    enum class Network { tcp, udp };
    enum class Protocol { http, tls, dns, ssh, stun, quic, tls_ech };
    [[nodiscard]] auto parse_protocol(std::string_view) noexcept -> std::optional<Protocol>;
    // Domain predicates accept ASCII hostnames, a stricter subset than DNS
    // wire labels. Metadata outside this subset remains unknown.
    [[nodiscard]] auto valid_domain(std::string_view name) -> bool;
    [[nodiscard]] auto valid_source_interface(std::string_view) noexcept -> bool;
    [[nodiscard]] auto parse_source_uid(std::string_view) noexcept -> std::optional<std::uint32_t>;
    [[nodiscard]] auto is_private_address(std::span<std::uint8_t const> address) noexcept -> bool;
    using MacAddress=std::array<std::uint8_t,6>;
    [[nodiscard]] auto parse_mac(std::string_view) noexcept -> std::optional<MacAddress>;
    [[nodiscard]] auto parse_dscp(std::string_view) noexcept -> std::optional<std::uint8_t>;
    [[nodiscard]] auto parse_dscp_list(std::string_view) noexcept -> std::optional<std::uint64_t>;

    struct IngressMetadata {
        std::optional<std::uint8_t> dscp;
        std::optional<MacAddress> source_mac, gateway_mac;
        auto operator==(IngressMetadata const&) const -> bool = default;

        template<class Input>
        [[nodiscard]] auto apply(Input input) const -> Input {
            input.dscp=dscp;
            input.source_mac=source_mac;
            input.gateway_mac=gateway_mac;
            return input;
        }
    };

    struct MatchInput {
        std::optional<std::string_view> domain;
        std::optional<std::string_view> ip;
        std::optional<std::uint16_t> port;
        std::optional<Network> network;
        std::optional<std::string_view> source_ip;
        std::optional<std::uint16_t> source_port;
        // Network-order IPv4 or IPv6 bytes, borrowed for the call. Mutually
        // exclusive with source_ip; a missing address remains unknown.
        std::optional<std::span<std::uint8_t const>> source_ip_bytes;
        std::optional<std::string_view> inbound;
        std::optional<std::string_view> auth_user;
        // DNS QTYPE, when evaluation is tied to a concrete question.
        std::optional<std::uint16_t> query_type;
        std::optional<Protocol> protocol;
        std::optional<std::uint32_t> source_uid;
        std::optional<std::string_view> process_path;
        std::optional<std::string_view> source_interface;
        std::optional<bool> tls_ech;
        std::optional<std::uint8_t> dscp;
        std::optional<MacAddress> source_mac, gateway_mac;
    };
    struct ProgramAddress {std::array<std::uint8_t,16> bytes{};std::uint8_t size=0;};

    class Matcher {
    public:
        enum class Truth { no, yes, unknown };
    private:
        enum class Kind { suffix, domain, keyword, wildcard, inbound, auth_user, process_name, process_path, domain_regex, process_path_regex, source_interface, ip, source_ip, ip_version, ip_is_private, source_private, port, source_port, source_uid, network, query_type, protocol, tls_ech, dscp, source_mac, gateway_mac, all, any, negate };
        struct IpPredicate { std::array<std::uint8_t,16> address; unsigned prefix, family; };
        struct PortPredicate { std::uint16_t first, last; };
        struct ChildRange { std::uint32_t first, count, any_index = std::numeric_limits<std::uint32_t>::max(); };
        struct Entry {
            Kind kind = Kind::suffix;
            // Only trivial payloads share storage; kind selects the active one.
            union { IpPredicate ip{}; PortPredicate port; Network network; Protocol protocol; ChildRange children; std::string_view text; std::uint8_t ip_version; std::uint16_t query_type; std::uint32_t source_uid; std::uint16_t regex; bool offered; std::uint64_t dscp_mask; MacAddress mac; };
        };
        struct Prepared {
            MatchInput input;
            std::array<std::uint8_t, 16> address{};
            unsigned family = 0;
            std::array<std::uint8_t,16> source_address{};
            unsigned source_family = 0;
            bool match_mapped_ipv4 = false;
            bool domain_absent = false;
            std::optional<std::span<ProgramAddress const>> candidates;
        };
        struct IndexedDomain { std::string_view text; std::size_t rule; };
        struct IndexedIp { std::array<std::uint8_t,16> address; std::size_t rule; };
        struct IpGroup { unsigned prefix; std::vector<IndexedIp> entries; };
        using IpIndex = std::vector<IpGroup>;
        struct Ipv4Interval { std::uint32_t first, last; };
        struct Ipv6Interval { std::array<std::uint8_t, 16> first, last; };
        struct AnyIndex {
            std::vector<Ipv4Interval> ipv4;
            std::vector<Ipv6Interval> ipv6;
            std::vector<std::uint16_t> domains, suffixes, remainder;
            bool has_ip = false, has_domain = false;
        };
        bool uses_source_uid_=false, uses_process_=false;
        std::vector<Entry> entries_;
        std::vector<std::string> texts_;
        std::vector<BoundedRegex> regexes_;
        std::vector<std::uint16_t> children_;
        std::vector<std::size_t> roots_;
        std::vector<IndexedDomain> domains_, suffixes_;
        IpIndex ipv4_, ipv6_;
        std::vector<AnyIndex> any_indexes_;
        std::vector<std::size_t> unindexed_;
        [[nodiscard]] static auto prepare(MatchInput) -> std::expected<Prepared, Error>;
        [[nodiscard]] auto evaluate(std::size_t, Prepared const&) const noexcept -> Truth;
        [[nodiscard]] auto first_match(Prepared const&) const noexcept -> std::optional<std::size_t>;
        [[nodiscard]] auto first_match(Prepared const&,std::size_t,std::size_t) const noexcept -> std::optional<std::size_t>;
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
        [[nodiscard]] auto match(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error>;
        // Evaluate a mapped IPv6 address against both IPv6 and IPv4 predicates.
        [[nodiscard]] auto match_mapped(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error>;
        // A one-root expression can expose unknown without turning NOT unknown
        // into a match. Multiple roots are not a single logical condition.
        [[nodiscard]] auto match_truth_mapped(MatchInput input,
            std::optional<std::span<ProgramAddress const>> candidates={}) const -> std::expected<Truth, Error>;
    };

    // Ordered rule sets choose an opaque outbound index; all predicates in one
    // set share its action. The caller owns and validates the outbound table.
    struct RouteRule {
        RuleSet predicates;
        std::size_t outbound;
        std::optional<std::size_t> source_index{};
    };
    // Callers may enable source predicates only after their routing paths
    // supply the actual source or deliberately leave it unknown.
    enum class SourceMetadata { unavailable, provided };
    enum class AuthMetadata { unavailable, provided };
    struct OutboundDistribution {
        std::size_t physical_count=2;
        std::vector<std::vector<std::size_t>> groups;

        [[nodiscard]] auto choose(std::size_t outbound,std::string_view host) const noexcept -> std::size_t {
            if (outbound<physical_count) return outbound;
            std::uint64_t hash=14695981039346656037ull;
            if (host.ends_with('.')) host.remove_suffix(1);
            for (unsigned char byte : host) {
                if (byte>='A' && byte<='Z') byte=static_cast<unsigned char>(byte+('a'-'A'));
                hash=(hash^byte)*1099511628211ull;
            }
            for (std::size_t depth=0;outbound>=physical_count;++depth) {
                if (depth==groups.size()) return 1;
                auto index=outbound-physical_count;
                if (index>=groups.size() || groups[index].empty()) return 1;
                auto const& members=groups[index];
                hash=(hash^outbound)*1099511628211ull;
                outbound=members[hash%members.size()];
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
        Matcher matcher_;
        std::vector<Action> actions_;
        std::size_t default_outbound_ = 0;
        std::shared_ptr<OutboundDistribution const> distribution_;
        bool needs_source_ = false;
        bool needs_auth_user_ = false;
        std::optional<std::string> inbound_;
    public:
        [[nodiscard]] static auto compile(std::span<RouteRule const> rules, std::size_t default_outbound,
                                          std::size_t outbound_count, SourceMetadata source=SourceMetadata::unavailable,
                                          std::optional<std::string_view> inbound={}, AuthMetadata auth=AuthMetadata::unavailable)
            -> std::expected<RouteMatcher, Error>;
        auto set_distribution(std::shared_ptr<OutboundDistribution const> value) noexcept -> void {
            distribution_=std::move(value);
        }
        [[nodiscard]] auto choose_outbound(std::size_t outbound,std::string_view host) const noexcept -> std::size_t {
            return distribution_ ? distribution_->choose(outbound,host) : outbound;
        }
        [[nodiscard]] auto uses_source_uid() const noexcept -> bool {return matcher_.uses_source_uid_;}
        [[nodiscard]] auto uses_process() const noexcept -> bool {return matcher_.uses_process_;}
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
            return match_with_rule(input).transform([](MatchedRoute const& route) {return route.outbound;});
        }
        [[nodiscard]] auto match_with_rule(MatchInput input) const -> std::expected<MatchedRoute,Error>;
    };
    // Continued actions are returned to an I/O owner, which updates the input
    // before resuming at next_index. Terminal actions must end evaluation.
    // An empty predicate set is unconditional.
    enum class ProgramActionKind { sniff, resolve, route, reject, route_options, hijack_dns, bypass };
    enum class RejectMethod : std::uint8_t { default_rst, drop };
    struct ProgramAction {
        ProgramActionKind kind;
        std::size_t outbound = 0;
        std::uint32_t connect_timeout_ms = 0;
        bool route_only = false;
        RejectMethod reject_method = RejectMethod::default_rst;
        bool reject_no_drop = false;
        bool tls_record_fragment = false;
        std::uint16_t tls_fragment_min = 0, tls_fragment_max = 0;
        std::array<std::uint8_t, 64> tcp_prefix{};
        std::uint8_t tcp_prefix_len = 0;
        std::uint32_t udp_timeout_ms = 0;
        bool udp_adaptive_timeout = false;
        auto operator==(ProgramAction const&) const -> bool = default;
    };
    [[nodiscard]] inline auto adaptive_udp_timeout_ms(std::optional<Protocol> proto,
        std::uint16_t dst_port, std::uint32_t fallback_ms = 60000) noexcept -> std::uint32_t {
        if (proto) {
            if (*proto == Protocol::dns || *proto == Protocol::stun) return 10000;
            if (*proto == Protocol::quic) return 30000;
        }
        if (dst_port == 53 || dst_port == 123 || dst_port == 3478 || dst_port == 5349) return 10000;
        if (dst_port == 443 || dst_port == 853) return 30000;
        return fallback_ms;
    }
    enum class DomainSource { explicit_target, fakeip, reverse_dns, sniffed };
    // All views are borrowed for the duration of next(). Domain sources stay
    // separate even when they contain conflicting values.
    struct ProgramInput {
        std::optional<std::string_view> explicit_domain, fakeip_domain, reverse_domain, sniffed_domain;
        std::optional<std::string_view> ip;
        std::optional<std::uint16_t> port;
        std::optional<Network> network;
        std::optional<std::string_view> source_ip;
        std::optional<std::uint16_t> source_port;
        std::optional<std::span<std::uint8_t const>> source_ip_bytes;
        std::optional<std::string_view> inbound;
        std::optional<std::string_view> auth_user;
        // A present empty set is known empty; absence means unresolved.
        // Each IP predicate matches any candidate independently.
        std::optional<std::span<ProgramAddress const>> candidates;
        // Per DomainSource: the source was inspected and contains no domain.
        // A missing value without this marker remains unknown.
        std::array<bool,4> domain_absent{};
        std::optional<Protocol> protocol;
        std::optional<std::uint32_t> source_uid;
        std::optional<std::string_view> process_path;
        std::optional<std::string_view> source_interface;
        std::optional<bool> tls_ech;
        std::optional<std::uint8_t> dscp;
        std::optional<MacAddress> source_mac, gateway_mac;
        bool dns_hijack_tcp=false;
        std::optional<bool> dns_query;
    };
    struct ProgramRule {
        RuleSet predicates;
        ProgramAction action;
        DomainSource domain_source = DomainSource::explicit_target;
    };
    struct ProgramStep {
        std::size_t rule_index, next_index;
        ProgramAction action;
        [[nodiscard]] auto terminal() const noexcept -> bool {
            return action.kind==ProgramActionKind::route || action.kind==ProgramActionKind::reject || action.kind==ProgramActionKind::hijack_dns;
        }
    };
    enum class ProgramPreflightKind { step,uncertain,exhausted };
    struct ProgramPreflight {
        ProgramPreflightKind kind;
        std::size_t rule_index;
        std::optional<ProgramStep> step;
    };
    class RouteProgram {
        struct Instruction { std::size_t first, last; ProgramAction action; DomainSource domain_source; };
        Matcher matcher_;
        std::vector<Instruction> instructions_;
        bool has_dns_hijack_=false;
    public:
        [[nodiscard]] static auto compile(std::span<ProgramRule const>,std::size_t outbound_count)
            -> std::expected<RouteProgram, Error>;
        // Returns one action, or no result after the last instruction. Even
        // unconditional and exhausted programs validate supplied input.
        [[nodiscard]] auto next(ProgramInput,std::size_t start=0) const
            -> std::expected<std::optional<ProgramStep>, Error>;
        // Unlike next(), stop on the first instruction whose predicates are
        // unknown, so the caller can supply missing context before proceeding.
        [[nodiscard]] auto preflight(ProgramInput,std::size_t start=0) const -> std::expected<ProgramPreflight,Error>;
        [[nodiscard]] auto uses_source_uid() const noexcept -> bool {return matcher_.uses_source_uid_;}
        [[nodiscard]] auto uses_process() const noexcept -> bool {return matcher_.uses_process_;}
        [[nodiscard]] auto size() const noexcept -> std::size_t {return instructions_.size();}
        [[nodiscard]] auto has_dns_hijack() const noexcept -> bool {return has_dns_hijack_;}
    };
    enum class ProgramCursorError { awaiting_action,terminal,stale_action,stale_uncertainty };
    // A single request owns this cursor. Continuing actions must be explicitly
    // acknowledged after their I/O completes; failed actions do not advance.
    class ProgramCursor {
        std::size_t index_=0;
        std::optional<ProgramStep> pending_;
        std::optional<std::size_t> uncertain_;
        RouteProgram const* program_=nullptr;
        bool terminal_=false;
    public:
        ProgramCursor()=default;
        ProgramCursor(ProgramCursor const&)=delete;
        auto operator=(ProgramCursor const&) -> ProgramCursor& = delete;
        [[nodiscard]] auto index() const noexcept -> std::size_t {return index_;}
        [[nodiscard]] auto terminal() const noexcept -> bool {return terminal_;}
        [[nodiscard]] auto pending() const noexcept -> std::optional<ProgramStep> const& {return pending_;}
        [[nodiscard]] auto poll(RouteProgram const&,ProgramInput,bool wait_unknown=true)
            -> std::expected<ProgramPreflight,Error>;
        [[nodiscard]] auto complete(ProgramStep const&) noexcept -> std::expected<void,ProgramCursorError>;
        // Skip only the uncertainty returned by the most recent poll. A later
        // poll may still pause at another rule after a continuing action.
        [[nodiscard]] auto skip_unknown(std::size_t rule_index) noexcept -> std::expected<void,ProgramCursorError>;
    };
    // Compatibility bridge for existing ordered route sets. The old matcher
    // remains authoritative for preflight because unknown IP predicates may
    // defer the decision until resolution. The program supplies the same
    // terminal action after candidate metadata is available.
    class LegacyRouteProgram {
        RouteMatcher matcher_;
        RouteProgram program_;
        std::size_t default_outbound_=0;
    public:
        [[nodiscard]] static auto compile(std::span<RouteRule const>,std::size_t default_outbound,
            std::size_t outbound_count,SourceMetadata source=SourceMetadata::unavailable,
            std::optional<std::string_view> inbound={},AuthMetadata auth=AuthMetadata::unavailable)
            -> std::expected<LegacyRouteProgram,Error>;
        [[nodiscard]] auto needs_source() const noexcept -> bool {return matcher_.needs_source();}
        [[nodiscard]] auto needs_auth_user() const noexcept -> bool {return matcher_.needs_auth_user();}
        [[nodiscard]] auto inbound() const noexcept -> std::optional<std::string_view> {return matcher_.inbound();}
        [[nodiscard]] auto preflight(std::string_view domain) const -> std::expected<std::optional<std::size_t>,Error> {return matcher_.preflight(domain);}
        [[nodiscard]] auto preflight(MatchInput input) const -> std::expected<std::optional<std::size_t>,Error> {return matcher_.preflight(input);}
        [[nodiscard]] auto preflight_program(ProgramInput) const -> std::expected<std::optional<std::size_t>,Error>;
        [[nodiscard]] auto match(MatchInput) const -> std::expected<std::size_t,Error>;
        [[nodiscard]] auto next(ProgramInput,std::size_t start=0) const -> std::expected<ProgramStep,Error>;
    };
    inline constexpr unsigned max_rules = 16384;
    inline constexpr unsigned max_rule_depth = 32;
    inline constexpr unsigned max_input_bytes = 1048576;

    // The lookup borrows the loaded sets for compilation only.
    using RuleSetLookup=std::function_ref<RuleSet const*(std::string_view)>;
    [[nodiscard]] auto expand_rule_sets(RuleSet const&,RuleSetLookup,std::size_t& remaining) -> std::expected<RuleSet,Error>;
    [[nodiscard]] auto normalize_rule(Rule rule) -> std::expected<Rule, Error>;
    [[nodiscard]] auto normalize_set(RuleSet set) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto parse_kdl(std::string_view input) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto write_kdl(RuleSet const& set) -> std::expected<std::string, Error>;
    [[nodiscard]] auto parse_beve(std::string_view input) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto write_beve(RuleSet const& set) -> std::expected<std::string, Error>;
}

export namespace policy {
    // An edge points from a consumer to a prerequisite. The returned order
    // places every prerequisite before its consumers; repeated edges are valid.
    struct DependencyEdge { std::size_t consumer, prerequisite; };
    enum class DependencyError { limit, invalid_edge, cycle };
    inline constexpr std::size_t max_dependency_nodes=4096;
    inline constexpr std::size_t max_dependency_edges=65536;

    [[nodiscard]] inline auto dependency_order(std::size_t count,std::span<DependencyEdge const> edges)
        -> std::expected<std::vector<std::size_t>,DependencyError> {
        if (count>max_dependency_nodes || edges.size()>max_dependency_edges)
            return std::unexpected(DependencyError::limit);
        std::vector<std::size_t> offsets(count+1), indegree(count);
        for (auto edge:edges) {
            if (edge.consumer>=count || edge.prerequisite>=count)
                return std::unexpected(DependencyError::invalid_edge);
            ++offsets[edge.consumer+1]; ++indegree[edge.prerequisite];
        }
        for (std::size_t i=0;i<count;++i) offsets[i+1]+=offsets[i];
        auto cursor=offsets;
        std::vector<std::size_t> adjacent(edges.size());
        for (auto edge:edges) adjacent[cursor[edge.consumer]++]=edge.prerequisite;
        std::vector<std::size_t> order;
        order.reserve(count);
        for (std::size_t i=0;i<count;++i) if (!indegree[i]) order.push_back(i);
        for (std::size_t next=0;next<order.size();++next) {
            auto node=order[next];
            for (auto i=offsets[node];i<offsets[node+1];++i)
                if (--indegree[adjacent[i]]==0) order.push_back(adjacent[i]);
        }
        if (order.size()!=count) return std::unexpected(DependencyError::cycle);
        std::ranges::reverse(order);
        return order;
    }
}
