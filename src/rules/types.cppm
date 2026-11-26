export module rules:types;
import std;

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
        unsigned version = 2;
        auto operator==(RuleSet const&) const -> bool;
    };

    enum class Network { tcp, udp };
    enum class Protocol { http, tls, dns, ssh, stun, quic, bittorrent, dtls, rdp, ntp, tls_ech };
    [[nodiscard]] inline constexpr auto protocol_mask(Protocol protocol) noexcept -> std::uint32_t {
        return std::uint32_t{1} << static_cast<unsigned>(protocol);
    }

    enum class RouteMode : std::uint8_t { rule, global, direct };
    [[nodiscard]] inline constexpr auto parse_route_mode(std::string_view text) noexcept -> std::optional<RouteMode> {
        if (text == "rule") return RouteMode::rule;
        if (text == "global") return RouteMode::global;
        if (text == "direct") return RouteMode::direct;
        return {};
    }
    [[nodiscard]] inline constexpr auto route_mode_name(RouteMode mode) noexcept -> std::string_view {
        switch (mode) {
        case RouteMode::rule: return "rule";
        case RouteMode::global: return "global";
        case RouteMode::direct: return "direct";
        }
        return "rule";
    }
    struct RuntimeRouteMode {
        std::atomic<RouteMode> mode{RouteMode::rule};
        std::atomic<std::size_t> global_outbound{0};
    };

    enum class NetworkType : std::uint8_t { wifi, cellular, ethernet, other };
    [[nodiscard]] inline constexpr auto parse_network_type(std::string_view text) noexcept -> std::optional<NetworkType> {
        if (text == "wifi") return NetworkType::wifi;
        if (text == "cellular") return NetworkType::cellular;
        if (text == "ethernet") return NetworkType::ethernet;
        if (text == "other") return NetworkType::other;
        return {};
    }
    [[nodiscard]] inline constexpr auto network_type_name(NetworkType type) noexcept -> std::string_view {
        switch (type) {
        case NetworkType::wifi: return "wifi";
        case NetworkType::cellular: return "cellular";
        case NetworkType::ethernet: return "ethernet";
        case NetworkType::other: return "other";
        }
        return "other";
    }

    enum class DnsRuleStrategy : std::uint8_t { prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only };
    [[nodiscard]] inline constexpr auto parse_dns_rule_strategy(std::string_view text) noexcept -> std::optional<DnsRuleStrategy> {
        if (text == "prefer-ipv4" || text == "prefer_ipv4") return DnsRuleStrategy::prefer_ipv4;
        if (text == "prefer-ipv6" || text == "prefer_ipv6") return DnsRuleStrategy::prefer_ipv6;
        if (text == "ipv4-only" || text == "ipv4_only") return DnsRuleStrategy::ipv4_only;
        if (text == "ipv6-only" || text == "ipv6_only") return DnsRuleStrategy::ipv6_only;
        return {};
    }
    [[nodiscard]] inline constexpr auto dns_rule_strategy_name(DnsRuleStrategy value) noexcept -> std::string_view {
        switch (value) {
        case DnsRuleStrategy::prefer_ipv4: return "prefer-ipv4";
        case DnsRuleStrategy::prefer_ipv6: return "prefer-ipv6";
        case DnsRuleStrategy::ipv4_only: return "ipv4-only";
        case DnsRuleStrategy::ipv6_only: return "ipv6-only";
        }
        return "prefer-ipv4";
    }

    struct SubnetPrefix {
        std::array<std::uint8_t, 16> address{};
        std::uint8_t size = 0, bits = 0;
        auto operator==(SubnetPrefix const&) const -> bool = default;
    };

    using MacAddress = std::array<std::uint8_t, 6>;

    struct IngressMetadata {
        std::optional<std::uint8_t> dscp;
        std::optional<MacAddress> source_mac, gateway_mac;
        auto operator==(IngressMetadata const&) const -> bool = default;

        template<class Input>
        [[nodiscard]] auto apply(Input input) const -> Input {
            input.dscp = dscp;
            input.source_mac = source_mac;
            input.gateway_mac = gateway_mac;
            return input;
        }
    };

    struct ProgramAddress { std::array<std::uint8_t, 16> bytes{}; std::uint8_t size = 0; };

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
        std::optional<RouteMode> route_mode;
        std::optional<NetworkType> network_type;
        std::optional<bool> network_is_expensive;
        std::optional<bool> network_is_constrained;
        std::optional<std::string_view> wifi_ssid;
        std::optional<MacAddress> wifi_bssid;
        std::optional<std::span<ProgramAddress const>> default_interface_addresses;
        std::optional<std::uint32_t> source_gid;
        std::optional<std::string_view> source_user;
        std::optional<std::string_view> package_name;
        std::optional<std::string_view> client;
        // Network-order destination IPv4 or IPv6 bytes, borrowed for the call.
        // Mutually exclusive with ip; avoids ASCII formatting/parsing roundtrips.
        std::optional<std::span<std::uint8_t const>> ip_bytes;
        // Multi-holder candidate executable paths (borrowed); matched if any path matches.
        std::optional<std::span<std::string const>> process_paths;
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
        std::optional<std::string> override_address{};
        std::uint16_t override_port = 0;
        std::uint32_t tls_fragment_fallback_delay_ms = 0;
        std::optional<DnsRuleStrategy> resolve_strategy{};
        std::optional<std::size_t> resolve_server{};
        std::optional<bool> resolve_disable_cache{};
        std::optional<std::uint32_t> resolve_rewrite_ttl{};
        std::optional<SubnetPrefix> resolve_client_subnet{};
        std::uint32_t sniff_protocols = 0;
        bool sniff_override_destination = false;
        std::uint32_t sniff_timeout_ms = 0;
        bool udp_disable_domain_unmapping = false;
        auto operator==(ProgramAction const&) const -> bool = default;
    };

    [[nodiscard]] inline auto adaptive_udp_timeout_ms(std::optional<Protocol> proto,
        std::uint16_t dst_port, std::uint32_t fallback_ms = 60000) noexcept -> std::uint32_t {
        if (proto) {
            if (*proto == Protocol::dns || *proto == Protocol::stun || *proto == Protocol::ntp) return 10000;
            if (*proto == Protocol::quic || *proto == Protocol::dtls) return 30000;
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
        std::array<bool, 4> domain_absent{};
        std::optional<Protocol> protocol;
        std::optional<std::uint32_t> source_uid;
        std::optional<std::string_view> process_path;
        std::optional<std::string_view> source_interface;
        std::optional<bool> tls_ech;
        std::optional<std::uint8_t> dscp;
        std::optional<MacAddress> source_mac, gateway_mac;
        bool dns_hijack_tcp = false;
        std::optional<bool> dns_query;
        std::optional<RouteMode> route_mode;
        std::optional<NetworkType> network_type;
        std::optional<bool> network_is_expensive;
        std::optional<bool> network_is_constrained;
        std::optional<std::string_view> wifi_ssid;
        std::optional<MacAddress> wifi_bssid;
        std::optional<std::span<ProgramAddress const>> default_interface_addresses;
        std::optional<std::uint32_t> source_gid;
        std::optional<std::string_view> source_user;
        std::optional<std::string_view> package_name;
        std::optional<std::string_view> client;
        std::optional<std::span<std::string const>> process_paths;
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
            return action.kind == ProgramActionKind::route ||
                   action.kind == ProgramActionKind::reject ||
                   action.kind == ProgramActionKind::hijack_dns;
        }
    };

    enum class ProgramPreflightKind { step, uncertain, exhausted };
    struct ProgramPreflight {
        ProgramPreflightKind kind;
        std::size_t rule_index;
        std::optional<ProgramStep> step;
    };
}
