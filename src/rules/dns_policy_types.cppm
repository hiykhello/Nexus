export module dns.policy:types;
import std;
import rules;
import rules.regex;

export namespace policy {
    enum class DnsPattern : std::uint8_t { name, keyword, wildcard, regex };
    enum class DnsAction : std::uint8_t { route, reject, route_options, evaluate, respond, predefined };
    enum class ResponseSection : std::uint8_t { answer, authority, additional };
    struct PredefinedRecord {
        ResponseSection section;
        std::string name;
        std::uint16_t type,klass;
        std::uint32_t ttl;
        std::vector<std::uint8_t> data;
    };
    struct PredefinedResponse { std::uint8_t rcode=0;std::vector<PredefinedRecord> records; };
    struct ResponsePrefix { std::array<std::uint8_t,16> address{};std::uint8_t size=0,bits=0; };
    struct CnameCondition {
        std::string pattern;
        DnsPattern kind=DnsPattern::name;
        bool suffix=false;
        bool invert=false;
        std::optional<rules::BoundedRegex> compiled_regex{};
    };
    struct ResponseCondition {
        std::optional<std::uint16_t> rcode;
        std::optional<ResponseSection> section;
        std::optional<std::uint16_t> record_type;
        bool invert=false;
        std::optional<ResponsePrefix> address;
        bool address_private=false,address_any=false;
        std::optional<std::string> record_name;
        std::optional<std::uint16_t> record_class;
        std::optional<std::uint32_t> record_ttl_min,record_ttl_max;
        std::optional<std::vector<std::uint8_t>> record_data;
        std::optional<bool> authenticated_data;
        std::vector<CnameCondition> cname{};
    };
    // Borrowed for synchronous question selection. The network is the
    // originating business flow, independent of the DNS transport.
    struct DnsContext {
        std::optional<rules::Network> network;
        std::optional<std::uint16_t> source_port;
        std::optional<std::span<std::uint8_t const>> source_ip_bytes;
        std::optional<std::string_view> inbound,auth_user;
        std::optional<bool> query_dnssec;
        std::optional<bool> query_checking_disabled;
        std::optional<bool> query_authenticated_data;
        bool subnet_known=false;
        std::optional<ResponsePrefix> query_subnet;
        std::uint16_t query_class=1;
        // Present empty means a response with no address answers.
        std::optional<std::span<rules::ProgramAddress const>> response_addresses;
        std::optional<std::string_view> source_interface;
        std::optional<rules::NetworkType> network_type{};
        std::optional<bool> network_is_expensive{};
        std::optional<bool> network_is_constrained{};
        std::optional<std::string_view> wifi_ssid{};
        std::optional<rules::MacAddress> wifi_bssid{};
        std::span<rules::ProgramAddress const> default_interface_addresses{};
        std::span<rules::NetworkInterfaceAddress const> network_interface_addresses{};
        std::optional<std::uint32_t> source_uid{};
        std::optional<std::uint32_t> source_gid{};
        std::optional<std::string_view> source_user{};
        std::optional<std::string_view> process_name{};
        std::optional<std::string_view> process_path{};
        std::optional<std::string_view> package_name{};
        std::optional<rules::RouteMode> route_mode{};
        std::optional<std::string_view> client{};
        std::optional<std::span<std::string const>> process_paths{};
    };
    struct DnsRule {
        std::string domain;
        bool suffix=false;
        std::size_t server=0;
        std::optional<std::uint16_t> query_type;
        std::optional<std::uint16_t> query_class;
        DnsPattern pattern=DnsPattern::name;
        DnsAction action=DnsAction::route;
        bool match_all=false;
        bool invert=false;
        bool reject_drop=false;
        std::optional<bool> disable_cache;
        std::optional<rules::BoundedRegex> domain_regex{};
        std::optional<rules::DnsRuleStrategy> strategy{};
        std::optional<std::uint8_t> reject_rcode{};
#ifdef NEXUS_DNS_RESPONSE
        std::optional<bool> query_dnssec;
        std::optional<bool> query_checking_disabled;
        std::optional<bool> query_authenticated_data;
        std::optional<ResponsePrefix> query_subnet;
        bool match_response=false;
        bool race=false,speculative=false;
        std::optional<ResponseCondition> response;
        std::optional<PredefinedResponse> predefined;
        std::optional<std::uint32_t> timeout_ms;
        std::optional<std::uint32_t> rewrite_ttl;
        std::optional<ResponsePrefix> client_subnet;
        bool remove_client_subnet=false;
#else
        static constexpr std::optional<bool> query_dnssec{};
        static constexpr std::optional<bool> query_checking_disabled{};
        static constexpr std::optional<bool> query_authenticated_data{};
        static constexpr std::optional<ResponsePrefix> query_subnet{};
        static constexpr bool match_response=false;
        static constexpr bool race=false,speculative=false;
        static constexpr std::optional<ResponseCondition> response{};
        static constexpr std::optional<PredefinedResponse> predefined{};
        static constexpr std::optional<std::uint32_t> timeout_ms{};
        static constexpr std::optional<std::uint32_t> rewrite_ttl{};
        static constexpr std::optional<ResponsePrefix> client_subnet{};
        static constexpr bool remove_client_subnet=false;
#endif
        // All context predicates must match. Compiled at configuration time,
        // with the same unknown and source-address semantics as traffic rules.
        std::vector<rules::Rule> context;
        std::optional<rules::Matcher> context_matcher;
        bool has_rule_set=false, rule_set_needs_source=false, rule_set_needs_auth_user=false, rule_set_needs_response=false;
        bool rule_set_needs_source_uid=false, rule_set_needs_process=false, rule_set_needs_network=false;
        std::optional<rules::Matcher> rule_set_matcher;
        // Optional inline logical predicate tree (mode="logical" logic="and"|"or" or nested and/or/not blocks).
        std::optional<rules::Rule> inline_predicate;
        std::optional<rules::Matcher> inline_matcher;
        bool inline_needs_source=false, inline_needs_auth_user=false, inline_needs_response=false;
        bool inline_needs_source_uid=false, inline_needs_process=false, inline_needs_network=false;
        // Empty optionals denote the anonymous evaluate slot.
        std::optional<std::string> evaluate_tag,match_response_tag;
    };
    struct DnsDecision {
        DnsAction action=DnsAction::route;
        std::size_t server=0;
        bool disable_cache=false;
        std::optional<rules::DnsRuleStrategy> strategy{};
        std::optional<std::uint8_t> reject_rcode{};
        // Matched rule index metadata for CLI diagnostics (excluded from ==).
        std::optional<std::size_t> rule{};
        auto operator==(DnsDecision const& other) const -> bool {
            return action==other.action && server==other.server &&
                disable_cache==other.disable_cache && strategy==other.strategy &&
                reject_rcode==other.reject_rcode;
        }
    };
}
