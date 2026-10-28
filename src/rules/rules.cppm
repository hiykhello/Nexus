export module nexus.rules;
import std;

export namespace nexus::rules {
    enum class ErrorCode { syntax, schema, limit, invalid_rule, invalid_query };

    struct Error {
        ErrorCode code;
        std::string message;
    };

    struct Rule {
        std::string type;
        std::string value;
        auto operator==(Rule const&) const -> bool;
    };

    struct RuleSet {
        std::vector<Rule> rules;
        auto operator==(RuleSet const&) const -> bool;
    };

    struct MatchInput {
        std::optional<std::string_view> domain;
        std::optional<std::string_view> ip;
    };

    class Matcher {
        struct Entry {
            std::string suffix;
            std::array<std::uint8_t, 16> address{};
            unsigned prefix = 0;
            unsigned family = 0;
        };
        std::vector<Entry> entries_;

    public:
        Matcher();
        Matcher(Matcher const&);
        Matcher(Matcher&&) noexcept;
        auto operator=(Matcher const&) -> Matcher&;
        auto operator=(Matcher&&) noexcept -> Matcher&;
        ~Matcher();

        [[nodiscard]] static auto compile(RuleSet const& set) -> std::expected<Matcher, Error>;
        [[nodiscard]] auto match(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error>;
    };

    // Ordered rule sets choose an opaque outbound index; all predicates in one
    // set share its action. The caller owns and validates the outbound table.
    struct RouteRule { RuleSet predicates; std::size_t outbound; };
    class RouteMatcher {
        Matcher matcher_;
        std::vector<std::size_t> actions_;
        std::size_t default_outbound_ = 0;
        std::vector<bool> ip_predicates_;
    public:
        [[nodiscard]] static auto compile(std::span<RouteRule const> rules, std::size_t default_outbound,
                                          std::size_t outbound_count) -> std::expected<RouteMatcher, Error>;
        // A missing result means an earlier IP predicate requires resolution.
        // A result determines the action only, not the endpoint to dial.
        [[nodiscard]] auto preflight(std::string_view domain) const
            -> std::expected<std::optional<std::size_t>, Error>;
        // A mapped IPv6 target is evaluated as both families. The earliest
        // matching predicate wins across domain, IPv6 and mapped IPv4.
        [[nodiscard]] auto match(MatchInput input) const -> std::expected<std::size_t, Error>;
    };
    inline constexpr unsigned max_rules = 16384;
    inline constexpr unsigned max_input_bytes = 1048576;

    [[nodiscard]] auto normalize_rule(Rule rule) -> std::expected<Rule, Error>;
    [[nodiscard]] auto parse_kdl(std::string_view input) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto write_kdl(RuleSet const& set) -> std::expected<std::string, Error>;
    [[nodiscard]] auto parse_beve(std::string_view input) -> std::expected<RuleSet, Error>;
    [[nodiscard]] auto write_beve(RuleSet const& set) -> std::expected<std::string, Error>;
}
