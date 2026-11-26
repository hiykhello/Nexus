export module tailscale.magic_dns;
import std;
import tailscale.control_messages;
import tailscale.snapshot;

export namespace tailscale::magic_dns {
    namespace cm = control_messages;

    enum class QueryType : std::uint16_t {
        a = 1,
        aaaa = 28,
        any = 255,
    };

    struct ResolverEndpoint {
        std::string addr;
        std::uint16_t port = 53;
        bool bootstrap_only = false;
        bool use_with_exit_node = false;
        auto operator==(ResolverEndpoint const&) const -> bool = default;
    };

    struct DnsConfig {
        bool proxied = false;
        std::string magic_dns_suffix;
        std::vector<std::string> search_domains;
        std::vector<ResolverEndpoint> resolvers;
        std::vector<ResolverEndpoint> fallback_resolvers;
        std::unordered_map<std::string, std::vector<ResolverEndpoint>> split_routes;
    };

    struct HostRecord {
        std::string fqdn;
        std::string short_name;
        std::vector<std::array<std::uint8_t, 4>> ipv4;
        std::vector<std::array<std::uint8_t, 16>> ipv6;
    };

    struct ResolveResult {
        bool authoritative_local = false;
        bool nxdomain = false;
        std::vector<std::array<std::uint8_t, 4>> ipv4;
        std::vector<std::array<std::uint8_t, 16>> ipv6;
        std::vector<ResolverEndpoint> upstreams;
        std::uint32_t ttl_s = 600;
    };

    // Parse MapResponse DNSConfig + Domain JSON fields into normalized MagicDNS configuration.
    // Returns std::nullopt when neither field carries a value (preserving prior snapshot).
    [[nodiscard]] auto parse_dns_config(cm::JsonField dns_config, cm::JsonField domain) noexcept
        -> std::expected<std::optional<DnsConfig>, cm::Failure>;

    // Normalize a DNS name to lowercase without trailing dot.
    [[nodiscard]] auto normalize_name(std::string_view name) -> std::string;

    // Thread-safe MagicDNS resolver and split-DNS router suitable for concurrent
    // multi-worker DNS queries while Tailscale control updates Map snapshots.
    class Resolver {
        struct Snapshot {
            DnsConfig config;
            std::unordered_map<std::string, HostRecord> by_fqdn;
            std::unordered_map<std::string, std::string> by_short;
            std::uint64_t generation = 0;
        };
        mutable std::mutex mutex_;
        std::shared_ptr<Snapshot const> current_;
        std::uint64_t generation_ = 0;

    public:
        Resolver() = default;

        auto update(DnsConfig config, std::span<snapshot::Peer const> peers,
                    snapshot::Peer const* self = nullptr) -> std::uint64_t;
        auto clear() noexcept -> void;

        [[nodiscard]] auto ready() const noexcept -> bool;
        [[nodiscard]] auto generation() const noexcept -> std::uint64_t;
        [[nodiscard]] auto magic_dns_suffix() const -> std::string;
        [[nodiscard]] auto proxied() const noexcept -> bool;

        // Resolve local tailnet names (.ts.net / short names via search domains)
        // or return split-DNS / global upstream resolvers for external queries.
        [[nodiscard]] auto resolve(std::string_view qname, QueryType qtype = QueryType::any) const
            -> ResolveResult;

        // Select upstream resolvers for split-DNS or fallback forwarding.
        [[nodiscard]] auto select_upstreams(std::string_view qname, bool via_exit_node = false) const
            -> std::vector<ResolverEndpoint>;
    };
}
