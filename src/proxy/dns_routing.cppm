export module proxy.dns_routing;
import std;
import dns.corosio_query;
export import dns.policy;

export namespace proxy {
    struct DnsServer {
        std::array<std::uint8_t,16> address{};
        bool ipv6=false;
        std::uint16_t port=0;
        bool tcp=false;
        std::string host;
        std::optional<std::size_t> resolver;
        std::shared_ptr<dns::detail::ProtectedQuery const> protection{};
        bool proxy_detour=false;
    };
    using DnsRule=policy::DnsRule;
    enum class DnsStrategy { automatic, prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only };
    struct DnsRouting {
        std::vector<DnsServer> servers;
        std::vector<DnsRule> rules;
        std::size_t final=0;
        DnsStrategy strategy=DnsStrategy::automatic;
        bool disable_cache=false;
        bool edns=false;
        std::uint32_t optimistic_cache_seconds=0;
        std::vector<std::size_t> view_finals;
        [[nodiscard]] auto resolver_count() const noexcept -> std::size_t { return servers.size()+view_finals.size(); }
    };
}
