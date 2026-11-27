export module dns.dhcp_upstream;
import std;
import containers.inplace_vector;
import platform.ip_address;

export namespace dns {
    struct DhcpServerEntry {
        platform::IpAddress address{};
        std::uint32_t lease_ttl_seconds = 3600;
        std::string scope{};
    };

    [[nodiscard]] auto is_ipv6_link_local(platform::IpAddress const& addr) noexcept -> bool;
    [[nodiscard]] auto resolve_ipv6_scope_id(std::string_view scope) noexcept -> std::uint32_t;

    [[nodiscard]] auto parse_dhcp_option6(std::span<std::uint8_t const> bytes, std::uint32_t lease_ttl_seconds = 3600)
        -> containers::inplace_vector<DhcpServerEntry, 8>;

    [[nodiscard]] auto parse_dhcp_lease_text(std::string_view text, std::string_view interface_filter = {})
        -> containers::inplace_vector<DhcpServerEntry, 8>;

    [[nodiscard]] auto discover_dhcp_dns_servers(std::span<std::string_view const> candidate_paths = {},
        std::string_view interface_filter = {})
        -> containers::inplace_vector<DhcpServerEntry, 8>;
}
