export module dns.dhcp_upstream;
import std;
import nexus.compat;
import platform.ip_address;

export namespace dns {
    struct DhcpServerEntry {
        platform::IpAddress address{};
        std::uint32_t lease_ttl_seconds = 3600;
    };

    [[nodiscard]] auto parse_dhcp_option6(std::span<std::uint8_t const> bytes, std::uint32_t lease_ttl_seconds = 3600)
        -> nexus::inplace_vector<DhcpServerEntry, 8>;

    [[nodiscard]] auto parse_dhcp_lease_text(std::string_view text)
        -> nexus::inplace_vector<DhcpServerEntry, 8>;

    [[nodiscard]] auto discover_dhcp_dns_servers(std::span<std::string_view const> candidate_paths = {})
        -> nexus::inplace_vector<DhcpServerEntry, 8>;
}
