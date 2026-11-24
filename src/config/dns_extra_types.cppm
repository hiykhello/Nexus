// Extended DNS server configuration types for config module.
export module config.dns_extra_types;
import std;
import platform.ip_address;

export namespace config {
    enum class DnsServerKind : std::uint8_t { standard, hosts, dhcp, mdns };
    struct DnsHostEntry {
        std::string domain;
        std::vector<platform::IpAddress> addresses;
        std::optional<std::string> cname{};
        auto operator==(DnsHostEntry const&) const -> bool = default;
    };
}
