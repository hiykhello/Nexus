module cli.dns_transports;
import std;
import config;
import dns.corosio_query;
import dns.input_budget;
import dns.message;
import platform.ip_address;

namespace cli {
    auto resolve_dhcp_endpoint(platform::IpAddress const&, std::string_view,
        std::string_view, std::uint16_t) noexcept -> std::optional<corosio::endpoint> {
        return std::nullopt;
    }

    auto query_dhcp_endpoints(corosio::io_context&, std::span<corosio::endpoint const>,
        dns::QueryMessage const&, std::uint16_t, std::chrono::steady_clock::time_point,
        dns::InputBudget&, std::stop_token)
        -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
        co_return std::unexpected(dns::detail::UdpError::transport);
    }

    auto prepare_dhcp_dns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        return std::unexpected("DHCP DNS server requires the dns-dhcp build feature");
    }
}
