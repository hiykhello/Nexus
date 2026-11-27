module cli.dns_transports;
import std;
import config;
import dns.corosio_query;
import dns.message;

namespace cli {
    auto convert_mdns_response(dns::Question const&, std::uint16_t, std::span<std::uint8_t const>)
        -> std::expected<std::optional<dns::Response>, dns::detail::UdpError> {
        return std::unexpected(dns::detail::UdpError::transport);
    }
    auto prepare_mdns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        return std::unexpected("mDNS server requires the dns-mdns build feature");
    }
}
