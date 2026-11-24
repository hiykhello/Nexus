module cli.dns_transports;
import std;
import config;
import dns.corosio_query;

namespace cli {
    auto prepare_dhcp_dns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        return std::unexpected("DHCP DNS server requires the dns-dhcp build feature");
    }
}
