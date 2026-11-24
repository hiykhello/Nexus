module cli.dns_transports;
import std;
import config;
import dns.corosio_query;

namespace cli {
    auto prepare_mdns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        return std::unexpected("mDNS server requires the dns-mdns build feature");
    }
}
