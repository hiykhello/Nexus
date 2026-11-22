module cli.dns_proxy_https;
import std;
import dns.corosio_query;

namespace cli {
    auto prepare_proxy_https(std::string_view,std::string_view,std::string_view,std::size_t,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        return std::unexpected("DNS over HTTPS is unavailable in this build");
    }
}
