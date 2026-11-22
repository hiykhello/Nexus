module cli.dns_proxy_quic;
import std;
import dns.corosio_query;

namespace cli {
    auto prepare_proxy_quic(std::string_view,std::string_view,std::size_t,bool,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        return std::unexpected("DNS over QUIC is unavailable in this build");
    }
}
