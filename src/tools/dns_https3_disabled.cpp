module cli.dns_https3;
import std;
import dns.corosio_query;
import platform.socket_options;

namespace cli {
    auto prepare_dns_https3(std::string_view,std::string_view,std::string_view,platform::SocketBinding,
        std::optional<std::chrono::milliseconds>,std::optional<std::size_t>,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        return std::unexpected("DNS over HTTP/3 is unavailable in this build");
    }
}
