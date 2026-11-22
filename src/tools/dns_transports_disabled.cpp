module cli.dns_transports;
import std;
import config;
import dns.corosio_query;

namespace cli {
    auto prepare_encrypted_dns_transport(config::DnsTls const& profile,config::TcpSocketOptions const&,
        std::optional<std::chrono::milliseconds>,std::optional<std::size_t>,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        switch (profile.transport) {
        case config::DnsSecurity::tls:
            return std::unexpected("DNS over TLS is unavailable in this build");
        case config::DnsSecurity::https:
            return std::unexpected("DNS over HTTPS is unavailable in this build");
        case config::DnsSecurity::https3:
            return std::unexpected("DNS over HTTP/3 is unavailable in this build");
        case config::DnsSecurity::quic:
            return std::unexpected("DNS over QUIC is unavailable in this build");
        }
        std::unreachable();
    }
}
