module cli.dns_https3;
import std;
import cli.dns_proxy_quic;
import dns.corosio_query;
import dns.doh3_pool;
import dns.quic_query;
import platform.socket_options;

namespace cli {
    auto prepare_dns_https3(std::string_view server_name,std::string_view ca_file,std::string_view path,
        platform::SocketBinding binding,std::optional<std::chrono::milliseconds> timeout,
        std::optional<std::size_t> outbound,dns::detail::TransportSnapshotRef snapshot)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        auto route=outbound ? make_proxy_quic_datagram(*outbound,std::move(snapshot)) : dns::QuicDnsDatagramFactory{};
        return dns::make_https3_query(server_name,ca_file,path,std::move(binding),timeout,std::move(route));
    }
}
