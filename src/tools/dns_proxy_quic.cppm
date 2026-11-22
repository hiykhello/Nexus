export module cli.dns_proxy_quic;
import std;
import dns.corosio_query;
import dns.quic_query;

export namespace cli {
    auto make_proxy_quic_datagram(std::size_t outbound,dns::detail::TransportSnapshotRef) -> dns::QuicDnsDatagramFactory;
    auto prepare_proxy_quic(std::string_view server_name,std::string_view ca_file,std::size_t outbound,bool early_data,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
}
