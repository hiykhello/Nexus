export module cli.dns_proxy_tls;
import std;
import dns.corosio_query;

export namespace cli {
    auto prepare_proxy_tls(std::string_view server_name,std::string_view ca_file,std::size_t outbound,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
}
