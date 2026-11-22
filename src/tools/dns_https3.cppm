export module cli.dns_https3;
import std;
import dns.corosio_query;
import platform.socket_options;

export namespace cli {
    auto prepare_dns_https3(std::string_view server_name,std::string_view ca_file,std::string_view path,
        platform::SocketBinding,std::optional<std::chrono::milliseconds>,std::optional<std::size_t> outbound,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
}
