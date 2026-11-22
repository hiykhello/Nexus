module cli.dns_transports;
import std;
import config;
import dns.corosio_query;
import dns.tls_query;
import dns.https_query;
import dns.quic_query;
import cli.dns_proxy_quic;
import cli.dns_proxy_https;
import cli.dns_https3;
import cli.dns_proxy_tls;

namespace cli {
    auto prepare_encrypted_dns_transport(config::DnsTls const& profile,config::TcpSocketOptions const& options,
        std::optional<std::chrono::milliseconds> connect_timeout,std::optional<std::size_t> proxy_outbound,
        dns::detail::TransportSnapshotRef snapshot)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        switch (profile.transport) {
        case config::DnsSecurity::tls:
            if (proxy_outbound)
                return prepare_proxy_tls(profile.server_name,profile.ca_file,*proxy_outbound,snapshot);
            return dns::make_tls_query(profile.server_name,profile.ca_file,options,connect_timeout.value_or(std::chrono::seconds(5)));
        case config::DnsSecurity::https:
            if (proxy_outbound)
                return prepare_proxy_https(profile.server_name,profile.ca_file,profile.path,*proxy_outbound,snapshot);
            return dns::make_https_query(profile.server_name,profile.ca_file,profile.path,options,connect_timeout);
        case config::DnsSecurity::https3:
            return prepare_dns_https3(profile.server_name,profile.ca_file,profile.path,options.binding,connect_timeout,proxy_outbound,snapshot);
        case config::DnsSecurity::quic:
            if (proxy_outbound)
                return prepare_proxy_quic(profile.server_name,profile.ca_file,*proxy_outbound,profile.early_data,snapshot);
            return dns::make_quic_query(profile.server_name,profile.ca_file,options.binding,connect_timeout.value_or(std::chrono::seconds(5)),profile.early_data);
        }
        std::unreachable();
    }
}
