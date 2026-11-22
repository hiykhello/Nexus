module dns.tls_query;
import std;
import nexus.thirdparty.corosio;
import platform.socket_options;
import dns.corosio_query;

namespace dns {
    auto make_tls_query(std::string_view,std::string_view,platform::TcpSocketOptions,std::chrono::milliseconds)
        -> std::expected<detail::ProtectedQuery,std::string> {
        return std::unexpected("DNS over TLS is unavailable in this build");
    }

    auto make_routed_tls_query(TlsDnsStreamFactory,std::chrono::milliseconds)
        -> std::expected<detail::ProtectedQuery,std::string> {
        return std::unexpected("DNS over TLS is unavailable in this build");
    }

    auto stop_tls_queries(nex::corosio::io_context&) noexcept -> void {}
    auto resume_tls_queries(nex::corosio::io_context&) noexcept -> void {}
    auto reap_idle_tls_queries(nex::corosio::io_context&,std::chrono::steady_clock::time_point) noexcept -> void {}
}
