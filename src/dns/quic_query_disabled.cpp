module dns.quic_query;
import std;
import dns.corosio_query;
import platform.socket_options;
import corosio;

namespace dns {
    auto stop_quic_queries(corosio::io_context&) noexcept -> void {}
    auto resume_quic_queries(corosio::io_context&) noexcept -> void {}
    auto make_quic_query(std::string_view,std::string_view,platform::SocketBinding,std::chrono::milliseconds,bool,QuicDnsDatagramFactory)
        -> std::expected<detail::ProtectedQuery,std::string> {
        return std::unexpected("DNS over QUIC is unavailable in this build");
    }
}
