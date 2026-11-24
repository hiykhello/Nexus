module dns.https_query;
import std;
import dns.corosio_query;
import platform.socket_options;
import corosio;

namespace dns {
    auto stop_https_queries(corosio::io_context&) noexcept -> void {}
    auto resume_https_queries(corosio::io_context&) noexcept -> void {}
    auto reap_idle_https_queries(corosio::io_context&,std::chrono::steady_clock::time_point) noexcept -> void {}

    auto make_https_query(std::string_view,std::string_view,std::string_view,platform::TcpSocketOptions,std::optional<std::chrono::milliseconds>)
        -> std::expected<detail::ProtectedQuery,std::string> {
        return std::unexpected("DNS over HTTPS is unavailable in this build");
    }
}
