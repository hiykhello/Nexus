export module dns.doh3_pool;
import std;
import dns.corosio_query;
import dns.quic_query;
import platform.socket_options;
import nexus.thirdparty.corosio;

export namespace dns {
    [[nodiscard]] auto make_https3_query(std::string_view server_name,std::string_view ca_file,std::string_view path,
        platform::SocketBinding,std::optional<std::chrono::milliseconds>,QuicDnsDatagramFactory)
        -> std::expected<detail::ProtectedQuery,std::string>;
    auto stop_https3_queries(nex::corosio::io_context&) noexcept -> void;
    auto resume_https3_queries(nex::corosio::io_context&) noexcept -> void;
    auto reap_idle_https3_queries(nex::corosio::io_context&,std::chrono::steady_clock::time_point) noexcept -> void;
}
