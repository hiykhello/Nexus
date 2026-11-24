export module dns.https_query;
import std;
import dns.corosio_query;
import platform.socket_options;
import corosio;

export namespace dns {
    auto stop_https_queries(corosio::io_context&) noexcept -> void;
    auto resume_https_queries(corosio::io_context&) noexcept -> void;
    auto reap_idle_https_queries(corosio::io_context&,std::chrono::steady_clock::time_point) noexcept -> void;

    [[nodiscard]] auto make_https_query(std::string_view server_name,std::string_view ca_file,std::string_view path,
        platform::TcpSocketOptions, std::optional<std::chrono::milliseconds> connect_timeout={}) -> std::expected<detail::ProtectedQuery,std::string>;
}
