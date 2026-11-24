module;
#include <proxy/proxy_macros.h>

export module dns.tls_query;
import std;
export import functional;
import proxy.v4;
import dns.corosio_query;
import dns.https_query;
import platform.socket_options;

export namespace dns {
    PRO_DEF_MEM_DISPATCH(DnsStreamStart,start);
    PRO_DEF_MEM_DISPATCH(DnsStreamRead,read);
    PRO_DEF_MEM_DISPATCH(DnsStreamSend,send);
    PRO_DEF_MEM_DISPATCH(DnsStreamCancel,cancel);

    struct TlsDnsStreamFacade : pro::facade_builder
        ::add_convention<DnsStreamStart,detail::dns_capy::task<bool>(std::chrono::steady_clock::time_point)>
        ::add_convention<DnsStreamRead,detail::dns_capy::task<std::size_t>(std::span<std::uint8_t>)>
        ::add_convention<DnsStreamSend,detail::dns_capy::task<bool>(
            std::span<std::uint8_t const>,std::chrono::steady_clock::time_point)>
        ::add_convention<DnsStreamCancel,void() noexcept>::build {};
    using TlsDnsStream=pro::proxy<TlsDnsStreamFacade>;
    using TlsDnsStreamFactory=functional::move_only_function<TlsDnsStream(
        detail::dns_io::io_context&,detail::dns_io::endpoint) const>;

    [[nodiscard]] auto make_routed_tls_query(TlsDnsStreamFactory,std::chrono::milliseconds connect_timeout)
        -> std::expected<detail::ProtectedQuery,std::string>;
    [[nodiscard]] auto make_tls_query(std::string_view server_name,std::string_view ca_file,platform::TcpSocketOptions, std::chrono::milliseconds connect_timeout=std::chrono::seconds(5))
        -> std::expected<detail::ProtectedQuery,std::string>;
    auto reap_idle_tls_queries(corosio::io_context&,std::chrono::steady_clock::time_point) noexcept -> void;

    auto stop_tls_queries(corosio::io_context&) noexcept -> void;
    auto resume_tls_queries(corosio::io_context&) noexcept -> void;

    class TlsQueryMaintenance {
        using Clock=std::chrono::steady_clock;
        Clock::time_point next_{};
    public:
        auto poll(corosio::io_context& context,Clock::time_point now=Clock::now()) noexcept -> void {
            if (now<next_) return;
            next_=now+std::chrono::seconds(1);
            reap_idle_tls_queries(context,now);
            reap_idle_https_queries(context,now);
        }
    };
}
