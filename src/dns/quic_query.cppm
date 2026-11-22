module;
#include <proxy/proxy_macros.h>

export module dns.quic_query;
import std;
export import nexus.compat;
import proxy.v4;
import dns.corosio_query;
import platform.socket_options;

export namespace dns {
    PRO_DEF_MEM_DISPATCH(DnsDatagramPrepare,prepare);
    PRO_DEF_MEM_DISPATCH(DnsDatagramLocal,local_endpoint);
    PRO_DEF_MEM_DISPATCH(DnsDatagramClose,close);
    PRO_DEF_MEM_DISPATCH(DnsDatagramSend,send_to);
    PRO_DEF_MEM_DISPATCH(DnsDatagramReceive,recv_from);

    struct QuicDnsDatagramFacade : pro::facade_builder
        ::add_convention<DnsDatagramPrepare,detail::dns_capy::task<bool>(
            detail::dns_io::endpoint,std::chrono::steady_clock::time_point)>
        ::add_convention<DnsDatagramLocal,detail::dns_io::endpoint() const noexcept>
        ::add_convention<DnsDatagramClose,void() noexcept>
        ::add_convention<DnsDatagramSend,detail::dns_capy::task<detail::dns_capy::results<std::size_t>>(
            detail::dns_capy::const_buffer,detail::dns_io::endpoint)>
        ::add_convention<DnsDatagramReceive,detail::dns_capy::task<detail::dns_capy::results<std::size_t>>(
            detail::dns_capy::mutable_buffer,detail::dns_io::endpoint&)>::build {};
    using QuicDnsDatagram=pro::proxy<QuicDnsDatagramFacade>;
    using QuicDnsDatagramFactory=nexus::move_only_function<QuicDnsDatagram(detail::dns_io::io_context&) const>;

    [[nodiscard]] auto make_quic_query(std::string_view server_name,std::string_view ca_file,platform::SocketBinding, std::chrono::milliseconds connect_timeout=std::chrono::seconds(5),bool early_data=false,QuicDnsDatagramFactory={})
        -> std::expected<detail::ProtectedQuery,std::string>;
}
