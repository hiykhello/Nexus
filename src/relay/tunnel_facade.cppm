// Tunnel facade and factory declarations for proxy runtime.
module;
#include <proxy/proxy_macros.h>

export module relay:tunnel_facade;
import std;
import capy;
import corosio;
import functional;
import proxy.v4;
import net.datagram_frame;
import :types;

namespace relay {
    enum class TunnelConnectResult { connected, retryable, failed, timeout };
    PRO_DEF_MEM_DISPATCH(TunnelConnect, connect);
    PRO_DEF_MEM_DISPATCH(TunnelConnectUntil, connect_until);
    PRO_DEF_MEM_DISPATCH(TunnelConnectDomainMember, connect_domain);
    struct TunnelConnectDomain : TunnelConnectDomainMember {
        using TunnelConnectDomainMember::operator();
        template<class T>
        requires (!requires(T& tunnel, std::string_view host, std::uint16_t port, Clock::time_point until) {
            tunnel.connect_domain(host, port, until);
        })
        static auto operator()(T&, std::string_view, std::uint16_t, Clock::time_point)
            -> capy::task<TunnelConnectResult> {
            co_return TunnelConnectResult::failed;
        }
    };
    PRO_DEF_MEM_DISPATCH(TunnelConnectUot, connect_uot);
    PRO_DEF_MEM_DISPATCH(TunnelConnectUotUntil, connect_uot_until);
    PRO_DEF_MEM_DISPATCH(TunnelHasUot, has_uot);
    PRO_DEF_MEM_DISPATCH(TunnelConnectXudp, connect_xudp);
    PRO_DEF_MEM_DISPATCH(TunnelConnectXudpUntil, connect_xudp_until);
    PRO_DEF_MEM_DISPATCH(TunnelHasXudp, has_xudp);
    PRO_DEF_MEM_DISPATCH(TunnelSend, send);
    PRO_DEF_MEM_DISPATCH(TunnelRead, read);
    PRO_DEF_MEM_DISPATCH(TunnelUpload, upload);
    PRO_DEF_MEM_DISPATCH(TunnelDownload, download);
    PRO_DEF_MEM_DISPATCH(TunnelCancel, cancel);
    PRO_DEF_MEM_DISPATCH(TunnelCloseOutput, close_output);
    PRO_DEF_MEM_DISPATCH(TunnelPacketTransport, packet_transport);
    PRO_DEF_MEM_DISPATCH(TunnelConnectPacketsMember, connect_packets);
    struct TunnelConnectPackets : TunnelConnectPacketsMember {
        using TunnelConnectPacketsMember::operator();
        template<class T>
        requires (!requires(T& tunnel, net::ProxyAddress const& peer, Clock::time_point until) {
            tunnel.connect_packets(peer, until);
        })
        static auto operator()(T& tunnel, net::ProxyAddress const&, Clock::time_point until)
            -> decltype(tunnel.connect_packets(until)) {
            return tunnel.connect_packets(until);
        }
    };
    struct TunnelFacade : pro::facade_builder
        ::add_convention<TunnelPacketTransport, net::PacketTransport() const noexcept>
        ::add_convention<TunnelConnectPackets, capy::task<TunnelConnectResult>(Clock::time_point),
            capy::task<TunnelConnectResult>(net::ProxyAddress const&, Clock::time_point)>
        ::add_convention<TunnelConnect, capy::task<TunnelConnectResult>(io::endpoint)>
        ::add_convention<TunnelConnectUntil, capy::task<TunnelConnectResult>(io::endpoint, Clock::time_point)>
        ::add_convention<TunnelConnectDomain, capy::task<TunnelConnectResult>(std::string_view, std::uint16_t, Clock::time_point)>
        ::add_convention<TunnelConnectUot, capy::task<TunnelConnectResult>()>
        ::add_convention<TunnelConnectUotUntil, capy::task<TunnelConnectResult>(Clock::time_point)>
        ::add_convention<TunnelHasUot, bool() const noexcept>
        ::add_convention<TunnelConnectXudp, capy::task<TunnelConnectResult>()>
        ::add_convention<TunnelConnectXudpUntil, capy::task<TunnelConnectResult>(Clock::time_point)>
        ::add_convention<TunnelHasXudp, bool() const noexcept>
        ::add_convention<TunnelSend, capy::task<bool>(std::span<std::uint8_t const>)>
        ::add_convention<TunnelRead, capy::task<std::expected<std::size_t, std::string>>(std::span<std::uint8_t>)>
        ::add_convention<TunnelUpload, capy::task<bool>()>
        ::add_convention<TunnelDownload, capy::task<bool>()>
        ::add_convention<TunnelCloseOutput, capy::task<bool>()>
        ::add_convention<TunnelCancel, void() noexcept>::build {};
    struct TunnelFactory {
        functional::move_only_function<pro::proxy<TunnelFacade>(Session&, io::io_context&, bool, TcpSocketOptions const*) const> create;
        std::uint32_t timeout_ms;
        // Both constructors borrow the immutable profile owned by create.
        functional::move_only_function<pro::proxy<TunnelFacade>(Session&, io::io_context&, TunnelFactory const&, bool) const> through;
        std::optional<std::size_t> detour;
        bool requires_direct_socket = false;
        bool detour_direct = false;
        functional::move_only_function<bool(OutboundContext const&, TunnelFactory const*, bool) const> start_context;
        functional::move_only_function<void(io::io_context&) const noexcept> stop_context, finish_context, reap_context;
        // Optional shutdown barrier for a consumer whose final packets use
        // a lower factory. Evaluated only while stopping, on this executor.
        functional::move_only_function<bool(io::io_context&) const noexcept> quiesced_context;
        // This packet carrier accepts targets from both address families on
        // the same association.
        bool packet_dual_family = false;
        bool packet_fixed_peer = false;
        bool remote_domain_dial = false;
        // Only the terminal relay owns cancellation of the inbound socket.
        auto operator()(Session& session, io::io_context& context, bool relay_local = true) const -> pro::proxy<TunnelFacade>;
    };
    export enum class PacketConnectResult { connected, retryable, failed, timeout };
    // A packet transport borrows its routing session and factory. Cancel and
    // drain its read/write tasks before destroying the transport or session.
}
