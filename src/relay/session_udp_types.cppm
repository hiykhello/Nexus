// Shared SOCKS5 UDP slot types, UOT/XUDP helpers, and framed reader declaration.
module relay:session_udp_types;
import std;
import capy;
import corosio;
import proxy.v4;
import net.datagram_frame;
import socks5;
import socks5.udp_ingress;
import socks5.udp_tunnel_authorization;
import uot;
import xudp;
import xudp.client_io;
import :types;
import :tunnel_facade;
import :session_interface;

namespace relay::session_udp_detail {
#ifdef NEXUS_ENABLE_SOCKS_UDP
#ifdef NEXUS_ENABLE_VLESS
    struct XudpStream {
        pro::proxy<TunnelFacade>* tunnel = nullptr;
        std::optional<Clock::time_point>* deadline = nullptr;
        bool const* closed = nullptr;
        auto write(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            auto until = deadline && *deadline ? **deadline : Clock::time_point::max();
            if ((closed && *closed) || Clock::now() >= until) { cancel(); co_return false; }
            auto sent = co_await (*tunnel)->send(bytes);
            // ClientIo commits reply authorization only after this returns.
            if (!sent || (closed && *closed) || Clock::now() >= until) { cancel(); co_return false; }
            co_return true;
        }
        auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
            co_return co_await (*tunnel)->read(bytes);
        }
        auto cancel() noexcept -> void { if (tunnel && *tunnel) (*tunnel)->cancel(); }
    };
#endif

    struct UotSlot {
        pro::proxy<TunnelFacade> tunnel;
        socks5::UdpTunnelAuthorization authorization;
        net::DatagramFraming framing;
#ifdef NEXUS_ENABLE_VLESS
        XudpStream xudp_stream;
        std::unique_ptr<xudp::ClientIo<XudpStream>> xudp_client;
        std::uint16_t xudp_session = 0;
#endif
        bool ready = false, rotating = false, reader_active = false;
        capy::async_event readiness, reader_done;
    };

    inline constexpr std::size_t routed_udp_slots = 4096;
    inline constexpr std::size_t fixed_udp_slots = 512;
    inline constexpr std::size_t alias_udp_slots = 512;
    inline constexpr std::size_t ordinary_udp_slots = routed_udp_slots + fixed_udp_slots;

    inline auto uot_address(socks5::UdpPeer peer) -> uot::Address {
        uot::Address out;
        out.family = peer.address_type == 1 ? uot::Family::ipv4 : uot::Family::ipv6;
        out.length = peer.address_type == 1 ? 4 : 16;
        out.port = peer.port;
        std::copy_n(peer.address.begin(), out.length, out.bytes.begin());
        return out;
    }

#ifdef NEXUS_ENABLE_VLESS
    inline auto xudp_address(socks5::UdpPeer peer) -> xudp::Address {
        xudp::Address out;
        out.family = peer.address_type == 1 ? xudp::Family::ipv4 : xudp::Family::ipv6;
        out.length = peer.address_type == 1 ? 4 : 16;
        out.port = peer.port;
        std::copy_n(peer.address.begin(), out.length, out.bytes.begin());
        return out;
    }
#endif

    struct UdpResolution {
        bool active = false, canceled = false;
        Clock::time_point deadline{};
    };

    auto uot_read_framed(Session& session, socks5::UdpIngress& ingress,
        pro::proxy<TunnelFacade>& tunnel, socks5::UdpTunnelAuthorization& authorization, net::DatagramFraming framing,
        net::ProxyAddress peer, socks5::UdpPeer const* alias = nullptr, bool const* closing = nullptr,
        Clock::time_point* touched = nullptr) -> capy::task<>;
#endif
}
