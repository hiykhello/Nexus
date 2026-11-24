module;
#include <proxy/proxy_macros.h>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>

module relay:masque_common;
import std;
import proxy.v4;
import masque.client_profile;
import masque.client_session;
import masque.connect_ip;
import quic.ech_config;
import net.datagram_frame;
import net.packet_stream_socket;
import net.unified_datagram;
import platform.socket_options;
import capy;
import corosio;
import :types;
import :tunnel_facade;
import :session_interface;
import :quic_ech;

namespace relay::masque_detail {
    namespace io = ::corosio;

    struct LowerPacketStream {
        Session session;
        pro::proxy<TunnelFacade> tunnel;
        explicit LowerPacketStream(Session const& parent, io::io_context& ctx) : session(ctx) {
            session.dns = parent.dns;
            session.local_dns = parent.local_dns;
            session.tunnel_factories = parent.tunnel_factories;
            session.direct_tcp_options = parent.direct_tcp_options;
            session.started = parent.started;
            session.handshake_deadline = parent.handshake_deadline;
        }
        ~LowerPacketStream() { cancel(); }
        auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
        auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
        auto cancel() noexcept -> void { if (tunnel) tunnel->cancel(); session.close(); }
        auto connect(TunnelFactory const& factory, io::io_context& ctx, net::UnifiedDatagramSocket& socket,
                     io::endpoint peer, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (session.closed || tunnel) co_return TunnelConnectResult::failed;
            if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
            auto stop = co_await capy::this_coro::stop_token;
            std::stop_callback canceled(stop, [this]() noexcept { cancel(); });
            if (session.closed) co_return TunnelConnectResult::failed;
            tunnel = factory(session, ctx, false);
            if (!tunnel) co_return TunnelConnectResult::failed;
            auto transport = tunnel->packet_transport();
            if (transport.kind == net::PacketTransportKind::none) co_return TunnelConnectResult::failed;
            auto connected = co_await tunnel->connect_packets(net::packet_peer_address(peer), deadline);
            if (connected != TunnelConnectResult::connected) co_return connected;
            if (session.closed || !socket.attach_detour(*this, transport, peer)) co_return TunnelConnectResult::failed;
            if (co_await socket.prepare_detour(deadline) && !session.closed) co_return TunnelConnectResult::connected;
            co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
        }
    };

    struct MasqueIpHost;

    struct MasqueOutProfile {
        std::string host;
        std::uint16_t port = 0;
        std::optional<std::size_t> bootstrap;
        std::uint32_t timeout = 10000;
        std::unique_ptr<masque::ClientProfile> client;
        TcpSocketOptions options;
        MasqueIpOptions ip;
        masque::ConnectIpScope scope;
        quic_ech::Profile ech;
        std::mutex mutex;
        std::unordered_map<io::io_context*, std::shared_ptr<MasqueIpHost>> physical_hosts;
        std::unordered_map<io::io_context*, std::shared_ptr<MasqueIpHost>> packet_hosts;

        auto hosts(bool layered) noexcept -> auto& {
            return layered ? packet_hosts : physical_hosts;
        }

        auto get_host(io::io_context&, platform::SocketBinding const&, TunnelFactory const* = nullptr)
            -> std::shared_ptr<MasqueIpHost>;
    };

    struct MasqueConnection {
        using Client = masque::Client<net::UnifiedDatagramSocket>;
        std::optional<LowerPacketStream> lower;
        Client client;

        MasqueConnection(Session const& session, io::io_context& ctx, masque::ClientProfile const& profile, bool layered)
            : client(ctx, profile) {
            if (layered) lower.emplace(session, ctx);
        }
        ~MasqueConnection() { client.finish(); }

        auto stop() noexcept -> void {
            client.request_stop();
            if (lower) lower->cancel();
        }
    };

    auto start_masque_connection(Session& session, io::io_context& context, MasqueOutProfile const& profile,
        platform::SocketBinding binding, TunnelFactory const* lower, io::endpoint peer, quic::EchConfig const* ech,
        Clock::time_point deadline, bool const& stopped, std::shared_ptr<MasqueConnection>& current)
        -> capy::task<TunnelConnectResult>;
}
