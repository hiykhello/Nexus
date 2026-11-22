#pragma once

// Included inside the QUIC outbound implementation's private namespace.
struct QuicPacketDetour {
    Session session;
    pro::proxy<TunnelFacade> tunnel;

    QuicPacketDetour(Session const& parent, io::io_context& context) : session(context) {
        session.dns = parent.dns;
        session.local_dns = parent.local_dns;
        session.tunnel_factories = parent.tunnel_factories;
        session.direct_tcp_options = parent.direct_tcp_options;
        session.started = parent.started;
        session.handshake_deadline = parent.handshake_deadline;
    }

    auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
    auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
    auto cancel() noexcept -> void {
        if (tunnel) tunnel->cancel();
        session.close();
    }

    using Socket = net::PacketStreamSocket<QuicPacketDetour>;

    auto connect(TunnelFactory const& factory, io::io_context& context, Socket& socket,
                 io::endpoint peer, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
        if (session.closed || tunnel) co_return TunnelConnectResult::failed;
        if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
        auto stop = co_await nex::capy::this_coro::stop_token;
        std::stop_callback canceled(stop, [this]() noexcept { cancel(); });
        if (session.closed) co_return TunnelConnectResult::failed;
        tunnel = factory(session, context, false);
        if (!tunnel) co_return TunnelConnectResult::failed;
        auto transport = tunnel->packet_transport();
        if (transport.kind == net::PacketTransportKind::none) co_return TunnelConnectResult::failed;
        auto connected = co_await tunnel->connect_packets(net::packet_peer_address(peer),deadline);
        if (connected != TunnelConnectResult::connected) co_return connected;
        if (session.closed || !socket.attach(*this, transport, peer)) co_return TunnelConnectResult::failed;
        auto prepared = co_await socket.prepare(deadline);
        if (prepared && !session.closed) co_return TunnelConnectResult::connected;
        co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
    }
};

struct PhysicalQuicPacketSocket {
    using Socket = io::udp_socket;
    explicit PhysicalQuicPacketSocket(Session const&, io::io_context&) noexcept {}
    auto cancel() noexcept -> void {}
};
