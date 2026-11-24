module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>

module relay:wireguard_detour;
import std;
import proxy.v4;
import net.udp_socket;
import net.datagram_frame;
import net.packet_stream_socket;
import capy;
import corosio;
import :types;
import :tunnel_facade;
import :session_interface;

namespace relay::wg_detail {
    namespace io = ::corosio;

    // WireGuard's nonblocking port polls these bounded queues. The lower
    // packet tunnel handles framing and peer validation on the same executor.
    class WireGuardOuterSocket {
        using Endpoint = net::UdpEndpoint;
        using Error = std::error_code;
        using Datagram = std::vector<std::uint8_t>;
        static constexpr std::size_t capacity = 16;
        net::UdpSocket physical_;
        std::optional<Endpoint> remote_;
        std::string const* network_namespace_ = nullptr;
        std::deque<Datagram> input_, output_;
        capy::async_event tx_;
        bool closed_ = false;

    public:
        auto attach(Endpoint peer) noexcept -> void { remote_ = peer; }
        auto native_handle() const noexcept -> int { return physical_.native_handle(); }
        auto set_network_namespace(std::string const& path) noexcept -> void { network_namespace_ = &path; }
        auto open() -> std::expected<void, Error> {
            return network_namespace_ ? physical_.open(false, *network_namespace_) : physical_.open();
        }
        auto bind(Endpoint local) -> std::expected<void, Error> {
            if (!remote_) return physical_.bind(local);
            return {};
        }
        auto local_endpoint() const -> std::expected<Endpoint, Error> {
            return remote_ ? std::expected<Endpoint, Error>(Endpoint{remote_->family}) : physical_.local_endpoint();
        }
        auto send(Endpoint peer, std::span<std::uint8_t const> bytes) -> std::expected<void, Error> {
            if (!remote_) return physical_.send(peer, bytes);
            if (closed_ || *remote_ != peer) return std::unexpected(std::make_error_code(std::errc::not_connected));
            if (output_.size() == capacity) return std::unexpected(std::make_error_code(std::errc::operation_would_block));
            output_.emplace_back(bytes.begin(), bytes.end());
            tx_.set();
            return {};
        }
        auto receive(std::span<std::uint8_t> bytes) -> std::expected<std::optional<net::UdpPacket>, Error> {
            if (!remote_) return physical_.receive(bytes);
            if (input_.empty()) return std::nullopt;
            auto const& packet = input_.front();
            auto valid = packet.size() <= bytes.size();
            if (valid) std::ranges::copy(packet, bytes.begin());
            net::UdpPacket info{*remote_, packet.size(), valid};
            input_.pop_front();
            return info;
        }
        auto close() noexcept -> void {
            physical_.close();
            closed_ = true;
            input_.clear();
            output_.clear();
            tx_.set();
        }

        template<class Socket>
        auto read_from(Socket& lower) -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 2048> bytes;
            while (!closed_) {
                io::endpoint source;
                auto [ec, size] = co_await lower.recv_from(capy::mutable_buffer(bytes.data(), bytes.size()), source);
                if (ec || closed_) break;
                if (input_.size() < capacity) input_.emplace_back(bytes.begin(), bytes.begin() + size);
            }
            co_return capy::results<>{};
        }

        template<class Socket>
        auto write_to(Socket& lower, io::endpoint peer) -> capy::task<capy::results<>> {
            while (!closed_) {
                tx_.clear();
                if (output_.empty()) {
                    auto [ec] = co_await tx_.wait();
                    if (ec) break;
                    continue;
                }
                auto packet = std::move(output_.front());
                output_.pop_front();
                auto [ec, size] = co_await lower.send_to(capy::const_buffer(packet.data(), packet.size()), peer);
                if (ec || size != packet.size()) break;
            }
            co_return capy::results<>{};
        }
    };

    struct WireGuardLowerStream {
        pro::proxy<TunnelFacade> tunnel;
        auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
        auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
        auto cancel() noexcept -> void { if (tunnel) tunnel->cancel(); }
    };

    struct WireGuardDetour {
        Session session;
        WireGuardLowerStream stream;
        net::PacketStreamSocket<WireGuardLowerStream> socket;
        io::endpoint peer;

        WireGuardDetour(Session const& parent, io::io_context& context, io::endpoint endpoint)
            : session(context), socket(context), peer(endpoint) {
            session.dns = parent.dns;
            session.local_dns = parent.local_dns;
            session.tunnel_factories = parent.tunnel_factories;
            session.direct_tcp_options = parent.direct_tcp_options;
        }

        auto connect(TunnelFactory const& factory, io::io_context& context, Clock::time_point deadline) -> capy::task<bool> {
            stream.tunnel = factory(session, context, false);
            if (!stream.tunnel) co_return false;
            auto transport = stream.tunnel->packet_transport();
            if (transport.kind == net::PacketTransportKind::none) co_return false;
            auto result = co_await stream.tunnel->connect_packets(net::packet_peer_address(peer), deadline);
            if (result != TunnelConnectResult::connected || !socket.attach(stream, transport, peer)) co_return false;
            co_return co_await socket.prepare(deadline);
        }

        auto close() noexcept -> void {
            socket.close();
            stream.cancel();
            session.close();
        }
    };
}
