module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>

module relay:wireguard_detour;
import std;
import containers.ring_queue;
import proxy.v4;
import net.udp_socket;
import net.datagram_frame;
import net.packet_stream_socket;
import uot;
import xudp;
import xudp.client_io;
import xudp.client_sessions;
import capy;
import corosio;
import :types;
import :tunnel_facade;
import :session_interface;

namespace relay::wg_detail {
    namespace io = ::corosio;

    inline auto to_io_endpoint(net::UdpEndpoint const& ep) noexcept -> io::endpoint {
        if (ep.family == 6) return io::endpoint(io::ipv6_address(ep.address), ep.port);
        io::ipv4_address::bytes_type b{};
        std::copy_n(ep.address.begin(), 4, b.begin());
        return io::endpoint(io::ipv4_address(b), ep.port);
    }

    inline auto to_udp_endpoint(io::endpoint const& ep) noexcept -> net::UdpEndpoint {
        net::UdpEndpoint out{};
        out.port = ep.port();
        if (ep.is_v6()) {
            out.family = 6;
            out.address = ep.address().to_v6().to_bytes();
        } else {
            out.family = 4;
            auto b = ep.address().to_v4().to_bytes();
            std::ranges::copy(b, out.address.begin());
        }
        return out;
    }

    inline auto proxy_to_io_endpoint(net::ProxyAddress const& addr) noexcept -> std::optional<io::endpoint> {
        if (!addr.port) return std::nullopt;
        if (addr.family == net::ProxyAddressFamily::ipv4 && addr.length == 4) {
            io::ipv4_address::bytes_type b{};
            std::copy_n(addr.bytes.begin(), 4, b.begin());
            return io::endpoint(io::ipv4_address(b), addr.port);
        }
        if (addr.family == net::ProxyAddressFamily::ipv6 && addr.length == 16) {
            io::ipv6_address::bytes_type b{};
            std::copy_n(addr.bytes.begin(), 16, b.begin());
            return io::endpoint(io::ipv6_address(b), addr.port);
        }
        return std::nullopt;
    }

    inline auto io_to_xudp_address(io::endpoint const& ep) noexcept -> xudp::Address {
        xudp::Address result{};
        result.port = ep.port();
        if (ep.is_v6()) {
            result.family = xudp::Family::ipv6;
            result.length = 16;
            auto b = ep.address().to_v6().to_bytes();
            std::ranges::copy(b, result.bytes.begin());
        } else {
            result.family = xudp::Family::ipv4;
            result.length = 4;
            auto b = ep.address().to_v4().to_bytes();
            std::ranges::copy(b, result.bytes.begin());
        }
        return result;
    }

    inline auto xudp_to_io_endpoint(xudp::Address const& addr) noexcept -> std::optional<io::endpoint> {
        if (!addr.port) return std::nullopt;
        if (addr.family == xudp::Family::ipv4 && addr.length == 4) {
            io::ipv4_address::bytes_type b{};
            std::copy_n(addr.bytes.begin(), 4, b.begin());
            return io::endpoint(io::ipv4_address(b), addr.port);
        }
        if (addr.family == xudp::Family::ipv6 && addr.length == 16) {
            io::ipv6_address::bytes_type b{};
            std::copy_n(addr.bytes.begin(), 16, b.begin());
            return io::endpoint(io::ipv6_address(b), addr.port);
        }
        return std::nullopt;
    }

    // WireGuard's nonblocking port polls these bounded queues. Preserving per-datagram
    // endpoints lets WireGuard roam across peer addresses over unconnected packet detours.
    class WireGuardOuterSocket {
        using Endpoint = net::UdpEndpoint;
        using Error = std::error_code;
        using Datagram = std::vector<std::uint8_t>;
        struct QueuedPacket {
            Endpoint peer{};
            Datagram bytes{};
        };
        static constexpr std::size_t capacity = 16;
        net::UdpSocket physical_;
        std::optional<Endpoint> remote_;
        std::string const* network_namespace_ = nullptr;
        containers::BoundedRing<QueuedPacket, capacity> input_, output_;
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
            if (closed_) return std::unexpected(std::make_error_code(std::errc::not_connected));
            if (!peer.port || (peer.family != 4 && peer.family != 6))
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            if (output_.size() == capacity) return std::unexpected(std::make_error_code(std::errc::operation_would_block));
            output_.push_back(QueuedPacket{peer, Datagram(bytes.begin(), bytes.end())});
            tx_.set();
            return {};
        }
        auto receive(std::span<std::uint8_t> bytes) -> std::expected<std::optional<net::UdpPacket>, Error> {
            if (!remote_) return physical_.receive(bytes);
            if (input_.empty()) return std::nullopt;
            auto const& packet = input_.front();
            auto valid = packet.bytes.size() <= bytes.size();
            if (valid) std::ranges::copy(packet.bytes, bytes.begin());
            net::UdpPacket info{packet.peer, packet.bytes.size(), valid};
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
                auto src = source.port() ? to_udp_endpoint(source) : (remote_ ? *remote_ : Endpoint{});
                if (input_.size() < capacity)
                    input_.push_back(QueuedPacket{src, Datagram(bytes.begin(), bytes.begin() + size)});
            }
            co_return capy::results<>{};
        }

        template<class Socket>
        auto write_to(Socket& lower, io::endpoint default_peer = {}) -> capy::task<capy::results<>> {
            while (!closed_) {
                tx_.clear();
                if (output_.empty()) {
                    auto [ec] = co_await tx_.wait();
                    if (ec) break;
                    continue;
                }
                auto packet = std::move(output_.front());
                output_.pop_front();
                auto dest = packet.peer.port ? to_io_endpoint(packet.peer) : default_peer;
                auto [ec, size] = co_await lower.send_to(capy::const_buffer(packet.bytes.data(), packet.bytes.size()), dest);
                if (ec || size != packet.bytes.size()) break;
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

    // Multi-peer packet socket over a packet-capable detour tunnel; preserves
    // source/destination addresses when the carrier is unconnected so WireGuard
    // peers can roam across endpoints.
    class WireGuardPacketSocket {
        struct Adapter {
            WireGuardPacketSocket& owner;
            auto write(std::span<std::uint8_t const> bytes) { return owner.stream_->send(bytes); }
            auto read(std::span<std::uint8_t> bytes) { return owner.stream_->read(bytes); }
            auto cancel() noexcept -> void { if (owner.stream_) owner.stream_->cancel(); }
        };
        struct Guard {
            WireGuardPacketSocket& owner;
            bool completed = false;
            ~Guard() { if (!completed) owner.close(); }
        };
        io::io_context& context_;
        WireGuardLowerStream* stream_ = nullptr;
        io::endpoint peer_{};
        net::PacketTransport transport_{};
        net::ProxyAddress target_{};
        bool fixed_peer_ = false;
        std::optional<net::DatagramDecoder> decoder_;
        Adapter adapter_{*this};
        std::optional<xudp::ClientIo<Adapter>> xudp_;
        std::uint16_t session_ = 0;
        xudp::Address open_target_{};
        capy::async_event session_ready_;
        std::array<std::uint8_t, 16384> input_{};
        std::size_t begin_ = 0, end_ = 0;
        bool closed_ = false, prepared_ = false, reading_ = false, writing_ = false;

        static auto failure(std::errc code) noexcept -> std::error_code { return std::make_error_code(code); }
        auto send_request(std::span<std::uint8_t const> bytes) -> capy::task<capy::results<>> {
            auto sent = co_await stream_->send(bytes);
            co_return capy::results<>{sent ? std::error_code{} : failure(std::errc::io_error)};
        }

    public:
        explicit WireGuardPacketSocket(io::io_context& context) noexcept : context_(context) {}
        WireGuardPacketSocket(WireGuardPacketSocket const&) = delete;
        auto operator=(WireGuardPacketSocket const&) -> WireGuardPacketSocket& = delete;
        ~WireGuardPacketSocket() { close(); }

        auto attach(WireGuardLowerStream& stream, net::PacketTransport transport, io::endpoint peer, bool fixed_peer) -> bool {
            if (stream_ || closed_ || !peer.port() || transport.kind == net::PacketTransportKind::none) return false;
            stream_ = &stream;
            peer_ = peer;
            transport_ = transport;
            target_ = net::packet_peer_address(peer);
            fixed_peer_ = fixed_peer || (transport.kind == net::PacketTransportKind::framed && transport.framing.connected);
            if (transport.kind == net::PacketTransportKind::framed) decoder_.emplace(transport.framing, target_);
            else if (transport.kind == net::PacketTransportKind::xudp) xudp_.emplace(adapter_, 1);
            else { stream_ = nullptr; return false; }
            return true;
        }

        auto prepare(Clock::time_point deadline) -> capy::task<bool> {
            if (!stream_ || closed_ || prepared_ || Clock::now() >= deadline) co_return false;
            Guard guard{*this};
            if (transport_.needs_uot_request) {
                if (transport_.kind != net::PacketTransportKind::framed) co_return false;
                auto request = uot::encode_request({transport_.framing.connected, target_});
                if (!request) co_return false;
                auto [error] = co_await io::timeout(send_request(*request), deadline);
                if (error || closed_ || Clock::now() >= deadline) co_return false;
            }
            prepared_ = true;
            guard.completed = true;
            co_return true;
        }

        auto close() noexcept -> void {
            if (std::exchange(closed_, true)) return;
            session_ready_.set();
            if (decoder_) decoder_->close();
            if (xudp_) xudp_->cancel();
            else if (stream_) stream_->cancel();
        }

        auto send_to(capy::const_buffer buffer, io::endpoint destination) -> capy::task<capy::results<std::size_t>> {
            if (!prepared_ || closed_ || writing_ || !destination.port())
                co_return capy::results<std::size_t>{failure(std::errc::invalid_argument), 0};
            if (fixed_peer_ && destination != peer_)
                co_return capy::results<std::size_t>{failure(std::errc::invalid_argument), 0};
            if (buffer.size() > 65535) co_return capy::results<std::size_t>{failure(std::errc::message_size), 0};
            writing_ = true;
            struct Active { bool& value; ~Active() { value = false; } } active{writing_};
            Guard guard{*this};
            auto bytes = std::span(static_cast<std::uint8_t const*>(buffer.data()), buffer.size());
            if (xudp_) {
                auto xa = io_to_xudp_address(destination);
                if (!session_) {
                    auto opened = co_await xudp_->open(xa, bytes);
                    if (!opened || closed_) co_return capy::results<std::size_t>{failure(std::errc::io_error), 0};
                    session_ = *opened;
                    open_target_ = xa;
                    session_ready_.set();
                } else {
                    auto dest_opt = (xa == open_target_) ? std::nullopt : std::optional<xudp::Address>(xa);
                    auto sent = co_await xudp_->send(session_, dest_opt, bytes);
                    if (!sent || closed_) co_return capy::results<std::size_t>{failure(std::errc::io_error), 0};
                }
            } else {
                auto addr = fixed_peer_ ? target_ : net::packet_peer_address(destination);
                auto frame = net::encode_datagram(transport_.framing, addr, bytes);
                if (!frame || !co_await stream_->send(*frame) || closed_)
                    co_return capy::results<std::size_t>{failure(std::errc::io_error), 0};
            }
            guard.completed = true;
            co_return capy::results<std::size_t>{std::error_code{}, buffer.size()};
        }

        auto recv_from(capy::mutable_buffer buffer, io::endpoint& source) -> capy::task<capy::results<std::size_t>> {
            if (!prepared_ || closed_ || reading_)
                co_return capy::results<std::size_t>{failure(std::errc::invalid_argument), 0};
            reading_ = true;
            struct Active { bool& value; ~Active() { value = false; } } active{reading_};
            Guard guard{*this};
            auto output = std::span(static_cast<std::uint8_t*>(buffer.data()), buffer.size());
            if (xudp_) {
                while (!closed_ && !session_) {
                    session_ready_.clear();
                    auto [error] = co_await session_ready_.wait();
                    if (error) co_return capy::results<std::size_t>{error, 0};
                }
                while (!closed_) {
                    auto event = co_await xudp_->read();
                    if (!event || closed_ || event->action == xudp::Incoming::ended) break;
                    if (event->action != xudp::Incoming::datagram || event->session != session_) continue;
                    io::endpoint src = peer_;
                    if (event->source) {
                        auto parsed = xudp_to_io_endpoint(*event->source);
                        if (!parsed) continue;
                        src = *parsed;
                    }
                    if (fixed_peer_ && src != peer_) continue;
                    if (event->payload.size() > output.size())
                        co_return capy::results<std::size_t>{failure(std::errc::message_size), 0};
                    std::ranges::copy(event->payload, output.begin());
                    source = src;
                    guard.completed = true;
                    co_return capy::results<std::size_t>{std::error_code{}, event->payload.size()};
                }
            } else while (!closed_) {
                if (begin_ == end_) {
                    auto result = co_await stream_->read(input_);
                    if (!result || !*result || *result > input_.size() || closed_) break;
                    begin_ = 0;
                    end_ = *result;
                }
                auto fed = decoder_->feed(std::span(input_).subspan(begin_, end_ - begin_));
                begin_ += fed.consumed;
                if (fed.status == net::DatagramStatus::incomplete && fed.consumed) continue;
                if (fed.status != net::DatagramStatus::accepted) break;
                auto packet = decoder_->packet();
                if (!packet) break;
                auto parsed = fixed_peer_
                    ? (packet->destination == target_ ? std::optional<io::endpoint>(peer_) : std::nullopt)
                    : proxy_to_io_endpoint(packet->destination);
                if (!parsed) { (void)decoder_->consume(); continue; }
                if (packet->payload.size() > output.size())
                    co_return capy::results<std::size_t>{failure(std::errc::message_size), 0};
                auto size = packet->payload.size();
                std::ranges::copy(packet->payload, output.begin());
                (void)decoder_->consume();
                source = *parsed;
                guard.completed = true;
                co_return capy::results<std::size_t>{std::error_code{}, size};
            }
            co_return capy::results<std::size_t>{failure(closed_ ? std::errc::operation_canceled : std::errc::io_error), 0};
        }
    };

    struct WireGuardDetour {
        Session session;
        WireGuardLowerStream stream;
        WireGuardPacketSocket socket;
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
            bool fixed_peer = factory.packet_fixed_peer ||
                (transport.kind == net::PacketTransportKind::framed && transport.framing.connected);
            auto result = fixed_peer
                ? co_await stream.tunnel->connect_packets(net::packet_peer_address(peer), deadline)
                : co_await stream.tunnel->connect_packets(deadline);
            if (result != TunnelConnectResult::connected || !socket.attach(stream, transport, peer, fixed_peer)) co_return false;
            co_return co_await socket.prepare(deadline);
        }

        auto close() noexcept -> void {
            socket.close();
            stream.cancel();
            session.close();
        }
    };
}
