module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
module relay:shadowsocks_native;
import std;
import proxy.v4;
import crypto;
import shadowsocks.udp_client;
import net.packet_stream_socket;
import net.unified_datagram;
import net.datagram_frame;
import platform.socket_options;
import platform.wall_clock;
import capy;
import corosio;
import :types;
import :tunnel_facade;
import :route_interface;
import :session_interface;
import :internal_decls;

namespace relay::ss_detail {
    namespace io = ::corosio;

    inline auto next_native_session_id() noexcept -> std::optional<std::array<std::uint8_t, 8>> {
        static std::mutex mutex;
        static std::optional<std::uint64_t> next;
        static bool exhausted = false;
        std::lock_guard guard(mutex);
        if (exhausted) return {};
        if (!next) {
            std::array<std::uint8_t, 8> seed{};
            if (!crypto::random_bytes(seed)) return {};
            std::uint64_t value = 0;
            for (auto byte : seed) value = (value << 8) | byte;
            next = value;
        }
        std::array<std::uint8_t, 8> id{};
        for (std::size_t i = 0; i < id.size(); ++i) id[i] = static_cast<std::uint8_t>(*next >> (56 - 8 * i));
        if (*next == std::numeric_limits<std::uint64_t>::max()) exhausted = true;
        else ++*next;
        return id;
    }

    template<class Profile>
    class NativeShadowsocksPackets {
        struct Lower {
            Session session;
            pro::proxy<TunnelFacade> tunnel;
            Lower(Session const& parent, io::io_context& context) : session(context) {
                session.dns = parent.dns;
                session.local_dns = parent.local_dns;
                session.tunnel_factories = parent.tunnel_factories;
                session.direct_tcp_options = parent.direct_tcp_options;
                session.started = parent.started;
                session.handshake_deadline = parent.handshake_deadline;
            }
            auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
            auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
            auto cancel() noexcept -> void { if (tunnel) tunnel->cancel(); session.close(); }
            auto connect(TunnelFactory const& factory, io::io_context& context, net::UnifiedDatagramSocket& socket,
                         io::endpoint peer, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (session.closed || tunnel) co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                auto stop = co_await capy::this_coro::stop_token;
                std::stop_callback canceled(stop, [this]() noexcept { cancel(); });
                if (session.closed) co_return TunnelConnectResult::failed;
                tunnel = factory(session, context, false);
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
        Session& session_;
        io::io_context& context_;
        Profile const& profile_;
        platform::SocketBinding const& binding_;
        std::unique_ptr<Lower> lower_;
        net::UnifiedDatagramSocket socket_;
        TunnelFactory const* detour_;
        io::endpoint peer_;
        DnsSlot dns_;
        // Some peers choose the family's outbound socket on the first
        // request of each SS session. Both sessions use this one physical
        // socket, including when the source port is fixed.
        std::array<std::optional<shadowsocks::UdpClientSession>, 2> codecs_;
        std::vector<std::uint8_t> reply_;
        std::size_t reply_offset_ = 0;
        bool canceled_ = false;

        static auto wall_seconds() noexcept -> std::uint64_t {
            auto seconds = platform::calibrated_wall_seconds();
            return seconds >= 0 ? static_cast<std::uint64_t>(seconds) : 0;
        }

    public:
        static constexpr net::DatagramFraming framing{net::AddressWire::socks};

        NativeShadowsocksPackets(Session& session, io::io_context& context, Profile const& profile,
                                 platform::SocketBinding const& binding, TunnelFactory const* detour = nullptr)
            : session_(session), context_(context), profile_(profile), binding_(binding), socket_(context), detour_(detour) {}

        auto cancel() noexcept -> void {
            canceled_ = true;
            dns_.cancel();
            socket_.close();
            if (lower_) lower_->cancel();
        }

        auto start(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (canceled_ || peer_.port() || session_.closed) co_return TunnelConnectResult::failed;
            if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
            auto stop = co_await capy::this_coro::stop_token;
            std::stop_callback cancel_on_stop(stop, [this]() noexcept { cancel(); });
            if (canceled_) co_return TunnelConnectResult::failed;
            auto endpoints = profile_.bootstrap
                ? co_await resolve_bootstrap_owned(session_, context_, dns_, *profile_.bootstrap, profile_.host, profile_.port, deadline)
                : co_await resolve_local_owned(session_, context_, dns_, profile_.host, profile_.port, deadline);
            if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
            if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
            if (!endpoints || endpoints->size() > 64) co_return TunnelConnectResult::retryable;
            for (auto const& endpoint : *endpoints) {
                if (!valid_destination(endpoint)) continue;
                if (detour_) {
                    lower_ = std::make_unique<Lower>(session_, context_);
                    auto result = co_await lower_->connect(*detour_, context_, socket_, endpoint, deadline);
                    if (result != TunnelConnectResult::connected || canceled_ || session_.closed) {
                        lower_.reset();
                        co_return canceled_ || session_.closed ? TunnelConnectResult::failed : result;
                    }
                } else if (auto error = socket_.prepare_physical(endpoint, &binding_, deadline)) {
                    if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                    if (platform::network::retry_interface_error(error)) continue;
                    co_return TunnelConnectResult::failed;
                }
                peer_ = endpoint;
                if (!detour_) session_.record_physical_peer(endpoint);
                co_return TunnelConnectResult::connected;
            }
            co_return TunnelConnectResult::retryable;
        }

        auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            if (!peer_.port() || canceled_ || session_.closed) co_return false;
            auto frame = net::parse_datagram(framing, {}, bytes);
            if (frame.status != net::DatagramStatus::accepted || frame.consumed != bytes.size() || !frame.destination.port)
                co_return false;
            auto address = net::parse_proxy_address(bytes, framing.address);
            auto& codec = codecs_[frame.destination.family == net::ProxyAddressFamily::ipv6 ? 1 : 0];
            if (!codec) {
                auto id = next_native_session_id();
                if (!id) co_return false;
                codec.emplace(profile_.key, *id, 8, profile_.method);
            }
            auto wire = codec->request(bytes.first(address.consumed), frame.payload, {}, Clock::now(), wall_seconds(), profile_.identities);
            if (!wire || wire->size() > (peer_.is_v4() ? 65507 : 65527)) co_return false;
            auto input = capy::const_buffer(wire->data(), wire->size());
            auto [error, sent] = co_await socket_.send_to(input, peer_);
            if (error || sent != wire->size() || canceled_ || session_.closed) co_return false;
            session_.touched = Clock::now();
            co_return true;
        }

        auto read(std::span<std::uint8_t> output) -> capy::task<std::expected<std::size_t, std::string>> {
            if (!peer_.port() || canceled_ || session_.closed || output.empty()) co_return std::unexpected("native SS UDP closed");
            if (reply_.empty()) {
                std::array<std::uint8_t, 65536> input;
                while (!canceled_ && !session_.closed) {
                    io::endpoint source;
                    auto buffer = capy::mutable_buffer(input.data(), input.size());
                    auto [error, size] = co_await socket_.recv_from(buffer, source);
                    if (error || canceled_ || session_.closed) co_return std::unexpected("native SS UDP read failed");
                    if (source != peer_ || size > input.size()) continue;
                    auto now = Clock::now();
                    auto wall = wall_seconds();
                    for (auto& codec : codecs_) {
                        if (!codec) continue;
                        auto packet = codec->receive(std::span(input).first(size), now, wall);
                        if (!packet && (packet.error() == shadowsocks::UdpClientError::session_conflict ||
                            packet.error() == shadowsocks::UdpClientError::time_reversed))
                            co_return std::unexpected("native SS UDP session is no longer valid");
                        if (!packet) continue;
                        auto address = net::parse_proxy_address(packet->address, framing.address);
                        if (address.status != net::DatagramStatus::accepted || !address.address.port) break;
                        auto frame = net::encode_datagram(framing, address.address, packet->payload);
                        if (!frame) break;
                        reply_ = std::move(*frame);
                        session_.touched = now;
                        break;
                    }
                    if (!reply_.empty()) break;
                }
            }
            if (reply_.empty()) co_return std::unexpected("native SS UDP closed");
            auto count = std::min(output.size(), reply_.size() - reply_offset_);
            std::ranges::copy(std::span(reply_).subspan(reply_offset_, count), output.begin());
            reply_offset_ += count;
            if (reply_offset_ == reply_.size()) { reply_.clear(); reply_offset_ = 0; }
            co_return count;
        }
    };
}
