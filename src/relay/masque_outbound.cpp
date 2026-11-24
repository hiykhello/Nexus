module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>
module relay;
import std;
import proxy.v4;
import config;
import masque.client_session;
import quic.ech_config;
import masque.connect_ip;
import masque.ip_control;
import masque.ip_packet;
import tls.fingerprint;
import hysteria2.transport_options;
import net.datagram_frame;
import net.packet_stream_socket;
import net.unified_datagram;
import net.stream_relay;
import packet;
import tcp.send;
import tcp.receive;
import platform.linux_random;
import capy;
import corosio;
import relay.l3_mux;
import relay.masque_ip_addresses;
import :quic_ech;
import :masque_common;
import :masque_ip_tunnel;

namespace relay {
    namespace masque_detail {
        auto start_masque_connection(Session& session,io::io_context& context,MasqueOutProfile const& profile,
            platform::SocketBinding binding,TunnelFactory const* lower,io::endpoint peer,quic::EchConfig const* ech,
            Clock::time_point deadline,bool const& stopped,std::shared_ptr<MasqueConnection>& current)
            -> capy::task<TunnelConnectResult> {
            if (!valid_destination(peer)) co_return TunnelConnectResult::failed;
            bool layered = lower != nullptr;
            platform::network::InterfaceCandidates paths;
            if (!layered && binding.network) paths=(*binding.network)(peer.is_v6());
            else paths.indices.push_back(binding.interface_index);
            binding.network.reset();
            for (std::size_t index=0;index<paths.indices.size();++index) {
                if (stopped || session.closed) co_return TunnelConnectResult::failed;
                auto now=Clock::now();
                if (now>=deadline) co_return TunnelConnectResult::timeout;
                auto attempt=index+1<paths.indices.size() ? std::min(deadline,now+paths.fallback_delay) : deadline;
                binding.interface_index=paths.indices[index];
                auto candidate=std::make_shared<MasqueConnection>(session,context,*profile.client,layered);
                current=candidate;
                std::stop_callback cancel(session.stop.get_token(),[candidate]() noexcept {candidate->stop();});
                auto& client=candidate->client;
                auto release=[&] {
                    candidate->stop();
                    if (current==candidate) current.reset();
                };
                if (lower) {
                    auto prepared=co_await candidate->lower->connect(*lower,context,client.socket(),peer,attempt);
                    if (prepared!=TunnelConnectResult::connected) {release();co_return prepared;}
                }
                if (stopped || session.closed) {release();co_return TunnelConnectResult::failed;}
                std::error_code socket_error;
                if (!client.start(peer,layered ? nullptr : &binding,ech,{},attempt,&socket_error)) {
                    release();
                    if (platform::network::retry_interface_error(socket_error)) continue;
                    co_return Clock::now()>=attempt ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                }
                try {
                    capy::run_async(context.get_executor(),[candidate](auto) noexcept {},
                        [candidate](std::exception_ptr) noexcept {candidate->stop();})(client.run());
                } catch (...) {release();co_return TunnelConnectResult::failed;}
                if (co_await client.wait_http_ready(attempt)) {
                    if (!stopped && !session.closed) co_return TunnelConnectResult::connected;
                    release();
                    co_return TunnelConnectResult::failed;
                }
                auto retry=client.retryable_http_handshake(attempt);
                release();
                if (!retry || stopped || session.closed) co_return TunnelConnectResult::failed;
            }
            co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
        }

        auto MasqueOutProfile::get_host(io::io_context& ctx, platform::SocketBinding const& binding, TunnelFactory const* lower)
            -> std::shared_ptr<MasqueIpHost> {
            std::lock_guard lock(mutex);
            auto& selected = hosts(lower != nullptr);
            if (auto it = selected.find(&ctx); it != selected.end()) return it->second;
            auto h = std::make_shared<MasqueIpHost>(ctx, *this, binding, lower);
            selected.emplace(&ctx, h);
            return h;
        }
    }

    namespace {
        using namespace masque_detail;
        class MasqueTunnel {
            using Connection = MasqueConnection;

            Session& session_;
            io::io_context& context_;
            MasqueOutProfile const& profile_;
            DnsSlot dns_;
            std::shared_ptr<Connection> connection_;
            TunnelFactory const* lower_;
            platform::SocketBinding binding_;
            bool starting_=false;
            bool launched_ = false;
            bool opened_ = false;
            bool canceled_ = false;
            Clock::time_point deadline_;
            std::vector<std::uint8_t> rx_buf_;
            std::size_t rx_off_ = 0;
            net::ProxyAddress remote_addr_{};
            std::string remote_host_;

        public:
            MasqueTunnel(Session& s, io::io_context& ctx, MasqueOutProfile const& p,
                         platform::SocketBinding binding, TunnelFactory const* lower = nullptr)
                : session_(s),context_(ctx),profile_(p),lower_(lower),binding_(std::move(binding)) {}
            ~MasqueTunnel() { cancel(); }

            auto cancel() noexcept -> void {
                if (std::exchange(canceled_, true)) return;
                dns_.cancel();
                if (connection_) connection_->stop();
            }
            auto connect(io::endpoint) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_until(io::endpoint, Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto packet_transport() const noexcept -> net::PacketTransport {
                return {net::PacketTransportKind::framed, {}, false};
            }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (starting_ || launched_ || canceled_ || session_.closed || Clock::now()>=deadline)
                    co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                deadline_=deadline;
                starting_=true;
                struct Started {
                    bool& pending;
                    ~Started() {pending=false;}
                } started{starting_};
                auto eps = profile_.bootstrap
                    ? co_await resolve_bootstrap_owned(session_, context_, dns_, *profile_.bootstrap, profile_.host, profile_.port, deadline)
                    : co_await resolve_local_owned(session_, context_, dns_, profile_.host, profile_.port, deadline);
                if (canceled_ || session_.closed || !eps || eps->empty())
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                auto ech = co_await profile_.ech.resolve(session_, context_, dns_, profile_.bootstrap, profile_.port, deadline);
                if (canceled_ || session_.closed || !ech || Clock::now() >= deadline)
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                auto connected=co_await start_masque_connection(session_,context_,profile_,binding_,lower_,eps->front(),
                    *ech ? &**ech : nullptr,deadline,canceled_,connection_);
                launched_=connected==TunnelConnectResult::connected;
                co_return connected;
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }

            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (canceled_ || !launched_) co_return false;
                auto frame = net::parse_datagram({}, {}, bytes);
                if (frame.status != net::DatagramStatus::accepted || frame.consumed != bytes.size()) co_return false;
                if (!opened_) {
                    remote_addr_ = frame.destination;
                    if (remote_addr_.family == net::ProxyAddressFamily::ipv4) {
                        io::ipv4_address::bytes_type raw{};
                        std::copy_n(remote_addr_.bytes.begin(), 4, raw.begin());
                        remote_host_ = io::ipv4_address(raw).to_string();
                    } else if (remote_addr_.family == net::ProxyAddressFamily::ipv6) {
                        io::ipv6_address::bytes_type raw{};
                        std::copy_n(remote_addr_.bytes.begin(), 16, raw.begin());
                        remote_host_ = io::ipv6_address(raw).to_string();
                    } else {
                        remote_host_.assign(reinterpret_cast<char const*>(remote_addr_.bytes.data()), remote_addr_.length);
                    }
                    auto connected = co_await connection_->client.connect_udp(remote_host_, remote_addr_.port, deadline_);
                    if (!connected || canceled_) co_return false;
                    opened_ = true;
                }
                if (frame.destination != remote_addr_) co_return false;
                bool ok = connection_->client.send(frame.payload);
                if (ok) session_.touched = Clock::now();
                co_return ok;
            }

            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if (canceled_ || !launched_) co_return std::unexpected("MASQUE closed");
                while (!opened_) {
                    if (canceled_ || session_.closed) co_return std::unexpected("MASQUE closed");
                    auto [ec] = co_await io::delay(std::chrono::milliseconds(5));
                    if (ec) co_return std::unexpected("MASQUE interrupted");
                }
                for (;;) {
                    if (rx_off_ < rx_buf_.size()) {
                        auto n = std::min(bytes.size(), rx_buf_.size() - rx_off_);
                        std::copy_n(rx_buf_.begin() + static_cast<std::ptrdiff_t>(rx_off_), n, bytes.begin());
                        rx_off_ += n;
                        if (rx_off_ == rx_buf_.size()) { rx_buf_.clear(); rx_off_ = 0; }
                        session_.touched = Clock::now();
                        co_return n;
                    }
                    auto pkt = co_await connection_->client.receive(Clock::now() + std::chrono::seconds(300));
                    if (!pkt) co_return std::unexpected("MASQUE datagram stream closed");
                    auto framed = net::encode_datagram({}, remote_addr_, *pkt);
                    if (framed) { rx_buf_ = std::move(*framed); rx_off_ = 0; }
                }
            }
            auto close_output() -> capy::task<bool> { co_return true; }
            auto upload() -> capy::task<bool> { co_return false; }
            auto download() -> capy::task<bool> { co_return false; }
        };
    }

    auto make_masque_factory(std::string_view host, std::uint16_t port, std::string_view authority,
        std::string_view bearer_file, std::string_view server_name, std::string_view ca_file,
        TlsKeyExchange exchange, TlsFingerprint fingerprint, std::uint32_t handshake_ms,
        std::uint32_t idle_ms, std::size_t native_bytes, std::optional<std::size_t> bootstrap,
        std::uint32_t timeout_ms, TcpSocketOptions options, MasqueIpOptions ip,
        QuicEchOptions const& ech, bool dns_available, std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<TunnelFactory, std::string> {
        using namespace masque_detail;
        if (host.empty() || !port || !timeout_ms || timeout_ms > 3600000 || !options.valid())
            return std::unexpected("invalid MASQUE outbound options");
        if (ip.enabled && (ip.mtu < 68 || ip.mtu > 1500))
            return std::unexpected("invalid MASQUE CONNECT-IP MTU");
        masque::ConnectIpScope scope;
        if (ip.enabled && ip.path.starts_with("/.well-known/masque/ip/")) {
            auto parsed = masque::parse_default_ip_path(ip.path);
            if (!parsed || parsed->kind == masque::IpTargetKind::hostname)
                return std::unexpected("MASQUE CONNECT-IP requires a wildcard or numeric prefix target");
            scope = std::move(*parsed);
        }
        auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!fp) return std::unexpected("invalid MASQUE TLS fingerprint");
        hysteria2::TransportOptions opts{
            std::chrono::milliseconds(handshake_ms), std::chrono::milliseconds(idle_ms), native_bytes, true};
        if (ip.enabled) opts.max_udp_payload_size = std::clamp<std::size_t>(static_cast<std::size_t>(ip.mtu) + 64, 1200, 1452);
        auto ech_profile = quic_ech::Profile::load(ech, server_name, dns_available);
        if (!ech_profile) return std::unexpected(ech_profile.error());
        auto client = masque::ClientProfile::load(
            server_name, ca_file, authority, bearer_file,
            exchange == TlsKeyExchange::x25519 ? 0x001d : 0x11ec,
            exchange == TlsKeyExchange::x25519_mlkem768_only, opts, *fp, pins);
        if (!client) return std::unexpected(client.error());
        auto profile = std::make_shared<MasqueOutProfile>(
            std::string(host), port, bootstrap, timeout_ms, std::move(*client), options, std::move(ip), std::move(scope), std::move(*ech_profile));
        TunnelFactory factory{
            [profile](Session& s, io::io_context& ctx, bool relay_local, TcpSocketOptions const* direct) -> pro::proxy<TunnelFacade> {
                auto const& binding = direct ? direct->binding : profile->options.binding;
                if (profile->ip.enabled)
                    return pro::make_proxy<TunnelFacade, MasqueIpTunnel>(s, profile, profile->get_host(ctx, binding), relay_local);
                return pro::make_proxy<TunnelFacade, MasqueTunnel>(s, ctx, *profile, binding);
            },
            timeout_ms, {}, std::nullopt, options.configured()};
        factory.packet_fixed_peer=!profile->ip.enabled;
        factory.through = [profile](Session& session, io::io_context& context, TunnelFactory const& lower,
                                    bool relay_local) -> pro::proxy<TunnelFacade> {
            if (profile->ip.enabled)
                return pro::make_proxy<TunnelFacade, MasqueIpTunnel>(session, profile,
                    profile->get_host(context, {}, &lower), relay_local);
            return pro::make_proxy<TunnelFacade, MasqueTunnel>(session, context, *profile, platform::SocketBinding{}, &lower);
        };
        auto visit_hosts = [](MasqueOutProfile& owner, io::io_context& ctx, auto&& visit) {
            auto apply = [&](auto& hosts) {
                if (auto it = hosts.find(&ctx); it != hosts.end()) return visit(it->second);
                return true;
            };
            return apply(owner.physical_hosts) && apply(owner.packet_hosts);
        };
        factory.stop_context = [profile,visit_hosts](io::io_context& ctx) noexcept {
            std::lock_guard lock(profile->mutex);
            (void)visit_hosts(*profile,ctx,[](auto const& host) {host->stop();return true;});
        };
        factory.quiesced_context = [profile,visit_hosts](io::io_context& ctx) noexcept -> bool {
            std::lock_guard lock(profile->mutex);
            return visit_hosts(*profile,ctx,[](auto const& host) {return !host->loop_active && !host->connecting;});
        };
        factory.finish_context = [profile](io::io_context& ctx) noexcept {
            std::lock_guard lock(profile->mutex);
            profile->physical_hosts.erase(&ctx);
            profile->packet_hosts.erase(&ctx);
        };
        return factory;
    }
}
