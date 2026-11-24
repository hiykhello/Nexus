// Shared TCP proxy outbound tunnel and Server::add_tcp_proxy template implementation.
module relay:tcp_proxy_impl;
import std;
import capy;
import corosio;
import config;
import http.connect;
import http.header;
import net.datagram_frame;
import net.socket_stream;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import net.udp_connect;
import platform.socket_options;
import relay.dns_routing;
import proxy.v4;
import rulefile;
import socks5;
import utility;
import :types;
import :tunnel_facade;
import :route_interface;
import :session_interface;
import :internal_decls;
import :probe_h2_wire;
import :tcp_proxy_handshake;
import :tcp_proxy_udp;

namespace relay::tcp_proxy_detail {
    enum class UpstreamCarrier { tcp, fast_open, detour };

    template<UpstreamCarrier Carrier, class TlsOps>
    class TcpProxyTunnel {
        using Profile = typename TlsOps::Profile;
        using TcpProxyProfile = BasicTcpProxyProfile<Profile>;
        using LayeredSocket = net::ByteStreamAdapter<probe_h2_detail::ProxyLowerStream>;
        using Socket = std::conditional_t<Carrier == UpstreamCarrier::detour, LayeredSocket, corosio::tcp_socket>;
        using Stream = std::conditional_t<Carrier == UpstreamCarrier::fast_open,
            net::FastOpenStream, net::SocketByteStream<Socket>>;
        using TlsSocket = std::conditional_t<Carrier == UpstreamCarrier::fast_open, net::ByteStreamAdapter<Stream>, Socket>;
        static constexpr bool kFastOpen = (Carrier == UpstreamCarrier::fast_open);

        Session& session_;
        corosio::io_context& context_;
        TcpProxyProfile const& profile_;
        TcpSocketOptions const& options_;
        bool relay_local_;
        DnsSlot dns_;
        LowerConnector lower_;
        probe_h2_detail::ProxyLowerStream lower_stream_{lower_.tunnel};
        struct Transport {
            std::optional<Socket> socket;
            std::optional<Stream> stream;
            typename TlsOps::template State<TlsSocket, Stream> tls;
        };
        std::shared_ptr<Transport> transport_ = std::make_shared<Transport>();
        std::shared_ptr<SocksUdpRelay> udp_;
        corosio::endpoint peer_;
        std::uint32_t interface_index_ = 0;
        std::string buffered_;
        std::size_t buffered_offset_ = 0;
        bool starting_ = false, ready_ = false, canceled_ = false;

        auto prepare(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if constexpr (Carrier == UpstreamCarrier::detour) {
                LowerConnector::Candidates candidates;
                auto connected = co_await lower_.connect(session_, deadline, candidates);
                if (connected != TunnelConnectResult::connected) co_return connected;
                transport_->socket.emplace(lower_stream_);
                transport_->stream.emplace(*transport_->socket);
            } else {
                auto endpoints = profile_.bootstrap ?
                    co_await resolve_bootstrap_owned(session_, context_, dns_, *profile_.bootstrap, profile_.host, profile_.port, deadline) :
                    co_await resolve_local_owned(session_, context_, dns_, profile_.host, profile_.port, deadline);
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                if (!endpoints || endpoints->empty()) co_return TunnelConnectResult::retryable;
                if constexpr (Carrier == UpstreamCarrier::fast_open) {
                    transport_->stream.emplace(context_, std::move(*endpoints), deadline, options_);
                } else {
                    transport_->socket.emplace(context_);
                    bool preparation_failed = false;
                    auto operation = net::connect_tcp_candidates(*transport_->socket, std::span(*endpoints),
                        [](auto const&, auto const& endpoint) { return valid_destination(endpoint); },
                        options_, preparation_failed, deadline, &interface_index_);
                    auto [error, selected] = co_await corosio::timeout(std::move(operation), deadline);
                    if (error) {
                        if (capy::is_timeout(error) || Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                        co_return preparation_failed ? TunnelConnectResult::failed : TunnelConnectResult::retryable;
                    }
                    peer_ = selected;
                    transport_->stream.emplace(*transport_->socket);
                }
            }
            co_return TunnelConnectResult::connected;
        }

    public:
        TcpProxyTunnel(Session& session, corosio::io_context& context, TcpProxyProfile const& profile,
            TcpSocketOptions const& options, bool relay_local) requires (Carrier != UpstreamCarrier::detour)
            : session_(session), context_(context), profile_(profile), options_(options), relay_local_(relay_local) {}

        TcpProxyTunnel(Session& session, corosio::io_context& context, TcpProxyProfile const& profile,
            TunnelFactory const& detour, bool relay_local) requires (Carrier == UpstreamCarrier::detour)
            : session_(session), context_(context), profile_(profile), options_(profile.options), relay_local_(relay_local),
              lower_{{}, &context, &detour, profile.host, profile.port, profile.bootstrap} {}

        ~TcpProxyTunnel() { if (udp_) cancel(); }

        auto connect(corosio::endpoint target) -> capy::task<TunnelConnectResult> {
            return connect_until(target, session_.started + std::chrono::milliseconds(profile_.timeout_ms));
        }

        auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (profile_.protocol == config::TcpProxyProtocol::socks4) {
                DnsSlot target_dns;
                auto eps = co_await resolve_local_owned(session_, context_, target_dns, std::string(domain), port, deadline);
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                if (!eps) co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                for (auto const& ep : *eps) {
                    if (ep.address().is_v4() && valid_destination(ep))
                        co_return co_await connect_until(ep, deadline, {});
                }
                co_return TunnelConnectResult::failed;
            }
            co_return co_await connect_until(corosio::endpoint(corosio::ipv4_address{}, port), deadline, domain);
        }

        auto connect_until(corosio::endpoint target, Clock::time_point deadline, std::string_view domain = {}) -> capy::task<TunnelConnectResult> {
            if ((domain.empty() && !valid_destination(target)) || starting_ || ready_ || canceled_ || session_.closed)
                co_return TunnelConnectResult::failed;
            if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
            starting_ = true;
            struct Guard {
                TcpProxyTunnel& tunnel;
                ~Guard() { tunnel.starting_ = false; if (!tunnel.ready_) tunnel.cancel(); }
            } guard{*this};
            auto prepared = co_await prepare(deadline);
            if (prepared != TunnelConnectResult::connected) co_return prepared;
            if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
            bool accepted = false;
            if (profile_.protocol == config::TcpProxyProtocol::socks5) {
                auto result = co_await socks5_command(*transport_->stream, profile_, target, false, deadline, domain);
                accepted = result.has_value();
            } else if (profile_.protocol == config::TcpProxyProtocol::socks4 ||
                       profile_.protocol == config::TcpProxyProtocol::socks4a) {
                accepted = co_await socks4_command(*transport_->stream, profile_, target, deadline, domain);
            } else if (profile_.tls_profile) {
                if constexpr (TlsOps::supported) {
                    Socket* raw_socket = nullptr;
                    if constexpr (kFastOpen) (void)raw_socket;
                    else raw_socket = &*transport_->socket;
                    accepted = co_await TlsOps::template handshake_and_connect<kFastOpen, Socket, Stream>(
                        session_, transport_->tls, raw_socket, *transport_->stream,
                        profile_, target, buffered_, deadline, domain, canceled_);
                }
            } else {
                accepted = co_await http_connect(*transport_->stream, profile_, target, buffered_, deadline, domain);
            }
            if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
            if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
            if (!accepted) co_return TunnelConnectResult::failed;
            ready_ = true;
            co_return TunnelConnectResult::connected;
        }

        auto cancel() noexcept -> void {
            canceled_ = true;
            dns_.cancel();
            if (udp_) udp_->stop();
            if constexpr (TlsOps::supported) {
                if (TlsOps::cancel(transport_->tls)) return;
            }
            if (transport_->stream) transport_->stream->cancel();
            else if (transport_->socket) transport_->socket->cancel();
            else lower_.cancel();
        }

        auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            if (!ready_ || canceled_) co_return false;
            bool sent = false;
            if (udp_) sent = co_await udp_->send(bytes);
            else if (TlsOps::active(transport_->tls)) sent = co_await TlsOps::send(transport_->tls, bytes);
            else sent = co_await transport_->stream->send(bytes);
            if (sent) session_.touched = Clock::now();
            co_return sent;
        }

        auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
            if (!ready_ || canceled_) co_return std::unexpected("TCP proxy stream closed");
            if (udp_) {
                auto count = co_await udp_->read(bytes);
                if (count && *count) session_.touched = Clock::now();
                co_return count;
            }
            if (buffered_offset_ < buffered_.size()) {
                auto count = std::min(bytes.size(), buffered_.size() - buffered_offset_);
                std::copy_n(buffered_.data() + buffered_offset_, count, bytes.begin());
                buffered_offset_ += count;
                if (count) session_.touched = Clock::now();
                co_return count;
            }
            if (TlsOps::active(transport_->tls)) {
                auto count = co_await TlsOps::read(transport_->tls, bytes);
                if (!count) co_return std::unexpected("HTTP CONNECT TLS stream read failed");
                if (*count) session_.touched = Clock::now();
                co_return *count;
            }
            auto count = co_await transport_->stream->read(bytes);
            if (!count) co_return std::unexpected("TCP proxy read failed");
            if (*count) session_.touched = Clock::now();
            co_return *count;
        }

        auto close_output() -> capy::task<bool> {
            if (!ready_ || canceled_ || udp_) co_return false;
            if (TlsOps::active(transport_->tls)) co_return co_await TlsOps::close_output(transport_->tls);
            co_return co_await transport_->stream->close_output();
        }

        auto upload() -> capy::task<bool> {
            return net::stream_relay::upload(net::ByteRelayAdapter{session_.client, *this,
                [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }

        auto download() -> capy::task<bool> {
            return net::stream_relay::download(net::ByteRelayAdapter{session_.client, *this,
                [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }

        auto packet_transport() const noexcept -> net::PacketTransport {
            if constexpr (Carrier != UpstreamCarrier::detour)
                if (profile_.udp) return {net::PacketTransportKind::framed, {}, false};
            return {};
        }

        auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if constexpr (Carrier == UpstreamCarrier::detour) co_return TunnelConnectResult::failed;
            else {
                if (!profile_.udp || starting_ || ready_ || canceled_ || session_.closed)
                    co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                starting_ = true;
                struct Guard {
                    TcpProxyTunnel& tunnel;
                    ~Guard() { tunnel.starting_ = false; if (!tunnel.ready_) tunnel.cancel(); }
                } guard{*this};
                auto prepared = co_await prepare(deadline);
                if (prepared != TunnelConnectResult::connected) co_return prepared;
                auto bound = co_await socks5_command(*transport_->stream, profile_,
                    corosio::endpoint(corosio::ipv4_address{}, 0), true, deadline);
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                if (!bound) co_return TunnelConnectResult::failed;
                if constexpr (Carrier == UpstreamCarrier::fast_open) {
                    peer_ = transport_->stream->remote_endpoint();
                    interface_index_ = transport_->stream->interface_index();
                }
                auto binding = options_.binding;
                if (binding.network) {
                    binding.interface_index = interface_index_;
                    binding.network.reset();
                }
                auto relay = std::make_shared<SocksUdpRelay>(context_);
                if (!relay->start(*bound, peer_, binding, deadline))
                    co_return TunnelConnectResult::failed;
                auto transport = transport_;
                capy::run_async(context_.get_executor(), [relay] noexcept { relay->stop(); },
                    [relay](std::exception_ptr) noexcept { relay->stop(); })(relay->monitor(std::move(transport)));
                udp_ = std::move(relay);
                ready_ = true;
                co_return TunnelConnectResult::connected;
            }
        }

        auto has_uot() const noexcept -> bool { return false; }
        auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto has_xudp() const noexcept -> bool { return false; }
        auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
    };

    template<class TlsOps>
    auto add_tcp_proxy_impl(config::TcpProxyOutbound const& config, std::vector<TunnelFactory>& outbounds,
        std::optional<DnsRouting> const& dns_routing, std::optional<std::size_t>& max_bootstrap_index,
        bool server_busy) -> std::expected<std::size_t, std::string> {
        using Profile = typename TlsOps::Profile;
        using TcpProxyProfile = BasicTcpProxyProfile<Profile>;
        if (server_busy)
            return std::unexpected("stop the server before changing the outbound");
        if (config.protocol == config::TcpProxyProtocol::http_connect && config.http_version != config::HttpProxyVersion::h1) {
#ifdef NEXUS_ENABLE_NAIVE
            if (outbounds.size() >= 256) return std::unexpected("too many tunnel outbounds");
            if (config.bootstrap_index && (!dns_routing || *config.bootstrap_index >= dns_routing->resolver_count()))
                return std::unexpected("invalid TCP proxy bootstrap resolver");
            auto factory = make_http_modern_factory(config);
            if (!factory) return std::unexpected(factory.error());
            auto index = outbounds.size() + 2;
            outbounds.push_back(std::move(*factory));
            if (config.bootstrap_index && (!max_bootstrap_index || *config.bootstrap_index > *max_bootstrap_index))
                max_bootstrap_index = config.bootstrap_index;
            return index;
#else
            return std::unexpected("HTTP/2 and HTTP/3 proxy outbounds require naive build feature");
#endif
        }
        if (outbounds.size() >= 256 || config.host.empty() || config.host.size() > 253 || !config.port ||
            !config.connect_timeout_ms || config.connect_timeout_ms > 3600000 || !config.tcp_options.valid())
            return std::unexpected("invalid TCP proxy outbound options");
        if (config.bootstrap_index && (!dns_routing || *config.bootstrap_index >= dns_routing->resolver_count()))
            return std::unexpected("invalid TCP proxy bootstrap resolver");
        auto is_socks4 = config.protocol == config::TcpProxyProtocol::socks4 || config.protocol == config::TcpProxyProtocol::socks4a;
        if (config.protocol != config::TcpProxyProtocol::socks5 && (config.udp || (config.protocol != config::TcpProxyProtocol::http_connect && !is_socks4)))
            return std::unexpected("invalid TCP proxy outbound protocol");
        if (config.tls && config.protocol != config::TcpProxyProtocol::http_connect)
            return std::unexpected("TLS is supported on HTTP CONNECT outbounds");
        if (config.username.size() > 255 || (!is_socks4 && config.username.empty() != config.password_file.empty()) ||
            (is_socks4 && !config.password_file.empty()) ||
            std::ranges::any_of(config.username, [](unsigned char c) { return c < 32 || c == 127; }) ||
            (config.protocol == config::TcpProxyProtocol::http_connect && config.username.contains(':')))
            return std::unexpected("invalid TCP proxy authentication");
        auto profile = std::unique_ptr<TcpProxyProfile>(new TcpProxyProfile{
            config.host, config.username, {}, config.port, config.protocol, config.udp, config.bootstrap_index,
            config.connect_timeout_ms, config.tcp_options});
        if (config.tls) {
            auto loaded = TlsOps::load(*config.tls);
            if (!loaded) return std::unexpected(loaded.error());
            profile->tls_profile.emplace(std::move(*loaded));
        }
        if (!config.password_file.empty()) {
            auto password = rulefile::read_password_file(config.password_file);
            if (!password) return std::unexpected("invalid TCP proxy password-file");
            struct WipePassword {
                std::string& value;
                ~WipePassword() { utility::secure_zero(value.data(), value.size()); }
            } wipe{*password};
            profile->password = *password;
        }
        auto* borrowed = profile.get();
        auto index = outbounds.size() + 2;
        TunnelFactory factory{
            [profile = std::move(profile)](Session& session, corosio::io_context& context, bool relay_local,
                TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
                auto const& options = inherited ? *inherited : profile->options;
                if (options.tcp_fast_open.value_or(false))
                    return pro::make_proxy<TunnelFacade, TcpProxyTunnel<UpstreamCarrier::fast_open, TlsOps>>(
                        session, context, *profile, options, relay_local);
                return pro::make_proxy<TunnelFacade, TcpProxyTunnel<UpstreamCarrier::tcp, TlsOps>>(
                    session, context, *profile, options, relay_local);
            },
            config.connect_timeout_ms,
            [borrowed](Session& session, corosio::io_context& context, TunnelFactory const& detour, bool relay_local)
                -> pro::proxy<TunnelFacade> {
                return pro::make_proxy<TunnelFacade, TcpProxyTunnel<UpstreamCarrier::detour, TlsOps>>(
                    session, context, *borrowed, detour, relay_local);
            },
            std::nullopt, config.tcp_options.configured()};
        factory.packet_dual_family = config.udp;
        outbounds.push_back(std::move(factory));
        if (config.bootstrap_index && (!max_bootstrap_index || *config.bootstrap_index > *max_bootstrap_index))
            max_bootstrap_index = config.bootstrap_index;
        return index;
    }
}
