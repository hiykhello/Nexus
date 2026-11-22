#pragma once

namespace proxy {
    namespace {
#include "tcp_proxy_handshake.hpp"
#include "tcp_proxy_udp.hpp"

        struct ProxyLowerStream {
            pro::proxy<TunnelFacade>& tunnel;
            auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
            auto close_output() { return tunnel->close_output(); }
            auto cancel() noexcept -> void { tunnel->cancel(); }
        };

        enum class UpstreamCarrier { tcp, fast_open, detour };

        template<UpstreamCarrier Carrier>
        class TcpProxyTunnel {
            using LayeredSocket=net::ByteStreamAdapter<ProxyLowerStream>;
            using Socket=std::conditional_t<Carrier==UpstreamCarrier::detour,LayeredSocket,nex::corosio::tcp_socket>;
            using Stream=std::conditional_t<Carrier==UpstreamCarrier::fast_open,
                net::FastOpenStream,net::SocketByteStream<Socket>>;
#ifdef NEXUS_HTTP_CONNECT_TLS
            using TlsSocket=std::conditional_t<Carrier==UpstreamCarrier::fast_open,net::ByteStreamAdapter<Stream>,Socket>;
#endif
            Session& session_;
            nex::corosio::io_context& context_;
            TcpProxyProfile const& profile_;
            TcpSocketOptions const& options_;
            bool relay_local_;
            DnsSlot dns_;
            LowerConnector lower_;
            ProxyLowerStream lower_stream_{lower_.tunnel};
            struct Transport {
                std::optional<Socket> socket;
                std::optional<Stream> stream;
#ifdef NEXUS_HTTP_CONNECT_TLS
                std::optional<net::ByteStreamAdapter<net::FastOpenStream>> tls_fast_open;
                std::unique_ptr<tls::detail::ClientConnection<TlsSocket>> tls_client;
                std::unique_ptr<tls::detail::ByteStream<TlsSocket>> tls_stream;
#endif
            };
            std::shared_ptr<Transport> transport_=std::make_shared<Transport>();
            std::shared_ptr<SocksUdpRelay> udp_;
            nex::corosio::endpoint peer_;
            std::uint32_t interface_index_=0;
            std::string buffered_;
            std::size_t buffered_offset_=0;
            bool starting_=false,ready_=false,canceled_=false;

            auto prepare(Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
                if constexpr (Carrier==UpstreamCarrier::detour) {
                    LowerConnector::Candidates candidates;
                    auto connected=co_await lower_.connect(session_,deadline,candidates);
                    if (connected!=TunnelConnectResult::connected) co_return connected;
                    transport_->socket.emplace(lower_stream_);
                    transport_->stream.emplace(*transport_->socket);
                } else {
                    auto endpoints=profile_.bootstrap ?
                        co_await resolve_bootstrap_owned(session_,context_,dns_,*profile_.bootstrap,profile_.host,profile_.port,deadline) :
                        co_await resolve_local_owned(session_,context_,dns_,profile_.host,profile_.port,deadline);
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                    if (!endpoints || endpoints->empty()) co_return TunnelConnectResult::retryable;
                    if constexpr (Carrier==UpstreamCarrier::fast_open) {
                        transport_->stream.emplace(context_,std::move(*endpoints),deadline,options_);
                    } else {
                        transport_->socket.emplace(context_);
                        bool preparation_failed=false;
                        auto operation=net::connect_tcp_candidates(*transport_->socket,std::span(*endpoints),
                            [](auto const&,auto const& endpoint) {return valid_destination(endpoint);},
                            options_,preparation_failed,deadline,&interface_index_);
                        auto [error,selected]=co_await nex::corosio::timeout(std::move(operation),deadline);
                        if (error) {
                            if (nex::capy::is_timeout(error) || Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                            co_return preparation_failed ? TunnelConnectResult::failed : TunnelConnectResult::retryable;
                        }
                        peer_=selected;
                        transport_->stream.emplace(*transport_->socket);
                    }
                }
                co_return TunnelConnectResult::connected;
            }

#ifdef NEXUS_HTTP_CONNECT_TLS
            auto start_tls(Clock::time_point deadline) -> nex::capy::task<bool> {
                using std::chrono::duration_cast;
                using std::chrono::milliseconds;
                auto start=duration_cast<milliseconds>(Clock::now().time_since_epoch()).count();
                auto end=duration_cast<milliseconds>(deadline.time_since_epoch()).count();
                auto verified=duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                if (start<0 || end<=start) co_return false;
                auto handshake=profile_.tls_profile->handshake(static_cast<std::uint64_t>(start),
                    static_cast<std::uint64_t>(end),verified,std::span<std::uint8_t const>{});
                if (!handshake) co_return false;
                TlsSocket* socket;
                if constexpr (Carrier==UpstreamCarrier::fast_open)
                    socket=&transport_->tls_fast_open.emplace(*transport_->stream);
                else socket=&*transport_->socket;
                transport_->tls_client=std::make_unique<tls::detail::ClientConnection<TlsSocket>>(
                    *socket,std::move(*handshake));
                auto authenticated=co_await transport_->tls_client->start();
                if (!authenticated || canceled_ || session_.closed) co_return false;
                auto* application=transport_->tls_client->application();
                if (!application) co_return false;
                transport_->tls_stream=std::make_unique<tls::detail::ByteStream<TlsSocket>>(*application);
                (void)transport_->tls_stream->try_enable_ktls();
                co_return true;
            }
#endif

        public:
            TcpProxyTunnel(Session& session,nex::corosio::io_context& context,TcpProxyProfile const& profile,
                TcpSocketOptions const& options,bool relay_local) requires (Carrier!=UpstreamCarrier::detour)
                :session_(session),context_(context),profile_(profile),options_(options),relay_local_(relay_local) {}

            TcpProxyTunnel(Session& session,nex::corosio::io_context& context,TcpProxyProfile const& profile,
                TunnelFactory const& detour,bool relay_local) requires (Carrier==UpstreamCarrier::detour)
                :session_(session),context_(context),profile_(profile),options_(profile.options),relay_local_(relay_local),
                 lower_{{},&context,&detour,profile.host,profile.port,profile.bootstrap} {}

            ~TcpProxyTunnel() {if (udp_) cancel();}

            auto connect(nex::corosio::endpoint target) -> nex::capy::task<TunnelConnectResult> {
                return connect_until(target,session_.started+std::chrono::milliseconds(profile_.timeout_ms));
            }

            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
                if (profile_.protocol==config::TcpProxyProtocol::socks4) {
                    DnsSlot target_dns;
                    auto eps=co_await resolve_local_owned(session_,context_,target_dns,std::string(domain),port,deadline);
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (!eps) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    for (auto const& ep : *eps) {
                        if (ep.address().is_v4() && valid_destination(ep))
                            co_return co_await connect_until(ep,deadline,{});
                    }
                    co_return TunnelConnectResult::failed;
                }
                co_return co_await connect_until(nex::corosio::endpoint(nex::corosio::ipv4_address{},port),deadline,domain);
            }

            auto connect_until(nex::corosio::endpoint target,Clock::time_point deadline,std::string_view domain={}) -> nex::capy::task<TunnelConnectResult> {
                if ((domain.empty() && !valid_destination(target)) || starting_ || ready_ || canceled_ || session_.closed)
                    co_return TunnelConnectResult::failed;
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                starting_=true;
                struct Guard {
                    TcpProxyTunnel& tunnel;
                    ~Guard() { tunnel.starting_=false;if (!tunnel.ready_) tunnel.cancel(); }
                } guard{*this};
                auto prepared=co_await prepare(deadline);
                if (prepared!=TunnelConnectResult::connected) co_return prepared;
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                bool accepted=false;
                if (profile_.protocol==config::TcpProxyProtocol::socks5) {
                    auto result=co_await socks5_command(*transport_->stream,profile_,target,false,deadline,domain);
                    accepted=result.has_value();
                } else if (profile_.protocol==config::TcpProxyProtocol::socks4 ||
                           profile_.protocol==config::TcpProxyProtocol::socks4a) {
                    accepted=co_await socks4_command(*transport_->stream,profile_,target,deadline,domain);
                } else {
#ifdef NEXUS_HTTP_CONNECT_TLS
                    if (profile_.tls_profile) {
                        auto authenticated=co_await start_tls(deadline);
                        if (authenticated)
                            accepted=co_await http_connect(*transport_->tls_stream,profile_,target,buffered_,deadline,domain);
                    } else
#endif
                    {
                        accepted=co_await http_connect(*transport_->stream,profile_,target,buffered_,deadline,domain);
                    }
                }
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                if (!accepted) co_return TunnelConnectResult::failed;
                ready_=true;
                co_return TunnelConnectResult::connected;
            }

            auto cancel() noexcept -> void {
                canceled_=true;
                dns_.cancel();
                if (udp_) udp_->stop();
#ifdef NEXUS_HTTP_CONNECT_TLS
                if (transport_->tls_stream) {
                    transport_->tls_stream->cancel();
                    return;
                }
                if (transport_->tls_client) {
                    transport_->tls_client->cancel();
                    return;
                }
#endif
                if (transport_->stream) transport_->stream->cancel();
                else if (transport_->socket) transport_->socket->cancel();
                else lower_.cancel();
            }

            auto send(std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
                if (!ready_ || canceled_) co_return false;
                bool sent=false;
                if (udp_) sent=co_await udp_->send(bytes);
#ifdef NEXUS_HTTP_CONNECT_TLS
                else if (transport_->tls_stream) sent=co_await transport_->tls_stream->send(bytes);
#endif
                else sent=co_await transport_->stream->send(bytes);
                if (sent) session_.touched=Clock::now();
                co_return sent;
            }

            auto read(std::span<std::uint8_t> bytes) -> nex::capy::task<std::expected<std::size_t,std::string>> {
                if (!ready_ || canceled_) co_return std::unexpected("TCP proxy stream closed");
                if (udp_) {
                    auto count=co_await udp_->read(bytes);
                    if (count && *count) session_.touched=Clock::now();
                    co_return count;
                }
                if (buffered_offset_<buffered_.size()) {
                    auto count=std::min(bytes.size(),buffered_.size()-buffered_offset_);
                    std::copy_n(buffered_.data()+buffered_offset_,count,bytes.begin());
                    buffered_offset_+=count;
                    if (count) session_.touched=Clock::now();
                    co_return count;
                }
#ifdef NEXUS_HTTP_CONNECT_TLS
                if (transport_->tls_stream) {
                    auto count=co_await transport_->tls_stream->read(bytes);
                    if (!count) co_return std::unexpected("HTTP CONNECT TLS stream read failed");
                    if (*count) session_.touched=Clock::now();
                    co_return *count;
                }
#endif
                auto count=co_await transport_->stream->read(bytes);
                if (!count) co_return std::unexpected("TCP proxy read failed");
                if (*count) session_.touched=Clock::now();
                co_return *count;
            }

            auto close_output() -> nex::capy::task<bool> {
                if (!ready_ || canceled_ || udp_) co_return false;
#ifdef NEXUS_HTTP_CONNECT_TLS
                if (transport_->tls_stream) co_return co_await transport_->tls_stream->close_output();
#endif
                co_return co_await transport_->stream->close_output();
            }

            auto upload() -> nex::capy::task<bool> {
                return net::stream_relay::upload(net::ByteRelayAdapter{session_.client,*this,
                    [this] {session_.touched=Clock::now();},relay_local_,session_.traffic_delivery()});
            }

            auto download() -> nex::capy::task<bool> {
                return net::stream_relay::download(net::ByteRelayAdapter{session_.client,*this,
                    [this] {session_.touched=Clock::now();},relay_local_,session_.traffic_delivery()});
            }

            auto packet_transport() const noexcept -> net::PacketTransport {
                if constexpr (Carrier!=UpstreamCarrier::detour)
                    if (profile_.udp) return {net::PacketTransportKind::framed,{},false};
                return {};
            }
            auto connect_packets(Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
                if constexpr (Carrier==UpstreamCarrier::detour) co_return TunnelConnectResult::failed;
                else {
                    if (!profile_.udp || starting_ || ready_ || canceled_ || session_.closed)
                        co_return TunnelConnectResult::failed;
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                    starting_=true;
                    struct Guard {
                        TcpProxyTunnel& tunnel;
                        ~Guard() {tunnel.starting_=false;if (!tunnel.ready_) tunnel.cancel();}
                    } guard{*this};
                    auto prepared=co_await prepare(deadline);
                    if (prepared!=TunnelConnectResult::connected) co_return prepared;
                    auto bound=co_await socks5_command(*transport_->stream,profile_,
                        nex::corosio::endpoint(nex::corosio::ipv4_address{},0),true,deadline);
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                    if (!bound) co_return TunnelConnectResult::failed;
                    if constexpr (Carrier==UpstreamCarrier::fast_open) {
                        peer_=transport_->stream->remote_endpoint();
                        interface_index_=transport_->stream->interface_index();
                    }
                    auto binding=options_.binding;
                    if (binding.network) {
                        binding.interface_index=interface_index_;
                        binding.network.reset();
                    }
                    auto relay=std::make_shared<SocksUdpRelay>(context_);
                    if (!relay->start(*bound,peer_,binding,deadline))
                        co_return TunnelConnectResult::failed;
                    auto transport=transport_;
                    nex::capy::run_async(context_.get_executor(),[relay] noexcept {relay->stop();},
                        [relay](std::exception_ptr) noexcept {relay->stop();})(relay->monitor(std::move(transport)));
                    udp_=std::move(relay);
                    ready_=true;
                    co_return TunnelConnectResult::connected;
                }
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        };
    }

    auto Server::add_tcp_proxy(config::TcpProxyOutbound const& config) -> std::expected<std::size_t,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
        if (config.protocol==config::TcpProxyProtocol::http_connect && config.http_version!=config::HttpProxyVersion::h1) {
#ifdef NEXUS_ENABLE_NAIVE
            if (outbounds.size()>=16) return std::unexpected("too many tunnel outbounds");
            if (config.bootstrap_index && (!dns_routing || *config.bootstrap_index>=dns_routing->resolver_count()))
                return std::unexpected("invalid TCP proxy bootstrap resolver");
            auto factory=make_http_modern_factory(config);
            if (!factory) return std::unexpected(factory.error());
            auto index=outbounds.size()+2;
            outbounds.push_back(std::move(*factory));
            if (config.bootstrap_index && (!max_bootstrap_index || *config.bootstrap_index>*max_bootstrap_index))
                max_bootstrap_index=config.bootstrap_index;
            return index;
#else
            return std::unexpected("HTTP/2 and HTTP/3 proxy outbounds require naive build feature");
#endif
        }
        if (outbounds.size()>=16 || config.host.empty() || config.host.size()>253 || !config.port ||
            !config.connect_timeout_ms || config.connect_timeout_ms>3600000 || !config.tcp_options.valid())
            return std::unexpected("invalid TCP proxy outbound options");
        if (config.bootstrap_index && (!dns_routing || *config.bootstrap_index>=dns_routing->resolver_count()))
            return std::unexpected("invalid TCP proxy bootstrap resolver");
        auto is_socks4=config.protocol==config::TcpProxyProtocol::socks4 || config.protocol==config::TcpProxyProtocol::socks4a;
        if (config.protocol!=config::TcpProxyProtocol::socks5 && (config.udp || (config.protocol!=config::TcpProxyProtocol::http_connect && !is_socks4)))
            return std::unexpected("invalid TCP proxy outbound protocol");
        if (config.tls && config.protocol!=config::TcpProxyProtocol::http_connect)
            return std::unexpected("TLS is supported on HTTP CONNECT outbounds");
        if (config.username.size()>255 || (!is_socks4 && config.username.empty()!=config.password_file.empty()) ||
            (is_socks4 && !config.password_file.empty()) ||
            std::ranges::any_of(config.username,[](unsigned char c) {return c<32 || c==127;}) ||
            (config.protocol==config::TcpProxyProtocol::http_connect && config.username.contains(':')))
            return std::unexpected("invalid TCP proxy authentication");
        auto profile=std::unique_ptr<TcpProxyProfile>(new TcpProxyProfile{
            config.host,config.username,{},config.port,config.protocol,config.udp,config.bootstrap_index,
            config.connect_timeout_ms,config.tcp_options});
        if (config.tls) {
#ifdef NEXUS_HTTP_CONNECT_TLS
            constexpr std::array<std::string_view,1> protocols{"http/1.1"};
            auto identity=tls::ClientProfile::load(config.tls->server_name,config.tls->ca_file,0x001d,false,protocols);
            if (!identity) return std::unexpected(identity.error());
            identity->certificate_pins=config.tls->certificate_sha256;
            auto fp=tls::parse_fingerprint(config::tls_fingerprint_name(config.tls->fingerprint));
            if (!fp) return std::unexpected("invalid HTTP CONNECT TLS fingerprint");
            auto shaped=tls::ShapedClientProfile::create(std::move(*identity),*fp);
            if (!shaped) return std::unexpected(shaped.error());
            profile->tls_profile.emplace(std::move(*shaped));
#else
            return std::unexpected("HTTP CONNECT TLS is unavailable in this build");
#endif
        }
        if (!config.password_file.empty()) {
            auto password=rulefile::read_password_file(config.password_file);
            if (!password) return std::unexpected("invalid TCP proxy password-file");
            struct WipePassword {
                std::string& value;
                ~WipePassword() { ::explicit_bzero(value.data(),value.size()); }
            } wipe{*password};
            profile->password=*password;
        }
        auto* borrowed=profile.get();
        auto index=outbounds.size()+2;
        TunnelFactory factory{
            [profile=std::move(profile)](Session& session,nex::corosio::io_context& context,bool relay_local,
                TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
                auto const& options=inherited ? *inherited : profile->options;
                if (options.tcp_fast_open.value_or(false))
                    return pro::make_proxy<TunnelFacade,TcpProxyTunnel<UpstreamCarrier::fast_open>>(
                        session,context,*profile,options,relay_local);
                return pro::make_proxy<TunnelFacade,TcpProxyTunnel<UpstreamCarrier::tcp>>(
                    session,context,*profile,options,relay_local);
            },
            config.connect_timeout_ms,
            [borrowed](Session& session,nex::corosio::io_context& context,TunnelFactory const& detour,bool relay_local)
                -> pro::proxy<TunnelFacade> {
                return pro::make_proxy<TunnelFacade,TcpProxyTunnel<UpstreamCarrier::detour>>(
                    session,context,*borrowed,detour,relay_local);
            },
            std::nullopt,config.tcp_options.configured()};
        factory.packet_dual_family=config.udp;
        outbounds.push_back(std::move(factory));
        if (config.bootstrap_index && (!max_bootstrap_index || *config.bootstrap_index>*max_bootstrap_index))
            max_bootstrap_index=config.bootstrap_index;
        return index;
    }

#include "probe_h2.hpp"
}
