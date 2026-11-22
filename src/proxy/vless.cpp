module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/task.hpp>
#include "../coro/quitter.hpp"
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/async_mutex.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/shutdown_type.hpp>

module proxy;
import proxy.v4;
import std;
import socks5;
import rules;
import http.connect;
import config;
import rulefile;
import vless;
import tls.client_handshake_io;
import tls.application_io;
import tls.corosio_client;
import tls.corosio_application;
import tls.connector;
import vless.corosio_client;
import vless.vision_client;
import vless.client_profile;
import net.stream_relay;
import net.tcp_connect;
#ifdef NEXUS_TEST_TUNNEL_PROFILE
extern "C" void nexus_test_tunnel_profile_created();
extern "C" void nexus_test_tunnel_profile_released();
extern "C" void nexus_test_tunnel_profile_destroy();
#endif

namespace proxy {
    namespace {
        using Profile=vless::detail::ClientProfile;
        auto domain_request(Profile const& profile,std::string_view domain,std::uint16_t port) -> vless::TcpRequest {
            return {.user=profile.user,.kind=vless::AddressKind::domain,.port=port,
                .address={domain.begin(),domain.end()}};
        }
        auto fixed_request(Profile const& profile,net::ProxyAddress const& peer)
            -> std::optional<vless::TcpRequest> {
            if (!profile.fixed_udp || !net::valid_proxy_address(peer) || !peer.port ||
                peer.family==net::ProxyAddressFamily::domain) return {};
            auto kind=peer.family==net::ProxyAddressFamily::ipv4 ? vless::AddressKind::ipv4 : vless::AddressKind::ipv6;
            return vless::TcpRequest{.user=profile.user,.kind=kind,.port=peer.port,
                .address={peer.bytes.begin(),peer.bytes.begin()+peer.length},.command=vless::TargetCommand::udp};
        }
        auto packet_format(Profile const& profile) noexcept -> net::PacketTransport {
            if (profile.fixed_udp) return {net::PacketTransportKind::framed,{.connected=true}};
            if (profile.packetaddr) return {net::PacketTransportKind::framed,{net::AddressWire::packetaddr}};
            return {net::PacketTransportKind::xudp};
        }
        struct OwnedProfile {
            Profile value;
            std::optional<std::size_t> bootstrap; std::uint32_t timeout_ms;
            TcpSocketOptions tcp_options;
            OwnedProfile(Profile&& profile,std::optional<std::size_t> bootstrap_,std::uint32_t timeout,TcpSocketOptions options={})
                : value(std::move(profile)),bootstrap(bootstrap_),timeout_ms(timeout),tcp_options(options) {
#ifdef NEXUS_TEST_TUNNEL_PROFILE
                nexus_test_tunnel_profile_created();
#endif
            }
#ifdef NEXUS_TEST_TUNNEL_PROFILE
            ~OwnedProfile() { nexus_test_tunnel_profile_released(); }
#endif
        };
        using Client=vless::detail::TcpClient<io::tcp_socket>;
        using Relay=vless::detail::DuplexRelay<io::tcp_socket,io::tcp_socket>;
        using VisionClient=vless::detail::VisionClient<io::tcp_socket>;
        using VisionRelay=vless::detail::VisionRelay<io::tcp_socket,io::tcp_socket>;
        struct LowerStream {
            pro::proxy<TunnelFacade>& lower;
            auto read(std::span<std::uint8_t> bytes) { return lower->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return lower->send(bytes); }
            auto close_output() { return lower->close_output(); }
            auto cancel() noexcept -> void { lower->cancel(); }
        };
        class VlessLayer {
            using Socket=net::ByteStreamAdapter<LowerStream>;
            Session& session_; LowerConnector lower_; LowerStream stream_; Socket socket_;
            Profile const& profile_; std::uint32_t timeout_ms_; std::stop_source stop_; bool starting_=false,relay_local_=true;
            std::unique_ptr<tls::detail::ClientConnection<Socket>> owner_;
            std::unique_ptr<vless::detail::TcpClient<Socket>> client_;
            std::unique_ptr<vless::detail::DuplexRelay<io::tcp_socket,Socket>> relay_;
            std::unique_ptr<vless::detail::VisionClient<Socket>> vision_client_;
            std::unique_ptr<vless::detail::VisionRelay<io::tcp_socket,Socket>> vision_relay_;
        public:
            VlessLayer(Session& session,pro::proxy<TunnelFacade>&& lower,Profile const& profile,std::uint32_t timeout_ms)
                : session_(session),lower_{std::move(lower)},stream_{lower_.tunnel},socket_(stream_),profile_(profile),timeout_ms_(timeout_ms) {}
            VlessLayer(Session& session,io::io_context& context,TunnelFactory const& detour,Profile const& profile,
                       std::optional<std::size_t> bootstrap,std::uint32_t timeout_ms,bool relay_local)
                : session_(session),lower_{{},&context,&detour,profile.host,profile.port,bootstrap},
                  stream_{lower_.tunnel},socket_(stream_),profile_(profile),timeout_ms_(timeout_ms),relay_local_(relay_local) {}
            auto cancel() noexcept -> void {
                stop_.request_stop(); if (relay_) relay_->cancel(); if (vision_relay_) vision_relay_->cancel();
                if (owner_) owner_->cancel(); lower_.cancel();
            }
            auto connect(io::endpoint destination) -> capy::task<TunnelConnectResult> {
                return connect_until(destination,session_.started+std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_until(io::endpoint destination,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(start(destination,false,deadline));
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(start({},false,deadline,domain_request(profile_,domain,port)));
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return !profile_.packetaddr && !profile_.fixed_udp; }
            auto packet_transport() const noexcept -> net::PacketTransport { return packet_format(profile_); }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (profile_.fixed_udp) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(start({},true,deadline));
            }
            auto connect_packets(net::ProxyAddress const& peer,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.fixed_udp) co_return co_await connect_packets(deadline);
                auto request=fixed_request(profile_,peer);
                if (!request) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(start({},true,deadline,std::move(request)));
            }
            auto connect_xudp() -> capy::task<TunnelConnectResult> {
                return connect_xudp_until(Clock::now()+std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_xudp_until(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return has_xudp() ? co_await connect_packets(deadline) : TunnelConnectResult::failed;
            }
        private:
            auto start(io::endpoint destination,bool mux,Clock::time_point deadline,
                       std::optional<vless::TcpRequest> fixed={}) -> coro::quitter<TunnelConnectResult> {
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                if ((!lower_.tunnel && !lower_.factory) || owner_ || starting_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                starting_=true;
                struct Guard { VlessLayer& layer; bool done=false; ~Guard() { layer.starting_=false; if (!done) layer.cancel(); } } guard{*this};
                {
                    LowerConnector::Candidates candidates;
                    for (;;) {
                        if (lower_.factory) {
                            auto connected=co_await lower_.connect(session_,deadline,candidates);
                            if (connected!=TunnelConnectResult::connected) co_return connected;
                        }
                        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
                        auto end=std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count();
                        auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                        if (now<0 || end<=now) co_return TunnelConnectResult::timeout;
                        auto handshake=profile_.handshake(static_cast<std::uint64_t>(now),static_cast<std::uint64_t>(end),seconds);
                        if (!handshake) co_return TunnelConnectResult::failed;
                        owner_=std::make_unique<tls::detail::ClientConnection<Socket>>(socket_,std::move(*handshake));
                        auto connected=co_await owner_->start();
                        if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                        if (connected && profile_.accepts_alpn(owner_->negotiated())) {
                            if (!profile_.transport) break;
                            client_=std::make_unique<vless::detail::TcpClient<Socket>>(*owner_->application());
                            auto upgraded=co_await client_->upgrade(*profile_.transport,deadline);
                            if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                            if (upgraded) break;
                        }
                        auto timed_out=Clock::now()>=deadline || (!connected && connected.error()==tls::detail::AsyncHandshakeError::timeout);
                        client_.reset();
                        owner_.reset();
                        if (timed_out) co_return TunnelConnectResult::timeout;
                        if (!lower_.retry()) co_return TunnelConnectResult::failed;
                    }
                }
                auto& connection=*owner_->application();
                vless::TcpRequest request; request.user=profile_.user;
                if (!mux && !fixed) {
                    request.port=destination.port(); auto address=destination.address();
                    if (address.is_v4()) { request.kind=vless::AddressKind::ipv4; auto bytes=address.to_v4().to_bytes(); request.address.assign(bytes.begin(),bytes.end()); }
                    else { request.kind=vless::AddressKind::ipv6; auto bytes=address.to_v6().to_bytes(); request.address.assign(bytes.begin(),bytes.end()); }
                }
                if (profile_.vision) {
                    vision_client_=std::make_unique<vless::detail::VisionClient<Socket>>(socket_,connection,profile_.user);
                    vision_relay_=std::make_unique<vless::detail::VisionRelay<io::tcp_socket,Socket>>(session_.client,*vision_client_,[this] { session_.touched=Clock::now(); },relay_local_ && !mux);
                    auto sent=mux ? co_await vision_client_->start_mux(deadline) : co_await vision_client_->start(fixed ? *fixed : request,deadline);
                    if (!sent || stop_.stop_requested() || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                } else {
                    if (!client_) client_=std::make_unique<vless::detail::TcpClient<Socket>>(connection);
                    auto sent=mux && !fixed ? co_await client_->start_datagrams(profile_.user,profile_.packetaddr,deadline) : co_await client_->start(fixed ? *fixed : request,deadline);
                    if (!sent || stop_.stop_requested() || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    relay_=std::make_unique<vless::detail::DuplexRelay<io::tcp_socket,Socket>>(session_.client,connection,*client_,[this] { session_.touched=Clock::now(); },relay_local_ && !mux);
                }
                guard.done=true; co_return TunnelConnectResult::connected;
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if ((!relay_ && !vision_relay_) || stop_.stop_requested()) co_return false;
                if (bytes.empty()) co_return true;
                if (vision_relay_) co_return co_await vision_relay_->write(bytes);
                co_return co_await relay_->write(bytes);
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if ((!relay_ && !vision_relay_) || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto result=vision_relay_ ? co_await vision_relay_->read(bytes) : co_await relay_->read(bytes);
                if (!result) co_return std::unexpected("tunnel read failed"); co_return *result;
            }
            auto close_output() -> capy::task<bool> { if (vision_relay_) co_return co_await vision_relay_->close_output(); if (!relay_) co_return false; co_return co_await relay_->close_output(); }
            auto upload() -> capy::task<bool> { if (vision_relay_) co_return co_await vision_relay_->upload({},session_.traffic_delivery()); if (!relay_) co_return false; co_return co_await relay_->upload({},session_.traffic_delivery()); }
            auto download() -> capy::task<bool> { if (vision_relay_) co_return co_await vision_relay_->download({},session_.traffic_delivery()); if (!relay_) co_return false; co_return co_await relay_->download({},session_.traffic_delivery()); }
        };
#include "vless_fast.hpp"
        class VlessTunnel {
            Session& session_;
            io::io_context& context_;
            Profile const& profile_;
            DnsSlot local_dns_;
            std::unique_ptr<tls::detail::OwnedClient> owner_;
            std::unique_ptr<Client> client_;
            std::unique_ptr<Relay> relay_;
            std::unique_ptr<VisionClient> vision_client_;
            std::unique_ptr<VisionRelay> vision_relay_;
            std::optional<std::size_t> bootstrap_;
            std::stop_source stop_;
            std::uint32_t timeout_ms_;
            bool relay_local_;
            TcpSocketOptions const& tcp_options_;
        public:
            VlessTunnel(Session& session, io::io_context& context, Profile const& profile, std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms,bool relay_local,TcpSocketOptions const& options)
                : session_(session),context_(context),profile_(profile),bootstrap_(bootstrap),timeout_ms_(timeout_ms),relay_local_(relay_local),tcp_options_(options) {}
#ifdef NEXUS_TEST_TUNNEL_PROFILE
            ~VlessTunnel() { nexus_test_tunnel_profile_destroy(); }
#endif
            auto cancel() noexcept -> void {
                stop_.request_stop();
                local_dns_.cancel();
                if (relay_) relay_->cancel();
                if (vision_relay_) vision_relay_->cancel();
                if (owner_) owner_->cancel();
            }
            auto connect(io::endpoint destination) -> capy::task<TunnelConnectResult> {
                return connect_until(destination,session_.started+std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_until(io::endpoint destination,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(connect_impl(destination,false,deadline));
            }
            // UoT is a distinct extension and is not a VLESS UDP encoding.
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(connect_impl({},false,deadline,domain_request(profile_,domain,port)));
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return !profile_.packetaddr && !profile_.fixed_udp; }
            auto packet_transport() const noexcept -> net::PacketTransport { return packet_format(profile_); }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (profile_.fixed_udp) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(connect_impl({},true,deadline));
            }
            auto connect_packets(net::ProxyAddress const& peer,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.fixed_udp) co_return co_await connect_packets(deadline);
                auto request=fixed_request(profile_,peer);
                if (!request) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(connect_impl({},true,deadline,std::move(request)));
            }
            auto connect_xudp() -> capy::task<TunnelConnectResult> {
                return connect_xudp_until(Clock::now()+std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_xudp_until(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return has_xudp() ? co_await connect_packets(deadline) : TunnelConnectResult::failed;
            }
        private:
            auto connect_impl(io::endpoint destination,bool mux,Clock::time_point deadline,
                       std::optional<vless::TcpRequest> fixed={}) -> coro::quitter<TunnelConnectResult> {
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                std::vector<io::endpoint> endpoints;
                if (bootstrap_) {
                    auto result=co_await resolve_bootstrap_owned(session_,context_,local_dns_,*bootstrap_,profile_.host,profile_.port,deadline);
                    if (!result) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
                    endpoints=std::move(*result);
                } else {
                    auto result=co_await resolve_local_owned(session_,context_,local_dns_,profile_.host,profile_.port,deadline);
                    if (!result) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
                    endpoints=std::move(*result);
                }
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (endpoints.empty() || endpoints.size()>64) co_return TunnelConnectResult::retryable;
                auto deadline_ms=std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count();
                for (auto endpoint : endpoints) {
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!valid_destination(endpoint)) continue;
                    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
                    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    if (now<0) co_return TunnelConnectResult::failed;
                    if (deadline_ms<=now) co_return TunnelConnectResult::timeout;
                    auto handshake=profile_.handshake(static_cast<std::uint64_t>(now),static_cast<std::uint64_t>(deadline_ms),seconds);
                    if (!handshake) co_return TunnelConnectResult::retryable;
                    owner_=std::make_unique<tls::detail::OwnedClient>(context_,std::move(*handshake));
                    if (tcp_options_.configured()) {
                        auto* socket=owner_->unconnected_socket();
                        if (!socket || net::prepare_tcp_socket(*socket,endpoint,tcp_options_,deadline)) co_return TunnelConnectResult::failed;
                    }
                    auto connected=co_await owner_->start(endpoint);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!connected) {
                        auto timed_out=connected.error()==tls::detail::AsyncHandshakeError::timeout;
                        owner_.reset(); if (timed_out) co_return TunnelConnectResult::timeout; continue;
                    }
                    auto& connection=*owner_->client()->application();
                    if (!profile_.accepts_alpn(owner_->client()->negotiated())) { owner_.reset(); continue; }
                    vless::TcpRequest request; request.user=profile_.user;
                    if (!mux && !fixed) {
                        request.port=destination.port(); auto address=destination.address();
                        if (address.is_v4()) {
                            request.kind=vless::AddressKind::ipv4;
                            auto bytes=address.to_v4().to_bytes(); request.address.assign(bytes.begin(),bytes.end());
                        } else {
                            request.kind=vless::AddressKind::ipv6;
                            auto bytes=address.to_v6().to_bytes(); request.address.assign(bytes.begin(),bytes.end());
                        }
                    }
                    if (profile_.vision) {
                        vision_client_=std::make_unique<VisionClient>(*owner_->socket(),connection,profile_.user);
                        vision_relay_=std::make_unique<VisionRelay>(session_.client,*vision_client_,[this] { session_.touched=Clock::now(); },relay_local_ && !mux);
                        auto started=mux ? co_await vision_client_->start_mux(deadline) : co_await vision_client_->start(fixed ? *fixed : request,deadline);
                        if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                        if (!started) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                        co_return TunnelConnectResult::connected;
                    }
                    client_=std::make_unique<Client>(connection);
                    if (profile_.transport) {
                        auto upgraded=co_await client_->upgrade(*profile_.transport,deadline);
                        if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                        if (!upgraded) {
                            auto timed_out=Clock::now()>=deadline;
                            client_.reset(); owner_.reset();
                            if (timed_out) co_return TunnelConnectResult::timeout;
                            continue;
                        }
                    }
#ifdef NEXUS_TEST_VLESS_PARTIAL_REQUEST
                    std::expected<void,vless::detail::ClientError> sent;
                    if (fixed) sent=co_await client_->start(*fixed,deadline);
                    else if (mux) sent=co_await client_->start_datagrams(profile_.user,profile_.packetaddr,deadline);
                    else if (std::getenv("NEXUS_TEST_VLESS_PARTIAL_REQUEST")) {
                        auto header=vless::encode_tcp_request(fixed ? *fixed : request);
                        if (!header || !co_await connection.send_all(std::span{*header}.first(8),deadline))
                            co_return TunnelConnectResult::failed;
                        sent=std::unexpected(vless::detail::ClientError::tls);
                    } else sent=co_await client_->start(request,deadline);
#else
                    auto sent=mux && !fixed ? co_await client_->start_datagrams(profile_.user,profile_.packetaddr,deadline) : co_await client_->start(fixed ? *fixed : request,deadline);
#endif
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!sent) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    relay_=std::make_unique<Relay>(session_.client,connection,*client_,[this] { session_.touched=Clock::now(); },relay_local_ && !mux);
                    co_return TunnelConnectResult::connected;
                }
                co_return TunnelConnectResult::retryable;
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if ((!relay_ && !vision_relay_) || stop_.stop_requested()) co_return false;
                if (bytes.empty()) co_return true;
                if (vision_relay_) co_return co_await vision_relay_->write(bytes);
                co_return co_await relay_->write(bytes);
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if ((!relay_ && !vision_relay_) || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto result=vision_relay_ ? co_await vision_relay_->read(bytes) : co_await relay_->read(bytes);
                if (!result) co_return std::unexpected("tunnel read failed");
                co_return *result;
            }
            auto close_output() -> capy::task<bool> {
                if (vision_relay_) co_return co_await vision_relay_->close_output();
                if (!relay_) co_return false;
                co_return co_await relay_->close_output();
            }
            auto upload() -> capy::task<bool> {
                if (vision_relay_) co_return co_await vision_relay_->upload({},session_.traffic_delivery());
                if (!relay_) co_return false;
                co_return co_await relay_->upload({},session_.traffic_delivery());
            }
            auto download() -> capy::task<bool> {
                if (vision_relay_) co_return co_await vision_relay_->download({},session_.traffic_delivery());
                if (!relay_) co_return false;
                co_return co_await relay_->download({},session_.traffic_delivery());
            }
        };
    }
    auto make_vless_layer_factory(std::string_view uuid_file,
                          std::string_view server_name,std::string_view ca_file,TlsKeyExchange key_exchange,
                          std::optional<Reality> reality,bool vision,std::uint32_t timeout_ms,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit)
        -> std::expected<TunnelLayerFactory,std::string> {
        if (grpc) return std::unexpected("gRPC preconnected layer requires a retained connection worker");
        if (!timeout_ms || timeout_ms>3600000) return std::unexpected("invalid VLESS timeout");
        if (key_exchange!=TlsKeyExchange::x25519 && key_exchange!=TlsKeyExchange::x25519_mlkem768 && key_exchange!=TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto group=key_exchange==TlsKeyExchange::x25519 ? config::TlsKeyExchange::x25519 :
            key_exchange==TlsKeyExchange::x25519_mlkem768 ? config::TlsKeyExchange::x25519_mlkem768 : config::TlsKeyExchange::x25519_mlkem768_only;
        config::VlessOutbound config{"layer",1,std::string(uuid_file),std::string(server_name),std::string(ca_file),{},group};
        config.vision=vision; config.transport=std::move(transport); config.fingerprint=fingerprint;config.record_size_limit=record_size_limit;
        if (reality) config.reality=config::VlessOutbound::Reality{reality->public_key,reality->short_id};
        auto profile=Profile::load(config); if (!profile) return std::unexpected(profile.error());
        auto shared=std::make_unique<OwnedProfile>(std::move(*profile),std::nullopt,timeout_ms);
        return TunnelLayerFactory{[profile=std::move(shared)](Session& session,pro::proxy<TunnelFacade>&& lower) {
            if (!lower) return pro::proxy<TunnelFacade>{};
            return pro::make_proxy<TunnelFacade,VlessLayer>(session,std::move(lower),profile->value,profile->timeout_ms);
        }};
    }
    auto make_vless_factory(std::string_view host, std::uint16_t port, std::string_view uuid_file,
                            std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap, std::optional<Reality> reality, bool vision, std::uint32_t timeout_ms,TcpSocketOptions tcp_options,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc,bool fast_open,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit,bool packetaddr,bool fixed_udp,std::span<std::array<std::uint8_t,32> const> pins)
        -> std::expected<TunnelFactory,std::string> {
        if (packetaddr && fixed_udp) return std::unexpected("conflicting VLESS packet encodings");
        if ((packetaddr || fixed_udp) && (vision || grpc))
            return std::unexpected("VLESS packetaddr and fixed UDP require non-Vision TCP or HTTPUpgrade");
        if (grpc) {
            if (transport || vision || reality) return std::unexpected("gRPC requires ordinary VLESS TLS and one transport");
            if(fast_open)grpc->tcp_fast_open=true;
#ifdef NEXUS_ENABLE_GRPC_VLESS
            return make_vless_grpc_factory(host,port,uuid_file,server_name,ca_file,key_exchange,bootstrap,timeout_ms,tcp_options,std::move(*grpc),fingerprint,record_size_limit,pins);
#else
            return std::unexpected("gRPC VLESS transport is not available in this build");
#endif
        }
        if (!timeout_ms || timeout_ms>3600000) return std::unexpected("invalid connect timeout");
        if (!tcp_options.valid()) return std::unexpected("invalid TCP socket options");
        if (key_exchange!=TlsKeyExchange::x25519 && key_exchange!=TlsKeyExchange::x25519_mlkem768 && key_exchange!=TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto group=key_exchange==TlsKeyExchange::x25519 ? config::TlsKeyExchange::x25519 :
            key_exchange==TlsKeyExchange::x25519_mlkem768 ? config::TlsKeyExchange::x25519_mlkem768 : config::TlsKeyExchange::x25519_mlkem768_only;
        config::VlessOutbound config{std::string(host),port,std::string(uuid_file),std::string(server_name),std::string(ca_file),{pins.begin(),pins.end()},group};
        config.vision=vision; config.transport=std::move(transport); config.fingerprint=fingerprint;config.record_size_limit=record_size_limit;
        if (reality) config.reality=config::VlessOutbound::Reality{reality->public_key,reality->short_id};
        config.packetaddr=packetaddr; config.fixed_udp=fixed_udp;
        auto profile=Profile::load(config);
        if (!profile) return std::unexpected(profile.error());
        auto shared=std::make_unique<OwnedProfile>(std::move(*profile),bootstrap,timeout_ms,tcp_options);
        auto* layer_profile=shared.get();
        auto factory=TunnelFactory{[profile=std::move(shared),fast_open](Session& session,io::io_context& context,bool relay_local,TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
            if (profile->timeout_ms>10000)
                session.handshake_deadline=std::max(session.handshake_deadline,session.started+std::chrono::milliseconds(profile->timeout_ms)+std::chrono::seconds(1));
            if(inherited ? inherited->tcp_fast_open.value_or(false) : fast_open)return pro::make_proxy<TunnelFacade,VlessFast>(session,context,profile->value,profile->bootstrap,profile->timeout_ms,relay_local,inherited ? *inherited : profile->tcp_options);
            return pro::make_proxy<TunnelFacade,VlessTunnel>(session,context,profile->value,profile->bootstrap,profile->timeout_ms,relay_local,inherited ? *inherited : profile->tcp_options);
        },timeout_ms,[layer_profile](Session& session,io::io_context& context,TunnelFactory const& detour,bool relay_local) {
            return pro::make_proxy<TunnelFacade,VlessLayer>(session,context,detour,layer_profile->value,layer_profile->bootstrap,layer_profile->timeout_ms,relay_local);
        },std::nullopt,tcp_options.configured() || fast_open};
        factory.packet_dual_family=packetaddr;
        factory.packet_fixed_peer=fixed_udp;
        return factory;
    }
}
