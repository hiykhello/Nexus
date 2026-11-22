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
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/shutdown_type.hpp>
module proxy;
import proxy.v4;
import std;
import nexus.compat;
import crypto;
import shadowsocks.corosio_client;
import shadowsocks.key;
import shadowsocks.udp_client;
import net.udp_connect;
import net.packet_stream_socket;
import net.datagram_frame;
import nexus.thirdparty.capy;
import shadowsocks.corosio_relay;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import uot;
#ifdef NEXUS_TEST_TUNNEL_PROFILE
extern "C" void nexus_test_tunnel_profile_created();
extern "C" void nexus_test_tunnel_profile_released();
extern "C" void nexus_test_tunnel_profile_destroy();
#endif
namespace proxy {
    namespace {
        struct Profile {
            std::string host; std::uint16_t port; std::vector<std::uint8_t> key; bool udp_over_tcp,udp_native;
            std::optional<std::size_t> bootstrap; std::uint32_t timeout_ms;
            TcpSocketOptions tcp_options;
            nexus::inplace_vector<std::array<std::uint8_t,32>,8> identities;
            shadowsocks::CipherMethod method;
            Profile(std::string_view host_,std::uint16_t port_,std::span<std::uint8_t const> key_,bool uot,
                    std::optional<std::size_t> bootstrap_,std::uint32_t timeout,TcpSocketOptions options={},
                    std::span<std::array<std::uint8_t,32> const> identity_keys={},
                    shadowsocks::CipherMethod cipher=shadowsocks::CipherMethod::aes,bool native=false)
                : host(host_),port(port_),key(key_.begin(),key_.end()),udp_over_tcp(uot),udp_native(native),bootstrap(bootstrap_),
                  timeout_ms(timeout),tcp_options(options),identities(identity_keys.begin(),identity_keys.end()),method(cipher) {
#ifdef NEXUS_TEST_TUNNEL_PROFILE
                nexus_test_tunnel_profile_created();
#endif
            }
            auto packet_transport() const noexcept -> net::PacketTransport {
                if (udp_native) return {net::PacketTransportKind::framed,{net::AddressWire::socks},false};
                if (udp_over_tcp) return {net::PacketTransportKind::framed,{},true};
                return {};
            }
            ~Profile() {
                crypto::cleanse(key);
                for (auto& identity:identities) crypto::cleanse(identity);
#ifdef NEXUS_TEST_TUNNEL_PROFILE
                nexus_test_tunnel_profile_released();
#endif
            }
        };
#include "quic_packet_detour.hpp"
#include "shadowsocks_native.hpp"
        struct TunnelStream {
            pro::proxy<TunnelFacade>& lower;
            auto read(std::span<std::uint8_t> bytes) { return lower->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return lower->send(bytes); }
            auto close_output() { return lower->close_output(); }
            auto cancel() noexcept -> void { lower->cancel(); }
        };
        class ShadowsocksLayer {
            Session& session_;
            LowerConnector lower_;
            TunnelStream stream_;
            net::ByteStreamAdapter<TunnelStream> socket_;
            Profile const& profile_;
            using LayerRelay=shadowsocks::detail::DuplexRelay<io::tcp_socket,net::ByteStreamAdapter<TunnelStream>>;
            std::unique_ptr<LayerRelay> relay_;
            std::unique_ptr<NativeShadowsocksPackets> packets_;
            std::stop_source stop_;
            bool starting_=false,relay_local_=true;
            std::uint32_t timeout_ms_;
        public:
            ShadowsocksLayer(Session& session,pro::proxy<TunnelFacade>&& lower,Profile const& profile,std::uint32_t timeout_ms)
                : session_(session),lower_{std::move(lower)},stream_{lower_.tunnel},socket_(stream_),profile_(profile),timeout_ms_(timeout_ms) {}
            ShadowsocksLayer(Session& session,io::io_context& context,TunnelFactory const& detour,Profile const& profile,
                             std::optional<std::size_t> bootstrap,std::uint32_t timeout_ms,bool relay_local)
                : session_(session),lower_{{},&context,&detour,profile.host,profile.port,bootstrap},
                  stream_{lower_.tunnel},socket_(stream_),profile_(profile),relay_local_(relay_local),timeout_ms_(timeout_ms) {}
            auto cancel() noexcept -> void { stop_.request_stop(); if (packets_) packets_->cancel(); if (relay_) relay_->cancel(); lower_.cancel(); }
            auto connect(io::endpoint destination) -> capy::task<TunnelConnectResult> {
                return connect_until(destination,session_.started+std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_until(io::endpoint destination,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                std::vector<std::uint8_t> address;
                if (destination.address().is_v4()) {
                    auto bytes=destination.address().to_v4().to_bytes(); address.push_back(1); address.insert(address.end(),bytes.begin(),bytes.end());
                } else {
                    auto bytes=destination.address().to_v6().to_bytes(); address.push_back(4); address.insert(address.end(),bytes.begin(),bytes.end());
                }
                address.push_back(static_cast<std::uint8_t>(destination.port()>>8)); address.push_back(static_cast<std::uint8_t>(destination.port()));
                co_return co_await capy::run(stop_.get_token())(start(std::move(address),deadline));
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                std::vector<std::uint8_t> address{3,static_cast<std::uint8_t>(domain.size())};
                address.append_range(domain);
                address.push_back(static_cast<std::uint8_t>(port>>8));
                address.push_back(static_cast<std::uint8_t>(port));
                co_return co_await capy::run(stop_.get_token())(start(std::move(address),deadline));
            }
            auto has_uot() const noexcept -> bool { return profile_.udp_over_tcp; }
            auto packet_transport() const noexcept -> net::PacketTransport { return profile_.packet_transport(); }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.udp_native) co_return co_await connect_uot_until(deadline);
                if (packets_ || relay_ || starting_ || stop_.stop_requested() || !lower_.factory)
                    co_return TunnelConnectResult::failed;
                packets_=std::make_unique<NativeShadowsocksPackets>(session_,*lower_.context,profile_,profile_.tcp_options.binding,lower_.factory);
                co_return co_await packets_->start(deadline);
            }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot() -> capy::task<TunnelConnectResult> {
                return connect_uot_until(Clock::now()+std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_uot_until(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.udp_over_tcp) co_return TunnelConnectResult::failed;
                std::vector<std::uint8_t> address{3,static_cast<std::uint8_t>(uot::v2_destination.size())};
                address.insert(address.end(),uot::v2_destination.begin(),uot::v2_destination.end()); address.insert(address.end(),{0,0});
                co_return co_await capy::run(stop_.get_token())(start(std::move(address),deadline));
            }
        private:
            auto start(std::vector<std::uint8_t> address,Clock::time_point deadline) -> coro::quitter<TunnelConnectResult> {
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                if ((!lower_.tunnel && !lower_.factory) || relay_ || packets_ || starting_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                starting_=true;
                struct StartGuard { ShadowsocksLayer& layer; bool done=false; ~StartGuard() { layer.starting_=false; if (!done) layer.cancel(); } } guard{*this};
                if (lower_.factory) {
                    LowerConnector::Candidates candidates;
                    auto connected=co_await lower_.connect(session_,deadline,candidates);
                    if (connected!=TunnelConnectResult::connected) co_return connected;
                }
                auto started=co_await shadowsocks::detail::start_request(socket_,profile_.key,address,deadline,profile_.identities,profile_.method);
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (!started) co_return started.error()==shadowsocks::detail::StartError::timeout ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                relay_=std::make_unique<LayerRelay>(session_.client,socket_,profile_.key,std::move(*started),[this] { session_.touched=Clock::now(); },relay_local_);
                guard.done=true;
                co_return TunnelConnectResult::connected;
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (packets_) co_return co_await packets_->send(bytes);
                if (!relay_ || stop_.stop_requested()) co_return false;
                co_return co_await relay_->write(bytes,Clock::now()+std::chrono::seconds(300));
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if (packets_) co_return co_await packets_->read(bytes);
                if (!relay_ || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto result=co_await relay_->read(bytes,Clock::now()+std::chrono::seconds(300));
                if (!result) co_return std::unexpected("tunnel read failed");
                co_return *result;
            }
            auto close_output() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->close_output(); }
            auto upload() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->upload(session_.traffic_delivery()); }
            auto download() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->download(session_.traffic_delivery()); }
        };
        template<bool Fast>
        class ShadowsocksTunnel {
            Session& session_; io::io_context& context_; Profile const& profile_;
            using Remote=std::conditional_t<Fast,net::ByteStreamAdapter<net::FastOpenStream>,io::tcp_socket>;
            using RemoteRelay=shadowsocks::detail::DuplexRelay<io::tcp_socket,Remote>;
            DnsSlot local_dns_; std::unique_ptr<net::FastOpenStream> fast_;std::unique_ptr<Remote> remote_;
            std::unique_ptr<RemoteRelay> relay_;
            std::unique_ptr<NativeShadowsocksPackets> packets_;
            std::optional<std::size_t> bootstrap_; std::stop_source stop_; std::uint32_t timeout_ms_;
            bool relay_local_;
            TcpSocketOptions const& tcp_options_;
        public:
            ShadowsocksTunnel(Session& session,io::io_context& context,Profile const& profile,std::optional<std::size_t> bootstrap,std::uint32_t timeout_ms,bool relay_local,TcpSocketOptions const& options)
                : session_(session),context_(context),profile_(profile),bootstrap_(bootstrap),timeout_ms_(timeout_ms),relay_local_(relay_local),tcp_options_(options) {}
#ifdef NEXUS_TEST_TUNNEL_PROFILE
            ~ShadowsocksTunnel() { nexus_test_tunnel_profile_destroy(); }
#endif
            auto cancel() noexcept -> void {
                stop_.request_stop(); local_dns_.cancel(); if (packets_) packets_->cancel(); if (relay_) relay_->cancel(); if (remote_) remote_->cancel();
            }
            auto connect(io::endpoint destination) -> capy::task<TunnelConnectResult> {
                return connect_until(destination,session_.started+std::chrono::milliseconds(timeout_ms_));
            }
            // A caller constructing a chain supplies the shared absolute deadline.
            auto connect_until(io::endpoint destination,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                std::vector<std::uint8_t> address;
                if (destination.address().is_v4()) {
                    auto bytes=destination.address().to_v4().to_bytes(); address.push_back(1); address.insert(address.end(),bytes.begin(),bytes.end());
                } else {
                    auto bytes=destination.address().to_v6().to_bytes(); address.push_back(4); address.insert(address.end(),bytes.begin(),bytes.end());
                }
                address.push_back(static_cast<std::uint8_t>(destination.port()>>8)); address.push_back(static_cast<std::uint8_t>(destination.port()));
                co_return co_await capy::run(stop_.get_token())(connect_impl(std::move(address),deadline));
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                std::vector<std::uint8_t> address{3,static_cast<std::uint8_t>(domain.size())};
                address.append_range(domain);
                address.push_back(static_cast<std::uint8_t>(port>>8));
                address.push_back(static_cast<std::uint8_t>(port));
                co_return co_await capy::run(stop_.get_token())(connect_impl(std::move(address),deadline));
            }
            auto has_uot() const noexcept -> bool { return profile_.udp_over_tcp; }
            auto packet_transport() const noexcept -> net::PacketTransport { return profile_.packet_transport(); }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.udp_native) co_return co_await connect_uot_until(deadline);
                if (packets_ || remote_ || stop_.stop_requested()) co_return TunnelConnectResult::failed;
                packets_=std::make_unique<NativeShadowsocksPackets>(session_,context_,profile_,tcp_options_.binding);
                co_return co_await packets_->start(deadline);
            }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot() -> capy::task<TunnelConnectResult> {
                return connect_uot_until(Clock::now()+std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_uot_until(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.udp_over_tcp) co_return TunnelConnectResult::failed;
                std::vector<std::uint8_t> address{3,static_cast<std::uint8_t>(uot::v2_destination.size())};
                address.insert(address.end(),uot::v2_destination.begin(),uot::v2_destination.end());
                address.insert(address.end(),{0,0});
                co_return co_await capy::run(stop_.get_token())(connect_impl(std::move(address),deadline));
            }
        private:
            auto connect_impl(std::vector<std::uint8_t> address, Clock::time_point deadline) -> coro::quitter<TunnelConnectResult> {
                if (packets_) co_return TunnelConnectResult::failed;
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
                if constexpr (Fast) {
                    fast_=std::make_unique<net::FastOpenStream>(context_,std::move(endpoints),deadline,tcp_options_);
                    remote_=std::make_unique<Remote>(*fast_);
                    auto started=co_await shadowsocks::detail::start_request(*remote_,profile_.key,address,deadline,profile_.identities,profile_.method);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!started) co_return started.error()==shadowsocks::detail::StartError::timeout || Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    if (session_.physical_peer) session_.record_physical_peer(fast_->remote_endpoint());
                    relay_=std::make_unique<RemoteRelay>(session_.client,*remote_,profile_.key,std::move(*started),[this] { session_.touched=Clock::now(); },relay_local_);
                    co_return TunnelConnectResult::connected;
                } else {
                for (auto endpoint:endpoints) {
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!valid_destination(endpoint)) continue;
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                    remote_=std::make_unique<io::tcp_socket>(context_);
                    if (auto error=net::prepare_tcp_socket(*remote_,endpoint,tcp_options_,deadline))
                        co_return TunnelConnectResult::failed;
                    auto operation=remote_->connect(endpoint);
                    auto [connect_error]=co_await io::timeout(std::move(operation),deadline);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (connect_error || Clock::now()>=deadline) {
                        auto timed_out=connect_error==capy::cond::timeout || Clock::now()>=deadline;
                        remote_->close(); remote_.reset(); if (timed_out) co_return TunnelConnectResult::timeout; continue;
                    }
                    auto started=co_await shadowsocks::detail::start_request(*remote_,profile_.key,address,deadline,profile_.identities,profile_.method);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!started) co_return started.error()==shadowsocks::detail::StartError::timeout ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    session_.record_physical_peer(endpoint);
                    relay_=std::make_unique<RemoteRelay>(session_.client,*remote_,profile_.key,std::move(*started),[this] { session_.touched=Clock::now(); },relay_local_);
                    co_return TunnelConnectResult::connected;
                }
                co_return TunnelConnectResult::retryable;
                }
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (packets_) co_return co_await packets_->send(bytes);
                if (!relay_ || stop_.stop_requested()) co_return false;
                co_return co_await relay_->write(bytes,Clock::now()+std::chrono::seconds(300));
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if (packets_) co_return co_await packets_->read(bytes);
                if (!relay_ || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto result=co_await relay_->read(bytes,Clock::now()+std::chrono::seconds(300));
                if (!result) co_return std::unexpected("tunnel read failed");
                co_return *result;
            }
            auto close_output() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->close_output(); }
            auto upload() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->upload(session_.traffic_delivery()); }
            auto download() -> capy::task<bool> { if (!relay_) co_return false; co_return co_await relay_->download(session_.traffic_delivery()); }
        };
    }
    auto make_shadowsocks_layer_factory(std::span<std::uint8_t const> key,bool udp_over_tcp,std::uint32_t timeout_ms) -> std::expected<TunnelLayerFactory,std::string> {
        if ((key.size()!=16 && key.size()!=32) || !timeout_ms || timeout_ms>3600000) return std::unexpected("invalid Shadowsocks key or timeout");
        auto profile=std::make_unique<Profile>("",0,key,udp_over_tcp,std::nullopt,timeout_ms);
        return TunnelLayerFactory{[profile=std::move(profile)](Session& session,pro::proxy<TunnelFacade>&& lower) {
            if (!lower) return pro::proxy<TunnelFacade>{};
            return pro::make_proxy<TunnelFacade,ShadowsocksLayer>(session,std::move(lower),*profile,profile->timeout_ms);
        }};
    }
    auto make_shadowsocks_factory(std::string_view host,std::uint16_t port,std::span<std::uint8_t const> key,std::optional<std::size_t> bootstrap,bool udp_over_tcp,std::uint32_t timeout_ms,TcpSocketOptions tcp_options,bool fast_open,
        std::span<std::array<std::uint8_t,32> const> identities,ShadowsocksCipher cipher,bool udp_native)
        -> std::expected<TunnelFactory,std::string> {
        if (!timeout_ms || timeout_ms>3600000) return std::unexpected("invalid connect timeout");
        if (!tcp_options.valid()) return std::unexpected("invalid TCP socket options");
        if (host.empty() || host.size()>255 || host.find('\0')!=std::string_view::npos || !port || (key.size()!=16 && key.size()!=32))
            return std::unexpected("invalid Shadowsocks 2022 server or key");
        if (udp_native && udp_over_tcp) return std::unexpected("conflicting Shadowsocks datagram transports");
        if (identities.size()>8) return std::unexpected("too many Shadowsocks identity keys");
        if (cipher==ShadowsocksCipher::chacha20 && (key.size()!=32 || !identities.empty()))
            return std::unexpected("ChaCha20 requires a 32-byte key and has no identity headers");
        for (std::size_t index=0;index<identities.size();++index) {
            auto value=std::span(identities[index]).first(key.size());
            if (crypto::constant_time_equal(value,key) ||
                std::ranges::any_of(identities.first(index),[&](auto const& previous) {
                    return crypto::constant_time_equal(value,std::span(previous).first(key.size()));
                })) return std::unexpected("duplicate Shadowsocks identity or user key");
        }
        auto method=cipher==ShadowsocksCipher::chacha20 ? shadowsocks::CipherMethod::chacha20 : shadowsocks::CipherMethod::aes;
        auto profile=std::make_unique<Profile>(host,port,key,udp_over_tcp,bootstrap,timeout_ms,tcp_options,identities,method,udp_native);
        auto* layer_profile=profile.get();
        auto factory=TunnelFactory{[profile=std::move(profile),fast_open](Session& session,io::io_context& context,bool relay_local,TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
            if (profile->timeout_ms>10000)
                session.handshake_deadline=std::max(session.handshake_deadline,session.started+std::chrono::milliseconds(profile->timeout_ms)+std::chrono::seconds(1));
            if (inherited ? inherited->tcp_fast_open.value_or(false) : fast_open) return pro::make_proxy<TunnelFacade,ShadowsocksTunnel<true>>(session,context,*profile,profile->bootstrap,profile->timeout_ms,relay_local,inherited ? *inherited : profile->tcp_options);
            return pro::make_proxy<TunnelFacade,ShadowsocksTunnel<false>>(session,context,*profile,profile->bootstrap,profile->timeout_ms,relay_local,inherited ? *inherited : profile->tcp_options);
        },timeout_ms,[layer_profile](Session& session,io::io_context& context,TunnelFactory const& detour,bool relay_local) {
            return pro::make_proxy<TunnelFacade,ShadowsocksLayer>(session,context,detour,*layer_profile,layer_profile->bootstrap,layer_profile->timeout_ms,relay_local);
        },std::nullopt,tcp_options.configured() || fast_open};
        factory.packet_dual_family=udp_native;
        return factory;
    }
}
