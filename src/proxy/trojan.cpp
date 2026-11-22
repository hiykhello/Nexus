module proxy;
import std;
import proxy.v4;
import trojan;
import trojan.auth;
import trojan.stream;
import httpupgrade;
import httpupgrade.stream;
import websocket.stream;
import grpc.headers;
import grpc.session;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.connection;
import platform.ip_address;
import tls.byte_stream;
import tls.profiles;
import tls.fingerprint;
import tls.connector;
import net.connection_pool;
import net.operation_token;
import net.stream_relay;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "transport_helpers.hpp"
#include "grpc_pool.hpp"
#include "trojan_grpc.hpp"

namespace proxy {
    namespace {
        using Connected=tls::detail::ConnectResult;
        auto result(Connected value) -> TunnelConnectResult {
            switch (value) {
            case Connected::connected: return TunnelConnectResult::connected;
            case Connected::retryable: return TunnelConnectResult::retryable;
            case Connected::failed: return TunnelConnectResult::failed;
            case Connected::timeout: return TunnelConnectResult::timeout;
            }
            std::terminate();
        }
        struct Profile {
            std::string host;
            std::uint16_t port;
            trojan::PasswordKey password;
            tls::ShapedClientProfile tls;
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout_ms;
            TcpSocketOptions options;
            bool fast_open;
            std::optional<httpupgrade::Profile> transport;
        };
        struct Resolver {
            Session& session; nex::corosio::io_context& context; Profile const& profile; DnsSlot slot;
            auto operator()(Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
                if (profile.bootstrap) return resolve_bootstrap_owned(session,context,slot,*profile.bootstrap,profile.host,profile.port,deadline);
                return resolve_local_owned(session,context,slot,profile.host,profile.port,deadline);
            }
            auto connected(nex::corosio::endpoint const& endpoint) noexcept -> void { session.record_physical_peer(endpoint); }
            auto cancel() noexcept -> void { slot.cancel(); }
        };
        struct Lower {
            using Candidates=LowerConnector::Candidates;
            Session& session;
            LowerConnector connector;
            Lower(Session& value,nex::corosio::io_context& context,TunnelFactory const& factory,Profile const& profile)
                : session(value),connector{{},&context,&factory,profile.host,profile.port,profile.bootstrap} {}
            auto connect(Clock::time_point deadline,Candidates& candidates) -> nex::capy::task<Connected> {
                auto value=co_await connector.connect(session,deadline,candidates);
                switch (value) {
                case TunnelConnectResult::connected: co_return Connected::connected;
                case TunnelConnectResult::retryable: co_return Connected::retryable;
                case TunnelConnectResult::failed: co_return Connected::failed;
                case TunnelConnectResult::timeout: co_return Connected::timeout;
                }
                std::terminate();
            }
            auto retry() noexcept -> bool { return connector.retry(); }
            auto read(std::span<std::uint8_t> bytes) { return connector.tunnel->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return connector.tunnel->send(bytes); }
            auto close_output() { return connector.tunnel->close_output(); }
            auto cancel() noexcept -> void { connector.cancel(); }
        };
        using Physical=tls::detail::PhysicalConnector<Resolver,tls::ShapedClientProfile>;
        using FastOpenPhysical=tls::detail::FastOpenPhysicalConnector<Resolver,tls::ShapedClientProfile>;
        using Layer=tls::detail::LayerConnector<Lower,tls::ShapedClientProfile>;
        template<class Connector>
        class Tunnel {
            using Socket=typename Connector::Socket;
            using WsStream=websocket::VlessByteStream<Socket>;
            using Client=trojan::detail::Client<Socket,WsStream>;
            Session& session_;
            Profile const& profile_;
            bool relay_local_,ready_=false;
            std::stop_source stop_;
            Connector connector_;
            std::unique_ptr<Client> client_;
        public:
            template<class... Args>
            Tunnel(Session& session,Profile const& profile,bool relay_local,Args&&... args)
                : session_(session),profile_(profile),relay_local_(relay_local),
                  connector_(std::forward<Args>(args)...) {}
            ~Tunnel() { cancel(); }
            auto cancel() noexcept -> void {
                stop_.request_stop(); if (client_) client_->cancel();
                connector_.cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }
            auto connect(nex::corosio::endpoint endpoint) -> nex::capy::task<TunnelConnectResult> {
                return connect_until(endpoint,session_.started+std::chrono::milliseconds(profile_.timeout_ms));
            }
            auto connect_until(nex::corosio::endpoint endpoint,Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
                return start(endpoint,false,deadline);
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline)
                -> nex::capy::task<TunnelConnectResult> {
                return start(nex::corosio::endpoint(nex::corosio::ipv4_address{},port),false,deadline,domain);
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto packet_transport() const noexcept -> net::PacketTransport { return {net::PacketTransportKind::framed,trojan::datagram_framing,false}; }
            auto connect_packets(Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> { return start({},true,deadline); }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_uot() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        private:
            auto start(nex::corosio::endpoint endpoint,bool packets,Clock::time_point deadline,
                       std::string_view domain={}) -> nex::capy::task<TunnelConnectResult> {
                if (ready_ || client_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                struct Guard { Tunnel& owner; bool done=false; ~Guard() { if (!done) owner.cancel(); } } guard{*this};
                auto connected=co_await connector_.start(deadline);
                if (session_.closed || stop_.stop_requested()) co_return TunnelConnectResult::failed;
                if (connected!=Connected::connected) co_return result(connected);
                auto* application=connector_.application();
                if (!application) co_return TunnelConnectResult::failed;
                trojan::Request request;
                request.command=packets ? trojan::Command::udp : trojan::Command::tcp;
                auto& address=request.destination;
                if (packets) { address.family=trojan::Family::ipv4; address.length=4; }
                else {
                    address.port=endpoint.port();
                    if (!domain.empty()) {
                        address.family=trojan::Family::domain; address.length=static_cast<std::uint8_t>(domain.size());
                        std::ranges::copy(domain,address.bytes.begin());
                    } else if (endpoint.address().is_v4()) {
                        address.family=trojan::Family::ipv4; address.length=4;
                        auto bytes=endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes,address.bytes.begin());
                    } else {
                        address.family=trojan::Family::ipv6; address.length=16;
                        auto bytes=endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes,address.bytes.begin());
                    }
                }
#ifdef NEXUS_ENABLE_KTLS
                if (!profile_.transport) (void)application->try_enable_ktls();
#endif
                client_=std::make_unique<Client>(*application);
                if (profile_.transport) {
                    if (!co_await transport_detail::handshake_ws_or_hu(client_->stream(),*profile_.transport,deadline) || session_.closed || stop_.stop_requested())
                        co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                }
                auto sent=co_await client_->start(profile_.password.view(),request,deadline);
                if (!sent || session_.closed || stop_.stop_requested()) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                ready_=true; guard.done=true; co_return TunnelConnectResult::connected;
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                auto sent=co_await client_->send(bytes);
                if (sent) session_.touched=Clock::now();
                else cancel();
                co_return sent;
            }
            auto read(std::span<std::uint8_t> bytes) -> nex::capy::task<std::expected<std::size_t,std::string>> {
                if (!ready_ || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto value=co_await client_->read(bytes);
                if (!value) { cancel(); co_return std::unexpected("TLS stream read failed"); }
                if (*value) session_.touched=Clock::now();
                co_return *value;
            }
            auto close_output() -> nex::capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await client_->close_output();
            }
            auto upload() -> nex::capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{session_.client,*client_,
                    [this] { session_.touched=Clock::now(); },relay_local_, session_.traffic_delivery()});
            }
            auto download() -> nex::capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::download(net::ByteRelayAdapter{session_.client,*client_,
                    [this] { session_.touched=Clock::now(); },relay_local_, session_.traffic_delivery()});
            }
        };
    }
    auto make_trojan_factory(std::string_view host,std::uint16_t port,std::string_view password_file,std::string_view server_name,
        std::string_view ca_file,TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,std::uint32_t timeout_ms,TcpSocketOptions options,bool fast_open,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit,std::span<std::array<std::uint8_t,32> const> pins,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc_cfg)
        -> std::expected<TunnelFactory,std::string> {
        if (host.empty() || host.size()>253 || !port || std::ranges::any_of(host,[](unsigned char c) { return c<33 || c>126; })) return std::unexpected("invalid Trojan server");
        if (!timeout_ms || timeout_ms>3600000 || !options.valid()) return std::unexpected("invalid Trojan dial options");
        if (transport && grpc_cfg) return std::unexpected("Trojan accepts at most one transport");
        if (exchange!=TlsKeyExchange::x25519 && exchange!=TlsKeyExchange::x25519_mlkem768 && exchange!=TlsKeyExchange::x25519_mlkem768_only) return std::unexpected("invalid TLS key exchange");
        auto key=trojan::PasswordKey::load(password_file);
        if (!key) return std::unexpected(key.error());
        std::optional<httpupgrade::Profile> hu_prof;
        if (transport) {
            auto compiled=transport_detail::compile_httpupgrade(*transport,true,server_name);
            if (!compiled) return std::unexpected(compiled.error());
            hu_prof=std::move(*compiled);
        }
        std::optional<transport_detail::GrpcSettings> grpc_prof;
        if (grpc_cfg) {
            auto compiled=transport_detail::compile_grpc(*grpc_cfg,true,server_name);
            if (!compiled) return std::unexpected(compiled.error());
            grpc_prof=std::move(*compiled);
        }
        constexpr std::array<std::string_view,1> alpn_h1{"http/1.1"}, alpn_h2{"h2"};
        std::span<std::string_view const> alpn = grpc_prof ? std::span<std::string_view const>(alpn_h2) : hu_prof ? std::span<std::string_view const>(alpn_h1) : std::span<std::string_view const>{};
        auto profile_tls=tls::ClientProfile::load(server_name,ca_file,exchange==TlsKeyExchange::x25519 ? 0x001d : 0x11ec,exchange==TlsKeyExchange::x25519_mlkem768_only,alpn);
        if (!profile_tls) return std::unexpected(profile_tls.error());
        profile_tls->certificate_pins.assign(pins.begin(),pins.end());
        auto shape=tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!shape) return std::unexpected("invalid TLS fingerprint configuration");
        auto shaped=tls::ShapedClientProfile::create(std::move(*profile_tls),*shape,record_size_limit);
        if (!shaped) return std::unexpected(shaped.error());
        if (grpc_prof) {
            auto gp=std::make_unique<trojan_grpc::Profile>(std::string(host),port,std::move(*key),std::move(*shaped),
                std::move(grpc_prof->request),grpc_prof->response,grpc_prof->limits,grpc_prof->max_sessions,
                bootstrap,timeout_ms,options,fast_open);
            return trojan_grpc::make_factory(std::move(gp));
        }
        auto profile=std::make_unique<Profile>(std::string(host),port,std::move(*key),std::move(*shaped),bootstrap,timeout_ms,options,fast_open,std::move(hu_prof));
        auto* layered=profile.get();
        return TunnelFactory{[profile=std::move(profile)](Session& session,nex::corosio::io_context& context,bool relay_local,TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
            if(inherited ? inherited->tcp_fast_open.value_or(false) : profile->fast_open)
                return pro::make_proxy<TunnelFacade,Tunnel<FastOpenPhysical>>(session,*profile,relay_local,context,Resolver{session,context,*profile},profile->tls,inherited ? *inherited : profile->options);
            return pro::make_proxy<TunnelFacade,Tunnel<Physical>>(session,*profile,relay_local,context,Resolver{session,context,*profile},profile->tls,inherited ? *inherited : profile->options);
        },timeout_ms,[layered](Session& session,nex::corosio::io_context& context,TunnelFactory const& detour,bool relay_local) {
            return pro::make_proxy<TunnelFacade,Tunnel<Layer>>(session,*layered,relay_local,layered->tls,session,context,detour,*layered);
        },std::nullopt,options.configured() || fast_open};
    }
}
