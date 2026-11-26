module;
#include <boost/capy/ex/run.hpp>

module relay;
import std;
import proxy.v4;
import config;
import crypto;
import http.connect;
import http.header;
import http2.client_channel;
import net.socket_stream;
import net.datagram_driver;
import net.udp_connect;
import masque.client_profile;
import masque.session;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.native_memory;
import hysteria2.transport_options;
import http2.headers;
import nghttp3;
import ngtcp2;
import net.stream_relay;
import net.tcp_connect;
import platform.ip_address;
import rulefile;
import tls.byte_stream;
import tls.corosio_application;
import tls.connector;
import tls.fingerprint;
import tls.profiles;
import vless;
import vless.corosio_client;
import vless.client_profile;
import xhttp.client;
import xhttp.config;
import xhttp.wire;
import xhttp.xmux;
import capy;
import corosio;
import :xhttp_http1;
import :xhttp_http1_dial;
import :xhttp_carrier;
import :xhttp_http2_pool;
import :xhttp_stream_client;

namespace relay {
    namespace vless_xhttp {
        template<class Stream>
        class Tunnel {
            using Client=vless::detail::TcpClient<Socket,false,Stream&>;
            using Relay=vless::detail::DuplexRelay<Socket,Socket,Stream&>;
            Session& session_;
            Profile const& profile_;
            bool relay_local_;
            Stream stream_;
            Client client_;
            Relay relay_;
            bool started_=false,ready_=false;
            auto start(corosio::endpoint target,std::string_view name,bool mux,Clock::time_point until)
                -> capy::task<TunnelConnectResult> {
                if (started_ || session_.closed) co_return TunnelConnectResult::failed;
                started_=true;
                if (Clock::now()>=until) co_return TunnelConnectResult::timeout;
                if (co_await stream_.start(until)) {
                    vless::TcpRequest request;
                    request.user=profile_.user;
                    request.port=target.port();
                    if (!mux && !name.empty()) {
                        request.kind=vless::AddressKind::domain;request.address.assign(name.begin(),name.end());
                    } else if (!mux && target.is_v4()) {
                        request.kind=vless::AddressKind::ipv4;
                        auto address=target.address().to_v4().to_bytes();request.address.assign(address.begin(),address.end());
                    } else if (!mux) {
                        request.kind=vless::AddressKind::ipv6;
                        auto address=target.address().to_v6().to_bytes();request.address.assign(address.begin(),address.end());
                    }
                    auto result=mux ? co_await client_.start_mux(request.user,false,until) : co_await client_.start(request,until);
                    if (result && !session_.closed) {ready_=true;co_return TunnelConnectResult::connected;}
                }
                stream_.cancel();
                co_return Clock::now()>=until ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            }
        public:
            template<class... Args>
            Tunnel(Session& session,corosio::io_context& context,Profile const& profile,bool local,TcpSocketOptions const& options,
                Args&&... args)
                :session_(session),profile_(profile),relay_local_(local),stream_(session,context,profile,options,std::forward<Args>(args)...),
                  client_(stream_),relay_(session.client,client_,[this]{session_.touched=Clock::now();},local) {}
            auto connect(corosio::endpoint target) {return connect_until(target,Clock::now()+std::chrono::milliseconds(profile_.timeout));}
            auto connect_until(corosio::endpoint target,Clock::time_point until) -> capy::task<TunnelConnectResult> {return start(target,{},false,until);}
            auto connect_domain(std::string_view name,std::uint16_t port,Clock::time_point until) {
                return start(corosio::endpoint(corosio::ipv4_address{},port),name,false,until);
            }
            auto has_uot() const noexcept -> bool {return false;}
            auto connect_uot() -> capy::task<TunnelConnectResult> {co_return TunnelConnectResult::failed;}
            auto connect_uot_until(Clock::time_point) {return connect_uot();}
            auto has_xudp() const noexcept -> bool {return true;}
            auto packet_transport() const noexcept -> net::PacketTransport {return {net::PacketTransportKind::xudp};}
            auto connect_packets(Clock::time_point until) {return start({}, {},true,until);}
            auto connect_xudp_until(Clock::time_point until) {return connect_packets(until);}
            auto connect_xudp() {return connect_packets(Clock::now()+std::chrono::milliseconds(profile_.timeout));}
            auto send(std::span<std::uint8_t const> data) -> capy::task<bool> {co_return ready_ && co_await relay_.write(data);}
            auto read(std::span<std::uint8_t> data) -> capy::task<std::expected<std::size_t,std::string>> {
                if (ready_) if (auto result=co_await relay_.read(data)) co_return *result;
                if (auto status=stream_.last_http_status(); status && status!=200)
                    co_return std::unexpected(std::format("VLESS XHTTP rejected with HTTP {}",status));
                co_return std::unexpected("VLESS XHTTP read failed");
            }
            auto close_output() -> capy::task<bool> {co_return ready_ && co_await relay_.close_output();}
            auto upload() -> capy::task<bool> {co_return ready_ && co_await relay_.upload({},session_.traffic_delivery());}
            auto download() -> capy::task<bool> {co_return ready_ && co_await relay_.download({},session_.traffic_delivery());}
            auto cancel() noexcept -> void {
                stream_.cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }
        };


        auto dispatch(std::unique_ptr<Profile> profile) -> TunnelFactory {
            using Worker = HttpWorker<HttpCarrier>;
            using Stream = HttpStream<HttpCarrier>;
            auto timeout = profile->timeout;
            auto options = profile->options;
            auto upload = profile->up.endpoint.version;
            auto download = profile->down ? profile->down->endpoint.version : upload;
            struct Workers {
                std::mutex mutex;
                std::unordered_map<corosio::io_context*, std::shared_ptr<Worker>> contexts;
                auto get(corosio::io_context& context) noexcept -> std::shared_ptr<Worker> {
                    std::lock_guard lock(mutex);
                    auto it = contexts.find(&context);
                    return it == contexts.end() ? nullptr : it->second;
                }
            };
            auto workers = std::make_shared<Workers>();
            auto mux = profile->transport.mux;
            TunnelFactory factory{[profile = std::move(profile), workers](Session& session, corosio::io_context& context, bool local,
                TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
                auto const& settings = inherited ? *inherited : profile->options;
                auto worker = workers->get(context);
                if (!worker) return {};
                return pro::make_proxy<TunnelFacade, Tunnel<Stream>>(session, context, *profile, local, settings, std::move(worker));
            }, timeout, {}, std::nullopt, options.configured()};
            factory.start_context = [workers, mux, upload, download](OutboundContext const& env, TunnelFactory const*, bool) {
                auto worker = std::make_shared<Worker>(env.context, mux, upload, download);
                std::lock_guard lock(workers->mutex);
                if (!workers->contexts.emplace(&env.context, worker).second) return false;
                Worker::start(std::move(worker));
                return true;
            };
            factory.stop_context = [workers](corosio::io_context& context) noexcept {
                if (auto worker = workers->get(context)) worker->stop();
            };
            factory.quiesced_context = [workers](corosio::io_context& context) noexcept {
                auto worker = workers->get(context);
                return !worker || worker->drained();
            };
            factory.finish_context = [workers](corosio::io_context& context) noexcept {
                std::lock_guard lock(workers->mutex);
                workers->contexts.erase(&context);
            };
            factory.packet_dual_family = true;
            return factory;
        }
    }

    auto make_vless_xhttp_factory(std::string_view host,std::uint16_t port,std::string_view uuid,std::string_view server_name,
        std::string_view ca,TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,std::uint32_t timeout,
        TcpSocketOptions options,xhttp::Profile transport,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size,std::optional<Reality> reality,std::span<std::array<std::uint8_t,32> const> pins,QuicEchOptions const& ech,bool dns_available)
        -> std::expected<TunnelFactory,std::string> {
        using namespace vless_xhttp;
        if (!timeout || timeout>3600000 || !options.valid() || !transport.limits.valid() ||
            !transport.mux.valid() || !xhttp::valid_padding(transport.padding))
            return std::unexpected("invalid VLESS XHTTP outbound limits");
        if (transport.endpoint.version==xhttp::HttpVersion::http3 &&
            (server_name.empty() || options.tcp_configured() || record_size))
            return std::unexpected("VLESS XHTTP HTTP/3 requires TLS and UDP socket options");
        auto effective=xhttp::select_mode(transport.mode,transport.endpoint.version,reality.has_value(),transport.download.has_value());
        if (!xhttp::mode_supported(effective,transport.endpoint.version,
                transport.download ? transport.download->endpoint.version : transport.endpoint.version,transport.download.has_value()))
            return std::unexpected("invalid VLESS XHTTP outbound mode");
        if (transport.download && transport.download->endpoint.version==xhttp::HttpVersion::http3 &&
            (transport.download->server_name.empty() || options.tcp_configured()))
            return std::unexpected("VLESS XHTTP HTTP/3 download requires TLS and UDP socket options");
        auto secret=rulefile::read_password_file(uuid);
        if (!secret) return std::unexpected("UUID file: "+secret.error());
        auto user=vless::parse_user_id(*secret);
        std::fill(secret->begin(),secret->end(),'\0');
        if (!user) return std::unexpected("invalid VLESS UUID");
        auto up=make_peer(host,port,transport.endpoint,server_name,ca,exchange,fingerprint,record_size,reality,pins,ech,dns_available);
        if (!up) return std::unexpected(up.error());
        std::optional<Peer> down;
        if (auto const& download=transport.download) {
            auto peer=make_peer(download->host,download->port,download->endpoint,download->server_name,
                download->ca_file,exchange,fingerprint,record_size);
            if (!peer) return std::unexpected(peer.error());
            down.emplace(std::move(*peer));
        }
        auto profile=std::make_unique<Profile>(std::move(*up),std::move(down),std::move(transport),*user,bootstrap,timeout,options);
        return dispatch(std::move(profile));
    }
}
