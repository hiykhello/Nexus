module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/async_mutex.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/shutdown_type.hpp>

module relay;
import proxy.v4;
import std;
import coro.quitter;
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
import platform.ip_address;
import platform.wall_clock;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import net.unified_stream;
#ifdef NEXUS_TEST_TUNNEL_PROFILE
extern "C" void nexus_test_tunnel_profile_created();
extern "C" void nexus_test_tunnel_profile_released();
extern "C" void nexus_test_tunnel_profile_destroy();
#endif

namespace relay {
    namespace {
        using Profile = vless::detail::ClientProfile;
        using Mode = tls::detail::TransportMode;
        auto domain_request(Profile const& profile, std::string_view domain, std::uint16_t port) -> vless::TcpRequest {
            return {.user = profile.user, .kind = vless::AddressKind::domain, .port = port,
                .address = {domain.begin(), domain.end()}};
        }
        auto fixed_request(Profile const& profile, net::ProxyAddress const& peer) -> std::optional<vless::TcpRequest> {
            if (!profile.fixed_udp || !net::valid_proxy_address(peer) || !peer.port ||
                peer.family == net::ProxyAddressFamily::domain) return {};
            auto kind = peer.family == net::ProxyAddressFamily::ipv4 ? vless::AddressKind::ipv4 : vless::AddressKind::ipv6;
            return vless::TcpRequest{.user = profile.user, .kind = kind, .port = peer.port,
                .address = {peer.bytes.begin(), peer.bytes.begin() + peer.length}, .command = vless::TargetCommand::udp};
        }
        auto packet_format(Profile const& profile) noexcept -> net::PacketTransport {
            if (profile.fixed_udp) return {net::PacketTransportKind::framed, {.connected = true}};
            if (profile.packetaddr) return {net::PacketTransportKind::framed, {net::AddressWire::packetaddr}};
            return {net::PacketTransportKind::xudp};
        }
        auto parse_static_endpoint(std::string_view host, std::uint16_t port) noexcept -> std::optional<io::endpoint> {
            auto parsed = platform::parse_ip_address(host);
            if (!parsed) return std::nullopt;
            if (parsed->size == 4) {
                io::ipv4_address::bytes_type b{};
                std::copy_n(parsed->bytes.begin(), 4, b.begin());
                return io::endpoint(io::ipv4_address(b), port);
            }
            if (parsed->size == 16) {
                io::ipv6_address::bytes_type b{};
                std::copy_n(parsed->bytes.begin(), 16, b.begin());
                return io::endpoint(io::ipv6_address(b), port);
            }
            return std::nullopt;
        }
        struct OwnedProfile {
            Profile value;
            std::optional<std::size_t> bootstrap; std::uint32_t timeout_ms;
            TcpSocketOptions tcp_options;
            std::optional<io::endpoint> static_endpoint;
            OwnedProfile(Profile&& profile, std::optional<std::size_t> bootstrap_, std::uint32_t timeout, TcpSocketOptions options = {})
                : value(std::move(profile)), bootstrap(bootstrap_), timeout_ms(timeout), tcp_options(options),
                  static_endpoint(bootstrap_ ? std::nullopt : parse_static_endpoint(value.host, value.port)) {
#ifdef NEXUS_TEST_TUNNEL_PROFILE
                nexus_test_tunnel_profile_created();
#endif
            }
#ifdef NEXUS_TEST_TUNNEL_PROFILE
            ~OwnedProfile() { nexus_test_tunnel_profile_released(); }
#endif
        };
        struct LowerStream {
            pro::proxy<TunnelFacade>& lower;
            auto read(std::span<std::uint8_t> bytes) { return lower->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return lower->send(bytes); }
            auto close_output() { return lower->close_output(); }
            auto cancel() noexcept -> void { if (lower) lower->cancel(); }
        };

        class VlessTunnel {
            using Socket = net::UnifiedStreamSocket;
            using Client = vless::detail::TcpClient<Socket>;
            using Relay = vless::detail::DuplexRelay<io::tcp_socket, Socket>;
            using VisionClient = vless::detail::VisionClient<Socket>;
            using VisionRelay = vless::detail::VisionRelay<io::tcp_socket, Socket>;

            Session& session_;
            io::io_context& context_;
            Profile const& profile_;
            Mode mode_;
            DnsSlot local_dns_;
            std::optional<std::size_t> bootstrap_;
            std::optional<io::endpoint> static_endpoint_;
            std::uint32_t timeout_ms_;
            bool relay_local_, starting_ = false;
            TcpSocketOptions tcp_options_{};
            LowerConnector lower_{};
            LowerStream lower_stream_{lower_.tunnel};
            std::optional<io::tcp_socket> tcp_;
            std::unique_ptr<net::FastOpenStream> fast_;
            Socket socket_;
            std::unique_ptr<tls::detail::ClientConnection<Socket>> owner_;
            std::unique_ptr<Client> client_;
            std::unique_ptr<Relay> relay_;
            std::unique_ptr<VisionClient> vision_client_;
            std::unique_ptr<VisionRelay> vision_relay_;
            std::stop_source stop_;

            auto make_handshake(Clock::time_point deadline) -> std::expected<tls::ClientHandshakeIo, TunnelConnectResult> {
                auto deadline_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count();
                auto now = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
                auto seconds = platform::calibrated_wall_seconds();
                if (now < 0 || seconds < 0) return std::unexpected(TunnelConnectResult::failed);
                if (deadline_ms <= now) return std::unexpected(TunnelConnectResult::timeout);
                auto hs = profile_.handshake(static_cast<std::uint64_t>(now), static_cast<std::uint64_t>(deadline_ms), seconds);
                if (!hs) return std::unexpected(mode_ == Mode::layered ? TunnelConnectResult::failed : TunnelConnectResult::retryable);
                return std::move(*hs);
            }
            auto reset_attempt() noexcept -> void {
                client_.reset(); owner_.reset(); socket_.reset(); tcp_.reset(); fast_.reset();
            }
            auto connect_tls(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (mode_ == Mode::layered) {
                    if (!lower_.tunnel && !lower_.factory) co_return TunnelConnectResult::failed;
                    socket_.bind(lower_stream_);
                    LowerConnector::Candidates candidates;
                    for (;;) {
                        if (lower_.factory) {
                            auto connected = co_await lower_.connect(session_, deadline, candidates);
                            if (connected != TunnelConnectResult::connected) co_return connected;
                        }
                        auto hs = make_handshake(deadline);
                        if (!hs) co_return hs.error();
                        owner_ = std::make_unique<tls::detail::ClientConnection<Socket>>(socket_, std::move(*hs));
                        auto connected = co_await owner_->start();
                        if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                        if (connected && profile_.accepts_alpn(owner_->negotiated())) {
                            if (!profile_.transport) co_return TunnelConnectResult::connected;
                            client_ = std::make_unique<Client>(*owner_->application());
                            auto upgraded = co_await client_->upgrade(*profile_.transport, deadline);
                            if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                            if (upgraded) co_return TunnelConnectResult::connected;
                        }
                        auto timed_out = Clock::now() >= deadline || (!connected && connected.error() == tls::detail::AsyncHandshakeError::timeout);
                        client_.reset(); owner_.reset();
                        if (timed_out) co_return TunnelConnectResult::timeout;
                        if (!lower_.retry()) co_return TunnelConnectResult::failed;
                    }
                }
                std::optional<std::vector<io::endpoint>> resolved;
                std::span<io::endpoint const> candidates;
                std::array<io::endpoint, 1> static_arr{};
                if (static_endpoint_ && !bootstrap_) {
                    if (mode_ == Mode::fast_open) {
                        resolved.emplace(1, *static_endpoint_);
                        candidates = *resolved;
                    } else {
                        static_arr[0] = *static_endpoint_;
                        candidates = static_arr;
                    }
                } else {
                    resolved = bootstrap_
                        ? co_await resolve_bootstrap_owned(session_, context_, local_dns_, *bootstrap_, profile_.host, profile_.port, deadline)
                        : co_await resolve_local_owned(session_, context_, local_dns_, profile_.host, profile_.port, deadline);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!resolved || resolved->empty() || resolved->size() > 64)
                        co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
                    candidates = *resolved;
                }
                if (mode_ == Mode::fast_open) {
                    auto hs = make_handshake(deadline);
                    if (!hs) co_return TunnelConnectResult::failed;
                    fast_ = std::make_unique<net::FastOpenStream>(context_, std::move(*resolved), deadline, tcp_options_);
                    socket_.bind(*fast_);
                    owner_ = std::make_unique<tls::detail::ClientConnection<Socket>>(socket_, std::move(*hs));
                    auto connected = co_await owner_->start();
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!connected || !profile_.accepts_alpn(owner_->negotiated()))
                        co_return (!connected && connected.error() == tls::detail::AsyncHandshakeError::timeout) || Clock::now() >= deadline
                            ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    co_return TunnelConnectResult::connected;
                }
                for (auto const& endpoint : candidates) {
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!valid_destination(endpoint)) continue;
                    auto hs = make_handshake(deadline);
                    if (!hs) co_return hs.error();
                    tcp_.emplace(context_);
                    bool prep_failed = false; std::error_code error;
                    if (tcp_options_.binding.network) {
                        auto cand = net::connect_tcp_candidates(*tcp_, std::array{endpoint},
                            [](auto const&, auto const&) { return true; }, tcp_options_, prep_failed, deadline);
                        auto [res, sel] = co_await corosio::timeout(std::move(cand), deadline);
                        (void)sel; error = res;
                    } else {
                        if (tcp_options_.configured() && net::prepare_tcp_socket(*tcp_, endpoint, tcp_options_, deadline)) {
                            tcp_.reset(); co_return TunnelConnectResult::failed;
                        }
                        auto [res] = co_await corosio::timeout(tcp_->connect(endpoint), deadline);
                        error = res;
                    }
                    if (stop_.stop_requested() || session_.closed) { reset_attempt(); co_return TunnelConnectResult::failed; }
                    if (error || Clock::now() >= deadline) {
                        bool timed_out = capy::is_timeout(error) || Clock::now() >= deadline;
                        reset_attempt();
                        if (prep_failed) co_return TunnelConnectResult::failed;
                        if (timed_out) co_return TunnelConnectResult::timeout;
                        continue;
                    }
                    platform::tune_tcp_low_latency(tcp_->native_handle());
                    socket_.bind(*tcp_);
                    owner_ = std::make_unique<tls::detail::ClientConnection<Socket>>(socket_, std::move(*hs));
                    auto connected = co_await owner_->start();
                    if (stop_.stop_requested() || session_.closed) { reset_attempt(); co_return TunnelConnectResult::failed; }
                    if (!connected) {
                        bool timed_out = connected.error() == tls::detail::AsyncHandshakeError::timeout;
                        reset_attempt();
                        if (timed_out) co_return TunnelConnectResult::timeout;
                        continue;
                    }
                    if (!profile_.accepts_alpn(owner_->negotiated())) { reset_attempt(); continue; }
                    if (profile_.transport) {
                        client_ = std::make_unique<Client>(*owner_->application());
                        auto upgraded = co_await client_->upgrade(*profile_.transport, deadline);
                        if (stop_.stop_requested() || session_.closed) { reset_attempt(); co_return TunnelConnectResult::failed; }
                        if (!upgraded) {
                            bool timed_out = Clock::now() >= deadline;
                            reset_attempt();
                            if (timed_out) co_return TunnelConnectResult::timeout;
                            continue;
                        }
                    }
                    co_return TunnelConnectResult::connected;
                }
                co_return TunnelConnectResult::retryable;
            }
            auto start(io::endpoint destination, bool mux, Clock::time_point deadline,
                       std::optional<vless::TcpRequest> fixed = {}) -> coro::quitter<TunnelConnectResult> {
                if (starting_ || relay_ || vision_relay_ || stop_.stop_requested() || session_.closed)
                    co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                starting_ = true;
                struct Guard { VlessTunnel& owner; bool done = false; ~Guard() { owner.starting_ = false; if (!done && owner.mode_ != Mode::physical) owner.cancel(); } } guard{*this};
                auto ready = co_await connect_tls(deadline);
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (ready != TunnelConnectResult::connected) co_return ready;
                auto* connection = owner_->application();
                if (!connection) co_return TunnelConnectResult::failed;
#ifdef NEXUS_ENABLE_KTLS
                if (!profile_.vision && !profile_.transport && mode_ != Mode::layered)
                    (void)connection->try_enable_ktls();
#endif
                vless::TcpRequest request; request.user = profile_.user;
                if (!mux && !fixed) {
                    request.port = destination.port(); auto address = destination.address();
                    if (address.is_v4()) { request.kind = vless::AddressKind::ipv4; auto bytes = address.to_v4().to_bytes(); request.address.assign(bytes.begin(), bytes.end()); }
                    else { request.kind = vless::AddressKind::ipv6; auto bytes = address.to_v6().to_bytes(); request.address.assign(bytes.begin(), bytes.end()); }
                }
                if (profile_.vision) {
                    vision_client_ = std::make_unique<VisionClient>(socket_, *connection, profile_.user);
                    vision_relay_ = std::make_unique<VisionRelay>(session_.client, *vision_client_, [this] { session_.touched = Clock::now(); }, relay_local_ && !mux);
                    auto started = mux ? co_await vision_client_->start_mux(deadline) : co_await vision_client_->start(fixed ? *fixed : request, deadline);
                    if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                    if (!started) co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    guard.done = true; co_return TunnelConnectResult::connected;
                }
                if (!client_) {
                    client_ = std::make_unique<Client>(*connection);
                    if (profile_.transport) {
                        auto upgraded = co_await client_->upgrade(*profile_.transport, deadline);
                        if (!upgraded || stop_.stop_requested() || session_.closed)
                            co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    }
                }
#ifdef NEXUS_TEST_VLESS_PARTIAL_REQUEST
                std::expected<void, vless::detail::ClientError> sent;
                if (fixed) sent = co_await client_->start(*fixed, deadline);
                else if (mux) sent = co_await client_->start_datagrams(profile_.user, profile_.packetaddr, deadline);
                else if (std::getenv("NEXUS_TEST_VLESS_PARTIAL_REQUEST")) {
                    auto header = vless::encode_tcp_request(fixed ? *fixed : request);
                    if (!header || !co_await connection->send_all(std::span{*header}.first(8), deadline)) co_return TunnelConnectResult::failed;
                    sent = std::unexpected(vless::detail::ClientError::tls);
                } else sent = co_await client_->start(request, deadline);
#else
                auto sent = mux && !fixed ? co_await client_->start_datagrams(profile_.user, profile_.packetaddr, deadline)
                                          : co_await client_->start(fixed ? *fixed : request, deadline);
#endif
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (!sent) co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                relay_ = std::make_unique<Relay>(session_.client, *connection, *client_, [this] { session_.touched = Clock::now(); }, relay_local_ && !mux);
                guard.done = true; co_return TunnelConnectResult::connected;
            }

        public:
            VlessTunnel(Session& session, io::io_context& context, Profile const& profile,
                        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, bool relay_local,
                        TcpSocketOptions const& options, bool fast_open, std::optional<io::endpoint> static_endpoint = {})
                : session_(session), context_(context), profile_(profile),
                  mode_(fast_open ? Mode::fast_open : Mode::physical),
                  bootstrap_(bootstrap), static_endpoint_(static_endpoint), timeout_ms_(timeout_ms), relay_local_(relay_local), tcp_options_(options) {}
            VlessTunnel(Session& session, pro::proxy<TunnelFacade>&& lower, Profile const& profile, std::uint32_t timeout_ms)
                : session_(session), context_(static_cast<io::io_context&>(session.client.context())), profile_(profile), mode_(Mode::layered),
                  timeout_ms_(timeout_ms), relay_local_(true), lower_{std::move(lower)} {}
            VlessTunnel(Session& session, io::io_context& context, TunnelFactory const& detour, Profile const& profile,
                        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, bool relay_local)
                : session_(session), context_(context), profile_(profile), mode_(Mode::layered),
                  bootstrap_(bootstrap), timeout_ms_(timeout_ms), relay_local_(relay_local),
                  lower_{{}, &context, &detour, profile.host, profile.port, bootstrap} {}
#ifdef NEXUS_TEST_TUNNEL_PROFILE
            ~VlessTunnel() { nexus_test_tunnel_profile_destroy(); }
#endif
            auto cancel() noexcept -> void {
                stop_.request_stop(); local_dns_.cancel();
                if (relay_) relay_->cancel();
                if (vision_relay_) vision_relay_->cancel();
                if (client_) client_->cancel();
                if (owner_) owner_->cancel();
                if (tcp_) tcp_->cancel();
                if (fast_) fast_->cancel();
                lower_.cancel();
            }
            auto connect(io::endpoint destination) -> capy::task<TunnelConnectResult> {
                return connect_until(destination, session_.started + std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_until(io::endpoint destination, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(start(destination, false, deadline));
            }
            auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(start({}, false, deadline, domain_request(profile_, domain, port)));
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return !profile_.packetaddr && !profile_.fixed_udp; }
            auto packet_transport() const noexcept -> net::PacketTransport { return packet_format(profile_); }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (profile_.fixed_udp) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(start({}, true, deadline));
            }
            auto connect_packets(net::ProxyAddress const& peer, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.fixed_udp) co_return co_await connect_packets(deadline);
                auto request = fixed_request(profile_, peer);
                if (!request) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(start({}, true, deadline, std::move(request)));
            }
            auto connect_xudp() -> capy::task<TunnelConnectResult> {
                return connect_xudp_until(Clock::now() + std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_xudp_until(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return has_xudp() ? co_await connect_packets(deadline) : TunnelConnectResult::failed;
            }
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if ((!relay_ && !vision_relay_) || stop_.stop_requested()) co_return false;
                if (bytes.empty()) co_return true;
                if (vision_relay_) co_return co_await vision_relay_->write(bytes);
                co_return co_await relay_->write(bytes);
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if ((!relay_ && !vision_relay_) || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
                auto result = vision_relay_ ? co_await vision_relay_->read(bytes) : co_await relay_->read(bytes);
                if (!result) co_return std::unexpected("tunnel read failed");
                co_return *result;
            }
            auto close_output() -> capy::task<bool> {
                if (vision_relay_) co_return co_await vision_relay_->close_output();
                if (!relay_) co_return false;
                co_return co_await relay_->close_output();
            }
            auto upload() -> capy::task<bool> {
                if (vision_relay_) co_return co_await vision_relay_->upload({}, session_.traffic_delivery());
                if (!relay_) co_return false;
                co_return co_await relay_->upload({}, session_.traffic_delivery());
            }
            auto download() -> capy::task<bool> {
                if (vision_relay_) co_return co_await vision_relay_->download({}, session_.traffic_delivery());
                if (!relay_) co_return false;
                co_return co_await relay_->download({}, session_.traffic_delivery());
            }
        };
    }

    auto make_vless_layer_factory(std::string_view uuid_file,
                          std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange,
                          std::optional<Reality> reality, bool vision, std::uint32_t timeout_ms, std::optional<HttpUpgradeTransport> transport, std::optional<GrpcTransport> grpc, TlsFingerprint fingerprint, std::optional<std::uint16_t> record_size_limit)
        -> std::expected<TunnelLayerFactory, std::string> {
        if (grpc) return std::unexpected("gRPC preconnected layer requires a retained connection worker");
        if (!timeout_ms || timeout_ms > 3600000) return std::unexpected("invalid VLESS timeout");
        if (key_exchange != TlsKeyExchange::x25519 && key_exchange != TlsKeyExchange::x25519_mlkem768 && key_exchange != TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto group = key_exchange == TlsKeyExchange::x25519 ? config::TlsKeyExchange::x25519 :
            key_exchange == TlsKeyExchange::x25519_mlkem768 ? config::TlsKeyExchange::x25519_mlkem768 : config::TlsKeyExchange::x25519_mlkem768_only;
        config::VlessOutbound config{"layer", 1, std::string(uuid_file), std::string(server_name), std::string(ca_file), {}, group};
        config.vision = vision; config.transport = std::move(transport); config.fingerprint = fingerprint; config.record_size_limit = record_size_limit;
        if (reality) config.reality = config::VlessOutbound::Reality{reality->public_key, reality->short_id};
        auto profile = Profile::load(config); if (!profile) return std::unexpected(profile.error());
        auto shared = std::make_unique<OwnedProfile>(std::move(*profile), std::nullopt, timeout_ms);
        return TunnelLayerFactory{[profile = std::move(shared)](Session& session, pro::proxy<TunnelFacade>&& lower) {
            if (!lower) return pro::proxy<TunnelFacade>{};
            return pro::make_proxy<TunnelFacade, VlessTunnel>(session, std::move(lower), profile->value, profile->timeout_ms);
        }};
    }

    auto make_vless_factory(std::string_view host, std::uint16_t port, std::string_view uuid_file,
                            std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap, std::optional<Reality> reality, bool vision, std::uint32_t timeout_ms, TcpSocketOptions tcp_options, std::optional<HttpUpgradeTransport> transport, std::optional<GrpcTransport> grpc, bool fast_open, TlsFingerprint fingerprint, std::optional<std::uint16_t> record_size_limit, bool packetaddr, bool fixed_udp, std::span<std::array<std::uint8_t, 32> const> pins)
        -> std::expected<TunnelFactory, std::string> {
        if (packetaddr && fixed_udp) return std::unexpected("conflicting VLESS packet encodings");
        if ((packetaddr || fixed_udp) && (vision || grpc))
            return std::unexpected("VLESS packetaddr and fixed UDP require non-Vision TCP or HTTPUpgrade");
        if (grpc) {
            if (transport || vision || reality) return std::unexpected("gRPC requires ordinary VLESS TLS and one transport");
            if (fast_open) grpc->tcp_fast_open = true;
#ifdef NEXUS_ENABLE_GRPC_VLESS
            return make_vless_grpc_factory(host, port, uuid_file, server_name, ca_file, key_exchange, bootstrap, timeout_ms, tcp_options, std::move(*grpc), fingerprint, record_size_limit, pins);
#else
            return std::unexpected("gRPC VLESS transport is not available in this build");
#endif
        }
        if (!timeout_ms || timeout_ms > 3600000) return std::unexpected("invalid connect timeout");
        if (!tcp_options.valid()) return std::unexpected("invalid TCP socket options");
        if (key_exchange != TlsKeyExchange::x25519 && key_exchange != TlsKeyExchange::x25519_mlkem768 && key_exchange != TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto group = key_exchange == TlsKeyExchange::x25519 ? config::TlsKeyExchange::x25519 :
            key_exchange == TlsKeyExchange::x25519_mlkem768 ? config::TlsKeyExchange::x25519_mlkem768 : config::TlsKeyExchange::x25519_mlkem768_only;
        config::VlessOutbound config{std::string(host), port, std::string(uuid_file), std::string(server_name), std::string(ca_file), {pins.begin(), pins.end()}, group};
        config.vision = vision; config.transport = std::move(transport); config.fingerprint = fingerprint; config.record_size_limit = record_size_limit;
        if (reality) config.reality = config::VlessOutbound::Reality{reality->public_key, reality->short_id};
        config.packetaddr = packetaddr; config.fixed_udp = fixed_udp;
        auto profile = Profile::load(config);
        if (!profile) return std::unexpected(profile.error());
        auto shared = std::make_unique<OwnedProfile>(std::move(*profile), bootstrap, timeout_ms, tcp_options);
        auto* layer_profile = shared.get();
        auto factory = TunnelFactory{[profile = std::move(shared), fast_open](Session& session, io::io_context& context, bool relay_local, TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
            if (profile->timeout_ms > 10000)
                session.handshake_deadline = std::max(session.handshake_deadline, session.started + std::chrono::milliseconds(profile->timeout_ms) + std::chrono::seconds(1));
            bool tfo = inherited ? inherited->tcp_fast_open.value_or(false) : fast_open;
            return pro::make_proxy<TunnelFacade, VlessTunnel>(session, context, profile->value, profile->bootstrap,
                profile->timeout_ms, relay_local, inherited ? *inherited : profile->tcp_options, tfo, profile->static_endpoint);
        }, timeout_ms, [layer_profile](Session& session, io::io_context& context, TunnelFactory const& detour, bool relay_local) {
            return pro::make_proxy<TunnelFacade, VlessTunnel>(session, context, detour, layer_profile->value,
                layer_profile->bootstrap, layer_profile->timeout_ms, relay_local);
        }, std::nullopt, tcp_options.configured() || fast_open};
        factory.packet_dual_family = packetaddr;
        factory.packet_fixed_peer = fixed_udp;
        return factory;
    }
}
