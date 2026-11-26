module relay;
import std;
import proxy.v4;
import config;
import tls.fingerprint;
import grpc.headers;
import grpc.session;
import grpc.connection;
import net.connection_pool;
import net.operation_token;
import net.stream_relay;
import tls.connector;
import tls.profiles;
import tls.byte_stream;
import vless;
import vless.corosio_client;
import rulefile;
import crypto;
import platform.ip_address;
import capy;
import corosio;
import :grpc_pool;
import :quic_ech;

namespace relay {
    namespace grpc_vless {
        using Mode = grpc_pool::Mode;
        using Worker = grpc_pool::PoolWorker;

        struct Profile {
            std::string host; std::uint16_t port; vless::UserId user;
            tls::ShapedClientProfile tls; grpc::RequestProfile request; grpc::ResponsePolicy response;
            grpc::Limits limits; std::size_t max_sessions;
            std::optional<std::size_t> bootstrap; std::uint32_t timeout; TcpSocketOptions options; bool fast_open;
            quic_ech::Profile ech;
            std::mutex mutex;
            std::vector<std::unique_ptr<Worker>> physical;
            std::vector<std::unique_ptr<Worker>> layered;
            std::vector<std::unique_ptr<Worker>> fast;
            ~Profile();
        };
        Profile::~Profile() = default;

        auto endpoint_spec(Profile const& p) noexcept -> grpc_pool::EndpointSpec {
            return {p.host, p.port, p.bootstrap, p.tls, p.request, p.response, p.limits, p.max_sessions, &p.ech};
        }

        auto initialize(Profile& profile, Mode mode, OutboundContext const& environment,
                        TunnelFactory const* detour, bool direct) -> bool {
            std::lock_guard lock(profile.mutex);
            if (grpc_pool::find(profile, mode, environment.context) || (direct && !environment.direct_options)) return false;
            auto& entries = grpc_pool::slots(profile, mode);
            auto slot = std::ranges::find_if(entries, [](auto const& value) { return !value; });
            bool append = slot == entries.end();
            if (append) entries.reserve(entries.size() + 1);
            auto worker = std::make_unique<Worker>(environment, endpoint_spec(profile), detour,
                                                 direct ? *environment.direct_options : profile.options, mode);
            worker->start_reaper();
            if (!append) *slot = std::move(worker); else entries.push_back(std::move(worker));
            return true;
        }

        class Tunnel {
            using State = grpc_pool::Connection;
            using Protocol = typename State::Protocol;
            using Rpc = typename Protocol::Stream;
            using Socket = grpc_pool::Node::Socket;
            using Client = vless::detail::TcpClient<Socket, false, Rpc&>;
            using Relay = vless::detail::DuplexRelay<corosio::tcp_socket, Socket, Rpc&>;
            Session& session_; Worker& worker_; Profile const& profile_; bool relay_local_, ready_ = false;
            std::stop_source stop_;
            std::optional<typename Worker::Pool::Lease> lease_;
            std::optional<Rpc> rpc_;
            std::optional<Client> client_;
            std::optional<Relay> relay_;

            auto start(corosio::endpoint destination, bool mux, Clock::time_point deadline,
                       std::string_view domain = {}) -> capy::task<TunnelConnectResult> {
                if (ready_ || lease_ || stop_.stop_requested() || session_.closed || worker_.stopped)
                    co_return TunnelConnectResult::failed;
                struct Guard { Tunnel& owner; bool done = false; ~Guard() { if (!done) owner.cancel(); } } guard{*this};
                auto acquired = co_await worker_.acquire(stop_, deadline);
                if (!acquired || session_.closed || stop_.stop_requested())
                    co_return !acquired ? acquired.error()
                        : (Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
                lease_.emplace(std::move(*acquired));
                auto& channel = *lease_->connection().protocol();
                auto opened = channel.open();
                if (!opened) co_return TunnelConnectResult::failed;
                rpc_.emplace(channel, *opened);
                client_.emplace(*rpc_);
                relay_.emplace(session_.client, *client_, [this] { session_.touched = Clock::now(); }, relay_local_ && !mux);
                vless::TcpRequest request; request.user = profile_.user;
                if (!mux) {
                    request.port = destination.port(); auto address = destination.address();
                    if (!domain.empty()) { request.kind = vless::AddressKind::domain; request.address.assign(domain.begin(), domain.end()); }
                    else if (address.is_v4()) { request.kind = vless::AddressKind::ipv4; auto bytes = address.to_v4().to_bytes(); request.address.assign(bytes.begin(), bytes.end()); }
                    else { request.kind = vless::AddressKind::ipv6; auto bytes = address.to_v6().to_bytes(); request.address.assign(bytes.begin(), bytes.end()); }
                }
                auto sent = mux ? co_await client_->start_mux(request.user, false, deadline) : co_await client_->start(request, deadline);
                if (!sent || stop_.stop_requested() || session_.closed)
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                ready_ = true; guard.done = true; co_return TunnelConnectResult::connected;
            }
            auto normal() const noexcept -> bool { return rpc_ && rpc_->complete() && !rpc_->failure(); }
        public:
            Tunnel(Session& session, Worker& worker, Profile const& profile, bool local)
                : session_(session), worker_(worker), profile_(profile), relay_local_(local) {}
            auto cancel() noexcept -> void {
                if (normal()) return;
                stop_.request_stop(); if (rpc_) rpc_->cancel(); if (relay_) relay_->cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }
            auto connect(corosio::endpoint endpoint) -> capy::task<TunnelConnectResult> { return connect_until(endpoint, session_.started + std::chrono::milliseconds(profile_.timeout)); }
            auto connect_until(corosio::endpoint endpoint, Clock::time_point deadline) -> capy::task<TunnelConnectResult> { return start(endpoint, false, deadline); }
            auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                return start(corosio::endpoint(corosio::ipv4_address{}, port), false, deadline, domain);
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return true; }
            auto packet_transport() const noexcept -> net::PacketTransport { return {net::PacketTransportKind::xudp}; }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> { return start({}, true, deadline); }
            auto connect_xudp_until(Clock::time_point deadline) -> capy::task<TunnelConnectResult> { return start({}, true, deadline); }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { return start({}, true, Clock::now() + std::chrono::milliseconds(profile_.timeout)); }
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await relay_->write(bytes);
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if (!ready_ || stop_.stop_requested()) co_return std::unexpected("gRPC VLESS stream closed");
                auto result = co_await relay_->read(bytes);
                if (!result) co_return std::unexpected("gRPC VLESS stream read failed");
                co_return *result;
            }
            auto close_output() -> capy::task<bool> { co_return ready_ && co_await relay_->close_output(); }
            auto upload() -> capy::task<bool> { co_return ready_ && co_await relay_->upload({}, session_.traffic_delivery()); }
            auto download() -> capy::task<bool> { co_return ready_ && co_await relay_->download({}, session_.traffic_delivery()); }
        };
    }

    auto make_vless_grpc_factory(std::string_view host, std::uint16_t port, std::string_view uuid, std::string_view server_name, std::string_view ca,
        TlsKeyExchange exchange, std::optional<std::size_t> bootstrap, std::uint32_t timeout, TcpSocketOptions options, GrpcTransport transport, TlsFingerprint fingerprint, std::optional<std::uint16_t> record_size_limit, std::span<std::array<std::uint8_t, 32> const> pins, QuicEchOptions const& ech, bool dns_available)
        -> std::expected<TunnelFactory, std::string> {
        namespace v = grpc_vless;
        if (host.empty() || host.size() > 253 || !port || std::ranges::any_of(host, [](unsigned char c) { return c < 33 || c > 126; }) ||
            !timeout || timeout > 3600000 || !options.valid() || !transport.max_sessions || transport.max_sessions > 256)
            return std::unexpected("invalid gRPC VLESS options");
        if ((ech.dns || !ech.config_file.empty()) && fingerprint == TlsFingerprint::tls12)
            return std::unexpected("VLESS ECH requires TLS 1.3");
        auto ech_profile = quic_ech::Profile::load(ech, server_name, dns_available);
        if (!ech_profile) return std::unexpected(ech_profile.error());
        if (exchange != TlsKeyExchange::x25519 && exchange != TlsKeyExchange::x25519_mlkem768 && exchange != TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto secret = rulefile::read_password_file(uuid); if (!secret) return std::unexpected("UUID file: " + secret.error());
        auto user = vless::parse_user_id(*secret); std::fill(secret->begin(), secret->end(), '\0'); if (!user) return std::unexpected("invalid UUID");
        constexpr std::array<std::string_view, 1> alpn{"h2"};
        auto tls = tls::ClientProfile::load(server_name, ca, exchange == TlsKeyExchange::x25519 ? 0x001d : 0x11ec, exchange == TlsKeyExchange::x25519_mlkem768_only, alpn);
        if (!tls) return std::unexpected(tls.error());
        tls->certificate_pins.assign(pins.begin(), pins.end());
        auto shape = tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!shape) return std::unexpected("invalid TLS fingerprint configuration");
        auto shaped = tls::ShapedClientProfile::create(std::move(*tls), *shape, record_size_limit);
        if (!shaped) return std::unexpected(shaped.error());
        std::string default_authority(server_name);
        if (transport.authority.empty()) if (auto ip = platform::parse_ip_address(default_authority); ip && ip->size == 16)
            default_authority = "[" + default_authority + "]";
        auto request = grpc::RequestProfile::create(transport.service_name, transport.authority.empty() ? default_authority : transport.authority, true);
        auto response = transport.response_policy == GrpcTransport::ResponsePolicy::standard ? grpc::ResponsePolicy::standard : grpc::ResponsePolicy::sing_box_lite;
        grpc::Limits limits{transport.input_window, transport.message_bytes, transport.hunk_bytes, transport.output_bytes, transport.output_messages, transport.library_bytes, transport.idle_timeout_ms, transport.ping_timeout_ms, transport.permit_without_stream};
        if (!request || !grpc::Session::create(grpc::Role::client, *request, response, limits))
            return std::unexpected("invalid gRPC TLS/request/limits");
        auto profile = std::make_unique<v::Profile>(std::string(host), port, *user, std::move(*shaped), std::move(*request), response, limits, transport.max_sessions, bootstrap, timeout, options, transport.tcp_fast_open, std::move(*ech_profile));
        auto* borrowed = profile.get();
        TunnelFactory factory{[profile = std::move(profile)](Session& session, corosio::io_context& context, bool local, TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
            v::Worker* fast = nullptr; { std::lock_guard lock(profile->mutex); fast = grpc_pool::find(*profile, v::Mode::fast_open, context); }
            if (fast) return pro::make_proxy<TunnelFacade, v::Tunnel>(session, *fast, *profile, local);
            v::Worker* worker = nullptr; { std::lock_guard lock(profile->mutex); worker = grpc_pool::find(*profile, v::Mode::physical, context); }
            return worker ? pro::make_proxy<TunnelFacade, v::Tunnel>(session, *worker, *profile, local) : pro::proxy<TunnelFacade>{};
        }, timeout, [borrowed](Session& session, corosio::io_context& context, TunnelFactory const&, bool local) -> pro::proxy<TunnelFacade> {
            v::Worker* worker = nullptr; { std::lock_guard lock(borrowed->mutex); worker = grpc_pool::find(*borrowed, v::Mode::layered, context); }
            return worker ? pro::make_proxy<TunnelFacade, v::Tunnel>(session, *worker, *borrowed, local) : pro::proxy<TunnelFacade>{};
        }, std::nullopt, options.configured() || transport.tcp_fast_open};
        factory.start_context = [borrowed](OutboundContext const& environment, TunnelFactory const* detour, bool direct) {
            auto fast = direct && environment.direct_options ? environment.direct_options->tcp_fast_open.value_or(false) : borrowed->fast_open;
            return detour ? v::initialize(*borrowed, v::Mode::layered, environment, detour, direct)
                : v::initialize(*borrowed, fast ? v::Mode::fast_open : v::Mode::physical, environment, nullptr, direct);
        };
        factory.stop_context = [borrowed](corosio::io_context& context) noexcept { grpc_pool::stop(*borrowed, context); };
        factory.reap_context = [borrowed](corosio::io_context& context) noexcept { grpc_pool::reap(*borrowed, context); };
        factory.quiesced_context = [borrowed](corosio::io_context& context) noexcept { return grpc_pool::drained(*borrowed, context); };
        factory.finish_context = [borrowed](corosio::io_context& context) noexcept { grpc_pool::finish(*borrowed, context); };
        return factory;
    }
}
