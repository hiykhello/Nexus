module relay;
import std;
import proxy.v4;
import anytls;
import anytls.auth;
import anytls.client;
import anytls.connection;
import anytls.padding;
import anytls.pool;
import anytls.session;
import anytls.writer;
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
import net.datagram_frame;
import net.stream_relay;
import tls.byte_stream;
import tls.connector;
import tls.profiles;
import tls.fingerprint;
import quic.ech_config;
import uot;
import net.connection_pool;
import net.operation_token;
import capy;
import corosio;
import :transport_helpers;
import :grpc_pool;
import :quic_ech;
import :anytls_grpc;

namespace relay {
    namespace {
        namespace a=anytls;
        using Connected=tls::detail::ConnectResult;
        using Mode=tls::detail::TransportMode;
        struct Worker;
        struct Profile {
            std::string host;
            std::uint16_t port;
            a::PasswordKey key;
            tls::ShapedClientProfile tls;
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout;
            TcpSocketOptions options;
            a::PoolOptions pool;
            bool fast_open;
            std::optional<httpupgrade::Profile> transport;
            quic_ech::Profile ech;
            std::mutex mutex;
            std::vector<std::unique_ptr<Worker>> physical;
            std::vector<std::unique_ptr<Worker>> layered;
            std::vector<std::unique_ptr<Worker>> fast;
            ~Profile();
        };
        struct Resolver {
            Session& session; corosio::io_context& context; Profile const& profile; DnsSlot slot;
            auto operator()(Clock::time_point deadline) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
                if (profile.bootstrap) return resolve_bootstrap_owned(session,context,slot,*profile.bootstrap,profile.host,profile.port,deadline);
                return resolve_local_owned(session,context,slot,profile.host,profile.port,deadline);
            }
            auto cancel() noexcept -> void { slot.cancel(); }
        };
        struct Lower {
            using Candidates=LowerConnector::Candidates;
            Session& session;
            LowerConnector connector;
            Lower(Session& owner,OutboundContext const& environment,TunnelFactory const& factory,Profile const& profile)
                : session(owner),connector{{},&environment.context,&factory,profile.host,profile.port,profile.bootstrap} {}
            auto connect(Clock::time_point deadline,Candidates& candidates) -> capy::task<Connected> {
                switch (co_await connector.connect(session,deadline,candidates)) {
                case TunnelConnectResult::connected: co_return Connected::connected;
                case TunnelConnectResult::retryable: co_return Connected::retryable;
                case TunnelConnectResult::timeout: co_return Connected::timeout;
                default: co_return Connected::failed;
                }
            }
            auto retry() noexcept -> bool { return connector.retry(); }
            auto read(std::span<std::uint8_t> bytes) { return connector.tunnel->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return connector.tunnel->send(bytes); }
            auto close_output() { return connector.tunnel->close_output(); }
            auto cancel() noexcept -> void { connector.cancel(); }
        };
        using Connector=tls::detail::UnifiedConnector<Resolver,Lower,tls::ShapedClientProfile>;
        // Each cached TLS connection owns its complete lower proxy state.
        // No member borrows the business Session that happened to request it.
        class Node {
            corosio::io_context& context_;
            Profile const& profile_;
            DnsSlot ech_dns_;
            Session state_;
            std::optional<Connector> connector_;
            bool ktls_eligible_ = false;
        public:
            using Socket=typename Connector::Socket;
            Node(OutboundContext const& environment,Profile const& profile,TunnelFactory const* detour,TcpSocketOptions const& options,Mode mode)
                : context_(environment.context), profile_(profile), state_(environment.context), ktls_eligible_(!profile.transport && mode!=Mode::layered) {
                state_.dns=environment.dns; state_.local_dns=environment.local_dns;
                if (environment.owner) state_.route_snapshot=environment.owner->current_route_snapshot();
                state_.tunnel_factories=environment.factories; state_.direct_tcp_options=environment.direct_options;
                if (mode==Mode::layered) connector_.emplace(environment.context,profile.tls,std::in_place,state_,environment,*detour,profile);
                else connector_.emplace(mode,environment.context,Resolver{state_,environment.context,profile},profile.tls,options);
            }
            ~Node() { state_.close(); }
            auto start(Clock::time_point deadline) -> capy::task<Connected> {
                auto ech = co_await profile_.ech.resolve(state_, context_, ech_dns_, profile_.bootstrap, profile_.port, deadline, quic_ech::Transport::tcp);
                if (state_.closed) co_return Connected::failed;
                if (!ech) co_return Clock::now() >= deadline ? Connected::timeout : Connected::failed;
                auto connected = co_await connector_->start(deadline, *ech ? &**ech : nullptr);
#ifdef NEXUS_ENABLE_KTLS
                if (connected == Connected::connected && ktls_eligible_ && connector_->application())
                    (void)connector_->application()->try_enable_ktls();
#endif
                co_return connected;
            }
            auto application() noexcept { return connector_->application(); }
            auto cancel() noexcept -> void { ech_dns_.cancel(); connector_->cancel(); state_.close(); }
        };
        struct Factory {
            using Connection=a::PooledConnection<Node>;
            OutboundContext environment;
            Profile const& profile;
            TunnelFactory const* detour;
            TcpSocketOptions const& options;
            Mode mode;
            auto prewarm_allowed() const noexcept -> bool { return environment.prewarm_allowed(); }
            auto operator()(a::PaddingScheme& padding,capy::async_event* changed) -> std::unique_ptr<Connection> {
                auto conn=std::make_unique<Connection>(padding,changed,environment,profile,detour,options,mode);
                if (profile.transport) conn->set_transport(&*profile.transport);
                return conn;
            }
        };
        struct Worker {
            OutboundContext environment;
            TcpSocketOptions options;
            a::Client<Factory> client;
            Worker(OutboundContext const& env,Profile const& profile,TunnelFactory const* detour,TcpSocketOptions socket_options,Mode mode,a::PaddingScheme padding)
                : environment(env),options(socket_options),client(env.context,Factory{environment,profile,detour,options,mode},
                    profile.key.view(),std::move(padding),profile.pool,std::chrono::milliseconds(profile.timeout)) {}
        };
        Profile::~Profile()=default;
        auto slots(Profile& profile,Mode mode) noexcept -> auto& {
            if (mode==Mode::layered) return profile.layered;
            if (mode==Mode::fast_open) return profile.fast;
            return profile.physical;
        }
        auto find(Profile& profile,Mode mode,corosio::io_context& context) noexcept -> Worker* {
            for (auto const& worker:slots(profile,mode)) if (worker && &worker->environment.context==&context) return worker.get();
            return nullptr;
        }
        auto initialize(Profile& profile,Mode mode,OutboundContext const& environment,TunnelFactory const* detour,bool direct) -> bool {
            std::lock_guard lock(profile.mutex);
            if (find(profile,mode,environment.context)) return false;
            auto& entries=slots(profile,mode);
            auto slot=std::ranges::find_if(entries,[](auto const& worker) { return !worker; });
            auto padding=a::PaddingScheme::parse(a::default_padding_scheme);
            if (!padding || (direct && !environment.direct_options)) return false;
            bool append=slot==entries.end();
            if (append) entries.reserve(entries.size()+1);
            auto worker=std::make_unique<Worker>(environment,profile,detour,direct ? *environment.direct_options : profile.options,mode,std::move(*padding));
            worker->client.start();
            if (!append) *slot=std::move(worker); else entries.push_back(std::move(worker));
            return true;
        }
        auto stop(Profile& profile,corosio::io_context& context) noexcept -> void {
            for (auto mode : {Mode::physical,Mode::layered,Mode::fast_open}) {
                Worker* worker=nullptr;
                { std::lock_guard lock(profile.mutex); worker=find(profile,mode,context); }
                if (worker) worker->client.stop();
            }
        }
        auto drained(Profile& profile,corosio::io_context& context) noexcept -> bool {
            std::lock_guard lock(profile.mutex);
            for (auto mode : {Mode::physical,Mode::layered,Mode::fast_open})
                for (auto const& worker:slots(profile,mode))
                    if (worker && &worker->environment.context==&context && !worker->client.drained()) return false;
            return true;
        }
        auto finish(Profile& profile,corosio::io_context& context) noexcept -> void {
            std::lock_guard lock(profile.mutex);
            for (auto mode : {Mode::physical,Mode::layered,Mode::fast_open})
                for (auto& worker:slots(profile,mode)) if (worker && &worker->environment.context==&context) {
                    if (!worker->client.drained()) std::terminate();
                    worker.reset(); break;
                }
        }
        class Tunnel {
            using Client=a::Client<Factory>;
            using Connection=typename Factory::Connection;
            Session& session_;
            Client& client_;
            std::uint32_t timeout_;
            bool relay_local_,ready_=false;
            std::stop_source stop_;
            std::optional<typename Client::Lease> lease_;
            std::optional<typename Connection::Channel> channel_;
            auto start(a::Address address,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (ready_ || lease_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                struct Guard { Tunnel& owner; bool done=false; ~Guard() { if (!done) owner.cancel(); } } guard{*this};
                auto lease=co_await client_.acquire(deadline,stop_.get_token());
                if (!lease) co_return lease.error()==a::ClientError::timeout ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                lease_.emplace(std::move(*lease));
                auto* protocol=lease_->connection().protocol();
                auto id=co_await protocol->open(address,deadline);
                if (!id || stop_.stop_requested() || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                channel_.emplace(*protocol,*id); ready_=true; guard.done=true;
                co_return TunnelConnectResult::connected;
            }
        public:
            Tunnel(Session& session,Client& client,std::uint32_t timeout,bool relay_local)
                : session_(session),client_(client),timeout_(timeout),relay_local_(relay_local) {}
            auto cancel() noexcept -> void {
                stop_.request_stop();
                if (channel_) channel_->cancel();
                else if (lease_) lease_->connection().cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }
            auto connect(corosio::endpoint endpoint) -> capy::task<TunnelConnectResult> {
                return connect_until(endpoint,session_.started+std::chrono::milliseconds(timeout_));
            }
            auto connect_until(corosio::endpoint endpoint,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                a::Address address; address.port=endpoint.port();
                if (endpoint.address().is_v4()) {
                    address.family=net::ProxyAddressFamily::ipv4; address.length=4;
                    auto bytes=endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes,address.bytes.begin());
                } else {
                    address.family=net::ProxyAddressFamily::ipv6; address.length=16;
                    auto bytes=endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes,address.bytes.begin());
                }
                return start(address,deadline);
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                a::Address address{net::ProxyAddressFamily::domain,{},static_cast<std::uint8_t>(domain.size()),port};
                std::ranges::copy(domain,address.bytes.begin());
                return start(address,deadline);
            }
            auto packet_transport() const noexcept -> net::PacketTransport { return {net::PacketTransportKind::framed,{},true}; }
            auto has_uot() const noexcept -> bool { return true; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                a::Address address{net::ProxyAddressFamily::domain,{},static_cast<std::uint8_t>(uot::v2_destination.size()),443};
                std::ranges::copy(uot::v2_destination,address.bytes.begin());
                return start(address,deadline);
            }
            auto connect_uot_until(Clock::time_point deadline) { return connect_packets(deadline); }
            auto connect_uot() { return connect_packets(Clock::now()+std::chrono::milliseconds(timeout_)); }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                auto sent=co_await channel_->send(bytes);
                if (sent) session_.touched=Clock::now(); else cancel();
                co_return sent;
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if (!ready_ || stop_.stop_requested()) co_return std::unexpected("AnyTLS stream closed");
                auto read=co_await channel_->read(bytes);
                if (!read) { cancel(); co_return std::unexpected("AnyTLS stream read failed"); }
                if (*read) session_.touched=Clock::now();
                co_return *read;
            }
            auto close_output() -> capy::task<bool> { co_return ready_ && co_await channel_->close_output(); }
            auto upload() -> capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{session_.client,*channel_,[this] { session_.touched=Clock::now(); },relay_local_, session_.traffic_delivery()});
            }
            auto download() -> capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::download(net::ByteRelayAdapter{session_.client,*channel_,[this] { session_.touched=Clock::now(); },relay_local_, session_.traffic_delivery()});
            }
        };
    }
    auto make_anytls_factory(std::string_view host,std::uint16_t port,std::string_view password_file,std::string_view server_name,
        std::string_view ca_file,TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,std::uint32_t timeout,TcpSocketOptions options,AnyTlsOptions pool_options,bool fast_open,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit,std::span<std::array<std::uint8_t,32> const> pins,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc_cfg,QuicEchOptions const& ech,bool dns_available)
        -> std::expected<TunnelFactory,std::string> {
        auto pool=pool_options;
        if (host.empty() || host.size()>253 || !port || std::ranges::any_of(host,[](unsigned char c) { return c<33 || c>126; }) ||
            !timeout || timeout>3600000 || !options.valid() || !pool.valid()) return std::unexpected("invalid AnyTLS dial options");
        if (transport && grpc_cfg) return std::unexpected("AnyTLS accepts at most one transport");
        if ((ech.dns || !ech.config_file.empty()) && fingerprint==TlsFingerprint::tls12) return std::unexpected("AnyTLS ECH requires TLS 1.3");
        auto ech_profile=quic_ech::Profile::load(ech,server_name,dns_available);
        if (!ech_profile) return std::unexpected(ech_profile.error());
        if (exchange!=TlsKeyExchange::x25519 && exchange!=TlsKeyExchange::x25519_mlkem768 && exchange!=TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto key=a::PasswordKey::load(password_file);
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
            auto gp=std::make_unique<anytls_grpc::Profile>(std::string(host),port,std::move(*key),std::move(*shaped),
                std::move(grpc_prof->request),grpc_prof->response,grpc_prof->limits,grpc_prof->max_sessions,
                bootstrap,timeout,options,pool,fast_open,std::move(*ech_profile));
            return anytls_grpc::make_factory(std::move(gp));
        }
        auto profile=std::make_unique<Profile>(std::string(host),port,std::move(*key),std::move(*shaped),bootstrap,timeout,options,pool,fast_open,std::move(hu_prof),std::move(*ech_profile));
        auto* borrowed=profile.get();
        TunnelFactory factory{[profile=std::move(profile)](Session& session,corosio::io_context& context,bool local,TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
            Worker* fast=nullptr;
            { std::lock_guard lock(profile->mutex); fast=find(*profile,Mode::fast_open,context); }
            if(fast)return pro::make_proxy<TunnelFacade,Tunnel>(session,fast->client,profile->timeout,local);
            Worker* worker=nullptr;
            { std::lock_guard lock(profile->mutex); worker=find(*profile,Mode::physical,context); }
            return worker ? pro::make_proxy<TunnelFacade,Tunnel>(session,worker->client,profile->timeout,local) : pro::proxy<TunnelFacade>{};
        },timeout,[borrowed](Session& session,corosio::io_context& context,TunnelFactory const&,bool local) -> pro::proxy<TunnelFacade> {
            Worker* worker=nullptr;
            { std::lock_guard lock(borrowed->mutex); worker=find(*borrowed,Mode::layered,context); }
            return worker ? pro::make_proxy<TunnelFacade,Tunnel>(session,worker->client,borrowed->timeout,local) : pro::proxy<TunnelFacade>{};
        },std::nullopt,options.configured() || fast_open};
        factory.start_context=[borrowed](OutboundContext const& environment,TunnelFactory const* detour,bool direct) {
            auto fast=direct && environment.direct_options ? environment.direct_options->tcp_fast_open.value_or(false) : borrowed->fast_open;
            return detour ? initialize(*borrowed,Mode::layered,environment,detour,direct) :
                initialize(*borrowed,fast ? Mode::fast_open : Mode::physical,environment,nullptr,direct);
        };
        factory.stop_context=[borrowed](corosio::io_context& context) noexcept { stop(*borrowed,context); };
        factory.quiesced_context=[borrowed](corosio::io_context& context) noexcept { return drained(*borrowed,context); };
        factory.finish_context=[borrowed](corosio::io_context& context) noexcept { finish(*borrowed,context); };
        return factory;
    }
}
