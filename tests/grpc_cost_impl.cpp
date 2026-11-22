module proxy;
import std;
import proxy.v4;
import config;
import grpc.headers;
import grpc.session;
import grpc.connection;
import net.connection_pool;
import net.stream_relay;
import tls.connector;
import tls.profiles;
import tls.byte_stream;
import vless;
import vless.corosio_client;
import rulefile;
import crypto;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    namespace grpc_vless {
        namespace g=grpc;
        using Connected=tls::detail::ConnectResult;
        template<bool> struct Worker;
        struct Profile {
            std::string host;std::uint16_t port;vless::UserId user;
            tls::ClientProfile tls;g::RequestProfile request;g::ResponsePolicy response;
            g::Limits limits;std::size_t max_sessions;
            std::optional<std::size_t> bootstrap;std::uint32_t timeout;TcpSocketOptions options;
            std::mutex mutex;
            std::array<std::unique_ptr<Worker<false>>,16> physical;
            std::array<std::unique_ptr<Worker<true>>,16> layered;
            ~Profile();
        };
        struct ReadPolicy {
            using Error=tls::detail::ByteStreamError;
            static auto close_deadline() noexcept {return Clock::now()+std::chrono::seconds(10);}
            static auto convert(g::Failure failure) noexcept -> Error {
                if (failure.error==g::Error::state) return Error::state;
                return failure.error==g::Error::transport || failure.error==g::Error::timeout ||
                    failure.error==g::Error::canceled ? Error::io : Error::protocol;
            }
        };
        struct Resolver {
            Session& session;nex::corosio::io_context& context;Profile const& profile;DnsSlot slot;
            auto operator()(Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
                if (profile.bootstrap) return resolve_bootstrap_owned(session,context,slot,*profile.bootstrap,profile.host,profile.port,deadline);
                return resolve_local_owned(session,context,slot,profile.host,profile.port,deadline);
            }
            auto cancel() noexcept -> void {slot.cancel();}
        };
        struct Lower {
            using Candidates=LowerConnector::Candidates;
            Session& session;LowerConnector connector;
            Lower(Session& state,OutboundContext const& environment,TunnelFactory const& detour,Profile const& profile)
                : session(state),connector{{},&environment.context,&detour,profile.host,profile.port,profile.bootstrap} {}
            auto connect(Clock::time_point deadline,Candidates& candidates) -> nex::capy::task<Connected> {
                switch (co_await connector.connect(session,deadline,candidates)) {
                case TunnelConnectResult::connected:co_return Connected::connected;
                case TunnelConnectResult::retryable:co_return Connected::retryable;
                case TunnelConnectResult::timeout:co_return Connected::timeout;
                default:co_return Connected::failed;
                }
            }
            auto retry() noexcept -> bool {return connector.retry();}
            auto read(std::span<std::uint8_t> bytes) {return connector.tunnel->read(bytes);}
            auto send(std::span<std::uint8_t const> bytes) {return connector.tunnel->send(bytes);}
            auto close_output() {return connector.tunnel->close_output();}
            auto cancel() noexcept -> void {connector.cancel();}
        };
        using Physical=tls::detail::PhysicalConnector<Resolver,tls::ClientProfile>;
        using Layer=tls::detail::LayerConnector<Lower,tls::ClientProfile>;
        template<bool Layered>
        class Node {
            using Connector=std::conditional_t<Layered,Layer,Physical>;
            Session state_;
            std::optional<Connector> connector_;
        public:
            using Socket=typename Connector::Socket;
            Node(OutboundContext const& environment,Profile const& profile,TunnelFactory const* detour,TcpSocketOptions const& options)
                : state_(environment.context) {
                state_.dns=environment.dns;state_.local_dns=environment.local_dns;
                state_.tunnel_factories=environment.factories;state_.direct_tcp_options=environment.direct_options;
                if constexpr (Layered) connector_.emplace(profile.tls,state_,environment,*detour,profile);
                else connector_.emplace(environment.context,Resolver{state_,environment.context,profile},profile.tls,options);
            }
            ~Node() {state_.close();}
            auto start(Clock::time_point deadline) {return connector_->start(deadline);}
            auto application() noexcept {return connector_->application();}
            auto accepts_alpn() const noexcept -> bool {
                auto* selected=connector_->negotiated();
                return selected && selected->alpn && std::ranges::equal(*selected->alpn,std::string_view("h2"));
            }
            auto cancel() noexcept -> void {connector_->cancel();state_.close();}
        };
        template<bool Layered>
        using Connection=g::OwnedConnection<Node<Layered>,ReadPolicy>;
        template<bool Layered>
        struct Worker {
            using Pool=net::ConnectionPool<Connection<Layered>>;
            OutboundContext environment;Profile const& profile;TunnelFactory const* detour;TcpSocketOptions options;
            Pool pool;
            Worker(OutboundContext const& env,Profile const& value,TunnelFactory const* lower,TcpSocketOptions selected)
                : environment(env),profile(value),detour(lower),options(selected),pool(net::PoolOptions{.max_sessions=value.max_sessions}) {}
            ~Worker() {pool.stop();if (!pool.drained()) std::terminate();}
        };
        Profile::~Profile()=default;
        template<bool Layered> auto slots(Profile& profile) noexcept -> auto& {
            if constexpr (Layered) return profile.layered;else return profile.physical;
        }
        template<bool Layered> auto find(Profile& profile,nex::corosio::io_context& context) noexcept -> Worker<Layered>* {
            for (auto const& slot:slots<Layered>(profile)) if (slot && &slot->environment.context==&context) return slot.get();
            return nullptr;
        }
        template<bool Layered> auto initialize(Profile& profile,OutboundContext const& environment,TunnelFactory const* detour,bool direct) -> bool {
            std::lock_guard lock(profile.mutex);
            if (find<Layered>(profile,environment.context) || (direct && !environment.direct_options)) return false;
            auto& entries=slots<Layered>(profile);auto slot=std::ranges::find_if(entries,[](auto const& value) {return !value;});
            if (slot==entries.end()) return false;
            *slot=std::make_unique<Worker<Layered>>(environment,profile,detour,direct ? *environment.direct_options : profile.options);
            return true;
        }
        template<bool Layered> auto stop(Profile& profile,nex::corosio::io_context& context) noexcept -> void {
            Worker<Layered>* worker=nullptr;{std::lock_guard lock(profile.mutex);worker=find<Layered>(profile,context);}
            if (worker) worker->pool.stop();
        }
        template<bool Layered> auto finish(Profile& profile,nex::corosio::io_context& context) noexcept -> void {
            std::lock_guard lock(profile.mutex);
            for (auto& worker:slots<Layered>(profile)) if (worker && &worker->environment.context==&context) {
                if (!worker->pool.drained()) std::terminate();worker.reset();return;
            }
        }
        template<bool Layered>
        class Tunnel {
            using State=Connection<Layered>;
            using Protocol=typename State::Protocol;
            using Socket=typename Node<Layered>::Socket;
            using Client=vless::detail::TcpClient<Socket,false,Protocol&>;
            using Relay=vless::detail::DuplexRelay<nex::corosio::tcp_socket,Socket,Protocol&>;
            Session& session_;Worker<Layered>& worker_;bool relay_local_,ready_=false;
            std::stop_source stop_;
            std::optional<typename Worker<Layered>::Pool::Lease> lease_;
            std::optional<Client> client_;
            std::optional<Relay> relay_;
            auto start(nex::corosio::endpoint destination,bool mux,Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
                if (ready_ || lease_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                struct Guard {Tunnel& owner;bool done=false;~Guard() {if (!done) owner.cancel();}} guard{*this};
                worker_.pool.reap(Clock::now());auto creation=worker_.pool.reserve();if (!creation) co_return TunnelConnectResult::failed;
                auto connection=std::make_unique<State>(worker_.environment,worker_.profile,worker_.detour,worker_.options);
                std::stop_callback starting(stop_.get_token(),[pointer=connection.get()]() noexcept {pointer->stop();});
                auto connected=co_await connection->start(worker_.profile.request,worker_.profile.limits,worker_.profile.response,deadline);
                if (connected!=Connected::connected || stop_.stop_requested() || session_.closed)
                    co_return connected==Connected::timeout || Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                auto accepted=creation->commit(std::move(connection));if (!accepted) co_return TunnelConnectResult::failed;
                lease_.emplace(std::move(*accepted));auto& owned=lease_->connection();
                owned.run(worker_.environment.context);auto& channel=*owned.protocol();
                client_.emplace(channel);relay_.emplace(session_.client,*client_,[this] {session_.touched=Clock::now();},relay_local_ && !mux);
                vless::TcpRequest request;request.user=worker_.profile.user;
                if (!mux) {
                    request.port=destination.port();auto address=destination.address();
                    if (address.is_v4()) {request.kind=vless::AddressKind::ipv4;auto bytes=address.to_v4().to_bytes();request.address.assign(bytes.begin(),bytes.end());}
                    else {request.kind=vless::AddressKind::ipv6;auto bytes=address.to_v6().to_bytes();request.address.assign(bytes.begin(),bytes.end());}
                }
                auto sent=mux ? co_await client_->start_mux(request.user,false,deadline) : co_await client_->start(request,deadline);
                if (!sent || stop_.stop_requested() || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                ready_=true;guard.done=true;co_return TunnelConnectResult::connected;
            }
            auto normal() const noexcept -> bool {
                return lease_ && lease_->connection().protocol() && lease_->connection().protocol()->transport_ended() && !lease_->connection().protocol()->failure();
            }
        public:
            Tunnel(Session& session,Worker<Layered>& worker,bool local) : session_(session),worker_(worker),relay_local_(local) {}
            auto cancel() noexcept -> void {
                if (normal()) return;
                stop_.request_stop();if (lease_) lease_->connection().stop();if (relay_) relay_->cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }
            auto connect(nex::corosio::endpoint endpoint) {return connect_until(endpoint,session_.started+std::chrono::milliseconds(worker_.profile.timeout));}
            auto connect_until(nex::corosio::endpoint endpoint,Clock::time_point deadline) {return start(endpoint,false,deadline);}
            auto has_uot() const noexcept -> bool {return false;}
            auto connect_uot() -> nex::capy::task<TunnelConnectResult> {co_return TunnelConnectResult::failed;}
            auto connect_uot_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> {co_return TunnelConnectResult::failed;}
            auto has_xudp() const noexcept -> bool {return true;}
            auto packet_transport() const noexcept -> net::PacketTransport {return {net::PacketTransportKind::xudp};}
            auto connect_packets(Clock::time_point deadline) {return start({},true,deadline);}
            auto connect_xudp_until(Clock::time_point deadline) {return start({},true,deadline);}
            auto connect_xudp() {return start({},true,Clock::now()+std::chrono::milliseconds(worker_.profile.timeout));}
            auto send(std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await relay_->write(bytes);
            }
            auto read(std::span<std::uint8_t> bytes) -> nex::capy::task<std::expected<std::size_t,std::string>> {
                if (!ready_ || stop_.stop_requested()) co_return std::unexpected("gRPC VLESS stream closed");
                auto result=co_await relay_->read(bytes);if (!result) co_return std::unexpected("gRPC VLESS stream read failed");co_return *result;
            }
            auto close_output() -> nex::capy::task<bool> {co_return ready_ && co_await relay_->close_output();}
            auto upload() -> nex::capy::task<bool> {co_return ready_ && co_await relay_->upload();}
            auto download() -> nex::capy::task<bool> {co_return ready_ && co_await relay_->download();}
        };
    }
    auto make_vless_grpc_factory(std::string_view host,std::uint16_t port,std::string_view uuid,std::string_view server_name,std::string_view ca,
        TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,std::uint32_t timeout,TcpSocketOptions options,GrpcTransport transport)
        -> std::expected<TunnelFactory,std::string> {
        namespace v=grpc_vless;
        if (host.empty() || host.size()>253 || !port || std::ranges::any_of(host,[](unsigned char c) {return c<33 || c>126;}) ||
            !timeout || timeout>3600000 || !options.valid() || !transport.max_sessions || transport.max_sessions>256) return std::unexpected("invalid gRPC VLESS options");
        if (exchange!=TlsKeyExchange::x25519 && exchange!=TlsKeyExchange::x25519_mlkem768 && exchange!=TlsKeyExchange::x25519_mlkem768_only)
            return std::unexpected("invalid TLS key exchange");
        auto secret=rulefile::read_password_file(uuid);if (!secret) return std::unexpected("UUID file: "+secret.error());
        auto user=vless::parse_user_id(*secret);std::fill(secret->begin(),secret->end(),'\0');if (!user) return std::unexpected("invalid UUID");
        constexpr std::array<std::string_view,1> alpn{"h2"};
        auto tls=tls::ClientProfile::load(server_name,ca,exchange==TlsKeyExchange::x25519 ? 0x001d : 0x11ec,exchange==TlsKeyExchange::x25519_mlkem768_only,alpn);
        auto request=grpc::RequestProfile::create(transport.service_name,transport.authority.empty() ? server_name : transport.authority,true);
        auto response=transport.response_policy==GrpcTransport::ResponsePolicy::standard ? grpc::ResponsePolicy::standard : grpc::ResponsePolicy::sing_box_lite;
        grpc::Limits limits{transport.input_window,transport.message_bytes,transport.hunk_bytes,transport.output_bytes,transport.output_messages,transport.library_bytes};
        if (!tls || !request || !grpc::Session::create(grpc::Role::client,*request,response,limits)) return std::unexpected("invalid gRPC TLS/request/limits");
        auto profile=std::make_unique<v::Profile>(std::string(host),port,*user,std::move(*tls),std::move(*request),response,limits,transport.max_sessions,bootstrap,timeout,options);
        auto* borrowed=profile.get();
        TunnelFactory factory{[profile=std::move(profile)](Session& session,nex::corosio::io_context& context,bool local,TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
            v::Worker<false>* worker=nullptr;{std::lock_guard lock(profile->mutex);worker=v::find<false>(*profile,context);}
            return worker ? pro::make_proxy<TunnelFacade,v::Tunnel<false>>(session,*worker,local) : pro::proxy<TunnelFacade>{};
        },timeout,[borrowed](Session& session,nex::corosio::io_context& context,TunnelFactory const&,bool local) -> pro::proxy<TunnelFacade> {
            v::Worker<true>* worker=nullptr;{std::lock_guard lock(borrowed->mutex);worker=v::find<true>(*borrowed,context);}
            return worker ? pro::make_proxy<TunnelFacade,v::Tunnel<true>>(session,*worker,local) : pro::proxy<TunnelFacade>{};
        },std::nullopt,options.configured()};
        factory.start_context=[borrowed](OutboundContext const& environment,TunnelFactory const* detour,bool direct) {
            return detour ? v::initialize<true>(*borrowed,environment,detour,direct) : v::initialize<false>(*borrowed,environment,nullptr,direct);
        };
        factory.stop_context=[borrowed](nex::corosio::io_context& context) noexcept {v::stop<false>(*borrowed,context);v::stop<true>(*borrowed,context);};
        factory.finish_context=[borrowed](nex::corosio::io_context& context) noexcept {v::finish<false>(*borrowed,context);v::finish<true>(*borrowed,context);};
        return factory;
    }
}

extern "C" int nexus_grpc_cost() {
    namespace v=proxy::grpc_vless;
    std::println("Profile={} PhysicalNode={} LayeredNode={} PhysicalOwner={} LayeredOwner={} PhysicalWorker={} LayeredWorker={} PhysicalTunnel={} LayeredTunnel={}",
        sizeof(v::Profile),sizeof(v::Node<false>),sizeof(v::Node<true>),sizeof(v::Connection<false>),sizeof(v::Connection<true>),sizeof(v::Worker<false>),sizeof(v::Worker<true>),sizeof(v::Tunnel<false>),sizeof(v::Tunnel<true>));
    return 0;
}
