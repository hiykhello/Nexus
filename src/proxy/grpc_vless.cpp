module proxy;
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
import config;
import tls.fingerprint;
import tls.byte_stream;
import vless;
import vless.corosio_client;
import rulefile;
import crypto;
import platform.ip_address;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    namespace grpc_vless {
        namespace g=grpc;
        using Connected=tls::detail::ConnectResult;
        template<int> struct Worker;
        struct Profile {
            std::string host;std::uint16_t port;vless::UserId user;
            tls::ShapedClientProfile tls;g::RequestProfile request;g::ResponsePolicy response;
            g::Limits limits;std::size_t max_sessions;
            std::optional<std::size_t> bootstrap;std::uint32_t timeout;TcpSocketOptions options;bool fast_open;
            std::mutex mutex;
            std::array<std::unique_ptr<Worker<0>>,17> physical;
            std::array<std::unique_ptr<Worker<1>>,17> layered;
            std::array<std::unique_ptr<Worker<2>>,17> fast;
            ~Profile();
        };
        using ReadPolicy=g::detail::ByteStreamReadPolicy;
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
        using Physical=tls::detail::PhysicalConnector<Resolver,tls::ShapedClientProfile>;
        using Layer=tls::detail::LayerConnector<Lower,tls::ShapedClientProfile>;
        using Fast=tls::detail::FastOpenPhysicalConnector<Resolver,tls::ShapedClientProfile>;
        template<int Mode>
        class Node {
            using Connector=std::conditional_t<Mode==1,Layer,std::conditional_t<Mode==2,Fast,Physical>>;
            Session state_;
            std::optional<Connector> connector_;
        public:
            using Socket=typename Connector::Socket;
            Node(OutboundContext const& environment,Profile const& profile,TunnelFactory const* detour,TcpSocketOptions const& options)
                : state_(environment.context) {
                state_.dns=environment.dns;state_.local_dns=environment.local_dns;
                state_.tunnel_factories=environment.factories;state_.direct_tcp_options=environment.direct_options;
                if constexpr (Mode==1) connector_.emplace(profile.tls,state_,environment,*detour,profile);
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
        template<int Mode>
        using Connection=g::OwnedConnection<Node<Mode>,ReadPolicy,16>;
        template<int Mode>
        struct Worker {
            using Pool=net::ConnectionPool<Connection<Mode>,true>;
            OutboundContext environment;Profile const& profile;TunnelFactory const* detour;TcpSocketOptions options;
            Pool pool;
            nex::capy::async_mutex starting;
            Connection<Mode>* starting_connection=nullptr;
            bool stopped=false;
            Worker(OutboundContext const& env,Profile const& value,TunnelFactory const* lower,TcpSocketOptions selected)
                : environment(env),profile(value),detour(lower),options(selected),pool(net::PoolOptions{.max_sessions=value.max_sessions}) {}
            auto stop() noexcept -> void{
                stopped=true;
                if(auto* active=starting_connection)active->stop();
                pool.stop();
            }
            ~Worker() {stop();if (starting_connection||!pool.drained()) std::terminate();}
        };
        Profile::~Profile()=default;
        template<int Mode> auto slots(Profile& profile) noexcept -> auto& {
            if constexpr (Mode==1) return profile.layered;else if constexpr (Mode==2) return profile.fast;else return profile.physical;
        }
        template<int Mode> auto find(Profile& profile,nex::corosio::io_context& context) noexcept -> Worker<Mode>* {
            for (auto const& slot:slots<Mode>(profile)) if (slot && &slot->environment.context==&context) return slot.get();
            return nullptr;
        }
        template<int Mode> auto initialize(Profile& profile,OutboundContext const& environment,TunnelFactory const* detour,bool direct) -> bool {
            std::lock_guard lock(profile.mutex);
            if (find<Mode>(profile,environment.context) || (direct && !environment.direct_options)) return false;
            auto& entries=slots<Mode>(profile);auto slot=std::ranges::find_if(entries,[](auto const& value) {return !value;});
            if (slot==entries.end()) return false;
            *slot=std::make_unique<Worker<Mode>>(environment,profile,detour,direct ? *environment.direct_options : profile.options);
            return true;
        }
        template<int Mode> auto stop(Profile& profile,nex::corosio::io_context& context) noexcept -> void {
            Worker<Mode>* worker=nullptr;{std::lock_guard lock(profile.mutex);worker=find<Mode>(profile,context);}
            if (worker) worker->stop();
        }
        template<int Mode> auto finish(Profile& profile,nex::corosio::io_context& context) noexcept -> void {
            std::lock_guard lock(profile.mutex);
            for (auto& worker:slots<Mode>(profile)) if (worker && &worker->environment.context==&context) {
                if (!worker->pool.drained()) std::terminate();worker.reset();return;
            }
        }
        template<int Mode>
        class Tunnel {
            using State=Connection<Mode>;
            using Protocol=typename State::Protocol;
            using Rpc=typename Protocol::Stream;
            using Socket=typename Node<Mode>::Socket;
            using Client=vless::detail::TcpClient<Socket,false,Rpc&>;
            using Relay=vless::detail::DuplexRelay<nex::corosio::tcp_socket,Socket,Rpc&>;
            Session& session_;Worker<Mode>& worker_;bool relay_local_,ready_=false;
            std::stop_source stop_;
            std::optional<typename Worker<Mode>::Pool::Lease> lease_;
            std::optional<Rpc> rpc_;
            std::optional<Client> client_;
            std::optional<Relay> relay_;
            auto start(nex::corosio::endpoint destination,bool mux,Clock::time_point deadline,
                       std::string_view domain={}) -> nex::capy::task<TunnelConnectResult> {
                if (ready_ || lease_ || stop_.stop_requested() || session_.closed||worker_.stopped) co_return TunnelConnectResult::failed;
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                struct Guard {Tunnel& owner;bool done=false;~Guard() {if (!done) owner.cancel();}} guard{*this};
                worker_.pool.reap(Clock::now());
                if(auto reused=worker_.pool.acquire())lease_.emplace(std::move(*reused));
                else{
                    // Concurrent cold requests share the first authenticated
                    // connection instead of racing separate TLS startups.
                    // This wait keeps the caller's original connect budget.
                    auto wait=nex::corosio::timeout(worker_.starting.scoped_lock(),deadline);
                    auto [lock_error,lock]=co_await net::OperationToken(std::move(wait),stop_);
                    if(lock_error||stop_.stop_requested()||session_.closed||worker_.stopped||Clock::now()>=deadline)
                        co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                    if(auto reused=worker_.pool.acquire())lease_.emplace(std::move(*reused));
                    else{
                    auto creation=worker_.pool.reserve();if(!creation)co_return TunnelConnectResult::failed;
                    auto connection=std::make_unique<State>(worker_.environment,worker_.profile,worker_.detour,worker_.options);
                    struct Starting {
                        Worker<Mode>& worker;
                        Starting(Worker<Mode>& owner,State* connection) noexcept:worker(owner){worker.starting_connection=connection;}
                        ~Starting(){worker.starting_connection=nullptr;}
                    } registration(worker_,connection.get());
                    Connected connected;
                    {
                        // Once committed, other RPCs may share this owner.
                        // A business cancellation may stop only its own RPC.
                        std::stop_callback starting(stop_.get_token(),[pointer=connection.get()]() noexcept {pointer->stop();});
                        connected=co_await connection->start(worker_.profile.request,worker_.profile.limits,worker_.profile.response,deadline);
                    }
                    if(connected!=Connected::connected||stop_.stop_requested()||session_.closed||worker_.stopped)
                        co_return connected==Connected::timeout||Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                    auto accepted=creation->commit(std::move(connection));if(!accepted)co_return TunnelConnectResult::failed;
                    lease_.emplace(std::move(*accepted));lease_->connection().run(worker_.environment.context);
                    }
                }
                auto& channel=*lease_->connection().protocol();auto opened=channel.open();if(!opened)co_return TunnelConnectResult::failed;
                rpc_.emplace(channel,*opened);
                client_.emplace(*rpc_);relay_.emplace(session_.client,*client_,[this] {session_.touched=Clock::now();},relay_local_ && !mux);
                vless::TcpRequest request;request.user=worker_.profile.user;
                if (!mux) {
                    request.port=destination.port();auto address=destination.address();
                    if (!domain.empty()) {request.kind=vless::AddressKind::domain;request.address.assign(domain.begin(),domain.end());}
                    else if (address.is_v4()) {request.kind=vless::AddressKind::ipv4;auto bytes=address.to_v4().to_bytes();request.address.assign(bytes.begin(),bytes.end());}
                    else {request.kind=vless::AddressKind::ipv6;auto bytes=address.to_v6().to_bytes();request.address.assign(bytes.begin(),bytes.end());}
                }
                auto sent=mux ? co_await client_->start_mux(request.user,false,deadline) : co_await client_->start(request,deadline);
                if (!sent || stop_.stop_requested() || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                ready_=true;guard.done=true;co_return TunnelConnectResult::connected;
            }
            auto normal() const noexcept -> bool {
                return rpc_&&rpc_->complete()&&!rpc_->failure();
            }
        public:
            Tunnel(Session& session,Worker<Mode>& worker,bool local) : session_(session),worker_(worker),relay_local_(local) {}
            auto cancel() noexcept -> void {
                if (normal()) return;
                stop_.request_stop();if(rpc_)rpc_->cancel();if (relay_) relay_->cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }
            auto connect(nex::corosio::endpoint endpoint) {return connect_until(endpoint,session_.started+std::chrono::milliseconds(worker_.profile.timeout));}
            auto connect_until(nex::corosio::endpoint endpoint,Clock::time_point deadline) {return start(endpoint,false,deadline);}
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                return start(nex::corosio::endpoint(nex::corosio::ipv4_address{},port),false,deadline,domain);
            }
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
            auto upload() -> nex::capy::task<bool> {co_return ready_ && co_await relay_->upload({},session_.traffic_delivery());}
            auto download() -> nex::capy::task<bool> {co_return ready_ && co_await relay_->download({},session_.traffic_delivery());}
        };
    }
    auto make_vless_grpc_factory(std::string_view host,std::uint16_t port,std::string_view uuid,std::string_view server_name,std::string_view ca,
        TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,std::uint32_t timeout,TcpSocketOptions options,GrpcTransport transport,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit,std::span<std::array<std::uint8_t,32> const> pins)
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
        if (!tls) return std::unexpected(tls.error());
        tls->certificate_pins.assign(pins.begin(),pins.end());
        auto shape=tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!shape) return std::unexpected("invalid TLS fingerprint configuration");
        auto shaped=tls::ShapedClientProfile::create(std::move(*tls),*shape,record_size_limit);
        if (!shaped) return std::unexpected(shaped.error());
        std::string default_authority(server_name);
        if(transport.authority.empty())if(auto ip=platform::parse_ip_address(default_authority);ip && ip->size==16)
            default_authority="["+default_authority+"]";
        auto request=grpc::RequestProfile::create(transport.service_name,transport.authority.empty() ? default_authority : transport.authority,true);
        auto response=transport.response_policy==GrpcTransport::ResponsePolicy::standard ? grpc::ResponsePolicy::standard : grpc::ResponsePolicy::sing_box_lite;
        grpc::Limits limits{transport.input_window,transport.message_bytes,transport.hunk_bytes,transport.output_bytes,transport.output_messages,transport.library_bytes};
        if (!request || !grpc::Session::create(grpc::Role::client,*request,response,limits)) return std::unexpected("invalid gRPC TLS/request/limits");
        auto profile=std::make_unique<v::Profile>(std::string(host),port,*user,std::move(*shaped),std::move(*request),response,limits,transport.max_sessions,bootstrap,timeout,options,transport.tcp_fast_open);
        auto* borrowed=profile.get();
        TunnelFactory factory{[profile=std::move(profile)](Session& session,nex::corosio::io_context& context,bool local,TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
            v::Worker<2>* fast=nullptr;{std::lock_guard lock(profile->mutex);fast=v::find<2>(*profile,context);}
            if(fast)return pro::make_proxy<TunnelFacade,v::Tunnel<2>>(session,*fast,local);
            v::Worker<0>* worker=nullptr;{std::lock_guard lock(profile->mutex);worker=v::find<0>(*profile,context);}
            return worker ? pro::make_proxy<TunnelFacade,v::Tunnel<0>>(session,*worker,local) : pro::proxy<TunnelFacade>{};
        },timeout,[borrowed](Session& session,nex::corosio::io_context& context,TunnelFactory const&,bool local) -> pro::proxy<TunnelFacade> {
            v::Worker<1>* worker=nullptr;{std::lock_guard lock(borrowed->mutex);worker=v::find<1>(*borrowed,context);}
            return worker ? pro::make_proxy<TunnelFacade,v::Tunnel<1>>(session,*worker,local) : pro::proxy<TunnelFacade>{};
        },std::nullopt,options.configured() || transport.tcp_fast_open};
        factory.start_context=[borrowed](OutboundContext const& environment,TunnelFactory const* detour,bool direct) {
            auto fast=direct && environment.direct_options ? environment.direct_options->tcp_fast_open.value_or(false) : borrowed->fast_open;
            return detour ? v::initialize<1>(*borrowed,environment,detour,direct) : fast ?
                v::initialize<2>(*borrowed,environment,nullptr,direct) : v::initialize<0>(*borrowed,environment,nullptr,direct);
        };
        factory.stop_context=[borrowed](nex::corosio::io_context& context) noexcept {v::stop<0>(*borrowed,context);v::stop<1>(*borrowed,context);v::stop<2>(*borrowed,context);};
        factory.finish_context=[borrowed](nex::corosio::io_context& context) noexcept {v::finish<0>(*borrowed,context);v::finish<1>(*borrowed,context);v::finish<2>(*borrowed,context);};
        return factory;
    }
}
