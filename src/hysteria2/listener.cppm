export module hysteria2.listener;
import std;
import crypto;
import hysteria2.application;
import hysteria2.auth;
import hysteria2.wire;
import hysteria2.stream_state;
import hysteria2.tcp_channel;
import hysteria2.transport_options;
import hysteria2.salamander;
import http.header;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.native_memory;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import net.datagram_driver;
import tls.server_credential;
import ngtcp2;
import capy;
import corosio;

export namespace hysteria2 {
    template<class Hooks,class=void>struct ListenerConnectionState {using Type=std::monostate;};
    template<class Hooks>struct ListenerConnectionState<Hooks,std::void_t<typename Hooks::ConnectionState>> {using Type=typename Hooks::ConnectionState;};
    // One concrete owner per UDP listener/executor. Hooks and immutable TLS
    // credentials outlive this owner. Host retains it through context shutdown,
    // then checks drained() before releasing it. Per-stream business tasks are
    // directly owned by their guards; native retirement waits for every guard.
    template<class Hooks,std::size_t Sessions=64,std::size_t Streams=16,std::size_t Window=16384,class Heap=quic::NativeHeap>
    class Listener {
    public:
        struct InitializationFailure {quic::SessionHandle owner;int native;};
        struct RuntimeFailure {enum class Kind {allocation,callback} kind;std::exception_ptr exception;};
    private:
        using Clock=std::chrono::steady_clock;
        using ConnectionState=typename ListenerConnectionState<Hooks>::Type;
        using Registry=quic::CidRegistry<Sessions,8>;
        struct Policy {
            Hooks& hooks;Registry& registry;quic::SessionHandle owner;capy::async_event& work;
            std::optional<std::size_t> user;
            auto changed() noexcept -> void {work.set();}
            auto has_masquerade() const noexcept -> bool requires requires { hooks.has_masquerade(); } {
                return hooks.has_masquerade();
            }
            auto authenticate(ClientAuthView request) noexcept -> bool {
                static_assert(noexcept(hooks.authenticate(request)));auto selected=hooks.authenticate(request);
                if(user)return selected==user;
                if (selected) {
                    if constexpr (requires {hooks.admit_authenticated(owner,*selected);}) {
                        static_assert(noexcept(hooks.admit_authenticated(owner,*selected)));
                        if (!hooks.admit_authenticated(owner,*selected)) return false;
                    }
                    user=selected;
                    if constexpr (requires {hooks.authenticated(owner,*selected);}) hooks.authenticated(owner,*selected);
                }
                return selected.has_value();
            }
            auto datagram(std::span<std::uint8_t const> bytes) noexcept -> int {
                static_assert(noexcept(hooks.datagram(owner,bytes)));return hooks.datagram(owner,bytes);
            }
            auto datagram_output() noexcept requires requires{hooks.datagram_output(owner);} {return hooks.datagram_output(owner);}
            auto datagram_accepted() noexcept -> void requires requires{hooks.datagram_accepted(owner);} {hooks.datagram_accepted(owner);}
            auto datagram_rejected() noexcept -> void requires requires{hooks.datagram_rejected(owner);} {hooks.datagram_rejected(owner);}
            auto add_connection_id(ngtcp2::ngtcp2_cid const& id,ngtcp2::ngtcp2_stateless_reset_token const&) noexcept -> int {
                return registry.insert(owner,{id.data,id.datalen})?0:ngtcp2::err_callback_failure;
            }
            auto remove_connection_id(ngtcp2::ngtcp2_cid const& id) noexcept -> int {(void)registry.remove(owner,{id.data,id.datalen});return 0;}
        };
        using App=Application<quic::TlsServer,Policy,Streams,Window>;
        using NativeSession=quic::DatagramSession<quic::TlsServer,App>;
        struct Bundle {
            [[no_unique_address]] ConnectionState connection;
            quic::TlsServer tls;quic::NativeMemory<Heap> memory;Policy policy;App app;NativeSession session;
            corosio::endpoint peer;quic::SessionHandle owner;std::stop_source stop;
            std::size_t business=0;std::optional<int> failure;bool canceled=false,reported=false;
            Bundle(Listener& listener,Registry& registry,quic::SessionHandle owner,corosio::endpoint const& peer,ConnectionState&& connection)
                :connection(std::move(connection)),tls(listener.credential_,"h3"),memory(listener.options_.native_bytes),policy{listener.hooks_,registry,owner,listener.work_},
                app(tls,policy,true,memory.http3(),{},ServerAuth{listener.options_.udp,true,0},
                    listener.options_.congestion,listener.options_.receive_windows.max_stream),session(tls,app,listener.local_),peer(peer),owner(owner){}
        };
        struct Factory {
            using Session=NativeSession;using ControlFailure=quic::RetryFailure;
            Listener& listener;quic::RetryAdmission<> retry;
            std::optional<quic::RetryClaims> permit;std::optional<ControlFailure> error;
            std::array<std::optional<Bundle>,Sessions> bundles;
            explicit Factory(Listener& listener) noexcept:listener(listener){}
            auto admit(ngtcp2::ngtcp2_pkt_hd const& initial,corosio::endpoint const& peer,Clock::time_point now,std::size_t bytes) noexcept -> bool {
                permit.reset();auto result=retry.inspect(initial,peer,now,bytes);
                if(!result){if(!error)error=result.error();return false;}permit=*result;return permit.has_value();
            }
            auto control_failure() const noexcept {return error;}
            auto control_output(std::span<std::uint8_t> bytes,Clock::time_point now) noexcept -> std::expected<std::optional<net::DatagramOutput>,ControlFailure> {
                if(error)return std::unexpected(*error);return retry.output(bytes,now);
            }
            auto control_transmitted(std::uint64_t token,Clock::time_point now) noexcept {return retry.transmitted(token,now);}
            auto control_next_expiry() const noexcept {return retry.next_expiry();}
            auto control_expire(Clock::time_point now) noexcept {return retry.expire(now);}
            auto control_request_stop() noexcept -> void {retry.request_stop();}
            auto control_stop() noexcept -> void {permit.reset();retry.stop();}
            auto control_drained() const noexcept -> bool {return retry.drained();}
            auto create(quic::SessionHandle owner,Registry& registry,std::span<std::uint8_t const> source,ngtcp2::ngtcp2_pkt_hd const& initial,
                corosio::endpoint const& peer,Clock::time_point now) noexcept -> std::expected<Session*,int> {
                namespace n = ::ngtcp2;
                try {
                    if(!permit || !std::ranges::equal(permit->retry.bytes(),std::span(initial.dcid.data).first(initial.dcid.datalen)))return std::unexpected(n::err_callback_failure);
                    auto verified=*permit;permit.reset();auto& entry=bundles[owner.slot];if(entry)return std::unexpected(n::err_callback_failure);
                    std::optional<ConnectionState> connection;
                    if constexpr(requires{listener.hooks_.admit(owner,peer);})connection=listener.hooks_.admit(owner,peer);
                    else connection.emplace();
                    // A host's physical-session quota rejects before any native
                    // or TLS owner allocation. This is an admission decision.
                    if(!connection)return static_cast<Session*>(nullptr);
                    entry.emplace(listener,registry,owner,peer,std::move(*connection));auto parameters=TransportProfile<Streams,Window>::parameters(listener.options_);
                    auto settings=TransportProfile<Streams,Window>::settings(listener.options_);
                    if(!parameters || !settings){entry.reset();return std::unexpected(n::err_invalid_argument);}
                    n::ngtcp2_cid_init(&parameters->original_dcid,verified.original.data.data(),verified.original.size);parameters->original_dcid_present=1;
                    parameters->retry_scid=initial.dcid;parameters->retry_scid_present=1;
                    settings->token=initial.token;settings->tokenlen=initial.tokenlen;settings->token_type=n::NGTCP2_TOKEN_TYPE_RETRY;
                    n::ngtcp2_cid cid{};n::ngtcp2_cid_init(&cid,source.data(),source.size());
                    auto code=entry->session.start(true,initial.scid,cid,peer,*settings,*parameters,entry->memory.transport(),now);
                    if(code){entry->session.request_stop();entry->session.stop();entry->session.drain();listener.clean_&=!entry->memory.used() && entry->app.clean();if((code==n::err_nomem || code==n::err_callback_failure) && !listener.initialization_failure_)listener.initialization_failure_=InitializationFailure{owner,code};entry.reset();return std::unexpected(code);}
                    if constexpr(requires{listener.hooks_.opened(owner,peer,entry->connection);})listener.hooks_.opened(owner,peer,entry->connection);
                    listener.work_.set();return &entry->session;
                }catch(std::bad_alloc const&){if(!listener.initialization_failure_)listener.initialization_failure_=InitializationFailure{owner,n::err_nomem};bundles[owner.slot].reset();return std::unexpected(n::err_nomem);}
                catch(...){if(!listener.initialization_failure_)listener.initialization_failure_=InitializationFailure{owner,n::err_callback_failure};bundles[owner.slot].reset();return std::unexpected(n::err_callback_failure);}
            }
            auto application_drained(quic::SessionHandle owner,Session const&) const noexcept -> bool {
                if(!bundles[owner.slot] || bundles[owner.slot]->business)return false;
                if constexpr(requires{listener.hooks_.drained(owner);})return listener.hooks_.drained(owner);
                return true;
            }
            // Native callbacks only close a gate and wake maintenance. Business
            // cancellation and native destruction happen after callbacks return.
            auto failed(quic::SessionHandle owner,int code) noexcept -> void {auto& entry=bundles[owner.slot];if(entry && !entry->failure)entry->failure=code;listener.work_.set();}
            auto destroy(quic::SessionHandle owner,Session&) noexcept -> void {
                auto& entry=bundles[owner.slot];listener.clean_&=entry && !entry->business && !entry->memory.used() && entry->app.clean() && !entry->session.transport().key_slots();
                if constexpr(requires{listener.hooks_.closed(owner,entry->failure);}){static_assert(noexcept(listener.hooks_.closed(owner,entry->failure)));listener.hooks_.closed(owner,entry->failure);}
                entry.reset();listener.work_.set();
            }
        };
        using Port=quic::DatagramPort<Factory,Sessions,8,8,true>;
    public:
        using Driver=net::DatagramDriver<SalamanderPort<Port>>;
        using Channel=TcpChannel<App,Driver>;
        class Request {
            Listener& listener_;Bundle& bundle_;StreamHandle stream_;
        public:
            Channel channel;
            Request(Listener& listener,Bundle& bundle,StreamHandle stream) noexcept
                :listener_(listener),bundle_(bundle),stream_(stream),channel(bundle.app,listener.driver_,stream){}
            auto address() const noexcept -> std::string_view {return bundle_.app.address(stream_);}
            auto peer() const noexcept -> corosio::endpoint const& {return bundle_.peer;}
            auto user() const noexcept -> std::optional<std::size_t> {return bundle_.policy.user;}
            auto connection() noexcept -> ConnectionState& {return bundle_.connection;}
            auto stop_token() const noexcept -> std::stop_token {return bundle_.stop.get_token();}
            auto respond(TcpStatus status,std::string_view message={}) -> bool {
                auto result=bundle_.app.respond(stream_,status,message);listener_.driver_.notify();return result.has_value();
            }
        };
        class MasqueradeRequest {
            Listener& listener_;Bundle& bundle_;StreamHandle stream_;
        public:
            MasqueradeRequest(Listener& listener,Bundle& bundle,StreamHandle stream) noexcept
                :listener_(listener),bundle_(bundle),stream_(stream){}
            auto headers() const noexcept -> std::span<http::HeaderField const> {return bundle_.app.http3_request_headers(stream_);}
            auto stop_token() const noexcept -> std::stop_token {return bundle_.stop.get_token();}
            auto respond(std::uint16_t status,std::span<std::pair<std::string,std::string> const> extra_headers,
                std::vector<std::uint8_t> body,bool omit_body=false) -> bool {
                auto ok=bundle_.app.respond_http3(stream_,status,extra_headers,std::move(body),omit_body);
                listener_.driver_.notify();return ok;
            }
        };
    private:
        corosio::io_context& context_;Hooks& hooks_;tls::ServerCredential const& credential_;TransportOptions options_;
        corosio::udp_socket socket_;corosio::endpoint local_;capy::async_event work_;
        Factory factory_;Port port_;SalamanderPort<Port> wire_;Driver driver_;std::stop_source stop_;
        std::optional<InitializationFailure> initialization_failure_;std::optional<RuntimeFailure> runtime_failure_;
        std::size_t business_=0;bool prepared_=false,started_=false,driver_root_=false,stopped_=false,monitor_=false,clean_=true;
        // This guard lives in the existing completion handler's closure.
        // Its destructor also runs when a scheduled root is canceled before
        // the generic driver first resumes. The awaited driver is already
        // destroyed before handler parameters retire: no extra coroutine.
        struct DriverRoot {
            Listener* listener;
            explicit DriverRoot(Listener& listener) noexcept:listener(&listener){listener.driver_root_=true;}
            DriverRoot(DriverRoot const&)=delete;
            DriverRoot(DriverRoot&& other) noexcept:listener(std::exchange(other.listener,nullptr)){}
            ~DriverRoot(){if(listener){listener->stop();listener->driver_root_=false;listener->port_.stop();listener->port_.drain();listener->work_.set();}}
        };
        struct Business {
            Listener* listener;Bundle* bundle;StreamHandle stream;
            Business(Listener& listener,Bundle& bundle,StreamHandle stream) noexcept:listener(&listener),bundle(&bundle),stream(stream){++bundle.business;++listener.business_;}
            Business(Business const&)=delete;
            Business(Business&& other) noexcept:listener(std::exchange(other.listener,nullptr)),bundle(other.bundle),stream(other.stream){}
            ~Business(){if(listener){--bundle->business;--listener->business_;listener->work_.set();}}
        };
        struct Monitor {
            Listener* listener;
            explicit Monitor(Listener& listener) noexcept:listener(&listener){}
            Monitor(Monitor const&)=delete;Monitor(Monitor&& other) noexcept:listener(std::exchange(other.listener,nullptr)){}
            ~Monitor(){if(listener){listener->stop();listener->monitor_=false;listener->port_.drain();}}
        };
        auto failed(std::exception_ptr exception) noexcept -> void {
            if(!runtime_failure_){
                auto kind=RuntimeFailure::Kind::callback;
                try{std::rethrow_exception(exception);}catch(std::bad_alloc const&){kind=RuntimeFailure::Kind::allocation;}catch(...){}
                runtime_failure_=RuntimeFailure{kind,std::move(exception)};
            }
            clean_=false;stop();
        }
        static auto serve(Business lifetime) -> capy::task<> {
            auto& owner=*lifetime.listener;Request request(owner,*lifetime.bundle,lifetime.stream);
            co_await owner.hooks_.serve(request);
        }
        static auto serve_masquerade(Business lifetime) -> capy::task<> {
            auto& owner=*lifetime.listener;
            if constexpr (requires(MasqueradeRequest& r) { owner.hooks_.serve_masquerade(r); }) {
                MasqueradeRequest request(owner,*lifetime.bundle,lifetime.stream);
                co_await owner.hooks_.serve_masquerade(request);
            }
            co_return;
        }
        static auto maintain(Monitor lifetime) -> capy::task<> {
            auto& owner=*lifetime.listener;
            while(!owner.stopped_){
                owner.work_.clear();
                for(auto& entry:owner.factory_.bundles)if(entry){
                    if(entry->session.stopping()){
                        if(!entry->canceled){entry->canceled=true;entry->stop.request_stop();if constexpr(requires{owner.hooks_.stopping(entry->owner);})owner.hooks_.stopping(entry->owner);}
                        continue;
                    }
                    while(auto pending=entry->app.pending()){
                        if(!entry->app.claim(*pending))break;
                        auto handle=*pending;
                        try {
                            capy::run_async(owner.context_.get_executor(),entry->stop.get_token(),[] {},
                                [parent=&owner,bundle=&*entry,handle](std::exception_ptr) noexcept {
                                    (void)bundle->app.reset(handle);parent->driver_.notify();parent->work_.set();
                                })(serve(Business(owner,*entry,handle)));
                        }catch(...){(void)entry->app.reset(handle);throw;}
                    }
                    if constexpr (requires(MasqueradeRequest& r) { owner.hooks_.serve_masquerade(r); }) {
                        while(auto pending=entry->app.pending_masquerade()){
                            if(!entry->app.claim_masquerade(*pending))break;
                            auto handle=*pending;
                            try {
                                capy::run_async(owner.context_.get_executor(),entry->stop.get_token(),
                                    [parent=&owner,bundle=&*entry,handle]() noexcept {
                                        bundle->app.finish_masquerade(handle);parent->driver_.notify();parent->work_.set();
                                    },
                                    [parent=&owner,bundle=&*entry,handle](std::exception_ptr) noexcept {
                                        bundle->app.finish_masquerade(handle);parent->driver_.notify();parent->work_.set();
                                    })(serve_masquerade(Business(owner,*entry,handle)));
                            }catch(...){entry->app.finish_masquerade(handle);throw;}
                        }
                    }
                }
                owner.port_.maintain();owner.driver_.notify();
                auto [error]=co_await owner.work_.wait();if(error)break;
            }
        }
    public:
        using PrepareFailure=std::variant<std::error_code,quic::RetryFailure>;
        Listener(corosio::io_context& context,Hooks& hooks,tls::ServerCredential const& credential,TransportOptions options={})
            :context_(context),hooks_(hooks),credential_(credential),options_(options),socket_(context),factory_(*this),port_(factory_),wire_(port_,options_.salamander_password),driver_(socket_,wire_){
            if(!options.valid())throw std::invalid_argument("invalid Hysteria2 transport options");
        }
        Listener(Listener const&)=delete;auto operator=(Listener const&) -> Listener& = delete;
        ~Listener(){stop();port_.drain();if(!drained())std::terminate();}
        auto prepare(corosio::endpoint local,bool reuse=false) -> std::expected<corosio::endpoint,PrepareFailure> {
            if(prepared_ || started_ || stopped_)return std::unexpected(PrepareFailure{std::make_error_code(std::errc::operation_not_permitted)});
            auto key=factory_.retry.initialize();if(!key){factory_.error=key.error();stop();return std::unexpected(PrepareFailure{key.error()});}
            if(auto error=socket_.open(local.address().family())){stop();return std::unexpected(PrepareFailure{error});}
            if(local.address().is_v6())if(auto error=socket_.set_option(corosio::socket_option::v6_only(true))){stop();return std::unexpected(PrepareFailure{error});}
            if(reuse)if(auto error=socket_.set_option(corosio::socket_option::reuse_port(true))){stop();return std::unexpected(PrepareFailure{error});}
            if(auto error=socket_.bind(local)){stop();return std::unexpected(PrepareFailure{error});}
            local_=socket_.local_endpoint();prepared_=true;return local_;
        }
        auto start() -> void {
            if(!prepared_ || started_ || stopped_)throw std::logic_error("Hysteria2 listener cannot start");
            started_=monitor_=true;
            try {
                capy::run_async(context_.get_executor(),stop_.get_token(),[lifetime=DriverRoot(*this)](auto) noexcept{},[this](std::exception_ptr exception) noexcept{failed(std::move(exception));})(driver_.run());
                capy::run_async(context_.get_executor(),stop_.get_token(),[] {},[this](std::exception_ptr exception) noexcept{failed(std::move(exception));})(maintain(Monitor(*this)));
            }catch(...){monitor_=false;stop();if(!driver_root_)port_.stop();throw;}
        }
        auto begin_shutdown() noexcept -> void {
            for(auto& entry:factory_.bundles)if(entry && !entry->canceled){entry->canceled=true;entry->stop.request_stop();if constexpr(requires{hooks_.stopping(entry->owner);})hooks_.stopping(entry->owner);}
            port_.begin_shutdown();driver_.notify();work_.set();
        }
        auto shutdown_drained() const noexcept -> bool {return port_.quiescent();}
        auto shutdown_failure() const noexcept -> std::optional<int> const& {return port_.shutdown_failure();}
        auto shutdown_unsent() const noexcept -> bool {return port_.shutdown_unsent();}
        auto stop() noexcept -> void {
            if(!std::exchange(stopped_,true)){
                for(auto& entry:factory_.bundles)if(entry && !entry->canceled){entry->canceled=true;entry->stop.request_stop();if constexpr(requires{hooks_.stopping(entry->owner);})hooks_.stopping(entry->owner);}
                driver_.finish();if(!started_)port_.stop();stop_.request_stop();work_.set();
            }
        }
        auto maintain() noexcept -> void {port_.maintain();}
        auto notify() noexcept -> void {driver_.notify();}
        auto physical_live(quic::SessionHandle owner) noexcept -> bool {return port_.active(owner);}
        auto datagram_budget(quic::SessionHandle owner) noexcept -> std::size_t {
            if(owner.slot>=Sessions)return 0;auto& entry=factory_.bundles[owner.slot];
            return entry && entry->owner==owner ? entry->app.datagram_budget() : 0;
        }
        auto size() const noexcept -> std::size_t {return port_.size();}
        auto business() const noexcept -> std::size_t {return business_;}
        auto clean() const noexcept -> bool {return clean_;}
        auto drained() const noexcept -> bool {return stopped_ && !monitor_ && !business_ && !driver_root_ && port_.drained();}
        auto failure() const noexcept -> auto const& {return driver_.failure();}
        auto initialization_failure() const noexcept -> auto const& {return initialization_failure_;}
        auto runtime_failure() const noexcept -> auto const& {return runtime_failure_;}
        // Configure before start. During natural context abandonment the host
        // may move this handle into its shutdown scope before releasing the
        // context; the listener and its native owners stay alive until tasks
        // are destroyed, exactly as when the generic driver borrows a socket.
        auto transport_socket() noexcept -> corosio::udp_socket& {return socket_;}
    };
}
