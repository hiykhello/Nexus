module;
#ifdef NEXUS_TEST_MASQUE_LISTENER_START
extern "C" void nexus_test_masque_listener_start(unsigned);
#endif
export module masque.listener;
import std;
import relay;
import relay.session_quota;
import net.udp_socket;
import masque.host;
import masque.config;
import masque.ip_server;
import net.datagram_driver;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.native_memory;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import hysteria2.transport_options;
import dns.local_config;
import tls.ech_server;
import tls.server_credential;
import ngtcp2;
import capy;
import corosio;

export namespace masque {
    // Concrete per-executor production listener. A shared QUIC port handles
    // Retry/CID routing; each admitted connection owns its host and joins all
    // DNS/readiness roots before native QUIC and HTTP3 storage can retire.
    template<std::size_t Sessions=32,std::size_t Streams=16,std::size_t Window=16384> class Listener {
        using Clock=std::chrono::steady_clock;
        using Registry=quic::CidRegistry<Sessions,8>;
        using Host=ServerHost<quic::TlsServer,Streams>;
        using NativeSession=quic::DatagramSession<quic::TlsServer,typename Host::ServerType::Application>;
        struct Bundle {
            Listener& listener;Registry& registry;quic::SessionHandle owner;
            struct Flow {
                std::int64_t stream;
                relay::SessionQuota::Lease quota;
                relay::TrafficRegistration traffic;
            };
            net::UdpEndpoint source;
            std::array<std::optional<Flow>,Streams> flows;
            quic::TlsServer tls;quic::NativeMemory<> memory;Host host;NativeSession session;

            static auto source_endpoint(corosio::endpoint const& endpoint) -> net::UdpEndpoint {
                auto address=endpoint.address();
                net::UdpEndpoint peer{address.is_v4() ? std::uint8_t{4} : std::uint8_t{6},{},endpoint.port()};
                if (address.is_v4()) {
                    auto bytes=address.to_v4().to_bytes();
                    std::ranges::copy(bytes,peer.address.begin());
                } else peer.address=address.to_v6().to_bytes();
                return peer;
            }
            auto find_flow(std::int64_t stream) noexcept {
                return std::ranges::find_if(flows,[&](auto const& slot) {return slot && slot->stream==stream;});
            }
            auto open_flow(std::int64_t stream,std::uint16_t port,bool ip) -> bool {
                auto slot=std::ranges::find_if(flows,[](auto const& item) {return !item;});
                auto lease=listener.accounting_->acquire_session();
                if (slot==flows.end() || !lease) return false;
                auto protocol=ip ? relay::TrafficProtocol::masque_ip : relay::TrafficProtocol::masque_udp;
                auto traffic=listener.accounting_->track_traffic(protocol,relay::ConnectPath::datagrams,source,port,true);
                slot->emplace(Flow{stream,std::move(*lease),std::move(traffic)});
                return true;
            }
            Bundle(Listener& parent,Registry& table,quic::SessionHandle id,corosio::endpoint const& peer,std::optional<tls::ServerCredential>&& dynamic_credential)
                :listener(parent),registry(table),owner(id),source(source_endpoint(peer)),tls(std::move(dynamic_credential),parent.credential_,"h3",parent.ech_keys_),memory(parent.config_.native_bytes),
                 host(parent.context_,tls,parent.config_,parent.snapshots_,memory.http3(),[&parent]() {parent.notify();},parent.ip_port_),
                 session(tls,host.server().application(),parent.local_) {
                if (parent.accounting_) host.server().observe_traffic({this,
                    [](void* data,std::int64_t stream,std::uint16_t port,bool ip) {
                        return static_cast<Bundle*>(data)->open_flow(stream,port,ip);
                    },
                    [](void* data,std::int64_t stream,bool upstream,std::size_t bytes) noexcept {
                        auto& self=*static_cast<Bundle*>(data);
                        auto flow=self.find_flow(stream);
                        if (flow!=self.flows.end()) (*flow)->traffic.count(upstream,bytes);
                    },
                    [](void* data,std::int64_t stream) noexcept {
                        auto& self=*static_cast<Bundle*>(data);
                        auto flow=self.find_flow(stream);
                        if (flow!=self.flows.end()) flow->reset();
                    }});
                host.cid_callbacks(this,[](void* raw,std::span<std::uint8_t const> id) noexcept -> bool {
                    auto& self=*static_cast<Bundle*>(raw);return self.registry.insert(self.owner,id).has_value();
                },[](void* raw,std::span<std::uint8_t const> id) noexcept {
                    auto& self=*static_cast<Bundle*>(raw);(void)self.registry.remove(self.owner,id);
                });
            }
        };
        struct Factory {
            using Session=NativeSession;using ControlFailure=quic::RetryFailure;
            Listener& listener;quic::RetryAdmission<> retry;std::optional<quic::RetryClaims> permit;std::optional<ControlFailure> error;
            std::array<std::optional<Bundle>,Sessions> bundles;
            std::array<bool,Sessions> orphan{};
            explicit Factory(Listener& owner) noexcept:listener(owner) {}
            auto admit(ngtcp2::ngtcp2_pkt_hd const& initial,corosio::endpoint const& peer,Clock::time_point now,std::size_t bytes) noexcept -> bool {
                permit.reset();auto result=retry.inspect(initial,peer,now,bytes);if(!result){if(!error)error=result.error();return false;}permit=*result;return permit.has_value();
            }
            auto control_failure() const noexcept {return error;}
            auto control_output(std::span<std::uint8_t> bytes,Clock::time_point now) noexcept -> std::expected<std::optional<net::DatagramOutput>,ControlFailure> {if(error)return std::unexpected(*error);return retry.output(bytes,now);}
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
                    std::optional<tls::ServerCredential> dyn_cred;
                    if(listener.atomic_credential_) {
                        auto cur=listener.atomic_credential_->clone_current();
                        if(!cur)return std::unexpected(n::err_callback_failure);
                        dyn_cred.emplace(std::move(*cur));
                    } else if(!listener.credential_)return std::unexpected(n::err_callback_failure);
                    entry.emplace(listener,registry,owner,peer,std::move(dyn_cred));
                    hysteria2::TransportOptions options;options.native_bytes=listener.config_.native_bytes;
                    auto params=hysteria2::TransportProfile<Streams,Window>::parameters(options);
                    auto settings=hysteria2::TransportProfile<Streams,Window>::settings(options);
                    if(!params || !settings){entry.reset();return std::unexpected(n::err_invalid_argument);}
                    n::ngtcp2_cid_init(&params->original_dcid,verified.original.data.data(),verified.original.size);params->original_dcid_present=1;
                    params->retry_scid=initial.dcid;params->retry_scid_present=1;
                    settings->token=initial.token;settings->tokenlen=initial.tokenlen;settings->token_type=n::NGTCP2_TOKEN_TYPE_RETRY;
                    n::ngtcp2_cid cid{};n::ngtcp2_cid_init(&cid,source.data(),source.size());
                    auto code=entry->session.start(true,initial.scid,cid,peer,*settings,*params,entry->memory.transport(),now);
                    if(code){entry->host.stop();entry->session.stop();entry->session.drain();entry.reset();return std::unexpected(code);}
                    if(listener.ip_withdrawing_)entry->host.server().withdraw_ip();
                    entry->host.start();listener.notify();return &entry->session;
                }catch(...) {
                    listener.failed_=true;auto& entry=bundles[owner.slot];
                    if(entry){entry->host.stop();orphan[owner.slot]=true;listener.changed_.set();}
                    return std::unexpected(n::err_callback_failure);
                }
            }
            auto maintain_orphans() noexcept -> void {
                for(std::size_t i=0;i<Sessions;++i)if(orphan[i] && bundles[i] && bundles[i]->host.drained()) {
                    auto& entry=*bundles[i];entry.session.stop();entry.session.drain();
                    listener.clean_&=entry.host.clean() && !entry.memory.used();bundles[i].reset();orphan[i]=false;
                }
            }
            auto has_orphans() const noexcept -> bool {return std::ranges::any_of(orphan,[](bool value){return value;});}
            auto application_drained(quic::SessionHandle owner,Session const&) const noexcept -> bool {auto const& e=bundles[owner.slot];return e && e->host.drained();}
            auto failed(quic::SessionHandle owner,int) noexcept -> void {auto& e=bundles[owner.slot];if(e)e->host.stop();listener.notify();}
            auto destroy(quic::SessionHandle owner,Session&) noexcept -> void {auto& e=bundles[owner.slot];listener.clean_&=e && e->host.clean() && !e->memory.used();e.reset();listener.notify();}
        };
        using Port=quic::DatagramPort<Factory,Sessions,8,8,true>;
        using Driver=net::DatagramDriver<Port>;
        corosio::io_context& context_;HostConfig const& config_;tls::ServerCredential const* credential_=nullptr;
        std::shared_ptr<tls::AtomicServerCredential> atomic_credential_{};
        std::shared_ptr<tls::EchServerKeys const> ech_keys_{};
        dns::LocalSnapshotSource& snapshots_;
        IpServerPort* ip_port_;
        relay::Server* accounting_;
        bool ip_withdrawing_=false;
        corosio::udp_socket socket_;corosio::endpoint local_;Factory factory_;Port port_;Driver driver_;capy::async_event changed_;
        std::stop_source stop_;bool prepared_=false,started_=false,stopped_=false,root_=false,monitor_=false,failed_=false,clean_=true;
        auto monitor() -> capy::task<> {
            while(true) {
                changed_.clear();
                for(auto& entry:factory_.bundles)if(entry && entry->session.stopping())entry->host.stop();
                factory_.maintain_orphans();port_.maintain();
                if(stopped_ && !root_ && port_.drained() && !factory_.has_orphans())break;
                auto [error]=co_await changed_.wait();if(error && !stopped_){failed_=true;stop();}
            }
        }
        struct Root {
            Listener* owner;explicit Root(Listener& value) noexcept:owner(&value){owner->root_=true;}
            Root(Root const&)=delete;Root(Root&& other) noexcept:owner(std::exchange(other.owner,nullptr)){}
            ~Root(){if(owner){owner->stop();owner->root_=false;owner->port_.stop();owner->port_.drain();owner->changed_.set();}}
        };
    public:
        Listener(corosio::io_context& context,HostConfig const& config,tls::ServerCredential const* credential,
            std::shared_ptr<tls::AtomicServerCredential> atomic_credential,dns::LocalSnapshotSource& snapshots,
            IpServerPort* ip_port=nullptr,relay::Server* accounting=nullptr,std::shared_ptr<tls::EchServerKeys const> ech_keys={})
            :context_(context),config_(config),credential_(credential),atomic_credential_(std::move(atomic_credential)),
             ech_keys_(std::move(ech_keys)),snapshots_(snapshots),ip_port_(ip_port),accounting_(accounting),socket_(context),factory_(*this),port_(factory_),driver_(socket_,port_) {
            if(!config.valid(ip_port!=nullptr))throw std::invalid_argument("invalid MASQUE listener config");
        }
        Listener(corosio::io_context& context,HostConfig const& config,tls::ServerCredential const& credential,dns::LocalSnapshotSource& snapshots,IpServerPort* ip_port=nullptr,relay::Server* accounting=nullptr,std::shared_ptr<tls::EchServerKeys const> ech_keys={})
            :Listener(context,config,&credential,{},snapshots,ip_port,accounting,std::move(ech_keys)) {}
        Listener(corosio::io_context& context,HostConfig const& config,std::shared_ptr<tls::AtomicServerCredential> atomic_credential,dns::LocalSnapshotSource& snapshots,IpServerPort* ip_port=nullptr,relay::Server* accounting=nullptr,std::shared_ptr<tls::EchServerKeys const> ech_keys={})
            :Listener(context,config,nullptr,std::move(atomic_credential),snapshots,ip_port,accounting,std::move(ech_keys)) {}
        Listener(Listener const&)=delete;auto operator=(Listener const&) -> Listener& = delete;
        ~Listener(){stop();port_.drain();if(!drained())std::terminate();}
        auto process_traffic_closes() -> bool {
            if (stopped_) return true;
            for (std::size_t i = 0; i < Sessions; ++i) {
                if (factory_.orphan[i]) continue;
                auto& entry = factory_.bundles[i];
                if (!entry || entry->session.stopping()) continue;
                for (auto& flow : entry->flows) if (flow && flow->traffic.close_requested()) {
                    auto id = flow->stream;
                    if (!entry->host.server().close_stream(id)) {
                        entry->session.request_stop();
                        break;
                    }
                }
            }
            return true;
        }
        auto prepare(corosio::endpoint local,bool reuse=false) -> std::expected<corosio::endpoint,std::error_code> {
            if(prepared_ || stopped_)return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
            if(!factory_.retry.initialize()) {stop();return std::unexpected(std::make_error_code(std::errc::io_error));}
            if(auto error=socket_.open(local.address().family()))return std::unexpected(error);
            if(local.address().is_v6())if(auto error=socket_.set_option(corosio::socket_option::v6_only(true)))return std::unexpected(error);
            if(reuse)if(auto error=socket_.set_option(corosio::socket_option::reuse_port(true)))return std::unexpected(error);
            if(auto error=socket_.bind(local))return std::unexpected(error);local_=socket_.local_endpoint();prepared_=true;return local_;
        }
        auto notify() noexcept -> void {driver_.notify();changed_.set();}
        auto start() -> void {
            if(!prepared_ || started_ || stopped_)throw std::logic_error("MASQUE listener cannot start");started_=true;
            bool monitor_launched=false;
            try {
                monitor_=true;
#ifdef NEXUS_TEST_MASQUE_LISTENER_START
                nexus_test_masque_listener_start(0);
#endif
                capy::run_async(context_.get_executor(),[this]() noexcept {monitor_=false;changed_.set();},
                    [this](std::exception_ptr) noexcept {monitor_=false;failed_=true;stop();})(monitor());
                monitor_launched=true;
#ifdef NEXUS_TEST_MASQUE_LISTENER_START
                nexus_test_masque_listener_start(1);
#endif
                capy::run_async(context_.get_executor(),stop_.get_token(),[guard=Root(*this)](auto) noexcept {},
                    [this](std::exception_ptr) noexcept {failed_=true;stop();})(driver_.run());
            }catch(...) {if(!monitor_launched)monitor_=false;stop();if(!root_)port_.stop();changed_.set();throw;}
        }
        auto stop() noexcept -> void {
            if(std::exchange(stopped_,true))return;
            for(auto& entry:factory_.bundles)if(entry)entry->host.stop();
            driver_.finish();if(!started_)port_.stop();stop_.request_stop();changed_.set();
        }
        auto maintain() noexcept -> void {port_.maintain();}
        auto poll_ip() -> void {
            if(!ip_port_ || stopped_)return;
            for(std::size_t i=0;i<Sessions;++i)if(!factory_.orphan[i] && factory_.bundles[i] && !factory_.bundles[i]->session.stopping()) {
                auto& entry=factory_.bundles[i];
                if(ip_withdrawing_)entry->host.server().withdraw_ip();
                if(!entry->host.server().poll_ip())entry->session.request_stop();
            }
        }
        auto withdraw_ip() noexcept -> void {ip_withdrawing_=true;}
        auto drained() const noexcept -> bool {return stopped_ && !root_ && !monitor_ && port_.drained() && !factory_.has_orphans();}
        auto clean() const noexcept -> bool {return clean_;}
        auto failed() const noexcept -> bool {return failed_ || driver_.failure().has_value() || (ip_port_ && *ip_port_ && !(*ip_port_)->healthy());}
        auto sessions() const noexcept -> std::size_t {return port_.size();}
    };
}
