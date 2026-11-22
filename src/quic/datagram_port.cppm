export module quic.datagram_port;
import std;
import crypto;
import net.datagram_driver;
import quic.cid_registry;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.corosio;

export namespace quic {
    enum class DatagramPortError { state,random,exhausted,invalid_output,invalid_token };
    template<class Factory,class=void>struct DatagramPortFailure {using type=DatagramPortError;};
    template<class Factory>struct DatagramPortFailure<Factory,std::void_t<typename Factory::ControlFailure>> {
        using type=std::variant<DatagramPortError,typename Factory::ControlFailure>;
    };
    template<class Failure,bool Enabled> struct GracefulFailureState {};
    template<class Failure> struct GracefulFailureState<Failure,true> {std::optional<Failure> failure;};
    // A single generic UDP driver supplies all I/O. Factory retains concrete
    // sessions and their application roots; this port stores routing/pin state,
    // never erased owner bytes or a per-session forwarding coroutine.
    template<class Factory,std::size_t Capacity=64,std::size_t IdsPerSession=8,std::size_t ShortCidBytes=8,bool Graceful=false>
    class DatagramPort {
        static_assert(ShortCidBytes>=8 && ShortCidBytes<=20);
    public:
        using Registry=CidRegistry<Capacity,IdsPerSession>;
        using Session=typename Factory::Session;
        using Failure=typename DatagramPortFailure<Factory>::type;
    private:
        struct Slot { Session* session=nullptr;SessionHandle owner;bool retiring=false,close_started=false; };
        struct Pending { SessionHandle owner;std::uint64_t session_token,token; };
        Factory& factory_;
        Registry registry_;
        std::array<Slot,Capacity> slots_{};
        std::optional<Pending> pending_;
        [[no_unique_address]] GracefulFailureState<typename Session::Failure,Graceful> shutdown_failure_;
        std::uint64_t token_=0;
        std::size_t cursor_=0;
        bool busy_=false,stopped_=false,joined_=false,quiescing_=false,shutdown_unsent_=false;
        struct Call {
            DatagramPort& owner;
            ~Call(){owner.busy_=false;owner.maintain();}
        };
        auto slot(SessionHandle owner) noexcept -> Slot* {
            if(!registry_.live(owner) || !slots_[owner.slot].session || slots_[owner.slot].owner!=owner)return nullptr;
            return &slots_[owner.slot];
        }
        auto retire(Slot& entry) noexcept -> void {
            if(std::exchange(entry.retiring,true))return;
            static_assert(noexcept(entry.session->request_stop()));entry.session->request_stop();
        }
        auto failed(Slot& entry,typename Session::Failure failure) noexcept -> void {
            static_assert(noexcept(factory_.failed(entry.owner,failure)));
            factory_.failed(entry.owner,failure);retire(entry);
        }
        auto enter() noexcept -> bool {if(busy_)return false;busy_=true;return true;}
    public:
        explicit DatagramPort(Factory& factory) noexcept:factory_(factory){}
        DatagramPort(DatagramPort const&)=delete;
        auto operator=(DatagramPort const&) -> DatagramPort& = delete;
        ~DatagramPort(){request_stop();if(registry_.size() || pending_)std::terminate();}
        auto registry() noexcept -> Registry& {return registry_;}
        auto size() const noexcept -> std::size_t {return registry_.size();}
        auto live(SessionHandle owner) const noexcept -> bool {return registry_.live(owner);}
        auto pinned(SessionHandle owner) const noexcept -> bool {return pending_ && pending_->owner==owner;}
        auto active(SessionHandle owner) noexcept -> bool {auto* entry=slot(owner);return entry && !entry->retiring && !stopped_ && (!Graceful || !quiescing_);}
        // Outgoing clients reserve/register their CID before attachment, then
        // use the same shared socket and native CID routing as admitted peers.
        auto attach(SessionHandle owner,Session& session) noexcept -> bool {
            if(stopped_ || (Graceful && quiescing_) || busy_ || !registry_.live(owner) || slots_[owner.slot].session)return false;
            slots_[owner.slot]={&session,owner,false};return true;
        }
        auto request_retire(SessionHandle owner) noexcept -> bool {
            auto* entry=slot(owner);if(!entry)return false;retire(*entry);return true;
        }
        // Call only at a port maintenance boundary, after application task
        // roots have joined. Native callback stacks cannot run this method.
        // A sealed packet pins its session from output return until actual
        // transmitted or until global joined cancellation clears that pin.
        auto maintain() noexcept -> void {
            if(busy_ || (stopped_ && !joined_))return;
            busy_=true;struct Guard{bool& busy;~Guard(){busy=false;}}guard{busy_};
            for(auto& entry:slots_)if(entry.session && entry.retiring && !pinned(entry.owner)){
                static_assert(noexcept(factory_.application_drained(entry.owner,*entry.session)));
                if(!factory_.application_drained(entry.owner,*entry.session))continue;
                static_assert(noexcept(entry.session->stop()) && noexcept(entry.session->drain()) && noexcept(factory_.destroy(entry.owner,*entry.session)));
                entry.session->stop();entry.session->drain();
                // Invalid routing/generation state precedes object reuse.
                registry_.release(entry.owner);auto* session=std::exchange(entry.session,nullptr);factory_.destroy(entry.owner,*session);entry={};
            }
        }
        // Graceful shutdown keeps the UDP driver alive until one authenticated
        // close packet per live connection is actually sent, or its caller
        // invokes request_stop on deadline/error. Business is canceled first.
        auto begin_shutdown() noexcept -> void requires (Graceful && requires(Session& session,std::span<std::uint8_t> bytes,net::DatagramClock::time_point now) {session.close_output(bytes,now);}) {
            if(stopped_ || std::exchange(quiescing_,true))return;
            if constexpr(requires{factory_.control_request_stop();})factory_.control_request_stop();
            for(auto& entry:slots_)if(entry.session && !entry.retiring)entry.session->request_stop();
        }
        auto quiescent() const noexcept -> bool requires Graceful {return quiescing_ && !registry_.size() && !pending_;}
        auto shutdown_failure() const noexcept -> std::optional<typename Session::Failure> const& requires Graceful {return shutdown_failure_.failure;}
        auto shutdown_unsent() const noexcept -> bool requires Graceful {return shutdown_unsent_;}
        auto request_stop() noexcept -> void {
            if(std::exchange(stopped_,true))return;
            if constexpr(requires{factory_.control_request_stop();}){static_assert(noexcept(factory_.control_request_stop()));factory_.control_request_stop();}
            for(auto& entry:slots_)if(entry.session)retire(entry);
        }
        // The generic driver calls these only after its three tasks join.
        // If a business root is still unwinding, native teardown waits for a
        // subsequent maintain()/drain() after that root's join; it never lies
        // about port.drained(), which includes actual factory/native release.
        auto stop() noexcept -> void {
            joined_=true;pending_.reset();
            if constexpr(requires{factory_.control_stop();}){static_assert(noexcept(factory_.control_stop()));factory_.control_stop();}
            maintain();
        }
        auto drain() noexcept -> void {maintain();}
        auto drained() const noexcept -> bool {
            if constexpr(requires{factory_.control_drained();})if(!factory_.control_drained())return false;
            return stopped_ && joined_ && !registry_.size() && !pending_;
        }
        auto receive(nex::corosio::endpoint const& peer,std::span<std::uint8_t const> bytes,net::DatagramClock::time_point now) -> std::expected<void,Failure> {
            if(stopped_ || (Graceful && quiescing_))return {};
            if(!enter())return std::unexpected(Failure{DatagramPortError::state});Call call{*this};
            nex::ngtcp2::ngtcp2_version_cid parsed{};
            if(nex::ngtcp2::ngtcp2_pkt_decode_version_cid(&parsed,bytes.data(),bytes.size(),ShortCidBytes))return {};
            auto found=registry_.find({parsed.dcid,parsed.dcidlen});Slot* entry=found?slot(*found):nullptr;
            if(!entry){
                nex::ngtcp2::ngtcp2_pkt_hd initial{};
                if(bytes.size()<1200 || parsed.version!=nex::ngtcp2::proto_ver_v1 || nex::ngtcp2::ngtcp2_accept(&initial,bytes.data(),bytes.size()))return {};
                if constexpr(requires{factory_.admit(initial,peer,now,bytes.size());}){
                    static_assert(noexcept(factory_.admit(initial,peer,now,bytes.size())));
                    if(!factory_.admit(initial,peer,now,bytes.size())){
                        if constexpr(requires{factory_.control_failure();})if(auto failure=factory_.control_failure())return std::unexpected(Failure{*failure});
                        return {};
                    }
                }else{
                    static_assert(noexcept(factory_.admit(initial,peer,now)));
                    if(!factory_.admit(initial,peer,now))return {};
                }
                auto owner=registry_.reserve();if(!owner)return {};
                std::array<std::uint8_t,ShortCidBytes> source{};
                if(!crypto::random_bytes(source)){registry_.release(*owner);return std::unexpected(Failure{DatagramPortError::random});}
                if(initial.dcid.datalen>20){registry_.release(*owner);return {};}
                auto initial_id=std::span(initial.dcid.data).first(initial.dcid.datalen);
                if(!registry_.insert(*owner,initial_id) || !registry_.insert(*owner,source)){registry_.release(*owner);return {};}
                static_assert(noexcept(factory_.create(*owner,registry_,source,initial,peer,now)));
                auto created=factory_.create(*owner,registry_,source,initial,peer,now);
                if(!created || !*created){registry_.release(*owner);return {};}
                entry=&slots_[owner->slot];*entry={*created,*owner,false};
            }
            if(entry->retiring)return {};
            auto result=entry->session->receive(peer,bytes,now);
            if(!result)failed(*entry,result.error());else if(entry->session->stopping())retire(*entry);
            return {};
        }
        auto output(std::span<std::uint8_t> bytes,net::DatagramClock::time_point now) -> std::expected<std::optional<net::DatagramOutput>,Failure> {
            if(stopped_)return std::optional<net::DatagramOutput>{};
            if(pending_ || !enter())return std::unexpected(Failure{DatagramPortError::state});Call call{*this};
            if constexpr(Graceful)if(quiescing_){
                for(std::size_t count=0;count<Capacity;++count){
                    auto& entry=slots_[cursor_++%Capacity];if(!entry.session || entry.retiring || entry.close_started)continue;
                    entry.close_started=true;auto packet=entry.session->close_output(bytes,now);
                    if(!packet){if(!shutdown_failure_.failure)shutdown_failure_.failure=packet.error();failed(entry,packet.error());continue;}
                    if(!*packet){shutdown_unsent_=true;retire(entry);continue;}
                    if((**packet).size>bytes.size())return std::unexpected(Failure{DatagramPortError::invalid_output});
                    if(token_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(Failure{DatagramPortError::exhausted});
                    pending_=Pending{entry.owner,(**packet).token,++token_};(**packet).token=token_;return *packet;
                }
                return std::optional<net::DatagramOutput>{};
            }
            if constexpr(requires{factory_.control_output(bytes,now);}){
                auto packet=factory_.control_output(bytes,now);
                if(!packet)return std::unexpected(Failure{packet.error()});
                if(*packet){
                    if((**packet).size>bytes.size())return std::unexpected(Failure{DatagramPortError::invalid_output});
                    if(token_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(Failure{DatagramPortError::exhausted});
                    // Generation0 is never a valid native session. It marks
                    // stateless control output without adding an owner field.
                    pending_=Pending{SessionHandle{},(**packet).token,++token_};(**packet).token=token_;return *packet;
                }
            }
            for(std::size_t count=0;count<Capacity;++count){
                auto& entry=slots_[cursor_++%Capacity];if(!entry.session || entry.retiring)continue;
                auto packet=entry.session->output(bytes,now);
                if(!packet){failed(entry,packet.error());continue;}
                if(entry.session->stopping()){retire(entry);continue;}
                if(!*packet)continue;
                if((**packet).size>bytes.size())return std::unexpected(Failure{DatagramPortError::invalid_output});
                if(token_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(Failure{DatagramPortError::exhausted});
                pending_=Pending{entry.owner,(**packet).token,++token_};(**packet).token=token_;
                return *packet;
            }
            return std::optional<net::DatagramOutput>{};
        }
        auto transmitted(std::uint64_t token,net::DatagramClock::time_point now) -> std::expected<void,Failure> {
            if(!pending_ || pending_->token!=token || !enter())return std::unexpected(Failure{DatagramPortError::invalid_token});Call call{*this};
            auto pending=*pending_;
            if constexpr(requires{factory_.control_transmitted(pending.session_token,now);})if(!pending.owner.generation){
                pending_.reset();auto result=factory_.control_transmitted(pending.session_token,now);
                if(!result)return std::unexpected(Failure{result.error()});return {};
            }
            auto* entry=slot(pending.owner);if(!entry)return std::unexpected(Failure{DatagramPortError::invalid_token});
            // Clear the pin only after entering this synchronous callback;
            // maintenance remains barred until the native commit returns.
            pending_.reset();auto result=entry->session->transmitted(pending.session_token,now);
            if(!result)failed(*entry,result.error());else if(entry->session->stopping() && (!Graceful || !quiescing_ || entry->close_started))retire(*entry);
            return {};
        }
        auto mtu_rejected(std::uint64_t token,net::DatagramClock::time_point now) -> std::expected<void,Failure> {
            if(!pending_ || pending_->token!=token || !pending_->owner.generation || !enter())return std::unexpected(Failure{DatagramPortError::invalid_token});Call call{*this};
            auto pending=*pending_;auto* entry=slot(pending.owner);
            if(!entry)return std::unexpected(Failure{DatagramPortError::invalid_token});
            if constexpr(requires {entry->session->mtu_rejected(pending.session_token,now);}) {
                pending_.reset();auto result=entry->session->mtu_rejected(pending.session_token,now);
                if(!result)failed(*entry,result.error());else if(entry->session->stopping() && (!Graceful || !quiescing_ || entry->close_started))retire(*entry);
                return {};
            } else return std::unexpected(Failure{DatagramPortError::invalid_token});
        }
        auto next_expiry() const noexcept -> net::DatagramDeadline {
            net::DatagramDeadline next;
            if constexpr(requires{factory_.control_next_expiry();})next=factory_.control_next_expiry();
            for(auto const& entry:slots_)if(entry.session && !entry.retiring){auto expiry=entry.session->next_expiry();if(expiry && (!next || *expiry<*next))next=expiry;}
            return next;
        }
        auto expire(net::DatagramClock::time_point now) -> std::expected<void,Failure> {
            if(stopped_)return {};
            if(!enter())return std::unexpected(Failure{DatagramPortError::state});Call call{*this};
            if constexpr(requires{factory_.control_expire(now);}){auto result=factory_.control_expire(now);if(!result)return std::unexpected(Failure{result.error()});}
            for(auto& entry:slots_)if(entry.session && !entry.retiring){
                auto next=entry.session->next_expiry();if(!next || *next>now)continue;
                auto result=entry.session->expire(now);if(!result)failed(entry,result.error());else if(entry.session->stopping())retire(entry);
            }return {};
        }
    };
}
