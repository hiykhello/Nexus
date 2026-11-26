module relay.hysteria2_business;
import std;
import relay;
import relay.session_quota;
import relay.principal_limits;
import relay.dns_state;
import hysteria2.udp_receiver;
import hysteria2.udp_transmitter;
import hysteria2.sessions;
import hysteria2.fragments;
import http.connect;
import net.stream_datagrams;
import net.datagram_frame;
import net.udp_socket;
import quic.cid_registry;
import rules;
import ngtcp2;
import capy;
import corosio;
namespace relay {
    namespace h=hysteria2;namespace capy = ::capy;namespace io = ::corosio;using Clock=std::chrono::steady_clock;
    struct Hysteria2Business::UdpOwner {
        struct Slot {
            UdpOwner& owner;h::UdpSessionHandle handle;std::uint32_t id;Session session;bool active=true;
            struct Incoming {
                Slot& slot;
                static constexpr bool accounts_download=true;
                auto send_packet(net::ProxyAddress const& address,std::span<std::uint8_t const> payload)->capy::task<bool> {
                    auto& owner=slot.owner;std::string host;
                    if(address.family==net::ProxyAddressFamily::ipv4){io::ipv4_address::bytes_type bytes{};std::ranges::copy(std::span(address.bytes).first(4),bytes.begin());host=io::ipv4_address(bytes).to_string()+":"+std::to_string(address.port);}
                    else if(address.family==net::ProxyAddressFamily::ipv6){io::ipv6_address::bytes_type bytes{};std::ranges::copy(std::span(address.bytes).first(16),bytes.begin());host="["+io::ipv6_address(bytes).to_string()+"]:"+std::to_string(address.port);}
                    else co_return false;
                    auto deadline=Clock::now()+std::chrono::seconds(10);
                    auto operation=owner.writer.scoped_lock();auto [lock_error,lock]=co_await io::timeout(std::move(operation),deadline);
                    if (lock_error) co_return lock_error==capy::cond::timeout && !session_closed();
                    if (session_closed()) co_return false;
                    auto credit=slot.session.reserve_principal_datagram(false,payload.size());
                    if (!credit) co_return true;
                    auto budget=owner.parent.listener->datagram_budget(owner.physical);
                    auto ticket=owner.outgoing.submit(slot.id,++owner.packet_id,host,payload,budget);
                    if (!ticket) co_return ticket.error()!=h::UdpSendError::exhausted && ticket.error()!=h::UdpSendError::state;
                    credit->submit();
                    struct CancelPending {UdpOwner& owner;bool done=false;~CancelPending(){if(!done){owner.outgoing.cancel();owner.parent.listener->notify();}}} guard{owner};
                    owner.parent.listener->notify();
                    while (!session_closed() && Clock::now()<deadline) {
                        auto done=owner.outgoing.done(*ticket);
                        if (!done) co_return done.error()==h::UdpSendError::canceled && !session_closed();
                        if (*done) {
                            guard.done=true;
                            credit->complete(payload.size());
                            slot.session.count_traffic(false,payload.size());
                            co_return true;
                        }
                        auto [error]=co_await io::delay(std::chrono::milliseconds(5));
                        if (error) break;
                    }
                    co_return !session_closed();
                }
                auto session_closed() const noexcept -> bool {return slot.session.closed || slot.owner.stopping;}
            } incoming{*this};
            struct Resolve {
                Slot& slot;
                auto operator()(std::string name,std::uint16_t port,Clock::time_point deadline) {return resolve_udp_domain(slot.session,slot.owner.parent.server.executor_context(),std::move(name),port,deadline,&slot.owner.source);}
            };
            using State=net::stream_datagrams::Server<Session,Incoming,Resolve>;
            std::unique_ptr<State> state;
            Slot(UdpOwner& owner,h::UdpSessionHandle handle,std::uint32_t id,SessionQuota::Lease&& lease)
                :owner(owner),handle(handle),id(id),session(owner.parent.server.executor_context()) {
                owner.parent.server.attach_session(session,std::move(lease));
                session.datagram_source=owner.source;
                session.begin_traffic(TrafficProtocol::hysteria2_udp,0);
                session.select_traffic_path(ConnectPath::datagrams);
                auto const& policy=session.route_snapshot ? session.route_snapshot->matcher : owner.parent.server.routing_policy();
                state=std::make_unique<State>(session,owner.parent.server.executor_context(),incoming,policy,
                    Resolve{*this},net::DatagramFraming{},net::ProxyAddress{},owner.source);
            }
            auto stop() noexcept -> void {session.close();if(state)state->cancel();}
            ~Slot(){stop();}
        };
        struct Observer {
            UdpOwner& owner;
            auto session_created(h::UdpSessionHandle handle,std::uint32_t id) noexcept -> bool {return owner.create(handle,id);}
            auto session_closed(h::UdpSessionHandle handle,std::uint32_t) noexcept -> void {if(auto* slot=owner.get(handle))slot->stop();}
        } observer{*this};
        Hysteria2Business& parent;quic::SessionHandle physical;ConnectionState& connection;net::UdpEndpoint source;
        std::size_t user=0;std::array<std::unique_ptr<Slot>,16> slots;h::UdpReceiver<Observer,16,16> receiver{observer,true,idle,256*1024};
        h::UdpTransmitter outgoing;capy::async_mutex writer;std::uint16_t packet_id=0;bool stopping=false;
        static constexpr auto idle=std::chrono::minutes(5);
        std::exception_ptr failure;std::error_code error;
        UdpOwner(Hysteria2Business& parent,quic::SessionHandle physical,ConnectionState& connection,net::UdpEndpoint peer,std::size_t user)
            :parent(parent),physical(physical),connection(connection),source(peer),user(user) {}
        ~UdpOwner(){stop();if(!drained())std::terminate();}
        auto get(h::UdpSessionHandle handle) noexcept -> Slot* {if(handle.slot>=slots.size())return nullptr;auto* slot=slots[handle.slot].get();return slot && slot->handle==handle ? slot : nullptr;}
        auto reap() noexcept -> void {for(auto& slot:slots)if(slot && !slot->active){(void)receiver.release(slot->handle,Clock::now());slot.reset();}}
        auto create(h::UdpSessionHandle handle,std::uint32_t id) noexcept -> bool {
            if(stopping || handle.slot>=slots.size() || slots[handle.slot])return false;
            try {
                auto lease=connection.try_acquire();if(!lease)return false;
                auto slot=std::make_unique<Slot>(*this,handle,id,std::move(*lease));
                if (user<parent.names.size() && !slot->session.admit_principal(parent.names[user],PrincipalResource::stream)) return false;
                auto* ptr=slot.get();slots[handle.slot]=std::move(slot);
                capy::run_async(parent.server.executor_context().get_executor(),[ptr]() noexcept {ptr->active=false;},[ptr](std::exception_ptr error) noexcept {if(!ptr->owner.failure)ptr->owner.failure=std::move(error);ptr->stop();ptr->active=false;})(run(*ptr));return true;
            }catch(...){if(!failure)failure=std::current_exception();slots[handle.slot].reset();return false;}
        }
        static auto run(Slot& slot)->capy::task<> {
            try {
            auto& state=*slot.state;std::vector<capy::task<capy::results<>>> tasks;
            tasks.push_back(net::stream_datagrams::process(state));tasks.push_back(net::stream_datagrams::download(state));tasks.push_back(net::stream_datagrams::timeout(state));
            if(slot.session.tunnel_factories && !slot.session.tunnel_factories->empty())
                tasks.push_back(state.readers.run([&state](std::size_t index) {
                    return net::stream_datagrams::tunnel_download(state,index);
                }));
            auto [error]=co_await capy::when_all(std::move(tasks));
            if(error && !slot.session.closed && !slot.owner.error)slot.owner.error=error;
            }catch(...){if(!slot.owner.failure)slot.owner.failure=std::current_exception();slot.stop();}

        }
        auto input(std::span<std::uint8_t const> bytes) noexcept -> int {
            if(stopping)return 0;auto now=Clock::now();auto status=receiver.receive(bytes,now);
            if(failure)return ngtcp2::err_callback_failure;
            if(status==h::ReassemblyStatus::allocation_failed)return ngtcp2::err_nomem;
            if(status!=h::ReassemblyStatus::accepted)return 0;auto packet=receiver.packet(now);
            if(packet)try{
                auto* slot=get(packet->owner);auto parsed=http::parse_destination_authority(packet->address);
                if(slot && !slot->session.closed && parsed.status==http::ConnectStatus::accepted){
                    net::ProxyAddress target;target.port=parsed.port;
                    if(parsed.kind==http::HostKind::domain){if(parsed.host.size()>target.bytes.size()){(void)receiver.consume();return 0;}target.family=net::ProxyAddressFamily::domain;target.length=parsed.host.size();std::ranges::copy(parsed.host,target.bytes.begin());}
                    else{target.family=parsed.kind==http::HostKind::ipv4?net::ProxyAddressFamily::ipv4:net::ProxyAddressFamily::ipv6;target.length=target.family==net::ProxyAddressFamily::ipv4?4:16;std::copy_n(parsed.address.begin(),target.length,target.bytes.begin());}
                    auto& state=*slot->state;
                    if(state.pending.size()<64 && state.pending_bytes+packet->payload.size()<=256*1024){state.pending.push_back({target,{packet->payload.begin(),packet->payload.end()},now});state.pending_bytes+=packet->payload.size();state.notify_pending();}
                }
            }catch(std::bad_alloc const&){(void)receiver.consume();return ngtcp2::err_nomem;}catch(...){(void)receiver.consume();return ngtcp2::err_callback_failure;}
            (void)receiver.consume();return 0;
        }
        auto stop() noexcept -> void {if(std::exchange(stopping,true))return;receiver.close();outgoing.cancel();for(auto& slot:slots)if(slot)slot->stop();}
        auto drained()const noexcept -> bool {return std::ranges::all_of(slots,[](auto const& slot){return !slot || !slot->active;});}
    };
    Hysteria2Business::Hysteria2Business(Server& s,std::span<h::Password const> p,std::span<std::string const> n,config::Hysteria2Masquerade m):server(s),passwords(p),names(n),masquerade(std::move(m)){}
    Hysteria2Business::~Hysteria2Business()=default;
    auto Hysteria2Business::opened(quic::SessionHandle owner,io::endpoint const& peer,ConnectionState& connection)->void {
        auto& state=peers[owner.slot];state={owner,&connection};
        if (!udp_enabled) return;
        state.source.port=peer.port();auto address=peer.address();
        if(address.is_v4()){state.source.family=4;auto bytes=address.to_v4().to_bytes();std::ranges::copy(bytes,state.source.address.begin());}
        else{state.source.family=6;auto bytes=address.to_v6().to_bytes();std::ranges::copy(bytes,state.source.address.begin());}
    }
    auto Hysteria2Business::admit_authenticated(quic::SessionHandle owner,std::size_t user) noexcept -> bool {
        auto const* policy=server.principal_policy();
        if (!policy || user>=names.size()) return true;
        auto const* budget=policy->find(names[user]);
        if (!budget) return true;
        auto& peer=peers[owner.slot];
        if (peer.owner!=owner) return false;
        peer.principal=budget->acquire(PrincipalResource::connection);
        return peer.principal.has_value();
    }
    auto Hysteria2Business::authenticated(quic::SessionHandle owner,std::size_t user) noexcept ->void {auto& state=peers[owner.slot];if(state.owner==owner){state.user=user;state.authenticated=true;}}
    auto Hysteria2Business::datagram(quic::SessionHandle owner,std::span<std::uint8_t const> bytes) noexcept ->int {
        auto& state=peers[owner.slot];if(!udp_enabled || state.owner!=owner || !state.authenticated || !state.connection)return ngtcp2::err_callback_failure;
        if(!udp[owner.slot])try{udp[owner.slot]=std::make_unique<UdpOwner>(*this,owner,*state.connection,state.source,state.user);}
        catch(std::bad_alloc const&){if(!udp_exception)udp_exception=std::current_exception();udp_failed=true;udp_error=ngtcp2::err_nomem;return udp_error;}
        catch(...){if(!udp_exception)udp_exception=std::current_exception();udp_failed=true;udp_error=ngtcp2::err_callback_failure;return udp_error;}
        auto code=udp[owner.slot]->input(bytes);if(code && !udp_error)udp_error=code;return code;
    }
    auto Hysteria2Business::datagram_output(quic::SessionHandle owner) noexcept ->std::optional<h::UdpWriteView> {return udp[owner.slot]?udp[owner.slot]->outgoing.pending():std::nullopt;}
    auto Hysteria2Business::datagram_accepted(quic::SessionHandle owner) noexcept ->void {if(udp[owner.slot])(void)udp[owner.slot]->outgoing.accepted();}
    auto Hysteria2Business::maintain_udp() noexcept ->void {
        for(std::size_t i=0;i<udp.size();++i)if(auto& owner=udp[i]){
            if(!listener->physical_live(owner->physical)){owner->stop();continue;}
            (void)owner->receiver.expire(Clock::now());owner->reap();
        }
    }
    auto Hysteria2Business::datagram_rejected(quic::SessionHandle owner) noexcept ->void {if(udp[owner.slot])udp[owner.slot]->outgoing.cancel();}
    auto Hysteria2Business::udp_failure() const noexcept ->bool {for(auto const& owner:udp)if(owner && (owner->failure || owner->error))return true;return udp_failed || udp_error!=0;}
    auto Hysteria2Business::stopping(quic::SessionHandle owner) noexcept ->void {if(udp[owner.slot])udp[owner.slot]->stop();}
    auto Hysteria2Business::drained(quic::SessionHandle owner) const noexcept ->bool {return !udp[owner.slot] || udp[owner.slot]->drained();}
    auto Hysteria2Business::closed(quic::SessionHandle owner,std::optional<int>) noexcept ->void {if(udp[owner.slot]){if(!udp[owner.slot]->drained())std::terminate();if(!udp_exception && udp[owner.slot]->failure)udp_exception=udp[owner.slot]->failure;
        if(!udp_system && udp[owner.slot]->error)udp_system=udp[owner.slot]->error;udp_failed|=bool(udp_exception)||bool(udp_system);udp[owner.slot].reset();}peers[owner.slot]={};}
}
