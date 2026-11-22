module;
#include <fcntl.h>
#include <unistd.h>
export module masque.host;
import std;
import masque.server;
import masque.ip_server;
import masque.config;
import masque.udp_session;
import net.udp_socket;
import dns.local_config;
import dns.corosio_local;
import nexus.thirdparty.nghttp3;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace masque {
    // One HTTP/3 connection and all DNS/readiness roots share one executor.
    // The host outlives every root and its DatagramSession/driver; stop() is
    // synchronous cancellation, drained() becomes true only after join.
    template<class Tls,std::size_t Streams=16,std::size_t Mtu=1150> class ServerHost {
        using Clock=std::chrono::steady_clock;
        using Server=UdpServer<Tls,ConfigPolicy,Streams,Mtu>;
        struct Watch {
            UdpHandle handle;int original=-1;
            nex::corosio::udp_socket socket;
            std::stop_source stop;
            bool done=false,canceled=false;
            Watch(nex::corosio::io_context& context,UdpHandle id,int fd):handle(id),original(fd),socket(context) {}
        };
        struct Lookup {
            typename Server::Route route;
            std::shared_ptr<dns::LocalSnapshot const> snapshot;
            std::unique_ptr<dns::detail::LocalAddressResolver> resolver;
            bool done=false,canceled=false;
            explicit Lookup(typename Server::Route value):route(std::move(value)) {}
        };
        nex::corosio::io_context& context_;
        HostConfig const& config_;
        dns::LocalSnapshotSource& snapshots_;
        std::function<void()> notify_transport_;
        nex::capy::async_event work_;
        ConfigPolicy policy_;
        Server server_;
        std::array<std::unique_ptr<Watch>,Streams> watches_{};
        std::array<std::unique_ptr<Lookup>,Streams> lookups_{};
        std::stop_source stop_;
        std::size_t active_=0;
        bool started_=false,stopped_=false,monitor_=false,failed_=false;
#ifdef NEXUS_TEST_MASQUE_HOST_LIFETIME
        bool hold_lookup_=false,lookup_waiting_=false;
        nex::capy::async_event lookup_gate_;
#endif
        auto changed() noexcept -> void {work_.set();try {notify_transport_();}catch(...) {failed_=true;stop();}}
        auto complete() noexcept -> void {if(!active_)std::terminate();--active_;changed();}
        auto fail() noexcept -> void {failed_=true;stop();}
        auto watch(Watch& watch) -> nex::capy::task<> {
            while(!stopped_ && !watch.canceled) {
                auto [error]=co_await watch.socket.wait(nex::corosio::wait_type::read);
                if(stopped_ || watch.canceled)break;
                if(error) {if(!server_.socket_failed(watch.handle,watch.original))fail();else changed();break;}
                if(!server_.ready_socket(watch.handle,watch.original)) {fail();break;}
                changed();
            }
        }
        auto resolve(Lookup& lookup) -> nex::capy::task<> {
#ifdef NEXUS_TEST_MASQUE_HOST_LIFETIME
            if(hold_lookup_) {lookup_waiting_=true;auto [ignored]=co_await lookup_gate_.wait();(void)ignored;lookup_waiting_=false;}
            if(stopped_ || lookup.canceled)co_return;
#endif
            lookup.snapshot=snapshots_.acquire();
            if(!lookup.snapshot) {server_.resolve_failed(lookup.route.handle);changed();co_return;}
            lookup.resolver=std::make_unique<dns::detail::LocalAddressResolver>(context_,lookup.snapshot->config,lookup.snapshot->hosts,config_.family);
            auto answers=co_await lookup.resolver->resolve(lookup.route.host,Clock::now()+config_.dns_timeout);
            lookup.resolver.reset();
            if(stopped_ || lookup.canceled)co_return;
            bool ready=false;
            if(answers)for(auto const& address:*answers) {
                if(address.size!=4 && address.size!=16)continue;
                net::UdpEndpoint endpoint{address.size==4 ? std::uint8_t{4} : std::uint8_t{6},address.bytes,lookup.route.port};
                if(server_.resolved(lookup.route.handle,endpoint)){ready=true;break;}
            }
            if(!ready)server_.resolve_failed(lookup.route.handle);
            changed();
        }
        auto launch_watch(UdpHandle handle,int fd) -> bool {
            if(handle.slot>=Streams || watches_[handle.slot])return false;
            auto watch=std::make_unique<Watch>(context_,handle,fd);
            auto duplicate=::fcntl(fd,F_DUPFD_CLOEXEC,0);if(duplicate<0)return false;
            if(watch->socket.assign(duplicate)) {::close(duplicate);return false;}
            auto* raw=watch.get();watches_[handle.slot]=std::move(watch);++active_;
            try {
                nex::capy::run_async(context_.get_executor(),raw->stop.get_token(),[this,raw]() noexcept {raw->socket.close();raw->done=true;complete();},
                    [this,raw](std::exception_ptr) noexcept {raw->socket.close();raw->done=true;complete();fail();})(this->watch(*raw));
            }catch(...) {--active_;watches_[handle.slot].reset();return false;}
            return true;
        }
        auto launch_lookup(typename Server::Route route) -> bool {
            auto index=route.handle.slot;if(index>=Streams || lookups_[index])return false;
            auto lookup=std::make_unique<Lookup>(std::move(route));auto* raw=lookup.get();lookups_[index]=std::move(lookup);++active_;
            try {
                nex::capy::run_async(context_.get_executor(),stop_.get_token(),[this,raw]() noexcept {raw->done=true;complete();},
                    [this,raw](std::exception_ptr) noexcept {raw->done=true;complete();fail();})(resolve(*raw));
            }catch(...) {--active_;lookups_[index].reset();return false;}
            return true;
        }
        auto maintain() -> nex::capy::task<> {
            while(!stopped_) {
                work_.clear();
                auto current=server_.sockets();
                for(std::size_t i=0;i<Streams;++i) {
                    auto& watch=watches_[i];
                    if(watch && !watch->done && (!current[i] || current[i]->first!=watch->handle || current[i]->second!=watch->original)) {
                        watch->canceled=true;watch->stop.request_stop();watch->socket.cancel();
                    }
                    if(watch && watch->done)watch.reset();
                    if(!watch && current[i] && !launch_watch(current[i]->first,current[i]->second)) {fail();break;}
                    auto& lookup=lookups_[i];
                    if(lookup && !lookup->done && !server_.pending_current(lookup->route.handle)) {
                        lookup->canceled=true;if(lookup->resolver)lookup->resolver->cancel();
                    }
                    if(lookup && lookup->done)lookup.reset();
                }
                if(stopped_)break;
                for(std::size_t i=0;i<Streams;++i)if(!lookups_[i])if(auto route=server_.pending(i)) {
                    auto handle=route->handle;
                    if(!launch_lookup(std::move(*route))) {server_.resolve_failed(handle);changed();}
                }
                auto [error]=co_await work_.wait();if(error && !stopped_){fail();break;}
            }
        }
    public:
        using ServerType=Server;
        using Transport=typename Server::Transport;
        ServerHost(nex::corosio::io_context& context,Tls& tls,HostConfig const& config,dns::LocalSnapshotSource& snapshots,
            nex::nghttp3::nghttp3_mem const& memory,std::function<void()> notify_transport,IpServerPort* ip_port=nullptr)
            :context_(context),config_(config),snapshots_(snapshots),notify_transport_(std::move(notify_transport)),
             policy_(config_,this,[](void* owner) noexcept {static_cast<ServerHost*>(owner)->changed();}),server_(tls,policy_,config.authority,memory,ip_port) {
            if(!config_.valid(ip_port!=nullptr) || !notify_transport_)throw std::invalid_argument("invalid MASQUE host configuration");
        }
        ServerHost(ServerHost const&)=delete;
        auto operator=(ServerHost const&) -> ServerHost& = delete;
        ~ServerHost(){stop();if(!drained())std::terminate();}
        auto server() noexcept -> Server& {return server_;}
        auto cid_callbacks(void* context,bool (*add)(void*,std::span<std::uint8_t const>) noexcept,
            void (*remove)(void*,std::span<std::uint8_t const>) noexcept) noexcept -> void {policy_.cid_callbacks(context,add,remove);}
        auto start() -> void {
            if(started_ || stopped_)throw std::logic_error("MASQUE host cannot start");
            started_=monitor_=true;
            try {
                nex::capy::run_async(context_.get_executor(),stop_.get_token(),[this]() noexcept {monitor_=false;changed();},
                    [this](std::exception_ptr) noexcept {monitor_=false;fail();})(maintain());
            }catch(...) {monitor_=false;stop();throw;}
            changed();
        }
        auto stop() noexcept -> void {
            if(std::exchange(stopped_,true))return;
            server_.stop();stop_.request_stop();
            for(auto& w:watches_)if(w && !w->done){w->canceled=true;w->stop.request_stop();w->socket.cancel();}
            for(auto& l:lookups_)if(l && !l->done){l->canceled=true;if(l->resolver)l->resolver->cancel();}
            work_.set();
#ifdef NEXUS_TEST_MASQUE_HOST_LIFETIME
            lookup_gate_.set();
#endif
        }
        auto drained() const noexcept -> bool {return stopped_ && !monitor_ && !active_;}
        auto joined() noexcept -> void {server_.joined();}
        auto drain() noexcept -> void {server_.drain();}
        auto clean() const noexcept -> bool {return drained() && server_.clean();}
        auto failed() const noexcept -> bool {return failed_;}
#ifdef NEXUS_TEST_MASQUE_HOST_LIFETIME
        auto hold_lookup(bool value) noexcept -> void {hold_lookup_=value;if(!value)lookup_gate_.set();}
        auto lookup_waiting() const noexcept -> bool {return lookup_waiting_;}
        auto watching(UdpHandle handle) const noexcept -> bool {
            return handle.slot<Streams && watches_[handle.slot] && !watches_[handle.slot]->done && watches_[handle.slot]->handle==handle && watches_[handle.slot]->socket.is_open();
        }
#endif
    };
}
