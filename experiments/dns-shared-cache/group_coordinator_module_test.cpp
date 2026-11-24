// Real UDP DNS through the exported, test-only coordinator module boundary.
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import functional;
import dns.message;
import dns.cache;
import dns.corosio_resolver;
import dns.reverse;
import dns.shared_cache;
import dns.shared_coordinator;
import capy;
import corosio;

namespace hp=dns_hp_experiment;
namespace io = ::corosio;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace {
auto require(bool condition,char const* message) -> void { if (!condition) throw std::runtime_error(message); }
struct Peer {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    io::endpoint endpoint{io::ipv4_address::loopback(),0};
    struct Packet { std::vector<std::uint8_t> bytes; sockaddr_in sender{}; };
    Peer() {
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        require(fd>=0 && !::bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address)),"module peer bind failed");
        socklen_t size=sizeof(address); require(!::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size),"module peer address failed");
        endpoint={io::ipv4_address::loopback(),ntohs(address.sin_port)};
    }
    ~Peer() { if (fd>=0) ::close(fd); }
    auto receive() -> Packet {
        pollfd wait{fd,POLLIN,0}; require(::poll(&wait,1,3000)==1 && (wait.revents&POLLIN),"module peer query timeout");
        std::array<std::uint8_t,4096> buffer{}; Packet result; socklen_t size=sizeof(result.sender);
        auto count=::recvfrom(fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&result.sender),&size);
        require(count>=17,"short module DNS query"); result.bytes.assign(buffer.begin(),buffer.begin()+count); return result;
    }
    auto empty() -> bool { pollfd wait{fd,POLLIN,0}; return ::poll(&wait,1,100)==0; }
    auto reply(Packet packet,std::uint8_t address,std::uint8_t ttl=30) -> void {
        packet.bytes[2]=0x81; packet.bytes[3]=0x80; packet.bytes[7]=1;
        std::array<std::uint8_t,16> answer{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,127,0,0,address};
        answer[9]=ttl;
        packet.bytes.insert(packet.bytes.end(),answer.begin(),answer.end());
        require(::sendto(fd,packet.bytes.data(),packet.bytes.size(),0,reinterpret_cast<sockaddr*>(&packet.sender),sizeof(packet.sender))==
                static_cast<ssize_t>(packet.bytes.size()),"module peer reply failed");
    }
    auto reply_dual(Packet packet,bool alias) -> void {
        auto ipv6=packet.bytes[packet.bytes.size()-3]==28;
        packet.bytes[2]=0x81; packet.bytes[3]=0x80; packet.bytes[7]=alias ? 2 : 1;
        std::array<std::uint8_t,18> target{3,'a','l','t',7,'e','x','a','m','p','l','e',4,'t','e','s','t',0};
        if (alias) {
            std::array<std::uint8_t,12> cname{0xc0,0x0c,0,5,0,1,0,0,0,30,0,18};
            packet.bytes.insert(packet.bytes.end(),cname.begin(),cname.end());
            packet.bytes.insert(packet.bytes.end(),target.begin(),target.end());
        }
        if (alias) packet.bytes.insert(packet.bytes.end(),target.begin(),target.end());
        else { packet.bytes.push_back(0xc0); packet.bytes.push_back(0x0c); }
        std::array<std::uint8_t,10> header{0,static_cast<std::uint8_t>(ipv6 ? 28 : 1),0,1,0,0,0,30,0,
                                           static_cast<std::uint8_t>(ipv6 ? 16 : 4)};
        packet.bytes.insert(packet.bytes.end(),header.begin(),header.end());
        if (ipv6) {
            std::array<std::uint8_t,16> address{0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
            packet.bytes.insert(packet.bytes.end(),address.begin(),address.end());
        } else {
            std::array<std::uint8_t,4> address{127,0,0,105};
            packet.bytes.insert(packet.bytes.end(),address.begin(),address.end());
        }
        require(::sendto(fd,packet.bytes.data(),packet.bytes.size(),0,reinterpret_cast<sockaddr*>(&packet.sender),sizeof(packet.sender))==
                static_cast<ssize_t>(packet.bytes.size()),"dual peer reply failed");
    }
};
struct State { std::optional<hp::CoordinatedResult> result; std::exception_ptr failure; bool done=false; };
auto execute(hp::CoordinatorQuery& query,io::endpoint endpoint,std::string name,State& state,std::uint64_t view) -> capy::task<> {
    state.result=co_await query.resolve(endpoint,view,std::move(name),Clock::now()+3s);
}
auto launch(io::io_context& context,hp::CoordinatorQuery& query,io::endpoint endpoint,std::string name,State& state,std::uint64_t view=1) -> void {
    capy::run_async(context.get_executor(),[&state] { state.done=true; },[&state](std::exception_ptr error) { state.failure=error; state.done=true; })
        (execute(query,endpoint,std::move(name),state,view));
}
auto drive(io::io_context& context,std::chrono::milliseconds duration=100ms) -> void { context.restart(); (void)context.run_for(duration); }
auto success(State const& state,std::uint8_t value) -> bool {
    return state.done && !state.failure && state.result && *state.result && (**state.result).size()==1 && (**state.result)[0].bytes[3]==value;
}
auto canceled(State const& state) -> bool {
    return state.done && !state.failure && state.result && !*state.result && state.result->error()==hp::CoordinatedError::canceled;
}

// Construct, use and destroy each owner, reader and query on its own
// executor. Only the cache and coordinator are shared across the threads.
class Worker {
    struct Pending {
        std::unique_ptr<hp::CoordinatorQuery> query;
        std::promise<hp::CoordinatedResult> result;
    };
    struct Local {
        io::io_context context;
        hp::GroupBinding binding;
        hp::GroupSnapshot::Reader reader;
        hp::CoordinatorOwner owner;
        std::map<unsigned,std::unique_ptr<Pending>> pending;
        Local(bool uring,hp::GroupSnapshot& cache,hp::Coordinator& coordinator,std::size_t group)
            : context(io::make_io_context(uring)),binding(cache,group),reader(cache.reader(group)),
              owner(context,binding,coordinator) {}
    };
    hp::GroupSnapshot& cache_;
    hp::Coordinator& coordinator_;
    std::size_t group_;
    bool uring_;
    std::unique_ptr<Local> local_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<functional::move_only_function<void()>> commands_;
    std::thread thread_;
    unsigned next_=0;
    bool quitting_=false;
    auto enqueue(functional::move_only_function<void()> command) -> void {
        { std::lock_guard lock(mutex_); commands_.push_back(std::move(command)); }
        condition_.notify_one();
    }
    auto loop(std::promise<void> ready) noexcept -> void {
        try { local_=std::make_unique<Local>(uring_,cache_,coordinator_,group_); ready.set_value(); }
        catch (...) { ready.set_exception(std::current_exception()); return; }
        for (;;) {
            std::deque<functional::move_only_function<void()>> commands;
            {
                std::unique_lock lock(mutex_);
                condition_.wait_for(lock,2ms,[&] { return !commands_.empty(); });
                commands.swap(commands_);
            }
            for (auto& command:commands) command();
            local_->context.restart(); (void)local_->context.run_for(2ms);
            if (quitting_ && local_->pending.empty() && local_->owner.drained()) break;
        }
        local_.reset();
    }
    static auto execute(Pending& pending,io::endpoint endpoint,std::string name) -> capy::task<> {
        pending.result.set_value(co_await pending.query->resolve(endpoint,1,std::move(name),Clock::now()+3s));
    }
public:
    struct Request { unsigned id; std::future<hp::CoordinatedResult> result; };
    Worker(bool uring,hp::GroupSnapshot& cache,hp::Coordinator& coordinator,std::size_t group)
        : cache_(cache),coordinator_(coordinator),group_(group),uring_(uring) {
        std::promise<void> ready; auto initialized=ready.get_future();
        thread_=std::thread([this,ready=std::move(ready)]() mutable { loop(std::move(ready)); });
        try { initialized.get(); } catch (...) { thread_.join(); throw; }
    }
    Worker(Worker const&)=delete;
    ~Worker() {
        if (!thread_.joinable()) return;
        enqueue([this] {
            for (auto& [id,pending]:local_->pending) pending->query->cancel();
            local_->owner.stop(); quitting_=true;
        });
        thread_.join();
    }
    auto start(io::endpoint endpoint,std::string name) -> Request {
        auto id=++next_; auto pending=std::make_unique<Pending>(); auto result=pending->result.get_future();
        std::promise<void> ack; auto begun=ack.get_future();
        enqueue([this,id,endpoint,name=std::move(name),pending=std::move(pending),ack=std::move(ack)]() mutable {
            try {
                pending->query=std::make_unique<hp::CoordinatorQuery>(local_->owner,&local_->reader,hp::CoordinatedStrategy::ipv4_only);
                auto [it,inserted]=local_->pending.try_emplace(id);
                if (!inserted) throw std::runtime_error("duplicate module query");
                it->second=std::move(pending);
                try {
                    capy::run_async(local_->context.get_executor(),[this,id] { local_->pending.erase(id); },
                        [this,id](std::exception_ptr error) noexcept {
                            auto it=local_->pending.find(id);
                            if (it!=local_->pending.end()) {
                                try { it->second->result.set_exception(error); } catch (...) {}
                                local_->pending.erase(it);
                            }
                        })(execute(*it->second,endpoint,std::move(name)));
                } catch (...) { pending=std::move(it->second); local_->pending.erase(it); throw; }
                ack.set_value();
            } catch (...) { ack.set_exception(std::current_exception()); }
        });
        begun.get(); return {id,std::move(result)};
    }
    auto cancel(unsigned id) -> void {
        std::promise<void> ack; auto done=ack.get_future();
        enqueue([this,id,ack=std::move(ack)]() mutable {
            if (auto it=local_->pending.find(id);it!=local_->pending.end()) it->second->query->cancel();
            ack.set_value();
        });
        done.get();
    }
    auto stop() -> void {
        std::promise<void> ack; auto done=ack.get_future();
        enqueue([this,ack=std::move(ack)]() mutable { local_->owner.stop(); ack.set_value(); }); done.get();
    }
    auto drained() -> bool {
        std::promise<bool> ack; auto done=ack.get_future();
        enqueue([this,ack=std::move(ack)]() mutable { ack.set_value(local_->owner.drained()); }); return done.get();
    }
};
auto expect_success(std::future<hp::CoordinatedResult>& future,std::uint8_t value) -> void {
    require(future.wait_for(3s)==std::future_status::ready,"module threaded request timed out");
    auto result=future.get();
    require(result && result->size()==1 && (*result)[0].bytes[3]==value,"module threaded answer differs");
}
auto expect_canceled(std::future<hp::CoordinatedResult>& future) -> void {
    require(future.wait_for(3s)==std::future_status::ready,"module threaded cancellation timed out");
    auto result=future.get();
    require(!result && result.error()==hp::CoordinatedError::canceled,"module threaded request was not canceled");
}
auto wait_counts(hp::Coordinator& coordinator,std::pair<std::size_t,std::size_t> expected) -> void {
    auto deadline=Clock::now()+3s;
    while (coordinator.counts()!=expected) {
        require(Clock::now()<deadline,"module threaded counts did not settle"); std::this_thread::sleep_for(2ms);
    }
}
auto run_threaded(bool uring) -> void {
    Peer peer; std::array<std::size_t,2> capacities{1,1};
    hp::GroupSnapshot cache(capacities,hp::GroupSnapshot::SharedCapacity{32},2,0,1024*1024);
    hp::Coordinator coordinator(4,8);
    Worker a(uring,cache,coordinator,0),b(uring,cache,coordinator,1);
    auto left=a.start(peer.endpoint,"threaded-shared.example.test"); auto packet=peer.receive();
    auto right=b.start(peer.endpoint,"threaded-shared.example.test");
    wait_counts(coordinator,{1,2}); require(peer.empty(),"module threads sent duplicate queries");
    b.cancel(right.id); expect_canceled(right.result); wait_counts(coordinator,{1,1});
    peer.reply(std::move(packet),91); expect_success(left.result,91); wait_counts(coordinator,{0,0});
    auto hit=b.start(peer.endpoint,"threaded-shared.example.test"); expect_success(hit.result,91);
    require(peer.empty(),"module threaded cache did not share the answer");

    left=a.start(peer.endpoint,"threaded-stop.example.test"); auto late=peer.receive();
    right=b.start(peer.endpoint,"threaded-stop.example.test"); wait_counts(coordinator,{1,2});
    a.stop(); expect_canceled(left.result); expect_canceled(right.result); wait_counts(coordinator,{0,0});
    auto deadline=Clock::now()+3s;
    while (!a.drained()) { require(Clock::now()<deadline,"module threaded owner did not drain"); std::this_thread::sleep_for(2ms); }
    peer.reply(std::move(late),92);
    auto retry=b.start(peer.endpoint,"threaded-stop.example.test"); packet=peer.receive(); peer.reply(std::move(packet),93);
    expect_success(retry.result,93); wait_counts(coordinator,{0,0});
    require(peer.empty(),"module threaded late response caused an extra query");
    b.stop();
    std::println("{}: exported coordinator crossed two executor threads and drained",uring ? "io_uring" : "epoll");
}
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
auto run_reverse(bool uring) -> void {
    using dns::Address;
    auto now=[] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count()); };
    auto context=io::make_io_context(uring);
    Peer peer; std::array<std::size_t,1> capacities{1};
    hp::GroupSnapshot cache(capacities,hp::GroupSnapshot::SharedCapacity{32},1,5000,1024*1024);
    hp::GroupBinding binding(cache,0); auto reader=cache.reader(0);
    hp::Coordinator coordinator(4,8); hp::CoordinatorOwner owner(context,binding,coordinator);
    dns::ReverseCache reverse(16,42,{11,17});
    auto family=hp::CoordinatedStrategy::ipv4_only;
    auto ip=[](unsigned last) { return Address{{127,0,0,static_cast<std::uint8_t>(last)},4}; };
    {
        hp::CoordinatorQuery first(owner,&reader,family); first.observe_reverse_for_test(reverse); State result;
        launch(context,first,peer.endpoint,"observed.example.test",result); drive(context,30ms);
        auto packet=peer.receive(); peer.reply(std::move(packet),101); drive(context);
        auto name=reverse.lookup(1,ip(101),now());
        require(success(result,101) && name && name->view()=="observed.example.test" && !reverse.lookup(2,ip(101),now()),
                "network reverse observation or view isolation failed");
        require(reverse.clear(),"reverse clear failed");
        hp::CoordinatorQuery hit(owner,&reader,family); hit.observe_reverse_for_test(reverse); State cached;
        launch(context,hit,peer.endpoint,"observed.example.test",cached); drive(context,30ms);
        require(success(cached,101) && peer.empty() && reverse.lookup(1,ip(101),now()).has_value(),
                "fresh cache hit did not publish reverse observation");
    }
    {
        hp::CoordinatorQuery other(owner,&reader,family); other.observe_reverse_for_test(reverse); State result;
        launch(context,other,peer.endpoint,"different.example.test",result,2); drive(context,30ms);
        auto packet=peer.receive(); peer.reply(std::move(packet),101); drive(context);
        auto first=reverse.lookup(1,ip(101),now()),second=reverse.lookup(2,ip(101),now());
        require(success(result,101) && first && second && first->view()=="observed.example.test" &&
                second->view()=="different.example.test","same IP views mixed reverse observations");
        hp::CoordinatorQuery conflict(owner,&reader,family); conflict.observe_reverse_for_test(reverse); State other_name;
        launch(context,conflict,peer.endpoint,"conflict.example.test",other_name); drive(context,30ms);
        packet=peer.receive(); peer.reply(std::move(packet),101); drive(context);
        require(success(other_name,101) && !reverse.lookup(1,ip(101),now()) && reverse.lookup(2,ip(101),now()),
                "same-view conflict affected the wrong view or remained definite");
        require(reverse.clear(),"reverse view clear failed");
    }
    {
        hp::CoordinatorQuery dual(owner,&reader,hp::CoordinatedStrategy::prefer_ipv4); dual.observe_reverse_for_test(reverse); State result;
        launch(context,dual,peer.endpoint,"dual.example.test",result); drive(context,30ms);
        auto first=peer.receive(); peer.reply_dual(std::move(first),false); drive(context,30ms);
        auto second=peer.receive(); peer.reply_dual(std::move(second),false); drive(context);
        Address v6{{0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},16};
        require(result.done && result.result && *result.result && (**result.result).size()==2 &&
                reverse.lookup(1,ip(105),now()) && reverse.lookup(1,v6,now()),"dual-family observation failed");
        require(reverse.clear(),"dual reverse clear failed");
        hp::CoordinatorQuery mismatch(owner,&reader,hp::CoordinatedStrategy::prefer_ipv4); mismatch.observe_reverse_for_test(reverse); State bad;
        launch(context,mismatch,peer.endpoint,"mismatch.example.test",bad); drive(context,30ms);
        first=peer.receive(); peer.reply_dual(std::move(first),false); drive(context,30ms);
        second=peer.receive(); peer.reply_dual(std::move(second),true); drive(context);
        require(bad.done && bad.result && !*bad.result && bad.result->error()==hp::CoordinatedError::protocol &&
                !reverse.lookup(1,ip(105),now()) && !reverse.lookup(1,v6,now()),"inconsistent families published reverse observation");
    }
    {
        hp::CoordinatorQuery pending(owner,&reader,family); pending.observe_reverse_for_test(reverse); State result;
        launch(context,pending,peer.endpoint,"late.example.test",result); drive(context,30ms);
        auto packet=peer.receive(); require(reverse.clear(),"reverse generation clear failed");
        peer.reply(std::move(packet),102); drive(context);
        require(success(result,102) && !reverse.lookup(1,ip(102),now()),"late query crossed reverse epoch");
    }
    {
        hp::CoordinatorQuery pending(owner,&reader,family); pending.observe_reverse_for_test(reverse); State result;
        launch(context,pending,peer.endpoint,"cancel.example.test",result); drive(context,30ms);
        auto packet=peer.receive(); pending.cancel(); drive(context,30ms); peer.reply(std::move(packet),103); drive(context);
        require(canceled(result) && !reverse.lookup(1,ip(103),now()),"canceled query published reverse observation");
    }
    {
        hp::CoordinatorQuery initial(owner,&reader,family); State result;
        launch(context,initial,peer.endpoint,"stale.example.test",result); drive(context,30ms);
        auto packet=peer.receive(); peer.reply(std::move(packet),104,3); drive(context);
        require(success(result,104),"seed stale cache failed");
        std::this_thread::sleep_for(2200ms);
        auto prior=binding.lookup_stale({1,"stale.example.test",1},now(),reader);
        require(prior && *prior,"stale seed unavailable");
        hp::CoordinatorQuery stale(owner,&reader,family,false,false,false,true); stale.observe_reverse_for_test(reverse); State cached;
        launch(context,stale,peer.endpoint,"stale.example.test",cached); drive(context,30ms);
        auto reverse_hit=reverse.lookup(1,ip(104),now());
        if (!success(cached,104) || reverse_hit) {
            std::cerr << "stale diagnostic: done=" << cached.done << " result=" << bool(cached.result)
                      << " success=" << success(cached,104) << " reverse=" << bool(reverse_hit) << '\n';
            owner.stop(); drive(context,100ms);
            require(false,"stale response published reverse observation");
        }
    }
    owner.stop(); drive(context,100ms);
    require(owner.drained() && coordinator.counts()==std::pair<std::size_t,std::size_t>{0,0},"reverse owner did not drain");
    std::println("{}: experimental reverse observation network, cache, stale, epoch and cancellation passed",uring ? "io_uring" : "epoll");
}
#endif
// With no network permits, these results must come from the initial cache
// lookup. Check the exported production path, including cross-group adoption.
auto run_initial_cache(bool uring) -> void {
    namespace d=dns;
    using Error=d::detail::ResolveError;
    using Result=std::expected<d::AddressAnswer,Error>;
    auto context=io::make_io_context(uring); std::array<std::size_t,2> enabled{1,1};
    hp::GroupSnapshot cache(enabled,hp::GroupSnapshot::SharedCapacity{16},1,10000,1024*1024);
    hp::GroupBinding binding(cache,1); auto reader=cache.reader(0);
    hp::Coordinator coordinator(0,0); hp::CoordinatorOwner owner(context,binding,coordinator);
    auto sampled=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
    auto acquired=sampled-5000;
    auto seed=[&](std::string name,std::uint32_t ttl,std::optional<d::NegativeKind> negative={}) {
        d::CacheKey key{1,name,1}; auto token=cache.begin_query(0,key);
        require(bool(token),"initial cache token failed");
        if (negative) require(bool(cache.publish_negative(0,key,*negative,ttl,acquired,*token)),"initial negative seed failed");
        else {
            d::Address address{{127,0,0,111},4};
            require(bool(cache.publish(0,key,d::AddressAnswer{name,{name},{address},ttl},acquired,*token)),"initial positive seed failed");
        }
    };
    seed("initial-positive.test",60); seed("initial-stale.test",1);
    seed("initial-nxdomain.test",60,d::NegativeKind::name_not_found);
    seed("initial-nodata.test",60,d::NegativeKind::no_data);
    seed("initial-expired-negative.test",1,d::NegativeKind::name_not_found);
    auto query=[&](std::string name,bool no_cache=false,bool optimistic=false,std::uint64_t view=1,bool has_reader=true) -> Result {
        hp::CoordinatorQuery request(owner,has_reader ? &reader : nullptr,hp::CoordinatedStrategy::ipv4_only,false,no_cache,false,optimistic);
        std::optional<Result> result; std::exception_ptr failure; bool done=false;
        auto task=[&]() -> capy::task<> {
            result=co_await request.resolve_answer({io::ipv4_address::loopback(),9},view,std::move(name),Clock::now()+1s);
        };
        capy::run_async(context.get_executor(),[&] { done=true; },[&](std::exception_ptr error) { failure=error;done=true; })(task());
        drive(context,30ms);
        if (failure) std::rethrow_exception(failure);
        require(done && result && owner.drained() && coordinator.counts()==std::pair<std::size_t,std::size_t>{0,0} &&
                !coordinator.direct_active(),"initial cache lookup needed or retained network work");
        return std::move(*result);
    };
    auto answer=query("INITIAL-POSITIVE.TEST.");
    require(answer && answer->canonical_name=="initial-positive.test" && answer->addresses.size()==1 &&
            answer->addresses[0].bytes[3]==111 && answer->ttl && *answer->ttl>=50 && *answer->ttl<=55,
            "initial positive lookup changed answer or restarted TTL");
    auto error=[&](Result result,Error expected) { require(!result && result.error()==expected,"initial cache result classification changed"); };
    error(query("initial-nxdomain.test"),Error::name_not_found);
    error(query("initial-nodata.test"),Error::no_data);
    error(query("initial-expired-negative.test"),Error::limit);
    error(query("initial-stale.test"),Error::limit);
    error(query("initial-positive.test",true),Error::limit);
    error(query("initial-positive.test",false,false,2),Error::limit);
    error(query("initial-positive.test",false,false,1,false),Error::state);
    error(query("initial-missing.test"),Error::limit);
    answer=query("initial-stale.test",false,true);
    require(answer && answer->ttl==1 && answer->addresses[0].bytes[3]==111,"initial miss lost stale fallback");
    owner.stop(); drive(context,30ms);
    require(owner.drained(),"initial cache owner did not drain");
    std::println("{}: initial positive/negative cache, TTL, view, no-cache and stale paths passed",uring ? "io_uring" : "epoll");
}
auto run(bool uring) -> void {
    auto context=io::make_io_context(uring);
    Peer peer; std::array<std::size_t,2> capacities{1,1};
    hp::GroupSnapshot cache(capacities,hp::GroupSnapshot::SharedCapacity{32},2,0,1024*1024);
    hp::GroupBinding first(cache,0),second(cache,1); auto reader_a=cache.reader(0),reader_b=cache.reader(1);
    hp::Coordinator coordinator(4,8);
    hp::CoordinatorOwner owner_a(context,first,coordinator),owner_b(context,second,coordinator);
    auto family=hp::CoordinatedStrategy::ipv4_only;
    {
        hp::CoordinatorQuery a(owner_a,&reader_a,family),b(owner_b,&reader_b,family); State left,right;
        launch(context,a,peer.endpoint,"module-shared.example.test",left);
        launch(context,b,peer.endpoint,"module-shared.example.test",right);
        drive(context,30ms); auto packet=peer.receive();
        require(coordinator.counts()==std::pair<std::size_t,std::size_t>{1,2} && peer.empty(),"module queries did not coalesce");
        peer.reply(std::move(packet),81); drive(context);
        require(success(left,81) && success(right,81) && coordinator.counts()==std::pair<std::size_t,std::size_t>{0,0},
                "module shared reply did not drain");
        hp::CoordinatorQuery hit(owner_b,&reader_b,family); State cached;
        launch(context,hit,peer.endpoint,"module-shared.example.test",cached); drive(context,30ms);
        require(success(cached,81) && peer.empty(),"module shared cache hit failed");
    }
    {
        hp::CoordinatorQuery a(owner_a,&reader_a,family),b(owner_b,&reader_b,family); State left,right;
        launch(context,a,peer.endpoint,"module-cancel.example.test",left);
        launch(context,b,peer.endpoint,"module-cancel.example.test",right);
        drive(context,30ms); auto packet=peer.receive(); a.cancel(); drive(context,30ms);
        require(canceled(left) && !right.done && peer.empty(),"module cancellation affected another waiter");
        peer.reply(std::move(packet),82); drive(context);
        require(success(right,82) && coordinator.counts()==std::pair<std::size_t,std::size_t>{0,0},"module cancel test did not drain");
    }
    {
        hp::CoordinatorQuery a(owner_a,&reader_a,family),b(owner_b,&reader_b,family); State left,right;
        launch(context,a,peer.endpoint,"module-stop.example.test",left); drive(context,30ms); auto late=peer.receive();
        launch(context,b,peer.endpoint,"module-stop.example.test",right); drive(context,30ms);
        require(coordinator.counts()==std::pair<std::size_t,std::size_t>{1,2} && peer.empty(),"module stop follower did not join");
        owner_a.stop(); drive(context);
        require(canceled(left) && canceled(right) && owner_a.drained() && coordinator.counts()==std::pair<std::size_t,std::size_t>{0,0},
                "module owner stop did not drain both waiters");
        peer.reply(std::move(late),83);
        hp::CoordinatorQuery retry(owner_b,&reader_b,family); State fresh;
        launch(context,retry,peer.endpoint,"module-stop.example.test",fresh); drive(context,30ms);
        auto packet=peer.receive(); peer.reply(std::move(packet),84); drive(context);
        require(success(fresh,84) && peer.empty(),"module late response contaminated the retry");
    }
    {
        // A later waiter's deadline must survive the shared network owner's
        // shorter timeout. Its replacement query uses the original deadline.
        hp::CoordinatorOwner short_owner(context,first,coordinator,100ms);
        hp::CoordinatorQuery request(short_owner,&reader_a,family); State state;
        launch(context,request,peer.endpoint,"module-owner-timeout.example.test",state);
        drive(context,30ms); (void)peer.receive();
        drive(context,90ms);
        require(!state.done,"shared network timeout ended the waiter early");
        auto retry=peer.receive(); peer.reply(std::move(retry),85); drive(context);
        require(success(state,85),"waiter did not retry under its own deadline");
        short_owner.stop(); drive(context,30ms);
        require(short_owner.drained(),"retry owner did not drain");
    }
    owner_b.stop(); drive(context,30ms);
    require(owner_a.drained() && owner_b.drained() && coordinator.counts()==std::pair<std::size_t,std::size_t>{0,0} &&
            !coordinator.direct_active(),"module coordinator did not drain");
    std::println("{}: exported coordinator coalescing, cache, cancellation and stop passed",uring ? "io_uring" : "epoll");
}
}
int main() {
    try {
        run_initial_cache(false); run(false);
        run_threaded(false);
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        run_reverse(false);
#endif
        if (io::has_uring) {
            run_initial_cache(true); run(true); run_threaded(true);
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
            run_reverse(true);
#endif
        }
    } catch (std::exception const& error) { std::cerr << "coordinator module: " << error.what() << '\n'; return 1; }
}
