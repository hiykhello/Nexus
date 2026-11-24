// Two real executor threads, two immutable configuration generations and local
// UDP DNS peers. A second build uses experimental per-group cache adapters;
// neither configuration enables refresh in the production proxy.
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.corosio_cached;
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
import dns.shared_cache;
#endif

namespace d=dns;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;

auto now_ms() -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
}
struct Peer {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    io::endpoint endpoint;
    struct Packet { std::vector<std::uint8_t> data; sockaddr_in from{}; };
    Peer() : endpoint(io::ipv4_address::loopback(),0) {
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if (fd<0 || bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) throw std::runtime_error("peer bind failed");
        socklen_t size=sizeof(address);
        if (getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size)) throw std::runtime_error("peer name failed");
        endpoint=io::endpoint(io::ipv4_address::loopback(),ntohs(address.sin_port));
    }
    ~Peer() { if (fd>=0) close(fd); }
    auto receive() -> Packet {
        pollfd wait{fd,POLLIN,0};
        if (poll(&wait,1,2000)!=1 || !(wait.revents&POLLIN)) throw std::runtime_error("DNS query timeout");
        std::array<std::uint8_t,4096> data{}; Packet packet; socklen_t length=sizeof(packet.from);
        auto size=recvfrom(fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&packet.from),&length);
        if (size<17) throw std::runtime_error("invalid DNS query");
        packet.data.assign(data.begin(),data.begin()+size); return packet;
    }
    auto reply(Packet packet,std::uint8_t final_octet) -> void {
        packet.data[2]=0x81; packet.data[3]=0x80; packet.data[7]=1;
        std::array<std::uint8_t,16> answer{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,127,0,0,final_octet};
        packet.data.insert(packet.data.end(),answer.begin(),answer.end());
        if (sendto(fd,packet.data.data(),packet.data.size(),0,reinterpret_cast<sockaddr*>(&packet.from),sizeof(packet.from))!=
            static_cast<ssize_t>(packet.data.size())) throw std::runtime_error("DNS reply failed");
    }
};
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
using GroupCache=dns_hp_experiment::GroupSnapshot;
using OwnerCache=dns_hp_experiment::GroupBinding;
#else
using OwnerCache=d::AddressCache;
#endif
struct Generation {
    io::endpoint const upstream;
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
    std::array<std::size_t,2> capacities{16,16};
    GroupCache cache{capacities,2,10000,1024*1024};
    std::array<OwnerCache,2> bindings{{{cache,0},{cache,1}}};
#else
    d::AddressCache cache{16,10000,true,2};
#endif
    d::detail::RefreshBudget budget{3};
    auto binding(std::size_t group) -> OwnerCache& {
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
        return bindings[group];
#else
        (void)group; return cache;
#endif
    }
    auto begin(std::size_t group,d::CacheKey key) -> std::expected<d::CacheToken,d::CacheError> {
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
        return cache.begin_query(group,std::move(key));
#else
        (void)group; return cache.begin_query(std::move(key));
#endif
    }
    auto publish(std::size_t group,d::CacheKey key,d::AddressAnswer answer,std::uint64_t now,d::CacheToken token) {
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
        return cache.publish(group,std::move(key),std::move(answer),now,token);
#else
        (void)group; return cache.publish(std::move(key),std::move(answer),now,token);
#endif
    }
    auto reader(std::size_t index) { return cache.reader(index); }
    template<class Reader>
    auto lookup(std::size_t group,d::CacheKey key,std::uint64_t now,Reader& reader) {
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
        return cache.lookup(group,std::move(key),now,reader);
#else
        (void)group; return cache.lookup(std::move(key),now,reader);
#endif
    }
    template<class Reader>
    auto stale(std::size_t group,d::CacheKey key,std::uint64_t now,Reader& reader) {
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
        return cache.lookup_stale(group,std::move(key),now,reader);
#else
        (void)group; return cache.lookup_stale(std::move(key),now,reader);
#endif
    }
    explicit Generation(io::endpoint endpoint,std::uint8_t value) : upstream(endpoint) {
        auto stamp=now_ms()-1200;
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
        auto initial_reader=reader(0);
#endif
        for (auto name:{"same.test","other.test","third.test","fourth.test"}) {
            d::CacheKey key{1,name,1}; d::Address address{}; address.size=4; address.bytes[3]=value;
            d::AddressAnswer answer{name,{name},{address},1};
            auto token=begin(0,key);
            if (!token || !publish(0,key,std::move(answer),stamp,*token)) throw std::runtime_error("generation seed failed");
#ifdef DNS_REFRESH_GROUP_EXPERIMENT
            auto adopted=lookup(1,key,stamp,initial_reader);
            if (!adopted || !*adopted) throw std::runtime_error("generation admission failed");
#endif
        }
    }
};
class Worker {
    enum class Op { start,pump,stop,inspect,drop,quit };
    struct Result { bool started=false,drained=false; std::size_t active=0; };
    struct Job {
        Op op; unsigned generation; std::string name; std::barrier<>* sync=nullptr;
        std::promise<Result> result;
    };
    Generation& first_; Generation& second_;
    bool uring_; std::size_t group_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<std::unique_ptr<Job>> queue_;
    std::thread thread_;
    auto loop(std::promise<void> ready) noexcept -> void {
        try {
#if BOOST_COROSIO_HAVE_LIBURING
            io::io_context context=uring_ ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
            io::io_context context(io::epoll);
#endif
            std::array<Generation*,2> generations{&first_,&second_};
            using Owner=d::detail::BasicRefreshOwner<OwnerCache>;
            std::array<std::unique_ptr<Owner>,2> owners;
            for (unsigned i=0;i<2;++i)
                owners[i]=std::make_unique<Owner>(context,generations[i]->binding(group_),3,10s,1s,&generations[i]->budget);
            ready.set_value();
            for (;;) {
                std::unique_ptr<Job> job;
                { std::unique_lock lock(mutex_); wake_.wait(lock,[&] { return !queue_.empty(); });
                  job=std::move(queue_.front()); queue_.pop_front(); }
                try {
                    Result result;
                    if (job->op==Op::quit) {
                        for (auto& owner:owners) if (owner) owner->stop();
                        context.restart(); (void)context.run_for(1s);
                        if (std::ranges::any_of(owners,[](auto const& owner) { return owner && !owner->drained(); }))
                            throw std::runtime_error("executor did not drain");
                        job->result.set_value(result); break;
                    }
                    if (job->op==Op::pump) { context.restart(); (void)context.run_for(100ms); }
                    else {
                        auto& owner=owners.at(job->generation);
                        if (!owner) throw std::logic_error("generation already dropped");
                        if (job->op==Op::start) {
                            if (job->sync) job->sync->arrive_and_wait();
                            result.started=owner->start({1,std::move(job->name),1},generations[job->generation]->upstream);
                        } else if (job->op==Op::stop) owner->stop();
                        else if (job->op==Op::drop) {
                            if (!owner->drained()) throw std::logic_error("dropping active generation");
                            owner.reset();
                        }
                        if (owner) { result.active=owner->active(); result.drained=owner->drained(); }
                    }
                    job->result.set_value(result);
                } catch (...) { job->result.set_exception(std::current_exception()); }
            }
        } catch (...) {
            try { ready.set_exception(std::current_exception()); } catch (...) { std::terminate(); }
        }
    }
    auto submit(Op op,unsigned generation=0,std::string name={},std::barrier<>* sync=nullptr) -> std::future<Result> {
        auto job=std::make_unique<Job>(); job->op=op; job->generation=generation; job->name=std::move(name); job->sync=sync;
        auto future=job->result.get_future();
        { std::lock_guard lock(mutex_); queue_.push_back(std::move(job)); }
        wake_.notify_one(); return future;
    }
public:
    Worker(Generation& first,Generation& second,bool uring,std::size_t group) : first_(first),second_(second),uring_(uring),group_(group) {
        std::promise<void> ready; auto future=ready.get_future();
        thread_=std::thread([this,ready=std::move(ready)]() mutable { loop(std::move(ready)); });
        try { future.get(); } catch (...) { thread_.join(); throw; }
    }
    Worker(Worker const&)=delete;
    ~Worker() {
        if (!thread_.joinable()) return;
        try { submit(Op::quit).get(); } catch (...) { std::terminate(); }
        thread_.join();
    }
    auto start(unsigned generation,std::string name,std::barrier<>* sync=nullptr) -> std::future<Result> {
        return submit(Op::start,generation,std::move(name),sync);
    }
    auto pump() -> std::future<Result> { return submit(Op::pump); }
    auto stop(unsigned generation) -> std::future<Result> { return submit(Op::stop,generation); }
    auto inspect(unsigned generation) -> std::future<Result> { return submit(Op::inspect,generation); }
    auto drop(unsigned generation) -> std::future<Result> { return submit(Op::drop,generation); }
};

auto run(bool uring) -> void {
    Peer old_peer,new_peer;
    Generation old(old_peer.endpoint,1),fresh(new_peer.endpoint,2);
    auto old_reader=old.reader(0),new_reader=fresh.reader(0);
    Worker a(old,fresh,uring,0),b(old,fresh,uring,1);
    auto pump=[&] { auto x=a.pump(),y=b.pump(); x.get(); y.get(); };
    auto assert_=[](bool value,char const* message) { if (!value) throw std::runtime_error(message); };
    std::barrier sync(2);
    auto x=a.start(0,"SAME.TEST.",&sync),y=b.start(0,"same.test",&sync);
    bool first=x.get().started,second=y.get().started;
    assert_(first!=second && old.budget.active()==1,"same-key cross-executor deduplication failed");
    auto& other=first ? b : a;
    assert_(other.start(0,"other.test").get().started && old.budget.active()==2,"second task failed");
    pump(); auto old_one=old_peer.receive(),old_two=old_peer.receive();
    // A replacement invalidates the old cache token, but its actual network
    // task continues to own its global permit and same-key lease.
    d::CacheKey same{1,"same.test",1}; d::Address replacement{}; replacement.size=4; replacement.bytes[3]=7;
    auto token=old.begin(0,same);
    assert_(token && old.publish(0,same,{same.name,{same.name},{replacement},1},now_ms(),*token).has_value(),"replacement failed");
    std::this_thread::sleep_for(1100ms);
    assert_(!other.start(0,"SAME.TEST.").get().started && old.budget.active()==2,"live task lost same-key lease");
    assert_(a.start(0,"third.test").get().started && old.budget.active()==3 &&
            !b.start(0,"fourth.test").get().started,"shared task limit failed");
    pump(); auto old_three=old_peer.receive();
    // A new immutable configuration may reuse numeric view 1 but has a distinct
    // cache and budget, so its query must not reuse or block on the old one.
    assert_(b.start(1,"same.test").get().started && fresh.budget.active()==1,"new generation blocked by old lease");
    pump(); auto new_one=new_peer.receive(); new_peer.reply(std::move(new_one),9); pump();
    auto new_hit=fresh.lookup(0,same,now_ms(),new_reader);
    auto new_other=fresh.lookup(1,same,now_ms(),new_reader);
    auto old_stale=old.stale(0,same,now_ms(),old_reader);
    auto old_other=old.stale(1,same,now_ms(),old_reader);
    assert_(new_hit && *new_hit && (**new_hit).addresses[0].bytes[3]==9 && old_stale && *old_stale &&
            (**old_stale).answer.addresses[0].bytes[3]==7 && new_other && *new_other &&
            (**new_other).addresses[0].bytes[3]==9 && old_other && *old_other &&
            (**old_other).answer.addresses[0].bytes[3]==7 && fresh.budget.active()==0,"generation results mixed");
    assert_(a.start(1,"other.test").get().started,"new generation concurrent task failed");
    pump(); auto new_two=new_peer.receive();
    auto stop_a=a.stop(0),stop_b=b.stop(0); stop_a.get(); stop_b.get();
    assert_(old.budget.active()==3 && fresh.budget.active()==1,"cancel released running leases early");
    old_peer.reply(std::move(old_one),11); old_peer.reply(std::move(old_two),11); old_peer.reply(std::move(old_three),11);
    pump();
    assert_(a.inspect(0).get().drained && b.inspect(0).get().drained && old.budget.active()==0 && fresh.budget.active()==1,
            "old generation did not drain independently");
    old_stale=old.stale(0,same,now_ms(),old_reader);
    assert_(old_stale && *old_stale && (**old_stale).answer.addresses[0].bytes[3]==7,"canceled late response published");
    a.drop(0).get(); b.drop(0).get();
    new_peer.reply(std::move(new_two),10); pump();
    d::CacheKey other_key{1,"other.test",1}; auto other_hit=fresh.lookup(1,other_key,now_ms(),new_reader);
    assert_(other_hit && *other_hit && (**other_hit).addresses[0].bytes[3]==10 && fresh.budget.active()==0,
            "new generation failed after old owner dropped");
    auto stop_new_a=a.stop(1),stop_new_b=b.stop(1); stop_new_a.get(); stop_new_b.get(); pump();
    assert_(a.inspect(1).get().drained && b.inspect(1).get().drained,"new generation did not drain");
    a.drop(1).get(); b.drop(1).get();
}
int main() {
    try {
        run(false);
#if BOOST_COROSIO_HAVE_LIBURING
        run(true);
#endif
        std::puts("two DNS executors: leases, configuration generations, late replies and drain passed");
    } catch (std::exception const& error) { std::cerr<<"DNS executor test: "<<error.what()<<'\n'; return 1; }
}
