// Real DNS datagrams through the generic cached resolver. This is an isolated
// experiment, not an enabled proxy path or a production load benchmark.
#include <arpa/inet.h>
#include <cstdlib>
#include <new>
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
#include "../../src/dns-shared/group_cache_binding.hpp"

namespace {
thread_local bool fail_next_allocation=false,allocation_failed=false;
auto should_fail() noexcept -> bool {
    if (!fail_next_allocation) return false;
    fail_next_allocation=false; allocation_failed=true; return true;
}
}
auto operator new(std::size_t size) -> void* {
    if (should_fail()) throw std::bad_alloc();
    if (auto* pointer=std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer,std::size_t) noexcept { std::free(pointer); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {
    if (should_fail()) throw std::bad_alloc();
    void* pointer=nullptr;
    if (posix_memalign(&pointer,static_cast<std::size_t>(alignment),size ? size : 1)==0) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer,std::align_val_t) noexcept { std::free(pointer); }
void operator delete(void* pointer,std::size_t,std::align_val_t) noexcept { std::free(pointer); }

namespace d=dns;
namespace io=nex::corosio;
using Cache=dns_hp_experiment::GroupSnapshot;
using Binding=dns_hp_experiment::GroupBinding;
using Resolver=d::detail::BasicCachedAddressResolver<Binding>;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;

auto stamp() -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
}
auto seed(Cache& cache,d::CacheKey const& key,std::uint64_t now) -> bool {
    d::Address address{}; address.size=4; address.bytes[3]=1;
    d::AddressAnswer answer{key.name,std::vector<std::string>(16,std::string(200,'a')),std::vector<d::Address>(128,address),60};
    auto token=cache.begin_query(0,key);
    return token && cache.publish_view(0,key.view,key.name,key.type,std::move(answer),now,*token).has_value();
}
struct Peer {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    io::endpoint endpoint{io::ipv4_address::loopback(),0};
    unsigned requests=0;
    struct Packet { std::vector<std::uint8_t> data; sockaddr_in from{}; socklen_t length=sizeof(from); };
    Peer() {
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if (fd<0 || bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) throw std::runtime_error("bind failed");
        socklen_t length=sizeof(address);
        if (getsockname(fd,reinterpret_cast<sockaddr*>(&address),&length)) throw std::runtime_error("getsockname failed");
        endpoint=io::endpoint(io::ipv4_address::loopback(),ntohs(address.sin_port));
    }
    ~Peer() { if (fd>=0) close(fd); }
    auto receive() -> Packet {
        pollfd wait{fd,POLLIN,0}; if (poll(&wait,1,2000)!=1) throw std::runtime_error("query timeout");
        Packet packet; std::array<std::uint8_t,4096> data{};
        auto count=recvfrom(fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&packet.from),&packet.length);
        if (count<17) throw std::runtime_error("short query");
        packet.data.assign(data.begin(),data.begin()+count); ++requests; return packet;
    }
    auto reply(Packet packet) -> void {
        packet.data[2]=0x81; packet.data[3]=0x80;
        if (packet.data[packet.data.size()-4]==0 && packet.data[packet.data.size()-3]==28) {
            packet.data[9]=1;
            std::array<std::uint8_t,36> soa{0xc0,0x0c,0,6,0,1,0,0,0,30,0,24,0xc0,0x0c,0xc0,0x0c,
                                            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30};
            packet.data.insert(packet.data.end(),soa.begin(),soa.end());
        } else {
            packet.data[7]=1;
            std::array<std::uint8_t,16> answer{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,127,0,0,9};
            packet.data.insert(packet.data.end(),answer.begin(),answer.end());
        }
        if (sendto(fd,packet.data.data(),packet.data.size(),0,reinterpret_cast<sockaddr*>(&packet.from),packet.length)!=static_cast<ssize_t>(packet.data.size()))
            throw std::runtime_error("send failed");
    }
    auto reply() -> void { reply(receive()); }
    auto empty() -> bool { pollfd wait{fd,POLLIN,0}; return poll(&wait,1,0)==0; }
};
auto operation(Resolver& resolver,io::endpoint upstream,std::string name,
               std::optional<std::expected<d::AddressAnswer,d::detail::ResolveError>>& result) -> boost::capy::task<> {
    result=co_await resolver.resolve(upstream,1,{std::move(name),1},Clock::now()+3s);
}

// Two executor threads start same-key foreground queries while the shared
// cache is disabled. The peer holds every reply until one executor cancels;
// this measures an actual upstream burst and verifies cancellation drains.
auto burst(Cache& cache,Peer& peer,bool uring,std::string const& name) -> void {
    constexpr std::size_t count=8;
    struct Outcome { std::atomic<bool> done=false; std::exception_ptr failure; unsigned success=0,canceled=0; };
    std::array<Outcome,2> outcome; std::atomic<bool> cancel=false;
    auto worker=[&](std::stop_token stop,std::size_t group) {
        try {
#if BOOST_COROSIO_HAVE_LIBURING
            io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
            (void)uring; io::io_context context(io::epoll);
#endif
            auto reader=cache.reader(group+2); Binding binding(cache,group);
            using Result=std::expected<d::AddressAnswer,d::detail::ResolveError>;
            std::array<std::unique_ptr<Resolver>,count> resolvers;
            std::array<std::optional<Result>,count> results;
            std::array<std::exception_ptr,count> errors;
            std::array<bool,count> finished; finished.fill(true);
            struct Drain {
                io::io_context& context;
                std::array<std::unique_ptr<Resolver>,count>& resolvers;
                std::array<bool,count>& finished;
                ~Drain() {
                    for (auto& resolver:resolvers) if (resolver) resolver->cancel();
                    auto deadline=Clock::now()+2s;
                    try {
                        while (!std::ranges::all_of(finished,[](bool value) { return value; }) && Clock::now()<deadline) {
                            context.restart(); (void)context.run_for(10ms);
                        }
                    } catch (...) { std::terminate(); }
                    if (!std::ranges::all_of(finished,[](bool value) { return value; })) std::terminate();
                }
            } drain{context,resolvers,finished};
            for (std::size_t i=0;i<count;++i) {
                resolvers[i]=std::make_unique<Resolver>(context,binding,false,false,false,nullptr,&reader);
                finished[i]=false;
                try {
                    boost::capy::run_async(context.get_executor(),[&,i] { finished[i]=true; },
                        [&,i](std::exception_ptr error) { errors[i]=error; finished[i]=true; })
                        (operation(*resolvers[i],peer.endpoint,name,results[i]));
                } catch (...) { finished[i]=true; throw; }
            }
            bool canceled=false; auto deadline=Clock::now()+5s;
            while (!std::ranges::all_of(finished,[](bool value) { return value; })) {
                if (!canceled && (stop.stop_requested() || (group==0 && cancel.load()))) {
                    for (auto& resolver:resolvers) resolver->cancel();
                    canceled=true;
                }
                if (Clock::now()>=deadline) throw std::runtime_error("burst did not drain");
                context.restart(); (void)context.run_for(10ms);
            }
            for (std::size_t i=0;i<count;++i) {
                if (errors[i]) std::rethrow_exception(errors[i]);
                if (!results[i]) throw std::runtime_error("missing burst result");
                if (*results[i]) {
                    if ((**results[i]).addresses.size()!=1 || (**results[i]).addresses[0].bytes[3]!=9)
                        throw std::runtime_error("wrong burst answer");
                    ++outcome[group].success;
                } else if (results[i]->error()==d::detail::ResolveError::canceled) ++outcome[group].canceled;
                else throw std::runtime_error("unexpected burst error");
            }
        } catch (...) { outcome[group].failure=std::current_exception(); }
        outcome[group].done.store(true,std::memory_order_release);
    };
    std::jthread first(worker,0),second(worker,1);
    std::vector<Peer::Packet> queries;
    for (std::size_t i=0;i<count*2;++i) queries.push_back(peer.receive());
    cancel.store(true);
    auto deadline=Clock::now()+2s;
    while (!outcome[0].done.load(std::memory_order_acquire) && Clock::now()<deadline) std::this_thread::sleep_for(1ms);
    if (!outcome[0].done.load(std::memory_order_acquire)) throw std::runtime_error("burst cancellation timed out");
    if (outcome[0].failure) std::rethrow_exception(outcome[0].failure);
    if (outcome[0].canceled!=count || outcome[0].success) throw std::runtime_error("burst cancellation failed");
    for (auto& query:queries) peer.reply(std::move(query));
    first.join(); second.join();
    if (outcome[1].failure) std::rethrow_exception(outcome[1].failure);
    if (outcome[1].success!=count || outcome[1].canceled) throw std::runtime_error("burst responses failed");
}

class FaultBinding : public Binding {
    bool registration_,publication_;
    struct Fault {
        Fault() { allocation_failed=false; fail_next_allocation=true; }
        ~Fault() { fail_next_allocation=false; }
    };
public:
    bool observed=false;
    FaultBinding(Cache& cache,bool registration) : Binding(cache,0),registration_(registration),publication_(!registration) {}
    auto begin_query(d::CacheKey const& key) {
        if (!registration_) return Binding::begin_query(key);
        registration_=false; Fault fault;
        auto result=Binding::begin_query(key); observed=allocation_failed;
        return result;
    }
    using Binding::publish;
    auto publish(d::CacheKey const& key,d::AddressAnswer const& answer,std::uint64_t now,Token token) {
        if (!publication_) return Binding::publish(key,answer,now,token);
        publication_=false; Fault fault;
        auto result=Binding::publish(key,answer,now,token); observed=allocation_failed;
        return result;
    }
};
auto allocation_network(bool uring,bool registration) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)uring; io::io_context context(io::epoll);
#endif
    std::array<std::size_t,1> capacities{2}; Cache cache(capacities,1,0,1024*1024);
    auto reader=cache.reader(0); d::CacheKey old{1,"existing-allocation.example.test",1};
    if (!seed(cache,old,stamp())) throw std::runtime_error("allocation seed failed");
    FaultBinding binding(cache,registration); Peer peer;
    d::detail::BasicCachedAddressResolver<FaultBinding> resolver(context,binding,false,false,false,nullptr,&reader);
    std::optional<std::expected<d::AddressAnswer,d::detail::ResolveError>> result;
    bool finished=false; std::exception_ptr failure;
    auto run=[&]() -> boost::capy::task<> {
        result=co_await resolver.resolve(peer.endpoint,1,{"new-allocation.example.test",1},Clock::now()+3s);
    };
    boost::capy::run_async(context.get_executor(),[&] { finished=true; },[&](std::exception_ptr error) { failure=error; finished=true; })(run());
    context.restart(); (void)context.run_for(30ms);
    if (finished) throw std::runtime_error("allocation network query did not start");
    peer.reply(); context.restart(); (void)context.run_for(100ms);
    if (failure) std::rethrow_exception(failure);
    if (!finished || !result || !*result || (**result).addresses.size()!=1 || (**result).addresses[0].bytes[3]!=9 || !binding.observed)
        throw std::runtime_error("allocation failure lost network answer");
    auto old_result=cache.lookup(0,old,stamp(),reader); auto disabled=cache.begin_query(0,old);
    if (!old_result || *old_result || disabled || disabled.error()!=d::CacheError::disabled || !cache.clear(stamp()) ||
        !seed(cache,old,stamp())) throw std::runtime_error("allocation failure did not close and recover cache");
}

auto dual_network(bool uring) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)uring; io::io_context context(io::epoll);
#endif
    std::array<std::size_t,2> capacities{4,4}; Cache cache(capacities,1,0,1024*1024);
    auto reader=cache.reader(0); Binding first(cache,0),second(cache,1); Peer peer;
    using Dual=d::detail::BasicDualAddressResolver<Binding>;
    auto request=[&](Binding& binding,bool network) {
        Dual resolver(context,binding,false,d::detail::AddressStrategy::prefer_ipv4,false,false,nullptr,&reader);
        std::optional<std::expected<std::vector<d::Address>,d::detail::ResolveError>> result;
        bool finished=false; std::exception_ptr failure;
        auto run=[&]() -> boost::capy::task<> {
            result=co_await resolver.resolve(peer.endpoint,1,"dual-group.example.test",Clock::now()+3s);
        };
        boost::capy::run_async(context.get_executor(),[&] { finished=true; },[&](std::exception_ptr error) { failure=error; finished=true; })(run());
        context.restart(); (void)context.run_for(30ms);
        if (network) {
            for (unsigned i=0;i<2;++i) {
                if (finished) throw std::runtime_error("dual query ended before both families");
                peer.reply(); context.restart(); (void)context.run_for(30ms);
            }
        } else if (!peer.empty()) throw std::runtime_error("dual cache hit queried upstream");
        if (failure) std::rethrow_exception(failure);
        if (!finished || !result || !*result || (**result).size()!=1 || (**result)[0].bytes[3]!=9)
            throw std::runtime_error("dual group resolution failed");
    };
    request(first,true); request(second,false);
    if (peer.requests!=2) throw std::runtime_error("dual positive/negative cache not shared");
}

auto run(bool uring,bool automatic) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)uring; io::io_context context(io::epoll);
#endif
    Peer peer; std::array<std::size_t,2> capacities{2,2}; d::CacheKey old{1,"old-group.test",1},next{1,"new-group.test",1};
    auto now=stamp(); std::size_t limit=0;
    {
        Cache measure(capacities,4,0);
        if (!seed(measure,old,now)) throw std::runtime_error("cannot measure initial budget");
        limit=measure.charged_bytes();
    }
    Cache cache(capacities,4,0,limit,automatic ? 25 : 0); auto held=cache.reader(0),reader=cache.reader(1);
    Binding first(cache,0),second(cache,1);
    if (!seed(cache,old,now)) throw std::runtime_error("cannot seed bounded cache");
    auto request=[&](Binding& binding,bool network) {
        Resolver resolver(context,binding,false,false,false,nullptr,&reader);
        std::optional<std::expected<d::AddressAnswer,d::detail::ResolveError>> result;
        bool finished=false; std::exception_ptr failure;
        boost::capy::run_async(context.get_executor(),[&] { finished=true; },[&](std::exception_ptr error) { failure=error; finished=true; })
            (operation(resolver,peer.endpoint,next.name,result));
        context.restart(); (void)context.run_for(30ms);
        if (network) { if (finished) throw std::runtime_error("expected DNS request"); peer.reply(); context.restart(); (void)context.run_for(100ms); }
        else if (!peer.empty()) throw std::runtime_error("unexpected DNS request on cache hit");
        if (failure) std::rethrow_exception(failure);
        if (!finished || !result || !*result || (**result).addresses.size()!=1 || (**result).addresses[0].bytes[3]!=9)
            throw std::runtime_error("resolver result invalid");
    };
    bool bypassed=false;
    auto old_result=cache.lookup_with_hook(0,old,now,held,[&] {
        request(first,true);
        auto rejected=cache.begin_query(0,next);
        if (rejected || rejected.error()!=d::CacheError::disabled) return;
        // Each call bypasses the cache while disabled; this deterministic
        // sequence illustrates upstream amplification, not real concurrency.
        for (unsigned i=0;i<8;++i) request(i%2 ? second : first,true);
        burst(cache,peer,uring,next.name);
        bypassed=true;
    });
    if (!old_result || *old_result || !bypassed || peer.requests!=25 || cache.peak_charged_bytes()>limit)
        throw std::runtime_error("budget bypass failed");
    if (!automatic && !cache.clear(stamp())) throw std::runtime_error("clear failed");
    if (automatic) std::this_thread::sleep_for(30ms);
    request(first,true);
    request(second,false);
    if (peer.requests!=26 || cache.peak_charged_bytes()>limit) throw std::runtime_error("recovery or shared hit failed");
}
int main() {
    try {
        run(false,false); run(false,true);
        allocation_network(false,true); allocation_network(false,false);
        dual_network(false);
#if BOOST_COROSIO_HAVE_LIBURING
        run(true,false); run(true,true);
        allocation_network(true,true); allocation_network(true,false);
        dual_network(true);
#endif
        std::puts("DNS budget bypass, concurrent cancellation, allocation-fault answers and dual-family group sharing passed");
    } catch (std::exception const& error) { std::cerr<<"DNS budget bypass: "<<error.what()<<'\n'; return 1; }
}
