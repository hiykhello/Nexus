// Two real executor threads and a real UDP DNS peer exercise the experimental
// foreground coalescer. No production path uses this code.
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import capy;
import corosio;
import std;
import dns.corosio_cached;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.group_cache_binding;
import dns.group_coalesced_resolve;

namespace d=dns;
namespace io = ::corosio;
namespace hp=dns_hp_experiment;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
using Result=hp::FlightGroup::Result;
using Error=d::detail::ResolveError;
using Key=hp::FlightGroup::Key;

namespace {
thread_local int fail_after=-1;
thread_local bool injected=false;
}
void* operator new(std::size_t size) {
    if (fail_after>=0 && fail_after--==0) { fail_after=-1; injected=true; throw std::bad_alloc(); }
    if (auto* value=std::malloc(size ? size : 1)) return value;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value,std::size_t) noexcept { std::free(value); }

namespace {
auto require(bool condition,char const* reason) -> void {
    if (!condition) throw std::runtime_error(reason);
}
auto stamp() -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
}
auto key(io::endpoint endpoint,std::string name="same.example.test",std::uint64_t view=1,std::uint16_t type=1) -> Key {
    return {{view,std::move(name),type},endpoint,false,false,true};
}
struct Peer {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    io::endpoint endpoint{io::ipv4_address::loopback(),0};
    struct Packet { std::vector<std::uint8_t> data; sockaddr_in sender{}; };
    Peer() {
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        require(fd>=0 && !::bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address)),"DNS peer bind failed");
        socklen_t size=sizeof(address);
        require(!::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size),"DNS peer address failed");
        endpoint=io::endpoint(io::ipv4_address::loopback(),ntohs(address.sin_port));
    }
    ~Peer() { if (fd>=0) ::close(fd); }
    auto receive() -> Packet {
        pollfd wait{fd,POLLIN,0}; require(::poll(&wait,1,3000)==1 && (wait.revents&POLLIN),"DNS query timeout");
        Packet packet; std::array<std::uint8_t,4096> data{}; socklen_t length=sizeof(packet.sender);
        auto count=::recvfrom(fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&packet.sender),&length);
        require(count>=17,"short DNS query"); packet.data.assign(data.begin(),data.begin()+count); return packet;
    }
    auto empty(std::chrono::milliseconds wait=100ms) -> bool {
        pollfd p{fd,POLLIN,0}; return ::poll(&p,1,static_cast<int>(wait.count()))==0;
    }
    auto reply(Packet packet,std::uint8_t address,bool negative=false,std::uint32_t ttl=30,bool no_data=false,bool soa=true) -> void {
        packet.data[2]=0x81; packet.data[3]=negative && !no_data ? 0x83 : 0x80;
        if (negative && soa) {
            packet.data[9]=1;
            std::array<std::uint8_t,36> soa{0xc0,0x0c,0,6,0,1,0,0,0,30,0,24,0xc0,0x0c,0xc0,0x0c,
                                            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30};
            for (unsigned i=0;i<4;++i) {
                soa[6+i]=static_cast<std::uint8_t>(ttl>>(24-8*i));
                soa[32+i]=static_cast<std::uint8_t>(ttl>>(24-8*i));
            }
            packet.data.insert(packet.data.end(),soa.begin(),soa.end());
        } else if (!negative) {
            packet.data[7]=1;
            std::array<std::uint8_t,16> answer{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,127,0,0,address};
            answer[6]=static_cast<std::uint8_t>(ttl>>24); answer[7]=static_cast<std::uint8_t>(ttl>>16);
            answer[8]=static_cast<std::uint8_t>(ttl>>8); answer[9]=static_cast<std::uint8_t>(ttl);
            packet.data.insert(packet.data.end(),answer.begin(),answer.end());
        }
        require(::sendto(fd,packet.data.data(),packet.data.size(),0,reinterpret_cast<sockaddr*>(&packet.sender),sizeof(packet.sender))==
                    static_cast<ssize_t>(packet.data.size()),"DNS reply failed");
    }
    auto fail(Packet packet,std::uint8_t code=2) -> void {
        packet.data[2]=0x81; packet.data[3]=static_cast<std::uint8_t>(0x80|code);
        require(::sendto(fd,packet.data.data(),packet.data.size(),0,reinterpret_cast<sockaddr*>(&packet.sender),sizeof(packet.sender))==
                    static_cast<ssize_t>(packet.data.size()),"DNS failure reply failed");
    }
};
struct TcpPeer {
    int fd=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    io::endpoint endpoint{io::ipv4_address::loopback(),0};
    struct Packet {
        int fd=-1;
        std::vector<std::uint8_t> data;
        Packet(int socket,std::vector<std::uint8_t> value) : fd(socket),data(std::move(value)) {}
        Packet(Packet const&)=delete;
        Packet(Packet&& other) noexcept : fd(std::exchange(other.fd,-1)),data(std::move(other.data)) {}
        ~Packet() { if (fd>=0) ::close(fd); }
    };
    explicit TcpPeer(std::uint16_t port=0) {
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
        require(fd>=0 && !::bind(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address)) && !::listen(fd,16),"TCP DNS peer bind failed");
        socklen_t size=sizeof(address);
        require(!::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size),"TCP DNS peer address failed");
        endpoint=io::endpoint(io::ipv4_address::loopback(),ntohs(address.sin_port));
    }
    ~TcpPeer() { if (fd>=0) ::close(fd); }
    static auto read_exact(int socket,std::span<std::uint8_t> bytes) -> void {
        while (!bytes.empty()) {
            pollfd wait{socket,POLLIN,0}; require(::poll(&wait,1,3000)==1 && (wait.revents&POLLIN),"TCP DNS read timeout");
            auto count=::recv(socket,bytes.data(),bytes.size(),0);
            require(count>0,"TCP DNS query closed early"); bytes=bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    auto receive() -> Packet {
        pollfd wait{fd,POLLIN,0}; require(::poll(&wait,1,3000)==1 && (wait.revents&POLLIN),"TCP DNS accept timeout");
        auto socket=::accept4(fd,nullptr,nullptr,SOCK_CLOEXEC); require(socket>=0,"TCP DNS accept failed");
        Packet packet(socket,{}); std::array<std::uint8_t,2> length{}; read_exact(socket,length);
        auto size=(std::size_t(length[0])<<8)|length[1]; require(size>=17 && size<=4096,"invalid TCP DNS query length");
        packet.data.resize(size); read_exact(socket,packet.data); return packet;
    }
    auto empty() -> bool { pollfd wait{fd,POLLIN,0}; return ::poll(&wait,1,100)==0; }
    auto reply(Packet packet,std::uint8_t address) -> void {
        std::vector<std::uint8_t> opt;
        if (packet.data[11]) {
            require(packet.data[11]==1 && packet.data.size()>=11,"invalid EDNS query");
            opt.assign(packet.data.end()-11,packet.data.end()); packet.data.resize(packet.data.size()-11);
        }
        packet.data[2]=0x81; packet.data[3]=0x80; packet.data[7]=1;
        std::array<std::uint8_t,16> answer{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,127,0,0,address};
        packet.data.insert(packet.data.end(),answer.begin(),answer.end()); packet.data.insert(packet.data.end(),opt.begin(),opt.end());
        std::vector<std::uint8_t> frame{static_cast<std::uint8_t>(packet.data.size()>>8),static_cast<std::uint8_t>(packet.data.size())};
        frame.insert(frame.end(),packet.data.begin(),packet.data.end());
        std::span<std::uint8_t const> remaining(frame);
        while (!remaining.empty()) {
            auto count=::send(packet.fd,remaining.data(),remaining.size(),MSG_NOSIGNAL);
            require(count>0,"TCP DNS reply failed"); remaining=remaining.subspan(static_cast<std::size_t>(count));
        }
    }
};
auto allocation_failures(io::endpoint endpoint) -> void {
    for (bool existing:{false,true}) {
        unsigned failures=0; bool exhausted=false;
        for (int position=0;position<16;++position) {
            hp::FlightGroup faults(2,4);
            hp::FlightGroup::Waiter seed_waiter,attempt_waiter;
            std::optional<hp::FlightGroup::Joined> seed;
            if (existing) { auto result=faults.join(key(endpoint),seed_waiter); require(result.has_value(),"fault seed failed"); seed=*result; }
            auto attempt=key(endpoint);
            attempt.cache.name.reserve(1024); // exercise input compaction even for an existing flight
            injected=false; fail_after=position;
            try {
                auto result=faults.join(std::move(attempt),attempt_waiter); fail_after=-1;
                require(result.has_value(),"fault join returned error");
                faults.leave(attempt_waiter);
                if (!existing) { faults.complete(result->flight,std::unexpected(Error::canceled)); faults.finish(result->flight); }
                exhausted=true;
            } catch (std::bad_alloc const&) {
                fail_after=-1; require(injected,"unexpected allocation failure"); ++failures;
                require(faults.counts()==(existing ? std::pair<std::size_t,std::size_t>{1,1} : std::pair<std::size_t,std::size_t>{0,0}),
                        "registration allocation failure changed flight counts");
            }
            if (seed) { faults.leave(seed_waiter); faults.complete(seed->flight,std::unexpected(Error::canceled)); faults.finish(seed->flight); }
            if (exhausted) break;
        }
        require(exhausted && failures,"allocation sweep did not cover registration");
    }
    for (bool existing:{false,true}) {
        unsigned failures=0; bool exhausted=false;
        for (int position=0;position<16;++position) {
            hp::FlightGroup faults(2,4);
            std::optional<hp::FlightGroup::Joined> seed;
            if (existing) {
                auto result=faults.join_background(key(endpoint));
                require(result.has_value(),"background fault seed failed"); seed=*result;
            }
            auto attempt=key(endpoint); attempt.cache.name.reserve(1024);
            injected=false; fail_after=position;
            try {
                auto result=faults.join_background(std::move(attempt)); fail_after=-1;
                require(result && result->leader!=existing,"background fault registration returned an invalid result");
                if (!existing) { faults.complete(result->flight,std::unexpected(Error::canceled)); faults.finish(result->flight); }
                exhausted=true;
            } catch (std::bad_alloc const&) {
                fail_after=-1; require(injected,"unexpected background allocation failure"); ++failures;
                require(faults.counts()==(existing ? std::pair<std::size_t,std::size_t>{1,0} : std::pair<std::size_t,std::size_t>{0,0}),
                        "background allocation failure changed flight counts");
            }
            if (seed) { faults.complete(seed->flight,std::unexpected(Error::canceled)); faults.finish(seed->flight); }
            if (exhausted) break;
        }
        require(exhausted && failures,"allocation sweep did not cover background registration");
    }
}
auto retained_flights(io::endpoint endpoint) -> void {
    hp::FlightGroup group(2,4);
    hp::FlightGroup::Waiter a,b,next,full;
    auto first=group.join(key(endpoint),a);
    auto follower=group.join(key(endpoint,"SAME.EXAMPLE.TEST"),b);
    require(first && first->leader && follower && !follower->leader && first->flight==follower->flight,
            "normalized waiters did not join one flight");
    auto completed=Clock::now()+1s; // deterministic synthetic completion times
    d::AddressAnswer answer{"same.example.test",{"same.example.test"},{},20};
    group.complete(first->flight,std::move(answer),completed);
    auto immediately=group.result(a,completed);
    auto delayed=group.result(a,completed+3100ms);
    auto expired=group.result(a,completed+21s);
    require(immediately && !immediately->expired && immediately->answer && immediately->answer->ttl==20 &&
            delayed && !delayed->expired && delayed->answer && delayed->answer->ttl==16 && expired && expired->expired,
            "retained answer TTL did not decrease or expire");
    fail_after=0; injected=false;
    try { (void)group.result(a,completed); fail_after=-1; throw std::runtime_error("result copy fault not injected"); }
    catch (std::bad_alloc const&) { fail_after=-1; require(injected,"unexpected result copy allocation failure"); }
    auto retry=group.result(a,completed);
    require(retry && !retry->expired && retry->answer && retry->answer->ttl==20,"result copy fault damaged the retained answer");
    // A completed result is never joined by a later caller. Both retained
    // flights still count against capacity while a slow waiter owns a slot.
    auto later=group.join(key(endpoint),next);
    require(later && later->leader && later->flight!=first->flight,"later request joined completed result");
    auto rejected=group.join(key(endpoint,"another.example.test"),full);
    require(!rejected && rejected.error()==Error::limit,"retained result escaped flight capacity");
    group.finish(first->flight);
    group.leave(b);
    require(group.counts()==std::pair<std::size_t,std::size_t>{2,2},"slow waiter did not retain its result");
    group.leave(a);
    require(group.counts()==std::pair<std::size_t,std::size_t>{1,1},"completed flight did not release after last waiter");
    auto reused=group.join(key(endpoint),a);
    require(!reused && reused.error()==Error::state,"one-shot waiter was reused");
    group.complete(later->flight,std::unexpected(Error::canceled));
    group.leave(next);
    require(group.counts()==std::pair<std::size_t,std::size_t>{1,0},"flight released before its task finished");
    group.finish(later->flight);
    require(group.counts()==std::pair<std::size_t,std::size_t>{0,0},"flight remained after task and waiters finished");

    // Every network-affecting option is part of the merge key.
    hp::FlightGroup options(5,5);
    hp::FlightGroup::Waiter plain,tcp,edns,no_cache,other_type;
    auto plain_key=key(endpoint),tcp_key=plain_key,edns_key=plain_key,no_cache_key=plain_key,aaaa_key=plain_key;
    tcp_key.tcp=true; edns_key.edns=true; no_cache_key.use_cache=false; aaaa_key.cache.type=28;
    auto p=options.join(std::move(plain_key),plain),t=options.join(std::move(tcp_key),tcp),
         e=options.join(std::move(edns_key),edns),n=options.join(std::move(no_cache_key),no_cache),
         q=options.join(std::move(aaaa_key),other_type);
    require(p && t && e && n && q && p->leader && t->leader && e->leader && n->leader && q->leader &&
            options.counts()==std::pair<std::size_t,std::size_t>{5,5},"query options were coalesced");
    for (auto* waiter:{&plain,&tcp,&edns,&no_cache,&other_type}) options.leave(*waiter);
    for (auto flight:{p->flight,t->flight,e->flight,n->flight,q->flight}) {
        options.complete(flight,std::unexpected(Error::canceled)); options.finish(flight);
    }
    require(options.counts()==std::pair<std::size_t,std::size_t>{0,0},"isolated flights did not drain");
    hp::FlightGroup negatives(1,1); hp::FlightGroup::Waiter negative_waiter;
    auto negative=negatives.join(key(endpoint,"delayed-negative.example.test"),negative_waiter);
    require(negative && negative->leader,"negative flight registration failed");
    negatives.complete(negative->flight,std::unexpected(Error::name_not_found),completed,2);
    auto valid_negative=negatives.result(negative_waiter,completed+1999ms);
    auto expired_negative=negatives.result(negative_waiter,completed+2s);
    require(valid_negative && !valid_negative->expired && !valid_negative->answer &&
            valid_negative->answer.error()==Error::name_not_found && expired_negative && expired_negative->expired,
            "retained negative TTL boundary failed");
    negatives.finish(negative->flight); negatives.leave(negative_waiter);

    hp::FlightGroup timed(1,1); hp::FlightGroup::Waiter timed_waiter;
    auto cached=timed.join(key(endpoint,"fractional-cached.example.test"),timed_waiter);
    require(cached && cached->leader,"timed cache flight registration failed");
    d::AddressAnswer fractional{"fractional-cached.example.test",{"fractional-cached.example.test"},{},0};
    timed.complete(cached->flight,std::move(fractional),completed,{},completed+250ms);
    auto within=timed.result(timed_waiter,completed+249ms),past=timed.result(timed_waiter,completed+250ms);
    require(within && !within->expired && within->answer && within->answer->ttl==0 && past && past->expired,
            "fractional cached TTL did not honor its absolute expiry");
    timed.finish(cached->flight); timed.leave(timed_waiter);
}
auto capacity_boundaries(io::endpoint endpoint) -> void {
    {
        hp::FlightGroup group(1,2); hp::FlightGroup::Waiter waiter;
        auto background=group.join_background(key(endpoint));
        require(background && background->leader && group.counts()==std::pair<std::size_t,std::size_t>{1,0},
                "background did not reserve a flight");
        auto duplicate=group.join_background(key(endpoint));
        auto foreground=group.join(key(endpoint),waiter);
        require(duplicate && !duplicate->leader && foreground && !foreground->leader &&
                foreground->flight==background->flight,"foreground did not join background");
        group.leave(waiter);
        require(!group.retiring(background->flight),"background interest was lost after the last waiter");
        group.complete(background->flight,std::unexpected(Error::canceled)); group.finish(background->flight);
        require(group.counts()==std::pair<std::size_t,std::size_t>{0,0},"background flight did not drain");
        hp::FlightGroup::Waiter first;
        auto leader=group.join(key(endpoint),first),interest=group.join_background(key(endpoint));
        require(leader && leader->leader && interest && !interest->leader && interest->flight==leader->flight,
                "background did not attach to foreground");
        group.leave(first);
        require(!group.retiring(leader->flight),"attached background interest did not retain the task");
        group.complete(leader->flight,std::unexpected(Error::canceled)); group.finish(leader->flight);
    }
    {
        hp::FlightGroup group(1,1); hp::FlightGroup::Waiter waiter;
        auto background=group.join_background(key(endpoint)),joined=group.join(key(endpoint),waiter);
        require(background && joined && !joined->leader,"retry test failed to register");
        group.complete_retry(background->flight); auto result=group.result(waiter);
        require(result && result->expired,"ineligible background did not request a retry");
        group.finish(background->flight); group.leave(waiter);
        require(group.counts()==std::pair<std::size_t,std::size_t>{0,0},"retry flight did not drain");
    }
    {
        hp::FlightGroup group(2,3); hp::FlightGroup::Waiter first,follower,excess;
        auto direct=group.try_direct(); require(direct && group.direct_active()==1,"direct work did not reserve a slot");
        auto moved=std::move(direct); direct.reset();
        require(group.direct_active()==1,"moving a direct lease released its slot");
        auto flight=group.join(key(endpoint),first);
        require(flight && flight->leader && !group.try_direct(),"flight and direct work did not share the limit");
        auto rejected=group.join(key(endpoint,"other.example.test"),excess);
        require(!rejected && rejected.error()==Error::limit,"mixed limit admitted another flight");
        auto joined=group.join(key(endpoint),follower);
        require(joined && !joined->leader,"full work budget rejected an existing-flight waiter");
        group.complete(flight->flight,std::unexpected(Error::canceled)); group.finish(flight->flight);
        group.leave(first); group.leave(follower); moved.reset();
        require(group.counts()==std::pair<std::size_t,std::size_t>{0,0} && !group.direct_active(),
                "mixed work budget did not drain");
    }
    {
        hp::FlightGroup group(1024,8192); // constructor clamps to 256 and 4096
        auto waiters=std::make_unique<hp::FlightGroup::Waiter[]>(4097);
        std::optional<hp::FlightGroup::Joined> flight;
        for (std::size_t i=0;i<4096;++i) {
            auto joined=group.join(key(endpoint,"many-waiters.example.test"),waiters[i]);
            require(joined && (i==0 ? joined->leader : !joined->leader),"bounded waiter registration failed");
            if (!flight) flight=*joined;
        }
        auto rejected=group.join(key(endpoint,"many-waiters.example.test"),waiters[4096]);
        require(!rejected && rejected.error()==Error::limit && group.counts()==std::pair<std::size_t,std::size_t>{1,4096},
                "4096 waiter clamp failed");
        for (std::size_t i=0;i<4096;++i) group.leave(waiters[i]);
        require(group.counts()==std::pair<std::size_t,std::size_t>{1,0},"last waiter lost its retiring flight");
        group.complete(flight->flight,std::unexpected(Error::canceled)); group.finish(flight->flight);
        require(group.counts()==std::pair<std::size_t,std::size_t>{0,0},"maximum waiter flight did not drain");
    }
    {
        hp::FlightGroup group(1024,1024);
        auto waiters=std::make_unique<hp::FlightGroup::Waiter[]>(257);
        std::vector<hp::FlightGroup::Joined> flights; flights.reserve(256);
        for (std::size_t i=0;i<256;++i) {
            auto joined=group.join(key(endpoint,"flight-"+std::to_string(i)+".example.test"),waiters[i]);
            require(joined && joined->leader,"bounded flight registration failed"); flights.push_back(*joined);
        }
        auto rejected=group.join(key(endpoint,"flight-excess.example.test"),waiters[256]);
        require(!rejected && rejected.error()==Error::limit && group.counts()==std::pair<std::size_t,std::size_t>{256,256},
                "256 flight clamp failed");
        for (std::size_t i=0;i<flights.size();++i) {
            group.leave(waiters[i]); group.complete(flights[i].flight,std::unexpected(Error::canceled)); group.finish(flights[i].flight);
        }
        require(group.counts()==std::pair<std::size_t,std::size_t>{0,0},"maximum flight set did not drain");
    }
}
auto background_backoff(io::endpoint endpoint) -> void {
    hp::FlightGroup group(2,4,30s);
    auto now=Clock::now();
    auto fail=[&](Key query,Clock::time_point when) {
        auto flight=group.join_background(std::move(query));
        require(flight && flight->leader,"backoff flight registration failed");
        injected=false; fail_after=0;
        group.complete(flight->flight,std::unexpected(Error::state),when);
        fail_after=-1;
        require(!injected,"background completion allocated during backoff");
        group.finish(flight->flight);
    };
    auto first=key(endpoint,"backoff-first.example.test");
    fail(first,now);
    auto normalized=first; normalized.cache.name="BACKOFF-FIRST.EXAMPLE.TEST.";
    auto denied=group.join_background(std::move(normalized));
    require(!denied && denied.error()==Error::limit,"failed normalized key was not throttled");
    auto different_view=first,different_type=first,different_tcp=first,different_edns=first,different_upstream=first;
    different_view.cache.view=2; different_type.cache.type=28; different_tcp.tcp=true; different_edns.edns=true;
    different_upstream.upstream=io::endpoint(io::ipv4_address::loopback(),endpoint.port()==65535 ? 65534 : endpoint.port()+1);
    for (auto& query:{different_view,different_type,different_tcp,different_edns,different_upstream}) {
        auto flight=group.join_background(query);
        require(flight && flight->leader,"unrelated backoff key was throttled");
        group.complete(flight->flight,std::unexpected(Error::canceled)); group.finish(flight->flight);
    }
    fail(key(endpoint,"backoff-second.example.test"),now+1ms);
    fail(key(endpoint,"backoff-third.example.test"),now+2ms);
    auto evicted=group.join_background(first);
    require(evicted && evicted->leader,"full backoff table did not evict its earliest slot");
    group.complete(evicted->flight,std::unexpected(Error::state),now+3ms); group.finish(evicted->flight);
    hp::FlightGroup::Waiter waiter;
    auto foreground=group.join(first,waiter);
    require(foreground && foreground->leader,"backoff blocked a foreground request");
    d::AddressAnswer answer{first.cache.name,{first.cache.name},{},30};
    group.complete(foreground->flight,std::move(answer)); group.finish(foreground->flight); group.leave(waiter);
    auto cleared=group.join_background(first);
    require(cleared && cleared->leader,"successful foreground work did not clear backoff");
    group.complete(cleared->flight,std::unexpected(Error::canceled)); group.finish(cleared->flight);
    require(group.counts()==std::pair<std::size_t,std::size_t>{0,0},"backoff test did not drain");
    hp::FlightGroup maximum(256,0);
    std::println("background backoff: {} bytes reserved for 256 slots",maximum.backoff_reserved_bytes());
}
struct Generation {
    std::array<std::size_t,2> capacities{16,16};
    hp::GroupSnapshot cache;
    hp::FlightGroup flights;
    explicit Generation(std::size_t budget=1024*1024,std::uint64_t stale_ms=0,std::size_t flight_limit=8)
        : cache(capacities,3,stale_ms,budget),flights(flight_limit,32) {}
};
auto owner_start_failures(io::endpoint endpoint,bool uring) -> void {
    for (int position=0;position<2;++position) {
        Generation generation;
        hp::GroupBinding binding(generation.cache,0);
#if BOOST_COROSIO_HAVE_LIBURING
        io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
        io::io_context context(io::epoll); (void)uring;
#endif
        hp::FlightOwner<hp::GroupBinding> owner(context,binding,generation.flights);
        hp::FlightGroup::Waiter leader,follower;
        auto first=generation.flights.join(key(endpoint),leader);
        require(first && first->leader,"startup fault leader registration failed");
        auto follower_key=key(endpoint);
        injected=false; fail_after=0;
        auto second=generation.flights.join(std::move(follower_key),follower);
        fail_after=-1;
        require(second && !second->leader && !injected,"joining an existing flight allocated");
        injected=false; fail_after=position;
        owner.start(first->flight);
        fail_after=-1;
        require(injected && owner.drained(),"owner allocation fault did not drain");
        auto result=generation.flights.result(leader);
        require(result && !result->expired && !result->answer && result->answer.error()==Error::state,
                "owner start fault did not complete all waiters");
        generation.flights.leave(leader); generation.flights.leave(follower);
        require(generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0},"owner allocation fault retained a flight");
    }
}
// Insert a positive or negative answer precisely after the initial cache miss
// and before flight registration. The new leader must recheck the cache.
class RaceBinding : public hp::GroupBinding {
    bool negative_,injected_=false;
public:
    RaceBinding(hp::GroupSnapshot& cache,bool negative) : GroupBinding(cache,0),negative_(negative) {}
    using GroupBinding::lookup_fresh;
    auto lookup_fresh(d::CacheKey value,std::uint64_t now,Reader& reader) {
        auto before=GroupBinding::lookup_fresh(value,now,reader);
        if (!injected_) {
            injected_=true;
            auto token=GroupBinding::begin_query(value);
            if (!token) throw std::runtime_error("race token failed");
            if (negative_) {
                if (!GroupBinding::publish_negative(value,d::NegativeKind::name_not_found,30,now,*token))
                    throw std::runtime_error("race negative publication failed");
            } else {
                d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=31;
                d::AddressAnswer answer{value.name,{value.name},{address},30};
                if (!GroupBinding::publish(value,std::move(answer),now,*token))
                    throw std::runtime_error("race positive publication failed");
            }
        }
        return before;
    }
};
// Hold the leader after it reads an injected cache entry, allowing a follower
// on another executor to register and then stall past that entry's expiry.
class RecheckBlockingBinding : public hp::GroupBinding {
    bool negative_,fractional_,injected_=false;
    std::promise<void>& entered_;
    std::future<void>& release_;
    std::atomic<std::uint64_t>& expires_;
public:
    RecheckBlockingBinding(hp::GroupSnapshot& cache,bool negative,bool fractional,std::promise<void>& entered,
                           std::future<void>& release,std::atomic<std::uint64_t>& expires)
        : GroupBinding(cache,0),negative_(negative),fractional_(fractional),entered_(entered),release_(release),expires_(expires) {}
    using GroupBinding::lookup_fresh;
    auto lookup_fresh(d::CacheKey value,std::uint64_t now,Reader& reader) {
        auto before=GroupBinding::lookup_fresh(value,now,reader);
        if (!injected_) {
            injected_=true;
            auto token=GroupBinding::begin_query(value);
            if (!token) throw std::runtime_error("delayed recheck token failed");
            auto acquired=now-(fractional_ ? 100 : 0);
            auto ttl=fractional_ ? 1u : 2u;
            if (negative_) {
                if (!GroupBinding::publish_negative_from(value,d::NegativeKind::name_not_found,ttl,acquired,now,*token))
                    throw std::runtime_error("delayed negative recheck seed failed");
            } else {
                d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=42;
                d::AddressAnswer answer{value.name,{value.name},{address},ttl};
                if (!GroupBinding::publish_from(value,answer,acquired,now,*token))
                    throw std::runtime_error("delayed positive recheck seed failed");
            }
            return before;
        }
        auto found=std::move(before);
        if (!found || !*found || (negative_ ? !(**found).negative : !(**found).answer) ||
            (fractional_ && (!(**found).answer || (**found).answer->ttl!=0)))
            throw std::runtime_error("delayed recheck did not capture the expected cache entry");
        expires_.store((**found).expires);
        entered_.set_value();
        if (release_.wait_for(5s)!=std::future_status::ready) throw std::runtime_error("delayed recheck gate timed out");
        return found;
    }
};
auto cache_registration_race(bool uring,bool negative) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
    io::io_context context(io::epoll); (void)uring;
#endif
    Generation generation; Peer peer; RaceBinding binding(generation.cache,negative);
    auto reader=generation.cache.reader(0);
    hp::FlightOwner<RaceBinding> owner(context,binding,generation.flights);
    hp::CoalescedCachedResolver<RaceBinding> operation(context,binding,&reader,generation.flights,owner);
    std::optional<Result> answer; std::exception_ptr failure; bool done=false;
    auto task=[&]() -> boost::capy::task<> {
        answer=co_await operation.resolve(key(peer.endpoint,"cache-race.example.test"),Clock::now()+3s);
    };
    boost::capy::run_async(context.get_executor(),[&] { done=true; },[&](std::exception_ptr error) { failure=error; done=true; })(task());
    context.restart(); (void)context.run_for(100ms);
    if (failure) std::rethrow_exception(failure);
    require(done && answer && peer.empty() && owner.drained() &&
            generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0},"cache recheck launched or retained a network flight");
    if (negative) require(!*answer && answer->error()==Error::name_not_found,"negative recheck lost answer");
    else require(*answer && (**answer).addresses.size()==1 && (**answer).addresses[0].bytes[3]==31,"positive recheck lost answer");
}
auto recheck_failure(bool uring,bool allocation) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
    io::io_context context(io::epoll); (void)uring;
#endif
    Generation generation; Peer peer; hp::GroupBinding binding(generation.cache,0);
    hp::FlightOwner<hp::GroupBinding> owner(context,binding,generation.flights);
    hp::FlightOperation<hp::GroupBinding> operation(generation.flights,owner);
    std::optional<Result> answer; std::exception_ptr failure; bool done=false;
    auto task=[&]() -> boost::capy::task<> {
        answer=co_await operation.resolve(key(peer.endpoint,"recheck-fault.example.test"),Clock::now()+3s,
            [allocation](Key const&) -> std::optional<hp::FlightGroup::Rechecked> {
                if (allocation) throw std::bad_alloc();
                throw std::runtime_error("injected recheck fault");
            });
    };
    boost::capy::run_async(context.get_executor(),[&] { done=true; },[&](std::exception_ptr error) { failure=error; done=true; })(task());
    context.restart(); (void)context.run_for(30ms);
    if (allocation) {
        require(!done,"allocation fault did not fall back to the network");
        peer.reply(peer.receive(),32);
        context.restart(); (void)context.run_for(100ms);
    }
    if (failure) std::rethrow_exception(failure);
    require(done && answer && owner.drained() && generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0},
            "recheck failure did not drain");
    if (allocation) require(*answer && (**answer).addresses.size()==1 && (**answer).addresses[0].bytes[3]==32,
                            "recheck allocation fault lost the network result");
    else require(!*answer && answer->error()==Error::state && peer.empty(),"recheck error did not fail closed");
}
class OwnerFaultBinding : public hp::GroupBinding {
    bool registration_;
public:
    bool injected=false;
    unsigned canceled=0;
    OwnerFaultBinding(hp::GroupSnapshot& cache,bool registration) : GroupBinding(cache,0),registration_(registration) {}
    auto begin_query(d::CacheKey const& value) {
        if (registration_ && !injected) { injected=true; throw std::bad_alloc(); }
        return GroupBinding::begin_query(value);
    }
    using GroupBinding::publish;
    auto publish(d::CacheKey const& value,d::AddressAnswer const& answer,std::uint64_t now,Token token) {
        if (!registration_ && !injected) { injected=true; throw std::bad_alloc(); }
        return GroupBinding::publish(value,answer,now,token);
    }
    auto publish_from(d::CacheKey const& value,d::AddressAnswer const& answer,std::uint64_t acquired,std::uint64_t now,Token token) {
        if (!registration_ && !injected) { injected=true; throw std::bad_alloc(); }
        return GroupBinding::publish_from(value,answer,acquired,now,token);
    }
    auto cancel_query(Token token) { ++canceled; return GroupBinding::cancel_query(token); }
};
auto cache_fault_network(bool uring,bool registration) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
    io::io_context context(io::epoll); (void)uring;
#endif
    Generation generation; Peer peer; OwnerFaultBinding cache(generation.cache,registration);
    hp::FlightOwner<OwnerFaultBinding> owner(context,cache,generation.flights);
    hp::FlightOperation<OwnerFaultBinding> operation(generation.flights,owner);
    auto query=key(peer.endpoint,"owner-fault.example.test");
    std::optional<Result> answer; std::exception_ptr failure; bool finished=false;
    auto task=[&]() -> boost::capy::task<> { answer=co_await operation.resolve(query,Clock::now()+3s); };
    boost::capy::run_async(context.get_executor(),[&] { finished=true; },[&](std::exception_ptr error) { failure=error; finished=true; })(task());
    context.restart(); (void)context.run_for(30ms);
    require(!finished,"cache fault prevented the upstream query");
    peer.reply(peer.receive(),37);
    context.restart(); (void)context.run_for(100ms);
    if (failure) std::rethrow_exception(failure);
    require(finished && answer && *answer && (**answer).addresses[0].bytes[3]==37 && cache.injected &&
            cache.canceled==(registration ? 0u : 1u) && owner.drained() &&
            generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0},"cache fault lost the answer or token");
    auto reader=generation.cache.reader(0);
    auto hit=cache.lookup(query.cache,stamp(),reader);
    require(hit && !*hit,"failed cache registration or publication created an entry");
}
auto stale_refresh_composition(bool uring) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
    io::io_context context(io::epoll); (void)uring;
#endif
    Generation generation(1024*1024,10000); Peer peer;
    hp::GroupBinding first(generation.cache,0),second(generation.cache,1);
    auto reader_a=generation.cache.reader(0),reader_b=generation.cache.reader(1);
    hp::FlightOwner<hp::GroupBinding> flight_a(context,first,generation.flights),flight_b(context,second,generation.flights);
    d::detail::RefreshBudget budget(4);
    d::detail::BasicRefreshOwner<hp::GroupBinding> refresh_a(context,first,4,5s,1s,&budget),
        refresh_b(context,second,4,5s,1s,&budget);
    auto query=key(peer.endpoint,"stale-composed.example.test");
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=33;
    d::AddressAnswer initial{query.cache.name,{query.cache.name},{address},1};
    auto token=first.begin_query(query.cache);
    require(token && first.publish(query.cache,std::move(initial),stamp()-1500,*token),"stale composition seed failed");
    hp::CoalescedCachedResolver<hp::GroupBinding> a(context,first,&reader_a,generation.flights,flight_a,&refresh_a),
        b(context,second,&reader_b,generation.flights,flight_b,&refresh_b);
    std::optional<Result> answers[2]; std::exception_ptr errors[2]; bool done[2]{};
    auto task=[&](auto& operation,unsigned index) -> boost::capy::task<> {
        answers[index]=co_await operation.resolve(query,Clock::now()+3s);
    };
    boost::capy::run_async(context.get_executor(),[&] { done[0]=true; },[&](std::exception_ptr error) { errors[0]=error; done[0]=true; })(task(a,0));
    boost::capy::run_async(context.get_executor(),[&] { done[1]=true; },[&](std::exception_ptr error) { errors[1]=error; done[1]=true; })(task(b,1));
    context.restart(); (void)context.run_for(30ms);
    for (unsigned i=0;i<2;++i) {
        if (errors[i]) std::rethrow_exception(errors[i]);
        require(done[i] && answers[i] && *answers[i] && (**answers[i]).addresses[0].bytes[3]==33 && (**answers[i]).ttl==1,
                "stale result was not immediately available");
    }
    auto packet=peer.receive();
    require(peer.empty() && budget.active()==1 && generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0},
            "stale requests started duplicate refreshes or foreground flights");
    peer.reply(std::move(packet),34);
    context.restart(); (void)context.run_for(100ms);
    require(refresh_a.drained() && refresh_b.drained() && budget.active()==0,"refresh did not drain");
    hp::CoalescedCachedResolver<hp::GroupBinding> after(context,second,&reader_b,generation.flights,flight_b,&refresh_b);
    std::optional<Result> fresh; std::exception_ptr failure; bool finished=false;
    auto fresh_task=[&]() -> boost::capy::task<> { fresh=co_await after.resolve(query,Clock::now()+3s); };
    boost::capy::run_async(context.get_executor(),[&] { finished=true; },[&](std::exception_ptr error) { failure=error; finished=true; })(fresh_task());
    context.restart(); (void)context.run_for(30ms);
    if (failure) std::rethrow_exception(failure);
    require(finished && fresh && *fresh && (**fresh).addresses[0].bytes[3]==34 && peer.empty(),"refreshed result was not shared");
}
auto dual_composition(bool uring) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
    io::io_context context(io::epoll); (void)uring;
#endif
    using Dual=hp::CoalescedDualResolver<hp::GroupBinding>;
    using DualResult=std::expected<std::vector<d::Address>,Error>;
    Generation generation; Peer peer; hp::GroupBinding first(generation.cache,0),second(generation.cache,1);
    auto reader_a=generation.cache.reader(0),reader_b=generation.cache.reader(1);
    hp::FlightOwner<hp::GroupBinding> owner_a(context,first,generation.flights),owner_b(context,second,generation.flights);
    Dual a(context,first,&reader_a,generation.flights,owner_a,d::detail::AddressStrategy::prefer_ipv4),
         b(context,second,&reader_b,generation.flights,owner_b,d::detail::AddressStrategy::prefer_ipv4);
    std::optional<DualResult> results[2]; std::exception_ptr failures[2]; bool done[2]{};
    auto task=[&](Dual& resolver,unsigned index) -> boost::capy::task<> {
        results[index]=co_await resolver.resolve(peer.endpoint,1,"dual-composed.example.test",Clock::now()+3s);
    };
    boost::capy::run_async(context.get_executor(),[&] { done[0]=true; },[&](std::exception_ptr error) { failures[0]=error; done[0]=true; })(task(a,0));
    boost::capy::run_async(context.get_executor(),[&] { done[1]=true; },[&](std::exception_ptr error) { failures[1]=error; done[1]=true; })(task(b,1));
    context.restart(); (void)context.run_for(30ms);
    auto a_query=peer.receive();
    require(a_query.data[a_query.data.size()-3]==1 && peer.empty(),"dual A requests did not coalesce");
    peer.reply(std::move(a_query),36);
    context.restart(); (void)context.run_for(30ms);
    auto aaaa_query=peer.receive();
    require(aaaa_query.data[aaaa_query.data.size()-3]==28 && peer.empty(),"dual AAAA requests did not coalesce");
    peer.reply(std::move(aaaa_query),0,true,30,true);
    context.restart(); (void)context.run_for(100ms);
    for (unsigned i=0;i<2;++i) {
        if (failures[i]) std::rethrow_exception(failures[i]);
        require(done[i] && results[i] && *results[i] && (**results[i]).size()==1 && (**results[i])[0].bytes[3]==36,
                "dual coalesced resolution failed");
    }
    require(generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0} && owner_a.drained() && owner_b.drained(),
            "dual flights did not drain");
    Dual hit(context,second,&reader_b,generation.flights,owner_b,d::detail::AddressStrategy::prefer_ipv4);
    std::optional<DualResult> cached; std::exception_ptr failure; bool finished=false;
    auto cached_task=[&]() -> boost::capy::task<> {
        cached=co_await hit.resolve(peer.endpoint,1,"dual-composed.example.test",Clock::now()+3s);
    };
    boost::capy::run_async(context.get_executor(),[&] { finished=true; },[&](std::exception_ptr error) { failure=error; finished=true; })(cached_task());
    context.restart(); (void)context.run_for(30ms);
    if (failure) std::rethrow_exception(failure);
    require(finished && cached && *cached && (**cached).size()==1 && (**cached)[0].bytes[3]==36 && peer.empty(),
            "dual positive/negative shared cache hit failed");
}
auto dual_coordinated_composition(bool uring) -> void {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
    io::io_context context(io::epoll); (void)uring;
#endif
    using Dual=hp::CoalescedDualResolver<hp::GroupBinding>;
    using DualResult=std::expected<std::vector<d::Address>,Error>;
    Generation generation(1024*1024,10000); Peer peer;
    hp::GroupBinding first(generation.cache,0),second(generation.cache,1);
    auto reader_a=generation.cache.reader(0),reader_b=generation.cache.reader(1);
    hp::FlightOwner<hp::GroupBinding> owner_a(context,first,generation.flights),owner_b(context,second,generation.flights);
    d::CacheKey a_key{1,"dual-refresh.example.test",1},aaaa_key{1,"dual-refresh.example.test",28};
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=73;
    d::AddressAnswer seed{a_key.name,{a_key.name},{address},1};
    auto a_token=first.begin_query(a_key),aaaa_token=first.begin_query(aaaa_key);
    require(a_token && aaaa_token && first.publish(a_key,std::move(seed),stamp(),*a_token) &&
            first.publish_negative(aaaa_key,d::NegativeKind::no_data,30,stamp(),*aaaa_token),"dual refresh seed failed");
    std::this_thread::sleep_for(1100ms);
    Dual a(context,first,&reader_a,generation.flights,owner_a,d::detail::AddressStrategy::prefer_ipv4,false,false,false,nullptr,true),
         b(context,second,&reader_b,generation.flights,owner_b,d::detail::AddressStrategy::prefer_ipv4,false,false,false,nullptr,true);
    std::optional<DualResult> results[2]; std::exception_ptr failures[2]; bool done[2]{};
    auto task=[&](Dual& resolver,unsigned index) -> boost::capy::task<> {
        results[index]=co_await resolver.resolve(peer.endpoint,1,a_key.name,Clock::now()+3s);
    };
    boost::capy::run_async(context.get_executor(),[&] { done[0]=true; },[&](std::exception_ptr error) { failures[0]=error; done[0]=true; })(task(a,0));
    boost::capy::run_async(context.get_executor(),[&] { done[1]=true; },[&](std::exception_ptr error) { failures[1]=error; done[1]=true; })(task(b,1));
    context.restart(); (void)context.run_for(50ms);
    for (unsigned i=0;i<2;++i) {
        if (failures[i]) std::rethrow_exception(failures[i]);
        require(done[i] && results[i] && *results[i] && (**results[i]).size()==1 && (**results[i])[0].bytes[3]==73,
                "dual stale/negative result failed");
    }
    auto packet=peer.receive(); require(peer.empty() && generation.flights.counts()==std::pair<std::size_t,std::size_t>{1,0},
                                       "dual resolvers did not coordinate background refresh");
    peer.reply(std::move(packet),74); context.restart(); (void)context.run_for(100ms);
    require(generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0} && owner_a.drained() && owner_b.drained(),
            "dual background refresh did not drain");
    Dual fresh(context,second,&reader_b,generation.flights,owner_b,d::detail::AddressStrategy::prefer_ipv4,false,false,false,nullptr,true);
    std::optional<DualResult> result; std::exception_ptr failure; bool finished=false;
    auto fresh_task=[&]() -> boost::capy::task<> { result=co_await fresh.resolve(peer.endpoint,1,a_key.name,Clock::now()+3s); };
    boost::capy::run_async(context.get_executor(),[&] { finished=true; },[&](std::exception_ptr error) { failure=error; finished=true; })(fresh_task());
    context.restart(); (void)context.run_for(30ms);
    if (failure) std::rethrow_exception(failure);
    require(finished && result && *result && (**result).size()==1 && (**result)[0].bytes[3]==74 && peer.empty(),
            "dual coordinated refresh did not publish");
}
class Worker {
    using Binding=hp::GroupBinding;
    using Owner=hp::FlightOwner<Binding>;
    using Operation=hp::FlightOperation<Binding>;
    using Cached=hp::CoalescedCachedResolver<Binding>;
    struct Pending {
        std::unique_ptr<Operation> operation;
        std::unique_ptr<Cached> cached;
        std::promise<Result> result;
        auto cancel() noexcept -> void { if (operation) operation->cancel(); if (cached) cached->cancel(); }
    };
    struct State {
        io::io_context context;
        std::array<std::unique_ptr<Binding>,2> bindings;
        std::array<std::unique_ptr<Owner>,2> owners;
        std::array<std::optional<hp::GroupSnapshot::Reader>,2> readers;
        std::map<unsigned,std::unique_ptr<Pending>> pending;
        State(bool uring,std::size_t group,std::array<Generation*,2> generations)
#if BOOST_COROSIO_HAVE_LIBURING
            : context(uring ? io::io_context(io::uring) : io::io_context(io::epoll)) {
#else
            : context(io::epoll) { (void)uring;
#endif
            for (std::size_t i=0;i<generations.size();++i) {
                bindings[i]=std::make_unique<Binding>(generations[i]->cache,group);
                owners[i]=std::make_unique<Owner>(context,*bindings[i],generations[i]->flights,5s);
                readers[i].emplace(generations[i]->cache.reader(group));
            }
        }
    };
    std::array<Generation*,2> generations_;
    std::size_t group_;
    bool uring_;
    std::unique_ptr<State> state_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::move_only_function<void()>> commands_;
    std::thread thread_;
    bool quitting_=false;
    unsigned next_id_=0;
    auto execute(Pending& pending,Key value,Clock::time_point deadline) -> boost::capy::task<> {
        if (pending.cached) pending.result.set_value(co_await pending.cached->resolve(std::move(value),deadline));
        else pending.result.set_value(co_await pending.operation->resolve(std::move(value),deadline));
    }
    auto enqueue(std::move_only_function<void()> command) -> void {
        { std::lock_guard lock(mutex_); commands_.push_back(std::move(command)); }
        condition_.notify_one();
    }
    auto loop(std::promise<void> ready) noexcept -> void {
        try {
            state_=std::make_unique<State>(uring_,group_,generations_); ready.set_value();
            for (;;) {
                std::deque<std::move_only_function<void()>> commands;
                {
                    std::unique_lock lock(mutex_);
                    condition_.wait_for(lock,2ms,[&] { return !commands_.empty(); });
                    commands.swap(commands_);
                }
                for (auto& command:commands) command();
                state_->context.restart(); (void)state_->context.run_for(2ms);
                if (quitting_ && state_->pending.empty() && state_->owners[0]->drained() && state_->owners[1]->drained()) break;
            }
            state_.reset();
        } catch (...) {
            try { ready.set_exception(std::current_exception()); } catch (...) { std::terminate(); }
        }
    }
public:
    struct Request { unsigned id; std::future<Result> result; };
    Worker(Generation& first,Generation& second,std::size_t group,bool uring)
        : generations_{&first,&second},group_(group),uring_(uring) {
        std::promise<void> ready; auto future=ready.get_future();
        thread_=std::thread([this,ready=std::move(ready)]() mutable { loop(std::move(ready)); });
        try { future.get(); } catch (...) { thread_.join(); throw; }
    }
    Worker(Worker const&)=delete;
    ~Worker() {
        if (!thread_.joinable()) return;
        enqueue([this] {
            for (auto& [id,pending]:state_->pending) pending->cancel();
            for (auto& owner:state_->owners) owner->stop();
            quitting_=true;
        });
        thread_.join();
    }
    auto start(unsigned generation,Key value,std::chrono::milliseconds timeout=2s,bool cached=false,bool coordinated=false) -> Request {
        auto id=++next_id_;
        auto pending=std::make_unique<Pending>(); auto result=pending->result.get_future();
        std::promise<void> ack; auto begun=ack.get_future();
        enqueue([this,id,generation,pending=std::move(pending),ack=std::move(ack),data=std::move(value),timeout,cached,coordinated]() mutable {
            try {
                if (cached) pending->cached=std::make_unique<Cached>(state_->context,*state_->bindings.at(generation),
                    &*state_->readers.at(generation),generations_.at(generation)->flights,*state_->owners.at(generation),nullptr,coordinated);
                else pending->operation=std::make_unique<Operation>(generations_.at(generation)->flights,*state_->owners.at(generation));
                auto [it,inserted]=state_->pending.try_emplace(id);
                if (!inserted) throw std::runtime_error("duplicate operation");
                it->second=std::move(pending);
                try {
                    boost::capy::run_async(state_->context.get_executor(),[this,id] { state_->pending.erase(id); },
                        [this,id](std::exception_ptr error) noexcept {
                            auto found=state_->pending.find(id);
                            if (found!=state_->pending.end()) {
                                try { found->second->result.set_exception(error); } catch (...) {}
                                state_->pending.erase(found);
                            }
                        })(execute(*it->second,std::move(data),Clock::now()+timeout));
                } catch (...) { pending=std::move(it->second); state_->pending.erase(it); throw; }
                ack.set_value();
            } catch (...) {
                auto error=std::current_exception();
                if (pending) try { pending->result.set_exception(error); } catch (...) {}
                ack.set_exception(error);
            }
        });
        begun.get(); return {id,std::move(result)};
    }
    auto cancel(unsigned id) -> void {
        std::promise<void> ack; auto future=ack.get_future();
        enqueue([this,id,ack=std::move(ack)]() mutable {
            auto found=state_->pending.find(id);
            if (found!=state_->pending.end()) found->second->cancel();
            ack.set_value();
        });
        future.get();
    }
    auto stop(unsigned generation) -> void {
        std::promise<void> ack; auto future=ack.get_future();
        enqueue([this,generation,ack=std::move(ack)]() mutable { state_->owners.at(generation)->stop(); ack.set_value(); }); future.get();
    }
    auto start_registered(unsigned generation,hp::FlightGroup::Joined joined) -> void {
        std::promise<void> ack; auto future=ack.get_future();
        enqueue([this,generation,joined,ack=std::move(ack)]() mutable {
            state_->owners.at(generation)->start(joined.flight); ack.set_value();
        });
        future.get();
    }
    auto drained(unsigned generation) -> bool {
        std::promise<bool> ack; auto future=ack.get_future();
        enqueue([this,generation,ack=std::move(ack)]() mutable { ack.set_value(state_->owners.at(generation)->drained()); }); return future.get();
    }
    auto pause() -> std::promise<void> {
        std::promise<void> release,ack;
        auto gate=release.get_future(),ready=ack.get_future();
        enqueue([gate=std::move(gate),ack=std::move(ack)]() mutable { ack.set_value(); gate.wait(); });
        require(ready.wait_for(3s)==std::future_status::ready,"executor did not pause");
        ready.get(); return release;
    }
};
auto expect_success(std::future<Result>& future,std::uint8_t value) -> void {
    require(future.wait_for(3s)==std::future_status::ready,"request did not complete");
    auto answer=future.get();
    if (!answer) std::println(stderr,"expected address {}, error {}",value,static_cast<int>(answer.error()));
    else if (answer->addresses.size()!=1 || answer->addresses[0].bytes[3]!=value)
        std::println(stderr,"expected address {}, count {}, actual {}",value,answer->addresses.size(),answer->addresses.empty() ? 0 : answer->addresses[0].bytes[3]);
    require(answer && answer->addresses.size()==1 && answer->addresses[0].bytes[3]==value,"wrong shared DNS answer");
}
auto expect_error(std::future<Result>& future,Error error) -> void {
    require(future.wait_for(3s)==std::future_status::ready,"error request did not complete");
    auto answer=future.get(); require(!answer && answer.error()==error,"wrong DNS error");
}
auto wait_idle(hp::FlightGroup& group) -> void {
    auto deadline=Clock::now()+3s;
    while (group.counts()!=std::pair<std::size_t,std::size_t>{0,0}) {
        require(Clock::now()<deadline,"flights did not drain"); std::this_thread::sleep_for(2ms);
    }
}
auto wait_drained(Worker& worker,unsigned generation) -> void {
    auto deadline=Clock::now()+3s;
    while (!worker.drained(generation)) {
        require(Clock::now()<deadline,"network owner did not drain"); std::this_thread::sleep_for(2ms);
    }
}
// A completed flight can still occupy the only slot while a different
// waiter is stalled. An awakened waiter must still be able to consume a
// fresh cache entry without first reserving a second network flight.
auto retained_retry_recheck(bool uring,bool negative) -> void {
    Peer peer; Generation first(1024*1024,10000,1),second;
    Worker worker(first,second,1,uring);
    auto query=key(peer.endpoint,negative ? "retained-negative.example.test" : "retained-positive.example.test");
    auto background=first.flights.join_background(query);
    require(background && background->leader,"retained retry background registration failed");
    hp::FlightGroup::Waiter held;
    auto pin=first.flights.join(query,held);
    require(pin && !pin->leader,"retained retry pin registration failed");
    struct Release {
        hp::FlightGroup& group; hp::FlightGroup::Waiter& held;
        ~Release() { group.leave(held); }
    } release{first.flights,held};
    auto pending=worker.start(0,query,5s,true);
    auto deadline=Clock::now()+3s;
    while (first.flights.counts()!=std::pair<std::size_t,std::size_t>{1,2}) {
        require(Clock::now()<deadline,"retained retry waiter did not join"); std::this_thread::sleep_for(2ms);
    }
    auto token=first.cache.begin_query(0,query.cache);
    require(token.has_value(),"retained retry cache token failed");
    if (negative) {
        require(first.cache.publish_negative_view(0,query.cache.view,query.cache.name,query.cache.type,
                    d::NegativeKind::name_not_found,30,stamp(),*token).has_value(),"retained negative fill failed");
    } else {
        d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=51;
        d::AddressAnswer answer{query.cache.name,{query.cache.name},{address},30};
        require(first.cache.publish(0,query.cache,std::move(answer),stamp(),*token).has_value(),"retained positive fill failed");
    }
    first.flights.complete_retry(background->flight);
    first.flights.finish(background->flight);
    require(pending.result.wait_for(3s)==std::future_status::ready,"retained retry did not finish");
    auto result=pending.result.get();
    require(negative ? (!result && result.error()==Error::name_not_found) :
            (result && result->addresses.size()==1 && result->addresses[0].bytes[3]==51),
            "retained flight blocked a fresh cache recheck");
    require(peer.empty(),"retained retry unexpectedly queried upstream");
}
auto retry_recheck_boundaries(bool uring) -> void {
    // Check both answer kinds crossing expiry during the recheck, a caller
    // deadline expiring during it, and TTL rounding for a still-fresh hit.
    for (unsigned mode=0;mode<4;++mode) {
        Peer peer; Generation generation;
#if BOOST_COROSIO_HAVE_LIBURING
        io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
        io::io_context context(io::epoll); (void)uring;
#endif
        hp::GroupBinding binding(generation.cache,0);
        hp::FlightOwner<hp::GroupBinding> owner(context,binding,generation.flights);
        hp::FlightOperation<hp::GroupBinding> operation(generation.flights,owner);
        auto query=key(peer.endpoint,"retry-recheck-boundary.example.test");
        auto background=generation.flights.join_background(query);
        require(background && background->leader,"retry boundary registration failed");
        unsigned checks=0; bool done=false; std::optional<Result> answer; std::exception_ptr failure;
        auto recheck=[&](Key const& value) -> std::optional<hp::FlightGroup::Rechecked> {
            if (++checks>1) return {};
            auto expires=Clock::now()+(mode<2 ? 20ms : mode==2 ? 3s : 250ms);
            if (mode<2) std::this_thread::sleep_for(40ms);
            if (mode==2) std::this_thread::sleep_for(100ms);
            if (mode==1) return hp::FlightGroup::Rechecked{std::unexpected(Error::name_not_found),expires};
            d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=54;
            return hp::FlightGroup::Rechecked{d::AddressAnswer{value.cache.name,{value.cache.name},{address},30},expires};
        };
        auto task=[&]() -> boost::capy::task<> {
            answer=co_await operation.resolve(query,Clock::now()+(mode==2 ? 60ms : 3s),recheck);
        };
        boost::capy::run_async(context.get_executor(),[&] { done=true; },[&](std::exception_ptr error) { failure=error; done=true; })(task());
        context.restart(); (void)context.run_for(10ms);
        require(generation.flights.counts()==std::pair<std::size_t,std::size_t>{1,1},"retry boundary waiter did not join");
        generation.flights.complete_retry(background->flight); generation.flights.finish(background->flight);
        context.restart(); (void)context.run_for(150ms);
        if (mode<2) {
            require(!done,"expired retry recheck returned an old answer");
            peer.reply(peer.receive(),55);
            context.restart(); (void)context.run_for(100ms);
        }
        if (failure) std::rethrow_exception(failure);
        require(done && answer && owner.drained() && generation.flights.counts()==std::pair<std::size_t,std::size_t>{0,0},
                "retry recheck did not finish and drain");
        if (mode<2) require(*answer && (**answer).addresses[0].bytes[3]==55 && checks>=2,
                            "expired retry recheck did not obtain a new answer");
        else if (mode==2) require(!*answer && answer->error()==Error::timeout && peer.empty(),"retry recheck exceeded its deadline");
        else require(*answer && (**answer).ttl==0 && (**answer).addresses[0].bytes[3]==54 && peer.empty(),
                     "retry recheck did not clamp its remaining TTL");
    }
}
auto coordinated_refresh_capacity(bool uring) -> void {
    Peer peer; Generation first(1024*1024,10000,3),second;
    Worker a(first,second,0,uring),b(first,second,1,uring);
    auto seed=[&](std::string_view name,std::uint8_t value) {
        d::CacheKey item{1,std::string(name),1}; d::Address address{};
        address.size=4; address.bytes[0]=127; address.bytes[3]=value;
        d::AddressAnswer answer{item.name,{item.name},{address},1};
        auto token=first.cache.begin_query(0,item);
        require(token && first.cache.publish(0,item,std::move(answer),stamp(),*token),"mixed refresh seed failed");
    };
    seed("mixed-background.example.test",51);
    seed("mixed-foreground.example.test",52);
    seed("mixed-blocked.example.test",53);
    std::this_thread::sleep_for(1100ms);

    auto stale=a.start(0,key(peer.endpoint,"mixed-background.example.test"),5s,true,true);
    expect_success(stale.result,51); auto background_packet=peer.receive();
    auto foreground=b.start(0,key(peer.endpoint,"mixed-foreground.example.test"),5s);
    auto foreground_packet=peer.receive();
    auto direct_key=key(peer.endpoint,"mixed-direct.example.test"); direct_key.use_cache=false;
    auto direct=a.start(0,direct_key,5s,true); auto direct_packet=peer.receive();
    require(first.flights.counts()==std::pair<std::size_t,std::size_t>{2,1} && first.flights.direct_active()==1,
            "background, foreground and direct work did not share the full budget");

    // Existing transactions still accept refresh interest or a foreground
    // waiter while the global budget is full.
    auto stale_follower=a.start(0,key(peer.endpoint,"mixed-foreground.example.test"),5s,true,true);
    expect_success(stale_follower.result,52);
    b.cancel(foreground.id); expect_error(foreground.result,Error::canceled);
    auto foreground_follower=b.start(0,key(peer.endpoint,"mixed-background.example.test"),5s);
    auto denied_stale=a.start(0,key(peer.endpoint,"mixed-blocked.example.test"),5s,true,true);
    expect_success(denied_stale.result,53);
    auto denied_flight=b.start(0,key(peer.endpoint,"mixed-excess.example.test"),5s,true);
    expect_error(denied_flight.result,Error::limit);
    auto denied_direct=a.start(0,direct_key,5s,true); expect_error(denied_direct.result,Error::limit);
    require(first.flights.counts()==std::pair<std::size_t,std::size_t>{2,1} && first.flights.direct_active()==1 && peer.empty(),
            "full mixed budget launched extra work or lost attached interest");

    peer.reply(std::move(background_packet),61);
    peer.reply(std::move(foreground_packet),62);
    peer.reply(std::move(direct_packet),63);
    expect_success(foreground_follower.result,61); expect_success(direct.result,63);
    wait_idle(first.flights); wait_drained(a,0); wait_drained(b,0);
    require(first.flights.direct_active()==0,"mixed direct permit did not drain");
    auto published=a.start(0,key(peer.endpoint,"mixed-foreground.example.test"),5s,true,true);
    expect_success(published.result,62); require(peer.empty(),"attached refresh interest did not publish");
    auto resumed=a.start(0,key(peer.endpoint,"mixed-blocked.example.test"),5s,true,true);
    expect_success(resumed.result,53); auto resumed_packet=peer.receive();
    peer.reply(std::move(resumed_packet),64); wait_idle(first.flights); wait_drained(a,0);
    auto fresh=a.start(0,key(peer.endpoint,"mixed-blocked.example.test"),5s,true,true);
    expect_success(fresh.result,64); require(peer.empty(),"refresh did not reuse a released mixed permit");
}
auto coordinated_refresh_tcp(bool uring) -> void {
    Peer udp; TcpPeer tcp(udp.endpoint.port()); Generation first(1024*1024,10000),second;
    Worker a(first,second,0,uring),b(first,second,1,uring);
    auto seed=[&](std::string_view name,std::uint8_t value) {
        d::CacheKey item{1,std::string(name),1}; d::Address address{};
        address.size=4; address.bytes[0]=127; address.bytes[3]=value;
        d::AddressAnswer answer{item.name,{item.name},{address},1};
        auto token=first.cache.begin_query(0,item);
        require(token && first.cache.publish(0,item,std::move(answer),stamp(),*token),"TCP refresh seed failed");
    };
    seed("tcp-refresh.example.test",65); seed("tcp-stop.example.test",66);
    std::this_thread::sleep_for(1100ms);
    auto query=key(tcp.endpoint,"tcp-refresh.example.test"); query.tcp=true;
    auto stale=a.start(0,query,5s,true,true); expect_success(stale.result,65); auto packet=tcp.receive();
    auto joined=b.start(0,query,5s); require(tcp.empty() && udp.empty(),"TCP refresh was duplicated");
    tcp.reply(std::move(packet),67); expect_success(joined.result,67); wait_idle(first.flights); wait_drained(a,0);
    auto cached=b.start(0,query,5s,true,true); expect_success(cached.result,67);
    require(tcp.empty() && udp.empty(),"TCP refresh was not cached");

    // The same name/view and numeric server produce independent transactions
    // for TCP, UDP, and EDNS; cache view construction remains a caller duty.
    auto plain=key(tcp.endpoint,"tcp-options.example.test"); plain.tcp=true;
    auto edns=plain; edns.edns=true;
    auto datagram=plain; datagram.tcp=false;
    auto tcp_request=a.start(0,plain,5s),edns_request=b.start(0,edns,5s),udp_request=a.start(0,datagram,5s);
    auto first_tcp=tcp.receive(),second_tcp=tcp.receive(); auto udp_packet=udp.receive();
    require(first.flights.counts()==std::pair<std::size_t,std::size_t>{3,3} && tcp.empty() && udp.empty(),
            "TCP, UDP or EDNS options were merged");
    auto first_edns=first_tcp.data[11]!=0,second_edns=second_tcp.data[11]!=0;
    require(first_edns!=second_edns,"TCP option requests did not retain EDNS identity");
    tcp.reply(std::move(first_tcp),first_edns ? 69 : 68);
    tcp.reply(std::move(second_tcp),second_edns ? 69 : 68);
    udp.reply(std::move(udp_packet),70);
    expect_success(tcp_request.result,68); expect_success(edns_request.result,69); expect_success(udp_request.result,70);
    wait_idle(first.flights); wait_drained(a,0); wait_drained(b,0);

    auto stopped=key(tcp.endpoint,"tcp-stop.example.test"); stopped.tcp=true;
    auto stale_stop=a.start(0,stopped,5s,true,true); expect_success(stale_stop.result,66); auto late=tcp.receive();
    auto follower=b.start(0,stopped,5s); require(tcp.empty(),"TCP stop test duplicated the refresh");
    a.stop(0); expect_error(follower.result,Error::canceled); wait_idle(first.flights); wait_drained(a,0);
    // A peer write can succeed even after local cancellation; either outcome
    // is valid, but it must not seed the new transaction.
    try { tcp.reply(std::move(late),71); } catch (std::runtime_error const&) {}
    auto retry=b.start(0,stopped,5s); auto retry_packet=tcp.receive(); tcp.reply(std::move(retry_packet),72);
    expect_success(retry.result,72); wait_idle(first.flights); wait_drained(b,0);
    auto fresh=b.start(0,stopped,5s,true,true); expect_success(fresh.result,72);
    require(tcp.empty() && udp.empty(),"canceled TCP refresh contaminated its replacement");
}
auto coordinated_refresh(bool uring) -> void {
    Peer peer; Generation first(1024*1024,10000),second;
    Worker a(first,second,0,uring),b(first,second,1,uring);
    auto seed=[&](std::string_view name,unsigned address) {
        d::CacheKey item{1,std::string(name),1}; d::Address value{}; value.size=4; value.bytes[0]=127; value.bytes[3]=address;
        d::AddressAnswer answer{item.name,{item.name},{value},1};
        auto token=first.cache.begin_query(0,item);
        require(token && first.cache.publish(0,item,std::move(answer),stamp(),*token),"coordinated stale seed failed");
        // The shared snapshot has a monotonic time watermark: backdating a
        // later seed cannot make it stale after earlier tests advanced time.
        std::this_thread::sleep_for(1100ms);
    };
    seed("background-first.example.test",31);
    auto stale=a.start(0,key(peer.endpoint,"background-first.example.test"),5s,true,true);
    expect_success(stale.result,31); auto background_packet=peer.receive();
    require(first.flights.counts()==std::pair<std::size_t,std::size_t>{1,0},"background task was not registered");
    auto foreground=b.start(0,key(peer.endpoint,"background-first.example.test"),5s,true);
    require(peer.empty(),"foreground miss duplicated an in-flight refresh");
    peer.reply(std::move(background_packet),32); expect_success(foreground.result,32); wait_idle(first.flights); wait_drained(a,0);
    auto fresh=b.start(0,key(peer.endpoint,"background-first.example.test"),5s,true,true);
    expect_success(fresh.result,32); require(peer.empty(),"background result was not cached");

    seed("foreground-first.example.test",33);
    auto early=a.start(0,key(peer.endpoint,"foreground-first.example.test"),5s,true);
    auto foreground_packet=peer.receive();
    auto stale_follower=b.start(0,key(peer.endpoint,"foreground-first.example.test"),5s,true,true);
    expect_success(stale_follower.result,33);
    require(peer.empty(),"stale follower duplicated a foreground flight");
    a.cancel(early.id); expect_error(early.result,Error::canceled);
    require(first.flights.counts()==std::pair<std::size_t,std::size_t>{1,0},"background interest did not retain foreground task");
    peer.reply(std::move(foreground_packet),34); wait_idle(first.flights); wait_drained(a,0);
    auto shared=b.start(0,key(peer.endpoint,"foreground-first.example.test"),5s,true,true);
    expect_success(shared.result,34); require(peer.empty(),"attached background interest did not publish");

    // A cache fill between background registration and starting its task
    // invalidates the refresh token; a joined foreground waiter must recheck
    // and consume that fill instead of receiving a synthetic error.
    seed("registration-race.example.test",38);
    auto registered=first.flights.join_background(key(peer.endpoint,"registration-race.example.test"));
    require(registered && registered->leader,"background race registration failed");
    auto racing=b.start(0,key(peer.endpoint,"registration-race.example.test"),5s,true);
    auto deadline=Clock::now()+3s;
    while (first.flights.counts()!=std::pair<std::size_t,std::size_t>{1,1}) {
        require(Clock::now()<deadline,"foreground did not join the pending refresh"); std::this_thread::sleep_for(2ms);
    }
    d::CacheKey race_key{1,"registration-race.example.test",1}; d::Address race_address{};
    race_address.size=4; race_address.bytes[0]=127; race_address.bytes[3]=39;
    d::AddressAnswer race_answer{race_key.name,{race_key.name},{race_address},30};
    auto race_token=first.cache.begin_query(0,race_key);
    require(race_token && first.cache.publish(0,race_key,std::move(race_answer),stamp(),*race_token),"racing cache fill failed");
    a.start_registered(0,*registered);
    expect_success(racing.result,39); wait_idle(first.flights); wait_drained(a,0);
    require(peer.empty(),"ineligible background queried despite the fresh fill");

    seed("refresh-backoff.example.test",40);
    auto stale_failure=a.start(0,key(peer.endpoint,"refresh-backoff.example.test"),5s,true,true);
    expect_success(stale_failure.result,40); auto failure_packet=peer.receive(); peer.fail(std::move(failure_packet));
    wait_idle(first.flights); wait_drained(a,0);
    auto throttled=b.start(0,key(peer.endpoint,"refresh-backoff.example.test"),5s,true,true);
    expect_success(throttled.result,40); require(peer.empty(),"failed refresh ignored backoff");
    auto foreground_retry=b.start(0,key(peer.endpoint,"refresh-backoff.example.test"),5s,true);
    auto allowed=peer.receive(); peer.reply(std::move(allowed),41);
    expect_success(foreground_retry.result,41); wait_idle(first.flights); wait_drained(b,0);

    seed("refresh-retry.example.test",42);
    auto failed=a.start(0,key(peer.endpoint,"refresh-retry.example.test"),5s,true,true);
    expect_success(failed.result,42); auto failed_packet=peer.receive(); peer.fail(std::move(failed_packet));
    wait_idle(first.flights); wait_drained(a,0);
    std::this_thread::sleep_for(1100ms);
    auto retry_refresh=b.start(0,key(peer.endpoint,"refresh-retry.example.test"),5s,true,true);
    expect_success(retry_refresh.result,42); auto retried=peer.receive(); peer.reply(std::move(retried),43);
    wait_idle(first.flights); wait_drained(b,0);

    seed("stop-background.example.test",35);
    auto stale_stop=a.start(0,key(peer.endpoint,"stop-background.example.test"),5s,true,true);
    expect_success(stale_stop.result,35); auto pending=peer.receive();
    auto waiting=b.start(0,key(peer.endpoint,"stop-background.example.test"),5s,true);
    require(peer.empty(),"foreground stop test duplicated refresh");
    a.stop(0); expect_error(waiting.result,Error::canceled); wait_idle(first.flights); wait_drained(a,0);
    peer.reply(std::move(pending),36);
    auto retry=b.start(0,key(peer.endpoint,"stop-background.example.test"),5s,true);
    auto retry_packet=peer.receive(); peer.reply(std::move(retry_packet),37);
    expect_success(retry.result,37); wait_idle(first.flights); wait_drained(b,0);
    std::println("{}: foreground and refresh share one transaction and drain on stop",uring ? "io_uring" : "epoll");
}
auto delayed_cache_recheck(bool uring,bool negative,bool fractional=false) -> void {
    Peer peer; Generation first,second; Worker follower(first,second,1,uring);
    std::promise<void> entered,release; auto entered_future=entered.get_future(),release_future=release.get_future();
    std::atomic<std::uint64_t> expires=0;
    RecheckBlockingBinding binding(first.cache,negative,fractional,entered,release_future,expires);
    auto reader=first.cache.reader(0);
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(uring ? io::io_context(io::uring) : io::io_context(io::epoll));
#else
    io::io_context context(io::epoll); (void)uring;
#endif
    hp::FlightOwner<RecheckBlockingBinding> owner(context,binding,first.flights);
    hp::CoalescedCachedResolver<RecheckBlockingBinding> operation(context,binding,&reader,first.flights,owner);
    std::promise<Result> leader_result; auto leader_answer=leader_result.get_future();
    auto name=negative ? "delayed-cached-negative.example.test" :
              fractional ? "delayed-cached-fractional.example.test" : "delayed-cached-positive.example.test";
    auto task=[&]() -> boost::capy::task<> {
        leader_result.set_value(co_await operation.resolve(key(peer.endpoint,name),Clock::now()+7s));
    };
    std::jthread leader([&] {
        try {
            boost::capy::run_async(context.get_executor(),[] {},[&](std::exception_ptr error) noexcept {
                try { leader_result.set_exception(error); } catch (...) {}
            })(task());
            context.restart(); (void)context.run_for(7s);
        } catch (...) { try { leader_result.set_exception(std::current_exception()); } catch (...) {} }
    });
    require(entered_future.wait_for(3s)==std::future_status::ready,"leader did not reach the cache recheck");
    entered_future.get();
    auto delayed=follower.start(0,key(peer.endpoint,name),7s);
    auto until=Clock::now()+3s;
    while (first.flights.counts()!=std::pair<std::size_t,std::size_t>{1,2}) {
        require(Clock::now()<until,"follower did not join the cached result");
        std::this_thread::sleep_for(2ms);
    }
    auto unpause=follower.pause();
    release.set_value();
    if (negative) expect_error(leader_answer,Error::name_not_found);
    else expect_success(leader_answer,42);
    require(peer.empty(),"cached leader unexpectedly queried upstream");
    auto deadline=Clock::time_point(std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(expires.load())));
    std::this_thread::sleep_until(deadline+20ms);
    unpause.set_value();
    auto retry=peer.receive(); peer.reply(std::move(retry),43);
    expect_success(delayed.result,43); wait_idle(first.flights);
}
auto delayed_waiter_retry(Peer& peer,Generation& generation,Worker& a,Worker& b,bool negative) -> void {
    auto name=negative ? "delayed-negative-network.example.test" : "delayed-positive-network.example.test";
    auto first=a.start(0,key(peer.endpoint,name),5s);
    auto packet=peer.receive();
    auto delayed=b.start(0,key(peer.endpoint,name),5s);
    auto until=Clock::now()+3s;
    while (generation.flights.counts()!=std::pair<std::size_t,std::size_t>{1,2}) {
        require(Clock::now()<until,"delayed waiter did not join the flight");
        std::this_thread::sleep_for(2ms);
    }
    auto release=b.pause();
    peer.reply(std::move(packet),38,negative,2);
    if (negative) expect_error(first.result,Error::name_not_found);
    else expect_success(first.result,38);
    wait_drained(a,0);
    require(generation.flights.counts()==std::pair<std::size_t,std::size_t>{1,1},"delayed waiter did not retain the result");
    std::this_thread::sleep_for(1200ms);
    release.set_value();
    auto retry=peer.receive(); peer.reply(std::move(retry),39);
    expect_success(delayed.result,39); wait_idle(generation.flights); wait_drained(b,0);
}
auto delayed_waiter_deadline(Peer& peer,Generation& generation,Worker& a,Worker& b) -> void {
    auto first=a.start(0,key(peer.endpoint,"delayed-deadline.example.test"),5s);
    auto packet=peer.receive();
    auto delayed=b.start(0,key(peer.endpoint,"delayed-deadline.example.test"),400ms);
    auto until=Clock::now()+3s;
    while (generation.flights.counts()!=std::pair<std::size_t,std::size_t>{1,2}) {
        require(Clock::now()<until,"deadline waiter did not join the flight");
        std::this_thread::sleep_for(2ms);
    }
    auto release=b.pause();
    peer.reply(std::move(packet),40,false,2); expect_success(first.result,40);
    std::this_thread::sleep_for(500ms);
    release.set_value();
    expect_error(delayed.result,Error::timeout); wait_idle(generation.flights);
    require(peer.empty(),"expired waiter retried after its deadline");
}
// A zero/unknown TTL cannot seed a later request. Existing followers are part
// of the upstream transaction already in progress and keep their deadlines.
auto uncacheable_transaction(Peer& peer,Generation& generation,Worker& a,Worker& b,bool negative,bool soa) -> void {
    auto name=!negative ? "zero-positive.example.test" : soa ? "zero-negative.example.test" : "unknown-negative.example.test";
    auto first=a.start(0,key(peer.endpoint,name),5s,true); auto packet=peer.receive();
    auto delayed=b.start(0,key(peer.endpoint,name),5s,true);
    auto until=Clock::now()+3s;
    while (generation.flights.counts()!=std::pair<std::size_t,std::size_t>{1,2}) {
        require(Clock::now()<until,"uncacheable follower did not join");
        std::this_thread::sleep_for(2ms);
    }
    auto unpause=b.pause();
    peer.reply(std::move(packet),44,negative,0,false,soa);
    if (negative) expect_error(first.result,Error::name_not_found); else expect_success(first.result,44);
    wait_drained(a,0); std::this_thread::sleep_for(100ms); unpause.set_value();
    if (negative) expect_error(delayed.result,Error::name_not_found); else expect_success(delayed.result,44);
    wait_idle(generation.flights);
    auto later=a.start(0,key(peer.endpoint,name),5s,true);
    auto second=peer.receive(); peer.reply(std::move(second),45);
    expect_success(later.result,45); wait_idle(generation.flights);
}
auto seed_large(hp::GroupSnapshot& cache,d::CacheKey const& value,std::uint64_t now) -> bool {
    d::Address address{}; address.size=4; address.bytes[3]=1;
    d::AddressAnswer answer{value.name,std::vector<std::string>(16,std::string(200,'a')),
                            std::vector<d::Address>(128,address),60};
    auto token=cache.begin_query(0,value);
    return token && cache.publish_view(0,value.view,value.name,value.type,std::move(answer),now,*token).has_value();
}
auto subsecond_boundaries() -> void {
    Generation generation(1024*1024,5000);
    auto source_reader=generation.cache.reader(0),reader=generation.cache.reader(1);
    hp::GroupBinding first(generation.cache,0),second(generation.cache,1);
    d::CacheKey positive{1,"fraction-positive.example.test",1},negative{1,"fraction-negative.example.test",1};
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=35;
    d::AddressAnswer answer{positive.name,{positive.name},{address},2};
    auto p=first.begin_query(positive),n=first.begin_query(negative);
    require(p && n && first.publish(positive,std::move(answer),1000,*p) &&
            first.publish_negative(negative,d::NegativeKind::name_not_found,2,1000,*n),"subsecond seed failed");
    auto full=first.lookup(positive,2000,source_reader);
    auto full_negative=first.lookup_negative(negative,2000,source_reader);
    require(full && *full && (**full).ttl==1 && full_negative && *full_negative,"one-second cache boundary failed");
    auto fresh_positive=second.lookup_fresh(positive,2000,reader),fresh_negative=second.lookup_fresh(negative,2000,reader);
    require(fresh_positive && *fresh_positive && (**fresh_positive).answer && !(**fresh_positive).negative &&
            (**fresh_positive).expires==3000 && fresh_negative && *fresh_negative && (**fresh_negative).negative &&
            !(**fresh_negative).answer && (**fresh_negative).expires==3000,
            "cross-group fresh lookup lost its absolute expiry or answer kind");
    auto fraction=second.lookup(positive,2001,reader);
    auto fraction_negative=second.lookup_negative(negative,2001,reader);
#ifdef DNS_GROUP_ALLOW_SUBSECOND_EXPERIMENT
    require(fraction && *fraction && (**fraction).ttl==0 && fraction_negative && *fraction_negative,
            "subsecond positive or negative entry was missed");
#else
    require(fraction && !*fraction && fraction_negative && !*fraction_negative,"default subsecond miss changed");
#endif
    auto before_expiry=second.lookup(positive,2999,reader);
    auto before_negative=second.lookup_negative(negative,2999,reader);
#ifdef DNS_GROUP_ALLOW_SUBSECOND_EXPERIMENT
    require(before_expiry && *before_expiry && (**before_expiry).ttl==0 && before_negative && *before_negative,
            "subsecond result did not survive until the actual expiry");
#else
    require(before_expiry && !*before_expiry && before_negative && !*before_negative,"default subsecond miss changed");
#endif
    auto too_early=second.lookup_stale(positive,2999,reader);
    require(too_early && !*too_early,"fresh entry became stale before its expiry");
    auto expired=second.lookup(positive,3000,reader);
    auto expired_negative=second.lookup_negative(negative,3000,reader);
    auto expired_fresh=second.lookup_fresh(positive,3000,reader);
    auto stale=second.lookup_stale(positive,3000,reader);
    auto negative_stale=second.lookup_stale(negative,3000,reader);
    require(expired && !*expired && expired_negative && !*expired_negative && expired_fresh && !*expired_fresh && stale && *stale &&
            (**stale).age_ms==0 && (**stale).answer.ttl==1 && negative_stale && !*negative_stale,
            "expiry or stale boundary changed");
    d::CacheKey zero{1,"zero-ttl.example.test",1};
    d::AddressAnswer no_store{zero.name,{zero.name},{address},0};
    auto z=first.begin_query(zero);
    require(z && first.publish(zero,std::move(no_store),3000,*z),"zero-TTL publication failed");
    auto zero_hit=second.lookup(zero,3000,reader);
    require(zero_hit && !*zero_hit,"original zero-TTL response was cached");
}
auto acquired_expiry_boundaries() -> void {
    Generation generation(1024*1024,5000);
    hp::GroupBinding first(generation.cache,0),second(generation.cache,1);
    auto reader=generation.cache.reader(1);
    d::CacheKey positive{1,"acquired-positive.example.test",1},negative{1,"acquired-negative.example.test",1};
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=41;
    d::AddressAnswer answer{positive.name,{positive.name},{address},2};
    auto p=first.begin_query(positive),n=first.begin_query(negative);
    require(p && n && first.publish_from(positive,answer,1000,2500,*p) &&
            first.publish_negative_from(negative,d::NegativeKind::name_not_found,2,1000,2500,*n),
            "absolute acquisition publication failed");
    auto before=second.lookup(positive,2999,reader);
    auto neg_before=second.lookup_negative(negative,2999,reader);
#ifdef DNS_GROUP_ALLOW_SUBSECOND_EXPERIMENT
    require(before && *before && (**before).ttl==0 && neg_before && *neg_before,"absolute expiry moved earlier");
#else
    require(before && !*before && neg_before && !*neg_before,"default subsecond policy changed");
#endif
    auto expired=second.lookup(positive,3000,reader);
    auto neg_expired=second.lookup_negative(negative,3000,reader);
    auto stale=second.lookup_stale(positive,3000,reader);
    require(expired && !*expired && neg_expired && !*neg_expired && stale && *stale && (**stale).age_ms==0,
            "delayed publication extended the original deadline");

    Generation late;
    hp::GroupBinding late_binding(late.cache,0); auto late_reader=late.cache.reader(0);
    d::CacheKey subject{1,"late-acquired.example.test",1},other{1,"clock-advance.example.test",1};
    d::AddressAnswer subject_answer{subject.name,{subject.name},{address},2},other_answer{other.name,{other.name},{address},10};
    auto subject_token=late_binding.begin_query(subject),other_token=late_binding.begin_query(other);
    require(subject_token && other_token && late_binding.publish(other,std::move(other_answer),4000,*other_token) &&
            late_binding.publish_from(subject,subject_answer,1000,2500,*subject_token),"ordered delayed publication failed");
    auto late_hit=late_binding.lookup(subject,4000,late_reader);
    require(late_hit && !*late_hit,"cache clock advancement extended an expired result");
    auto future_token=late_binding.begin_query(subject);
    require(future_token.has_value(),"future acquisition token failed");
    auto future=late_binding.publish_from(subject,subject_answer,5000,2500,*future_token);
    require(!future && future.error()==d::CacheError::invalid_answer && late_binding.cancel_query(*future_token),
            "future acquisition was accepted or not recoverable");
    auto overflow_token=late_binding.begin_query(subject);
    require(overflow_token.has_value(),"overflow acquisition token failed");
    auto maximum=std::numeric_limits<std::uint64_t>::max();
    auto overflow=late_binding.publish_from(subject,subject_answer,maximum-1,maximum-1,*overflow_token);
    require(!overflow && overflow.error()==d::CacheError::invalid_answer && late_binding.cancel_query(*overflow_token),
            "overflow acquisition was accepted or not recoverable");
}
auto disabled_cache_burst(bool uring) -> void {
    d::CacheKey old{1,"old-burst.example.test",1},replacement{1,"new-burst.example.test",1};
    auto now=stamp(); std::size_t budget;
    {
        Generation measure;
        require(seed_large(measure.cache,old,now),"burst budget measurement failed");
        budget=measure.cache.charged_bytes();
    }
    Generation first(budget),second;
    require(seed_large(first.cache,old,now),"bounded burst seed failed");
    auto held=first.cache.reader(2);
    Peer peer; Worker a(first,second,0,uring),b(first,second,1,uring);
    bool checked=false;
    auto pin=first.cache.lookup_with_hook(0,old,now,held,[&] {
        require(!seed_large(first.cache,replacement,now),"held snapshot did not exhaust budget");
        auto disabled=first.cache.begin_query(0,old);
        require(!disabled && disabled.error()==d::CacheError::disabled,"bounded cache did not enter bypass");
        std::vector<Worker::Request> requests;
        requests.reserve(32);
        requests.push_back(a.start(0,key(peer.endpoint,"burst.example.test"),5s,true));
        auto packet=peer.receive();
        for (unsigned i=1;i<32;++i) requests.push_back((i%2 ? b : a).start(0,key(peer.endpoint,"burst.example.test"),5s,true));
        auto until=Clock::now()+3s;
        while (first.flights.counts()!=std::pair<std::size_t,std::size_t>{1,32}) {
            require(Clock::now()<until,"bounded burst did not register every waiter");
            std::this_thread::sleep_for(2ms);
        }
        auto rejected=b.start(0,key(peer.endpoint,"burst.example.test"),5s,true);
        expect_error(rejected.result,Error::limit);
        require(peer.empty(),"disabled cache burst launched extra upstream queries");
        for (unsigned i=0;i<requests.size();i+=2) a.cancel(requests[i].id);
        for (unsigned i=0;i<requests.size();i+=2) expect_error(requests[i].result,Error::canceled);
        require(peer.empty(),"canceling half the burst restarted the upstream query");
        peer.reply(std::move(packet),21);
        for (unsigned i=1;i<requests.size();i+=2) expect_success(requests[i].result,21);
        wait_idle(first.flights); wait_drained(a,0);
        checked=true;
    });
    require(pin && !*pin && checked && first.cache.peak_charged_bytes()<=budget,"disabled cache burst failed");
    require(first.cache.clear(stamp()).has_value() && seed_large(first.cache,old,stamp()),"bounded cache did not recover");
}
auto run(bool uring) -> void {
    Peer peer; Generation first,second; Worker a(first,second,0,uring),b(first,second,1,uring);
    owner_start_failures(peer.endpoint,uring); cache_registration_race(uring,false); cache_registration_race(uring,true);
    delayed_cache_recheck(uring,false); delayed_cache_recheck(uring,true);
#ifdef DNS_GROUP_ALLOW_SUBSECOND_EXPERIMENT
    delayed_cache_recheck(uring,false,true);
#endif
    recheck_failure(uring,false); recheck_failure(uring,true); cache_fault_network(uring,false); cache_fault_network(uring,true);
    stale_refresh_composition(uring); dual_composition(uring);
    // Compose normal cache lookup and bounded foreground sharing, including a
    // cross-group positive hit and a cached negative result after publication.
    auto cold_a=a.start(0,key(peer.endpoint,"cached.example.test"),5s,true);
    auto cold_b=b.start(0,key(peer.endpoint,"CACHED.EXAMPLE.TEST"),5s,true);
    auto cold_packet=peer.receive(); require(peer.empty(),"cached misses did not share the flight");
    peer.reply(std::move(cold_packet),23); expect_success(cold_a.result,23); expect_success(cold_b.result,23); wait_idle(first.flights);
    auto hit=b.start(0,key(peer.endpoint,"cached.example.test"),5s,true);
    expect_success(hit.result,23); require(peer.empty(),"cross-group positive cache hit queried upstream");
    auto negative_cold=a.start(0,key(peer.endpoint,"cached-negative.example.test"),5s,true);
    auto negative_packet_cached=peer.receive(); peer.reply(std::move(negative_packet_cached),0,true);
    expect_error(negative_cold.result,Error::name_not_found); wait_idle(first.flights);
    auto negative_hit=b.start(0,key(peer.endpoint,"cached-negative.example.test"),5s,true);
    expect_error(negative_hit.result,Error::name_not_found); require(peer.empty(),"cross-group negative cache hit queried upstream");
    // Network latency conservatively consumes one second of a two-second
    // wire TTL. Exercise the remaining fractional second in both variants.
    auto short_first=a.start(0,key(peer.endpoint,"short-cache.example.test"),5s,true);
    auto short_packet=peer.receive(); peer.reply(std::move(short_packet),25,false,2);
    expect_success(short_first.result,25); wait_idle(first.flights);
    std::this_thread::sleep_for(5ms);
    auto short_second=b.start(0,key(peer.endpoint,"short-cache.example.test"),5s,true);
#ifdef DNS_GROUP_ALLOW_SUBSECOND_EXPERIMENT
    expect_success(short_second.result,25);
    require(peer.empty(),"subsecond cache hit queried upstream");
#else
    auto short_miss=peer.receive(); peer.reply(std::move(short_miss),25,false,2);
    expect_success(short_second.result,25);
#endif
    // Explicit disable-cache preserves separate network requests.
    auto uncached_key=key(peer.endpoint,"explicit-no-cache.example.test"); uncached_key.use_cache=false;
    auto uncached_a=a.start(0,uncached_key,5s,true),uncached_b=b.start(0,uncached_key,5s,true);
    auto uncached_packet_a=peer.receive(),uncached_packet_b=peer.receive();
    peer.reply(std::move(uncached_packet_a),24); peer.reply(std::move(uncached_packet_b),24);
    expect_success(uncached_a.result,24); expect_success(uncached_b.result,24);
    // Uncached requests remain independent but must share the bounded budget
    // with foreground flights, including throughout cancellation and drain.
    std::vector<Worker::Request> direct_requests; std::vector<Peer::Packet> direct_packets;
    for (unsigned i=0;i<8;++i) {
        auto name=key(peer.endpoint,std::format("direct-budget-{}.example.test",i)); name.use_cache=false;
        direct_requests.push_back((i%2 ? b : a).start(0,std::move(name),5s,true));
        direct_packets.push_back(peer.receive());
    }
    require(first.flights.direct_active()==8,"direct requests did not retain all permits");
    auto over_key=key(peer.endpoint,"direct-excess.example.test"); over_key.use_cache=false;
    auto over=b.start(0,over_key,5s,true); expect_error(over.result,Error::limit);
    auto over_flight=a.start(0,key(peer.endpoint,"mixed-excess.example.test"),5s,true);
    expect_error(over_flight.result,Error::limit);
    require(peer.empty(),"full mixed budget started another query");
    for (unsigned i=0;i<4;++i) (i%2 ? b : a).cancel(direct_requests[i].id);
    for (unsigned i=0;i<4;++i) expect_error(direct_requests[i].result,Error::canceled);
    auto wait_direct=[&](std::size_t expected) {
        auto deadline=Clock::now()+3s;
        while (first.flights.direct_active()!=expected) {
            require(Clock::now()<deadline,"direct requests did not drain"); std::this_thread::sleep_for(2ms);
        }
    };
    wait_direct(4);
    auto mixed_a=a.start(0,key(peer.endpoint,"mixed-shared.example.test"),5s,true);
    auto mixed_packet=peer.receive();
    auto mixed_b=b.start(0,key(peer.endpoint,"mixed-shared.example.test"),5s,true);
    std::vector<Worker::Request> replacement_requests; std::vector<Peer::Packet> replacement_packets;
    for (unsigned i=0;i<3;++i) {
        auto name=key(peer.endpoint,std::format("direct-reuse-{}.example.test",i)); name.use_cache=false;
        replacement_requests.push_back((i%2 ? b : a).start(0,std::move(name),5s,true));
        replacement_packets.push_back(peer.receive());
    }
    auto full_again=a.start(0,over_key,5s,true); expect_error(full_again.result,Error::limit);
    require(peer.empty(),"reused mixed budget exceeded its limit");
    for (unsigned i=4;i<8;++i) peer.reply(std::move(direct_packets[i]),41);
    for (auto& packet:replacement_packets) peer.reply(std::move(packet),42);
    peer.reply(std::move(mixed_packet),43);
    for (unsigned i=4;i<8;++i) expect_success(direct_requests[i].result,41);
    for (auto& request:replacement_requests) expect_success(request.result,42);
    expect_success(mixed_a.result,43); expect_success(mixed_b.result,43);
    wait_idle(first.flights); wait_direct(0);
    for (unsigned i=0;i<4;++i) peer.reply(std::move(direct_packets[i]),44);
    auto timed_key=key(peer.endpoint,"direct-timeout.example.test"); timed_key.use_cache=false;
    auto timed=a.start(0,timed_key,200ms,true); auto timed_packet=peer.receive();
    expect_error(timed.result,Error::timeout); wait_direct(0);
    peer.reply(std::move(timed_packet),45);
    auto timed_retry=b.start(0,timed_key,5s,true); auto retry_direct_packet=peer.receive();
    peer.reply(std::move(retry_direct_packet),46); expect_success(timed_retry.result,46); wait_direct(0);
    delayed_waiter_retry(peer,first,a,b,false); delayed_waiter_retry(peer,first,a,b,true); delayed_waiter_deadline(peer,first,a,b);
    uncacheable_transaction(peer,first,a,b,false,true);
    uncacheable_transaction(peer,first,a,b,true,true);
    uncacheable_transaction(peer,first,a,b,true,false);
    auto one=a.start(0,key(peer.endpoint)); auto two=b.start(0,key(peer.endpoint,"SAME.EXAMPLE.TEST"));
    auto packet=peer.receive(); require(peer.empty(),"same key launched more than one upstream query");
    peer.reply(std::move(packet),7); expect_success(one.result,7); expect_success(two.result,7); wait_idle(first.flights);
    auto negative_a=a.start(0,key(peer.endpoint,"negative.example.test")); auto negative_b=b.start(0,key(peer.endpoint,"negative.example.test"));
    auto negative_packet=peer.receive(); require(peer.empty(),"negative flight was not shared"); peer.reply(std::move(negative_packet),0,true);
    expect_error(negative_a.result,Error::name_not_found); expect_error(negative_b.result,Error::name_not_found); wait_idle(first.flights);
    auto canceled=a.start(0,key(peer.endpoint,"cancel.example.test"),5s); auto cancel_packet=peer.receive();
    auto still=b.start(0,key(peer.endpoint,"cancel.example.test"),5s); a.cancel(canceled.id); expect_error(canceled.result,Error::canceled);
    require(peer.empty(),"canceling one waiter canceled the shared upstream"); peer.reply(std::move(cancel_packet),8); expect_success(still.result,8); wait_idle(first.flights);
    auto timeout=a.start(0,key(peer.endpoint,"timeout.example.test"),200ms); auto waiting=b.start(0,key(peer.endpoint,"timeout.example.test"),5s);
    auto timeout_packet=peer.receive(); expect_error(timeout.result,Error::timeout); require(peer.empty(),"timeout canceled the shared flight for another waiter");
    peer.reply(std::move(timeout_packet),9); expect_success(waiting.result,9); wait_idle(first.flights);
    // Last waiter cancellation retires the task until cancellation completes;
    // the late packet must not publish a cache result.
    auto last=a.start(0,key(peer.endpoint,"last.example.test"),5s); auto last_packet=peer.receive();
    a.cancel(last.id); expect_error(last.result,Error::canceled); wait_idle(first.flights); wait_drained(a,0);
    peer.reply(std::move(last_packet),11);
    {
        auto reader=first.cache.reader(2);
        auto cached=first.cache.lookup(0,{1,"last.example.test",1},stamp(),reader);
        require(cached && !*cached,"canceled last waiter published a cache entry");
    }
    // New configuration is an independent group even with the same numeric
    // view. A delayed old response cannot affect its result or cache.
    auto old_config=a.start(0,key(peer.endpoint,"generation.example.test")); auto old_packet=peer.receive();
    auto new_config=b.start(1,key(peer.endpoint,"generation.example.test")); auto new_packet=peer.receive();
    peer.reply(std::move(new_packet),10); expect_success(new_config.result,10);
    peer.reply(std::move(old_packet),12); expect_success(old_config.result,12);
    wait_idle(first.flights); wait_idle(second.flights);
    {
        auto reader=second.cache.reader(2);
        auto cached=second.cache.lookup(0,{1,"generation.example.test",1},stamp(),reader);
        require(cached && *cached && (**cached).addresses[0].bytes[3]==10,"old generation contaminated new cache");
    }
    // A second upstream and different query options remain separate even when
    // the normalized DNS name and view match.
    Peer other_peer;
    auto upstream_a=a.start(0,key(peer.endpoint,"upstream.example.test"));
    auto upstream_b=b.start(0,key(other_peer.endpoint,"upstream.example.test"));
    auto upstream_packet=peer.receive(),other_packet=other_peer.receive();
    peer.reply(std::move(upstream_packet),13); other_peer.reply(std::move(other_packet),14);
    expect_success(upstream_a.result,13); expect_success(upstream_b.result,14); wait_idle(first.flights);
    // Different upstream and view are intentionally independent flights.
    auto view_one=a.start(0,key(peer.endpoint,"view.example.test",1)); auto view_two=b.start(0,key(peer.endpoint,"view.example.test",2));
    auto first_packet=peer.receive(); auto second_packet=peer.receive(); peer.reply(std::move(first_packet),3); peer.reply(std::move(second_packet),3);
    expect_success(view_one.result,3); expect_success(view_two.result,3); wait_idle(first.flights);
    // Completion, cancellation and last-waiter retirement can win in either
    // order. Drain every task before the next iteration or worker shutdown.
    for (unsigned iteration=0;iteration<48;++iteration) {
        auto left=a.start(0,key(peer.endpoint,"race.example.test"),5s);
        auto right=b.start(0,key(peer.endpoint,"race.example.test"),5s);
        auto race_packet=peer.receive();
        std::exception_ptr send_error;
        std::thread sender([&peer,&send_error,packet=std::move(race_packet)]() mutable {
            try { peer.reply(std::move(packet),42); } catch (...) { send_error=std::current_exception(); }
        });
        a.cancel(left.id); b.cancel(right.id); sender.join();
        if (send_error) std::rethrow_exception(send_error);
        for (auto* future:{&left.result,&right.result}) {
            require(future->wait_for(3s)==std::future_status::ready,"racing waiter did not finish");
            auto answer=future->get();
            require((answer && answer->addresses.size()==1 && answer->addresses[0].bytes[3]==42) ||
                    (!answer && answer.error()==Error::canceled),"unexpected cancel/reply race result");
        }
        wait_idle(first.flights);
    }
    // Stopping an owner cancels its shared network operation. A later request
    // may start on another owner after the old operation has drained.
    auto old=a.start(0,key(peer.endpoint,"stop.example.test")); auto stop_packet=peer.receive();
    auto follower=b.start(0,key(peer.endpoint,"stop.example.test"));
    a.stop(0); expect_error(old.result,Error::canceled); expect_error(follower.result,Error::canceled);
    wait_idle(first.flights); wait_drained(a,0); peer.reply(std::move(stop_packet),5);
    auto stopped=a.start(0,key(peer.endpoint,"stop.example.test")); expect_error(stopped.result,Error::canceled);
    auto no_cache_stopped=key(peer.endpoint,"stopped-direct.example.test"); no_cache_stopped.use_cache=false;
    auto stopped_direct=a.start(0,std::move(no_cache_stopped),5s,true); expect_error(stopped_direct.result,Error::canceled);
    require(peer.empty(),"stopped owner started an uncached query");
    auto late=b.start(0,key(peer.endpoint,"stop.example.test")); auto retry_packet=peer.receive();
    peer.reply(std::move(retry_packet),6); expect_success(late.result,6); wait_idle(first.flights);
    // Capacity is bounded and rejected before a second upstream query starts.
    hp::FlightGroup bounded(1,1); hp::FlightGroup::Waiter first_waiter,rejected_waiter,excess_waiter,retiring_waiter;
    auto joined=bounded.join(key(peer.endpoint),first_waiter); require(joined.has_value(),"bounded join failed");
    auto rejected=bounded.join(key(peer.endpoint,"other.example.test"),rejected_waiter); require(!rejected && rejected.error()==Error::limit,"bounded flights accepted excess work");
    auto excess=bounded.join(key(peer.endpoint),excess_waiter); require(!excess && excess.error()==Error::limit,"bounded waiters accepted excess work");
    bounded.leave(first_waiter); require(bounded.counts()==std::pair<std::size_t,std::size_t>{1,0},"last waiter retired too early");
    bounded.retire(joined->flight); require(bounded.retiring(joined->flight),"retiring state missing");
    auto retiring=bounded.join(key(peer.endpoint),retiring_waiter); require(!retiring && retiring.error()==Error::limit,"retiring flight accepted a new waiter");
    bounded.complete(joined->flight,std::unexpected(Error::canceled));
    bounded.finish(joined->flight);
    std::println("{}: foreground singleflight sharing, individual timeout/cancel, view isolation and bounded rejection passed",uring ? "io_uring" : "epoll");
}
}
int main() {
    try {
        Peer allocation_peer; allocation_failures(allocation_peer.endpoint); retained_flights(allocation_peer.endpoint);
        capacity_boundaries(allocation_peer.endpoint); background_backoff(allocation_peer.endpoint);
        subsecond_boundaries(); acquired_expiry_boundaries();
        retained_retry_recheck(false,false); retained_retry_recheck(false,true);
        retry_recheck_boundaries(false);
        coordinated_refresh_capacity(false);
        coordinated_refresh_tcp(false);
        dual_coordinated_composition(false);
#if BOOST_COROSIO_HAVE_LIBURING
        retained_retry_recheck(true,false); retained_retry_recheck(true,true);
        retry_recheck_boundaries(true);
        coordinated_refresh_capacity(true);
        coordinated_refresh_tcp(true);
        dual_coordinated_composition(true);
#endif
        run(false); disabled_cache_burst(false); coordinated_refresh(false);
#if BOOST_COROSIO_HAVE_LIBURING
        run(true); disabled_cache_burst(true); coordinated_refresh(true);
#endif
        std::puts("disabled-cache 32-waiter burst: one upstream request, bounded rejection and cancellation passed");
    } catch (std::exception const& error) { std::println(stderr,"singleflight: {}",error.what()); return 1; }
}
