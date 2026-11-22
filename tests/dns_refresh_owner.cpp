#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.corosio_cached;
namespace d=dns;
namespace io=nex::corosio;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
auto now_ms() -> std::uint64_t { return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count(); }
struct Socket { int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); ~Socket() { if (fd>=0) ::close(fd); } };
auto stale_request(d::detail::CachedAddressResolver& resolver,io::endpoint upstream,
                   std::optional<std::expected<d::AddressAnswer,d::detail::ResolveError>>& output) -> boost::capy::task<> {
    output=co_await resolver.resolve(upstream,1,{"One.Test.",1},Clock::now()+2s);
}
int test(bool uring) {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if (uring) return 77; io::io_context context(io::epoll);
#endif
    Socket peer; sockaddr_in bind_address{}; bind_address.sin_family=AF_INET; bind_address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (peer.fd<0 || bind(peer.fd,reinterpret_cast<sockaddr*>(&bind_address),sizeof(bind_address))) return 1;
    socklen_t length=sizeof(bind_address); if (getsockname(peer.fd,reinterpret_cast<sockaddr*>(&bind_address),&length)) return 2;
    io::endpoint upstream(io::ipv4_address::loopback(),ntohs(bind_address.sin_port));
    d::AddressCache cache(8,10000); d::Address a{}; a.size=4; a.bytes[0]=127; a.bytes[3]=1;
    auto seed=[&](std::string name,bool already_stale=true) {
        d::CacheKey key{1,name,1}; d::AddressAnswer answer{name,{name},{a},1};
        auto token=cache.begin_query(key);
        return token && cache.publish(key,std::move(answer),now_ms()-(already_stale ? 1200 : 0),*token).has_value();
    };
    if (!seed("one.test") || !seed("two.test")) return 3;
    d::detail::RefreshOwner owner(context,cache,1,2s,800ms);
    auto tick=[&](std::chrono::milliseconds duration) { context.restart(); (void)context.run_for(duration); };
    auto receive=[&](std::vector<std::uint8_t>& packet,sockaddr_in& from) {
        std::array<std::uint8_t,512> data{}; socklen_t size=sizeof(from);
        for (unsigned i=0;i<50;++i) {
            tick(10ms); auto n=recvfrom(peer.fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&from),&size);
            if (n>0) { packet.assign(data.begin(),data.begin()+n); return true; }
        }
        return false;
    };
    auto answer=[&](std::vector<std::uint8_t> packet,sockaddr_in const& dest,int failure) {
        packet[2]=0x81; packet[3]=failure==2 ? 0x83 : failure ? 0x82 : 0x80;
        if (!failure) {
            packet[7]=1;
            std::array<std::uint8_t,16> record{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,127,0,0,9};
            packet.insert(packet.end(),record.begin(),record.end());
        }
        return sendto(peer.fd,packet.data(),packet.size(),0,reinterpret_cast<sockaddr const*>(&dest),sizeof(dest))==static_cast<ssize_t>(packet.size());
    };
    d::detail::CachedAddressResolver resolver(context,cache,false,false,false,&owner);
    std::optional<std::expected<d::AddressAnswer,d::detail::ResolveError>> stale_result;
    boost::capy::run_async(context.get_executor())(stale_request(resolver,upstream,stale_result));
    tick(20ms);
    if (!stale_result || !*stale_result || (**stale_result).ttl!=1 || (**stale_result).addresses[0].bytes[3]!=1 ||
        owner.active()!=1 || owner.start({1,"one.test",1},upstream) || owner.start({1,"two.test",1},upstream)) return 4;
    std::vector<std::uint8_t> packet; sockaddr_in from{};
    if (!receive(packet,from) || !answer(packet,from,false)) return 5;
    tick(100ms);
    auto fresh=cache.lookup({1,"one.test",1},now_ms());
    if (!owner.drained() || !fresh || !*fresh || (**fresh).addresses[0].bytes[3]!=9) return 6;
    if (!owner.start({1,"two.test",1},upstream) || !receive(packet,from) || !answer(packet,from,true)) return 7;
    tick(100ms);
    if (!owner.drained() || owner.start({1,"two.test",1},upstream)) return 8;
    auto stale=cache.lookup_stale({1,"two.test",1},now_ms()); if (!stale || !*stale) return 9;
    std::this_thread::sleep_for(850ms);
    if (!owner.start({1,"two.test",1},upstream) || !receive(packet,from)) return 10;
    if (!cache.clear(now_ms()) || !answer(packet,from,false)) return 11;
    tick(100ms);
    fresh=cache.lookup({1,"two.test",1},now_ms());
    if (!owner.drained() || !fresh || *fresh) return 12;
    if (!seed("three.test",false)) return 13;
    std::this_thread::sleep_for(1100ms);
    if (!owner.start({1,"three.test",1},upstream) || !receive(packet,from)) return 13;
    d::CacheKey third{1,"three.test",1}; d::Address replacement=a; replacement.bytes[3]=7;
    d::AddressAnswer newer{"three.test",{"three.test"},{replacement},30};
    auto next=cache.begin_query(third);
    if (!next || !cache.publish(third,newer,now_ms(),*next) || owner.start({1,"THREE.TEST.",1},upstream) || owner.active()!=1) return 15;
    if (!answer(packet,from,false)) return 16;
    tick(100ms);
    fresh=cache.lookup(third,now_ms());
    if (!owner.drained() || !fresh || !*fresh || (**fresh).addresses[0].bytes[3]!=7) return 17;
    if (!seed("four.test",false)) return 18;
    std::this_thread::sleep_for(1100ms);
    if (!owner.start({1,"four.test",1},upstream) || !receive(packet,from)) return 19;
    if (!answer(packet,from,2)) return 20;
    tick(100ms);
    stale=cache.lookup_stale({1,"four.test",1},now_ms());
    if (!owner.drained() || !stale || *stale) return 21;
    if (!seed("five.test",false)) return 22;
    std::this_thread::sleep_for(1100ms);
    if (!owner.start({1,"five.test",1},upstream) || !receive(packet,from)) return 23;
    owner.stop(); tick(100ms);
    if (!owner.drained() || owner.start({1,"five.test",1},upstream)) return 14;
    d::detail::RefreshOwner other(context,cache,2,5s,800ms);
    if (!seed("six.test",false) || !seed("seven.test",false)) return 24;
    std::this_thread::sleep_for(1100ms);
    if (!other.start({1,"six.test",1},upstream) || !receive(packet,from)) return 25;
    d::CacheKey sixth{1,"six.test",1}; d::AddressAnswer replacement_six{"six.test",{"six.test"},{replacement},1};
    auto newer_token=cache.begin_query(sixth);
    if (!newer_token || !cache.publish(sixth,replacement_six,now_ms(),*newer_token)) return 26;
    std::this_thread::sleep_for(1100ms);
    // The original token is gone and the replacement is stale, but the old
    // network task still owns this key and must prevent a second refresh.
    if (other.start({1,"SIX.TEST.",1},upstream) || other.active()!=1 ||
        !other.start({1,"seven.test",1},upstream) || !receive(packet,from) || other.active()!=2) return 27;
    other.stop(); tick(100ms); if (!other.drained()) return 28;

    d::AddressCache shared_cache(8,10000,true);
    auto stamp=now_ms()-1200;
    auto shared_seed=[&](std::string name) {
        d::CacheKey key{1,name,1}; d::AddressAnswer answer{name,{name},{a},1};
        auto token=shared_cache.begin_query(key);
        return token && shared_cache.publish(key,std::move(answer),stamp,*token).has_value();
    };
    if (!shared_seed("global-one.test") || !shared_seed("global-two.test") || !shared_seed("global-three.test")) return 29;
    d::detail::RefreshBudget budget(2);
    d::detail::RefreshOwner first(context,shared_cache,2,5s,800ms,&budget);
    d::detail::RefreshOwner second(context,shared_cache,2,5s,800ms,&budget);
    d::CacheKey global{1,"global-one.test",1};
    if (!first.start(global,upstream) || !receive(packet,from) || budget.active()!=1) return 30;
    auto replacement_token=shared_cache.begin_query(global);
    d::AddressAnswer global_replacement{global.name,{global.name},{replacement},1};
    if (!replacement_token || !shared_cache.publish(global,std::move(global_replacement),now_ms(),*replacement_token)) return 31;
    std::this_thread::sleep_for(1100ms);
    // The first task is still live even though the new publication removed its
    // cache token. Another executor owner must neither duplicate nor bypass it.
    if (second.start({1,"GLOBAL-ONE.TEST.",1},upstream) || budget.active()!=1 ||
        !second.start({1,"global-two.test",1},upstream) || !receive(packet,from) ||
        budget.active()!=2 || second.start({1,"global-three.test",1},upstream)) return 32;
    first.stop();
    if (budget.active()!=2) return 33;
    tick(100ms);
    if (!first.drained() || budget.active()!=1 || !second.start({1,"global-three.test",1},upstream) ||
        !receive(packet,from) || budget.active()!=2) return 34;
    second.stop(); tick(100ms);
    if (!second.drained() || budget.active()!=0) return 35;

    d::AddressCache backoff_cache(1,10000,true);
    d::CacheKey retry_key{1,"global-retry.test",1};
    d::AddressAnswer retry_answer{retry_key.name,{retry_key.name},{a},1};
    auto retry_token=backoff_cache.begin_query(retry_key);
    if (!retry_token || !backoff_cache.publish(retry_key,std::move(retry_answer),now_ms()-1200,*retry_token)) return 36;
    d::detail::RefreshBudget retry_budget(2);
    d::detail::RefreshOwner retry_first(context,backoff_cache,2,5s,800ms,&retry_budget);
    d::detail::RefreshOwner retry_second(context,backoff_cache,2,5s,800ms,&retry_budget);
    if (!retry_first.start(retry_key,upstream) || !receive(packet,from) || !answer(packet,from,true)) return 37;
    tick(100ms);
    if (!retry_first.drained() || retry_budget.active() || retry_second.start(retry_key,upstream)) return 38;
    std::this_thread::sleep_for(850ms);
    if (!retry_second.start(retry_key,upstream) || !receive(packet,from)) return 39;
    retry_second.stop(); tick(100ms);
    if (!retry_second.drained() || retry_budget.active()) return 40;
    return 0;
}
int main() {
    for (bool uring:{false,true}) {
        auto result=test(uring); if (result==77) continue;
        if (result) { std::fprintf(stderr,"refresh owner %s: %d\n",uring ? "io_uring" : "epoll",result); return result; }
    }
    std::puts("DNS refresh owner limits, backoff, generation and stop passed");
}
