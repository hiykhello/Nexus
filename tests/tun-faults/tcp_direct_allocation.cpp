#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <new>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import tcp.direct;
namespace p = ::packet;
namespace t=tcp;
namespace r = ::rules;
namespace { bool armed=false, fail_next=false, injected=false; }

void* operator new(std::size_t n) {
    if (fail_next) { fail_next=false; injected=true; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
extern "C" ssize_t __real_recv(int,void*,size_t,int);
extern "C" ssize_t __wrap_recv(int fd,void* buffer,size_t size,int flags) {
    auto result=__real_recv(fd,buffer,size,flags);
    if (armed && result>0) { armed=false; fail_next=true; }
    return result;
}
struct Socket { int fd=-1; ~Socket() { if (fd>=0) ::close(fd); } };

auto main() -> int {
    Socket listener{::socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (listener.fd<0 || ::bind(listener.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || ::listen(listener.fd,1)) return 1;
    socklen_t length=sizeof(address); if (::getsockname(listener.fd,reinterpret_cast<sockaddr*>(&address),&length)) return 2;
    p::MemoryLink link;
    auto table=t::ConnectionTable::create(1,64);
    p::Tcp4View syn{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
                    .destination_port=ntohs(address.sin_port),.sequence=99,.flags=2};
    auto id=table->open(syn,50,0); if (!id) return 3;
    auto* flow=table->get(*id);
    p::Tcp4View ack{.source=syn.source,.destination=syn.destination,.source_port=syn.source_port,
                    .destination_port=syn.destination_port,.sequence=100,.acknowledgement=51,.flags=0x10,.window=64};
    if (!flow->input(ack,0)) return 4;
    t::MemoryEngine engine(link,*table);
    t::Direct4 direct(*table,engine,r::Matcher{},1);
    if (!direct.start(*id,0)) return 5;
    Socket peer;
    std::uint64_t now=0;
    for (int i=0;i<400 && peer.fd<0;++i) {
        auto step=direct.step(++now); if (!step || step->error) return 6;
        peer.fd=::accept4(listener.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (peer.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 7;
        pollfd wait{.fd=listener.fd,.events=POLLIN,.revents=0}; (void)::poll(&wait,1,2);
    }
    if (peer.fd<0 || ::send(peer.fd,"hello",5,MSG_NOSIGNAL)!=5) return 8;
    armed=true; bool caught=false;
    for (int i=0;i<400 && !caught;++i) {
        try { auto step=direct.step(++now); if (!step || step->error) return 9; }
        catch (std::bad_alloc const&) { caught=true; }
        if (!caught) { pollfd wait{.fd=peer.fd,.events=POLLOUT,.revents=0}; (void)::poll(&wait,1,2); }
    }
    if (!caught || !injected || direct.size()!=1 || !flow->unsent(64).bytes.empty()) return 10;
    auto retry=direct.step(++now);
    if (!retry || retry->error || retry->from_upstream!=5) return 11;
    auto queued=flow->unsent(64).bytes;
    if (std::string(queued.begin(),queued.end())!="hello") return 12;
    auto again=direct.step(++now);
    if (!again || again->error || again->from_upstream || flow->unsent(64).bytes!=queued) return 13;
    std::println("TCP direct retains received bytes across allocation failure");
}
