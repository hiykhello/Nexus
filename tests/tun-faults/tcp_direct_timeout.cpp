#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import tcp.direct;
namespace p = ::packet;
namespace t = tcp;
namespace r = ::rules;
namespace { bool suppress_poll = false; int outbound = -1; bool closed = false; }
extern "C" int __real_poll(pollfd*, nfds_t, int);
extern "C" int __wrap_poll(pollfd* fds, nfds_t count, int timeout) {
    return suppress_poll ? 0 : __real_poll(fds, count, timeout);
}
extern "C" int __real_socket(int, int, int);
extern "C" int __wrap_socket(int domain, int type, int protocol) {
    int fd = __real_socket(domain, type, protocol);
    if (suppress_poll) outbound = fd;
    return fd;
}
extern "C" int __real_close(int);
extern "C" int __wrap_close(int fd) {
    if (fd == outbound && outbound >= 0) closed = true;
    return __real_close(fd);
}
int main() {
    int listener = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return 1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || ::listen(listener, 4)) return 1;
    socklen_t size=sizeof(address);
    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size)) return 1;
    p::MemoryLink link;
    auto table=t::ConnectionTable::create(1,8);
    p::Tcp4View syn{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
                    .destination_port=ntohs(address.sin_port),.sequence=99,.flags=2};
    auto id=table->open(syn,50,100);
    p::Tcp4View ack{.source=syn.source,.destination=syn.destination,.source_port=syn.source_port,
                    .destination_port=syn.destination_port,.sequence=100,.acknowledgement=51,.flags=0x10,.window=8};
    if (!id || !table->get(*id)->input(ack,100)) return 1;
    t::MemoryEngine engine(link,*table);
    t::Direct4 direct(*table,engine,r::Matcher{},1);
    suppress_poll=true;
    if (!direct.start(*id,100) || outbound < 0) return 1;
    auto reversed=direct.step(99);
    if (reversed || reversed.error()!=t::DirectError::time_reversed) return 1;
    auto before=direct.step(10099);
    if (!before || before->error || before->retired || closed) return 1;
    auto expired=direct.step(10100);
    if (!expired || !expired->error || !std::holds_alternative<t::DirectError>(*expired->error) ||
        std::get<t::DirectError>(*expired->error)!=t::DirectError::connect_timeout ||
        !expired->retired || !closed || direct.size()) return 1;
    auto output=link.receive(p::Side::first);
    if (!output || !*output) return 1;
    auto rst=p::parse_tcp4(**output);
    if (!rst || rst->flags!=0x14 || !table->reclaim(*id,10100)) return 1;
    suppress_poll=false;
    ::close(listener);
    std::cout << "TCP direct connect timeout and reset passed\n";
}
