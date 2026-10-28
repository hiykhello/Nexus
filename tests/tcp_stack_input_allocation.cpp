#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <new>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.tcp.stack;
namespace p=nexus::packet;
namespace t=nexus::tcp;
namespace r=nexus::rules;
namespace { int remaining=-1; }
void* operator new(std::size_t n) {
    if (remaining>0 && --remaining==0) { remaining=-1; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
struct Socket { int fd=-1; ~Socket() { if (fd>=0) ::close(fd); } };
int main() {
    for (int position=1;position<=2;++position) {
        Socket listener{::socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if (listener.fd<0 || ::bind(listener.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || ::listen(listener.fd,1)) return 1;
        socklen_t length=sizeof(address); if (::getsockname(listener.fd,reinterpret_cast<sockaddr*>(&address),&length)) return 2;
        p::MemoryLink link;
        auto table=t::ConnectionTable::create(1,64);
        t::MemoryDirect4 stack(link,*table,r::Matcher{},1);
        p::Tcp4View client{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
                           .destination_port=ntohs(address.sin_port),.sequence=99,.flags=2,.window=64};
        auto send=[&] { auto bytes=p::make_tcp4(client); return bytes && link.send(p::Side::first,*bytes).has_value(); };
        if (!send()) return 3;
        auto syn=stack.step(0,50); if (!syn || !syn->input.opened || !syn->input.id) return 4;
        auto response=link.receive(p::Side::first); if (!response || !*response) return 5;
        std::array<std::uint8_t,2> data{'a','b'};
        client.flags=0x18; client.sequence=100; client.acknowledgement=51; client.payload=data;
        if (!send()) return 6;
        remaining=position;
        if (position==1) {
            bool caught=false;
            try { (void)stack.step(1,50); } catch (std::bad_alloc const&) { caught=true; }
            remaining=-1; if (!caught) return 7;
        } else {
            auto result=stack.step(1,50); remaining=-1;
            if (!result || !result->input.backpressured || result->input.id!=syn->input.id) return 8;
        }
        Socket peer; std::array<std::uint8_t,4> received{}; std::size_t count=0;
        int replies=0;
        for (std::uint64_t now=2;now<1000 && (count<2 || !replies);++now) {
            auto step=stack.step(now,999); if (!step || step->start_error || step->direct.error) return 9;
            if (peer.fd<0) {
                peer.fd=::accept4(listener.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
                if (peer.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 10;
            }
            if (peer.fd>=0) {
                auto n=::recv(peer.fd,received.data()+count,received.size()-count,0);
                if (n>0) count+=static_cast<std::size_t>(n);
                else if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 11;
            }
            auto packet=link.receive(p::Side::first);
            if (!packet) return 12;
            if (*packet) { auto view=p::parse_tcp4(**packet); if (!view || view->acknowledgement!=102) return 13; ++replies; }
        }
        if (count!=2 || received[0]!='a' || received[1]!='b' || replies!=1) return 14;
        auto extra=::recv(peer.fd,received.data(),received.size(),0);
        if (extra>=0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 15;
    }
    std::println("TCP stack forwards handshake data once after input allocation failures");
}
