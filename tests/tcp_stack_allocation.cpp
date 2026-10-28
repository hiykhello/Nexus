#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <new>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.tcp.stack;
namespace p=nexus::packet;
namespace t=nexus::tcp;
namespace r=nexus::rules;
namespace { bool armed=false, fail_next=false, injected=false; int captured=-1; }
void* operator new(std::size_t n) {
    if (fail_next) { fail_next=false; injected=true; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
extern "C" int __real_socket(int,int,int);
extern "C" int __wrap_socket(int domain,int type,int protocol) {
    auto fd=__real_socket(domain,type,protocol);
    if (armed && fd>=0) { armed=false; captured=fd; fail_next=true; }
    return fd;
}
int main() {
    int listener=::socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (listener<0 || ::bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || ::listen(listener,2)) return 1;
    socklen_t length=sizeof(address); if (::getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)) return 2;
    p::MemoryLink link;
    auto table=t::ConnectionTable::create(2,64);
    t::MemoryDirect4 stack(link,*table,r::Matcher{},2);
    p::Tcp4View client{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
        .destination_port=ntohs(address.sin_port),.sequence=99,.flags=2,.window=64};
    auto send=[&](p::Tcp4View const& packet) {
        auto bytes=p::make_tcp4(packet); return bytes && link.send(p::Side::first,*bytes).has_value();
    };
    if (!send(client)) return 3;
    auto syn=stack.step(0,50);
    if (!syn || !syn->input.opened || !syn->input.id) return 4;
    auto reply=link.receive(p::Side::first); if (!reply || !*reply) return 5;
    client.flags=0x10; client.sequence=100; client.acknowledgement=51;
    if (!send(client)) return 6;
    armed=true; bool caught=false;
    try { (void)stack.step(1,50); } catch (std::bad_alloc const&) { caught=true; }
    if (!caught || !injected || captured<0 || table->size()!=0) return 7;
    errno=0; if (::fcntl(captured,F_GETFD)!=-1 || errno!=EBADF) return 8;
    client.source_port++; client.flags=2; client.sequence=199; client.acknowledgement=0;
    if (!send(client)) return 9;
    auto replacement=stack.step(2,70);
    if (!replacement || !replacement->input.opened || table->size()!=1) return 10;
    stack.stop(); ::close(listener);
    if (table->size()) return 11;
    std::println("TCP stack releases flow and socket on direct start allocation failure");
}
