#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.shadowsocks.udp_relay;
namespace s=nexus::shadowsocks;
static bool inject=false;
extern "C" auto __real_recvfrom(int,void*,size_t,int,sockaddr*,socklen_t*) -> ssize_t;
extern "C" auto __wrap_recvfrom(int fd,void* buf,size_t size,int flags,sockaddr* addr,socklen_t* len) -> ssize_t {
    if (inject) { inject=false; errno=EIO; return -1; }
    return __real_recvfrom(fd,buf,size,flags,addr,len);
}
int main() {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (fd<0 || ::bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 1;
    socklen_t len=sizeof(addr); if (::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len)) return 2;
    timeval timeout{2,0}; ::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    s::UdpPeer target{4,{127,0,0,1},ntohs(addr.sin_port)}; s::UdpRelay relay(2,2);
    std::array<std::uint8_t,8> one{1},two{2}; std::array<std::uint8_t,1> payload{42};
    if (!relay.send(one,target,payload) || !relay.send(two,target,payload)) return 3;
    std::array<std::uint8_t,16> buffer{}; sockaddr_in source{};
    for (int i=0;i<2;++i) {
        len=sizeof(source); auto n=::recvfrom(fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&source),&len);
        if (n!=1 || ::sendto(fd,buffer.data(),n,0,reinterpret_cast<sockaddr*>(&source),len)!=n) return 4;
    }
    inject=true; auto error=relay.poll();
    if (error || error.error().kind!=s::UdpRelayError::system || error.error().system.value()!=EIO || relay.size()!=1) return 5;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2); std::optional<s::UdpRelayReply> reply;
    while (!reply && std::chrono::steady_clock::now()<deadline) {
        auto result=relay.poll(); if (!result) return 6; reply=std::move(*result);
        if (!reply) std::this_thread::yield();
    }
    if (!reply || reply->session!=two || reply->payload!=std::vector<std::uint8_t>{42}) return 7;
    if (!relay.send(one,target,payload) || relay.size()!=2) return 8;
    ::close(fd); std::println("SS-2022 UDP relay isolates receive errors");
}
