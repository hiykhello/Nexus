#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import shadowsocks.udp_relay;
namespace s=shadowsocks;
static bool inject_receive=false,inject_send=false,inject_socket=false,inject_option=false,watch_receive=false;
static unsigned receive_calls=0;
extern "C" auto __real_socket(int,int,int) -> int;
extern "C" auto __wrap_socket(int domain,int type,int protocol) -> int {
    if (inject_socket) { inject_socket=false; errno=EIO; return -1; }
    return __real_socket(domain,type,protocol);
}
extern "C" auto __real_setsockopt(int,int,int,void const*,socklen_t) -> int;
extern "C" auto __wrap_setsockopt(int fd,int level,int option,void const* value,socklen_t length) -> int {
    if (inject_option) { inject_option=false; errno=EIO; return -1; }
    return __real_setsockopt(fd,level,option,value,length);
}
extern "C" auto __real_sendto(int,void const*,size_t,int,sockaddr const*,socklen_t) -> ssize_t;
extern "C" auto __wrap_sendto(int fd,void const* buf,size_t size,int flags,sockaddr const* addr,socklen_t len) -> ssize_t {
    if (inject_send) { inject_send=false; errno=EIO; return -1; }
    return __real_sendto(fd,buf,size,flags,addr,len);
}
extern "C" auto __real_recvfrom(int,void*,size_t,int,sockaddr*,socklen_t*) -> ssize_t;
extern "C" auto __wrap_recvfrom(int fd,void* buf,size_t size,int flags,sockaddr* addr,socklen_t* len) -> ssize_t {
    if (watch_receive) { ++receive_calls; if (flags!=MSG_TRUNC) { errno=EPROTO; return -1; } }
    if (inject_receive) { inject_receive=false; errno=EIO; return -1; }
    return __real_recvfrom(fd,buf,size,flags,addr,len);
}
int main() {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0),fd2=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (fd<0 || fd2<0 || ::bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) ||
        ::bind(fd2,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 1;
    socklen_t len=sizeof(addr); if (::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len)) return 2;
    timeval timeout{2,0}; ::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    s::UdpPeer target{4,{127,0,0,1},ntohs(addr.sin_port)}; s::UdpRelay relay(3,2);
    std::array<std::uint8_t,8> one{1},two{2}; std::array<std::uint8_t,1> payload{42};
    if (!relay.send(one,target,payload) || !relay.send(two,target,payload)) return 3;
    auto descriptor_count=[] { return std::distance(std::filesystem::directory_iterator("/proc/self/fd"),std::filesystem::directory_iterator{}); };
    auto descriptors=descriptor_count();
    std::array<std::uint8_t,8> three{3};
    auto fresh_failure=[&](bool& injected) {
        injected=true; auto result=relay.send(three,target,payload);
        return !result && result.error().kind==s::UdpRelayError::system && result.error().system.value()==EIO &&
               relay.size()==2 && descriptor_count()==descriptors;
    };
    if (!fresh_failure(inject_socket) || !fresh_failure(inject_option) || !fresh_failure(inject_send)) return 9;
    auto rejected=target; rejected.address[3]=2;
    inject_send=true; auto failure=relay.send(one,rejected,payload);
    if (failure || failure.error().kind!=s::UdpRelayError::system || failure.error().system.value()!=EIO) return 10;
    sockaddr_in addr2{}; len=sizeof(addr2); if (::getsockname(fd2,reinterpret_cast<sockaddr*>(&addr2),&len)) return 11;
    auto other=target; other.port=ntohs(addr2.sin_port);
    if (!relay.send(one,other,payload)) return 12;
    auto limited=relay.send(one,rejected,payload);
    if (limited || limited.error().kind!=s::UdpRelayError::target_limit) return 12;
    std::array<std::uint8_t,16> buffer{}; sockaddr_in source{};
    for (int i=0;i<2;++i) {
        len=sizeof(source); auto n=::recvfrom(fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&source),&len);
        if (n!=1 || ::sendto(fd,buffer.data(),n,0,reinterpret_cast<sockaddr*>(&source),len)!=n) return 4;
    }
    watch_receive=true; inject_receive=true; auto error=relay.poll();
    if (error || error.error().kind!=s::UdpRelayError::system || error.error().system.value()!=EIO || relay.size()!=1 || receive_calls!=1) return 5;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2); std::optional<s::UdpRelayReply> reply;
    while (!reply && std::chrono::steady_clock::now()<deadline) {
        auto before=receive_calls; auto result=relay.poll(); if (!result || receive_calls!=before+1) return 6; reply=std::move(*result);
        if (!reply) std::this_thread::yield();
    }
    watch_receive=false;
    if (!reply || reply->session!=two || reply->payload!=std::vector<std::uint8_t>{42}) return 7;
    if (!relay.send(one,target,payload) || !relay.send(three,target,payload) || relay.size()!=3) return 8;
    ::close(fd); ::close(fd2); std::println("SS-2022 UDP relay rolls back socket and send failures and isolates receive errors");
}
