#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import socks5.udp_direct;
import platform.socket_options;
namespace s=socks5;
static_assert(std::same_as<decltype(&::setsockopt),::platform::linux_socket_abi::SetOptionSignature>);
static_assert(SOL_SOCKET==::platform::linux_socket_abi::socket_level);
static_assert(IPPROTO_TCP==::platform::linux_socket_abi::tcp_level);
static_assert(SO_KEEPALIVE==::platform::linux_socket_abi::keepalive);

auto run(int family) -> bool {
    int fd=::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0);
    if (fd<0) return false;
    struct Guard { int fd; ~Guard(){::close(fd);} } guard{fd};
    timeval timeout{2,0};
    if (::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) return false;
    sockaddr_storage addr{}; socklen_t length;
    if (family==AF_INET) {
        auto& a=*reinterpret_cast<sockaddr_in*>(&addr); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(a);
    } else {
        auto& a=*reinterpret_cast<sockaddr_in6*>(&addr); a.sin6_family=AF_INET6; a.sin6_addr=in6addr_loopback; length=sizeof(a);
    }
    if (::bind(fd,reinterpret_cast<sockaddr*>(&addr),length) || ::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&length)) return false;
    s::UdpPeer target{};
    if (family==AF_INET) {
        auto& a=*reinterpret_cast<sockaddr_in*>(&addr); target={1,{127,0,0,1},ntohs(a.sin_port)};
    } else {
        auto& a=*reinterpret_cast<sockaddr_in6*>(&addr); target.address_type=4; target.address[15]=1; target.port=ntohs(a.sin6_port);
    }
    s::UdpSocket socket;
    std::array<std::uint8_t,3> payload{1,2,3}, incoming{};
    auto empty=socket.peek(incoming); if (!empty || *empty || !socket.send(target,payload)) return false;
    sockaddr_storage peer{}; socklen_t peer_len=sizeof(peer);
    auto n=::recvfrom(fd,incoming.data(),incoming.size(),0,reinterpret_cast<sockaddr*>(&peer),&peer_len);
    if (n!=3 || incoming!=payload || ::sendto(fd,payload.data(),payload.size(),0,reinterpret_cast<sockaddr*>(&peer),peer_len)!=3) return false;
    std::optional<s::UdpSocketPacket> packet;
    for (int i=0;i<200 && !packet;++i) {
        auto peeked=socket.peek(std::span(incoming).first(1)); if (!peeked) return false;
        packet=*peeked; if (!packet) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!packet || packet->valid || packet->size!=3) return false;
    auto full=socket.peek(incoming);
    if (!full || !*full || !(**full).valid || (**full).source!=target || incoming!=payload) return false;
    auto consumed=socket.consume(); if (!consumed || !*consumed || **consumed!=3) return false;
    empty=socket.peek(incoming); if (!empty || *empty) return false;
    if (::sendto(fd,nullptr,0,0,reinterpret_cast<sockaddr*>(&peer),peer_len)!=0) return false;
    packet.reset();
    for (int i=0;i<200 && !packet;++i) {
        auto peeked=socket.peek(incoming); if (!peeked) return false;
        packet=*peeked; if (!packet) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!packet || !packet->valid || packet->size!=0 || packet->source!=target) return false;
    consumed=socket.consume(); if (!consumed || !*consumed || **consumed!=0) return false;
    socket.close();
    return !socket.send(target,payload) && !socket.peek(incoming) && !socket.consume();
}
int main() { return run(AF_INET) && run(AF_INET6) ? 0 : 1; }
