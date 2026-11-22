#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import shadowsocks.udp_server;
import shadowsocks.udp_packet;
namespace s=shadowsocks;
using namespace std::chrono_literals;
int main() {
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (fd<0 || bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 1;
    socklen_t len=sizeof(addr); if (getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len)) return 2;
    timeval timeout{2,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    std::array<std::uint8_t,16> key{};
    s::UdpPeer source{4,{127,0,0,1},1234}, new_source{4,{127,0,0,1},1235};
    s::UdpPeer target{4,{127,0,0,1},ntohs(addr.sin_port)};
    s::UdpPacket packet{{1,2,3,4,5,6,7,8},0,1000,{}, {1,127,0,0,1,static_cast<std::uint8_t>(target.port>>8),static_cast<std::uint8_t>(target.port)}, {1,2,3}};
    auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    auto t=std::chrono::steady_clock::time_point{};
    s::UdpServer server(1,2);
    auto accepted=server.receive(key,wire,source,t,1000);
    if (!accepted || !server.forward(*accepted,target)) return 3;
    std::array<std::uint8_t,32> buffer{}; sockaddr_in sender{}; len=sizeof(sender);
    if (recvfrom(fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&sender),&len)!=3) return 4;
    packet.packet_id=1; packet.timestamp=1001; auto next=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    if (!server.receive(key,next,new_source,t+1s,1001)) return 5;
    if (sendto(fd,buffer.data(),3,0,reinterpret_cast<sockaddr*>(&sender),len)!=3) return 6;
    std::optional<s::UdpResponse> response; auto deadline=std::chrono::steady_clock::now()+2s;
    while (!response && std::chrono::steady_clock::now()<deadline) {
        auto result=server.poll(key,t+2s,1002); if (!result) return 7;
        response=std::move(*result); if (!response) std::this_thread::sleep_for(1ms);
    }
    if (!response || response->peer!=new_source) return 8;
    auto decoded=s::decode_udp_packet(key,s::UdpDirection::server,response->wire,1002,packet.session_id);
    if (!decoded || decoded->address!=packet.address || decoded->payload!=packet.payload) return 9;
    // An oversized upstream datagram must not fail the server; the largest
    // encapsulated datagram for each client family remains deliverable.
    auto check_size=[&](s::UdpPeer peer,std::size_t maximum) {
        ++packet.packet_id; packet.timestamp=1002;
        auto request=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
        if (!server.receive(key,request,peer,t+2s,1002)) return false;
        std::vector<std::uint8_t> large(maximum+1,0x5a);
        if (sendto(fd,large.data(),large.size(),0,reinterpret_cast<sockaddr*>(&sender),len)!=static_cast<ssize_t>(large.size())) return false;
        auto dropped=server.poll(key,t+2s,1002);
        if (!dropped || *dropped || server.sockets()!=1) return false;
        large.pop_back();
        if (sendto(fd,large.data(),large.size(),0,reinterpret_cast<sockaddr*>(&sender),len)!=static_cast<ssize_t>(large.size())) return false;
        auto delivered=server.poll(key,t+2s,1002);
        if (!delivered || !*delivered || (**delivered).peer!=peer) return false;
        auto unpacked=s::decode_udp_packet(key,s::UdpDirection::server,(**delivered).wire,1002,packet.session_id);
        return unpacked && unpacked->payload==large;
    };
    s::UdpPeer v6_source{6,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},1236};
    if (!check_size(new_source,65449) || !check_size(v6_source,65469)) return 19;
    server.close_relays();
    if (server.sockets()!=0 || server.sessions()!=1 || server.receive(key,next,new_source,t+2s,1002).error()!=s::UdpSessionError::duplicate) return 17;
    ++packet.packet_id; packet.timestamp=1002;
    auto after_close=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    auto fresh=server.receive(key,after_close,new_source,t+2s,1002);
    if (!fresh || !server.forward(*fresh,target) || server.sockets()!=1 || recv(fd,buffer.data(),buffer.size(),0)!=3) return 18;
    auto expired=server.expire(t+63s,1063);
    if (!expired || *expired!=0 || server.sockets()!=1) return 10;
    expired=server.expire(t+64s,1064);
    if (!expired || *expired!=1 || server.sockets()!=0 || server.sessions()!=0) return 11;
    if (server.forward(*accepted,target)) return 12;
    packet.packet_id=0; packet.timestamp=1064;
    auto restarted=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    auto new_session=server.receive(key,restarted,new_source,t+64s,1064);
    if (!new_session || !new_session->new_session || new_session->generation==accepted->generation) return 13;
    if (server.forward(*accepted,target) || server.sockets()!=0) return 14;
    if (!server.forward(*new_session,target) || server.sockets()!=1) return 15;
    if (recv(fd,buffer.data(),buffer.size(),0)!=3) return 16;
    ::close(fd);
    std::println("SS-2022 UDP server relay and expiry passed");
}
