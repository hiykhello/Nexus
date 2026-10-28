#include <arpa/inet.h>
#include <sys/socket.h>
import std;
import nexus.shadowsocks.udp_sessions;
namespace s=nexus::shadowsocks;
int main(int argc,char** argv) {
    if (argc!=3) return 1;
    int fd=std::atoi(argv[1]), size=std::atoi(argv[2]);
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),0);
    s::UdpServerSessions sessions(2);
    for (int i=0;i<2;++i) {
        std::array<std::uint8_t,65535> buffer{}; sockaddr_in source{}; socklen_t source_size=sizeof(source);
        auto n=recvfrom(fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&source),&source_size);
        if (n<=0 || source.sin_family!=AF_INET) return 2;
        s::UdpPeer peer{4,{},ntohs(source.sin_port)};
        std::memcpy(peer.address.data(),&source.sin_addr,4);
        auto wall=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto now=std::chrono::steady_clock::now();
        auto packet=sessions.receive(std::span{key}.first(size),std::span{buffer}.first(n),peer,now,wall);
        std::vector<std::uint8_t> expected{'h','e','l','l','o',static_cast<std::uint8_t>('0'+i)};
        if (!packet || packet->packet.payload!=expected || packet->new_session!=(i==0)) return 3;
        std::vector<std::uint8_t> payload{'w','o','r','l','d',static_cast<std::uint8_t>('0'+i)};
        auto response=sessions.response(std::span{key}.first(size),packet->packet.session_id,packet->packet.address,payload,{},now,wall);
        if (!response || response->peer!=peer) return 4;
        if (sendto(fd,response->wire.data(),response->wire.size(),0,reinterpret_cast<sockaddr*>(&source),source_size)!=static_cast<ssize_t>(response->wire.size())) return 5;
    }
}
