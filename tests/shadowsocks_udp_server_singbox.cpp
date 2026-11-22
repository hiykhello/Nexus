#include <arpa/inet.h>
#include <sys/socket.h>
import std;
import shadowsocks.udp_dispatch;
import rules;
namespace s=shadowsocks;
using namespace std::chrono_literals;
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    int fd=std::atoi(argv[1]), size=std::atoi(argv[2]), target_port=std::atoi(argv[3]);
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),0);
    auto policy=::rules::Matcher::compile({});
    if (!policy) return 9;
    s::UdpDispatcher server(std::move(*policy),2,2,4,262144);
    for (int i=0;i<2;++i) {
        std::array<std::uint8_t,65535> buf{}; sockaddr_in source{}; socklen_t len=sizeof(source);
        auto n=recvfrom(fd,buf.data(),buf.size(),0,reinterpret_cast<sockaddr*>(&source),&len);
        if (n<=0 || source.sin_family!=AF_INET) return 2;
        s::UdpPeer peer{4,{},ntohs(source.sin_port)}; std::memcpy(peer.address.data(),&source.sin_addr,4);
        auto clock=[] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()); };
        auto now=std::chrono::steady_clock::now();
        auto packet=server.begin(std::span{key}.first(size),std::span{buf}.first(n),peer,now,clock(),now+5s);
        if (!packet) return 3;
        auto const& address=packet->address;
        std::vector<std::uint8_t> expected{1,127,0,0,1,static_cast<std::uint8_t>(target_port>>8),static_cast<std::uint8_t>(target_port)};
        // Test fixture authorizes only the explicitly supplied loopback target.
        if (address!=expected) return 4;
        s::UdpPeer target{4,{127,0,0,1},static_cast<std::uint16_t>(target_port)};
        std::array candidates{target};
        if (!server.complete(packet->token,candidates,std::chrono::steady_clock::now())) return 5;
        std::optional<s::UdpResponse> response; auto deadline=std::chrono::steady_clock::now()+5s;
        while (!response && std::chrono::steady_clock::now()<deadline) {
            auto result=server.poll(std::span{key}.first(size),std::chrono::steady_clock::now(),clock());
            if (!result) return 6;
            response=std::move(*result); if (!response) std::this_thread::sleep_for(1ms);
        }
        if (!response || response->peer!=peer) return 7;
        if (sendto(fd,response->wire.data(),response->wire.size(),0,reinterpret_cast<sockaddr*>(&source),len)!=static_cast<ssize_t>(response->wire.size())) return 8;
    }
}
