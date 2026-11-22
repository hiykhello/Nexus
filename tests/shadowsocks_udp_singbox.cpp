#include <sys/socket.h>
#include <unistd.h>
import std;
import shadowsocks.udp_client;
namespace s=shadowsocks;
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    int fd=std::atoi(argv[1]), size=std::atoi(argv[2]), port=std::atoi(argv[3]);
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),0);
    auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::vector<std::uint8_t> address{1,127,0,0,1,static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
    std::vector<std::uint8_t> payload{'h','e','l','l','o'};
    s::UdpClientPool owner(std::span{key}.first(size),1,4,4);
    auto session=owner.open();
    if (!session) return 6;
    auto wire=owner.request(*session,address,payload,{},std::chrono::steady_clock::now(),now);
    if (!wire || send(fd,wire->data(),wire->size(),0)!=static_cast<ssize_t>(wire->size())) return 2;
    std::array<std::uint8_t,65535> buf{}; auto n=recv(fd,buf.data(),buf.size(),0);
    if (n<=0) return 3;
    now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto decoded=owner.receive(*session,std::span{buf}.first(n),std::chrono::steady_clock::now(),now);
    if (!decoded || decoded->address!=address || decoded->payload!=std::vector<std::uint8_t>({'w','o','r','l','d'})) return 4;
    auto replay=owner.receive(*session,std::span{buf}.first(n),std::chrono::steady_clock::now(),now);
    if (replay || replay.error()!=s::UdpClientError::duplicate) return 5;
}
