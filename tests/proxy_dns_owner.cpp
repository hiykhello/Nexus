#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
bool skip_stop=false, owner_destroyed=false, registration_destroyed=false, owner_alive_on_unregister=false;
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
extern "C" void nexus_test_dns_owner_destroy() { owner_destroyed=true; }
extern "C" void nexus_test_dns_registration_destroy() { registration_destroyed=true; owner_alive_on_unregister=!owner_destroyed; }
auto read_exact(nexus::proxy::Server& server,int fd,std::span<unsigned char> output) -> bool {
    auto deadline=std::chrono::steady_clock::now()+3s;
    while (!output.empty() && std::chrono::steady_clock::now()<deadline) {
        server.poll(10ms);
        auto n=recv(fd,output.data(),output.size(),MSG_DONTWAIT);
        if (n>0) output=output.subspan(static_cast<std::size_t>(n));
        else if (n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) return false;
    }
    return output.empty();
}
int main() {
    int dns=socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK,0); if (dns<0) return 1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(dns,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 2;
    socklen_t size=sizeof(address); if (getsockname(dns,reinterpret_cast<sockaddr*>(&address),&size)) return 3;
    int client=-1;
    {
        nexus::proxy::Server server;
        if (!server.set_dns_upstream(std::array<std::uint8_t,4>{127,0,0,1},ntohs(address.sin_port))) return 4;
        auto port=server.start(0); if (!port) return 5;
        client=socket(AF_INET,SOCK_STREAM,0); if (client<0) return 6;
        address.sin_port=htons(*port);
        if (connect(client,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 7;
        std::array<unsigned char,3> greeting{5,1,0}; std::array<unsigned char,2> method{};
        if (send(client,greeting.data(),greeting.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(greeting.size()) || !read_exact(server,client,method) || method!=std::array<unsigned char,2>{5,0}) return 8;
        std::array<unsigned char,13> request{5,1,0,3,6,'a','.','t','e','s','t',0x04,0xd2};
        if (send(client,request.data(),request.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(request.size())) return 9;
        std::array<char,512> wire{}; ssize_t received=-1;
        for (int i=0;i<300 && received<0;++i) { server.poll(10ms); received=recv(dns,wire.data(),wire.size(),0); }
        if (received<=0 || registration_destroyed || owner_destroyed) return 10;
        skip_stop=true;
    }
    close(client); close(dns);
    if (!registration_destroyed || !owner_alive_on_unregister || !owner_destroyed) return 11;
    std::println("Pending DNS query unregisters before worker DNS owner is destroyed");
}
