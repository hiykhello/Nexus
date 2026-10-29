#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
bool skip_stop=false, owner_destroyed=false, all_unregistered_before_owner=true;
unsigned registrations_destroyed=0;
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
extern "C" void nexus_test_handshake_borrowed_state(bool) {}
extern "C" void nexus_test_dns_owner_destroy() { owner_destroyed=true; }
extern "C" void nexus_test_dns_registration_destroy() { ++registrations_destroyed; all_unregistered_before_owner &= !owner_destroyed; }
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
int main(int argc,char** argv) {
    if (argc!=2 || (std::string_view(argv[1])!="udp" && std::string_view(argv[1])!="tcp")) return 1;
    bool tcp=std::string_view(argv[1])=="tcp";
    int dns=socket(AF_INET,(tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK,0); if (dns<0) return 2;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(dns,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || (tcp && listen(dns,4))) return 3;
    socklen_t size=sizeof(address); if (getsockname(dns,reinterpret_cast<sockaddr*>(&address),&size)) return 4;
    std::array<int,2> clients{-1,-1}, peers{-1,-1};
    {
        nexus::proxy::Server server;
        nexus::proxy::DnsServer upstream; upstream.address[0]=127; upstream.address[3]=1; upstream.port=ntohs(address.sin_port); upstream.tcp=tcp;
        nexus::proxy::DnsRouting routing; routing.servers.push_back(upstream); routing.strategy=nexus::proxy::DnsStrategy::ipv4_only;
        if (!server.set_dns_routing(std::move(routing))) return 5;
        auto port=server.start(0); if (!port) return 6;
        address.sin_port=htons(*port);
        for (unsigned i=0;i<clients.size();++i) {
            clients[i]=socket(AF_INET,SOCK_STREAM,0); if (clients[i]<0) return 7;
            if (connect(clients[i],reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 8;
            std::array<unsigned char,3> greeting{5,1,0}; std::array<unsigned char,2> method{};
            if (send(clients[i],greeting.data(),greeting.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(greeting.size()) || !read_exact(server,clients[i],method) || method!=std::array<unsigned char,2>{5,0}) return 9;
            std::array<unsigned char,13> request{5,1,0,3,6,static_cast<unsigned char>('a'+i),'.','t','e','s','t',0x04,0xd2};
            if (send(clients[i],request.data(),request.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(request.size())) return 10;
            if (tcp) {
                for (int j=0;j<300 && peers[i]<0;++j) { server.poll(10ms); peers[i]=accept4(dns,nullptr,nullptr,SOCK_NONBLOCK); }
                if (peers[i]<0) return 11;
            }
            std::array<unsigned char,512> wire{}; ssize_t received=-1;
            for (int j=0;j<300 && received<0;++j) { server.poll(10ms); received=recv(tcp ? peers[i] : dns,wire.data(),wire.size(),0); }
            if (received<static_cast<ssize_t>(tcp ? 3 : 1) || (tcp && ((wire[0]<<8)|wire[1])<12) || registrations_destroyed || owner_destroyed) return 12;
        }
        skip_stop=true;
    }
    for (int fd:clients) close(fd);
    for (int fd:peers) if (fd>=0) close(fd);
    close(dns);
    if (registrations_destroyed!=2 || !all_unregistered_before_owner || !owner_destroyed) return 13;
    std::println("Two pending {} DNS queries unregister before their worker owner is destroyed",tcp ? "TCP" : "UDP");
}
