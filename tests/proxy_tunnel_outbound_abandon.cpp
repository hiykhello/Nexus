#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
std::weak_ptr<void const> profile;
bool destroyed=false, alive_on_destroy=false, skip_stop=false;
extern "C" void nexus_test_tunnel_profile_owner(std::weak_ptr<void const> owner) { profile=std::move(owner); }
extern "C" void nexus_test_tunnel_profile_destroy() { destroyed=true; alive_on_destroy=profile.use_count()==1; }
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
extern "C" void nexus_test_ss_profile_owner(std::weak_ptr<void>) {}
extern "C" void nexus_test_ss_profile_frame_enter() {}
extern "C" void nexus_test_ss_profile_frame_exit() {}
auto connect_to(std::uint16_t port) -> int {
    int fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return -1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
    if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return -1; }
    return fd;
}
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
    if (argc!=1 && argc!=4) return 12;
    bool vless=argc==4;
    int listener=socket(AF_INET,SOCK_STREAM | SOCK_NONBLOCK,0); if (listener<0) return 1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || listen(listener,4)) return 2;
    socklen_t size=sizeof(address); if (getsockname(listener,reinterpret_cast<sockaddr*>(&address),&size)) return 3;
    int client=-1,upstream=-1;
    {
        nexus::proxy::Server server;
        std::array<std::uint8_t,16> key{};
        auto index=vless ? server.add_vless("127.0.0.1",ntohs(address.sin_port),argv[3],"localhost",argv[1]) :
            server.add_shadowsocks("127.0.0.1",ntohs(address.sin_port),key);
        if (!index || !server.set_indexed_routes({},*index)) return 4;
        auto port=server.start(0,nexus::proxy::Inbound::socks5,1); if (!port) return 5;
        client=connect_to(*port); if (client<0) return 6;
        std::array<unsigned char,3> greeting{5,1,0}; std::array<unsigned char,2> method{};
        if (send(client,greeting.data(),greeting.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(greeting.size()) || !read_exact(server,client,method) || method!=std::array<unsigned char,2>{5,0}) return 7;
        std::array<unsigned char,10> request{5,1,0,1,127,0,0,1,0x04,0xd2}, reply{};
        if (send(client,request.data(),request.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(request.size())) return 8;
        if (!vless && (!read_exact(server,client,reply) || reply[1]!=0)) return 8;
        for (int i=0;i<300 && upstream<0;++i) { server.poll(10ms); upstream=accept4(listener,nullptr,nullptr,SOCK_NONBLOCK); }
        if (upstream<0) return 9;
        std::array<unsigned char,512> wire{};
        ssize_t received=-1;
        for (int i=0;i<300 && received<0;++i) { server.poll(10ms); received=recv(upstream,wire.data(),wire.size(),0); }
        if (received<=0 || (vless && wire[0]!=0x16) || destroyed || profile.expired()) return 10;
        for (int i=0;i<5;++i) server.poll(10ms);
        skip_stop=true;
    }
    close(client); close(upstream); close(listener);
    if (!destroyed || !alive_on_destroy || !profile.expired()) return 11;
    std::println("{} active outbound releases tunnel before its borrowed profile on context abandonment",vless ? "VLESS" : "SS-2022");
}
