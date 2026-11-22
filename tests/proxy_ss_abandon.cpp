#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import proxy;
using namespace std::chrono_literals;
bool profile_alive=false;
bool entered=false, exited=false, skip_stop=false;
long owners_on_entry=0, owners_on_exit=0;
extern "C" void nexus_test_ss_profile_created() { profile_alive=true; }
extern "C" void nexus_test_ss_profile_released() { profile_alive=false; }
extern "C" void nexus_test_ss_profile_frame_enter() { entered=true; owners_on_entry=static_cast<int>(profile_alive); }
extern "C" void nexus_test_ss_profile_frame_exit() { exited=true; owners_on_exit=static_cast<int>(profile_alive); }
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
extern "C" void nexus_test_tunnel_profile_created() {}
extern "C" void nexus_test_tunnel_profile_released() {}
extern "C" void nexus_test_tunnel_profile_destroy() {}
int main() {
    int fd=-1;
    {
        proxy::Server server;
        std::array<std::uint8_t,16> key{};
        if (!server.prepare_shadowsocks_inbound(key) || static_cast<int>(profile_alive)!=1) return 1;
        auto port=server.start(0,proxy::Inbound::shadowsocks,1); if (!port) return 2;
        fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return 3;
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(*port);
        if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return 4; }
        for (int i=0;i<100 && !entered;++i) server.poll(10ms);
        if (!entered || exited || owners_on_entry!=1) { close(fd); return 5; }
        skip_stop=true;
    }
    close(fd);
    if (!exited || owners_on_exit!=1 || static_cast<int>(profile_alive)!=1) return 6;
    std::println("SS-2022 profile remains owned through session abandonment and retains replay state");
}
