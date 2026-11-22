#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import proxy;
using namespace std::chrono_literals;
bool profile_alive=false;
bool entered=false, exited=false, alive_on_exit=false, skip_stop=false;
extern "C" void nexus_test_vless_profile_created() { profile_alive=true; }
extern "C" void nexus_test_vless_profile_destroyed() { profile_alive=false; }
extern "C" void nexus_test_vless_profile_frame_enter() { entered=true; }
extern "C" void nexus_test_vless_profile_frame_exit() { exited=true; alive_on_exit=profile_alive; }
extern "C" void nexus_test_vless_relay_frame_enter() {}
extern "C" void nexus_test_vless_relay_frame_exit() {}
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    std::array<std::string,1> users{argv[3]};
    int fd=-1;
    {
        proxy::Server server;
        if (!server.prepare_vless_inbound(argv[1],argv[2],users) || !profile_alive) return 2;
        auto port=server.start(0,proxy::Inbound::vless,1); if (!port) return 3;
        fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return 4;
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(*port);
        if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return 5; }
        for (int i=0;i<100 && !entered;++i) server.poll(10ms);
        if (!entered || exited || !profile_alive) { close(fd); return 6; }
        skip_stop=true;
    }
    close(fd);
    if (!exited || !alive_on_exit || profile_alive) return 7;
    std::println("VLESS profile outlives suspended session frame on context abandonment");
}
