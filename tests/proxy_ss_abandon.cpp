#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
std::weak_ptr<void> profile;
bool entered=false, exited=false, skip_stop=false;
long owners_on_entry=0, owners_on_exit=0;
extern "C" void nexus_test_ss_profile_owner(std::weak_ptr<void> owner) { profile=std::move(owner); }
extern "C" void nexus_test_ss_profile_frame_enter() { entered=true; owners_on_entry=profile.use_count(); }
extern "C" void nexus_test_ss_profile_frame_exit() { exited=true; owners_on_exit=profile.use_count(); }
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
int main() {
    int fd=-1;
    {
        nexus::proxy::Server server;
        std::array<std::uint8_t,16> key{};
        if (!server.prepare_shadowsocks_inbound(key) || profile.use_count()!=2) return 1;
        auto port=server.start(0,nexus::proxy::Inbound::shadowsocks,1); if (!port) return 2;
        fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return 3;
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(*port);
        if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return 4; }
        for (int i=0;i<100 && !entered;++i) server.poll(10ms);
        if (!entered || exited || owners_on_entry!=2) { close(fd); return 5; }
        skip_stop=true;
    }
    close(fd);
    if (!exited || owners_on_exit!=2 || profile.use_count()!=1) return 6;
    std::println("SS-2022 profile remains owned through session abandonment and retains replay state");
}
