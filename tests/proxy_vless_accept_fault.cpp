#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory_resource>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
unsigned launches=0, entered=0;
extern "C" void nexus_test_root_launch(unsigned stage) {
    if (stage==0 && ++launches==2) throw std::bad_alloc();
}
extern "C" std::pmr::memory_resource* nexus_test_root_resource() { return std::pmr::get_default_resource(); }
extern "C" void nexus_test_vless_profile_enter() { ++entered; }
auto connect_to(std::uint16_t port) -> int {
    int fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return -1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
    if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return -1; }
    return fd;
}
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    std::array<std::string,1> users{argv[3]};
    nexus::proxy::Server server;
    if (!server.prepare_vless_inbound(argv[1],argv[2],users)) return 2;
    auto port=server.start(0,nexus::proxy::Inbound::vless,1); if (!port) return 3;
    auto first=connect_to(*port); if (first<0) return 4;
    for (int i=0;i<100 && !entered;++i) server.poll(10ms);
    if (entered!=1 || launches!=1) { close(first); return 5; }
    auto second=connect_to(*port); if (second<0) { close(first); return 6; }
    for (int i=0;i<100 && server.healthy();++i) server.poll(10ms);
    auto failure=server.failure();
    if (server.healthy() || !failure || failure->kind!=nexus::proxy::FailureKind::accept_task || launches!=2) { close(first); close(second); return 7; }
    auto denied=server.prepare_vless_inbound(argv[1],argv[2],users);
    if (denied || denied.error()!="server is running") { close(first); close(second); return 8; }
    server.stop(); close(first); close(second);
    if (!server.prepare_vless_inbound(argv[1],argv[2],users)) return 9;
    auto again=server.start(0,nexus::proxy::Inbound::vless,1); if (!again) return 10;
    server.stop();
    std::println("VLESS pending session blocks profile replacement after accept task failure");
}
