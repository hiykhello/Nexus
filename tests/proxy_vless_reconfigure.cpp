#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
import std;
import relay;
using namespace std::chrono_literals;
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    std::array<std::string,1> users{argv[3]};
    for (unsigned workers : {1u,2u}) {
    relay::Server server;
    if (!server.prepare_vless_inbound(argv[1],argv[2],users)) return 2;
    auto port=server.start(0,relay::Inbound::vless,workers); if (!port) return 3;
    int fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return 4;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(*port);
    if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return 5; }
    for (int i=0;i<10;++i) server.poll(10ms);
    auto denied=server.prepare_vless_inbound(argv[1],argv[2],users);
    if (denied || denied.error()!="server is running") { close(fd); return 6; }
    server.stop();
    char byte; auto n=recv(fd,&byte,1,0); close(fd);
    if (n!=0 && !(n<0 && (errno==ECONNRESET || errno==ENOTCONN))) return 7;
    if (!server.prepare_vless_inbound(argv[1],argv[2],users)) return 8;
    auto again=server.start(0,relay::Inbound::vless,workers); if (!again) return 9;
    server.stop();
    }
    std::println("VLESS profile replacement waits for session shutdown");
}
