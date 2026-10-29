#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>

extern "C" int nexus_test_dns_lifetime(unsigned, unsigned, std::uint16_t);
static bool inject;
extern "C" void nexus_test_dns_registered() { if (inject) throw 1; }

int main() {
    int socket_fd=socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK,0);
    if (socket_fd<0) return 1;
    sockaddr_in address{};
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(socket_fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 2;
    socklen_t size=sizeof(address);
    if (getsockname(socket_fd,reinterpret_cast<sockaddr*>(&address),&size)) return 3;
    for (unsigned backend=0; backend<2; ++backend) {
        bool supported=true;
        for (unsigned mode=0; mode<3; ++mode) {
            inject=mode==2;
            int result=nexus_test_dns_lifetime(backend,mode,ntohs(address.sin_port));
            if (result==77) { supported=false; break; }
            if (result) { std::fprintf(stderr,"backend %u mode %u: %d\n",backend,mode,result); return 4; }
            if (mode!=2) {
                char packet[512];
                if (recv(socket_fd,packet,sizeof(packet),0)<=0) return 5;
            }
        }
        std::printf("%s: %s\n",backend ? "io_uring" : "epoll",supported ? "passed" : "unavailable");
    }
    close(socket_fd);
    std::puts("DNS query cancellation, exception and context abandonment release registration");
}
