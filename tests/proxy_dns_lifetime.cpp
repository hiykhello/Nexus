#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>

extern "C" int nexus_test_dns_lifetime(unsigned, unsigned, std::uint16_t);
extern "C" int nexus_test_dns_independent_slots(unsigned, std::uint16_t);
extern "C" int nexus_test_dns_question_lifetime(unsigned,unsigned,std::uint16_t,std::uint16_t);
static bool inject;
static bool inject_received;
static int socket_fd;
static int first_fd;
static unsigned registrations,received;
static bool inject_second,inject_received_second;
extern "C" void nexus_test_dns_registered() { if (inject || (++registrations==2 && inject_second)) throw 1; }
extern "C" void nexus_test_dns_received() { if (inject_received || (++received==2 && inject_received_second)) throw 2; }
extern "C" bool nexus_test_dns_first_reply() {
    unsigned char packet[512];
    sockaddr_in source{}; socklen_t length=sizeof(source);
    auto size=recvfrom(first_fd,packet,sizeof(packet)-16,0,reinterpret_cast<sockaddr*>(&source),&length);
    if (size<17 || packet[size-4]!=0 || packet[size-3]!=1) return false;
    packet[2]=0x81; packet[3]=0x80; packet[7]=1;
    unsigned char answer[]{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,127,0,0,1};
    for (unsigned i=0;i<sizeof(answer);++i) packet[size+i]=answer[i];
    auto reply_size=size+static_cast<ssize_t>(sizeof(answer));
    return sendto(first_fd,packet,reply_size,0,reinterpret_cast<sockaddr*>(&source),length)==reply_size;
}
extern "C" bool nexus_test_dns_reply() {
    char packet[512];
    sockaddr_in source{};
    socklen_t length=sizeof(source);
    auto size=recvfrom(socket_fd,packet,sizeof(packet),0,reinterpret_cast<sockaddr*>(&source),&length);
    return size>0 && sendto(socket_fd,packet,size,0,reinterpret_cast<sockaddr*>(&source),length)==size;
}

int main() {
    socket_fd=socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK,0);
    if (socket_fd<0) return 1;
    sockaddr_in address{};
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(socket_fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 2;
    socklen_t size=sizeof(address);
    if (getsockname(socket_fd,reinterpret_cast<sockaddr*>(&address),&size)) return 3;
    first_fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0);
    auto first_address=address; first_address.sin_port=0;
    if (first_fd<0 || bind(first_fd,reinterpret_cast<sockaddr*>(&first_address),sizeof(first_address)) ||
        getsockname(first_fd,reinterpret_cast<sockaddr*>(&first_address),&size)) return 8;
    for (unsigned backend=0; backend<2; ++backend) {
        bool supported=true;
        for (unsigned mode=0; mode<4; ++mode) {
            inject=mode==2;
            inject_received=mode==3;
            int result=nexus_test_dns_lifetime(backend,mode,ntohs(address.sin_port));
            if (result==77) { supported=false; break; }
            if (result) { std::fprintf(stderr,"backend %u mode %u: %d\n",backend,mode,result); return 4; }
            if (mode<2) {
                char packet[512];
                if (recv(socket_fd,packet,sizeof(packet),0)<=0) return 5;
            }
        }
        if (supported) {
            inject=inject_received=false;
            int result=nexus_test_dns_independent_slots(backend,ntohs(address.sin_port));
            if (result) { std::fprintf(stderr,"backend %u independent slots: %d\n",backend,result); return 6; }
            char packet[512];
            for (unsigned i=0;i<2;++i) if (recv(socket_fd,packet,sizeof(packet),0)<=0) return 7;
            for (unsigned mode=0;mode<4;++mode) {
                registrations=received=0;
                inject_second=mode==2; inject_received_second=mode==3;
                result=nexus_test_dns_question_lifetime(backend,mode,ntohs(first_address.sin_port),ntohs(address.sin_port));
                if (result) { std::fprintf(stderr,"backend %u question mode %u: %d\n",backend,mode,result); return 9; }
                if (mode<2 && recv(socket_fd,packet,sizeof(packet),0)<=0) return 10;
            }
            inject_second=inject_received_second=false;
        }
        std::printf("%s: %s\n",backend ? "io_uring" : "epoll",supported ? "passed" : "unavailable");
    }
    close(socket_fd);
    close(first_fd);
    std::puts("DNS single and split question cancellation, exceptions and context abandonment release registration");
}
