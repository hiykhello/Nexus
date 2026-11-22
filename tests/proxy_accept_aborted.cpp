#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import proxy;
import dns.local_config;
using namespace std::chrono_literals;

auto client(std::uint16_t port) -> bool {
    int fd=::socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return false;
    timeval timeout{3,0};
    (void)::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    sockaddr_in address{};
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
    int result=::connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address));
    if (result<0 && errno==EINTR) {
        pollfd pending{fd,POLLOUT,0};
        do { result=::poll(&pending,1,3000); } while (result<0 && errno==EINTR);
        int error=0; socklen_t size=sizeof(error);
        result=result>0 && ::getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)==0 && !error ? 0 : -1;
    }
    unsigned char greeting[]{5,1,0}, reply[2]{};
    std::size_t sent=0, received=0;
    while (result==0 && sent<sizeof(greeting)) {
        auto n=::send(fd,greeting+sent,sizeof(greeting)-sent,MSG_NOSIGNAL);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) break;
        sent+=static_cast<std::size_t>(n);
    }
    while (sent==sizeof(greeting) && received<sizeof(reply)) {
        auto n=::recv(fd,reply+received,sizeof(reply)-received,0);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) break;
        received+=static_cast<std::size_t>(n);
    }
    ::close(fd);
    return received==2 && reply[0]==5 && reply[1]==0;
}
auto count(std::string_view path) -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator(path),std::filesystem::directory_iterator{});
}
auto main(int argc,char** argv) -> int {
    if (argc!=2 || (std::string_view(argv[1])!="1" && std::string_view(argv[1])!="2")) return 1;
    // The process-wide DNS refresh thread outlives each server.
    (void)dns::system_local_snapshots();
    unsigned workers=argv[1][0]-'0';
    auto fds=count("/proc/self/fd"), threads=count("/proc/self/task");
    {
    proxy::Server server;
    auto port=server.start(0,proxy::Inbound::socks5,workers);
    if (!port) return 2;
    auto start=std::chrono::steady_clock::now();
    auto peer=std::async(std::launch::async,client,*port);
    auto deadline=std::chrono::steady_clock::now()+4s;
    while (peer.wait_for(0ms)!=std::future_status::ready && server.healthy() && std::chrono::steady_clock::now()<deadline)
        server.poll(10ms);
    if (!peer.get() || !server.healthy()) return 3;
    auto mode=std::getenv("NEXUS_START_FAULT");
    if (workers==1 && mode && std::string_view(mode)=="accept-burst" &&
        std::chrono::steady_clock::now()-start<40ms) return 5;
    server.stop();
    }
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 4;
    std::println("{} worker(s): transient accept error recovered and SOCKS greeting succeeded",workers);
}
