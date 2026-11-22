#include <arpa/inet.h>
#include <cerrno>
#include <dlfcn.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import proxy;
import dns.local_config;

auto count(std::string_view path) -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator(path),std::filesystem::directory_iterator{});
}
auto main() -> int {
    // The DNS refresh thread belongs to the process, not the server.
    (void)dns::system_local_snapshots();
    auto* mode=std::getenv("NEXUS_START_FAULT");
    using Reset=void(*)();
    using Count=unsigned(*)();
    Count attempts=nullptr, started=nullptr, rejected=nullptr;
    if (mode && std::string_view(mode)=="thread") {
        auto reset=reinterpret_cast<Reset>(::dlsym(RTLD_DEFAULT,"nexus_test_thread_fault_reset"));
        attempts=reinterpret_cast<Count>(::dlsym(RTLD_DEFAULT,"nexus_test_thread_fault_attempts"));
        started=reinterpret_cast<Count>(::dlsym(RTLD_DEFAULT,"nexus_test_thread_fault_started"));
        rejected=reinterpret_cast<Count>(::dlsym(RTLD_DEFAULT,"nexus_test_thread_fault_rejected"));
        if (!reset || !attempts || !started || !rejected) return 13;
        reset();
    }
    int fd=::socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return 1;
    sockaddr_in address{};
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    socklen_t size=sizeof(address);
    if (::bind(fd,reinterpret_cast<sockaddr*>(&address),size)!=0 ||
        ::getsockname(fd,reinterpret_cast<sockaddr*>(&address),&size)!=0) return 2;
    ::close(fd);
    proxy::Server server;
    auto fds=count("/proc/self/fd"), threads=count("/proc/self/task");
    auto port=ntohs(address.sin_port);
    auto failed=server.start(port,proxy::Inbound::socks5,2);
    if (failed || server.healthy() || count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 3;
    // The failure must occur after one worker was started, so this actually
    // exercises rollback of a partially started server.
    if (attempts && (attempts()!=2 || started()!=1 || rejected()!=1)) return 14;
    if (mode && std::string_view(mode)=="reuse" && failed.error()!=std::errc::permission_denied) return 12;
    auto retry=server.start(port,proxy::Inbound::socks5,2);
    if (!retry || *retry!=port || !server.healthy()) return 4;
    fd=::socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return 6;
    timeval limit{3,0};
    (void)::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));
    if (::connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0) {
        if (errno!=EINTR) return 7;
        pollfd event{fd,POLLOUT,0};
        int ready;
        do { ready=::poll(&event,1,3000); } while (ready<0 && errno==EINTR);
        int error=0; socklen_t length=sizeof(error);
        if (ready<=0 || ::getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&length)!=0 || error) return 8;
    }
    unsigned char greeting[]{5,1,0}, reply[2]{};
    std::size_t sent=0, received=0;
    while (sent<sizeof(greeting)) {
        auto n=::send(fd,greeting+sent,sizeof(greeting)-sent,MSG_NOSIGNAL);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return 9;
        sent+=static_cast<std::size_t>(n);
    }
    while (received<sizeof(reply)) {
        auto n=::recv(fd,reply+received,sizeof(reply)-received,0);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return 10;
        received+=static_cast<std::size_t>(n);
    }
    if (reply[0]!=5 || reply[1]!=0) return 11;
    ::close(fd);
    server.stop();
    if (server.healthy() || count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 5;
    std::println("partial startup failure cleaned up; same server and port restarted");
}
