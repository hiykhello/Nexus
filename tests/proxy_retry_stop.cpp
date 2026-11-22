#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
import std;
import proxy;
import dns.local_config;
using namespace std::chrono_literals;

auto count(std::string_view path) -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator(path), std::filesystem::directory_iterator{});
}
auto now_ns() -> long {
    timespec now{};
    if (::clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return now.tv_sec*1000000000L+now.tv_nsec;
}
auto main() -> int {
    auto fault_time=reinterpret_cast<long(*)()>(::dlsym(RTLD_DEFAULT, "nexus_test_accept_fault_time_ns"));
    if (!fault_time) return 1;
    // The process-wide DNS refresh thread outlives each server.
    (void)dns::system_local_snapshots();
    auto fds=count("/proc/self/fd"), threads=count("/proc/self/task");
    {
    proxy::Server server;
    auto port=server.start(0);
    if (!port) return 2;
    int fd=::socket(AF_INET, SOCK_STREAM, 0);
    if (fd<0) return 3;
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK); addr.sin_port=htons(*port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) return 4;
    auto deadline=std::chrono::steady_clock::now()+3s;
    while (!fault_time() && std::chrono::steady_clock::now()<deadline) server.poll(1ms);
    auto fault=fault_time(), observed=now_ns();
    // Establish that the first 10 ms timer has not yet expired at the stop call.
    if (!fault || observed<fault || observed-fault>=8000000L || !server.healthy()) return 5;
    server.stop();
    ::close(fd);
    if (server.healthy() || server.failure() || count("/proc/self/task")!=threads) return 7;
    auto again=server.start(0);
    if (!again || !server.healthy()) {
        if (!again) std::println("restart error: {}", again.error().message());
        else if (auto failure=server.failure()) std::println("restart failure: {}", proxy::describe(failure->kind));
        return 8;
    }
    server.stop();
    }
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 9;
    std::println("stop during accept retry delay drained timer; restart and cleanup succeeded");
}
