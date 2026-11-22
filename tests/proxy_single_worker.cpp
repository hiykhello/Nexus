#include <sched.h>
import std;
import proxy;
import dns.local_config;
using namespace std::chrono_literals;

auto threads() -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator("/proc/self/task"),
                                 std::filesystem::directory_iterator{});
}
auto main() -> int {
    cpu_set_t original, single;
    CPU_ZERO(&original);
    if (::sched_getaffinity(0,sizeof(original),&original)!=0) return 1;
    int cpu=0;
    while (cpu<CPU_SETSIZE && !CPU_ISSET(cpu,&original)) ++cpu;
    if (cpu==CPU_SETSIZE) return 2;
    CPU_ZERO(&single); CPU_SET(cpu,&single);
    if (::sched_setaffinity(0,sizeof(single),&single)!=0) return 3;
    // The process-wide local DNS source owns a refresh thread. Initialize it
    // before counting so the test measures only the server's network loop.
    (void)dns::system_local_snapshots();
    auto before=threads();
    int result=0;
    {
        proxy::Server server;
        auto port=server.start(0);
        if (!port || threads()!=before) result=4;
        else {
            server.poll(5ms);
            if (threads()!=before) result=5;
        }
        server.stop();
        if (threads()!=before) result=6;
    }
    if (::sched_setaffinity(0,sizeof(original),&original)!=0) return 7;
    if (result) return result;
    std::println("single-CPU proxy uses caller thread for the network loop");
}
