#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
import std;
import nexus.transport.tun_linux;
namespace p=nexus::packet; namespace tr=nexus::transport;
using namespace std::chrono_literals;
int main(int argc, char** argv) {
    auto tun=p::LinuxTun::create("nx-owned"); if (!tun) return 1;
    if (argc != 2 || ::setns(std::atoi(argv[1]), CLONE_NEWNET) != 0) return 8;
    auto driver=tr::LinuxTunDirect::create(std::move(*tun),nexus::rules::Matcher{}); if (!driver) return 2;
    std::println("ready"); std::fflush(stdout);
    char begin{}; if (::read(STDIN_FILENO,&begin,1)!=1 || begin!='G') return 3;
    if (::fcntl(STDIN_FILENO,F_SETFL,::fcntl(STDIN_FILENO,F_GETFL)|O_NONBLOCK)<0) return 3;
    auto start=std::chrono::steady_clock::now(); bool opened=false, connected=false, udp_input=false, udp_output=false;
    while (std::chrono::steady_clock::now()-start<15s) {
        auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
        char signal{}; auto n=::read(STDIN_FILENO,&signal,1);
        if (n==1) {
            if (signal!='X' || !opened || !connected || !udp_input || !udp_output || !(*driver)->stop(now)) return 4;
            std::println("owned TUN driver carried Linux TCP and UDP direct traffic"); return 0;
        }
        if (n==0 || (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) return 5;
        auto result=(*driver)->step(now,0x12345678);
        if (!result || result->device.input_error || result->device.output_error || result->transport.device.input_error || result->transport.device.output_error ||
            result->transport.tcp.input.rejected || result->transport.tcp.input.input_error || result->transport.tcp.input.output_error ||
            result->transport.tcp.start_error || result->transport.tcp.direct.error || result->transport.tcp.direct.output_error ||
            result->transport.tcp.service.output.connection_error || result->transport.tcp.service.output.output_error ||
            result->transport.udp.rejected || result->transport.udp.ipv4_error || result->transport.udp.ipv6_error || result->transport.udp.output_error) return 6;
        opened |= result->transport.tcp.input.opened; connected |= result->transport.tcp.direct.connected;
        udp_input |= result->transport.udp.input; udp_output |= result->transport.udp.delivered;
        std::this_thread::sleep_for(1ms);
    }
    return 7;
}
