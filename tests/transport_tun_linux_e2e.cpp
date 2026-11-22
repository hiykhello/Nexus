#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
import std;
import transport.tun_linux;
namespace p = ::packet; namespace tr=transport;
using namespace std::chrono_literals;
int main(int argc, char** argv) {
    auto tun=p::LinuxTun::create("nx-owned"); if (!tun) return 1;
    if ((argc < 2 || argc > 5) || ::setns(std::atoi(argv[1]), CLONE_NEWNET) != 0) return 8;
    bool source_test=argc==5 && std::string_view(argv[4])=="source";
    if (argc==5 && !source_test) return 8;
    tr::TunLimits limits; if (argc>=3) limits.socket_mark=42;
    if (argc>=4) limits.mtu=1280;
    auto policy=source_test ? ::rules::Matcher::compile({{{"source-ip-cidr","10.77.0.4/32"},
        {"source-ip-cidr","fd77::4/128"},{"source-port","43110"}},2})
        : std::expected<::rules::Matcher,::rules::Error>{::rules::Matcher{}};
    if (!policy) return 2;
    auto driver=tr::LinuxTunDirect::create(std::move(*tun),std::move(*policy),limits); if (!driver) return 2;
    std::println("ready"); std::fflush(stdout);
    char begin{}; if (::read(STDIN_FILENO,&begin,1)!=1 || begin!='G') return 3;
    if (::fcntl(STDIN_FILENO,F_SETFL,::fcntl(STDIN_FILENO,F_GETFL)|O_NONBLOCK)<0) return 3;
    auto start=std::chrono::steady_clock::now(); bool opened=false, connected=false, udp_input=false, udp_output=false;
    while (std::chrono::steady_clock::now()-start<15s) {
        auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
        char signal{}; auto n=::read(STDIN_FILENO,&signal,1);
        if (n==1) {
            if ((signal!='X' && signal!='S') || !opened || !connected || !udp_input || !udp_output || !(*driver)->stop(now)) return 4;
            if (signal=='S') {
                std::println("stopped"); std::fflush(stdout);
                if (::fcntl(STDIN_FILENO,F_SETFL,::fcntl(STDIN_FILENO,F_GETFL)&~O_NONBLOCK)<0 ||
                    ::read(STDIN_FILENO,&signal,1)!=1 || signal!='Q') return 9;
            }
            std::println("owned TUN driver carried Linux TCP and UDP direct traffic"); return 0;
        }
        if (n==0 || (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) return 5;
        auto result=(*driver)->step(now);
        auto unexpected_rejection=[&](auto const& rejected) {
            return rejected && rejected->error!=tcp::DispatchError::unknown_flow &&
                !(source_test && rejected->error==tcp::DispatchError::blocked);
        };
        auto udp_rejected=result->transport.udp.rejected;
        bool udp_blocked=false;
        if (source_test && udp_rejected) {
            if (auto routed=std::get_if<udp::RoutedError>(&*udp_rejected))
                if (auto error=std::get_if<udp::RouteError>(routed)) udp_blocked=*error==udp::RouteError::blocked;
        }
        if (!result || result->device.input_error || result->device.output_error || result->transport.device.input_error || result->transport.device.output_error ||
            unexpected_rejection(result->transport.tcp.input.rejected) || result->transport.tcp.input.input_error || result->transport.tcp.input.output_error ||
            result->transport.tcp.start_error || result->transport.tcp.direct.error || result->transport.tcp.direct.output_error ||
            result->transport.tcp.service.output.connection_error || result->transport.tcp.service.output.output_error ||
            (udp_rejected && !udp_blocked) || result->transport.udp.ipv4_error || result->transport.udp.ipv6_error || result->transport.udp.output_error) return 6;
        if (auto const& tcp6=result->transport.tcp6; tcp6 &&
            (unexpected_rejection(tcp6->input.rejected) || tcp6->input.input_error || tcp6->input.output_error ||
             tcp6->start_error || tcp6->direct.error || tcp6->direct.output_error ||
             tcp6->service.output.connection_error || tcp6->service.output.output_error)) return 6;
        opened |= result->transport.tcp.input.opened; connected |= result->transport.tcp.direct.connected;
        udp_input |= result->transport.udp.input; udp_output |= result->transport.udp.delivered;
        std::this_thread::sleep_for(1ms);
    }
    return 7;
}
