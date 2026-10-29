#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
import std;
import nexus.packet.fd;
import nexus.transport.memory;
namespace p=nexus::packet; namespace t=nexus::tcp; namespace u=nexus::udp; namespace tr=nexus::transport;
using namespace std::chrono_literals;
int main(int argc,char** argv) {
    if (argc!=3) return 1;
    int fd=std::atoi(argv[1]), stop_fd=std::atoi(argv[2]);
    if (::fcntl(stop_fd,F_SETFL,::fcntl(stop_fd,F_GETFL)|O_NONBLOCK)<0) return 2;
    p::MemoryLink link({1500,32,48000});
    auto table=t::ConnectionTable::create(4,4096);
    auto pump=p::FdPump::create(fd,link,1500);
    if (!table || !pump) return 3;
    tr::MemoryEngine engine(link,*table,nexus::rules::Matcher{},4,u::Mapping::endpoint_independent,
                            u::Filtering::address_port_dependent,{4,4,60000},1500,{1500,16,24000});
    auto start=std::chrono::steady_clock::now(); bool opened=false, connected=false, udp_input=false, udp_output=false;
    while (std::chrono::steady_clock::now()-start<15s) {
        char signal{}; auto n=::read(stop_fd,&signal,1);
        if (n==1) {
            auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
            if (!opened || !connected || !udp_input || !udp_output || !engine.stop(now) || table->size()) return 4;
            std::println("isolated Linux TCP and UDP clients reached real direct upstreams through TUN"); return 0;
        }
        if (n==0 || (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) return 5;
        auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
        auto moved=pump->step(); if (moved.input_error || moved.output_error) return 6;
        auto result=engine.step(now,0x12345678);
        if (!result || result->device.input_error || result->device.output_error ||
            result->tcp.input.rejected || result->tcp.input.input_error || result->tcp.input.output_error || result->tcp.start_error || result->tcp.direct.error ||
            result->tcp.direct.output_error || result->tcp.service.output.connection_error || result->tcp.service.output.output_error ||
            result->udp.rejected || result->udp.ipv4_error || result->udp.ipv6_error || result->udp.output_error) return 7;
        opened |= result->tcp.input.opened;
        connected |= result->tcp.direct.connected;
        udp_input |= result->udp.input;
        udp_output |= result->udp.delivered;
        std::this_thread::sleep_for(1ms);
    }
    return 8;
}
