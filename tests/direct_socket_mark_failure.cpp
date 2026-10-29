#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
import std;
import nexus.tcp.direct;
import nexus.udp.direct;
namespace p=nexus::packet; namespace t=nexus::tcp; namespace u=nexus::udp;
namespace { int marks=0, connects=0, sends=0; }
extern "C" int __real_setsockopt(int,int,int,const void*,socklen_t);
extern "C" int __wrap_setsockopt(int fd,int level,int name,const void* value,socklen_t size) {
    if (level==SOL_SOCKET && name==SO_MARK) { ++marks; errno=EPERM; return -1; }
    return __real_setsockopt(fd,level,name,value,size);
}
extern "C" int __wrap_connect(int,const sockaddr*,socklen_t) { ++connects; errno=EIO; return -1; }
extern "C" ssize_t __wrap_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t) { ++sends; errno=EIO; return -1; }
int main() {
    p::MemoryLink link; auto table=t::ConnectionTable::create(2,8); if (!table) return 1;
    p::Tcp4View syn{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    auto id=table->open(syn,50,0); if (!id) return 2;
    p::Tcp4View ack{.source=syn.source,.destination=syn.destination,.source_port=syn.source_port,
                    .destination_port=syn.destination_port,.sequence=100,.acknowledgement=51,.flags=0x10,.window=8};
    if (!table->get(*id)->input(ack,0)) return 3;
    t::MemoryEngine engine(link,*table); t::Direct4 tcp(*table,engine,nexus::rules::Matcher{},2,42);
    auto tcp_result=tcp.start(*id,0);
    if (tcp_result || !std::holds_alternative<std::error_code>(tcp_result.error()) ||
        std::get<std::error_code>(tcp_result.error())!=std::error_code(EPERM,std::generic_category()) || connects || marks!=1) return 4;
    auto reset=tcp.step(0); if (!reset || !reset->retired || reset->error || connects) return 5;
    u::Direct4 udp4(nexus::rules::Matcher{},u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{},1500,42);
    u::Direct6 udp6(nexus::rules::Matcher{},u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{},1500,42);
    p::Bytes payload{'x'};
    auto a=p::make_udp4({10,0,0,1},{127,0,0,1},1234,53,payload);
    auto b=p::make_udp6({0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},1234,53,payload);
    if (!a || !b) return 6;
    auto r4=udp4.submit(*a,0), r6=udp6.submit(*b,0);
    auto failed=[](auto const& r) { return !r && std::holds_alternative<std::error_code>(r.error()) &&
        std::get<std::error_code>(r.error())==std::error_code(EPERM,std::generic_category()); };
    if (!failed(r4) || !failed(r6) || marks!=3 || sends || udp4.size() || udp6.size()) return 7;
    std::println("mark failures prevent TCP connect and both UDP sends");
}
