#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import transport.memory;
namespace p = ::packet;
namespace t=tcp;
namespace u=udp;
namespace tr=transport;
struct Socket { int fd=-1; ~Socket() { if (fd>=0) ::close(fd); } };
int main() {
    Socket listener4{::socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    Socket listener6{::socket(AF_INET6,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in addr4{}; addr4.sin_family=AF_INET; addr4.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    sockaddr_in6 addr6{}; addr6.sin6_family=AF_INET6; addr6.sin6_addr=in6addr_loopback;
    if (listener4.fd<0 || listener6.fd<0 ||
        ::bind(listener4.fd,reinterpret_cast<sockaddr*>(&addr4),sizeof(addr4)) || ::listen(listener4.fd,8) ||
        ::bind(listener6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6)) || ::listen(listener6.fd,8)) return 1;
    socklen_t len4=sizeof(addr4), len6=sizeof(addr6);
    if (::getsockname(listener4.fd,reinterpret_cast<sockaddr*>(&addr4),&len4) ||
        ::getsockname(listener6.fd,reinterpret_cast<sockaddr*>(&addr6),&len6)) return 1;
    for (bool first6 : {false,true}) {
        p::MemoryLink link;
        auto table4=t::ConnectionTable::create(4,64);
        auto table6=t::ConnectionTable6::create(4,64);
        tr::MemoryEngine engine(link,*table4,*table6,::rules::Matcher{},4,1,
                                u::Mapping::endpoint_independent,u::Filtering::address_port_dependent);
        std::uint64_t now=0;
        p::Tcp4View four{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1200,
                         .destination_port=ntohs(addr4.sin_port),.sequence=99,.flags=2,.window=64};
        p::Tcp6View six{.source={0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1},
                        .destination={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},.source_port=1200,
                        .destination_port=ntohs(addr6.sin6_port),.sequence=99,.flags=2,.window=64};
        auto send=[&](bool ipv6, std::uint8_t flags, std::uint16_t source) -> std::optional<tr::MemoryStep> {
            four.source_port=six.source_port=source; four.flags=six.flags=flags;
            four.sequence=six.sequence=(flags==2 ? 99 : 100);
            four.acknowledgement=six.acknowledgement=(flags==2 ? 0 : 51);
            auto packet=ipv6 ? p::make_tcp6(six) : p::make_tcp4(four);
            if (!packet || !link.send(p::Side::first,*packet)) return {};
            auto result=engine.step(++now,50); if (!result) return {};
            return std::move(*result);
        };
        auto tick=[&]() -> bool {
            auto result=engine.step(++now,50); if (!result) return false;
            auto packet=link.receive(p::Side::first); return packet.has_value();
        };
        auto syn=send(first6,2,1200);
        if (!syn || !(first6 ? syn->tcp6->input.opened : syn->tcp.input.opened) || !tick()) return 1;
        auto ack=send(first6,0x10,1200);
        if (!ack || (first6 ? ack->tcp6->start_error.has_value() : ack->tcp.start_error.has_value())) return 1;
        Socket peer;
        for (int i=0;i<400 && peer.fd<0;++i) {
            if (!tick()) return 1;
            peer.fd=::accept4(first6 ? listener6.fd : listener4.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
            if (peer.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        }
        if (peer.fd<0) return 1;
        syn=send(!first6,2,1300);
        if (!syn || !(first6 ? syn->tcp.input.opened : syn->tcp6->input.opened) || !tick()) return 1;
        ack=send(!first6,0x10,1300);
        if (!ack) return 1;
        auto& denied=first6 ? ack->tcp : *ack->tcp6;
        if (!denied.start_error || !std::holds_alternative<t::DirectError>(*denied.start_error) ||
            std::get<t::DirectError>(*denied.start_error)!=t::DirectError::full || !denied.reset) return 1;
        bool saw_rst=false;
        for (int i=0;i<8 && !saw_rst;++i) {
            if (!engine.step(++now,50)) return 1;
            auto output=link.receive(p::Side::first); if (!output) return 1;
            if (*output) {
                if (first6) { auto decoded=p::parse_tcp4(**output); saw_rst=decoded && (decoded->flags&4) && decoded->destination_port==1300; }
                else { auto decoded=p::parse_tcp6(**output); saw_rst=decoded && (decoded->flags&4) && decoded->destination_port==1300; }
            }
        }
        pollfd no_dial{first6 ? listener4.fd : listener6.fd,POLLIN,0};
        if (!saw_rst || ::poll(&no_dial,1,0)!=0) return 1;
        auto reset=send(first6,4,1200); if (!reset) return 1;
        bool closed=false;
        for (int i=0;i<400 && !closed;++i) {
            if (!tick()) return 1;
            char byte{}; auto n=::recv(peer.fd,&byte,1,0);
            if (n==0 || (n<0 && errno==ECONNRESET)) closed=true;
            else if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        }
        if (!closed) return 1;
        syn=send(!first6,2,1301);
        if (!syn || !(first6 ? syn->tcp.input.opened : syn->tcp6->input.opened) || !tick()) return 1;
        ack=send(!first6,0x10,1301);
        if (!ack || (first6 ? ack->tcp.start_error.has_value() : ack->tcp6->start_error.has_value())) return 1;
        Socket replacement;
        for (int i=0;i<400 && replacement.fd<0;++i) {
            if (!tick()) return 1;
            replacement.fd=::accept4(first6 ? listener4.fd : listener6.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
            if (replacement.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        }
        if (replacement.fd<0 || !engine.stop(++now)) return 1;
    }
    std::cout << "dual TCP shared direct limit, rejection and reuse passed\n";
}
