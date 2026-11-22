#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import transport.memory;
namespace p = ::packet;
namespace t=tcp;
namespace u=udp;
namespace tr=transport;
#ifdef NEXUS_TRANSPORT_SEND_FAULT
static bool block_udp_send = true;
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
extern "C" ssize_t __wrap_sendto(int fd,const void* data,size_t size,int flags,const sockaddr* address,socklen_t length) {
    if (block_udp_send) { errno=EAGAIN; return -1; }
    return __real_sendto(fd,data,size,flags,address,length);
}
#endif
struct Socket { int fd=-1; ~Socket() { if (fd>=0) ::close(fd); } };
int main() {
    Socket listener{::socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    Socket server{::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in tcp_addr{}, udp_addr{};
    tcp_addr.sin_family=udp_addr.sin_family=AF_INET;
    tcp_addr.sin_addr.s_addr=udp_addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (listener.fd<0 || server.fd<0 || ::bind(listener.fd,reinterpret_cast<sockaddr*>(&tcp_addr),sizeof(tcp_addr)) ||
        ::listen(listener.fd,4) || ::bind(server.fd,reinterpret_cast<sockaddr*>(&udp_addr),sizeof(udp_addr))) return 1;
    socklen_t size=sizeof(tcp_addr);
    if (::getsockname(listener.fd,reinterpret_cast<sockaddr*>(&tcp_addr),&size)) return 1;
    size=sizeof(udp_addr); if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&udp_addr),&size)) return 1;
    p::MemoryLink link({1500,4,6000});
    auto table=t::ConnectionTable::create(4,64);
    tr::MemoryEngine engine(link,*table,::rules::Matcher{},4,u::Mapping::endpoint_independent,
                            u::Filtering::address_port_dependent,{4,4,60000},1500,{1500,1,1500});
    std::uint64_t now=10;
#ifdef NEXUS_TRANSPORT_SEND_FAULT
    bool udp_blocked=false;
#endif
    auto step=[&]() -> bool {
        auto result=engine.step(now++,50);
#ifdef NEXUS_TRANSPORT_SEND_FAULT
        if (result && result->udp.input_backpressured) udp_blocked=true;
#endif
        return result && !result->device.rejected && !result->device.input_error && !result->device.output_error &&
            !result->tcp.input.rejected && !result->tcp.input.input_error && !result->tcp.start_error && !result->tcp.direct.error &&
            !result->udp.rejected && !result->udp.ipv4_error && !result->udp.ipv6_error && !result->udp.output_error;
    };
    p::Tcp4View client{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
                       .destination_port=ntohs(tcp_addr.sin_port),.sequence=99,.flags=2,.window=64};
    p::Bytes udp_payload{'u','d','p'}, tcp_payload{'t','c','p'};
    auto syn=p::make_tcp4(client);
    auto datagram=p::make_udp4({10,0,0,1},{127,0,0,1},2345,ntohs(udp_addr.sin_port),udp_payload);
    if (!syn || !datagram || !link.send(p::Side::first,*datagram) || !link.send(p::Side::first,*syn)) return 1;
    if (!step()) return 1;
    auto invalid=engine.step(9,50);
    if (invalid || !std::holds_alternative<tr::MemoryClockError>(invalid.error())) return 1;
    bool got_synack=false; sockaddr_in source{}; socklen_t source_size=sizeof(source);
    std::array<std::uint8_t,32> bytes{}; ssize_t udp_n=-1;
    for (int i=0;i<400 && (!got_synack || udp_n<0);++i) {
        if (!step()) return 1;
        auto out=link.receive(p::Side::first); if (!out) return 1;
        if (*out) { auto packet=p::parse_tcp4(**out); if (!packet || packet->flags!=0x12) return 1; got_synack=true; }
#ifdef NEXUS_TRANSPORT_SEND_FAULT
        if (got_synack && block_udp_send) {
            if (!udp_blocked || udp_n>=0) return 1;
            block_udp_send=false;
        }
#endif
        if (udp_n<0) {
            udp_n=::recvfrom(server.fd,bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&source),&source_size);
            if (udp_n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        }
    }
    if (!got_synack || udp_n!=3 || !std::ranges::equal(std::span(bytes).first(3),udp_payload)) return 1;
    client.flags=0x10; client.sequence=100; client.acknowledgement=51;
    auto ack=p::make_tcp4(client); if (!ack || !link.send(p::Side::first,*ack)) return 1;
    Socket peer;
    for (int i=0;i<400 && peer.fd<0;++i) {
        if (!step()) return 1;
        peer.fd=::accept4(listener.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (peer.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (peer.fd<0 || ::sendto(server.fd,udp_payload.data(),udp_payload.size(),0,reinterpret_cast<sockaddr*>(&source),source_size)!=3) return 1;
    client.flags=0x18; client.payload=tcp_payload;
    auto data=p::make_tcp4(client); if (!data || !link.send(p::Side::first,*data)) return 1;
    bool udp_reply=false; ssize_t tcp_n=-1;
    for (int i=0;i<400 && (!udp_reply || tcp_n<0);++i) {
        if (!step()) return 1;
        auto out=link.receive(p::Side::first); if (!out) return 1;
        if (*out && (**out)[9]==17) {
            auto packet=p::parse_udp4(**out);
            if (!packet || packet->destination_port!=2345 || !std::ranges::equal(packet->payload,udp_payload)) return 1;
            udp_reply=true;
        }
        if (tcp_n<0) {
            tcp_n=::recv(peer.fd,bytes.data(),bytes.size(),0);
            if (tcp_n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        }
    }
    if (!udp_reply || tcp_n!=3 || !std::ranges::equal(std::span(bytes).first(3),tcp_payload)) return 1;
    p::Bytes tcp_reply{'b','a','c','k'};
    if (::send(peer.fd,tcp_reply.data(),tcp_reply.size(),MSG_NOSIGNAL)!=4) return 1;
    p::Bytes received;
    for (int i=0;i<400 && received.size()<tcp_reply.size();++i) {
        if (!step()) return 1;
        auto out=link.receive(p::Side::first); if (!out) return 1;
        if (!*out || (**out)[9]!=6) continue;
        auto packet=p::parse_tcp4(**out); if (!packet) return 1;
        received.insert(received.end(),packet->payload.begin(),packet->payload.end());
    }
    if (received!=tcp_reply) return 1;
    Socket server6{::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in6 addr6{}; addr6.sin6_family=AF_INET6; addr6.sin6_addr=in6addr_loopback;
    if (server6.fd<0 || ::bind(server6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))) return 1;
    size=sizeof(addr6); if (::getsockname(server6.fd,reinterpret_cast<sockaddr*>(&addr6),&size)) return 1;
    constexpr p::Address6 client6{0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    constexpr p::Address6 loop6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    auto request6=p::make_udp6(client6,loop6,3456,ntohs(addr6.sin6_port),udp_payload);
    if (!request6 || !link.send(p::Side::first,*request6)) return 1;
    sockaddr_in6 source6{}; socklen_t source6_size=sizeof(source6); ssize_t n6=-1;
    for (int i=0;i<400 && n6<0;++i) {
        if (!step()) return 1;
        n6=::recvfrom(server6.fd,bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&source6),&source6_size);
        if (n6<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (n6!=3 || !std::ranges::equal(std::span(bytes).first(3),udp_payload)) return 1;
    p::Bytes sentinel{42};
    for (int i=0;i<4;++i) if (!link.send(p::Side::second,sentinel)) return 1;
    if (::sendto(server6.fd,udp_payload.data(),udp_payload.size(),0,
                 reinterpret_cast<sockaddr*>(&source6),source6_size)!=3) return 1;
    bool blocked=false;
    for (int i=0;i<400 && !blocked;++i) {
        auto result=engine.step(now++,50);
        if (!result || result->udp.ipv6_error || result->device.output_error) return 1;
        blocked=result->device.output_backpressured;
    }
    if (!blocked) return 1;
    client.flags=0x10; client.sequence=103; client.acknowledgement=55; client.payload={};
    ack=p::make_tcp4(client); if (!ack || !link.send(p::Side::first,*ack)) return 1;
    bool tcp_progress=false;
    for (int i=0;i<8 && !tcp_progress;++i) {
        auto result=engine.step(now++,50);
        if (!result || !result->device.output_backpressured || result->tcp.input.input_error) return 1;
        tcp_progress=result->tcp.input.input;
    }
    if (!tcp_progress) return 1;
    // Keep the accepted reply blocked across both UDP idle deadlines.
    now += 60000;
    auto expired=engine.step(now++,50);
    if (!expired || !expired->device.output_backpressured || expired->udp.expired!=2 ||
        expired->udp.ipv4_error || expired->udp.ipv6_error) return 1;
    for (int i=0;i<4;++i) {
        auto out=link.receive(p::Side::first); if (!out || !*out || **out!=sentinel) return 1;
    }
    bool received6=false;
    for (int i=0;i<400 && !received6;++i) {
        if (!step()) return 1;
        auto out=link.receive(p::Side::first); if (!out) return 1;
        if (!*out) continue;
        auto packet=p::parse_udp6(**out);
        if (!packet || packet->source!=loop6 || packet->destination!=client6 || packet->destination_port!=3456 ||
            !std::ranges::equal(packet->payload,udp_payload)) return 1;
        received6=true;
    }
    if (!received6) return 1;
    // Close the TCP stream through the same multiplexer after UDP has expired.
    client.flags=0x11; client.sequence=103; client.acknowledgement=55;
    auto fin=p::make_tcp4(client); if (!fin || !link.send(p::Side::first,*fin)) return 1;
    bool peer_eof=false;
    for (int i=0;i<400 && !peer_eof;++i) {
        if (!step()) return 1;
        auto out=link.receive(p::Side::first); if (!out) return 1;
        if (*out && !p::parse_tcp4(**out)) return 1;
        auto count=::recv(peer.fd,bytes.data(),bytes.size(),0);
        if (!count) peer_eof=true;
        else if (count<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (!peer_eof || ::shutdown(peer.fd,SHUT_WR)) return 1;
    bool remote_fin=false;
    for (int i=0;i<400 && !remote_fin;++i) {
        if (!step()) return 1;
        auto out=link.receive(p::Side::first); if (!out) return 1;
        if (!*out) continue;
        auto packet=p::parse_tcp4(**out); if (!packet) return 1;
        if (packet->flags & 1) { if (packet->sequence!=55) return 1; remote_fin=true; }
    }
    if (!remote_fin) return 1;
    client.flags=0x10; client.sequence=104; client.acknowledgement=56;
    ack=p::make_tcp4(client); if (!ack || !link.send(p::Side::first,*ack)) return 1;
    for (int i=0;i<20 && table->size();++i) if (!step()) return 1;
    if (table->size()) return 1;
    std::cout << "shared memory transport TCP and IPv4/IPv6 UDP loopback and backpressure passed\n";
}
