#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.transport.memory;
import nexus.packet.fd;
namespace p=nexus::packet;
namespace t=nexus::tcp;
namespace u=nexus::udp;
namespace tr=nexus::transport;
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
    tr::MemoryEngine engine(link,*table,nexus::rules::Matcher{},4,u::Mapping::endpoint_independent,
                            u::Filtering::address_port_dependent,{4,4,60000},1500,{1500,1,1500});
    int descriptors[2];
    if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,descriptors)) return 1;
    Socket local{descriptors[0]}, client_fd{descriptors[1]};
    auto pump=p::FdPump::create(local.fd,link,1500); if (!pump) return 1;
    auto send_packet=[&](p::Bytes const& packet) { return ::send(client_fd.fd,packet.data(),packet.size(),0)==static_cast<ssize_t>(packet.size()); };
    auto read_packet=[&]() -> std::expected<std::optional<p::Bytes>,p::DeviceError> {
        std::array<std::uint8_t,1500> buffer{};
        auto n=::recv(client_fd.fd,buffer.data(),buffer.size(),0);
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return std::optional<p::Bytes>{};
        if (n<=0) return std::unexpected(p::DeviceError::closed);
        return std::optional<p::Bytes>{p::Bytes(buffer.begin(),buffer.begin()+n)};
    };
    std::uint64_t now=10;
    auto step=[&]() -> bool {
        auto moved=pump->step();
        if (moved.input_error || moved.output_error) return false;
        auto result=engine.step(now++,50);
        return result && !result->device.rejected && !result->device.input_error && !result->device.output_error &&
            !result->tcp.input.rejected && !result->tcp.input.input_error && !result->tcp.start_error && !result->tcp.direct.error &&
            !result->udp.rejected && !result->udp.ipv4_error && !result->udp.ipv6_error && !result->udp.output_error;
    };
    p::Tcp4View client{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
                       .destination_port=ntohs(tcp_addr.sin_port),.sequence=99,.flags=2,.window=64};
    p::Bytes udp_payload{'u','d','p'}, tcp_payload{'t','c','p'};
    auto syn=p::make_tcp4(client);
    auto datagram=p::make_udp4({10,0,0,1},{127,0,0,1},2345,ntohs(udp_addr.sin_port),udp_payload);
    if (!syn || !datagram || !send_packet(*syn) || !send_packet(*datagram)) return 1;
    if (!step()) return 1;
    bool got_synack=false; sockaddr_in source{}; socklen_t source_size=sizeof(source);
    std::array<std::uint8_t,32> bytes{}; ssize_t udp_n=-1;
    for (int i=0;i<400 && (!got_synack || udp_n<0);++i) {
        if (!step()) return 1;
        auto out=read_packet(); if (!out) return 1;
        if (*out) { auto packet=p::parse_tcp4(**out); if (!packet || packet->flags!=0x12) return 1; got_synack=true; }
        if (udp_n<0) {
            udp_n=::recvfrom(server.fd,bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&source),&source_size);
            if (udp_n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        }
    }
    if (!got_synack || udp_n!=3 || !std::ranges::equal(std::span(bytes).first(3),udp_payload)) return 1;
    client.flags=0x10; client.sequence=100; client.acknowledgement=51;
    auto ack=p::make_tcp4(client); if (!ack || !send_packet(*ack)) return 1;
    Socket peer;
    for (int i=0;i<400 && peer.fd<0;++i) {
        if (!step()) return 1;
        peer.fd=::accept4(listener.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (peer.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (peer.fd<0 || ::sendto(server.fd,udp_payload.data(),udp_payload.size(),0,reinterpret_cast<sockaddr*>(&source),source_size)!=3) return 1;
    client.flags=0x18; client.payload=tcp_payload;
    auto data=p::make_tcp4(client); if (!data || !send_packet(*data)) return 1;
    bool udp_reply=false; ssize_t tcp_n=-1;
    for (int i=0;i<400 && (!udp_reply || tcp_n<0);++i) {
        if (!step()) return 1;
        auto out=read_packet(); if (!out) return 1;
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
        auto out=read_packet(); if (!out) return 1;
        if (!*out || (**out)[9]!=6) continue;
        auto packet=p::parse_tcp4(**out); if (!packet) return 1;
        received.insert(received.end(),packet->payload.begin(),packet->payload.end());
    }
    if (received!=tcp_reply) return 1;
    auto early=engine.stop(0);
    if (early || !std::holds_alternative<tr::MemoryClockError>(early.error()) ||
        std::get<tr::MemoryClockError>(early.error())!=tr::MemoryClockError::time_reversed || !table->size()) return 1;
    if (!engine.stop(now) || !engine.stop(now) || table->size()) return 1;
    auto stopped=engine.step(now,50);
    if (stopped || !std::holds_alternative<tr::MemoryClockError>(stopped.error()) ||
        std::get<tr::MemoryClockError>(stopped.error())!=tr::MemoryClockError::stopped) return 1;
    bool closed=false;
    for (int i=0;i<400 && !closed;++i) {
        auto count=::recv(peer.fd,bytes.data(),bytes.size(),0);
        if (!count) closed=true;
        else if (count<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (!closed) return 1;
    std::cout << "packet descriptor to shared TCP and UDP loopback passed\n";
}
