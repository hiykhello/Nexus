#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import tcp.stack;
namespace p = ::packet;
namespace t=tcp;
namespace r = ::rules;
struct Socket { int fd=-1; ~Socket() { if (fd>=0) ::close(fd); } };
int main() {
    constexpr std::size_t count=8;
    Socket listener{::socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (listener.fd<0 || ::bind(listener.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) || ::listen(listener.fd,16)) return 1;
    socklen_t len=sizeof(addr); if (::getsockname(listener.fd,reinterpret_cast<sockaddr*>(&addr),&len)) return 1;
    p::MemoryLink link({1500,64,96000});
    auto table=t::ConnectionTable::create(count,64);
    t::MemoryDirect4 stack(link,*table,r::Matcher{},count);
    std::array<Socket,count> peers;
    std::array<p::Tcp4View,count> client;
    std::uint64_t now=0;
    auto tick=[&]() -> bool {
        auto step=stack.step(now++,1000);
        return step && !step->input.rejected && !step->start_error && !step->direct.error &&
               !step->input.output_error && !step->service.output.output_error && !step->service.output.connection_error;
    };
    auto send=[&](p::Tcp4View packet) -> bool {
        auto bytes=p::make_tcp4(packet); return bytes && link.send(p::Side::first,*bytes).has_value();
    };
    auto receive=[&]() -> std::optional<p::Bytes> {
        auto bytes=link.receive(p::Side::first); if (!bytes || !*bytes) return {}; return std::move(**bytes);
    };
    for (std::size_t i=0;i<count;++i) {
        client[i]={.source={10,0,0,1},.destination={127,0,0,1},.source_port=static_cast<std::uint16_t>(2000+i),
                   .destination_port=ntohs(addr.sin_port),.sequence=99,.flags=2,.window=64};
        if (!send(client[i]) || !tick()) return 1;
        auto synack=receive(); if (!synack) return 1;
        auto packet=p::parse_tcp4(*synack); if (!packet || packet->flags!=0x12 || packet->destination_port!=2000+i) return 1;
        client[i].sequence=100; client[i].acknowledgement=1001; client[i].flags=0x10;
        if (!send(client[i]) || !tick()) return 1;
        for (int attempt=0;attempt<400 && peers[i].fd<0;++attempt) {
            if (!tick()) return 1;
            peers[i].fd=::accept4(listener.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
            if (peers[i].fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        }
        if (peers[i].fd<0) return 1;
    }
    std::array<p::Bytes,count> payloads;
    for (std::size_t i=0;i<count;++i) {
        payloads[i]={static_cast<std::uint8_t>('A'+i),static_cast<std::uint8_t>('0'+i)};
        client[i].flags=0x18; client[i].payload=payloads[i];
        if (!send(client[i])) return 1;
    }
    std::array<bool,count> received{};
    std::size_t complete=0;
    for (int attempt=0;attempt<4000 && complete<count;++attempt) {
        if (!tick()) return 1;
        while (receive()) {} // ACKs for the client data.
        for (std::size_t i=0;i<count;++i) if (!received[i]) {
            std::array<std::uint8_t,2> bytes{};
            auto n=::recv(peers[i].fd,bytes.data(),bytes.size(),MSG_PEEK);
            if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
            if (n==2) {
                if (::recv(peers[i].fd,bytes.data(),bytes.size(),0)!=2 || !std::ranges::equal(bytes,payloads[i])) return 1;
                received[i]=true; ++complete;
            }
        }
    }
    if (complete!=count) return 1;
    for (std::size_t i=0;i<count;++i) {
        std::ranges::reverse(payloads[i]);
        if (::send(peers[i].fd,payloads[i].data(),payloads[i].size(),MSG_NOSIGNAL)!=2) return 1;
    }
    std::array<p::Bytes,count> returned{}; complete=0;
    for (int attempt=0;attempt<4000 && complete<count;++attempt) {
        if (!tick()) return 1;
        while (auto bytes=receive()) {
            auto packet=p::parse_tcp4(*bytes); if (!packet) return 1;
            if (packet->payload.empty()) continue;
            auto index=static_cast<std::size_t>(packet->destination_port-2000);
            if (index>=count || returned[index].size()>=payloads[index].size() ||
                packet->sequence!=1001+returned[index].size()) return 1;
            returned[index].insert(returned[index].end(),packet->payload.begin(),packet->payload.end());
            if (returned[index].size()>payloads[index].size() ||
                !std::ranges::equal(returned[index],std::span(payloads[index]).first(returned[index].size()))) return 1;
            if (returned[index].size()==payloads[index].size()) ++complete;
        }
    }
    if (complete!=count) return 1;
    for (auto& flow : client) {
        flow.sequence=102; flow.flags=4; flow.payload={}; flow.acknowledgement=0;
        if (!send(flow)) return 1;
    }
    for (int attempt=0;attempt<400 && table->size();++attempt) {
        auto step=stack.step(now++,1000);
        if (!step || (step->input.input_error && *step->input.input_error!=t::ConnectionError::reset)) return 1;
    }
    if (table->size()) return 1;
    for (int i=0;i<16;++i) if (!tick()) return 1;
    for (auto& peer : peers) {
        std::uint8_t byte{};
        if (::recv(peer.fd,&byte,1,0)!=0) return 1;
    }
    std::cout << "TCP integrated stack eight concurrent streams and reset cleanup passed\n";
}
