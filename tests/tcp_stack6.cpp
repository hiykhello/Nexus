#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.tcp.stack;
namespace p=nexus::packet;
namespace t=nexus::tcp;
namespace r=nexus::rules;
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
int main() {
    Socket listener{::socket(AF_INET6,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in6 addr{}; addr.sin6_family=AF_INET6; addr.sin6_addr=in6addr_loopback;
    if (listener.fd<0 || ::bind(listener.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) || ::listen(listener.fd,4)) return 1;
    socklen_t length=sizeof(addr); if (::getsockname(listener.fd,reinterpret_cast<sockaddr*>(&addr),&length)) return 1;
    p::MemoryLink link({1500,1,1500});
    auto table=t::ConnectionTable6::create(2,32);
    t::MemoryDirect6 stack(link,*table,r::Matcher{},1);
    p::Tcp6View client{.source={0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1},.destination={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},.source_port=1234,
                       .destination_port=ntohs(addr.sin6_port),.sequence=99,.flags=2,.window=32};
    std::uint64_t now=0;
    auto inject=[&](p::Tcp6View view) -> std::optional<t::StackStep> {
        auto bytes=p::make_tcp6(view); if (!bytes || !link.send(p::Side::first,*bytes)) return {};
        auto step=stack.step(now++,50); if (!step || step->input.rejected || step->input.input_error) return {};
        return *step;
    };
    auto receive=[&]() -> std::optional<p::Bytes> {
        auto bytes=link.receive(p::Side::first); if (!bytes || !*bytes) return {}; return std::move(**bytes);
    };
    auto syn=inject(client); auto response=receive();
    if (!syn || !syn->input.opened || !syn->input.id || !response) return 1;
    auto parsed=p::parse_tcp6(*response); if (!parsed || parsed->flags!=0x12) return 1;
    client.flags=0x10; client.sequence=100; client.acknowledgement=51;
    auto ack=inject(client); if (!ack || ack->start_error || ack->direct.error) return 1;
    Socket peer{-1};
    for (int i=0;i<400 && peer.fd<0;++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
        peer.fd=::accept4(listener.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (peer.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (peer.fd<0) return 1;
    p::Bytes ping{'p','i','n','g'}; client.flags=0x18; client.payload=ping;
    if (!inject(client) || !receive()) return 1;
    std::array<std::uint8_t,8> buffer{}; ssize_t n=-1;
    for (int i=0;i<400 && n<0;++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
        n=::recv(peer.fd,buffer.data(),buffer.size(),0);
        if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (n!=4 || !std::ranges::equal(std::span(buffer).first(4),ping)) return 1;
    p::Bytes pong{'p','o','n','g'}; if (::send(peer.fd,pong.data(),pong.size(),MSG_NOSIGNAL)!=4) return 1;
    bool got=false;
    for (int i=0;i<400 && !got;++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
        auto bytes=receive(); if (!bytes) continue;
        auto packet=p::parse_tcp6(*bytes); if (!packet) return 1;
        if (!packet->payload.empty()) got=std::ranges::equal(packet->payload,pong);
    }
    if (!got) return 1;
    // A second established flow exceeds the direct limit and must be reset, not repeatedly dialed.
    client.source_port++; client.flags=2; client.sequence=199; client.acknowledgement=0; client.payload={};
    auto other=inject(client); if (!other || !other->input.opened || !receive()) return 1;
    client.flags=0x18; client.sequence=200; client.acknowledgement=51; client.payload=ping;
    auto refused=inject(client);
    if (!refused || !refused->start_error || !std::holds_alternative<t::DirectError>(*refused->start_error) ||
        std::get<t::DirectError>(*refused->start_error)!=t::DirectError::full ||
        !refused->reset || !refused->reset->notification.backpressured) return 1;
    auto data_ack=receive();
    if (!data_ack || !(parsed=p::parse_tcp6(*data_ack)) || parsed->flags!=0x10 || parsed->acknowledgement!=204) return 1;
    auto flushed=stack.step(now++,50); if (!flushed || !flushed->input.delivered) return 1;
    auto rst=receive(); if (!rst || !(parsed=p::parse_tcp6(*rst)) || parsed->flags!=0x14 || parsed->destination_port!=client.source_port) return 1;
    // Complete both half-closes on the first flow and verify it leaves the table.
    client.source_port=1234; client.flags=0x11; client.sequence=104;
    client.acknowledgement=55; client.payload={};
    auto closing=inject(client);
    if (!closing || !receive()) return 1;
    bool peer_eof=false;
    for (int i=0;i<400 && !peer_eof;++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
        auto count=::recv(peer.fd,buffer.data(),buffer.size(),0);
        if (!count) peer_eof=true;
        else if (count<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
        auto packet=receive(); if (packet) return 1;
    }
    if (!peer_eof || ::shutdown(peer.fd,SHUT_WR)) return 1;
    bool got_fin=false;
    for (int i=0;i<400 && !got_fin;++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
        auto packet=receive(); if (!packet) continue;
        auto view=p::parse_tcp6(*packet); if (!view) return 1;
        if (view->flags & 1) {
            if (view->sequence!=55) return 1;
            got_fin=true;
        }
    }
    if (!got_fin) return 1;
    client.flags=0x10; client.sequence=105; client.acknowledgement=56;
    if (!inject(client)) return 1;
    for (int i=0;i<10 && table->get(*syn->input.id);++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
    }
    if (table->get(*syn->input.id) || table->size()) return 1;
    // The released direct slot must accept a new flow.
    client.source_port=1236; client.sequence=299; client.acknowledgement=0; client.flags=2;
    auto replacement=inject(client); if (!replacement || !replacement->input.opened || !receive()) return 1;
    client.sequence=300; client.acknowledgement=51; client.flags=0x10;
    auto restarted=inject(client); if (!restarted || restarted->start_error || restarted->direct.error) return 1;
    Socket replacement_peer{-1};
    for (int i=0;i<400 && replacement_peer.fd<0;++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
        replacement_peer.fd=::accept4(listener.fd,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (replacement_peer.fd<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (replacement_peer.fd<0) return 1;
    client.flags=4; client.acknowledgement=0;
    auto reset_bytes=p::make_tcp6(client);
    if (!reset_bytes || !link.send(p::Side::first,*reset_bytes)) return 1;
    auto reset_step=stack.step(now++,50);
    if (!reset_step || reset_step->input.input_error!=t::ConnectionError::reset) return 1;
    bool closed_by_reset=false;
    for (int i=0;i<400 && !closed_by_reset;++i) {
        auto step=stack.step(now++,50); if (!step || step->direct.error) return 1;
        auto count=::recv(replacement_peer.fd,buffer.data(),buffer.size(),0);
        if (!count) closed_by_reset=true;
        else if (count<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    }
    if (!closed_by_reset || table->get(*replacement->input.id)) return 1;
    auto backwards=stack.step(0,50);
    if (backwards || !std::holds_alternative<t::EngineError>(backwards.error()) ||
        std::get<t::EngineError>(backwards.error())!=t::EngineError::time_reversed) return 1;
    // Stopping a stack removes its own half-open flows but preserves unrelated table entries.
    p::MemoryLink isolated;
    auto shared=t::ConnectionTable6::create(2,8);
    p::Tcp6View half{.source={10,0,0,2},.destination={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},.source_port=4000,
                     .destination_port=ntohs(addr.sin6_port),.sequence=1,.flags=2};
    auto external=shared->open(half,20,0); if (!external) return 1;
    half.source_port++;
    t::MemoryDirect6 stopped_stack(isolated,*shared,r::Matcher{},2);
    auto half_bytes=p::make_tcp6(half);
    if (!half_bytes || !isolated.send(p::Side::first,*half_bytes)) return 1;
    auto opened=stopped_stack.step(0,30);
    if (!opened || !opened->input.opened || shared->size()!=2) return 1;
    stopped_stack.stop(); stopped_stack.stop();
    if (shared->size()!=1 || !shared->get(*external)) return 1;
    auto after=stopped_stack.step(1,30);
    if (after || !std::holds_alternative<t::StackStopped>(after.error())) return 1;
    std::cout << "TCP integrated memory stack automatic dial, data, reset and close passed\n";
}
