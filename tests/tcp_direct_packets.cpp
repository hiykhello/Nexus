#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.tcp.direct;
namespace p = nexus::packet;
namespace t = nexus::tcp;
namespace r = nexus::rules;
struct Socket { int fd; ~Socket() { if (fd >= 0) ::close(fd); } };
int main() {
    Socket listener{::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (listener.fd < 0) return 1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (::bind(listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || ::listen(listener.fd, 4)) return 1;
    socklen_t length=sizeof(address);
    if (::getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &length)) return 1;
    p::MemoryLink link;
    auto table = t::ConnectionTable::create(2, 32);
    t::MemoryEngine engine(link, *table);
    t::Direct4 direct(*table, engine, r::Matcher{}, 2);
    p::Tcp4View client{.source={10,0,0,1}, .destination={127,0,0,1}, .source_port=1234,
                       .destination_port=ntohs(address.sin_port), .sequence=99, .flags=2, .window=32};
    auto inject = [&](p::Tcp4View v, std::uint64_t now) -> std::optional<t::EngineStep> {
        auto bytes=p::make_tcp4(v);
        if (!bytes || !link.send(p::Side::first, *bytes)) return {};
        auto result=engine.step(now, 50);
        if (!result || result->rejected || result->input_error) return {};
        return *result;
    };
    auto receive = [&]() -> std::optional<p::Bytes> {
        auto bytes=link.receive(p::Side::first);
        if (!bytes || !*bytes) return {};
        return std::move(**bytes);
    };
    auto opened=inject(client, 0);
    auto synack=receive();
    if (!opened || !opened->opened || !opened->id || !synack) return 1;
    auto view=p::parse_tcp4(*synack);
    if (!view || view->flags != 0x12 || view->sequence != 50 || view->acknowledgement != 100) return 1;
    client.sequence=100; client.acknowledgement=51; client.flags=0x10;
    if (!inject(client, 1) || !direct.start(*opened->id, 1)) return 1;
    Socket server{-1}; std::uint64_t now=1;
    for (int i=0; i<400 && server.fd<0; ++i) {
        auto step=direct.step(++now);
        if (!step || step->error) return 1;
        server.fd=::accept4(listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (server.fd < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 1;
        pollfd wait{.fd=listener.fd,.events=POLLIN,.revents=0}; (void)::poll(&wait,1,2);
    }
    if (server.fd < 0) return 1;
    p::Bytes ping{'p','i','n','g'};
    client.flags=0x19; client.payload=ping;
    if (!inject(client, ++now)) return 1;
    auto accepted=receive();
    if (!accepted || !(view=p::parse_tcp4(*accepted)) || view->acknowledgement != 105) return 1;
    std::array<std::uint8_t, 16> buffer{}; std::size_t count=0; bool eof=false;
    for (int i=0; i<400 && !eof; ++i) {
        auto step=direct.step(++now);
        if (!step || step->error) return 1;
        auto n=::recv(server.fd, buffer.data()+count, buffer.size()-count, 0);
        if (n>0) count+=static_cast<std::size_t>(n);
        else if (!n) eof=true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK) return 1;
        pollfd wait{.fd=server.fd,.events=POLLIN,.revents=0}; (void)::poll(&wait,1,2);
    }
    if (!eof || count != 4 || !std::ranges::equal(std::span(buffer).first(count), ping)) return 1;
    p::Bytes pong{'p','o','n','g'};
    if (::send(server.fd,pong.data(),pong.size(),MSG_NOSIGNAL) != 4 || ::shutdown(server.fd,SHUT_WR)) return 1;
    bool got_data=false, got_fin=false; std::uint32_t server_next=51;
    for (int i=0; i<400 && !got_fin; ++i) {
        auto upstream=direct.step(++now);
        if (!upstream || upstream->error) return 1;
        auto service=engine.service(now);
        if (!service || service->output.connection_error || service->output.output_error) return 1;
        if (service->output.delivered) {
            auto bytes=receive();
            if (!bytes || !(view=p::parse_tcp4(*bytes))) return 1;
            if (!view->payload.empty()) {
                if (view->sequence != server_next || !std::ranges::equal(view->payload,pong)) return 1;
                server_next += static_cast<std::uint32_t>(view->payload.size()); got_data=true;
            }
            if (view->flags & 1) { if (view->sequence != server_next) return 1; ++server_next; got_fin=true; }
            client.sequence=105; client.acknowledgement=server_next; client.flags=0x10; client.payload={};
            if (!inject(client, ++now)) return 1;
        }
        pollfd wait{.fd=server.fd,.events=POLLIN,.revents=0}; (void)::poll(&wait,1,2);
    }
    if (!got_data || !got_fin || !table->get(*opened->id)->send_closed()) return 1;
    auto reaped=engine.service(++now);
    if (!reaped || reaped->action != t::ServiceAction::reclaimed || table->size()) return 1;
    auto retired=direct.step(++now);
    if (!retired || !retired->retired || direct.size()) return 1;
    std::cout << "TCP packet ingress to real loopback and bidirectional close passed\n";
}
