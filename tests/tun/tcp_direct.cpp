#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import tcp.direct;
namespace p = ::packet;
namespace t = tcp;
namespace r = ::rules;
struct Socket { int fd = -1; ~Socket() { if (fd >= 0) ::close(fd); } };
int main() {
    Socket listener{::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (listener.fd < 0) return 1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (::bind(listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || ::listen(listener.fd, 4)) return 1;
    socklen_t length=sizeof(address);
    if (::getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &length)) return 1;
    p::MemoryLink link;
    auto table = t::ConnectionTable::create(2, 8);
    t::MemoryEngine engine(link, *table);
    t::Direct4 invalid_direct(*table, engine, r::Matcher{}, 2);
    for (auto [destination,port] : {std::pair{p::Address4{},ntohs(address.sin_port)},
                                    std::pair{p::Address4{127,0,0,1},std::uint16_t{0}}}) {
        p::Tcp4View bad_syn{.source={10,0,0,1},.destination=destination,.source_port=1234,
                            .destination_port=port,.sequence=99,.flags=2};
        auto bad_id=table->open(bad_syn,50,0);
        if (!bad_id) return 1;
        auto bad_ack=bad_syn; bad_ack.sequence=100; bad_ack.acknowledgement=51; bad_ack.flags=0x10; bad_ack.window=8;
        if (!table->get(*bad_id)->input(bad_ack,0)) return 1;
        auto result=invalid_direct.start(*bad_id,0);
        if (result || std::get<t::DirectError>(result.error())!=t::DirectError::invalid_target || invalid_direct.size()) return 1;
        if (!table->abort(*bad_id)) return 1;
    }
    pollfd no_connection{listener.fd,POLLIN,0};
    if (::poll(&no_connection,1,50)!=0) return 1;
    p::Tcp4View syn{.source={10,0,0,1}, .destination={127,0,0,1}, .source_port=1234,
                    .destination_port=ntohs(address.sin_port), .sequence=99, .flags=2};
    auto id = table->open(syn, 50, 0);
    if (!id) return 1;
    auto* flow = table->get(*id);
    p::Bytes ping{'p','i','n','g'};
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=syn.source_port,
                    .destination_port=syn.destination_port, .sequence=100, .acknowledgement=51,
                    .flags=0x18, .window=8, .payload=ping};
    if (!flow->input(ack, 0)) return 1;
    auto deny = r::Matcher::compile({{{"ip-cidr", "127.0.0.0/8"}}});
    if (!deny) return 1;
    t::Direct4 blocked(*table, engine, std::move(*deny), 2);
    auto denied = blocked.start(*id, 0);
    if (denied || std::get<t::DirectError>(denied.error()) != t::DirectError::blocked || blocked.size()) return 1;
    for (r::Rule rule : {r::Rule{"source-ip-cidr","10.0.0.1/32"},r::Rule{"source-port","1234"}}) {
        auto source_deny=r::Matcher::compile({{rule},2});
        if (!source_deny) return 1;
        t::Direct4 source_blocked(*table,engine,std::move(*source_deny),2);
        auto source_denied=source_blocked.start(*id,0);
        if (source_denied || std::get<t::DirectError>(source_denied.error())!=t::DirectError::blocked || source_blocked.size()) return 1;
    }
    t::Direct4 direct(*table, engine, r::Matcher{}, 2);
    if (!direct.start(*id, 0) || direct.size() != 1 || direct.start(*id, 0).has_value()) return 1;
    Socket server;
    std::uint64_t now=0;
    for (int i=0; i<400 && server.fd<0; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error) return 1;
        server.fd = ::accept4(listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (server.fd < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 1;
        pollfd wait{.fd=listener.fd, .events=POLLIN, .revents=0}; (void)::poll(&wait, 1, 2);
    }
    if (server.fd < 0) return 1;
    std::array<std::uint8_t, 16> buffer{}; ssize_t n=-1;
    for (int i=0; i<400 && n<0; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error) return 1;
        n = ::recv(server.fd, buffer.data(), buffer.size(), 0);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 1;
        pollfd wait{.fd=server.fd, .events=POLLIN, .revents=0}; (void)::poll(&wait, 1, 2);
    }
    if (n != 4 || !std::ranges::equal(std::span(buffer).first(4), ping)) return 1;
    auto window = link.receive(p::Side::first);
    if (!window || !*window) return 1;
    p::Bytes pong{'p','o','n','g'};
    if (::send(server.fd, pong.data(), pong.size(), MSG_NOSIGNAL) != 4) return 1;
    bool got_reply=false;
    for (int i=0; i<400 && !got_reply; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error) return 1;
        got_reply = step->from_upstream == 4;
        pollfd wait{.fd=server.fd, .events=POLLOUT, .revents=0}; (void)::poll(&wait, 1, 2);
    }
    if (!got_reply) return 1;
    auto emitted = engine.service(now);
    auto bytes = link.receive(p::Side::first);
    if (!emitted || emitted->action != t::ServiceAction::data || !emitted->output.delivered || !bytes || !*bytes) return 1;
    auto packet = p::parse_tcp4(**bytes);
    if (!packet || packet->sequence != 51 || !std::ranges::equal(packet->payload, pong)) return 1;
    // The send buffer fills at eight unacknowledged bytes and pauses upstream reads.
    p::Bytes extra{'1','2','3','4','5'};
    if (::send(server.fd, extra.data(), extra.size(), MSG_NOSIGNAL) != 5) return 1;
    std::size_t received_extra=0;
    for (int i=0; i<400 && received_extra<4; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error) return 1;
        received_extra += step->from_upstream;
    }
    if (received_extra != 4 || flow->send_capacity() != 0) return 1;
    for (int i=0; i<5; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error || step->from_upstream) return 1;
    }
    ack.sequence=104; ack.acknowledgement=55; ack.flags=0x11; ack.payload={};
    if (!flow->input(ack, ++now)) return 1;
    bool resumed=false;
    for (int i=0; i<400 && !resumed; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error) return 1;
        resumed = step->from_upstream == 1;
    }
    if (!resumed) return 1;
    bool peer_eof=false;
    for (int i=0; i<400 && !peer_eof; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error) return 1;
        n = ::recv(server.fd, buffer.data(), buffer.size(), 0);
        if (!n) peer_eof=true;
        else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 1;
        pollfd wait{.fd=server.fd, .events=POLLIN, .revents=0}; (void)::poll(&wait, 1, 2);
    }
    if (!peer_eof || ::shutdown(server.fd, SHUT_WR)) return 1;
    // Acknowledge the remaining upstream bytes before local FIN can be sent.
    while (!flow->unsent(8).bytes.empty()) {
        auto sent = engine.service(now);
        if (!sent || sent->action != t::ServiceAction::data || !sent->output.delivered) return 1;
        auto sent_packet = link.receive(p::Side::first);
        if (!sent_packet || !*sent_packet) return 1;
    }
    ack.sequence=105; ack.acknowledgement=60; ack.flags=0x10;
    if (!flow->input(ack, ++now)) return 1;
    bool got_fin=false;
    for (int i=0; i<400 && !got_fin; ++i) {
        auto step = direct.step(++now);
        if (!step || step->error) return 1;
        auto service = engine.service(now);
        if (!service) return 1;
        got_fin = service->action == t::ServiceAction::fin && service->output.delivered;
    }
    if (!got_fin || !direct.close(*id) || direct.size() || direct.close(*id)) return 1;
    auto fin_packet = link.receive(p::Side::first);
    if (!fin_packet || !*fin_packet) return 1;
    // A closed local listening port must report connect failure and release the socket.
    ::close(listener.fd); listener.fd = -1;
    auto failed_id = table->open(syn, 70, now);
    // The original tuple is still retained; use a different source port.
    if (failed_id || failed_id.error() != t::TableError::duplicate) return 1;
    syn.source_port++;
    failed_id = table->open(syn, 70, now);
    ack.source_port=syn.source_port; ack.sequence=100; ack.acknowledgement=71; ack.flags=0x10; ack.payload={};
    if (!failed_id || !table->get(*failed_id)->input(ack, now)) return 1;
    auto started = direct.start(*failed_id, now);
    bool failed = !started && std::holds_alternative<std::error_code>(started.error());
    for (int i=0; started && i<400 && !failed; ++i) {
        auto step = direct.step(++now);
        if (!step) return 1;
        failed = step->error && std::holds_alternative<std::error_code>(*step->error);
        pollfd wait{.fd=-1, .events=0, .revents=0}; (void)::poll(&wait, 0, 2);
    }
    for (int i=0; i<400 && direct.size(); ++i) {
        auto step = direct.step(++now);
        if (!step) return 1;
    }
    auto reset_packet = link.receive(p::Side::first);
    if (!failed || direct.size() || !reset_packet || !*reset_packet) return 1;
    auto reset = p::parse_tcp4(**reset_packet);
    if (!reset || reset->flags != 0x14 || reset->destination_port != syn.source_port ||
        table->get(*failed_id)->state() != t::ConnectionState::reset) return 1;
    // A previous pending reply must be flushed before a failed dial can queue its RST.
    p::MemoryLink pressured({1500,1,1500});
    auto small = t::ConnectionTable::create(2,8);
    syn.source_port=2000;
    auto old = small->open(syn,80,0);
    ack.source_port=syn.source_port; ack.acknowledgement=81; ack.sequence=100; ack.flags=0x10;
    if (!old || !small->get(*old)->input(ack,0)) return 1;
    syn.source_port++;
    auto rejected = small->open(syn,90,0);
    ack.source_port=syn.source_port; ack.acknowledgement=91;
    if (!rejected || !small->get(*rejected)->input(ack,0)) return 1;
    t::MemoryEngine delayed(pressured,*small);
    p::Bytes sentinel{42};
    if (!pressured.send(p::Side::second,sentinel)) return 1;
    auto pending = delayed.reset(*old,1);
    if (!pending || !pending->notification.backpressured) return 1;
    t::Direct4 retry(*small,delayed,r::Matcher{},2);
    auto attempt = retry.start(*rejected, 1);
    bool saw_failure = !attempt && std::holds_alternative<std::error_code>(attempt.error());
    for (int i=0; attempt && i<400 && !saw_failure; ++i) {
        auto step = retry.step(2);
        if (!step) return 1;
        saw_failure = step->error && std::holds_alternative<std::error_code>(*step->error);
    }
    if (!saw_failure || retry.size()!=1 || small->get(*rejected)->state()!=t::ConnectionState::established) return 1;
    auto first = pressured.receive(p::Side::first);
    auto flush = delayed.step(3,0);
    auto old_rst = pressured.receive(p::Side::first);
    if (!first || !*first || **first!=sentinel || !flush || !flush->delivered || !old_rst || !*old_rst) return 1;
    auto retried = retry.step(4);
    auto new_rst = pressured.receive(p::Side::first);
    if (!retried || !retried->retired || retry.size() || !new_rst || !*new_rst) return 1;
    auto decoded = p::parse_tcp4(**new_rst);
    if (!decoded || decoded->flags!=0x14 || decoded->destination_port!=syn.source_port ||
        !small->reclaim(*rejected,4)) return 1;
    std::cout << "TCP direct loopback, policy, data and half-close passed\n";
}
