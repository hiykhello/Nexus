import std;
import xudp;
import xudp.client_sessions;
namespace x=xudp;
int main() {
    x::Address a; a.length=4; a.port=53; a.bytes[0]=127; a.bytes[3]=1;
    auto b=a; b.port=54; std::array<std::uint8_t,2> bytes{1,2};
    x::ClientSessions sessions(2);
    auto first=sessions.open(a,bytes); if (!first || first->frame.session!=1 || sessions.size()!=0 || sessions.open(a,bytes).error()!=x::SessionError::busy) return 1;
    if (sessions.finish(first->token+1,true).error()!=x::SessionError::stale || !sessions.finish(first->token,true) || sessions.size()!=1) return 2;
    auto second=sessions.open(b,bytes); if (!second || !sessions.finish(second->token,true) || sessions.open(a,bytes).error()!=x::SessionError::limit) return 3;
    if (sessions.receive(x::Frame{1,x::Kind::data,true,false,b,{},bytes}).action!=x::Incoming::unauthorized) return 15;
    auto pending=sessions.send(1,b,bytes); if (!pending || sessions.receive(x::Frame{1,x::Kind::data,true,false,{}, {},bytes}).action!=x::Incoming::invalid || !sessions.finish(pending->token,true)) return 4;
    auto response=sessions.receive(x::Frame{1,x::Kind::data,true,false,{}, {},bytes});
    if (response.action!=x::Incoming::datagram || response.address!=a || !std::ranges::equal(response.payload,bytes)) return 5;
    response=sessions.receive(x::Frame{1,x::Kind::data,true,false,b,{},bytes}); if (response.action!=x::Incoming::datagram || response.address!=b) return 6;
    if (sessions.receive(x::Frame{2,x::Kind::data,true,false,a,{},bytes}).action!=x::Incoming::unauthorized) return 16;
    auto ending=sessions.end(1); if (!ending || !sessions.finish(ending->token,true) || sessions.receive(x::Frame{1,x::Kind::data,true}).action!=x::Incoming::unknown) return 7;
    auto next=sessions.open(a,bytes); if (!next || next->frame.session!=3 || !sessions.finish(next->token,true)) return 8;
    if (sessions.receive(x::Frame{2,x::Kind::end,true,true}).action!=x::Incoming::ended || sessions.size()!=1) return 9;
    auto failing=sessions.send(3,{},bytes); if (!failing || !sessions.finish(failing->token,false) || !sessions.is_closed() || sessions.size() || sessions.open(a,bytes).error()!=x::SessionError::closed) return 10;
    x::ClientSessions bounded(1); auto initial=bounded.open(a,bytes); if (!initial || !bounded.finish(initial->token,true)) return 17;
    for (std::uint16_t port=100;port<164;++port) {
        auto target=a; target.port=port; auto sent=bounded.send(1,target,bytes);
        if (!sent || !bounded.finish(sent->token,true)) return 18;
    }
    if (bounded.receive(x::Frame{1,x::Kind::data,true,false,a,{},bytes}).action!=x::Incoming::unauthorized) return 19;
    auto newest=a; newest.port=163;
    if (bounded.receive(x::Frame{1,x::Kind::data,true,false,newest,{},bytes}).action!=x::Incoming::datagram) return 20;
    auto last=bounded.end(1); if (!last || !bounded.finish(last->token,true)) return 21;
    auto replacement=bounded.open(a,bytes); if (!replacement || !bounded.finish(replacement->token,true)) return 22;
    if (bounded.receive(x::Frame{replacement->frame.session,x::Kind::data,true,false,newest,{},bytes}).action!=x::Incoming::unauthorized) return 23;
    x::ClientSessions limited(1); auto invalid=a; invalid.port=0;
    if (limited.open(invalid,bytes).error()!=x::SessionError::invalid_frame || limited.size()) return 11;
    for (std::uint32_t i=1;i<=65535;++i) {
        auto item=limited.open(a,{}); if (!item || item->frame.session!=i || !limited.finish(item->token,true)) return 12;
        auto end=limited.end(i); if (!end || !limited.finish(end->token,true)) return 13;
    }
    if (limited.open(a,{}).error()!=x::SessionError::exhausted) return 14;
    std::cout << "XUDP bounded client sessions, transactional writes and ID exhaustion passed\n";
}
