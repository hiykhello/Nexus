import std;
import xudp;
import xudp.server_sessions;
namespace x=xudp;
int main() {
    x::Address a; a.length=4; a.port=53; a.bytes[0]=127; a.bytes[3]=1;
    auto b=a; b.port=54; std::array<std::uint8_t,1> data{7};
    x::ServerSessions sessions(2);
    auto first=sessions.receive({1,x::Kind::open,true,false,a,{},data});
    if (first.action!=x::ServerAction::opened || first.destination!=a || !first.has_data || sessions.accepts(first.token,a)) return 1;
    if (!sessions.sent(first.token,a) || !sessions.accepts(first.token,a) || sessions.accepts(first.token,b)) return 2;
    if (sessions.receive({1,x::Kind::open,true,false,a,{},data}).action!=x::ServerAction::duplicate) return 3;
    auto second=sessions.receive({2,x::Kind::open,false,false,b});
    if (second.action!=x::ServerAction::opened || second.has_data || !sessions.sent(second.token,b)) return 4;
    if (sessions.receive({3,x::Kind::open,false,false,a}).action!=x::ServerAction::limit) return 5;
    auto changed=sessions.receive({1,x::Kind::data,true,false,b,{},data});
    if (changed.action!=x::ServerAction::datagram || changed.destination!=b || !sessions.sent(first.token,b) || sessions.accepts(second.token,a)) return 6;
    auto ended=sessions.receive({1,x::Kind::end,true,true,{}, {},data});
    if (ended.action!=x::ServerAction::ended || !ended.error || sessions.accepts(first.token,a)) return 7;
    auto reopened=sessions.receive({1,x::Kind::open,true,false,a,{},data});
    if (reopened.action!=x::ServerAction::opened || reopened.token==first.token || sessions.sent(first.token,b) || sessions.accepts(reopened.token,a)) return 8;
    if (sessions.receive({9,x::Kind::data,true,false,{}, {},data}).action!=x::ServerAction::unknown) return 9;
    if (sessions.receive({0,x::Kind::keepalive}).action!=x::ServerAction::ignored) return 10;
    (void)sessions.receive({1,x::Kind::end});
    std::array<std::uint8_t,8> global{1};
    auto with_global=sessions.receive({3,x::Kind::open,true,false,a,global,data});
    if (with_global.action!=x::ServerAction::opened || sessions.size()!=2) return 11;
    (void)sessions.receive({3,x::Kind::end});
    auto zero=sessions.receive({3,x::Kind::open,true,false,a,std::array<std::uint8_t,8>{},{}});
    if (zero.action!=x::ServerAction::opened || !zero.has_data || !zero.payload.empty()) return 12;
    for (std::uint16_t port=1000;port<1065;++port) {
        auto destination=a; destination.port=port;
        if (!sessions.sent(zero.token,destination)) return 14;
    }
    auto oldest=a; oldest.port=1000; auto newest=a; newest.port=1064;
    if (sessions.accepts(zero.token,oldest) || !sessions.accepts(zero.token,newest) || sessions.accepts(second.token,newest)) return 15;
    sessions.close();
    if (sessions.sent(zero.token,a) || sessions.accepts(second.token,b) || sessions.receive({2,x::Kind::end}).action!=x::ServerAction::closed) return 13;
    std::cout << "XUDP server bounded sessions, authorization and generation passed\n";
}
