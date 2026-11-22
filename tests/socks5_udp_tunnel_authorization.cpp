import std;
import socks5.udp_tunnel_authorization;
namespace s=socks5;
int main() {
    s::UdpTunnelAuthorization a,b;
    s::UdpPeer first{1,{127,0,0,1},53}, second{1,{127,0,0,2},53};
    auto token=a.begin(first);
    if (!token || a.classify(first)!=s::UdpTunnelReply::pending || a.classify(second)!=s::UdpTunnelReply::rejected || a.accepts(first) || a.begin(second).error()!=s::Status::send_in_progress || a.finish(*token+1,true).error()!=s::Status::stale_send) return 1;
    if (!a.finish(*token,false) || a.classify(first)!=s::UdpTunnelReply::rejected || a.accepts(first)) return 2;
    token=a.begin(first); if (!token || !a.finish(*token,true) || a.classify(first)!=s::UdpTunnelReply::accepted || !a.accepts(first) || b.accepts(first)) return 3;
    for (unsigned i=2;i<=64;++i) {
        s::UdpPeer peer{1,{10,0,0,static_cast<std::uint8_t>(i)},53};
        auto n=a.begin(peer); if (!n || !a.finish(*n,true)) return 4;
    }
    token=a.begin(second); if (!token || a.classify(first)!=s::UdpTunnelReply::accepted || a.classify(second)!=s::UdpTunnelReply::pending || !a.finish(*token,false) || !a.accepts(first) || a.accepts(second)) return 5;
    token=a.begin(second); if (!token || !a.finish(*token,true) || a.accepts(first) || !a.accepts(second)) return 6;
    if (a.begin({1,{},53}).error()!=s::Status::invalid_address) return 7;
    token=a.begin(first); if (!token) return 8;
    a.close(); if (a.accepts(second) || a.finish(*token,true).error()!=s::Status::association_closed || a.begin(first).error()!=s::Status::association_closed) return 9;
}
