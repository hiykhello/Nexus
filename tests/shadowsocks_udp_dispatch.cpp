#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.rules;
import nexus.shadowsocks.udp_dispatch;
import nexus.shadowsocks.udp_packet;
namespace s=nexus::shadowsocks;
using namespace std::chrono_literals;
int main() {
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); sockaddr_in addr{};
    addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (fd<0 || bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 1;
    socklen_t len=sizeof(addr); getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len);
    timeval timeout{2,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    auto policy=nexus::rules::Matcher::compile({{{"ip-cidr","192.0.2.0/24"},{"domain-suffix","blocked.example"}}});
    if (!policy) return 2;
    s::UdpDispatcher dispatcher(std::move(*policy),2,2,2,100);
    auto t=std::chrono::steady_clock::time_point{}; std::array<std::uint8_t,16> key{};
    auto port=ntohs(addr.sin_port);
    s::UdpPeer peer{4,{127,0,0,1},2222}, target{4,{127,0,0,1},port}, blocked{4,{192,0,2,1},port};
    s::UdpPacket packet{{1},0,1000,{}, {3,7,'o','k','.','t','e','s','t',static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)}, {1,2,3}};
    auto begin=[&](auto now,auto wall,auto deadline) {
        packet.timestamp=wall; auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{}); ++packet.packet_id;
        return dispatcher.begin(key,wire,peer,now,wall,deadline);
    };
    auto op=begin(t,1000,t+10s); if (!op || dispatcher.pending()!=1 || op->address!=packet.address) return 3;
    auto deny_all=nexus::rules::Matcher::compile({{{"ip-cidr","0.0.0.0/0"}}});
    if (!deny_all || dispatcher.replace_policy(std::move(*deny_all))) return 24;
    auto second=begin(t,1000,t+10s);
    if (!second || begin(t,1000,t+10s).error()!=s::UdpDispatchError::full || !dispatcher.cancel(second->token)) return 4;
    std::array<s::UdpPeer,2> candidates{blocked,target};
    if (!dispatcher.complete(op->token,candidates,t+1s) || dispatcher.pending()!=0) return 5;
    deny_all=nexus::rules::Matcher::compile({{{"ip-cidr","0.0.0.0/0"}}});
    if (!deny_all || dispatcher.replace_policy(std::move(*deny_all))) return 25;
    if (dispatcher.complete(op->token,candidates,t+1s).error()!=s::UdpDispatchError::stale) return 6;
    std::array<std::uint8_t,16> buf{}; if (recv(fd,buf.data(),buf.size(),0)!=3) return 7;
    op=begin(t+1s,1001,t+2s); if (!op) return 8;
    if (dispatcher.complete(op->token,candidates,t+2s).error()!=s::UdpDispatchError::timeout || dispatcher.pending()) return 9;
    op=begin(t+2s,1002,t+10s); if (!op || !dispatcher.cancel(op->token) || dispatcher.cancel(op->token)) return 10;
    op=begin(t+2s,1002,t+3s); if (!op) return 11;
    auto expired=dispatcher.expire(t+3s,1003); if (!expired || *expired!=1 || dispatcher.pending()) return 12;
    packet.address={3,15,'b','l','o','c','k','e','d','.','e','x','a','m','p','l','e',static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
    if (begin(t+3s,1003,t+5s).error()!=s::UdpDispatchError::route || dispatcher.pending()) return 13;
    packet.address={3,7,'o','k','.','t','e','s','t',static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
    op=begin(t+3s,1003,t+200s); if (!op) return 14;
    expired=dispatcher.expire(t+66s,1066); if (!expired || dispatcher.sockets()!=0) return 15;
    packet.packet_id=0; auto replacement=begin(t+66s,1066,t+70s); if (!replacement) return 16;
    if (dispatcher.complete(op->token,candidates,t+66s).error()!=s::UdpDispatchError::session || dispatcher.sockets()!=0) return 17;
    if (!dispatcher.complete(replacement->token,candidates,t+66s) || recv(fd,buf.data(),buf.size(),0)!=3) return 18;
    op=begin(t+66s,1066,t+70s); if (!op) return 19;
    std::array<s::UdpPeer,65> too_many{};
    if (dispatcher.complete(op->token,too_many,t+66s).error()!=s::UdpDispatchError::limit || dispatcher.pending()) return 20;
    if (begin(t+65s,1065,t+70s).error()!=s::UdpDispatchError::time_reversed) return 21;
    auto empty=nexus::rules::Matcher::compile({}); if (!empty) return 22;
    s::UdpDispatcher tiny(std::move(*empty),1,1,2,13);
    packet.timestamp=2000; auto oversized=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    if (tiny.begin(key,oversized,peer,t,2000,t+5s).error()!=s::UdpDispatchError::full || tiny.pending()) return 23;
    ::close(fd);
    std::println("SS-2022 UDP bounded dispatch passed");
}
