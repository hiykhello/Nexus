#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.shadowsocks.udp_relay;
namespace s=nexus::shadowsocks;
using namespace std::chrono_literals;
int main() {
    int target=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0), attacker=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    if (target<0 || attacker<0) return 1;
    sockaddr_in local{}; local.sin_family=AF_INET; local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(target,reinterpret_cast<sockaddr*>(&local),sizeof(local)) || bind(attacker,reinterpret_cast<sockaddr*>(&local),sizeof(local))) return 2;
    socklen_t len=sizeof(local); if (getsockname(target,reinterpret_cast<sockaddr*>(&local),&len)) return 3;
    timeval timeout{2,0}; setsockopt(target,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    s::UdpPeer dest{4,{127,0,0,1},ntohs(local.sin_port)};
    std::array<std::uint8_t,8> id{1}; std::array<std::uint8_t,3> data{1,2,3};
    s::UdpRelay relay(1,1);
    if (!relay.send(id,dest,data) || relay.size()!=1) return 4;
    std::array<std::uint8_t,100> buf{}; sockaddr_in sender{}; len=sizeof(sender);
    auto n=recvfrom(target,buf.data(),buf.size(),0,reinterpret_cast<sockaddr*>(&sender),&len);
    if (n!=3 || !std::ranges::equal(data,std::span{buf}.first<3>())) return 5;
    if (relay.send(std::array<std::uint8_t,8>{2},dest,data).error().kind!=s::UdpRelayError::session_limit) return 6;
    auto other=dest; ++other.port;
    if (relay.send(id,other,data).error().kind!=s::UdpRelayError::target_limit) return 7;
    std::array<std::uint8_t,3> forged{9,9,9};
    if (sendto(attacker,forged.data(),forged.size(),0,reinterpret_cast<sockaddr*>(&sender),len)!=3) return 8;
    auto forged_deadline=std::chrono::steady_clock::now()+20ms;
    while (std::chrono::steady_clock::now()<forged_deadline) {
        auto result=relay.poll();
        if (!result || *result) return 15;
        std::this_thread::sleep_for(1ms);
    }
    if (sendto(target,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&sender),len)!=3) return 9;
    auto deadline=std::chrono::steady_clock::now()+2s;
    std::optional<s::UdpRelayReply> reply;
    while (std::chrono::steady_clock::now()<deadline && !reply) {
        auto result=relay.poll(); if (!result) return 10;
        reply=std::move(*result);
        if (!reply) std::this_thread::sleep_for(1ms);
    }
    if (!reply || reply->session!=id || reply->source!=dest || !std::ranges::equal(reply->payload,data)) return 11;
    relay.close(id);
    if (relay.size()!=0 || !relay.poll() || *relay.poll()) return 12;
    // A forged reply on one session must not hide another session's valid
    // reply from the same bounded poll.
    s::UdpRelay pair(2,1);
    std::array<std::uint8_t,8> second{2};
    if (!pair.send(id,dest,data) || !pair.send(second,dest,data)) return 16;
    std::array<sockaddr_in,2> sources{};
    for (auto& source:sources) {
        len=sizeof(source);
        if (recvfrom(target,buf.data(),buf.size(),0,reinterpret_cast<sockaddr*>(&source),&len)!=3) return 17;
    }
    if (sendto(attacker,forged.data(),forged.size(),0,reinterpret_cast<sockaddr*>(&sources[0]),sizeof(sources[0]))!=3 ||
        sendto(target,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&sources[1]),sizeof(sources[1]))!=3) return 18;
    auto next=pair.poll();
    if (!next || !*next || (**next).session!=second || (**next).payload!=std::vector<std::uint8_t>(data.begin(),data.end())) return 19;
    s::UdpRelay none(1,0);
    if (none.send(id,dest,data).error().kind!=s::UdpRelayError::target_limit || none.size()!=0) return 13;
    std::vector<std::uint8_t> oversized(65536);
    if (relay.send(id,dest,oversized).error().kind!=s::UdpRelayError::system || relay.size()!=0) return 14;
    ::close(target); ::close(attacker);
    std::println("SS-2022 UDP relay loopback and source filter passed");
}
