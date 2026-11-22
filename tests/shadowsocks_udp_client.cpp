import std;
import shadowsocks.udp_client;
import shadowsocks.udp_cipher;
namespace s=shadowsocks;
using namespace std::chrono_literals;

int main() {
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),0);
    std::array<std::uint8_t,8> client{1,2,3,4,5,6,7,8}, server{8,7,6,5,4,3,2,1}, other{9};
    std::vector<std::uint8_t> address{1,127,0,0,1,0,53}, payload{42};
    auto t=std::chrono::steady_clock::time_point{};
    for (std::size_t size : {16u,32u}) {
        auto psk=std::span{key}.first(size);
        s::UdpClientSession owner(psk,client,1);
        auto first=owner.request(address,payload,{},t,1000);
        auto second=owner.request(address,payload,{},t,1000);
        if (!first || !second) return 1;
        auto decoded=s::decode_udp_packet(psk,s::UdpDirection::client,*first,1000);
        auto decoded2=s::decode_udp_packet(psk,s::UdpDirection::client,*second,1000);
        if (!decoded || !decoded2 || decoded->session_id!=client || decoded->packet_id!=0 ||
            decoded2->packet_id!=1 || decoded->address!=address || decoded->payload!=payload) return 2;
        if (owner.request({},payload,{},t,1000).error()!=s::UdpClientError::packet) return 3;
        auto next=owner.request(address,payload,{},t,1000);
        if (!next) return 4;
        auto decoded3=s::decode_udp_packet(psk,s::UdpDirection::client,*next,1000);
        if (!decoded3 || decoded3->packet_id!=3) return 4;
        auto wire=[&](auto id,std::uint64_t number,auto recipient) {
            return *s::encode_udp_packet(psk,s::UdpDirection::server,
                s::UdpPacket{id,number,1000,recipient,address,payload},{});
        };
        auto response=wire(server,2,client);
        auto forged=response; forged.back()^=1;
        if (owner.receive(forged,t,1000).error()!=s::UdpClientError::packet ||
            owner.receive(wire(server,2,other),t,1000).error()!=s::UdpClientError::packet ||
            owner.receive(response,t+31s,1031).error()!=s::UdpClientError::packet) return 5;
        // Use a fresh owner after the 1031 timestamp test: clocks cannot go backwards.
        s::UdpClientSession receiving(psk,client,1);
        if (receiving.receive(forged,t,1000).error()!=s::UdpClientError::packet ||
            !receiving.receive(response,t,1000) || receiving.receive(response,t,1000).error()!=s::UdpClientError::duplicate ||
            !receiving.receive(wire(server,1,client),t,1000) || !receiving.receive(wire(server,1027,client),t,1000) ||
            receiving.receive(wire(server,1,client),t,1000).error()!=s::UdpClientError::too_old ||
            receiving.receive(wire(other,0,client),t,1000).error()!=s::UdpClientError::full) return 6;
        if (receiving.request(address,payload,{},t,999).error()!=s::UdpClientError::time_reversed ||
            receiving.receive(response,t+1s,1001).error()!=s::UdpClientError::time_reversed) return 7;
        s::UdpClientSession stalled(psk,client,1);
        if (!stalled.receive(response,t,1000) ||
            stalled.receive(wire(server,3,client),t+1s,1000).has_value()==false ||
            stalled.receive(wire(server,4,client),t+2s,1000).error()!=s::UdpClientError::time_reversed ||
            stalled.request(address,payload,{},t+3s,1003).error()!=s::UdpClientError::time_reversed) return 9;
        s::UdpClientSession reversed(psk,client,1);
        if (!reversed.request(address,payload,{},t+1s,1000) ||
            reversed.receive(response,t,1000).error()!=s::UdpClientError::time_reversed) return 10;
        s::UdpClientSession wall_reversed(psk,client,1);
        if (!wall_reversed.request(address,payload,{},t,1000) ||
            !wall_reversed.request(address,payload,{},t+2s,1001) ||
            wall_reversed.request(address,payload,{},t+2s,1000).error()!=s::UdpClientError::time_reversed) return 11;

        s::UdpClientPool pool(psk,2,3,4);
        auto a=pool.open(), b=pool.open();
        if (!a || !b || *a==*b || pool.open().error()!=s::UdpClientError::full) return 12;
        auto req=pool.request(*a,address,payload,{},t,1000);
        if (!req || !s::decode_udp_packet(psk,s::UdpDirection::client,*req,1000)) return 13;
        auto pool_server=server;
        while (pool_server==*a || pool_server==*b) ++pool_server[0];
        auto response_a=wire(pool_server,0,*a);
        if (!pool.receive(*a,response_a,t,1000) ||
            pool.receive(*a,response_a,t,1000).error()!=s::UdpClientError::duplicate) return 14;
        if (!pool.close(*a) || pool.close(*a) ||
            pool.request(*a,address,payload,{},t,1000).error()!=s::UdpClientError::missing) return 15;
        auto c=pool.open();
        if (!c || *c==*a || *c==*b || pool.open().error()!=s::UdpClientError::full) return 16;
        // The same server session cannot be attributed to a different client.
        if (pool.receive(*b,wire(pool_server,1,*b),t,1000).error()!=s::UdpClientError::session_conflict ||
            pool.request(*c,address,payload,{},t,1000).error()!=s::UdpClientError::failed ||
            pool.open().error()!=s::UdpClientError::failed) return 17;
        s::UdpClientPool collision(psk,2,2,2);
        auto x=collision.open(), y=collision.open();
        if (!x || !y || !collision.close(*x)) return 18;
        if (collision.receive(*y,wire(*x,0,*y),t,1000).error()!=s::UdpClientError::session_conflict ||
            collision.request(*y,address,payload,{},t,1000).error()!=s::UdpClientError::failed) return 19;
        s::UdpClientPool self_collision(psk,1,1,1);
        auto self=self_collision.open();
        if (!self) return 21;
        auto valid=wire(server==*self ? other : server,0,*self);
        auto plain=s::open_udp(psk,valid);
        if (!plain) return 22;
        std::ranges::copy(*self,plain->separate_header.begin());
        auto conflicting=s::seal_udp(psk,plain->separate_header,plain->body);
        if (!conflicting || self_collision.receive(*self,*conflicting,t,1000).error()!=s::UdpClientError::session_conflict ||
            self_collision.request(*self,address,payload,{},t,1000).error()!=s::UdpClientError::failed) return 23;
        s::UdpClientPool clocks(psk,2,2,2);
        auto one=clocks.open(), two=clocks.open();
        if (!one || !two || !clocks.request(*one,address,payload,{},t,1000) ||
            clocks.request(*two,address,payload,{},t+2s,1000).error()!=s::UdpClientError::time_reversed ||
            clocks.request(*one,address,payload,{},t+3s,1003).error()!=s::UdpClientError::failed) return 20;
    }
    s::UdpClientSession invalid(std::span{key}.first(15),client,1);
    if (invalid.request(address,payload,{},t,1000).error()!=s::UdpClientError::invalid_key) return 8;
    std::println("SS-2022 UDP client session tests passed");
}
