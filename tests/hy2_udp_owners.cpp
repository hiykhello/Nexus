import std;
import hysteria2.udp;
import hysteria2.udp_transmitter;
import hysteria2.udp_receiver;
import hysteria2.sessions;
import hysteria2.fragments;
namespace h=hysteria2;
using namespace std::chrono_literals;
struct Observer {
    unsigned created=0,closed=0;
    bool allow=true;
    auto session_created(h::UdpSessionHandle,std::uint32_t) noexcept -> bool { ++created;return allow; }
    auto session_closed(h::UdpSessionHandle,std::uint32_t) noexcept -> void { ++closed; }
};
auto main() -> int {
    Observer observer;h::UdpReceiver<Observer,2,2> receiver(observer,true,100ms,65535,10ms);h::UdpTransmitter sender;
    auto now=h::UdpClock::now();std::array<std::uint8_t,65000> payload{};
    for(std::size_t i=0;i<payload.size();++i)payload[i]=static_cast<std::uint8_t>(i*73);
    for(auto size:{0u,1u,1100u,65000u}){
        auto ticket=sender.submit(0,0xffff,"[::1]:53",std::span(payload).first(size),1150);if(!ticket || *sender.done(*ticket))return 1;
        if(sender.submit(1,1,"x:1",{},1150).error()!=h::UdpSendError::busy)return 2;
        std::vector<std::vector<std::uint8_t>> packets;
        while(auto pending=sender.pending()){
            std::vector<std::uint8_t> packet(pending->header.begin(),pending->header.end());packet.insert(packet.end(),pending->payload.begin(),pending->payload.end());packets.push_back(std::move(packet));
            auto check=sender.pending();if(!std::ranges::equal(check->header,pending->header)||!std::ranges::equal(check->payload,pending->payload))return 3;
            if(!sender.accepted())return 4;
        }
        if(!*sender.done(*ticket))return 5;
        std::reverse(packets.begin(),packets.end());for(auto const& packet:packets){auto result=receiver.receive(packet,now);if(result!=h::ReassemblyStatus::incomplete && result!=h::ReassemblyStatus::accepted)return 6;}
        auto result=receiver.packet(now);if(!result || result->session!=0 || result->address!="[::1]:53" || !std::ranges::equal(result->payload,std::span(payload).first(size)))return 7;
        if(receiver.receive(packets.back(),now)!=h::ReassemblyStatus::backpressure || !receiver.consume())return 8;
    }
    if(observer.created!=1 || observer.closed || receiver.buffered_bytes() || receiver.pending_packets())return 9;
    auto first=receiver.open(0,now);if(!first)return 10;
    if(!receiver.expiry() || *receiver.expiry()!=now+100ms)return 11;
    if(!receiver.expire(now+100ms) || observer.closed!=1 || receiver.live(*first,now+100ms))return 12;
    auto second=receiver.open(0,now+100ms);if(!second || *first==*second)return 13;
    auto ticket=sender.submit(0,0,"example.test:53",payload,1150);if(!ticket)return 14;
    auto fragment=sender.pending();std::vector<std::uint8_t> wire(fragment->header.begin(),fragment->header.end());wire.insert(wire.end(),fragment->payload.begin(),fragment->payload.end());
    if(receiver.receive(wire,now+100ms)!=h::ReassemblyStatus::incomplete || receiver.buffered_bytes()==0 || *receiver.expiry()!=now+110ms)return 15;
    receiver.expire(now+110ms);if(receiver.buffered_bytes() || receiver.pending_packets()!=1 || *receiver.expiry()!=now+120ms)return 16;
    receiver.expire(now+120ms);if(receiver.pending_packets())return 17;
    sender.cancel();if(sender.done(*ticket).error()!=h::UdpSendError::canceled)return 18;
    receiver.close();if(observer.closed!=2 || receiver.size())return 19;
    Observer client_observer;h::UdpReceiver<Observer,2,2> client(client_observer,false);
    if(client.receive(wire,now)!=h::ReassemblyStatus::session || client_observer.created)return 20;
    if(!client.open(0,now) || client.receive(wire,now)!=h::ReassemblyStatus::incomplete)return 21;
    if(client.expire(now-1ms))return 22;
    {
        Observer queued_observer;h::UdpReceiver<Observer,2,2,3> queued(queued_observer,false,100ms,65535,10ms);
        auto owner=queued.open(9,now);if(!owner)return 23;
        std::array<std::uint8_t,1> a{1},b{2},c{3},d{4};
        auto first=h::encode_udp_packet({9,1,0,1,"x:1",a});
        auto second=h::encode_udp_packet({9,2,0,1,"x:1",b});
        auto third=h::encode_udp_packet({9,3,0,1,"x:1",c});
        auto fourth=h::encode_udp_packet({9,4,0,1,"x:1",d});
        if(!first || !second || !third || !fourth)return 24;
        if(queued.receive(*first,now)!=h::ReassemblyStatus::accepted)return 25;
        auto borrowed=queued.packet(now);if(!borrowed || !std::ranges::equal(borrowed->payload,a))return 26;
        if(queued.receive(*second,now)!=h::ReassemblyStatus::accepted || queued.receive(*third,now)!=h::ReassemblyStatus::accepted ||
            queued.receive(*fourth,now)!=h::ReassemblyStatus::backpressure || !std::ranges::equal(borrowed->payload,a))return 27;
        if(!queued.consume() || !std::ranges::equal(queued.packet(now)->payload,b))return 28;
        if(queued.receive(*fourth,now)!=h::ReassemblyStatus::accepted || !queued.consume() || !std::ranges::equal(queued.packet(now)->payload,c))return 29;
        if(!queued.consume() || !std::ranges::equal(queued.packet(now)->payload,d) || !queued.consume() || queued.packet(now))return 30;
        if(queued.receive(*first,now)!=h::ReassemblyStatus::accepted || !queued.release(*owner,now) || queued.packet(now))return 31;
        auto replacement=queued.open(9,now);if(!replacement || *replacement==*owner || queued.receive(*second,now)!=h::ReassemblyStatus::accepted || !std::ranges::equal(queued.packet(now)->payload,b))return 32;
    }
    {
        h::UdpMemoryBudget budget(4);Observer a,b;
        h::UdpReceiver<Observer,2,2,2> first(a,false,100ms,65535,10ms,&budget),second(b,false,100ms,65535,10ms,&budget);
        if(!first.open(1,now) || !second.open(1,now))return 33;
        std::array<std::uint8_t,4> value{1,2,3,4};
        auto packet=h::encode_udp_packet({1,1,0,1,"x:1",value});
        auto fragment=h::encode_udp_packet({1,2,0,2,"x:1",value});
        if(!packet || !fragment || first.receive(*packet,now)!=h::ReassemblyStatus::accepted ||
            first.receive(*packet,now)!=h::ReassemblyStatus::accepted || budget.used()!=4)return 34;
        if(second.receive(*fragment,now)!=h::ReassemblyStatus::full || second.pending_packets() || budget.used()!=4)return 35;
        if(!first.consume() || !first.consume() || budget.used() ||
            second.receive(*fragment,now)!=h::ReassemblyStatus::incomplete || budget.used()!=4)return 36;
        if(!second.expire(now+10ms) || budget.used() || second.pending_packets()!=1)return 37;
        second.close();if(budget.used())return 38;
    }
    std::println("Hy2 UDP owners: empty/65000B reverse fragments, borrow stability, backpressure, exact fragment/session expiry, generation, client admission, cancel; sender={} receiver={}",sizeof(sender),sizeof(receiver));
}
