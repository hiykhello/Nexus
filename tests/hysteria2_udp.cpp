import std;
import quic.varint;
import hysteria2.wire;
import hysteria2.udp;
import hysteria2.sessions;
import hysteria2.fragments;
namespace h=hysteria2;
using namespace std::chrono_literals;
auto wire_vectors() -> bool {
    std::array<std::uint8_t,2> data{0,255};
    h::UdpPacket packet{0x01020304,0x0506,127,1,"example.test:53",data};
    auto wire=h::encode_udp_packet(packet);
    std::vector<std::uint8_t> expected{1,2,3,4,5,6,127,1,15,'e','x','a','m','p','l','e','.','t','e','s','t',':','5','3',0,255};
    if (!wire || *wire!=expected) return false;
    auto decoded=h::parse_udp_packet(*wire);
    if (!decoded || decoded->session!=packet.session || decoded->packet!=packet.packet || decoded->fragment!=127 ||
        decoded->count!=1 || decoded->address!=packet.address || !std::ranges::equal(decoded->payload,data)) return false;
    for (std::size_t size=0;size<wire->size()-data.size();++size)
        if (h::parse_udp_packet(std::span(*wire).first(size))) return false;
    for (auto count:{0u,2u}) {
        auto bad=*wire; bad[7]=static_cast<std::uint8_t>(count);
        if (h::parse_udp_packet(bad)) return false;
    }
    if (h::encode_udp_packet({1,2,0,1,"",data}) || h::encode_udp_packet({1,2,0,0,"x:1",data}) ||
        h::encode_udp_packet({1,2,0,1,"x:1",std::vector<std::uint8_t>(65536)})) return false;
    std::vector<std::uint8_t> maximum(65535,123);
    auto empty=h::FragmentPlan::create(0,0,"x:1",{},12);
    if (!empty || empty->count()!=1 || !empty->fragment(0) || !empty->fragment(0)->payload.empty() || empty->fragment(1)) return false;
    auto single=h::FragmentPlan::create(0,0,"x:1",data,14);
    if (!single || single->count()!=1 || single->fragment(0)->payload.size()!=data.size()) return false;
    if (h::FragmentPlan::create(1,2,"x:1",data,12) || h::FragmentPlan::create(1,2,"x:1",maximum,13)) return false;
    auto plan=h::FragmentPlan::create(1,2,"x:1",maximum,512);
    if (!plan || plan->count()!=132 || plan->fragment(plan->count())) return false;
    std::size_t total=0;
    for (std::size_t i=0;i<plan->count();++i) {
        auto part=plan->fragment(i); auto encoded=part ? h::encode_udp_packet(*part) : std::unexpected(h::UdpError::invalid_fragment);
        if (!part || !encoded || encoded->size()>512 || part->fragment!=i || part->count!=plan->count()) return false;
        auto decoded=h::parse_udp_packet(*encoded);
        if (!decoded || decoded->address!="x:1" || !std::ranges::equal(decoded->payload,part->payload)) return false;
        total+=part->payload.size();
    }
    return total==maximum.size();
}
auto session_generations() -> bool {
    auto now=h::UdpClock::time_point{}+1s;
    h::UdpSessions<2> sessions(50ms);
    auto zero=sessions.acquire(0,now),other=sessions.acquire(1,now);
    if (!zero || !zero->created || !other || sessions.size()!=2 || sessions.acquire(2,now)) return false;
    auto reused=sessions.acquire(0,now+10ms);
    if (!reused || reused->created || reused->handle!=zero->handle || !sessions.live(zero->handle,now+59ms)) return false;
    auto expired=sessions.acquire(0,now+60ms);
    if (expired || expired.error()!=h::UdpSessionError::expired || sessions.touch(zero->handle,now+60ms)) return false;
    std::vector<std::uint32_t> released;
    if (sessions.expire(now+60ms,[&](auto,std::uint32_t id) { released.push_back(id); })!=2 || sessions.size() || released!=std::vector<std::uint32_t>{0,1}) return false;
    auto fresh=sessions.acquire(0,now+60ms);
    if (!fresh || !fresh->created || fresh->handle==zero->handle || sessions.valid(zero->handle) || sessions.release(zero->handle)) return false;
    if (sessions.acquire(2,now+59ms) || sessions.touch(fresh->handle,now+59ms)) return false;
    unsigned closed=0;
    sessions.close([&](auto handle,std::uint32_t id) { if (handle!=fresh->handle || id) closed+=10; ++closed; });
    return closed==1 && !sessions.size() && !sessions.valid(fresh->handle);
}
auto shuffled_fragments() -> bool {
    auto now=h::UdpClock::time_point{}+1s;
    h::UdpSessions<4> sessions(1s); auto one=sessions.acquire(7,now),two=sessions.acquire(8,now);
    if (!one || !two) return false;
    h::UdpReassembler<h::UdpSessions<4>,4> assembly(sessions);
    std::vector<std::uint8_t> payload(65535);
    for (std::size_t i=0;i<payload.size();++i) payload[i]=static_cast<std::uint8_t>(i);
    auto plan=h::FragmentPlan::create(7,65535,"[2001:db8::1]:53",payload,600);
    if (!plan) return false;
    std::vector<std::size_t> order(plan->count()); std::iota(order.begin(),order.end(),0);
    std::mt19937 random(41); std::ranges::shuffle(order,random);
    for (std::size_t i=0;i<order.size();++i) {
        auto fragment=*plan->fragment(order[i]);
        auto expected=i+1==order.size() ? h::ReassemblyStatus::accepted : h::ReassemblyStatus::incomplete;
        if (assembly.feed(one->handle,fragment,now)!=expected) return false;
        if (i+1!=order.size() && assembly.feed(one->handle,fragment,now)!=h::ReassemblyStatus::duplicate) return false;
    }
    auto packet=assembly.packet(now);
    if (!packet || packet->owner!=one->handle || packet->session!=7 || packet->address!="[2001:db8::1]:53" ||
        !std::ranges::equal(packet->payload,payload) || assembly.buffered_bytes() || assembly.pending_packets()) return false;
    if (assembly.feed(two->handle,{8,1,0,1,"x:1",{}},now)!=h::ReassemblyStatus::backpressure || !assembly.consume()) return false;
    if (assembly.feed(two->handle,{8,99,255,1,"x:1",{}},now)!=h::ReassemblyStatus::accepted) return false;
    auto empty=assembly.packet(now);
    if (!empty || !empty->payload.empty() || !assembly.consume()) return false;
    // Equal packet ID in another session remains independent.
    std::array<std::uint8_t,1> a{'a'},b{'b'};
    if (assembly.feed(one->handle,{7,9,0,2,"x:1",a},now)!=h::ReassemblyStatus::incomplete ||
        assembly.feed(two->handle,{8,9,1,2,"y:2",b},now)!=h::ReassemblyStatus::incomplete ||
        assembly.feed(one->handle,{7,9,1,2,"x:1",b},now)!=h::ReassemblyStatus::accepted) return false;
    auto first=assembly.packet(now);
    if (!first || first->address!="x:1" || !std::ranges::equal(first->payload,std::array<std::uint8_t,2>{'a','b'})) return false;
    (void)assembly.consume();
    if (assembly.feed(two->handle,{8,9,0,2,"y:2",a},now)!=h::ReassemblyStatus::accepted) return false;
    auto second=assembly.packet(now);
    return second && second->address=="y:2" && std::ranges::equal(second->payload,std::array<std::uint8_t,2>{'a','b'});
}
auto bounded_failures() -> bool {
    auto now=h::UdpClock::time_point{}+1s;
    h::UdpSessions<2> sessions(100ms); auto admitted=sessions.acquire(1,now);
    if (!admitted) return false;
    auto owner=admitted->handle;
    h::UdpReassembler<h::UdpSessions<2>,2> assembly(sessions,4,4,10ms);
    std::array<std::uint8_t,2> a{1,2},b{3,4}; std::array<std::uint8_t,1> bad{0};
    if (assembly.feed(owner,{1,1,0,2,"a:1",a},now)!=h::ReassemblyStatus::incomplete ||
        assembly.feed(owner,{1,2,0,2,"a:1",a},now)!=h::ReassemblyStatus::incomplete || assembly.buffered_bytes()!=4) return false;
    if (assembly.feed(owner,{1,1,1,2,"a:1",b},now)!=h::ReassemblyStatus::full || assembly.buffered_bytes()!=4) return false;
    if (assembly.feed(owner,{1,2,0,2,"a:1",bad},now)!=h::ReassemblyStatus::malformed || assembly.buffered_bytes()!=2) return false;
    if (assembly.feed(owner,{1,2,1,2,"a:1",b},now)!=h::ReassemblyStatus::expired) return false;
    if (assembly.feed(owner,{1,1,1,2,"b:1",b},now)!=h::ReassemblyStatus::malformed || assembly.buffered_bytes()) return false;
    if (assembly.feed(owner,{1,3,0,2,"a:1",{}},now)!=h::ReassemblyStatus::full) return false;
    if (!assembly.prune(now+20ms) || assembly.pending_packets()) return false;
    if (assembly.feed(owner,{1,3,0,2,"a:1",a},now+20ms)!=h::ReassemblyStatus::incomplete) return false;
    if (assembly.feed(owner,{1,3,1,2,"a:1",b},now+30ms)!=h::ReassemblyStatus::expired || assembly.buffered_bytes()) return false;
    // Duplicates and late fragments do not extend the original deadline.
    if (assembly.feed(owner,{1,3,0,2,"a:1",a},now+39ms)!=h::ReassemblyStatus::expired) return false;
    if (assembly.feed(owner,{1,3,0,2,"a:1",a},now+40ms)!=h::ReassemblyStatus::incomplete ||
        assembly.feed(owner,{1,3,1,2,"a:1",b},now+40ms)!=h::ReassemblyStatus::accepted) return false;
    if (assembly.packet(now+39ms) || !assembly.consume()) return false;
    if (assembly.feed(owner,{1,4,0,2,"a:1",a},now+40ms)!=h::ReassemblyStatus::incomplete) return false;
    if (!sessions.release(owner)) return false;
    auto fresh=sessions.acquire(1,now+40ms);
    if (!fresh || fresh->handle==owner) return false;
    if (assembly.feed(owner,{1,4,1,2,"a:1",b},now+40ms)!=h::ReassemblyStatus::session ||
        assembly.feed(fresh->handle,{1,4,1,2,"a:1",b},now+40ms)!=h::ReassemblyStatus::incomplete) return false;
    if (assembly.feed(fresh->handle,{1,4,0,2,"a:1",a},now+40ms)!=h::ReassemblyStatus::accepted) return false;
    (void)assembly.consume();
    if (assembly.feed(fresh->handle,{1,5,0,2,"a:1",a},now+39ms)!=h::ReassemblyStatus::clock) return false;
    if (assembly.feed(fresh->handle,{1,6,0,2,"a:1",a},now+40ms)!=h::ReassemblyStatus::incomplete ||
        assembly.feed(fresh->handle,{1,6,1,3,"a:1",b},now+40ms)!=h::ReassemblyStatus::malformed) return false;
    if (!assembly.prune(now+60ms)) return false;
    std::array<std::uint8_t,3> larger{1,2,3};
    if (assembly.feed(fresh->handle,{1,7,0,2,"a:1",larger},now+60ms)!=h::ReassemblyStatus::incomplete ||
        assembly.feed(fresh->handle,{1,7,1,2,"a:1",b},now+60ms)!=h::ReassemblyStatus::too_large || assembly.buffered_bytes()) return false;
    assembly.close();
    return assembly.feed(fresh->handle,{1,5,0,2,"a:1",a},now+60ms)==h::ReassemblyStatus::closed && !assembly.buffered_bytes();
}
auto ready_queue() -> bool {
    auto now=h::UdpClock::time_point{}+1s;
    h::UdpSessions<2> sessions(1s);auto first=sessions.acquire(1,now),second=sessions.acquire(2,now);
    if(!first || !second)return false;
    h::UdpReassembler<h::UdpSessions<2>,2,8> assembly(sessions);
    for(std::uint8_t i=0;i<8;++i) {
        std::array<std::uint8_t,1> payload{i};
        if(assembly.feed(first->handle,{1,i,0,1,"a:1",payload},now)!=h::ReassemblyStatus::accepted)return false;
    }
    if(assembly.feed(second->handle,{2,1,0,1,"b:2",{}},now)!=h::ReassemblyStatus::backpressure)return false;
    for(std::uint8_t i=0;i<3;++i) {
        auto packet=assembly.packet(now);
        if(!packet || packet->payload.size()!=1 || packet->payload[0]!=i || !assembly.consume())return false;
    }
    for(std::uint8_t i=8;i<11;++i) {
        std::array<std::uint8_t,1> payload{i};
        if(assembly.feed(second->handle,{2,i,0,1,"b:2",payload},now)!=h::ReassemblyStatus::accepted)return false;
    }
    if(!sessions.release(first->handle) || !assembly.prune(now))return false;
    for(std::uint8_t i=8;i<11;++i) {
        auto packet=assembly.packet(now);
        if(!packet || packet->owner!=second->handle || packet->address!="b:2" || packet->payload.size()!=1 || packet->payload[0]!=i || !assembly.consume())return false;
    }
    return !assembly.packet(now);
}
auto shared_budget() -> bool {
    h::UdpMemoryBudget budget(12);std::atomic<unsigned> admitted=0;std::barrier gate(9);
    std::array<std::thread,8> workers;
    for(auto& worker:workers) worker=std::thread([&] {
        bool acquired=budget.acquire(4);if(acquired)++admitted;
        gate.arrive_and_wait();gate.arrive_and_wait();
        if(acquired)budget.release(4);
    });
    gate.arrive_and_wait();bool bounded=admitted==3 && budget.used()==12 && !budget.acquire(1);
    gate.arrive_and_wait();for(auto& worker:workers)worker.join();
    if(!bounded || budget.used()!=0 || !budget.acquire(12))return false;
    budget.release(12);return budget.used()==0;
}
auto main() -> int {
    if (!wire_vectors()) return 1;
    if (!session_generations()) return 2;
    if (!shuffled_fragments()) return 3;
    if (!bounded_failures()) return 4;
    if (!ready_queue()) return 5;
    if (!shared_budget()) return 6;
    std::println("Hy2 UDP vectors, bounded sessions/generations, shuffled fragments, duplicate/timeout/budget and empty datagrams passed");
}

