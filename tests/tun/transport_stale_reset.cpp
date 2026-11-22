#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import transport.memory;
import packet.fd;
namespace p = ::packet; namespace t=tcp; namespace u=udp; namespace tr=transport;
struct Pair { int fd[2]{-1,-1}; ~Pair() { for (auto n:fd) if (n>=0) ::close(n); } };

template<class View, class Make>
auto stopped_pending(View syn, Make make) -> bool {
    p::MemoryLink external({1500,1,1500});
    auto table=t::ConnectionTable::create(2,64); auto table6=t::ConnectionTable6::create(2,64);
    tr::MemoryEngine engine(external,*table,*table6,::rules::Matcher{},2,2,
                            u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,
                            {},1500,{1500,1,1500});
    p::Bytes sentinel{42}; if (!external.send(p::Side::second,sentinel)) return false;
    auto ack=syn; ack.flags=0x10; ack.acknowledgement=77;
    auto wire=make(ack); if (!wire) return false;
    // Fill external output, then the switch's pending slot and internal output.
    for (int i=0;i<3;++i) {
        if (!external.send(p::Side::first,*wire)) return false;
        if (!engine.step(i+1,50)) return false;
    }
    auto live=[&]() { return table->watched_generations()+table6->watched_generations(); };
    if (live()!=1) return false;
    if (!engine.stop(4) || live()!=0) return false;
    auto out=external.receive(p::Side::first);
    return out && *out && **out==sentinel;
}

template<class Table, class Engine, class View, class Make>
auto stale_output(View syn, Make make, int kind) -> bool {
    Pair pair; if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair.fd)) return false;
    p::MemoryLink internal({1500,4,6000}), external({1500,4,6000});
    auto table=t::ConnectionTable::create(2,64); auto table6=t::ConnectionTable6::create(2,64);
    Table& chosen=[&]() -> Table& { if constexpr (std::same_as<Table,t::ConnectionTable>) return *table; else return *table6; }();
    tr::MemoryEngine transport(external,*table,*table6,::rules::Matcher{},2,2,
                               u::Mapping::endpoint_independent,u::Filtering::address_port_dependent);
    Engine engine(internal,chosen); auto pump=p::FdPump::create(pair.fd[0],external,1500);
    auto id=chosen.open(syn,50,0); if (!id || !pump) return false;
    auto* flow=chosen.get(*id); auto ack=syn;
    ack.flags=0x10; ack.sequence=100; ack.acknowledgement=51; ack.window=64;
    if (!flow->input(ack,0)) return false;
    p::Bytes payload{'x'};
    if (kind==0) {
        ack.flags=0x18; ack.payload=payload;
        auto wire=make(ack); if (!wire || !internal.send(p::Side::first,*wire)) return false;
        auto result=engine.step(1,0); if (!result || !result->delivered) return false;
    } else if (kind==1) {
        if (!flow->enqueue(payload)) return false;
        auto result=engine.transmit(*id,1); if (!result || !result->delivered) return false;
    } else {
        if (!flow->close_send()) return false;
        auto result=engine.send_fin(*id,1); if (!result || !result->delivered) return false;
    }
    auto packet=internal.receive_packet(p::Side::first);
    if (!packet || !*packet || !(**packet).generation ||
        !external.send(p::Side::second,(**packet).bytes,(**packet).kind,(**packet).flow_id,(**packet).generation)) return false;
    if (!chosen.abort(*id)) return false;
    auto replacement=chosen.open(syn,60,2); if (!replacement || !chosen.abort(*replacement)) return false;
    auto output=pump->step([](void* context,p::QueuedPacket const& packet) noexcept {
        return static_cast<tr::MemoryEngine*>(context)->valid_output(packet);
    },&transport);
    std::array<char,1500> buffer{};
    return output.output_discarded && !output.output_delivered &&
           ::recv(pair.fd[1],buffer.data(),buffer.size(),0)<0 && (errno==EAGAIN || errno==EWOULDBLOCK);
}

template<class View, class Make>
auto stale_synack(View syn, Make make) -> bool {
    Pair pair; if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair.fd)) return false;
    p::MemoryLink link({1500,2,3000});
    auto table=t::ConnectionTable::create(2,64); auto table6=t::ConnectionTable6::create(2,64);
    tr::MemoryEngine engine(link,*table,*table6,::rules::Matcher{},2,2,
                            u::Mapping::endpoint_independent,u::Filtering::address_port_dependent);
    auto pump=p::FdPump::create(pair.fd[0],link,1500); if (!pump) return false;
    auto wire=make(syn); if (!wire || !link.send(p::Side::first,*wire)) return false;
    auto opened=engine.step(1,50); auto forwarded=engine.step(2,50);
    if (!opened || !forwarded) return false;
    auto id=opened->tcp.input.id;
    if (!id && opened->tcp6) id=opened->tcp6->input.id;
    if (!id) return false;
    if constexpr (std::same_as<View,p::Tcp4View>) {
        if (!table->abort(*id)) return false;
        auto next=table->open(syn,60,3); if (!next || !table->abort(*next)) return false;
    } else {
        if (!table6->abort(*id)) return false;
        auto next=table6->open(syn,60,3); if (!next || !table6->abort(*next)) return false;
    }
    auto dropped=pump->step([](void* context,p::QueuedPacket const& packet) noexcept {
        return static_cast<tr::MemoryEngine*>(context)->valid_output(packet);
    },&engine);
    return dropped.output_discarded && !dropped.output_delivered;
}

template<class View, class Make, class Parse>
auto scenario(View syn, Make make, Parse parse, int stage, bool stateful, bool reap_new) -> bool {
    Pair pair; if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair.fd)) return false;
    p::MemoryLink link({1500,1,1500});
    auto table=t::ConnectionTable::create(2,64); auto table6=t::ConnectionTable6::create(2,64);
    if (!table || !table6) return false;
    tr::MemoryEngine engine(link,*table,*table6,::rules::Matcher{},2,2,
                            u::Mapping::endpoint_independent,u::Filtering::address_port_dependent);
    auto pump=p::FdPump::create(pair.fd[0],link,1500); if (!pump) return false;
    auto validate=[](void* context,p::QueuedPacket const& packet) noexcept {
        return static_cast<tr::MemoryEngine*>(context)->valid_output(packet);
    };
    std::uint64_t old_id=0;
    if (stateful) {
        auto wire=make(syn); if (!wire || !link.send(p::Side::first,*wire)) return false;
        auto opened=engine.step(1,50); auto forward=engine.step(2,50);
        if (!opened || !forward) return false;
        auto id=opened->tcp.input.id;
        if (!id && opened->tcp6) id=opened->tcp6->input.id;
        if (!id) return false;
        old_id=*id;
        auto synack=link.receive(p::Side::first);
        if (!synack || !*synack || parse(**synack)->flags!=0x12) return false;
    }
    p::Bytes filler(100,7), sentinel{42}; int filled=0;
    if (stage==2) {
        while (::send(pair.fd[0],filler.data(),filler.size(),0)==static_cast<ssize_t>(filler.size())) ++filled;
        if (!filled || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return false;
    }
    if (stage==0 && !link.send(p::Side::second,sentinel)) return false;
    auto old=syn; old.flags=0x10; old.sequence=syn.sequence+1; old.acknowledgement=stateful ? 52 : 77;
    auto wire=make(old); if (!wire || !link.send(p::Side::first,*wire)) return false;
    auto first=engine.step(10,50); auto second=engine.step(11,50);
    if (!first || !second) return false;
    if (stateful) {
        auto const& input = first->tcp.input.id ? first->tcp.input : first->tcp6->input;
        if (input.input_error!=t::ConnectionError::invalid_ack || !input.delivered) return false;
        auto reply=old; std::swap(reply.source,reply.destination); std::swap(reply.source_port,reply.destination_port);
        reply.flags=4; auto reply_wire=make(reply); if (!reply_wire) return false;
        if (!engine.valid_output({*reply_wire,p::PacketKind::stateful_tcp_reset,old_id}) ||
            engine.valid_output({*reply_wire,p::PacketKind::stateful_tcp_reset,0})) return false;
        if constexpr (std::same_as<View,p::Tcp4View>) { if (!table->abort(old_id)) return false; }
        else { if (!table6->abort(old_id)) return false; }
    }
    if (stage==0 && !second->device.output_backpressured) return false;
    if (stage==2) { auto blocked=pump->step(validate,&engine); if (!blocked.output_backpressured) return false; }
    wire=make(syn); if (!wire || !link.send(p::Side::first,*wire)) return false;
    auto opened=engine.step(12,50);
    if (!opened || !(opened->tcp.input.opened || (opened->tcp6 && opened->tcp6->input.opened))) return false;
    auto reply=old; std::swap(reply.source,reply.destination); std::swap(reply.source_port,reply.destination_port);
    reply.flags=4; auto reply_wire=make(reply); if (!reply_wire) return false;
    if (!engine.valid_output({*reply_wire,p::PacketKind::ordinary}) ||
        engine.valid_output({*reply_wire,p::PacketKind::stateless_tcp_reset}) ||
        (stateful && engine.valid_output({*reply_wire,p::PacketKind::stateful_tcp_reset,old_id}))) return false;
    if (reap_new) {
        auto id=opened->tcp.input.id;
        if (!id && opened->tcp6) id=opened->tcp6->input.id;
        if (!id) return false;
        if constexpr (std::same_as<View,p::Tcp4View>) { if (!table->abort(*id)) return false; }
        else { if (!table6->abort(*id)) return false; }
    }
    if (stage==0) {
        auto output=link.receive(p::Side::first); if (!output || !*output || **output!=sentinel) return false;
        if (!engine.step(13,50)) return false;
    }
    auto dropped=pump->step(validate,&engine);
    if (!dropped.output_discarded || dropped.output_delivered) return false;
    std::array<std::uint8_t,1500> bytes{};
    for (int i=0;i<filled;++i) if (::recv(pair.fd[1],bytes.data(),bytes.size(),0)!=100) return false;
    if (::recv(pair.fd[1],bytes.data(),bytes.size(),0)>=0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return false;
    if (reap_new) return true;
    for (int i=0;i<5;++i) {
        if (!engine.step(14+i,50)) return false;
        auto output=pump->step(validate,&engine);
        if (output.output_discarded) return false;
        auto n=::recv(pair.fd[1],bytes.data(),bytes.size(),0);
        if (n>0) {
            auto packet=parse(std::span(bytes).first(n));
            return packet && packet->flags==0x12 && packet->sequence==50;
        }
        if (errno!=EAGAIN && errno!=EWOULDBLOCK) return false;
    }
    return false;
}
int main() {
    p::Tcp4View syn4{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    p::Tcp6View syn6{.source={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                     .destination={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                     .source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    if (!stopped_pending(syn4,[](auto v) { return p::make_tcp4(v); }) ||
        !stopped_pending(syn6,[](auto v) { return p::make_tcp6(v); })) return 1;
    if (!stale_synack(syn4,[](auto v) { return p::make_tcp4(v); }) ||
        !stale_synack(syn6,[](auto v) { return p::make_tcp6(v); })) return 1;
    for (int kind=0;kind<3;++kind)
        if (!stale_output<t::ConnectionTable,t::MemoryEngine>(syn4,[](auto v) { return p::make_tcp4(v); },kind) ||
            !stale_output<t::ConnectionTable6,t::MemoryEngine6>(syn6,[](auto v) { return p::make_tcp6(v); },kind)) return 1;
    for (int stage=0;stage<3;++stage) for (bool stateful : {false,true}) for (bool reap : {false,true}) {
        if (!scenario(syn4,[](auto v) { return p::make_tcp4(v); },[](auto v) { return p::parse_tcp4(v); },stage,stateful,reap) ||
            !scenario(syn6,[](auto v) { return p::make_tcp6(v); },[](auto v) { return p::parse_tcp6(v); },stage,stateful,reap)) return 1;
    }
    std::println("stale resets are discarded at the device while SYN-ACKs survive");
}
