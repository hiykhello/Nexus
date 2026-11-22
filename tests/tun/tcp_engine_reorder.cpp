import std;
import tcp.engine;
import nexus.tests.scheduled_link;
namespace p = ::packet;
namespace t=tcp;

template<class Table, class Engine, class View, class Make, class Parse>
auto scenario(View syn, Make make, Parse parse) -> bool {
    p::MemoryLink link({1500,1,1500});
    ScheduledLink network(8,12000);
    auto table=Table::create(1,8); if (!table) return false;
    Engine engine(link,*table);
    auto wire=make(syn);
    if (!wire || !link.send(p::Side::first,*wire)) return false;
    auto opened=engine.step(0,50);
    auto synack=link.receive_packet(p::Side::first);
    if (!opened || !opened->opened || !opened->id || !synack || !*synack) return false;
    auto id=*opened->id;
    auto ack=syn; ack.flags=0x10; ack.sequence=syn.sequence+1; ack.acknowledgement=51; ack.window=8;
    wire=make(ack);
    if (!wire || !link.send(p::Side::first,*wire)) return false;
    auto established=engine.step(1,0);
    if (!established || established->rejected || established->input_error) return false;
    p::Bytes early{'a','b'}, late{'c','d'};
    auto first=ack; first.flags=0x18; first.payload=early;
    auto last=ack; last.flags=0x19; last.sequence=ack.sequence+2; last.payload=late;
    auto first_wire=make(first); auto last_wire=make(last);
    if (!first_wire || !last_wire ||
        !network.send(p::Side::first,*first_wire,2,true) ||
        !network.send(p::Side::first,*last_wire,2) ||
        !network.send(p::Side::first,*last_wire,3) ||
        !network.send(p::Side::first,*first_wire,4)) return false;
    auto process=[&](std::uint64_t now,std::uint32_t expected, bool blocked=false) {
        auto arrived=network.advance(now,link);
        if (!arrived || *arrived!=1) return false;
        p::Bytes sentinel{42};
        if (blocked && !link.send(p::Side::second,sentinel)) return false;
        auto step=engine.step(now,0);
        if (!step || step->input_error) return false;
        if (blocked) {
            auto queued=link.receive(p::Side::first);
            if (!step->backpressured || step->delivered || !queued || !*queued || **queued!=sentinel) return false;
            step=engine.step(now,0);
        }
        auto reply=link.receive_packet(p::Side::first);
        if (!step || !step->delivered || step->input_error || !reply || !*reply) return false;
        auto parsed=parse((**reply).bytes);
        return parsed && parsed->flags==0x10 && parsed->acknowledgement==expected;
    };
    if (!process(2,ack.sequence,true) || !process(3,ack.sequence)) return false;
    std::array<std::uint8_t,4> output{};
    auto before=engine.read(id,output,3);
    if (!before || before->bytes || before->eof) return false;
    if (!process(4,ack.sequence+5)) return false;
    auto read=engine.read(id,output,4);
    if (!read || read->bytes!=4 || !read->eof || output!=std::array<std::uint8_t,4>{'a','b','c','d'}) return false;
    auto remaining=engine.read(id,output,4);
    return remaining && remaining->bytes==0 && remaining->eof && network.size()==0;
}

int main() {
    p::Tcp4View v4{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,
                   .destination_port=80,.sequence=0xfffffffc,.flags=2};
    p::Tcp6View v6{.source={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                   .destination={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                   .source_port=1234,.destination_port=80,.sequence=0xfffffffc,.flags=2};
    if (!scenario<t::ConnectionTable,t::MemoryEngine>(v4,[](auto v) { return p::make_tcp4(v); },[](auto const& b) { return p::parse_tcp4(b); }) ||
        !scenario<t::ConnectionTable6,t::MemoryEngine6>(v6,[](auto v) { return p::make_tcp6(v); },[](auto const& b) { return p::parse_tcp6(b); })) return 1;
    std::println("dual-stack TCP engine handles loss, reordering, duplicate data and early FIN");
}
