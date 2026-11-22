import std;
import tcp.engine;
namespace p = ::packet;
namespace t = tcp;
int main() {
    p::MemoryLink link({1500,1,1500});
    auto table=t::ConnectionTable::create(1,8);
    p::Tcp4View syn{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    auto id=table->open(syn,50,0);
    auto* flow=table->get(*id);
    p::Tcp4View ack{.source=syn.source,.destination=syn.destination,.source_port=1234,.destination_port=80,
                    .sequence=100,.acknowledgement=51,.flags=0x10,.window=8};
    if (!flow->input(ack,0)) return 1;
    t::MemoryEngine engine(link,*table);
    p::Bytes sentinel{42};
    if (!link.send(p::Side::second,sentinel)) return 1;
    auto reset=engine.reset(*id,1);
    if (!reset || !reset->notification.backpressured || reset->notification.delivered ||
        flow->state()!=t::ConnectionState::reset || table->reclaim(*id,1)!=false) return 1;
    auto repeat=engine.reset(*id,1);
    if (!repeat || !repeat->notification.backpressured) return 1;
    auto first=link.receive(p::Side::first);
    if (!first || !*first || **first!=sentinel) return 1;
    auto delivered=engine.step(2,0);
    auto packet=link.receive_packet(p::Side::first);
    if (!delivered || !delivered->delivered || !packet || !*packet) return 1;
    if ((**packet).kind!=p::PacketKind::stateful_tcp_reset || (**packet).flow_id!=*id) return 1;
    auto parsed=p::parse_tcp4((**packet).bytes);
    if (!parsed || parsed->flags!=0x14 || parsed->sequence!=51 || parsed->acknowledgement!=100 ||
        table->reclaim(*id,2)!=true) return 1;
    auto replacement=table->open(syn,60,3);
    if (!replacement || *replacement==*id || engine.reset(*id,3).error()!=t::EngineError::unknown_flow) return 1;
    auto* next=table->get(*replacement);
    ack.acknowledgement=61;
    if (!next->input(ack,3) || !link.send(p::Side::second,sentinel)) return 1;
    auto queued=engine.reset(*replacement,4);
    if (!queued || !queued->notification.backpressured || !table->abort(*replacement)) return 1;
    auto third=table->open(syn,70,4);
    auto stale=engine.step(4,0);
    if (!third || !stale || !stale->stale_reply || stale->delivered) return 1;
    std::cout << "TCP local reset delivery and stale flow protection passed\n";
}
