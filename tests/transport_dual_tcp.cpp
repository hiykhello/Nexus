import std;
import nexus.transport.memory;
namespace p=nexus::packet;
namespace t=nexus::tcp;
namespace u=nexus::udp;
namespace tr=nexus::transport;
int main() {
    p::MemoryLink link;
    auto a=t::ConnectionTable::create(3,64);
    auto b=t::ConnectionTable6::create(3,64);
    tr::MemoryEngine engine(link,*a,*b,nexus::rules::Matcher{},1,1,u::Mapping::endpoint_independent,
                            u::Filtering::address_port_dependent);
    p::Tcp6View six{.source={0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1},
                    .destination={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},
                    .source_port=1234,.destination_port=80,.sequence=99,.flags=2,.window=64};
    auto bytes=p::make_tcp6(six);
    if (!bytes || !link.send(p::Side::first,*bytes)) return 1;
    auto step=engine.step(1,50);
    if (!step || !step->tcp6 || !step->tcp6->input.opened || a->size()!=0 || b->size()!=1) return 1;
    step=engine.step(2,50);
    auto out=link.receive(p::Side::first);
    if (!step || !out || !*out || !p::parse_tcp6(**out)) return 1;
    p::Tcp4View four{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
                     .destination_port=80,.sequence=99,.flags=2,.window=64};
    auto packet=p::make_tcp4(four);
    if (!packet || !link.send(p::Side::first,*packet)) return 1;
    step=engine.step(3,50);
    if (!step || !step->tcp.input.rejected || step->tcp.input.rejected->table_error!=t::TableError::full ||
        a->size()!=0 || b->size()!=1) return 1;
    if (!b->abort(1) || !link.send(p::Side::first,*packet)) return 1;
    step=engine.step(4,50);
    if (!step || !step->tcp.input.opened || a->size()!=1) return 1;
    if (!engine.stop(5) || a->size() || b->size()) return 1;
    std::cout << "dual TCP routing, shared capacity and stop passed\n";
}
