import std;
import nexus.tcp.engine;
namespace p = nexus::packet;
namespace t = nexus::tcp;
namespace r = nexus::rules;
int main() {
    auto matcher = r::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}}});
    auto table = t::ConnectionTable::create(1, 8);
    if (!matcher || !table) return 1;
    p::MemoryLink link;
    t::MemoryEngine engine(link, *table, std::move(*matcher));
    p::Tcp4View syn{.source={10,0,0,1}, .destination={192,0,2,7}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=0xc2};
    auto denied = p::make_tcp4(syn);
    if (!denied || !link.send(p::Side::first, *denied)) return 1;
    auto blocked = engine.step(0, 50);
    if (!blocked || !blocked->input || !blocked->rejected || blocked->rejected->error != t::DispatchError::blocked ||
        blocked->id || blocked->delivered || table->size()) return 1;
    auto no_reply = link.receive(p::Side::first);
    if (!no_reply || *no_reply) return 1;
    for (auto [address,port] : {std::pair{p::Address4{},std::uint16_t{80}},
                                std::pair{p::Address4{198,51,100,7},std::uint16_t{0}}}) {
        auto invalid_syn=syn; invalid_syn.destination=address; invalid_syn.destination_port=port;
        auto packet=p::make_tcp4(invalid_syn);
        if (!packet || !link.send(p::Side::first,*packet)) return 1;
        auto rejected=engine.step(0,50);
        if (!rejected || !rejected->rejected || rejected->rejected->error!=t::DispatchError::invalid_target ||
            rejected->id || rejected->delivered || table->size()) return 1;
    }
    auto corrupt = *denied; corrupt.back() ^= 1;
    if (!link.send(p::Side::first, corrupt)) return 1;
    auto bad = engine.step(1, 50);
    if (!bad || !bad->rejected || bad->rejected->error != t::DispatchError::invalid_packet || table->size()) return 1;
    syn.destination={198,51,100,7};
    auto allowed = p::make_tcp4(syn);
    if (!allowed || !link.send(p::Side::first, *allowed)) return 1;
    auto accepted = engine.step(2, 50);
    auto reply = link.receive(p::Side::first);
    if (!accepted || !accepted->opened || !accepted->id || !accepted->delivered || !reply || !*reply || table->size() != 1) return 1;
    auto view = p::parse_tcp4(**reply);
    if (!view || view->source != syn.destination || view->destination != syn.source || view->flags != 0x12) return 1;
    if (!link.send(p::Side::first, *denied)) return 1;
    auto blocked_when_full = engine.step(3, 60);
    if (!blocked_when_full || !blocked_when_full->rejected || blocked_when_full->rejected->error != t::DispatchError::blocked ||
        table->size() != 1) return 1;
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=1234, .destination_port=80,
                    .sequence=100, .acknowledgement=51, .flags=0x10, .window=8};
    auto acknowledgement = p::make_tcp4(ack);
    if (!acknowledgement || !link.send(p::Side::first, *acknowledgement)) return 1;
    auto established = engine.step(4, 0);
    if (!established || established->id != accepted->id || established->rejected || established->input_error ||
        table->get(*accepted->id)->state() != t::ConnectionState::established) return 1;
    std::cout << "TCP memory ingress applies destination policy before creating flows\n";
}
