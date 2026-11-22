import std;
import tcp.engine;
namespace p = ::packet;
namespace t = tcp;
int main() {
    p::MemoryLink link({1500, 1, 1500});
    auto table = t::ConnectionTable::create(1, 2);
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=2};
    auto id = table->open(syn, 50, 0);
    auto* flow = table->get(*id);
    p::Bytes data{'a','b'};
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=syn.source_port,
                    .destination_port=syn.destination_port, .sequence=100, .acknowledgement=51,
                    .flags=0x18, .window=8, .payload=data};
    if (!flow->input(ack, 0) || flow->ack().window != 0) return 1;
    p::Bytes sentinel{42};
    if (!link.send(p::Side::second, sentinel)) return 1;
    t::MemoryEngine engine(link, *table);
    std::array<std::uint8_t, 2> output{};
    auto read = engine.read(*id, output, 1);
    if (!read || read->bytes != 2 || output != std::array<std::uint8_t, 2>{'a','b'} ||
        !read->notification.backpressured || read->notification.delivered || read->eof) return 1;
    auto paused = engine.read(*id, output, 2);
    if (!paused || paused->bytes || !paused->notification.backpressured) return 1;
    auto service = engine.service(2);
    if (!service || !service->output.backpressured || service->id) return 1;
    auto first = link.receive(p::Side::first);
    if (!first || !*first || **first != sentinel) return 1;
    auto drained = engine.step(3, 0);
    auto packet = link.receive(p::Side::first);
    if (!drained || !drained->delivered || drained->input || !packet || !*packet) return 1;
    auto update = p::parse_tcp4(**packet);
    if (!update || update->flags != 0x10 || update->acknowledgement != 102 || update->window != 2) return 1;
    ack.sequence=102; ack.flags=0x19; ack.payload=data;
    if (!flow->input(ack, 4) || flow->ack().window != 0) return 1;
    auto final_data = engine.read(*id, output, 5);
    if (!final_data || final_data->bytes != 2 || final_data->eof || !final_data->notification.delivered) return 1;
    packet = link.receive(p::Side::first);
    if (!packet || !*packet || !(update = p::parse_tcp4(**packet)) || update->window != 2 || update->acknowledgement != 104) return 1;
    ack.sequence=104; ack.flags=0x11; ack.payload={};
    if (!flow->input(ack, 6)) return 1;
    auto eof = engine.read(*id, output, 7);
    if (!eof || eof->bytes || !eof->eof || eof->notification.delivered) return 1;
    auto nothing = link.receive(p::Side::first);
    if (!nothing || *nothing) return 1;
    // An adapter may defer EOF acknowledgement until its own buffer is flushed.
    // This flow already delivered EOF above; use a separate flow for deferred delivery.
    p::MemoryLink deferred_link;
    auto deferred_table = t::ConnectionTable::create(1, 2);
    auto deferred_id = deferred_table->open(syn, 50, 0);
    auto* deferred = deferred_table->get(*deferred_id);
    ack.sequence=100; ack.acknowledgement=51; ack.flags=0x11; ack.payload={};
    if (!deferred->input(ack, 0) || !deferred->close_send() || !deferred->fin_sent(1)) return 1;
    ack.sequence=101; ack.acknowledgement=52; ack.flags=0x10;
    if (!deferred->input(ack, 2)) return 1;
    t::MemoryEngine deferred_engine(deferred_link, *deferred_table);
    auto observed = deferred_engine.read(*deferred_id, output, 2, false);
    if (!observed || !observed->eof || deferred_table->reclaim(*deferred_id, 2) != false ||
        !deferred_table->observe_eof(*deferred_id) || deferred_table->reclaim(*deferred_id, 2) != true) return 1;
    std::cout << "TCP application reads advertise reopened windows with backpressure\n";
}
