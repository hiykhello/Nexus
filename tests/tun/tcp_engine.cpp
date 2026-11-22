import std;
import tcp.engine;
namespace p = ::packet;
namespace t = tcp;
template<class Table, class Engine, class View, class Make, class Address>
auto discard_invalid_syn(View syn, Make make, Address multicast) -> bool {
    p::MemoryLink link; auto table=Table::create(1,8); if (!table) return false;
    Engine engine(link,*table);
    for (bool source : {false,true}) {
        auto bad=syn; (source ? bad.source : bad.destination)=multicast;
        auto wire=make(bad); if (!wire || !link.send(p::Side::first,*wire)) return false;
        auto step=engine.step(1,50); auto output=link.receive_packet(p::Side::first);
        if (!step || !step->rejected || step->rejected->error!=t::DispatchError::invalid_target ||
            step->opened || step->delivered || table->size() || !output || *output) return false;
    }
    auto wire=make(syn); if (!wire || !link.send(p::Side::first,*wire)) return false;
    auto step=engine.step(2,50); auto output=link.receive_packet(p::Side::first);
    return step && step->opened && step->delivered && output && *output;
}
template<class Table, class Engine, class View, class Make, class Parse>
auto output_generation(View syn, Make make, Parse parse, int kind) -> bool {
    p::MemoryLink link({1500,4,6000}); auto table=Table::create(2,64); if (!table) return false;
    auto id=table->open(syn,50,0); if (!id) return false;
    auto* flow=table->get(*id); auto ack=syn;
    ack.flags=0x10; ack.sequence=syn.sequence+1; ack.acknowledgement=51; ack.window=64;
    if (!flow->input(ack,0)) return false;
    Engine engine(link,*table); p::Bytes payload{'a','b'};
    if (kind==0) {
        ack.flags=0x18; ack.payload=payload;
        auto wire=make(ack); if (!wire || !link.send(p::Side::first,*wire)) return false;
        auto result=engine.step(1,0); if (!result || !result->delivered) return false;
    } else if (kind==1) {
        if (!flow->enqueue(payload)) return false;
        auto result=engine.transmit(*id,1); if (!result || !result->delivered || result->bytes!=2) return false;
    } else {
        if (!flow->close_send()) return false;
        auto result=engine.send_fin(*id,1); if (!result || !result->delivered) return false;
    }
    auto packet=link.receive_packet(p::Side::first);
    if (!packet || !*packet || !(**packet).generation || !(**packet).generation->valid) return false;
    auto view=parse((**packet).bytes); if (!view) return false;
    if ((kind==0 && (view->flags!=0x10 || view->acknowledgement!=syn.sequence+3)) ||
        (kind==1 && !std::ranges::equal(view->payload,payload)) ||
        (kind==2 && !(view->flags & 1))) return false;
    std::weak_ptr<p::TcpGeneration> lifetime=(**packet).generation;
    auto unrelated=syn; ++unrelated.source_port;
    auto other=table->open(unrelated,90,2); if (!other || !(**packet).generation->valid) return false;
    if (!table->abort(*id)) return false;
    auto replacement=table->open(syn,80,2); if (!replacement || !table->abort(*replacement)) return false;
    if ((**packet).generation->valid) return false;
    packet->reset();
    return lifetime.expired();
}
template<class Table, class Engine, class View, class Make, class Parse>
auto stateless_backpressure(View syn, Make make, Parse parse) -> bool {
    p::MemoryLink link({1500,1,1500});
    auto table=Table::create(1,8); if (!table) return false;
    Engine engine(link,*table); p::Bytes sentinel{42};
    auto ack=syn; ack.flags=0x10; ack.acknowledgement=77;
    auto wire=make(ack);
    if (!wire || !link.send(p::Side::second,sentinel) || !link.send(p::Side::first,*wire)) return false;
    auto pending=engine.step(1,0);
    if (!pending || !pending->input || pending->id || !pending->backpressured || table->size()) return false;
    auto out=link.receive(p::Side::first);
    auto flush=engine.step(2,0); auto reset=link.receive(p::Side::first);
    if (!out || !*out || **out!=sentinel || !flush || !flush->delivered || !reset || !*reset) return false;
    auto view=parse(**reset); if (!view || view->flags!=4 || view->sequence!=77) return false;
    if (!link.send(p::Side::second,sentinel) || !link.send(p::Side::first,*wire)) return false;
    pending=engine.step(3,0); if (!pending || !pending->backpressured) return false;
    auto opened=table->open(syn,50,3); if (!opened) return false;
    if (!table->abort(*opened)) return false;
    out=link.receive(p::Side::first); auto stale=engine.step(4,0);
    auto empty=link.receive(p::Side::first);
    return out && *out && **out==sentinel && stale && stale->stale_reply && !stale->delivered && empty && !*empty;
}
int main() {
    p::MemoryLink link6({1500,1,1500});
    auto table6=t::ConnectionTable6::create(2,8);
    if (!table6) return 1;
    t::MemoryEngine6 engine6(link6,*table6);
    p::Bytes sentinel6{42};
    p::Tcp6View syn6{.source={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                     .destination={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                     .source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    if (!discard_invalid_syn<t::ConnectionTable6,t::MemoryEngine6>(syn6,[](auto v) { return p::make_tcp6(v); },p::Address6{0xff,2})) return 1;
    for (int kind=0;kind<3;++kind)
        if (!output_generation<t::ConnectionTable6,t::MemoryEngine6>(syn6,[](auto v) { return p::make_tcp6(v); },[](auto const& b) { return p::parse_tcp6(b); },kind)) return 1;
    if (!stateless_backpressure<t::ConnectionTable6,t::MemoryEngine6>(syn6,[](auto v) { return p::make_tcp6(v); },[](auto const& b) { return p::parse_tcp6(b); })) return 1;
    auto raw6=p::make_tcp6(syn6);
    if (!raw6 || !link6.send(p::Side::second,sentinel6) || !link6.send(p::Side::first,*raw6)) return 1;
    auto opened6=engine6.step(0,50);
    if (!opened6 || !opened6->opened || !opened6->id || !opened6->backpressured) return 1;
    auto sentinel_out6=link6.receive(p::Side::first);
    auto flush6=engine6.step(1,999); auto synack_raw6=link6.receive(p::Side::first);
    if (!sentinel_out6 || !*sentinel_out6 || **sentinel_out6!=sentinel6 || !flush6 || !flush6->delivered || !synack_raw6 || !*synack_raw6) return 1;
    auto synack6=p::parse_tcp6(**synack_raw6);
    if (!synack6 || synack6->sequence!=50 || synack6->acknowledgement!=100 || synack6->destination!=syn6.source) return 1;
    p::Tcp6View ack6{.source=syn6.source,.destination=syn6.destination,.source_port=1234,.destination_port=80,
                     .sequence=100,.acknowledgement=51,.flags=0x10,.window=8};
    raw6=p::make_tcp6(ack6);
    if (!raw6 || !link6.send(p::Side::first,*raw6) || !engine6.step(2,0)) return 1;
    p::Bytes incoming6{'h','i'}; ack6.flags=0x18; ack6.payload=incoming6;
    raw6=p::make_tcp6(ack6); if (!raw6 || !link6.send(p::Side::first,*raw6)) return 1;
    auto received6=engine6.step(3,0); auto response6=link6.receive(p::Side::first);
    if (!received6 || !received6->delivered || !response6 || !*response6 || p::parse_tcp6(**response6)->acknowledgement!=102) return 1;
    std::array<std::uint8_t,2> read6{};
    auto read_result6=engine6.read(*opened6->id,read6,4);
    if (!read_result6 || read_result6->bytes!=2 || !std::ranges::equal(read6,incoming6)) return 1;
    if (read_result6->notification.delivered) { auto update=link6.receive(p::Side::first); if (!update || !*update) return 1; }
    auto* flow6=table6->get(*opened6->id); p::Bytes outgoing6{'o','k'};
    if (!flow6 || !flow6->enqueue(outgoing6) || !link6.send(p::Side::second,sentinel6)) return 1;
    auto blocked6=engine6.transmit(*opened6->id,5);
    if (!blocked6 || !blocked6->backpressured || flow6->ack().sequence!=51) return 1;
    if (!link6.receive(p::Side::first)) return 1;
    auto sent6=engine6.transmit(*opened6->id,6); auto output6=link6.receive(p::Side::first);
    if (!sent6 || sent6->bytes!=2 || !output6 || !*output6) return 1;
    auto output_view6=p::parse_tcp6(**output6);
    if (!output_view6 || output_view6->sequence!=51 || !std::ranges::equal(output_view6->payload,outgoing6)) return 1;
    auto retry6=engine6.service(1006); auto retry_wire6=link6.receive(p::Side::first);
    if (!retry6 || retry6->action!=t::ServiceAction::retransmit || !retry_wire6 || !*retry_wire6) return 1;
    auto retry_view6=p::parse_tcp6(**retry_wire6);
    if (!retry_view6 || retry_view6->sequence!=51 || !std::ranges::equal(retry_view6->payload,outgoing6)) return 1;
    if (!link6.send(p::Side::second,sentinel6)) return 1;
    auto reset6=engine6.reset(*opened6->id,1007);
    if (!reset6 || !reset6->notification.backpressured || table6->reclaim(*opened6->id,1007)!=false) return 1;
    if (!link6.receive(p::Side::first)) return 1;
    auto reset_flush6=engine6.step(1008,0); auto reset_wire6=link6.receive_packet(p::Side::first);
    if (!reset_flush6 || !reset_flush6->delivered || !reset_wire6 || !*reset_wire6) return 1;
    if ((**reset_wire6).kind!=p::PacketKind::stateful_tcp_reset || (**reset_wire6).flow_id!=*opened6->id) return 1;
    auto reset_view6=p::parse_tcp6((**reset_wire6).bytes);
    if (!reset_view6 || reset_view6->flags!=0x14 || table6->reclaim(*opened6->id,1008)!=true) return 1;
    p::MemoryLink link({1500, 1, 1500});
    auto table = t::ConnectionTable::create(2, 8);
    if (!table) return 1;
    t::MemoryEngine engine(link, *table);
    p::Bytes sentinel{42};
    if (!link.send(p::Side::second, sentinel)) return 1;
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=2};
    if (!discard_invalid_syn<t::ConnectionTable,t::MemoryEngine>(syn,[](auto v) { return p::make_tcp4(v); },p::Address4{224,0,0,1})) return 1;
    for (int kind=0;kind<3;++kind)
        if (!output_generation<t::ConnectionTable,t::MemoryEngine>(syn,[](auto v) { return p::make_tcp4(v); },[](auto const& b) { return p::parse_tcp4(b); },kind)) return 1;
    if (!stateless_backpressure<t::ConnectionTable,t::MemoryEngine>(syn,[](auto v) { return p::make_tcp4(v); },[](auto const& b) { return p::parse_tcp4(b); })) return 1;
    auto raw = p::make_tcp4(syn);
    if (!raw || !link.send(p::Side::first, *raw)) return 1;
    auto blocked = engine.step(0, 50);
    if (!blocked || !blocked->input || !blocked->opened || !blocked->id || !blocked->backpressured ||
        blocked->delivered || table->size() != 1) return 1;
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=syn.source_port,
                    .destination_port=syn.destination_port, .sequence=100, .acknowledgement=51, .flags=0x10, .window=8};
    raw = p::make_tcp4(ack);
    if (!raw || !link.send(p::Side::first, *raw)) return 1;
    auto again = engine.step(1, 999);
    if (!again || !again->backpressured || again->input || table->get(*blocked->id)->state() != t::ConnectionState::handshake) return 1;
    auto reversed = engine.step(0, 999);
    if (reversed || std::get<t::EngineError>(reversed.error()) != t::EngineError::time_reversed) return 1;
    auto first = link.receive(p::Side::first);
    if (!first || !*first || **first != sentinel) return 1;
    auto drained = engine.step(2, 999);
    if (!drained || !drained->delivered || drained->input || drained->backpressured) return 1;
    auto reply = link.receive(p::Side::first);
    if (!reply || !*reply) return 1;
    auto decoded = p::parse_tcp4(**reply);
    if (!decoded || decoded->flags != 0x12 || decoded->sequence != 50 || decoded->acknowledgement != 100) return 1;
    auto established = engine.step(3, 999);
    if (!established || !established->input || established->id != blocked->id || established->delivered ||
        table->get(*blocked->id)->state() != t::ConnectionState::established) return 1;
    p::Bytes data{'h','i'};
    ack.flags=0x18; ack.payload=data;
    raw = p::make_tcp4(ack);
    if (!raw || !link.send(p::Side::first, *raw)) return 1;
    auto received = engine.step(4, 999);
    if (!received || !received->input || !received->delivered || received->input_error) return 1;
    reply = link.receive(p::Side::first);
    if (!reply || !*reply || !(decoded = p::parse_tcp4(**reply)) || decoded->acknowledgement != 102) return 1;
    std::array<std::uint8_t, 2> output{};
    if (table->get(*blocked->id)->read(output) != 2 || output != std::array<std::uint8_t, 2>{'h','i'}) return 1;
    p::Bytes outgoing{'o','k'};
    auto* flow = table->get(*blocked->id);
    if (!flow->enqueue(outgoing) || !link.send(p::Side::second, sentinel)) return 1;
    auto output_blocked = engine.transmit(*blocked->id, 5);
    if (!output_blocked || !output_blocked->backpressured || output_blocked->bytes || flow->ack().sequence != 51) return 1;
    first = link.receive(p::Side::first);
    if (!first || !*first || **first != sentinel) return 1;
    auto sent = engine.transmit(*blocked->id, 6);
    if (!sent || sent->bytes != 2 || sent->connection_error || sent->output_error || flow->ack().sequence != 53) return 1;
    reply = link.receive(p::Side::first);
    if (!reply || !*reply || !(decoded = p::parse_tcp4(**reply)) || decoded->sequence != 51 ||
        decoded->acknowledgement != 102 || !std::ranges::equal(decoded->payload, outgoing)) return 1;
    ack.flags=0x10; ack.payload={}; ack.sequence=102; ack.acknowledgement=53;
    raw = p::make_tcp4(ack);
    if (!raw || !link.send(p::Side::first, *raw)) return 1;
    auto confirmed = engine.step(7, 999);
    if (!confirmed || confirmed->input_error || !confirmed->input || confirmed->delivered) return 1;
    p::Bytes invalid{1,2,3};
    if (!link.send(p::Side::first, invalid)) return 1;
    auto bad = engine.step(8, 999);
    if (!bad || !bad->input || !bad->rejected || bad->rejected->error != t::DispatchError::invalid_packet) return 1;
    link.close(p::Side::first);
    auto closed = engine.step(9, 999);
    if (closed || std::get<p::DeviceError>(closed.error()) != p::DeviceError::peer_closed) return 1;
    p::MemoryLink second_link({1500, 1, 1500});
    auto second_table = t::ConnectionTable::create(1, 8);
    t::MemoryEngine second_engine(second_link, *second_table);
    raw = p::make_tcp4(syn);
    if (!second_link.send(p::Side::second, sentinel) || !second_link.send(p::Side::first, *raw)) return 1;
    auto queued = second_engine.step(0, 50);
    if (!queued || !queued->backpressured || !queued->id || !second_table->abort(*queued->id)) return 1;
    auto replacement = second_table->open(syn, 60, 1);
    if (!replacement || *replacement == *queued->id) return 1;
    auto stale = second_engine.step(1, 0);
    if (!stale || !stale->stale_reply || stale->delivered || stale->backpressured) return 1;
    auto only_sentinel = second_link.receive(p::Side::first);
    auto no_old_reply = second_link.receive(p::Side::first);
    if (!only_sentinel || !*only_sentinel || **only_sentinel != sentinel || !no_old_reply || *no_old_reply) return 1;
    // A handshake RST is retained under output pressure without ending the
    // handshake; a valid ACK may still complete it after the RST drains.
    p::MemoryLink reset_link({1500, 1, 1500});
    auto reset_table=t::ConnectionTable::create(1,8);
    auto reset_id=reset_table->open(syn,50,0);
    t::MemoryEngine reset_engine(reset_link,*reset_table);
    auto bad_ack=ack; bad_ack.sequence=100; bad_ack.acknowledgement=52; bad_ack.flags=0x10; bad_ack.payload={};
    auto bad_wire=p::make_tcp4(bad_ack);
    if (!reset_id || !bad_wire || !reset_link.send(p::Side::second,sentinel) || !reset_link.send(p::Side::first,*bad_wire)) return 1;
    auto blocked_reset=reset_engine.step(1,0);
    if (!blocked_reset || !blocked_reset->backpressured || blocked_reset->input_error!=t::ConnectionError::invalid_ack ||
        reset_table->get(*reset_id)->state()!=t::ConnectionState::handshake) return 1;
    auto valid_ack=bad_ack; valid_ack.acknowledgement=51;
    auto valid_wire=p::make_tcp4(valid_ack);
    if (!valid_wire || !reset_link.send(p::Side::first,*valid_wire)) return 1;
    auto reset_sentinel=reset_link.receive(p::Side::first);
    auto delivered_reset=reset_engine.step(2,0);
    auto reset_packet=reset_link.receive(p::Side::first);
    if (!reset_sentinel || !*reset_sentinel || **reset_sentinel!=sentinel || !delivered_reset ||
        !delivered_reset->delivered || !reset_packet || !*reset_packet) return 1;
    auto reset_view=p::parse_tcp4(**reset_packet);
    auto completed_reset=reset_engine.step(3,0);
    if (!reset_view || reset_view->flags!=4 || reset_view->sequence!=52 || !completed_reset ||
        completed_reset->input_error || reset_table->get(*reset_id)->state()!=t::ConnectionState::established) return 1;
    p::MemoryLink limited_link({1500,1,1500});
    auto limited_table=t::ConnectionTable::create(1,8,{0,1000});
    auto limited_id=limited_table->open(syn,50,0);
    if (!limited_id || !limited_table->get(*limited_id)->input(valid_ack,0)) return 1;
    t::MemoryEngine limited_engine(limited_link,*limited_table);
    auto attack=valid_ack; attack.flags=2;
    auto attack_wire=p::make_tcp4(attack);
    if (!attack_wire || !limited_link.send(p::Side::first,*attack_wire)) return 1;
    auto suppressed=limited_engine.step(1,0);
    auto no_challenge=limited_link.receive(p::Side::first);
    if (!suppressed || !suppressed->challenge_suppressed || suppressed->delivered || !no_challenge || *no_challenge ||
        limited_table->get(*limited_id)->state()!=t::ConnectionState::established) return 1;
    p::MemoryLink small_link({1500, 1, 1500});
    auto small_table = t::ConnectionTable::create(1, 8);
    auto small_id = small_table->open(syn, 50, 0);
    auto* small_flow = small_table->get(*small_id);
    ack.sequence=100; ack.acknowledgement=51; ack.window=8;
    if (!small_flow->input(ack, 0) || !small_flow->enqueue(outgoing)) return 1;
    t::MemoryEngine small_engine(small_link, *small_table, 41);
    for (std::uint32_t i = 0; i < 2; ++i) {
        auto part = small_engine.transmit(*small_id, i);
        auto packet = small_link.receive(p::Side::first);
        if (!part || part->bytes != 1 || part->connection_error || !packet || !*packet) return 1;
        auto view = p::parse_tcp4(**packet);
        if (!view || view->sequence != 51 + i || view->payload.size() != 1 || view->payload[0] != outgoing[i]) return 1;
    }
    if (!small_link.send(p::Side::second, sentinel)) return 1;
    auto retry_blocked = small_engine.retransmit(*small_id, 1000);
    if (!retry_blocked || !retry_blocked->backpressured || retry_blocked->bytes || small_flow->ack().sequence != 53) return 1;
    auto sentinel_out = small_link.receive(p::Side::first);
    if (!sentinel_out || !*sentinel_out || **sentinel_out != sentinel) return 1;
    auto retry = small_engine.retransmit(*small_id, 1001);
    auto retry_packet = small_link.receive(p::Side::first);
    if (!retry || retry->bytes != 1 || retry->connection_error || !retry_packet || !*retry_packet) return 1;
    auto retry_view = p::parse_tcp4(**retry_packet);
    if (!retry_view || retry_view->sequence != 51 || retry_view->payload.size() != 1 || retry_view->payload[0] != 'o') return 1;
    auto early_retry = small_engine.retransmit(*small_id, 3000);
    if (!early_retry || early_retry->bytes || early_retry->backpressured) return 1;
    retry = small_engine.retransmit(*small_id, 3001);
    if (!retry || retry->bytes != 1 || retry->connection_error) return 1;
    // Zero-window probes keep their sequence and timer when the device is full.
    p::MemoryLink probe_link({1500, 1, 1500});
    auto probe_table = t::ConnectionTable::create(1, 8);
    auto probe_id = probe_table->open(syn, 50, 0);
    auto* probe_flow = probe_table->get(*probe_id);
    ack.window=0; ack.acknowledgement=51;
    if (!probe_flow->input(ack, 0) || !probe_flow->enqueue(outgoing)) return 1;
    t::MemoryEngine probe_engine(probe_link, *probe_table);
    if (probe_engine.probe(*probe_id, 0)->delivered || !probe_link.send(p::Side::second, sentinel)) return 1;
    auto blocked_probe = probe_engine.probe(*probe_id, 1000);
    if (!blocked_probe || !blocked_probe->backpressured || blocked_probe->delivered || probe_flow->ack().sequence != 51) return 1;
    auto probe_sentinel = probe_link.receive(p::Side::first);
    if (!probe_sentinel || !*probe_sentinel || **probe_sentinel != sentinel) return 1;
    auto sent_probe = probe_engine.probe(*probe_id, 1001);
    auto probe_packet = probe_link.receive(p::Side::first);
    if (!sent_probe || !sent_probe->delivered || sent_probe->bytes != 1 || sent_probe->connection_error ||
        !probe_packet || !*probe_packet || probe_flow->ack().sequence != 52) return 1;
    auto probe_view = p::parse_tcp4(**probe_packet);
    if (!probe_view || probe_view->sequence != 51 || probe_view->payload.size() != 1 || probe_view->payload[0] != 'o') return 1;
    auto repeated_probe = probe_engine.probe(*probe_id, 3001);
    probe_packet = probe_link.receive(p::Side::first);
    if (!repeated_probe || !repeated_probe->delivered || !probe_packet || !*probe_packet ||
        !(probe_view = p::parse_tcp4(**probe_packet)) || probe_view->sequence != 51) return 1;
    p::MemoryLink empty_probe_link;
    auto empty_probe_table = t::ConnectionTable::create(1, 8);
    auto empty_probe_id = empty_probe_table->open(syn, 50, 0);
    auto* empty_probe_flow = empty_probe_table->get(*empty_probe_id);
    if (!empty_probe_flow->input(ack, 0) || !empty_probe_flow->close_send()) return 1;
    t::MemoryEngine empty_probe_engine(empty_probe_link, *empty_probe_table, 40);
    if (empty_probe_engine.probe(*empty_probe_id, 0)->delivered) return 1;
    auto empty_probe = empty_probe_engine.probe(*empty_probe_id, 1000);
    auto empty_packet = empty_probe_link.receive(p::Side::first);
    if (!empty_probe || !empty_probe->delivered || empty_probe->bytes || !empty_packet || !*empty_packet) return 1;
    auto empty_view = p::parse_tcp4(**empty_packet);
    if (!empty_view || empty_view->flags != 0x10 || empty_view->sequence != 50 || !empty_view->payload.empty()) return 1;
    // FIN and FIN retransmission are also committed only after device delivery.
    p::MemoryLink fin_link({1500, 1, 1500});
    auto fin_table = t::ConnectionTable::create(1, 8);
    auto fin_id = fin_table->open(syn, 50, 0);
    auto* fin_flow = fin_table->get(*fin_id);
    ack.window=1; ack.acknowledgement=51;
    if (!fin_flow->input(ack, 0) || !fin_flow->close_send() || !fin_link.send(p::Side::second, sentinel)) return 1;
    t::MemoryEngine fin_engine(fin_link, *fin_table);
    auto blocked_fin = fin_engine.send_fin(*fin_id, 0);
    if (!blocked_fin || !blocked_fin->backpressured || blocked_fin->delivered || !fin_flow->fin_ready()) return 1;
    auto fin_sentinel = fin_link.receive(p::Side::first);
    if (!fin_sentinel || !*fin_sentinel || **fin_sentinel != sentinel) return 1;
    auto first_fin = fin_engine.send_fin(*fin_id, 1);
    auto fin_packet = fin_link.receive(p::Side::first);
    if (!first_fin || !first_fin->delivered || first_fin->connection_error || !fin_packet || !*fin_packet) return 1;
    auto fin_view = p::parse_tcp4(**fin_packet);
    if (!fin_view || fin_view->flags != 0x11 || fin_view->sequence != 51 || fin_flow->ack().sequence != 52 ||
        !fin_link.send(p::Side::second, sentinel)) return 1;
    auto retry_fin_blocked = fin_engine.send_fin(*fin_id, 1001, true);
    if (!retry_fin_blocked || !retry_fin_blocked->backpressured || retry_fin_blocked->delivered) return 1;
    fin_sentinel = fin_link.receive(p::Side::first);
    if (!fin_sentinel || !*fin_sentinel || **fin_sentinel != sentinel) return 1;
    auto retry_fin = fin_engine.send_fin(*fin_id, 1002, true);
    fin_packet = fin_link.receive(p::Side::first);
    if (!retry_fin || !retry_fin->delivered || retry_fin->connection_error || !fin_packet || !*fin_packet ||
        !(fin_view = p::parse_tcp4(**fin_packet)) || fin_view->sequence != 51 || fin_view->flags != 0x11) return 1;
    ack.acknowledgement=52;
    if (!fin_flow->input(ack, 1003) || !fin_flow->send_closed()) return 1;
    std::cout << "TCP memory engine preserves replies during backpressure\n";
}
