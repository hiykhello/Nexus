import std;
import nexus.tcp.engine;
namespace p = nexus::packet;
namespace t = nexus::tcp;
int main() {
    {
        p::MemoryLink link6;
        auto table6=t::ConnectionTable6::create(1,8);
        p::Tcp6View syn6{.source={0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1},
                         .destination={0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,2},
                         .source_port=1234,.destination_port=80,.sequence=99,.flags=2};
        auto id6=table6->open(syn6,50,0);
        t::MemoryEngine6 engine6(link6,*table6,1280);
        auto retransmit6=engine6.service(1000);
        auto packet6=link6.receive(p::Side::first);
        if (!id6 || !retransmit6 || retransmit6->action!=t::ServiceAction::syn_ack || !packet6 || !*packet6) return 1;
        auto view6=p::parse_tcp6(**packet6);
        if (!view6 || p::parse_tcp_syn_options(view6->options)->mss!=1220) return 1;
    }
    p::MemoryLink link({1500, 1, 1500});
    auto table = t::ConnectionTable::create(2, 8);
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=2};
    auto first = table->open(syn, 50, 0);
    auto other = syn; other.source_port++;
    auto second = table->open(other, 60, 0);
    if (!first || !second) return 1;
    t::MemoryEngine engine(link, *table);
    auto waiting = engine.service(0);
    auto waiting2 = engine.service(0);
    if (!waiting || waiting->id != *first || waiting->action != t::ServiceAction::none ||
        !waiting2 || waiting2->id != *second || waiting2->action != t::ServiceAction::none) return 1;
    p::Bytes sentinel{42};
    if (!link.send(p::Side::second, sentinel)) return 1;
    auto blocked = engine.service(1000);
    auto blocked2 = engine.service(1000);
    if (!blocked || blocked->id != *first || blocked->action != t::ServiceAction::syn_ack || !blocked->output.backpressured ||
        !blocked2 || blocked2->id != *second || !blocked2->output.backpressured) return 1;
    auto received = link.receive(p::Side::first);
    if (!received || !*received || **received != sentinel) return 1;
    auto retry_syn = engine.service(1001);
    received = link.receive(p::Side::first);
    if (!retry_syn || retry_syn->id != *first || retry_syn->action != t::ServiceAction::syn_ack ||
        !retry_syn->output.delivered || !received || !*received) return 1;
    auto response = p::parse_tcp4(**received);
    if (!response || response->flags != 0x12 || response->sequence != 50 ||
        p::parse_tcp_syn_options(response->options)->mss!=1460) return 1;
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=syn.source_port,
                    .destination_port=syn.destination_port, .sequence=100, .acknowledgement=51, .flags=0x10, .window=8};
    auto* f1 = table->get(*first); auto* f2 = table->get(*second);
    if (!f1->input(ack, 1001)) return 1;
    ack.source_port++; ack.acknowledgement=61;
    p::Bytes data1{'a'}, data2{'b'};
    if (!f2->input(ack, 1001) || !f1->enqueue(data1) || !f2->enqueue(data2)) return 1;
    auto send2 = engine.service(1002);
    received = link.receive(p::Side::first);
    if (!send2 || send2->id != *second || send2->action != t::ServiceAction::data || !send2->output.delivered || !received || !*received) return 1;
    response = p::parse_tcp4(**received);
    if (!response || response->destination_port != 1235 || !std::ranges::equal(response->payload, data2)) return 1;
    auto send1 = engine.service(1002);
    received = link.receive(p::Side::first);
    if (!send1 || send1->id != *first || send1->action != t::ServiceAction::data || !send1->output.delivered || !received || !*received) return 1;
    auto retry2 = engine.service(2002);
    auto retry1_blocked = engine.service(2002);
    if (!retry2 || retry2->id != *second || retry2->action != t::ServiceAction::retransmit || !retry2->output.delivered ||
        !retry1_blocked || retry1_blocked->id != *first || !retry1_blocked->output.backpressured) return 1;
    received = link.receive(p::Side::first);
    if (!received || !*received) return 1;
    auto idle = engine.service(2003);
    auto retry1 = engine.service(2003);
    if (!idle || idle->id != *second || idle->action != t::ServiceAction::none ||
        !retry1 || retry1->id != *first || retry1->action != t::ServiceAction::retransmit || !retry1->output.delivered) return 1;
    received = link.receive(p::Side::first);
    if (!received || !*received || !(response = p::parse_tcp4(**received)) || response->sequence != 51) return 1;
    auto rst = syn; rst.flags=4; rst.sequence=100;
    if (f1->input(rst, 2004).error() != t::ConnectionError::reset) return 1;
    auto other_turn = engine.service(2004);
    auto reclaimed = engine.service(2004);
    if (!other_turn || other_turn->id != *second || !reclaimed || reclaimed->id != *first ||
        reclaimed->action != t::ServiceAction::reclaimed || table->get(*first) || table->size() != 1) return 1;
    p::MemoryLink closing_link;
    auto closing_table = t::ConnectionTable::create(1, 8);
    auto closing_id = closing_table->open(syn, 50, 0);
    auto* closing_flow = closing_table->get(*closing_id);
    ack.source_port=1234; ack.acknowledgement=51; ack.window=0;
    if (!closing_flow->input(ack, 0) || !closing_flow->enqueue(data1)) return 1;
    t::MemoryEngine closing_engine(closing_link, *closing_table);
    auto initial = closing_engine.service(0);
    auto probe = closing_engine.service(1000);
    received = closing_link.receive(p::Side::first);
    if (!initial || initial->action != t::ServiceAction::none || !probe || probe->action != t::ServiceAction::probe ||
        !probe->output.delivered || !received || !*received || !(response = p::parse_tcp4(**received)) ||
        response->sequence != 51 || !std::ranges::equal(response->payload, data1)) return 1;
    ack.acknowledgement=52; ack.window=1;
    if (!closing_flow->input(ack, 1001) || !closing_flow->close_send()) return 1;
    auto fin = closing_engine.service(1001);
    received = closing_link.receive(p::Side::first);
    if (!fin || fin->action != t::ServiceAction::fin || !fin->output.delivered || !received || !*received ||
        !(response = p::parse_tcp4(**received)) || response->flags != 0x11 || response->sequence != 52) return 1;
    auto fin_retry = closing_engine.service(2001);
    received = closing_link.receive(p::Side::first);
    if (!fin_retry || fin_retry->action != t::ServiceAction::fin_retry || !fin_retry->output.delivered || !received || !*received) return 1;
    ack.flags=0x11; ack.acknowledgement=53;
    if (!closing_flow->input(ack, 2002)) return 1;
    auto retained = closing_engine.service(122001);
    auto awaiting_eof = closing_engine.service(122002);
    std::array<std::uint8_t, 1> buffer{};
    auto eof = closing_engine.read(*closing_id, buffer, 122002);
    auto closed = closing_engine.service(122002);
    if (!retained || retained->action != t::ServiceAction::none || !awaiting_eof ||
        awaiting_eof->action != t::ServiceAction::none || !eof || !eof->eof || !closed ||
        closed->action != t::ServiceAction::reclaimed || closing_table->size()) return 1;
    p::MemoryLink timeout_link;
    auto timeout_table = t::ConnectionTable::create(1, 8);
    auto timeout_id = timeout_table->open(syn, 50, 0);
    t::MemoryEngine timeout_engine(timeout_link, *timeout_table);
    for (auto now : {1000ull, 3000ull, 7000ull, 15000ull}) {
        auto retransmitted = timeout_engine.service(now);
        auto packet = timeout_link.receive(p::Side::first);
        if (!retransmitted || retransmitted->id != *timeout_id || retransmitted->action != t::ServiceAction::syn_ack ||
            !retransmitted->output.delivered || !packet || !*packet) return 1;
    }
    auto expired = timeout_engine.service(31000);
    if (!expired || expired->action != t::ServiceAction::reclaimed || timeout_table->size()) return 1;
    std::cout << "TCP bounded round-robin service and retransmission passed\n";
}
