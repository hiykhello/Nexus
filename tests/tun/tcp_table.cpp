import std;
import tcp.table;
namespace p = ::packet;
namespace t = tcp;
template<class Table,class View>
auto watch_reuse(View syn) -> bool {
    auto table=Table::create(2,8); if (!table) return false;
    auto token=table->watch(syn); auto same=table->watch(syn);
    if (same!=token || table->watched_generations()!=1) return false;
    auto other=syn; ++other.source_port;
    auto unrelated=table->open(other,10,0);
    if (!unrelated || !token->valid) return false;
    auto bad=syn; bad.flags=0x10;
    if (table->open(bad,10,0) || !token->valid) return false;
    auto flow=table->open(syn,10,0);
    if (!flow || token->valid || same->valid || !table->abort(*flow) || token->valid) return false;
    auto next=table->watch(syn);
    if (!next->valid || !table->abort(*unrelated)) return false;
    auto reopened=table->open(syn,20,1);
    if (!reopened || next->valid || token->valid) return false;
    p::MemoryLink link; p::Bytes bytes{42};
    auto queued=table->watch(syn); std::weak_ptr<p::TcpGeneration> lifetime=queued;
    if (!link.send(p::Side::second,bytes,p::PacketKind::ordinary,0,queued)) return false;
    queued.reset(); if (lifetime.expired()) return false;
    link.close(p::Side::first);
    return lifetime.expired();
}
int main() {
    auto table6=t::ConnectionTable6::create(2,8);
    if (!table6 || t::ConnectionTable6::create(0,8)) return 1;
    p::Tcp6View syn6{.source={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                     .destination={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                     .source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    if (!watch_reuse<t::ConnectionTable6>(syn6)) return 1;
    auto id6=table6->open(syn6,50,0);
    auto syn6b=syn6; syn6b.source[15]=3;
    auto id6b=table6->open(syn6b,60,0);
    if (!id6 || !id6b || *id6==*id6b || table6->find(syn6)!=*id6 || table6->find(syn6b)!=*id6b ||
        table6->open(syn6,50,0).error()!=t::TableError::duplicate || table6->size()!=2) return 1;
    auto syn6c=syn6; syn6c.destination[15]=4;
    if (table6->open(syn6c,70,0).error()!=t::TableError::full || table6->find(syn6c)) return 1;
    auto target6=table6->target(*id6);
    if (!target6 || target6->address!=syn6.destination || target6->port!=80) return 1;
    p::Tcp6View ack6{.source=syn6.source,.destination=syn6.destination,.source_port=1234,.destination_port=80,
                     .sequence=100,.acknowledgement=51,.flags=0x10,.window=8};
    auto* first6=table6->get(*id6);
    if (!first6 || !first6->input(ack6,0) || !first6->close_send() || !first6->fin_sent(1)) return 1;
    ack6.flags=0x11; ack6.acknowledgement=52;
    if (!first6->input(ack6,2) || table6->reclaim(*id6,120002)!=false || !table6->observe_eof(*id6) ||
        table6->reclaim(*id6,120002)!=true || table6->find(syn6)) return 1;
    auto fresh6=table6->open(syn6,70,120002);
    if (!fresh6 || *fresh6==*id6 || !table6->abort(*fresh6) || !table6->abort(*id6b) || table6->size()) return 1;
    if (t::ConnectionTable::create(0, 8) || t::ConnectionTable::create(1, 0) ||
        t::ConnectionTable::create(1, 65536)) return 1;
    auto table = t::ConnectionTable::create(2, 8);
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=2};
    if (!watch_reuse<t::ConnectionTable>(syn)) return 1;
    auto invalid = syn; invalid.flags = 0x10;
    if (table->open(invalid, 50, 0).error() != t::TableError::invalid_syn || table->size()) return 1;
    auto id = table->open(syn, 50, 0);
    auto syn2 = syn; syn2.source_port++;
    auto id2 = table->open(syn2, 60, 0);
    auto syn3 = syn; syn3.source_port += 2;
    if (!id || !id2 || *id == *id2 || table->find(syn) != *id || table->find(syn2) != *id2 ||
        table->open(syn, 50, 0).error() != t::TableError::duplicate ||
        table->open(syn3, 70, 0).error() != t::TableError::full || table->size() != 2) return 1;
    auto* first = table->get(*id);
    auto* second = table->get(*id2);
    if (!first || !second || table->get(999) || table->observe_eof(*id) || table->observe_eof(999) ||
        table->reclaim(*id, 0) != false) return 1;
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=syn.source_port,
                    .destination_port=syn.destination_port, .sequence=100, .acknowledgement=51, .flags=0x10, .window=8};
    if (!first->input(ack, 0) || !first->close_send() || !first->fin_sent(1)) return 1;
    if (table->reclaim(*id, 0).error() != t::TableError::time_reversed || table->size() != 2) return 1;
    ack.flags = 0x11; ack.acknowledgement = 52;
    if (!first->input(ack, 2) || table->reclaim(*id, 120001) != false ||
        table->open(syn, 100, 120001).error() != t::TableError::duplicate ||
        table->reclaim(*id, 120002) != false || !table->observe_eof(*id) ||
        table->reclaim(*id, 120002) != true || table->get(*id) || table->find(syn)) return 1;
    auto replacement = table->open(syn, 100, 120002);
    if (!replacement || *replacement == *id || table->get(*id2) != second || table->size() != 2 ||
        table->reclaim(*id, 120002).error() != t::TableError::not_found) return 1;
    // A handshake timeout is removed only after its retransmission budget is committed.
    for (auto now : {1000ull, 3000ull, 7000ull, 15000ull}) if (!second->retransmitted(now)) return 1;
    if (table->reclaim(*id2, 30999) != false || table->reclaim(*id2, 31000) != true || table->get(*id2)) return 1;
    auto fresh = table->open(syn2, 60, 31000);
    if (!fresh || *fresh == *id2 || !table->abort(*fresh) || table->abort(*fresh) || table->size() != 1) return 1;
    auto reset = table->get(*replacement);
    auto rst = syn; rst.flags = 4; rst.sequence = 100;
    if (!reset || reset->input(rst, 120002).error() != t::ConnectionError::reset ||
        table->reclaim(*replacement, 120002) != true || table->size()) return 1;
    std::cout << "TCP bounded connection table, tuple retention and reclamation passed\n";
}
