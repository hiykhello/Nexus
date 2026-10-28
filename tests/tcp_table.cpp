import std;
import nexus.tcp.table;
namespace p = nexus::packet;
namespace t = nexus::tcp;
int main() {
    if (t::ConnectionTable::create(0, 8) || t::ConnectionTable::create(1, 0) ||
        t::ConnectionTable::create(1, 65536)) return 1;
    auto table = t::ConnectionTable::create(2, 8);
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=2};
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
