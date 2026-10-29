import std;
import nexus.tcp.dispatch;
namespace p = nexus::packet;
namespace t = nexus::tcp;
int main() {
    auto table = t::ConnectionTable::create(1, 8);
    if (!table) return 1;
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=2};
    auto raw = p::make_tcp4(syn);
    if (!raw) return 1;
    auto corrupt = *raw; corrupt.back() ^= 1;
    if (t::dispatch(*table, corrupt, 50, 0).error().error != t::DispatchError::invalid_packet || table->size() ||
        t::dispatch(*table, *raw, 50, 0, 39).error().error != t::DispatchError::output_error || table->size()) return 1;
    auto first = t::dispatch(*table, *raw, 50, 0);
    if (!first || !first->opened || !first->reply || table->size() != 1) return 1;
    auto synack = p::parse_tcp4(*first->reply);
    if (!synack || synack->flags != 0x12 || synack->sequence != 50 || synack->acknowledgement != 100) return 1;
    auto duplicate = t::dispatch(*table, *raw, 999, 1);
    if (!duplicate || duplicate->id != first->id || duplicate->opened || duplicate->reply != first->reply) return 1;
    auto other = syn; other.source_port++;
    auto other_raw = p::make_tcp4(other);
    auto full = t::dispatch(*table, *other_raw, 60, 2);
    if (full || full.error().error != t::DispatchError::table_error || full.error().table_error != t::TableError::full) return 1;
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=syn.source_port,
                    .destination_port=syn.destination_port, .sequence=100, .acknowledgement=51, .flags=0x10, .window=8};
    for (auto invalid_ack : {50u,52u}) {
        auto bad=ack; bad.acknowledgement=invalid_ack;
        auto bad_raw=p::make_tcp4(bad);
        auto rejected=t::dispatch(*table,*bad_raw,0,2);
        if (!rejected || rejected->input_error!=t::ConnectionError::invalid_ack || !rejected->reply ||
            table->get(first->id)->state()!=t::ConnectionState::handshake) return 1;
        auto reset=p::parse_tcp4(*rejected->reply);
        if (!reset || reset->flags!=4 || reset->sequence!=invalid_ack || reset->acknowledgement ||
            reset->window || !reset->payload.empty()) return 1;
    }
    auto wrong_seq=ack; wrong_seq.sequence=108; wrong_seq.acknowledgement=52;
    auto wrong_raw=p::make_tcp4(wrong_seq);
    auto ignored_ack=t::dispatch(*table,*wrong_raw,0,2);
    if (!ignored_ack || ignored_ack->input_error!=t::ConnectionError::unacceptable || !ignored_ack->reply ||
        table->get(first->id)->state()!=t::ConnectionState::handshake) return 1;
    auto window_ack=p::parse_tcp4(*ignored_ack->reply);
    if (!window_ack || window_ack->flags!=0x10 || window_ack->sequence!=51 || window_ack->acknowledgement!=100) return 1;
    raw = p::make_tcp4(ack);
    auto established = t::dispatch(*table, *raw, 0, 3);
    if (!established || established->input_error || established->reply ||
        table->get(first->id)->state() != t::ConnectionState::established) return 1;
    p::Bytes data{'h','i'};
    ack.flags=0x18; ack.payload=data;
    raw = p::make_tcp4(ack);
    auto accepted = t::dispatch(*table, *raw, 0, 4);
    if (!accepted || !accepted->reply || accepted->input_error) return 1;
    auto response = p::parse_tcp4(*accepted->reply);
    if (!response || response->flags != 0x10 || response->sequence != 51 || response->acknowledgement != 102) return 1;
    auto retransmit = t::dispatch(*table, *raw, 0, 5);
    if (!retransmit || retransmit->input_error != t::ConnectionError::unacceptable || !retransmit->reply) return 1;
    response = p::parse_tcp4(*retransmit->reply);
    std::array<std::uint8_t, 2> output{};
    if (!response || response->acknowledgement != 102 || table->get(first->id)->read(output) != 2 ||
        output != std::array<std::uint8_t, 2>{'h','i'}) return 1;
    // An ACK beyond SND.NXT must elicit the current ACK and discard both
    // its payload and window update, leaving outstanding data unacknowledged.
    auto* flow=table->get(first->id);
    if (!flow->enqueue(data) || !flow->sent(1,5)) return 1;
    ack.sequence=102; ack.acknowledgement=53; ack.window=0; ack.flags=0x18; ack.payload=data;
    raw=p::make_tcp4(ack);
    auto future=t::dispatch(*table,*raw,0,5);
    if (!future || future->input_error!=t::ConnectionError::invalid_ack || !future->reply) return 1;
    response=p::parse_tcp4(*future->reply);
    if (!response || response->flags!=0x10 || response->sequence!=52 || response->acknowledgement!=102 ||
        !response->payload.empty() || flow->read(output)!=0 || flow->send_capacity()!=6 ||
        flow->unsent(8).bytes.size()!=1) return 1;
    ack.flags=4; ack.payload={}; ack.sequence=103;
    raw = p::make_tcp4(ack);
    auto challenge = t::dispatch(*table, *raw, 0, 6);
    if (!challenge || challenge->input_error != t::ConnectionError::challenge_ack || !challenge->reply) return 1;
    ack.sequence=1000; raw = p::make_tcp4(ack);
    auto ignored = t::dispatch(*table, *raw, 0, 7);
    if (!ignored || ignored->input_error != t::ConnectionError::unacceptable || ignored->reply) return 1;
    ack.sequence=102; raw = p::make_tcp4(ack);
    auto reset = t::dispatch(*table, *raw, 0, 8);
    if (!reset || reset->input_error != t::ConnectionError::reset || reset->reply ||
        table->reclaim(first->id, 8) != true) return 1;
    auto unknown = t::dispatch(*table, *raw, 0, 9);
    if (unknown || unknown.error().error != t::DispatchError::unknown_flow) return 1;
    std::cout << "TCP packet dispatch, ACK and reset handling passed\n";
}
