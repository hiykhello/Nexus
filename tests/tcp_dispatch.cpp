import std;
import nexus.tcp.dispatch;
namespace p = nexus::packet;
namespace t = nexus::tcp;
auto challenge_limit() -> bool {
    if (t::ConnectionTable::create(1,8,{2,0})) return false;
    auto table=t::ConnectionTable::create(2,8,{2,10});
    p::Tcp4View syn{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,
                    .destination_port=80,.sequence=99,.flags=2,.window=8};
    auto first=table->open(syn,50,0); syn.source_port++;
    auto second=table->open(syn,50,0);
    if (!first || !second) return false;
    auto ack=syn; ack.sequence=100; ack.acknowledgement=51; ack.flags=0x10;
    if (!table->get(*second)->input(ack,0)) return false;
    ack.source_port--; if (!table->get(*first)->input(ack,0)) return false;
    auto syn_attack=ack; syn_attack.flags=2; syn_attack.sequence=1000;
    auto wire=p::make_tcp4(syn_attack); auto a=t::dispatch(*table,*wire,0,100);
    syn_attack.source_port++; auto future=ack; future.source_port++; future.acknowledgement=52;
    wire=p::make_tcp4(future); auto b=t::dispatch(*table,*wire,0,100);
    wire=p::make_tcp4(syn_attack);
    auto suppressed=t::dispatch(*table,*wire,0,100);
    if (!a || !b || !a->reply || !b->reply || !suppressed || suppressed->reply || !suppressed->challenge_suppressed) return false;
    p::Bytes payload{'x'}; auto data=ack; data.flags=0x18; data.payload=payload;
    wire=p::make_tcp4(data); auto ordinary=t::dispatch(*table,*wire,0,100);
    if (!ordinary || !ordinary->reply || ordinary->challenge_suppressed) return false;
    syn_attack.source_port--; wire=p::make_tcp4(syn_attack);
    auto early=t::dispatch(*table,*wire,0,109); auto renewed=t::dispatch(*table,*wire,0,110);
    if (!early || early->reply || !early->challenge_suppressed || !renewed || !renewed->reply || renewed->challenge_suppressed) return false;
    auto backwards=table->claim_challenge_ack(109);
    auto disabled=t::ConnectionTable::create(1,8,{0,10});
    return !backwards && disabled && !disabled->claim_challenge_ack(1) && !disabled->claim_challenge_ack(11);
}
int main() {
    auto table6=t::ConnectionTable6::create(2,8,{1,1000});
    auto policy6=nexus::rules::Matcher::compile({{{"ip-cidr","192.0.2.0/24"},{"ip-cidr","2001:db8:1::/48"}}});
    if (!table6 || !policy6) return 1;
    p::Tcp6View syn6{.source={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                     .destination={0x20,1,0x0d,0xb8,0,2,0,0,0,0,0,0,0,0,0,2},
                     .source_port=1234,.destination_port=80,.sequence=99,.flags=2,.window=8};
    auto denied6=syn6; denied6.destination[5]=1;
    auto raw6=p::make_tcp6(denied6); if (!raw6) return 1;
    auto blocked6=t::dispatch_routed(*table6,*policy6,*raw6,50,0);
    if (blocked6 || blocked6.error().error!=t::DispatchError::blocked || table6->size()) return 1;
    denied6.destination={0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1};
    raw6=p::make_tcp6(denied6); blocked6=t::dispatch_routed(*table6,*policy6,*raw6,50,0);
    if (blocked6 || blocked6.error().error!=t::DispatchError::blocked || table6->size()) return 1;
    denied6.destination={}; raw6=p::make_tcp6(denied6); blocked6=t::dispatch_routed(*table6,*policy6,*raw6,50,0);
    if (blocked6 || blocked6.error().error!=t::DispatchError::invalid_target || table6->size()) return 1;
    raw6=p::make_tcp6(syn6); if (!raw6) return 1;
    if (t::dispatch(*table6,*raw6,50,0,59).error().error!=t::DispatchError::output_error || table6->size()) return 1;
    auto opened6=t::dispatch_routed(*table6,*policy6,*raw6,50,0);
    if (!opened6 || !opened6->opened || !opened6->reply || table6->size()!=1) return 1;
    auto synack6=p::parse_tcp6(*opened6->reply);
    if (!synack6 || synack6->source!=syn6.destination || synack6->destination!=syn6.source ||
        synack6->sequence!=50 || synack6->acknowledgement!=100 || synack6->flags!=0x12) return 1;
    auto ack6=syn6; ack6.flags=0x10; ack6.sequence=100; ack6.acknowledgement=51;
    auto invalid_ack6=ack6; invalid_ack6.acknowledgement=52;
    raw6=p::make_tcp6(invalid_ack6); auto invalid6=t::dispatch(*table6,*raw6,0,1);
    if (!invalid6 || invalid6->input_error!=t::ConnectionError::invalid_ack || !invalid6->reply) return 1;
    auto reset6=p::parse_tcp6(*invalid6->reply);
    if (!reset6 || reset6->flags!=4 || reset6->sequence!=52 || reset6->acknowledgement!=0) return 1;
    raw6=p::make_tcp6(ack6); auto established6=t::dispatch(*table6,*raw6,0,1);
    if (!established6 || established6->reply || table6->get(opened6->id)->state()!=t::ConnectionState::established) return 1;
    p::Bytes body6{'h','i'}; ack6.flags=0x18; ack6.payload=body6;
    raw6=p::make_tcp6(ack6); auto received6=t::dispatch(*table6,*raw6,0,2);
    if (!received6 || !received6->reply || received6->input_error) return 1;
    auto reply6=p::parse_tcp6(*received6->reply); std::array<std::uint8_t,2> data6{};
    if (!reply6 || reply6->acknowledgement!=102 || table6->get(opened6->id)->read(data6)!=2 ||
        !std::ranges::equal(data6,body6)) return 1;
    auto attack6=ack6; attack6.flags=2; attack6.sequence=102; attack6.payload={};
    raw6=p::make_tcp6(attack6); auto challenge6=t::dispatch(*table6,*raw6,0,3);
    auto suppressed6=t::dispatch(*table6,*raw6,0,3);
    if (!challenge6 || !challenge6->reply || !suppressed6 || suppressed6->reply || !suppressed6->challenge_suppressed) return 1;
    if (!challenge_limit()) return 1;
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
    ack.acknowledgement=42; ack.flags=0x19;
    raw=p::make_tcp4(ack);
    auto old=t::dispatch(*table,*raw,0,5);
    if (!old || old->input_error!=t::ConnectionError::invalid_ack || !old->reply) return 1;
    response=p::parse_tcp4(*old->reply);
    if (!response || response->flags!=0x10 || response->sequence!=52 || response->acknowledgement!=102 ||
        flow->state()!=t::ConnectionState::established || flow->read(output)!=0 || flow->send_capacity()!=6 ||
        flow->unsent(8).bytes.size()!=1) return 1;
    // Unexpected SYNs inside or outside the receive window must neither
    // acknowledge outstanding bytes nor inject data or replace the flow.
    for (auto sequence : {102u,1000u}) {
        auto unexpected=ack; unexpected.sequence=sequence; unexpected.flags=0x1a;
        auto wire=p::make_tcp4(unexpected);
        auto challenged=t::dispatch(*table,*wire,999,5);
        if (!challenged || challenged->input_error!=t::ConnectionError::challenge_ack || !challenged->reply ||
            table->get(first->id)!=flow || flow->state()!=t::ConnectionState::established) return 1;
        auto reply=p::parse_tcp4(*challenged->reply);
        if (!reply || reply->flags!=0x10 || reply->sequence!=52 || reply->acknowledgement!=102 ||
            !reply->payload.empty() || flow->read(output)!=0 || flow->send_capacity()!=6 ||
            flow->unsent(8).bytes.size()!=1) return 1;
    }
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
