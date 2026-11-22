import std;
import packet;
import tcp.connection;
namespace p = ::packet;
namespace t = tcp;
int main() {
    p::Tcp6View syn6{.source={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                     .destination={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                     .source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    auto c6=t::PassiveConnection6::accept(syn6,50,4096,0);
    if (!c6 || c6->syn_ack().source!=syn6.destination || c6->syn_ack().destination!=syn6.source) return 1;
    p::Bytes body6{'a','b'};
    p::Tcp6View ack6{.source=syn6.source,.destination=syn6.destination,.source_port=1234,.destination_port=80,
                     .sequence=100,.acknowledgement=51,.flags=0x18,.window=4096,.payload=body6};
    auto wrong6=ack6; wrong6.source[15]=3;
    if (c6->input(wrong6).error()!=t::ConnectionError::wrong_peer || c6->state()!=t::ConnectionState::handshake) return 1;
    if (!c6->input(ack6) || c6->ack().acknowledgement!=102 || c6->ack().destination!=syn6.source) return 1;
    std::array<std::uint8_t,2> read6{};
    if (c6->read(read6)!=2 || !std::ranges::equal(read6,body6)) return 1;
    p::Bytes outgoing6(1400,'x');
    if (!c6->enqueue(outgoing6) || c6->unsent(1400).bytes.size()!=1220 || !c6->sent(1220,1)) return 1;
    ack6.sequence=102; ack6.acknowledgement=1271; ack6.flags=0x11; ack6.payload={};
    if (!c6->input(ack6,2) || !c6->eof() || c6->state()!=t::ConnectionState::peer_closed ||
        c6->ack().acknowledgement!=103 || c6->unsent(1400).bytes.size()!=180) return 1;
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=0xfffffffe, .flags=2};
    auto c = t::PassiveConnection::accept(syn, 50, 4, 0);
    if (!c || c->syn_ack().acknowledgement != 0xffffffff || c->poll(999) != t::HandshakeTimerEvent::waiting ||
        c->poll(1000) != t::HandshakeTimerEvent::retransmit || !c->retransmitted(1000)) return 1;
    auto pending_reset = t::PassiveConnection::accept(syn, 50, 4, 0);
    p::Tcp4View pending_rst{.source=syn.source, .destination=syn.destination, .source_port=1234,
                            .destination_port=80, .sequence=0, .flags=4};
    if (!pending_reset || pending_reset->input(pending_rst).error() != t::ConnectionError::challenge_ack ||
        pending_reset->state() != t::ConnectionState::handshake) return 1;
    pending_rst.sequence = 100;
    if (pending_reset->input(pending_rst).error() != t::ConnectionError::unacceptable) return 1;
    pending_rst.sequence = 0xffffffff; pending_rst.source_port++;
    if (pending_reset->input(pending_rst).error() != t::ConnectionError::wrong_peer) return 1;
    pending_rst.source_port--;
    if (pending_reset->input(pending_rst).error() != t::ConnectionError::reset ||
        pending_reset->state() != t::ConnectionState::reset ||
        pending_reset->poll(1000).error() != t::ConnectionError::unsupported) return 1;
    p::Bytes data{'a','b'};
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=1234, .destination_port=80,
                    .sequence=0xffffffff, .acknowledgement=51, .flags=0x18, .payload=data};
    // The final ACK can carry data after a gap, including across sequence wrap.
    auto handshake_reordered=t::PassiveConnection::accept(syn,50,4,0);
    auto late=ack; late.sequence=0; late.payload=std::span{data}.subspan(1);
    if (!handshake_reordered || !handshake_reordered->input(late) || handshake_reordered->state()!=t::ConnectionState::established ||
        handshake_reordered->ack().acknowledgement!=0xffffffff) return 1;
    auto early=ack; early.payload=std::span{data}.first(1);
    std::array<std::uint8_t,2> handshake_reordered_output{};
    if (!handshake_reordered->input(early) || handshake_reordered->ack().acknowledgement!=1 ||
        handshake_reordered->read(handshake_reordered_output)!=2 || handshake_reordered_output!=std::array<std::uint8_t,2>{'a','b'}) return 1;
    if (c->input(ack, 999).error() != t::ConnectionError::time_reversed || c->state() != t::ConnectionState::handshake) return 1;
    auto result = c->input(ack, 1000);
    if (!result || !*result || c->state() != t::ConnectionState::established || c->ack().acknowledgement != 1 ||
        c->ack().window != 2) return 1;
    auto forged = ack; forged.source_port++;
    if (c->input(forged, 1000).error() != t::ConnectionError::wrong_peer || c->ack().acknowledgement != 1) return 1;
    ack.sequence = 1; ack.acknowledgement = 52;
    if (c->input(ack, 1000).error() != t::ConnectionError::invalid_ack || c->ack().acknowledgement != 1) return 1;
    std::array<std::uint8_t, 2> out{};
    if (c->read(out) != 2 || !std::ranges::equal(out, data) || c->ack().window != 4) return 1;
    ack.acknowledgement = 51; ack.sequence = 3; ack.flags = 0x11; ack.payload = {};
    if (!c->input(ack, 1000) || c->state() != t::ConnectionState::established || c->ack().acknowledgement != 1) return 1;
    ack.sequence = 1; ack.flags = 0x18; ack.payload = data;
    if (!c->input(ack, 1000) || c->state() != t::ConnectionState::peer_closed || c->ack().acknowledgement != 4 || c->eof()) return 1;
    ack.sequence = 3; ack.flags = 0x11; ack.payload = {};
    if (!c->input(ack, 1000) || c->ack().acknowledgement != 4 || c->read(out) != 2 ||
        !std::ranges::equal(out, data) || !c->eof()) return 1;
    auto together = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.flags = 0x10;
    if (!together || !together->input(ack)) return 1;
    ack.flags = 0x19; ack.payload = data;
    if (!together->input(ack) || together->ack().acknowledgement != 2 || together->eof() ||
        together->read(out) != 2 || !together->eof()) return 1;
    auto handshake_fin = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.flags = 0x19; ack.payload = data;
    if (!handshake_fin || !handshake_fin->input(ack) || handshake_fin->state() != t::ConnectionState::peer_closed ||
        handshake_fin->ack().acknowledgement != 2 || handshake_fin->eof() ||
        handshake_fin->read(out) != 2 || out != std::array<std::uint8_t, 2>{'a','b'} || !handshake_fin->eof()) return 1;
    auto full_handshake_fin = t::PassiveConnection::accept(syn, 50, 2, 0);
    if (!full_handshake_fin || !full_handshake_fin->input(ack) || full_handshake_fin->ack().acknowledgement != 1 ||
        full_handshake_fin->state() != t::ConnectionState::established || full_handshake_fin->read(out) != 2) return 1;
    ack.sequence = 1; ack.flags = 0x11; ack.payload = {};
    if (!full_handshake_fin->input(ack, 1) || full_handshake_fin->ack().acknowledgement != 2 || !full_handshake_fin->eof()) return 1;
    auto duplex = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.flags = 0x10; ack.payload = {}; ack.window = 2;
    if (!duplex || !duplex->input(ack) || !duplex->enqueue(data)) return 1;
    auto sending = duplex->unsent(4);
    if (sending.sequence != 51 || sending.bytes != data || !duplex->sent(2, 10) ||
        !duplex->unsent(4).bytes.empty() || duplex->ack().sequence != 53) return 1;
    auto out_of_window = ack; out_of_window.sequence = 100; out_of_window.acknowledgement = 53; out_of_window.window = 4;
    if (duplex->input(out_of_window, 11).error() != t::ConnectionError::unacceptable ||
        !duplex->unsent(4).bytes.empty()) return 1;
    auto due = duplex->send_due(1010, 4);
    if (!due || !*due || (**due).sequence != 51 || (**due).bytes != data || !duplex->send_retransmitted(1010)) return 1;
    ack.acknowledgement = 52; ack.window = 1;
    if (!duplex->input(ack, 1011) || duplex->ack().sequence != 53 || !duplex->unsent(4).bytes.empty()) return 1;
    ack.acknowledgement = 53; ack.window = 4;
    if (!duplex->input(ack, 1012) || !duplex->enqueue(data) || duplex->unsent(4).sequence != 53 ||
        duplex->unsent(4).bytes != data) return 1;
    if (!duplex->close_send() || duplex->fin_ready() || duplex->enqueue(data).error() != t::ConnectionError::unsupported ||
        !duplex->sent(2, 1013)) return 1;
    ack.acknowledgement = 55;
    if (!duplex->input(ack, 1014) || !duplex->fin_ready() || duplex->fin().sequence != 55 ||
        duplex->fin_sent(1013).error() != t::ConnectionError::time_reversed || !duplex->fin_sent(1014) ||
        duplex->ack().sequence != 56) return 1;
    if (duplex->fin_due(2013) != false || duplex->fin_due(2014) != true ||
        !duplex->fin_retransmitted(2014) || duplex->fin().sequence != 55 || duplex->fin_due(2014) != false) return 1;
    ack.acknowledgement = 56;
    if (!duplex->input(ack, 2015) || !duplex->send_closed() ||
        duplex->fin_due(4014).error() != t::ConnectionError::unsupported) return 1;
    // Repeated peer FIN may carry the ACK of our FIN after the first ACK was lost.
    auto simultaneous = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.flags = 0x10; ack.payload = {}; ack.window = 4;
    if (!simultaneous || !simultaneous->input(ack) || !simultaneous->close_send() || !simultaneous->fin_sent(1)) return 1;
    ack.flags = 0x11; ack.acknowledgement = 51;
    if (!simultaneous->input(ack, 2) || simultaneous->state() != t::ConnectionState::peer_closed || simultaneous->send_closed()) return 1;
    ack.acknowledgement = 52;
    if (!simultaneous->input(ack, 3) || !simultaneous->send_closed() || simultaneous->ack().acknowledgement != 0) return 1;
    if (simultaneous->time_wait_deadline() != 120003 || simultaneous->reclaimable(120002) != false ||
        !simultaneous->input(ack, 120002)) return 1;
    if (simultaneous->time_wait_deadline() != 240002 || simultaneous->reclaimable(240001) != false ||
        simultaneous->reclaimable(240002) != true ||
        simultaneous->reclaimable(240001).error() != t::ConnectionError::time_reversed) return 1;
    if (simultaneous->input(ack, 240002).error() != t::ConnectionError::expired ||
        simultaneous->time_wait_deadline() != 240002) return 1;
    // A retransmitted data+FIN can acknowledge our FIN and restart TIME-WAIT.
    auto fin_with_data = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.flags = 0x10; ack.payload = {}; ack.window = 4;
    if (!fin_with_data || !fin_with_data->input(ack) || !fin_with_data->close_send() || !fin_with_data->fin_sent(1)) return 1;
    ack.flags = 0x19; ack.payload = data;
    if (!fin_with_data->input(ack, 2) || fin_with_data->ack().acknowledgement != 2) return 1;
    ack.acknowledgement = 52;
    if (!fin_with_data->input(ack, 3) || !fin_with_data->send_closed() ||
        fin_with_data->time_wait_deadline() != 120003 || fin_with_data->read(out) != 2 ||
        out != std::array<std::uint8_t, 2>{'a','b'} || !fin_with_data->eof()) return 1;
    if (!fin_with_data->input(ack, 4) || fin_with_data->time_wait_deadline() != 120004 ||
        fin_with_data->read(out) != 0 || !fin_with_data->eof()) return 1;
    auto passive = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.flags = 0x10; ack.payload = {}; ack.window = 4;
    if (!passive || !passive->input(ack)) return 1;
    ack.flags = 0x19; ack.payload = data;
    if (!passive->input(ack, 1) || !passive->close_send() || !passive->fin_sent(2)) return 1;
    ack.sequence = 2; ack.flags = 0x10; ack.payload = {}; ack.acknowledgement = 52;
    if (!passive->input(ack, 3) || passive->time_wait_deadline() || passive->reclaimable(3) != false ||
        passive->read(out) != 2 || passive->reclaimable(3) != true) return 1;
    if (passive->input(ack, 3).error() != t::ConnectionError::expired) return 1;
    auto unread = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.flags = 0x10; ack.payload = {}; ack.window = 4;
    if (!unread || !unread->input(ack) || !unread->close_send() || !unread->fin_sent(1)) return 1;
    ack.flags = 0x19; ack.payload = data; ack.acknowledgement = 52;
    if (!unread->input(ack, 2) || unread->time_wait_deadline() != 120002 || unread->reclaimable(120002) != false) return 1;
    if (unread->input(ack, 120002).error() != t::ConnectionError::expired || unread->read(out) != 2 ||
        unread->reclaimable(120002) != true) return 1;
    auto zero = t::PassiveConnection::accept(syn, 50, 2, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.window = 2; ack.flags = 0x10; ack.payload = {};
    if (!zero || !zero->input(ack) || !zero->enqueue(data) || !zero->sent(2, 1)) return 1;
    ack.payload = data; ack.flags = 0x18;
    if (!zero->input(ack, 2) || zero->ack().window != 0 || zero->ack().acknowledgement != 1) return 1;
    ack.sequence = 2; ack.acknowledgement = 53; ack.flags = 0x10; ack.payload = {};
    if (zero->input(ack, 3).error() != t::ConnectionError::unacceptable) return 1;
    ack.sequence = 1;
    if (!zero->input(ack, 4) || zero->send_due(1001, 2)->has_value()) return 1;
    // Lost window updates are recovered by a committed, exponentially backed-off probe.
    auto persist = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.window = 0;
    if (!persist || !persist->input(ack) || !persist->enqueue(data) ||
        persist->probe_due(10)->has_value() || persist->probe_due(1009)->has_value()) return 1;
    auto probe = persist->probe_due(1010);
    if (!probe || !*probe || (**probe).sequence != 51 || (**probe).bytes != p::Bytes{'a'} ||
        persist->ack().sequence != 51 || !persist->probe_sent(1010) || persist->ack().sequence != 52 ||
        persist->probe_due(3009)->has_value()) return 1;
    probe = persist->probe_due(3010);
    if (!probe || !*probe || (**probe).sequence != 51 || (**probe).bytes != p::Bytes{'a'} ||
        !persist->probe_sent(3010)) return 1;
    ack.acknowledgement = 52; ack.window = 1;
    if (!persist->input(ack, 3011) || persist->probe_due(3011)->has_value() ||
        persist->unsent(2).sequence != 52 || persist->unsent(2).bytes != p::Bytes{'b'}) return 1;
    auto closing_zero = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.acknowledgement = 51; ack.window = 0;
    if (!closing_zero || !closing_zero->input(ack) || !closing_zero->close_send() ||
        closing_zero->probe_due(0)->has_value()) return 1;
    probe = closing_zero->probe_due(1000);
    if (!probe || !*probe || (**probe).sequence != 50 || !(**probe).bytes.empty() ||
        !closing_zero->probe_sent(1000)) return 1;
    ack.window = 1;
    if (!closing_zero->input(ack, 1001) || !closing_zero->fin_ready()) return 1;
    // An old ACK must not discard valid data or roll the peer window back,
    // including when the send sequence has wrapped around zero.
    auto reordered = t::PassiveConnection::accept(syn, 0xfffffffe, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 0xffffffff; ack.window = 4;
    if (!reordered || !reordered->input(ack) || !reordered->enqueue(data) || !reordered->sent(2, 1)) return 1;
    ack.acknowledgement = 1;
    if (!reordered->input(ack, 2)) return 1;
    auto reduced=ack; reduced.window=0;
    if (!reordered->input(reduced, 2)) return 1;
    // A stale ACK outside the largest advertised window must not inject data
    // or FIN. The inclusive boundary is still accepted across sequence wrap.
    auto forged_old=ack; forged_old.acknowledgement=0xfffffffcu; forged_old.flags=0x19; forged_old.payload=data;
    if (reordered->input(forged_old, 2).error()!=t::ConnectionError::invalid_ack ||
        reordered->ack().acknowledgement!=0xffffffff || reordered->state()!=t::ConnectionState::established ||
        reordered->read(out)!=0) return 1;
    auto edge=ack; edge.acknowledgement=0xfffffffdu;
    if (!reordered->input(edge, 2)) return 1;
    if (!reordered->input(ack, 2)) return 1;
    ack.acknowledgement = 0xffffffff; ack.window = 0; ack.flags = 0x18; ack.payload = data;
    if (!reordered->input(ack, 3) || reordered->ack().acknowledgement != 1 ||
        reordered->read(out) != 2 || out != std::array<std::uint8_t, 2>{'a', 'b'} ||
        !reordered->enqueue(data) || reordered->unsent(2).bytes != data) return 1;
    ack.flags = 0x10; ack.payload = {};
    // Window ordering uses both segment sequence and ACK, even across wrap.
    auto windows = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.window = 4;
    if (!windows || !windows->input(ack) || !windows->enqueue(data) || !windows->sent(1, 1)) return 1;
    ack.sequence = 0; ack.window = 0;
    if (!windows->input(ack, 2) || !windows->unsent(2).bytes.empty()) return 1;
    ack.sequence = 0xffffffff; ack.acknowledgement = 52; ack.window = 4;
    if (!windows->input(ack, 3) || !windows->unsent(2).bytes.empty()) return 1;
    ack.sequence = 0;
    if (!windows->input(ack, 4) || windows->unsent(2).bytes != p::Bytes{'b'}) return 1;
    // A reduced advertised window limits retransmission of already-sent data.
    auto shrinking = t::PassiveConnection::accept(syn, 50, 8, 0);
    p::Bytes four{'a','b','c','d'};
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.window = 4;
    if (!shrinking || !shrinking->input(ack) || !shrinking->enqueue(four) || !shrinking->sent(4, 0)) return 1;
    ack.window = 1;
    if (!shrinking->input(ack, 1)) return 1;
    auto narrow = shrinking->send_due(1000, 4);
    if (!narrow || !*narrow || (**narrow).sequence != 51 || (**narrow).bytes != p::Bytes{'a'} ||
        !shrinking->send_retransmitted(1000)) return 1;
    ack.acknowledgement = 52; ack.window = 0;
    if (!shrinking->input(ack, 1001) || shrinking->probe_due(1001)->has_value()) return 1;
    auto narrow_probe = shrinking->probe_due(2001);
    if (!narrow_probe || !*narrow_probe || (**narrow_probe).sequence != 52 ||
        (**narrow_probe).bytes != p::Bytes{'b'} || !shrinking->probe_sent(2001)) return 1;
    ack.window = 3;
    if (!shrinking->input(ack, 2002)) return 1;
    narrow = shrinking->send_due(3001, 4);
    if (!narrow || !*narrow || (**narrow).sequence != 52 || (**narrow).bytes != p::Bytes{'b','c','d'}) return 1;
    auto resets = t::PassiveConnection::accept(syn, 50, 4, 0);
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.window = 4;
    if (!resets || !resets->input(ack) || !resets->enqueue(data) || !resets->sent(2, 0)) return 1;
    auto rst = ack; rst.flags = 4; rst.sequence = 0; rst.acknowledgement = 53;
    if (resets->input(rst).error() != t::ConnectionError::challenge_ack || resets->state() != t::ConnectionState::established) return 1;
    rst.sequence = 100;
    if (resets->input(rst).error() != t::ConnectionError::unacceptable || resets->state() != t::ConnectionState::established) return 1;
    rst.source_port++; rst.sequence = 0xffffffff;
    if (resets->input(rst).error() != t::ConnectionError::wrong_peer) return 1;
    rst.source_port--;
    if (resets->input(rst).error() != t::ConnectionError::reset || resets->state() != t::ConnectionState::reset ||
        resets->send_due(1000, 2).error() != t::ConnectionError::unsupported || resets->read(out) || resets->eof() ||
        resets->input(ack).error() != t::ConnectionError::reset) return 1;
    auto clocked = t::PassiveConnection::accept(syn, 50, 4, 100);
    if (!clocked || !clocked->input(ack, 100) || !clocked->close_send() || !clocked->fin_sent(101) ||
        !clocked->send_due(200, 1)) return 1;
    if (clocked->fin_due(199).error() != t::ConnectionError::time_reversed ||
        clocked->reclaimable(199).error() != t::ConnectionError::time_reversed || clocked->fin_due(200) != false) return 1;
    auto old_rst = ack; old_rst.flags = 4; old_rst.sequence = 0xffffffff;
    if (clocked->input(old_rst, 199).error() != t::ConnectionError::time_reversed ||
        clocked->state() != t::ConnectionState::established) return 1;
    auto old_fin_ack = ack; old_fin_ack.acknowledgement = 52;
    if (clocked->input(old_fin_ack, 199).error() != t::ConnectionError::time_reversed || clocked->send_closed() ||
        !clocked->input(old_fin_ack, 200) || !clocked->send_closed()) return 1;
    auto fin_clock = t::PassiveConnection::accept(syn, 50, 4, 0);
    if (!fin_clock || !fin_clock->input(ack, 0) || !fin_clock->close_send() || !fin_clock->fin_sent(1) ||
        !fin_clock->send_due(2000, 1) ||
        fin_clock->fin_retransmitted(1001).error() != t::ConnectionError::time_reversed ||
        fin_clock->fin_due(2000) != true || !fin_clock->fin_retransmitted(2000)) return 1;
    auto timeout = t::PassiveConnection::accept(syn, 50, 4, 0);
    if (!timeout) return 1;
    for (auto now : {1000ull, 3000ull, 7000ull, 15000ull})
        if (timeout->poll(now) != t::HandshakeTimerEvent::retransmit || !timeout->retransmitted(now)) return 1;
    if (timeout->poll(31000) != t::HandshakeTimerEvent::expired || timeout->state() != t::ConnectionState::expired ||
        timeout->input(ack).error() != t::ConnectionError::expired) return 1;
    auto direct_expiry = t::PassiveConnection::accept(syn, 50, 4, 0);
    for (auto now : {1000ull, 3000ull, 7000ull, 15000ull}) if (!direct_expiry->retransmitted(now)) return 1;
    if (direct_expiry->retransmitted(31000).error() != t::ConnectionError::expired ||
        direct_expiry->state() != t::ConnectionState::expired) return 1;
    auto late_ack = t::PassiveConnection::accept(syn, 50, 4, 0);
    for (auto now : {1000ull, 3000ull, 7000ull, 15000ull}) if (!late_ack->retransmitted(now)) return 1;
    ack.sequence = 0xffffffff; ack.acknowledgement = 51; ack.flags = 0x10; ack.payload = {};
    if (late_ack->input(ack, 31000).error() != t::ConnectionError::expired ||
        late_ack->state() != t::ConnectionState::expired) return 1;
    std::cout << "TCP passive connection handshake, receive and timeout passed\n";
}
