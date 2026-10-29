import std;
import nexus.packet;
import nexus.tcp.handshake;
import nexus.tcp.receive;
namespace p = nexus::packet;
namespace t = nexus::tcp;
int main() {
    for (std::uint16_t flags : {0x02,0x42,0x82,0xc2})
        if (!t::is_initial_syn(flags)) return 1;
    for (std::uint16_t flags : {0x00,0x03,0x12,0xc3,0x1c2})
        if (t::is_initial_syn(flags)) return 1;

    p::Tcp6View syn6{.source={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                     .destination={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                     .source_port=1234,.destination_port=80,.sequence=0xffffffff,.flags=2};
    auto raw6=p::make_tcp6(syn6); if (!raw6) return 1;
    auto decoded6=p::parse_tcp6(*raw6); if (!decoded6) return 1;
    auto h6=t::PassiveHandshake6::accept(*decoded6,0xffffffff);
    if (!h6 || h6->peer_mss()!=1220 || h6->receive_next()!=0 || h6->send_next()!=0) return 1;
    auto response6=p::make_tcp6(h6->syn_ack(4096));
    if (!response6) return 1;
    auto view6=p::parse_tcp6(*response6);
    if (!view6 || view6->destination!=syn6.source || view6->source!=syn6.destination || view6->flags!=0x12) return 1;
    p::Tcp6View ack6{.source=syn6.source,.destination=syn6.destination,.source_port=1234,
                     .destination_port=80,.sequence=0,.acknowledgement=0,.flags=0x10};
    auto wrong6=ack6; wrong6.source[15]=3;
    if (h6->input(wrong6,1).error()!=t::HandshakeError::wrong_peer || h6->established()) return 1;
    wrong6=ack6; wrong6.acknowledgement=1;
    if (h6->input(wrong6,1).error()!=t::HandshakeError::invalid_ack || h6->established()) return 1;
    auto completed6=h6->input(ack6,1);
    if (!completed6 || !*completed6 || !h6->established()) return 1;
    p::Bytes mss6{2,4,5,0xb4}; syn6.options=mss6;
    auto advertised6=t::PassiveHandshake6::accept(syn6,1);
    if (!advertised6 || advertised6->peer_mss()!=1460) return 1;
    p::Bytes options{2,4,5,0xb4};
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=0xffffffff, .flags=2, .options=options};
    auto raw = p::make_tcp4(syn);
    if (!raw) return 1;
    auto decoded = p::parse_tcp4(*raw);
    if (!decoded) return 1;
    auto h = t::PassiveHandshake::accept(*decoded, 0xffffffff);
    if (!h || h->established() || h->send_next() != 0 || h->receive_next() != 0 || h->peer_mss() != 1460) return 1;
    auto response = h->syn_ack(4096);
    auto response_raw = p::make_tcp4(response);
    auto response_decoded = p::parse_tcp4(*response_raw);
    if (!response_decoded || response_decoded->flags != 0x12 || response_decoded->sequence != 0xffffffff ||
        response_decoded->acknowledgement != 0 || response_decoded->destination != syn.source) return 1;
    auto repeated = h->input(*decoded, 1);
    if (!repeated || *repeated || h->established()) return 1;
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=1234,
                    .destination_port=80, .sequence=0, .acknowledgement=1, .flags=0x10};
    if (h->input(ack, 1).error() != t::HandshakeError::invalid_ack || h->established()) return 1;
    auto wrong_sequence=ack; wrong_sequence.sequence=1;
    if (h->input(wrong_sequence, 1).error() != t::HandshakeError::invalid_sequence || h->established()) return 1;
    ack.acknowledgement = 0; ack.source_port++;
    if (h->input(ack, 1).error() != t::HandshakeError::wrong_peer || h->established()) return 1;
    ack.source_port--;
    p::Bytes ack_options{1,1,0,0};
    p::Bytes payload{'h','i'};
    ack.options = ack_options; ack.payload = payload; ack.flags = 0x18;
    auto malformed = ack; p::Bytes malformed_options{2,1,0,0}; malformed.options = malformed_options;
    if (h->input(malformed, 1).error() != t::HandshakeError::invalid_options || h->established()) return 1;
    auto ack_raw = p::make_tcp4(ack);
    if (!ack_raw) return 1;
    auto parsed_ack = p::parse_tcp4(*ack_raw);
    if (!parsed_ack) return 1;
    auto done = h->input(*parsed_ack, 1);
    if (!done || !*done || !h->established() || h->input(ack, 1).error() != t::HandshakeError::unsupported_segment) return 1;
    auto receive = t::ReceiveBuffer::create(h->receive_next(), 8);
    if (!receive || receive->insert(parsed_ack->sequence, parsed_ack->payload).accepted != 2 || receive->next() != 2) return 1;
    std::array<std::uint8_t, 2> read{};
    if (receive->read(read) != 2 || !std::ranges::equal(read, payload)) return 1;
    auto early_fin = t::PassiveHandshake::accept(*decoded, 0xffffffff);
    ack.flags = 0x19;
    auto ack_fin_raw = p::make_tcp4(ack);
    if (!early_fin || !ack_fin_raw) return 1;
    auto parsed_fin = p::parse_tcp4(*ack_fin_raw);
    if (!parsed_fin || !early_fin->input(*parsed_fin, 1) || !early_fin->established()) return 1;
    auto fin_receive = t::ReceiveBuffer::create(early_fin->receive_next(), 8);
    if (!fin_receive || fin_receive->insert(parsed_fin->sequence, parsed_fin->payload).accepted != 2 ||
        fin_receive->insert_fin(parsed_fin->sequence + static_cast<std::uint32_t>(parsed_fin->payload.size())) != t::FinResult::accepted ||
        !fin_receive->finished() || fin_receive->next() != 3) return 1;
    syn.flags = 0x12;
    if (t::PassiveHandshake::accept(syn, 1).error() != t::HandshakeError::invalid_syn) return 1;
    syn.flags = 2; options[1] = 1;
    if (t::PassiveHandshake::accept(syn, 1).error() != t::HandshakeError::invalid_options) return 1;
    syn.options = {};
    auto default_mss = t::PassiveHandshake::accept(syn, 1);
    if (!default_mss || default_mss->peer_mss() != 536) return 1;
    // First SYN-ACK is lost; retry must preserve the same sequence numbers.
    t::HandshakeTimer retry_timer(0);
    auto original = default_mss->syn_ack(4096);
    if (retry_timer.poll(1000) != t::HandshakeTimerEvent::retransmit || !retry_timer.retransmitted(1000)) return 1;
    auto retry_synack = default_mss->syn_ack(4096);
    if (retry_synack.sequence != original.sequence || retry_synack.acknowledgement != original.acknowledgement) return 1;
    p::Tcp4View final_ack{.source=syn.source, .destination=syn.destination, .source_port=syn.source_port,
                          .destination_port=syn.destination_port, .sequence=0, .acknowledgement=2, .flags=0x10};
    auto completed = default_mss->input(final_ack, 1);
    if (!completed || !*completed) return 1;
    retry_timer.stop();
    if (retry_timer.poll(3000).error() != t::HandshakeTimerError::stopped) return 1;
    t::HandshakeTimer timer(100);
    if (timer.poll(1099) != t::HandshakeTimerEvent::waiting ||
        timer.retransmitted(1099).error() != t::HandshakeTimerError::not_due ||
        timer.poll(1098).error() != t::HandshakeTimerError::time_reversed) return 1;
    for (auto deadline : {1100ull, 3100ull, 7100ull, 15100ull}) {
        if (timer.deadline() != deadline || timer.poll(deadline) != t::HandshakeTimerEvent::retransmit ||
            timer.poll(deadline) != t::HandshakeTimerEvent::retransmit || !timer.retransmitted(deadline)) return 1;
    }
    if (timer.deadline() != 31100 || timer.poll(31100) != t::HandshakeTimerEvent::expired ||
        timer.poll(31100).error() != t::HandshakeTimerError::stopped) return 1;
    t::HandshakeTimer stopped(0); stopped.stop();
    if (stopped.poll(0).error() != t::HandshakeTimerError::stopped) return 1;
    std::cout << "TCP passive handshake subset and sequence wrap passed\n";
}
