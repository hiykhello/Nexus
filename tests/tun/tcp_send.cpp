import std;
import packet;
import tcp.send;
namespace p = ::packet;
namespace t = tcp;
int main() {
    if (t::SendBuffer::create(0, 0) || t::SendBuffer::create(0, 0x80000000ull)) return 1;
    auto b = t::SendBuffer::create(0xfffffffe, 5);
    std::array<std::uint8_t, 5> data{'a','b','c','d','e'};
    if (!b || !b->enqueue(data) || b->enqueue(data).error() != t::SendError::capacity) return 1;
    auto first = b->unsent(3);
    if (first.sequence != 0xfffffffe || first.bytes != std::vector<std::uint8_t>({'a','b','c'}) ||
        !b->mark_sent(3) || b->next() != 1 || b->in_flight() != 3) return 1;
    if (b->mark_sent(3).error() != t::SendError::invalid_count ||
        b->acknowledge(2).error() != t::SendError::invalid_ack || b->queued() != 5) return 1;
    auto ack = b->acknowledge(0);
    if (!ack || *ack != 2 || b->una() != 0 || b->next() != 1 || b->queued() != 3) return 1;
    auto retry = b->retransmit(10);
    if (retry.sequence != 0 || retry.bytes != std::vector<std::uint8_t>({'c'})) return 1;
    auto duplicate = b->acknowledge(0);
    if (!duplicate || *duplicate != 0 || b->acknowledge(0xffffffff).error() != t::SendError::invalid_ack) return 1;
    auto unsent = b->unsent(10);
    if (unsent.sequence != 1 || unsent.bytes != std::vector<std::uint8_t>({'d','e'}) || !b->mark_sent(2)) return 1;
    ack = b->acknowledge(3);
    if (!ack || *ack != 3 || b->queued() || b->in_flight() || b->next() != 3 || !b->enqueue(data)) return 1;
    auto timed = t::TimedSend::create(100, 5);
    if (!timed || !timed->enqueue(data) || !timed->sent(3, 10) || timed->deadline() != 1010 ||
        !timed->sent(2, 20) || timed->deadline() != 1010) return 1;
    auto early = timed->due(1009, 5);
    if (!early || *early || timed->retransmitted(1009).error() != t::SendError::not_due) return 1;
    auto due = timed->due(1010, 2);
    if (!due || !*due || (**due).sequence != 100 || (**due).bytes != std::vector<std::uint8_t>({'a','b'})) return 1;
    if (!timed->retransmitted(1010) || timed->rto() != 2000 || timed->deadline() != 3010) return 1;
    auto partial = timed->acknowledge(102, 1100);
    if (!partial || *partial != 2 || timed->deadline() != 3100) return 1;
    auto same = timed->acknowledge(102, 1200);
    if (!same || *same || timed->deadline() != 3100 ||
        timed->acknowledge(106, 1201).error() != t::SendError::invalid_ack || timed->deadline() != 3100) return 1;
    if (timed->due(1200, 1).error() != t::SendError::time_reversed) return 1;
    auto done = timed->acknowledge(105, 1201);
    if (!done || *done != 3 || timed->deadline() || timed->rto() != 1000) return 1;
    // Wraparound zero-alloc two-span SendView + jumbo MTU scatter make_tcp4/make_tcp6.
    auto wrap = t::TimedSend::create(500, 6);
    if (!wrap || !wrap->enqueue(std::array<std::uint8_t, 4>{1, 2, 3, 4}) ||
        !wrap->sent(4, 10) || !wrap->acknowledge(504, 15)) return 1;
    if (!wrap->enqueue(std::array<std::uint8_t, 5>{10, 11, 12, 13, 14})) return 1;
    auto uv = wrap->unsent_view(5);
    if (uv.sequence != 504 || uv.head.size() != 2 || uv.tail.size() != 3 || uv.size() != 5 ||
        uv.head[0] != 10 || uv.head[1] != 11 || uv.tail[0] != 12 || uv.tail[2] != 14) return 1;
    if (!wrap->sent(5, 20)) return 1;
    auto dv = wrap->due_view(2000, 5);
    if (!dv || !*dv || (**dv).sequence != 504 || (**dv).head.size() != 2 || (**dv).tail.size() != 3) return 1;
    std::vector<std::uint8_t> h(2500, 0x5au), tl(2000, 0xa5u);
    p::Tcp4View v4{.source = {10, 0, 0, 1}, .destination = {10, 0, 0, 2}, .source_port = 1234,
                   .destination_port = 443, .sequence = 1, .acknowledgement = 2, .flags = 0x18, .window = 65535, .payload = h};
    auto pkt4 = p::make_tcp4(v4, tl, 9000);
    if (!pkt4 || pkt4->size() != 4540) return 1;
    auto pv4 = p::parse_tcp4(*pkt4);
    if (!pv4 || pv4->payload.size() != 4500 || !std::ranges::equal(pv4->payload.first(2500), h) ||
        !std::ranges::equal(pv4->payload.subspan(2500), tl)) return 1;
    p::Tcp6View v6{.source = {0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                   .destination = {0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
                   .source_port = 1234, .destination_port = 443, .sequence = 1, .acknowledgement = 2, .flags = 0x18, .window = 65535, .payload = h};
    auto pkt6 = p::make_tcp6(v6, tl, 9000);
    if (!pkt6 || pkt6->size() != 4560) return 1;
    auto pv6 = p::parse_tcp6(*pkt6);
    if (!pv6 || pv6->payload.size() != 4500 || !std::ranges::equal(pv6->payload.first(2500), h) ||
        !std::ranges::equal(pv6->payload.subspan(2500), tl)) return 1;
    std::cout << "TCP send ownership, cumulative ACK and sequence wrap passed\n";
}
