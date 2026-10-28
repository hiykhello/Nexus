import std;
import nexus.packet;
import nexus.tcp.send;
import nexus.tcp.receive;
#include "support/scheduled_link.hpp"
namespace p = nexus::packet;
namespace t = nexus::tcp;
int main() {
    auto sender = t::TimedSend::create(0xfffffffe, 8);
    auto receiver = t::ReceiveBuffer::create(0xfffffffe, 8);
    if (!sender || !receiver) return 1;
    p::MemoryLink link;
    ScheduledLink network(8, 1024);
    p::Bytes data{'a','b','c','d'};
    if (!sender->enqueue(data)) return 1;
    auto packet = [](t::SendSlice const& slice) {
        p::Tcp4View v{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                      .destination_port=80, .sequence=slice.sequence, .flags=0x10, .window=8,
                      .payload=slice.bytes};
        return p::make_tcp4(v);
    };
    auto send_ack = [&](std::uint64_t due, bool drop) {
        p::Tcp4View v{.source={10,0,0,2}, .destination={10,0,0,1}, .source_port=80,
                      .destination_port=1234, .sequence=50, .acknowledgement=receiver->next(),
                      .flags=0x10, .window=static_cast<std::uint16_t>(receiver->window())};
        auto bytes = p::make_tcp4(v);
        return bytes && network.send(p::Side::second, *bytes, due, drop).has_value();
    };
    auto receive_ack = [&]() -> std::optional<std::uint32_t> {
        auto bytes = link.receive(p::Side::first);
        if (!bytes || !*bytes) return {};
        auto v = p::parse_tcp4(**bytes);
        if (!v || v->flags != 0x10 || !v->payload.empty()) return {};
        return v->acknowledgement;
    };
    auto first = sender->unsent(2);
    auto first_packet = packet(first);
    if (!first_packet || !network.send(p::Side::first, *first_packet, 1, true) || !sender->sent(2, 0)) return 1;
    auto second = sender->unsent(2);
    auto second_packet = packet(second);
    if (!second_packet || !network.send(p::Side::first, *second_packet, 1) || !sender->sent(2, 0)) return 1;
    auto advance = network.advance(1, link);
    auto received = link.receive(p::Side::second);
    if (!advance || *advance != 1 || !received || !*received) return 1;
    auto parsed = p::parse_tcp4(**received);
    if (!parsed || receiver->insert(parsed->sequence, parsed->payload).accepted != 2 || receiver->ready() ||
        receiver->next() != 0xfffffffe) return 1;
    if (!send_ack(1, false) || !network.advance(1, link)) return 1;
    auto ack_value = receive_ack();
    if (!ack_value) return 1;
    auto duplicate_ack = sender->acknowledge(*ack_value, 1);
    if (!duplicate_ack || *duplicate_ack || sender->deadline() != 1000) return 1;
    auto due = sender->due(1000, 2);
    if (!due || !*due) return 1;
    auto retry = packet(**due);
    if (!retry || !network.send(p::Side::first, *retry, 1001) || !sender->retransmitted(1000)) return 1;
    advance = network.advance(1001, link);
    received = link.receive(p::Side::second);
    if (!advance || *advance != 1 || !received || !*received) return 1;
    parsed = p::parse_tcp4(**received);
    if (!parsed || receiver->insert(parsed->sequence, parsed->payload).accepted != 2 || receiver->next() != 2) return 1;
    // Drop the cumulative ACK as well. A second timeout retransmits old data,
    // which the receiver must not deliver twice.
    if (!send_ack(1001, true)) return 1;
    due = sender->due(3000, 2);
    if (!due || !*due) return 1;
    retry = packet(**due);
    if (!retry || !network.send(p::Side::first, *retry, 3001) || !sender->retransmitted(3000)) return 1;
    advance = network.advance(3001, link);
    received = link.receive(p::Side::second);
    if (!advance || *advance != 1 || !received || !*received) return 1;
    parsed = p::parse_tcp4(**received);
    if (!parsed || receiver->insert(parsed->sequence, parsed->payload).duplicate != 2 || receiver->next() != 2) return 1;
    if (!send_ack(3001, false) || !network.advance(3001, link)) return 1;
    ack_value = receive_ack();
    if (!ack_value) return 1;
    auto ack = sender->acknowledge(*ack_value, 3001);
    std::array<std::uint8_t, 4> output{};
    if (!ack || *ack != 4 || sender->deadline() || receiver->read(output) != 4 ||
        !std::ranges::equal(output, data)) return 1;
    std::cout << "TCP packet buffers recover a dropped segment over virtual link\n";
}
