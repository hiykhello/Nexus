import std;
import packet;
import tcp.connection;
import tcp.receive;
import test.scheduled_link;
namespace p = ::packet;
namespace t = tcp;

int main() {
    p::Tcp4View syn{.source={10,0,0,1}, .destination={10,0,0,2}, .source_port=1234,
                    .destination_port=80, .sequence=99, .flags=2};
    auto sender = t::PassiveConnection::accept(syn, 50, 8, 0);
    auto receiver = t::ReceiveBuffer::create(51, 2);
    if (!sender || !receiver) return 1;
    p::Tcp4View ack{.source=syn.source, .destination=syn.destination, .source_port=1234,
                    .destination_port=80, .sequence=100, .acknowledgement=51, .flags=0x10, .window=2};
    if (!sender->input(ack, 0)) return 1;
    p::MemoryLink link;
    ScheduledLink network(8, 2048);
    auto transmit = [&](p::Side side, p::Tcp4View view, std::uint64_t now, bool drop = false) {
        auto bytes = p::make_tcp4(view);
        return bytes && network.send(side, *bytes, now, drop).has_value() && network.advance(now, link).has_value();
    };
    auto send_data = [&](t::SendSlice const& slice, std::uint64_t now) {
        auto view = sender->ack(); view.sequence = slice.sequence; view.payload = slice.bytes;
        return transmit(p::Side::second, view, now);
    };
    auto receive_data = [&]() -> std::optional<t::ReceiveResult> {
        auto bytes = link.receive(p::Side::first);
        if (!bytes || !*bytes) return {};
        auto view = p::parse_tcp4(**bytes);
        if (!view || view->flags != 0x10) return {};
        return receiver->insert(view->sequence, view->payload);
    };
    auto send_ack = [&](std::uint64_t now, bool drop = false) {
        ack.acknowledgement = receiver->next(); ack.window = static_cast<std::uint16_t>(receiver->window());
        return transmit(p::Side::first, ack, now, drop);
    };
    auto receive_ack = [&](std::uint64_t now) {
        auto bytes = link.receive(p::Side::second);
        if (!bytes || !*bytes) return false;
        auto view = p::parse_tcp4(**bytes);
        return view && sender->input(*view, now).has_value();
    };
    p::Bytes data{'a','b','c','d'};
    if (!sender->enqueue(data)) return 1;
    auto first = sender->unsent(4);
    if (first.bytes != p::Bytes{'a','b'} || !send_data(first, 1) || !sender->sent(2, 1)) return 1;
    auto result = receive_data();
    if (!result || result->accepted != 2 || receiver->window() != 0 || !send_ack(2) || !receive_ack(2)) return 1;
    std::array<std::uint8_t, 2> output{};
    if (receiver->read(output) != 2 || output != std::array<std::uint8_t, 2>{'a','b'} ||
        !send_ack(3, true) || !sender->unsent(2).bytes.empty()) return 1;
    if (sender->probe_due(3)->has_value()) return 1;
    auto probe = sender->probe_due(1003);
    if (!probe || !*probe || (**probe).sequence != 53 || (**probe).bytes != p::Bytes{'c'} ||
        !send_data(**probe, 1003) || !sender->probe_sent(1003)) return 1;
    result = receive_data();
    if (!result || result->accepted != 1 || !send_ack(1004, true)) return 1;
    probe = sender->probe_due(3003);
    if (!probe || !*probe || (**probe).sequence != 53 || (**probe).bytes != p::Bytes{'c'} ||
        !send_data(**probe, 3003) || !sender->probe_sent(3003)) return 1;
    result = receive_data();
    if (!result || result->duplicate != 1 || result->accepted || !send_ack(3004) || !receive_ack(3004)) return 1;
    auto last = sender->unsent(2);
    if (last.sequence != 54 || last.bytes != p::Bytes{'d'} || !send_data(last, 3005) || !sender->sent(1, 3005)) return 1;
    result = receive_data();
    if (!result || result->accepted != 1 || !send_ack(3006) || !receive_ack(3006) ||
        receiver->read(output) != 2 || output != std::array<std::uint8_t, 2>{'c','d'} ||
        sender->ack().sequence != 55 || receiver->read(output) != 0) return 1;
    std::cout << "TCP zero-window recovery across a lossy virtual packet link passed\n";
}
