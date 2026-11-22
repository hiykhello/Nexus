import std;
import tcp.receive;
namespace t = tcp;
int main() {
    if (t::ReceiveBuffer::create(0, 0) || t::ReceiveBuffer::create(0, 0x80000000ull)) return 1;
    auto buffer = t::ReceiveBuffer::create(0xfffffffe, 6);
    if (!buffer) return 1;
    std::array<std::uint8_t, 2> later{'c','d'}, first{'a','b'};
    auto r = buffer->insert(0, later);
    if (r.accepted != 2 || buffer->ready() || buffer->next() != 0xfffffffe) return 1;
    r = buffer->insert(0xfffffffe, first);
    if (r.accepted != 2 || buffer->ready() != 4 || buffer->next() != 2 || buffer->window() != 2) return 1;
    std::array<std::uint8_t, 3> overlap{'X','Y','e'};
    r = buffer->insert(0, overlap);
    if (r.duplicate != 2 || r.accepted != 1 || buffer->next() != 3) return 1;
    std::array<std::uint8_t, 3> output{};
    if (buffer->read(output) != 3 || output != std::array<std::uint8_t, 3>{'a','b','c'} ||
        buffer->next() != 3 || buffer->window() != 4) return 1;
    std::array<std::uint8_t, 4> segment{'x','y','f','g'};
    r = buffer->insert(1, segment);
    if (r.duplicate != 2 || r.accepted != 2 || buffer->next() != 5) return 1;
    std::array<std::uint8_t, 8> remaining{};
    if (buffer->read(remaining) != 4 || !std::ranges::equal(std::span(remaining).first(4),
        std::array<std::uint8_t, 4>{'d','e','f','g'})) return 1;
    std::array<std::uint8_t, 2> outside{'q','r'};
    r = buffer->insert(4, outside);
    if (r.outside != 1 || r.accepted != 1 || buffer->next() != 6) return 1;
    r = buffer->insert(12, outside);
    if (r.outside != 2 || buffer->next() != 6) return 1;
    auto bounded = t::ReceiveBuffer::create(100, 4);
    std::array<std::uint8_t, 4> end{'c','d','e','f'};
    r = bounded->insert(102, end);
    if (r.accepted != 2 || r.outside != 2 || bounded->ready() || bounded->window() != 4) return 1;
    r = bounded->insert(100, first);
    if (r.accepted != 2 || bounded->ready() != 4 || bounded->window() != 0 || bounded->next() != 104) return 1;
    std::array<std::uint8_t, 2> drained{};
    if (bounded->read(drained) != 2 || drained != first || bounded->window() != 2) return 1;
    r = bounded->insert(104, std::span(end).subspan(2));
    if (r.accepted != 2 || bounded->next() != 106 || bounded->window() != 0) return 1;
    auto closing = t::ReceiveBuffer::create(0xfffffffe, 6);
    r = closing->insert(1, end);
    if (r.accepted != 3 || r.outside != 1 || closing->insert_fin(1) != t::FinResult::accepted ||
        closing->insert_fin(1) != t::FinResult::duplicate || closing->insert_fin(2) != t::FinResult::conflict ||
        closing->finished()) return 1;
    std::array<std::uint8_t, 3> before_fin{'a','b','c'};
    r = closing->insert(0xfffffffe, before_fin);
    if (r.accepted != 3 || !closing->finished() || closing->next() != 2 || closing->window() != 0) return 1;
    r = closing->insert(1, end);
    if (r.accepted || r.outside != 4) return 1;
    if (closing->read(output) != 3 || output != before_fin || !closing->finished() || closing->next() != 2) return 1;
    auto full_fin = t::ReceiveBuffer::create(10, 2);
    if (full_fin->insert_fin(12) != t::FinResult::outside || full_fin->insert_fin(10) != t::FinResult::accepted ||
        !full_fin->finished() || full_fin->next() != 11) return 1;
    auto acknowledged = t::ReceiveBuffer::create(50, 2);
    if (acknowledged->insert(50, first).accepted != 2 || acknowledged->window() != 0 ||
        acknowledged->insert_fin(51) != t::FinResult::outside ||
        acknowledged->insert_fin(52) != t::FinResult::outside || acknowledged->next() != 52) return 1;
    if (acknowledged->read(drained) != 2 || acknowledged->insert_fin(52) != t::FinResult::accepted ||
        !acknowledged->finished() || acknowledged->next() != 53) return 1;
    std::cout << "TCP bounded receive reordering, overlap and sequence wrap passed\n";
}
