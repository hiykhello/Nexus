import std;
import nexus.packet;

namespace p = nexus::packet;

namespace {
    constexpr p::Address4 source{192, 0, 2, 1}, destination{198, 51, 100, 2};
    const p::Bytes sample{0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x4e, 0x95,
        0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x02, 0x30, 0x39, 0x00, 0x35, 0x00, 0x0d,
        0x9f, 0x5c, 'h', 'e', 'l', 'l', 'o'};
    auto header_checksum(p::Bytes& bytes) -> void {
        bytes[10] = bytes[11] = 0;
        auto sum = p::internet_checksum(std::span(bytes).first(20));
        bytes[10] = static_cast<std::uint8_t>(sum >> 8);
        bytes[11] = static_cast<std::uint8_t>(sum);
    }
    auto fails(p::Bytes const& packet, p::PacketError expected) -> bool {
        auto result = p::parse_udp4(packet);
        return !result && result.error() == expected;
    }
    auto packet_tests() -> bool {
        const std::array<std::uint8_t, 5> hello{'h', 'e', 'l', 'l', 'o'};
        auto built = p::make_udp4(source, destination, 12345, 53, hello);
        if (!built || *built != sample) return false;
        auto parsed = p::parse_udp4(sample);
        if (!parsed || parsed->source != source || parsed->destination != destination ||
            parsed->source_port != 12345 || parsed->destination_port != 53 ||
            !std::ranges::equal(parsed->payload, hello)) return false;
        for (std::size_t size = 0; size < sample.size(); ++size)
            if (p::parse_udp4(std::span(sample).first(size))) return false;
        auto bytes = sample;
        bytes[28] ^= 1;
        if (!fails(bytes, p::PacketError::invalid_checksum)) return false;
        bytes[26] = bytes[27] = 0; // IPv4 permits a UDP checksum of zero.
        if (!p::parse_udp4(bytes)) return false;
        bytes = sample; bytes[12] ^= 1; header_checksum(bytes);
        if (!fails(bytes, p::PacketError::invalid_checksum)) return false;
        bytes = sample; bytes[8] ^= 1;
        if (!fails(bytes, p::PacketError::invalid_checksum)) return false;
        bytes = sample; bytes[0] = 0x65;
        if (!fails(bytes, p::PacketError::invalid_version)) return false;
        bytes = sample; bytes[0] = 0x46;
        if (!fails(bytes, p::PacketError::unsupported_header)) return false;
        for (std::uint16_t flags : {0x2000, 0x0001, 0x8000}) {
            bytes = sample; bytes[6] = static_cast<std::uint8_t>(flags >> 8); bytes[7] = static_cast<std::uint8_t>(flags);
            header_checksum(bytes);
            if (!fails(bytes, p::PacketError::unsupported_fragment)) return false;
        }
        bytes = sample; bytes[9] = 6; header_checksum(bytes);
        if (!fails(bytes, p::PacketError::unsupported_protocol)) return false;
        bytes = sample; bytes[25] = 12;
        if (!fails(bytes, p::PacketError::invalid_length)) return false;
        bytes = sample; bytes.push_back(0);
        if (!fails(bytes, p::PacketError::invalid_length)) return false;
        if (p::make_udp4(source, destination, 1, 2, hello, 32)) return false;
        if (p::make_udp4(source, destination, 1, 2, p::Bytes(65508), 65536)) return false;
        auto largest = p::make_udp4(source, destination, 1, 2, p::Bytes(65507, 1), 65535);
        if (!largest || !p::parse_udp4(*largest)) return false;
        const std::array<std::uint8_t, 2> zero_checksum{0xe3, 0x34};
        auto zero = p::make_udp4(source, destination, 12345, 53, zero_checksum);
        if (!zero || (*zero)[26] != 0xff || (*zero)[27] != 0xff || !p::parse_udp4(*zero)) return false;
        return true;
    }
    auto device_tests() -> bool {
        p::MemoryLink link({33, 2, 40});
        auto nothing = link.receive(p::Side::first);
        if (!nothing || *nothing) return false;
        if (!link.send(p::Side::first, sample)) return false;
        auto full = link.send(p::Side::first, sample);
        if (full || full.error() != p::DeviceError::queue_full) return false;
        p::Bytes oversize(34);
        if (auto r = link.send(p::Side::first, oversize); r || r.error() != p::DeviceError::packet_too_large) return false;
        if (auto r = link.send(p::Side::first, {}); r || r.error() != p::DeviceError::empty_packet) return false;
        auto request = link.receive(p::Side::second);
        if (!request || !*request || **request != sample) return false;
        auto view = p::parse_udp4(**request);
        if (!view) return false;
        auto reply = p::make_udp4(view->destination, view->source, view->destination_port, view->source_port, view->payload);
        if (!reply || !link.send(p::Side::second, *reply)) return false;
        auto received = link.receive(p::Side::first);
        if (!received || !*received) return false;
        auto decoded = p::parse_udp4(**received);
        if (!decoded || decoded->source != destination || decoded->destination != source ||
            decoded->source_port != 53 || decoded->destination_port != 12345 ||
            !std::ranges::equal(decoded->payload, view->payload)) return false;
        p::Bytes payload{1, 2, 3};
        if (!link.send(p::Side::first, payload)) return false;
        payload[0] = 99; // The queue owns its copy.
        if (!link.send(p::Side::first, payload)) return false;
        auto too_many = link.send(p::Side::first, payload);
        if (too_many || too_many.error() != p::DeviceError::queue_full) return false;
        link.close(p::Side::first);
        link.close(p::Side::first);
        auto a = link.receive(p::Side::second), b = link.receive(p::Side::second);
        if (!a || !*a || (**a)[0] != 1 || !b || !*b || (**b)[0] != 99) return false;
        auto eof = link.receive(p::Side::second);
        if (eof || eof.error() != p::DeviceError::peer_closed) return false;
        auto closed = link.send(p::Side::first, payload);
        if (closed || closed.error() != p::DeviceError::closed) return false;
        auto peer = link.send(p::Side::second, payload);
        if (peer || peer.error() != p::DeviceError::peer_closed) return false;
        p::MemoryLink byte_limit({4, 3, 4});
        if (!byte_limit.send(p::Side::first, std::array<std::uint8_t, 4>{1, 2, 3, 4})) return false;
        auto at_limit = byte_limit.send(p::Side::first, std::array<std::uint8_t, 1>{1});
        if (at_limit || at_limit.error() != p::DeviceError::queue_full) return false;
        auto popped = byte_limit.receive(p::Side::second);
        if (!popped || !*popped || !byte_limit.send(p::Side::first, std::array<std::uint8_t, 1>{1})) return false;
        byte_limit.close(p::Side::second);
        auto discarded = byte_limit.receive(p::Side::second);
        if (discarded || discarded.error() != p::DeviceError::closed) return false;
        p::MemoryLink no_capacity({4, 0, 4});
        auto zero = no_capacity.send(p::Side::first, std::array<std::uint8_t, 1>{1});
        if (zero || zero.error() != p::DeviceError::queue_full) return false;
        p::MemoryLink too_small({100, 1, 2});
        auto impossible = too_small.send(p::Side::first, std::array<std::uint8_t, 3>{1, 2, 3});
        if (impossible || impossible.error() != p::DeviceError::packet_too_large) return false;
        link.close(p::Side::second);
        auto closed_read = link.receive(p::Side::second);
        if (closed_read || closed_read.error() != p::DeviceError::closed) return false;
        return true;
    }
}

int main() {
    if (!packet_tests()) { std::cerr << "IPv4/UDP packet validation failed\n"; return 1; }
    if (!device_tests()) { std::cerr << "memory packet link failed\n"; return 1; }
    std::cout << "IPv4/UDP packets and bounded memory link passed\n";
}
