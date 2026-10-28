module nexus.packet;
import std;

namespace nexus::packet {
    namespace {
        auto read16(std::span<std::uint8_t const> p, std::size_t offset) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{p[offset]} << 8) | p[offset + 1]);
        }
        auto put16(Bytes& p, std::size_t offset, std::uint16_t value) noexcept -> void {
            p[offset] = static_cast<std::uint8_t>(value >> 8);
            p[offset + 1] = static_cast<std::uint8_t>(value);
        }
        auto checksum(std::span<std::uint8_t const> p) noexcept -> std::uint16_t {
            std::uint32_t sum = 17 + static_cast<std::uint32_t>(p.size() - 40);
            auto add = [&sum](std::span<std::uint8_t const> bytes) {
                std::size_t i = 0;
                while (i + 1 < bytes.size()) {
                    sum += (std::uint32_t{bytes[i]} << 8) | bytes[i + 1];
                    sum = (sum & 0xffff) + (sum >> 16);
                    i += 2;
                }
                if (i < bytes.size()) sum += std::uint32_t{bytes[i]} << 8;
            };
            add(p.subspan(8, 32));
            add(p.subspan(40));
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            return static_cast<std::uint16_t>(~sum);
        }
    }
    auto parse_udp6(std::span<std::uint8_t const> p) noexcept -> std::expected<Udp6View, PacketError> {
        if (p.size() < 40) return std::unexpected(PacketError::truncated);
        if ((p[0] >> 4) != 6) return std::unexpected(PacketError::invalid_version);
        if (p[6] == 44) return std::unexpected(PacketError::unsupported_fragment);
        if (p[6] == 0 || p[6] == 43 || p[6] == 60 || p[6] == 51 || p[6] == 50)
            return std::unexpected(PacketError::unsupported_header);
        if (p[6] != 17) return std::unexpected(PacketError::unsupported_protocol);
        if (p.size() < 48 || read16(p, 4) != p.size() - 40 || read16(p, 44) != p.size() - 40)
            return std::unexpected(PacketError::invalid_length);
        if (read16(p, 46) == 0 || checksum(p) != 0) return std::unexpected(PacketError::invalid_checksum);
        Udp6View result;
        std::copy_n(p.begin() + 8, 16, result.source.begin());
        std::copy_n(p.begin() + 24, 16, result.destination.begin());
        result.source_port = read16(p, 40); result.destination_port = read16(p, 42);
        result.payload = p.subspan(48);
        return result;
    }
    auto make_udp6(Address6 source, Address6 destination, std::uint16_t source_port,
                   std::uint16_t destination_port, std::span<std::uint8_t const> payload, std::size_t mtu)
        -> std::expected<Bytes, PacketError> {
        if (payload.size() > 65535 - 8 || mtu < 48 || payload.size() > mtu - 48)
            return std::unexpected(PacketError::too_large);
        Bytes p(48 + payload.size());
        p[0] = 0x60; p[6] = 17; p[7] = 64;
        put16(p, 4, static_cast<std::uint16_t>(payload.size() + 8));
        std::copy(source.begin(), source.end(), p.begin() + 8);
        std::copy(destination.begin(), destination.end(), p.begin() + 24);
        put16(p, 40, source_port); put16(p, 42, destination_port);
        put16(p, 44, static_cast<std::uint16_t>(payload.size() + 8));
        std::copy(payload.begin(), payload.end(), p.begin() + 48);
        auto value = checksum(p);
        put16(p, 46, value == 0 ? 0xffff : value);
        return p;
    }
}
