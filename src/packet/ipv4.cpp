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
        auto add(std::uint32_t sum, std::span<std::uint8_t const> bytes) noexcept -> std::uint32_t {
            std::size_t i = 0;
            while (i + 1 < bytes.size()) {
                sum += (std::uint32_t{bytes[i]} << 8) | bytes[i + 1];
                sum = (sum & 0xffff) + (sum >> 16);
                i += 2;
            }
            if (i < bytes.size()) sum += std::uint32_t{bytes[i]} << 8;
            return sum;
        }
        auto finish(std::uint32_t sum) noexcept -> std::uint16_t {
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            return static_cast<std::uint16_t>(~sum);
        }
        auto udp_checksum(std::span<std::uint8_t const> p) noexcept -> std::uint16_t {
            auto udp = p.subspan(20);
            auto sum = add(0, p.subspan(12, 8));
            sum += 17 + static_cast<std::uint32_t>(udp.size());
            return finish(add(sum, udp));
        }
    }

    auto internet_checksum(std::span<std::uint8_t const> bytes) noexcept -> std::uint16_t {
        return finish(add(0, bytes));
    }

    auto parse_udp4(std::span<std::uint8_t const> p) noexcept -> std::expected<Udp4View, PacketError> {
        if (p.size() < 20) return std::unexpected(PacketError::truncated);
        if ((p[0] >> 4) != 4) return std::unexpected(PacketError::invalid_version);
        if ((p[0] & 15) != 5) return std::unexpected(PacketError::unsupported_header);
        if (read16(p, 2) != p.size() || p.size() < 28) return std::unexpected(PacketError::invalid_length);
        if (internet_checksum(p.first(20)) != 0) return std::unexpected(PacketError::invalid_checksum);
        if ((read16(p, 6) & 0xbfff) != 0) return std::unexpected(PacketError::unsupported_fragment);
        if (p[9] != 17) return std::unexpected(PacketError::unsupported_protocol);
        if (read16(p, 24) != p.size() - 20 || read16(p, 24) < 8) return std::unexpected(PacketError::invalid_length);
        if (read16(p, 26) != 0 && udp_checksum(p) != 0) return std::unexpected(PacketError::invalid_checksum);
        Udp4View result;
        std::copy_n(p.begin() + 12, 4, result.source.begin());
        std::copy_n(p.begin() + 16, 4, result.destination.begin());
        result.source_port = read16(p, 20);
        result.destination_port = read16(p, 22);
        result.payload = p.subspan(28);
        return result;
    }

    auto make_udp4(Address4 source, Address4 destination, std::uint16_t source_port,
                   std::uint16_t destination_port, std::span<std::uint8_t const> payload, std::size_t mtu)
        -> std::expected<Bytes, PacketError> {
        if (payload.size() > 65535 - 28 || mtu < 28 || payload.size() > mtu - 28)
            return std::unexpected(PacketError::too_large);
        Bytes p(28 + payload.size());
        p[0] = 0x45;
        put16(p, 2, static_cast<std::uint16_t>(p.size()));
        put16(p, 6, 0x4000); // Don't fragment; this builder does not implement fragmentation.
        p[8] = 64; p[9] = 17;
        std::copy(source.begin(), source.end(), p.begin() + 12);
        std::copy(destination.begin(), destination.end(), p.begin() + 16);
        put16(p, 10, internet_checksum(std::span(p).first(20)));
        put16(p, 20, source_port); put16(p, 22, destination_port);
        put16(p, 24, static_cast<std::uint16_t>(p.size() - 20));
        std::copy(payload.begin(), payload.end(), p.begin() + 28);
        auto checksum = udp_checksum(p);
        put16(p, 26, checksum == 0 ? 0xffff : checksum);
        return p;
    }
}
