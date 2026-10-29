module nexus.packet;
import std;

namespace nexus::packet {
    namespace {
        auto read16(std::span<std::uint8_t const> p, std::size_t i) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{p[i]} << 8) | p[i + 1]);
        }
        auto read32(std::span<std::uint8_t const> p, std::size_t i) noexcept -> std::uint32_t {
            return (std::uint32_t{read16(p, i)} << 16) | read16(p, i + 2);
        }
        auto put16(Bytes& p, std::size_t i, std::uint16_t n) noexcept -> void {
            p[i] = static_cast<std::uint8_t>(n >> 8); p[i + 1] = static_cast<std::uint8_t>(n);
        }
        auto put32(Bytes& p, std::size_t i, std::uint32_t n) noexcept -> void {
            put16(p, i, static_cast<std::uint16_t>(n >> 16)); put16(p, i + 2, static_cast<std::uint16_t>(n));
        }
        auto checksum(std::span<std::uint8_t const> p, std::size_t offset = 20) noexcept -> std::uint16_t {
            std::uint32_t sum = 6 + static_cast<std::uint32_t>(p.size() - offset);
            auto add = [&sum](std::span<std::uint8_t const> bytes) {
                std::size_t i = 0;
                for (; i + 1 < bytes.size(); i += 2) {
                    sum += (std::uint32_t{bytes[i]} << 8) | bytes[i + 1];
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                if (i < bytes.size()) sum += std::uint32_t{bytes[i]} << 8;
            };
            add(p.subspan(12, 8)); add(p.subspan(offset));
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            return static_cast<std::uint16_t>(~sum);
        }
    }
    auto parse_tcp4(std::span<std::uint8_t const> p) noexcept -> std::expected<Tcp4View, PacketError> {
        if (p.size() < 20) return std::unexpected(PacketError::truncated);
        if ((p[0] >> 4) != 4) return std::unexpected(PacketError::invalid_version);
        auto ip_header = static_cast<std::size_t>(p[0] & 15) * 4;
        if (ip_header < 20 || ip_header > p.size() || p.size() - ip_header < 20 || read16(p, 2) != p.size())
            return std::unexpected(PacketError::invalid_length);
        if (internet_checksum(p.first(ip_header)) != 0) return std::unexpected(PacketError::invalid_checksum);
        for (std::size_t i=20; i<ip_header; ++i) {
            if (p[i]==1) continue;
            if (p[i]==0 && std::ranges::all_of(p.subspan(i,ip_header-i), [](auto byte) { return byte==0; })) break;
            return std::unexpected(PacketError::unsupported_header);
        }
        if ((read16(p, 6) & 0xbfff) != 0) return std::unexpected(PacketError::unsupported_fragment);
        if (p[9] != 6) return std::unexpected(PacketError::unsupported_protocol);
        auto header = static_cast<std::size_t>(p[ip_header+12] >> 4) * 4;
        if (header < 20 || header > p.size() - ip_header) return std::unexpected(PacketError::invalid_length);
        if (p[ip_header+12] & 0x0e) return std::unexpected(PacketError::unsupported_header);
        if (checksum(p,ip_header) != 0) return std::unexpected(PacketError::invalid_checksum);
        Tcp4View v;
        std::copy_n(p.begin() + 12, 4, v.source.begin()); std::copy_n(p.begin() + 16, 4, v.destination.begin());
        v.source_port = read16(p, ip_header); v.destination_port = read16(p, ip_header+2);
        v.sequence = read32(p, ip_header+4); v.acknowledgement = read32(p, ip_header+8);
        v.flags = static_cast<std::uint16_t>(((p[ip_header+12] & 1) << 8) | p[ip_header+13]);
        v.window = read16(p, ip_header+14); v.urgent = read16(p, ip_header+18);
        v.options = p.subspan(ip_header+20, header - 20); v.payload = p.subspan(ip_header + header);
        return v;
    }
    auto make_tcp4(Tcp4View v, std::size_t mtu) -> std::expected<Bytes, PacketError> {
        return make_tcp4(v, mtu, {});
    }
    auto make_tcp4(Tcp4View v, std::size_t mtu, Bytes p) -> std::expected<Bytes, PacketError> {
        if (v.options.size() > 40 || v.options.size() % 4 || v.flags > 0x1ff)
            return std::unexpected(PacketError::unsupported_header);
        auto header = 40 + v.options.size();
        if (mtu < header || v.payload.size() > 65535 - header || v.payload.size() > mtu - header)
            return std::unexpected(PacketError::too_large);
        p.resize(header + v.payload.size());
        std::ranges::fill(p, 0);
        p[0] = 0x45; put16(p, 2, static_cast<std::uint16_t>(p.size())); put16(p, 6, 0x4000);
        p[8] = 64; p[9] = 6;
        std::copy(v.source.begin(), v.source.end(), p.begin() + 12);
        std::copy(v.destination.begin(), v.destination.end(), p.begin() + 16);
        put16(p, 10, internet_checksum(std::span(p).first(20)));
        put16(p, 20, v.source_port); put16(p, 22, v.destination_port);
        put32(p, 24, v.sequence); put32(p, 28, v.acknowledgement);
        p[32] = static_cast<std::uint8_t>(((20 + v.options.size()) / 4) << 4 | (v.flags >> 8));
        p[33] = static_cast<std::uint8_t>(v.flags); put16(p, 34, v.window); put16(p, 38, v.urgent);
        std::ranges::copy(v.options, p.begin() + 40);
        std::ranges::copy(v.payload, p.begin() + header);
        put16(p, 36, checksum(p));
        return p;
    }
    auto parse_tcp_options(std::span<std::uint8_t const> options) noexcept -> std::expected<TcpOptions, PacketError> {
        if (options.size() > 40 || options.size() % 4) return std::unexpected(PacketError::invalid_length);
        TcpOptions result;
        for (std::size_t i = 0; i < options.size();) {
            auto kind = options[i];
            if (kind == 0) break;
            if (kind == 1) { result.items[result.count++] = {kind, {}}; ++i; continue; }
            if (options.size() - i < 2) return std::unexpected(PacketError::truncated);
            auto length = options[i + 1];
            if (length < 2 || length > options.size() - i) return std::unexpected(PacketError::invalid_length);
            result.items[result.count++] = {kind, options.subspan(i + 2, length - 2)};
            i += length;
        }
        return result;
    }
    auto parse_tcp_syn_options(std::span<std::uint8_t const> options) noexcept -> std::expected<TcpSynOptions, PacketError> {
        auto parsed = parse_tcp_options(options);
        if (!parsed) return std::unexpected(parsed.error());
        TcpSynOptions result;
        for (auto const& option : std::span(parsed->items).first(parsed->count)) {
            auto data = option.data;
            switch (option.kind) {
            case 2:
                if (data.size() != 2 || result.mss) return std::unexpected(PacketError::unsupported_header);
                result.mss = read16(data, 0);
                break;
            case 3:
                if (data.size() != 1 || result.window_scale) return std::unexpected(PacketError::unsupported_header);
                result.window_scale = std::min<std::uint8_t>(data[0], 14);
                break;
            case 4:
                if (!data.empty() || result.sack_permitted) return std::unexpected(PacketError::unsupported_header);
                result.sack_permitted = true;
                break;
            case 8:
                if (data.size() != 8 || result.timestamp) return std::unexpected(PacketError::unsupported_header);
                result.timestamp = std::pair{read32(data, 0), read32(data, 4)};
                break;
            default: break;
            }
        }
        return result;
    }
}
