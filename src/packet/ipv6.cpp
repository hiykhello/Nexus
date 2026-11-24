module packet;
import std;

namespace packet {
    namespace {
        auto read16(std::span<std::uint8_t const> p, std::size_t offset) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{p[offset]} << 8) | p[offset + 1]);
        }
        auto put16(Bytes& p, std::size_t offset, std::uint16_t value) noexcept -> void {
            p[offset] = static_cast<std::uint8_t>(value >> 8);
            p[offset + 1] = static_cast<std::uint8_t>(value);
        }
        auto options_length(std::span<std::uint8_t const> p,std::size_t offset) noexcept
            -> std::expected<std::size_t,PacketError> {
            if (p.size()-offset<2) return std::unexpected(PacketError::invalid_length);
            auto length=(static_cast<std::size_t>(p[offset+1])+1)*8;
            if (length>p.size()-offset) return std::unexpected(PacketError::invalid_length);
            auto end=offset+length;
            for (auto i=offset+2;i<end;) {
                auto type=p[i++];
                if (type==0) continue;
                if (i==end) return std::unexpected(PacketError::invalid_length);
                auto size=static_cast<std::size_t>(p[i++]);
                if (size>end-i) return std::unexpected(PacketError::invalid_length);
                if (type==1) {
                    if (!std::ranges::all_of(p.subspan(i,size),[](auto byte) { return byte==0; }))
                        return std::unexpected(PacketError::unsupported_header);
                } else if ((type & 0xc0)!=0) {
                    // ICMP error generation for the 10 and 11 actions is not implemented.
                    return std::unexpected(PacketError::unsupported_header);
                }
                i+=size;
            }
            return length;
        }
        auto checksum(std::span<std::uint8_t const> p, std::size_t udp_offset) noexcept -> std::uint16_t {
            std::uint64_t sum = 17 + static_cast<std::uint64_t>(p.size() - udp_offset);
            auto add = [&sum](std::span<std::uint8_t const> bytes) {
                std::size_t i = 0;
                for (; i + 8 <= bytes.size(); i += 8) {
                    sum += ((std::uint64_t{bytes[i]} << 8) | bytes[i + 1]) +
                           ((std::uint64_t{bytes[i + 2]} << 8) | bytes[i + 3]) +
                           ((std::uint64_t{bytes[i + 4]} << 8) | bytes[i + 5]) +
                           ((std::uint64_t{bytes[i + 6]} << 8) | bytes[i + 7]);
                }
                for (; i + 1 < bytes.size(); i += 2) sum += (std::uint64_t{bytes[i]} << 8) | bytes[i + 1];
                if (i < bytes.size()) sum += std::uint64_t{bytes[i]} << 8;
            };
            add(p.subspan(8, 32));
            add(p.subspan(udp_offset));
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            return static_cast<std::uint16_t>(~sum);
        }
    }
    auto parse_udp6_fragment(std::span<std::uint8_t const> p) noexcept -> std::optional<Udp6Fragment> {
        if (p.size()<48 || p[0]>>4!=6 || read16(p,4)!=p.size()-40) return {};
        std::size_t prefix=40,next_field=6;
        if (p[next_field]==0) {
            auto length=options_length(p,prefix);
            if (!length) return {};
            next_field=prefix;
            prefix+=*length;
        }
        if (p[next_field]!=44 || p.size()-prefix<8 || p[prefix+1]!=0) return {};
        auto next=p[prefix];
        if (next!=17 && next!=60) return {};
        auto bits=read16(p,prefix+2);
        if (bits&6) return {};
        auto offset=static_cast<std::size_t>(bits&0xfff8);
        if (offset==0) {
            auto udp=prefix+8;
            if (next==60) {
                auto length=options_length(p,udp);
                if (!length || p[udp]!=17) return {};
                udp+=*length;
            }
            if (p.size()-udp<8) return {};
        }
        auto id=(std::uint32_t(read16(p,prefix+4))<<16)|read16(p,prefix+6);
        return Udp6Fragment{prefix,next_field,offset,id,bool(bits&1)};
    }
    auto parse_udp6(std::span<std::uint8_t const> p) noexcept -> std::expected<Udp6View, PacketError> {
        if (p.size() < 40) return std::unexpected(PacketError::truncated);
        if ((p[0] >> 4) != 6) return std::unexpected(PacketError::invalid_version);
        if (read16(p, 4) != p.size() - 40) return std::unexpected(PacketError::invalid_length);
        std::size_t offset=40;
        auto next=p[6]; bool hop=false, destination=false;
        while (next==0 || next==60) {
            if ((next==0 && (hop || destination || offset!=40)) || (next==60 && destination))
                return std::unexpected(PacketError::unsupported_header);
            if (next==0) hop=true; else destination=true;
            auto length=options_length(p,offset);
            if (!length) return std::unexpected(length.error());
            next=p[offset]; offset+=*length;
        }
        if (next==44) return std::unexpected(PacketError::unsupported_fragment);
        if (next==43 || next==51 || next==50) return std::unexpected(PacketError::unsupported_header);
        if (next!=17) return std::unexpected(PacketError::unsupported_protocol);
        if (p.size()-offset<8 || read16(p, offset+4) != p.size()-offset)
            return std::unexpected(PacketError::invalid_length);
        if (read16(p, offset+6) == 0 || checksum(p,offset) != 0) return std::unexpected(PacketError::invalid_checksum);
        Udp6View result;
        std::copy_n(p.begin() + 8, 16, result.source.begin());
        std::copy_n(p.begin() + 24, 16, result.destination.begin());
        result.source_port = read16(p, offset); result.destination_port = read16(p, offset+2);
        result.payload = p.subspan(offset+8);
        result.dscp=static_cast<std::uint8_t>(((p[0] & 15) << 2) | (p[1] >> 6));
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
        auto value = checksum(p,40);
        put16(p, 46, value == 0 ? 0xffff : value);
        return p;
    }
}
