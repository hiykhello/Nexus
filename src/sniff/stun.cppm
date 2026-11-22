export module sniff.stun;
import std;

export namespace sniff {
    [[nodiscard]] auto stun_datagram(std::span<std::uint8_t const> packet) noexcept -> bool {
        constexpr std::size_t header_size=20;
        constexpr std::array<std::uint8_t,4> cookie{0x21,0x12,0xa4,0x42};
        auto read16=[&](std::size_t at) {return (unsigned(packet[at])<<8)|packet[at+1];};
        if (packet.size()<header_size || (packet[0]&0xc0) ||
            !std::ranges::equal(packet.subspan<4,4>(),cookie) || read16(2)!=packet.size()-header_size)
            return false;
        for (std::size_t at=header_size;at<packet.size();) {
            auto remaining=packet.size()-at;
            if (remaining<4) return false;
            auto padded=(read16(at+2)+3u)&~3u;
            if (padded>remaining-4) return false;
            at+=4+padded;
        }
        return true;
    }
}
