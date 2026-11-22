#pragma once

namespace cli::tun_enabled {
    // Reply packets were already built and authorized by the UDP bridge.
    class TunUdpReplyFragments {
        std::uint32_t identification_=0;
        static auto put16(std::span<std::uint8_t> bytes,std::size_t at,std::uint16_t value) noexcept -> void {
            bytes[at]=static_cast<std::uint8_t>(value>>8);
            bytes[at+1]=static_cast<std::uint8_t>(value);
        }
    public:
        auto seed() noexcept -> bool {
            return platform::secure_random(std::as_writable_bytes(std::span{&identification_,1})).has_value();
        }
        auto send(packet::MemoryLink& link,packet::Bytes bytes,std::size_t mtu) -> bool {
            if (bytes.size()<=mtu) return link.send(packet::Side::second,bytes).has_value();
            auto ipv6=bytes.front()>>4==6;
            auto header=ipv6 ? 40u : 20u;
            auto overhead=header+(ipv6 ? 8u : 0u);
            if (mtu<overhead+8) return false;
            auto capacity=(mtu-overhead)&~std::size_t{7};
            auto content=std::span(bytes).subspan(header);
            auto count=(content.size()+capacity-1)/capacity;
            if (count>64) return false;
            auto identification=++identification_;
            std::vector<packet::Bytes> group;
            group.reserve(count);
            for (std::size_t offset=0;offset<content.size();offset+=capacity) {
                auto length=std::min(capacity,content.size()-offset);
                bool more=length<content.size()-offset;
                packet::Bytes fragment(overhead+length);
                std::copy_n(bytes.begin(),header,fragment.begin());
                std::ranges::copy(content.subspan(offset,length),fragment.begin()+overhead);
                if (ipv6) {
                    put16(fragment,4,static_cast<std::uint16_t>(length+8));
                    fragment[6]=44;
                    fragment[40]=17;
                    put16(fragment,42,static_cast<std::uint16_t>(offset|std::size_t(more)));
                    for (unsigned part=0;part<4;++part)
                        fragment[44+part]=static_cast<std::uint8_t>(identification>>(24-part*8));
                } else {
                    put16(fragment,2,static_cast<std::uint16_t>(fragment.size()));
                    put16(fragment,4,static_cast<std::uint16_t>(identification));
                    put16(fragment,6,static_cast<std::uint16_t>(offset/8|(more ? 0x2000 : 0)));
                    put16(fragment,10,0);
                    put16(fragment,10,packet::internet_checksum(std::span(fragment).first(header)));
                }
                group.push_back(std::move(fragment));
            }
            return link.send_packets(packet::Side::second,std::move(group)).has_value();
        }
    };
}
