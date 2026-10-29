module nexus.packet;
import std;

namespace nexus::packet {
    namespace {
        auto read16(std::span<std::uint8_t const> p, std::size_t i) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{p[i]}<<8)|p[i+1]);
        }
        auto read32(std::span<std::uint8_t const> p, std::size_t i) noexcept -> std::uint32_t {
            return (std::uint32_t{read16(p,i)}<<16)|read16(p,i+2);
        }
        auto put16(Bytes& p,std::size_t i,std::uint16_t n) noexcept -> void {
            p[i]=static_cast<std::uint8_t>(n>>8); p[i+1]=static_cast<std::uint8_t>(n);
        }
        auto put32(Bytes& p,std::size_t i,std::uint32_t n) noexcept -> void {
            put16(p,i,static_cast<std::uint16_t>(n>>16)); put16(p,i+2,static_cast<std::uint16_t>(n));
        }
        auto checksum(std::span<std::uint8_t const> p) noexcept -> std::uint16_t {
            std::uint32_t sum=6+static_cast<std::uint32_t>(p.size()-40);
            auto add=[&](std::span<std::uint8_t const> bytes) {
                std::size_t i=0;
                for (;i+1<bytes.size();i+=2) { sum+=(std::uint32_t{bytes[i]}<<8)|bytes[i+1]; sum=(sum&0xffff)+(sum>>16); }
                if (i<bytes.size()) sum+=std::uint32_t{bytes[i]}<<8;
            };
            add(p.subspan(8,32)); add(p.subspan(40));
            while (sum>>16) sum=(sum&0xffff)+(sum>>16);
            return static_cast<std::uint16_t>(~sum);
        }
    }
    auto parse_tcp6(std::span<std::uint8_t const> p) noexcept -> std::expected<Tcp6View,PacketError> {
        if (p.size()<40) return std::unexpected(PacketError::truncated);
        if ((p[0]>>4)!=6) return std::unexpected(PacketError::invalid_version);
        if (read16(p,4)!=p.size()-40 || p.size()<60) return std::unexpected(PacketError::invalid_length);
        if (p[6]==44) return std::unexpected(PacketError::unsupported_fragment);
        if (p[6]==0 || p[6]==60 || p[6]==43 || p[6]==51 || p[6]==50) return std::unexpected(PacketError::unsupported_header);
        if (p[6]!=6) return std::unexpected(PacketError::unsupported_protocol);
        auto header=static_cast<std::size_t>(p[52]>>4)*4;
        if (header<20 || header>p.size()-40) return std::unexpected(PacketError::invalid_length);
        if (p[52]&0x0e) return std::unexpected(PacketError::unsupported_header);
        if (checksum(p)!=0) return std::unexpected(PacketError::invalid_checksum);
        Tcp6View v;
        std::copy_n(p.begin()+8,16,v.source.begin()); std::copy_n(p.begin()+24,16,v.destination.begin());
        v.source_port=read16(p,40); v.destination_port=read16(p,42);
        v.sequence=read32(p,44); v.acknowledgement=read32(p,48);
        v.flags=static_cast<std::uint16_t>(((p[52]&1)<<8)|p[53]); v.window=read16(p,54); v.urgent=read16(p,58);
        v.options=p.subspan(60,header-20); v.payload=p.subspan(40+header);
        return v;
    }
    auto make_tcp6(Tcp6View v,std::size_t mtu) -> std::expected<Bytes,PacketError> {
        if (v.options.size()>40 || v.options.size()%4 || v.flags>0x1ff) return std::unexpected(PacketError::unsupported_header);
        auto header=60+v.options.size();
        if (mtu<header || v.payload.size()>65535-(header-40) || v.payload.size()>mtu-header)
            return std::unexpected(PacketError::too_large);
        Bytes p(header+v.payload.size()); p[0]=0x60; p[6]=6; p[7]=64;
        put16(p,4,static_cast<std::uint16_t>(p.size()-40));
        std::ranges::copy(v.source,p.begin()+8); std::ranges::copy(v.destination,p.begin()+24);
        put16(p,40,v.source_port); put16(p,42,v.destination_port); put32(p,44,v.sequence); put32(p,48,v.acknowledgement);
        p[52]=static_cast<std::uint8_t>(((20+v.options.size())/4)<<4 | (v.flags>>8)); p[53]=static_cast<std::uint8_t>(v.flags);
        put16(p,54,v.window); put16(p,58,v.urgent);
        std::ranges::copy(v.options,p.begin()+60); std::ranges::copy(v.payload,p.begin()+header);
        put16(p,56,checksum(p)); return p;
    }
}
