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
        auto checksum(std::span<std::uint8_t const> p, std::size_t offset) noexcept -> std::uint16_t {
            std::uint32_t sum=6+static_cast<std::uint32_t>(p.size()-offset);
            auto add=[&](std::span<std::uint8_t const> bytes) {
                std::size_t i=0;
                for (;i+1<bytes.size();i+=2) { sum+=(std::uint32_t{bytes[i]}<<8)|bytes[i+1]; sum=(sum&0xffff)+(sum>>16); }
                if (i<bytes.size()) sum+=std::uint32_t{bytes[i]}<<8;
            };
            add(p.subspan(8,32)); add(p.subspan(offset));
            while (sum>>16) sum=(sum&0xffff)+(sum>>16);
            return static_cast<std::uint16_t>(~sum);
        }
    }
    auto parse_tcp6(std::span<std::uint8_t const> p) noexcept -> std::expected<Tcp6View,PacketError> {
        if (p.size()<40) return std::unexpected(PacketError::truncated);
        if ((p[0]>>4)!=6) return std::unexpected(PacketError::invalid_version);
        if (read16(p,4)!=p.size()-40) return std::unexpected(PacketError::invalid_length);
        std::size_t offset=40;
        auto next=p[6]; bool hop=false, destination=false;
        while (next==0 || next==60) {
            if ((next==0 && (hop || destination || offset!=40)) || (next==60 && destination))
                return std::unexpected(PacketError::unsupported_header);
            if (next==0) hop=true; else destination=true;
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
                } else if ((type & 0xc0)!=0) return std::unexpected(PacketError::unsupported_header);
                i+=size;
            }
            next=p[offset]; offset=end;
        }
        if (next==44) return std::unexpected(PacketError::unsupported_fragment);
        if (next==43 || next==51 || next==50) return std::unexpected(PacketError::unsupported_header);
        if (next!=6) return std::unexpected(PacketError::unsupported_protocol);
        if (p.size()-offset<20) return std::unexpected(PacketError::invalid_length);
        auto header=static_cast<std::size_t>(p[offset+12]>>4)*4;
        if (header<20 || header>p.size()-offset) return std::unexpected(PacketError::invalid_length);
        if (p[offset+12]&0x0e) return std::unexpected(PacketError::unsupported_header);
        if (checksum(p,offset)!=0) return std::unexpected(PacketError::invalid_checksum);
        Tcp6View v;
        std::copy_n(p.begin()+8,16,v.source.begin()); std::copy_n(p.begin()+24,16,v.destination.begin());
        v.source_port=read16(p,offset); v.destination_port=read16(p,offset+2);
        v.sequence=read32(p,offset+4); v.acknowledgement=read32(p,offset+8);
        v.flags=static_cast<std::uint16_t>(((p[offset+12]&1)<<8)|p[offset+13]);
        v.window=read16(p,offset+14); v.urgent=read16(p,offset+18);
        v.options=p.subspan(offset+20,header-20); v.payload=p.subspan(offset+header);
        return v;
    }
    auto make_tcp6(Tcp6View v,std::size_t mtu) -> std::expected<Bytes,PacketError> {
        return make_tcp6(v,mtu,{});
    }
    auto make_tcp6(Tcp6View v,std::size_t mtu,Bytes p) -> std::expected<Bytes,PacketError> {
        if (v.options.size()>40 || v.options.size()%4 || v.flags>0x1ff) return std::unexpected(PacketError::unsupported_header);
        auto header=60+v.options.size();
        if (mtu<header || v.payload.size()>65535-(header-40) || v.payload.size()>mtu-header)
            return std::unexpected(PacketError::too_large);
        p.resize(header+v.payload.size()); std::ranges::fill(p,0); p[0]=0x60; p[6]=6; p[7]=64;
        put16(p,4,static_cast<std::uint16_t>(p.size()-40));
        std::ranges::copy(v.source,p.begin()+8); std::ranges::copy(v.destination,p.begin()+24);
        put16(p,40,v.source_port); put16(p,42,v.destination_port); put32(p,44,v.sequence); put32(p,48,v.acknowledgement);
        p[52]=static_cast<std::uint8_t>(((20+v.options.size())/4)<<4 | (v.flags>>8)); p[53]=static_cast<std::uint8_t>(v.flags);
        put16(p,54,v.window); put16(p,58,v.urgent);
        std::ranges::copy(v.options,p.begin()+60); std::ranges::copy(v.payload,p.begin()+header);
        put16(p,56,checksum(p,40)); return p;
    }
}
