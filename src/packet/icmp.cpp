module packet;
import std;

namespace packet {
    namespace {
        auto read16(std::span<std::uint8_t const> p, std::size_t i) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{p[i]}<<8)|p[i+1]);
        }
        auto put16(Bytes& p, std::size_t i, std::uint16_t value) noexcept -> void {
            p[i]=static_cast<std::uint8_t>(value>>8); p[i+1]=static_cast<std::uint8_t>(value);
        }
        auto checksum6(std::span<std::uint8_t const> p, std::size_t offset=40) noexcept -> std::uint16_t {
            std::uint32_t sum=58+static_cast<std::uint32_t>(p.size()-offset);
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
    auto parse_icmp_echo4(std::span<std::uint8_t const> p) noexcept -> std::expected<IcmpEcho4View,PacketError> {
        if (p.size()<20) return std::unexpected(PacketError::truncated);
        if (p[0]>>4!=4) return std::unexpected(PacketError::invalid_version);
        auto offset=static_cast<std::size_t>(p[0]&15)*4;
        if (offset<20 || offset>p.size() || p.size()-offset<8 || read16(p,2)!=p.size())
            return std::unexpected(PacketError::invalid_length);
        if (internet_checksum(p.first(offset))) return std::unexpected(PacketError::invalid_checksum);
        for (std::size_t i=20;i<offset;++i) {
            if (p[i]==1) continue;
            if (p[i]==0 && std::ranges::all_of(p.subspan(i,offset-i),[](auto byte) { return byte==0; })) break;
            return std::unexpected(PacketError::unsupported_header);
        }
        if (read16(p,6)&0xbfff) return std::unexpected(PacketError::unsupported_fragment);
        if (p[9]!=1 || (p[offset]!=0 && p[offset]!=8)) return std::unexpected(PacketError::unsupported_protocol);
        if (p[offset+1]) return std::unexpected(PacketError::unsupported_header);
        if (internet_checksum(p.subspan(offset))) return std::unexpected(PacketError::invalid_checksum);
        IcmpEcho4View view;
        std::copy_n(p.begin()+12,4,view.source.begin()); std::copy_n(p.begin()+16,4,view.destination.begin());
        view.kind=p[offset]==8 ? EchoKind::request : EchoKind::reply;
        view.identifier=read16(p,offset+4); view.sequence=read16(p,offset+6); view.payload=p.subspan(offset+8);
        return view;
    }
    auto parse_icmp_echo6(std::span<std::uint8_t const> p) noexcept -> std::expected<IcmpEcho6View,PacketError> {
        if (p.size()<40) return std::unexpected(PacketError::truncated);
        if (p[0]>>4!=6) return std::unexpected(PacketError::invalid_version);
        if (read16(p,4)!=p.size()-40) return std::unexpected(PacketError::invalid_length);
        auto next=p[6]; std::size_t offset=40; bool hop=false, destination=false;
        while (next==0 || next==60) {
            if ((next==0 && (hop || destination || offset!=40)) || (next==60 && destination))
                return std::unexpected(PacketError::unsupported_header);
            if (next==0) hop=true; else destination=true;
            if (p.size()-offset<2) return std::unexpected(PacketError::invalid_length);
            auto length=(static_cast<std::size_t>(p[offset+1])+1)*8;
            if (length>p.size()-offset) return std::unexpected(PacketError::invalid_length);
            auto end=offset+length;
            for (auto i=offset+2;i<end;) {
                auto type=p[i++]; if (type==0) continue;
                if (i==end) return std::unexpected(PacketError::invalid_length);
                auto size=static_cast<std::size_t>(p[i++]);
                if (size>end-i) return std::unexpected(PacketError::invalid_length);
                if (type==1) {
                    if (!std::ranges::all_of(p.subspan(i,size),[](auto byte) { return byte==0; }))
                        return std::unexpected(PacketError::unsupported_header);
                } else if (type&0xc0) return std::unexpected(PacketError::unsupported_header);
                i+=size;
            }
            next=p[offset]; offset=end;
        }
        if (next==44) return std::unexpected(PacketError::unsupported_fragment);
        if (next==43 || next==50 || next==51) return std::unexpected(PacketError::unsupported_header);
        if (next!=58) return std::unexpected(PacketError::unsupported_protocol);
        if (p.size()-offset<8) return std::unexpected(PacketError::invalid_length);
        if (p[offset]!=128 && p[offset]!=129) return std::unexpected(PacketError::unsupported_protocol);
        if (p[offset+1]) return std::unexpected(PacketError::unsupported_header);
        if (checksum6(p,offset)) return std::unexpected(PacketError::invalid_checksum);
        IcmpEcho6View view;
        std::copy_n(p.begin()+8,16,view.source.begin()); std::copy_n(p.begin()+24,16,view.destination.begin());
        view.kind=p[offset]==128 ? EchoKind::request : EchoKind::reply;
        view.identifier=read16(p,offset+4); view.sequence=read16(p,offset+6); view.payload=p.subspan(offset+8);
        return view;
    }
    auto make_icmp_echo4(IcmpEcho4View v, std::size_t mtu) -> std::expected<Bytes,PacketError> {
        if (mtu<28 || v.payload.size()>65535-28 || v.payload.size()>mtu-28) return std::unexpected(PacketError::too_large);
        Bytes p(28+v.payload.size()); p[0]=0x45; put16(p,2,static_cast<std::uint16_t>(p.size()));
        put16(p,6,0x4000); p[8]=64; p[9]=1;
        std::copy(v.source.begin(),v.source.end(),p.begin()+12); std::copy(v.destination.begin(),v.destination.end(),p.begin()+16);
        put16(p,10,internet_checksum(std::span(p).first(20)));
        p[20]=v.kind==EchoKind::request ? 8 : 0; put16(p,24,v.identifier); put16(p,26,v.sequence);
        std::copy(v.payload.begin(),v.payload.end(),p.begin()+28); put16(p,22,internet_checksum(std::span(p).subspan(20)));
        return p;
    }
    auto make_icmp_echo6(IcmpEcho6View v, std::size_t mtu) -> std::expected<Bytes,PacketError> {
        if (mtu<48 || v.payload.size()>65535-8 || v.payload.size()>mtu-48) return std::unexpected(PacketError::too_large);
        Bytes p(48+v.payload.size()); p[0]=0x60; put16(p,4,static_cast<std::uint16_t>(p.size()-40)); p[6]=58; p[7]=64;
        std::copy(v.source.begin(),v.source.end(),p.begin()+8); std::copy(v.destination.begin(),v.destination.end(),p.begin()+24);
        p[40]=v.kind==EchoKind::request ? 128 : 129; put16(p,44,v.identifier); put16(p,46,v.sequence);
        std::copy(v.payload.begin(),v.payload.end(),p.begin()+48); put16(p,42,checksum6(p));
        return p;
    }

    auto parse_icmp_ptb4(std::span<std::uint8_t const> p) noexcept -> std::expected<IcmpPtb4View,PacketError> {
        if (p.size()<28) return std::unexpected(PacketError::truncated);
        if ((p[0]>>4)!=4) return std::unexpected(PacketError::invalid_version);
        auto off=static_cast<std::size_t>(p[0]&15)*4;
        if (off<20 || off>p.size() || p.size()-off<8 || read16(p,2)!=p.size()) return std::unexpected(PacketError::invalid_length);
        if (internet_checksum(p.first(off))) return std::unexpected(PacketError::invalid_checksum);
        for (std::size_t i=20;i<off;++i) {
            if (p[i]==1) continue;
            if (p[i]==0 && std::ranges::all_of(p.subspan(i,off-i),[](auto byte) { return byte==0; })) break;
            return std::unexpected(PacketError::unsupported_header);
        }
        if (read16(p,6)&0xbfff) return std::unexpected(PacketError::unsupported_fragment);
        if (p[9]!=1 || p[off]!=3 || p[off+1]!=4) return std::unexpected(PacketError::unsupported_protocol);
        if (internet_checksum(p.subspan(off))) return std::unexpected(PacketError::invalid_checksum);
        IcmpPtb4View v;
        std::copy_n(p.begin()+12,4,v.source.begin()); std::copy_n(p.begin()+16,4,v.destination.begin());
        v.next_hop_mtu=read16(p,off+6);
        v.quote=p.subspan(off+8);
        return v;
    }
    auto parse_icmp_ptb6(std::span<std::uint8_t const> p) noexcept -> std::expected<IcmpPtb6View,PacketError> {
        if (p.size()<48) return std::unexpected(PacketError::truncated);
        if ((p[0]>>4)!=6) return std::unexpected(PacketError::invalid_version);
        if (read16(p,4)!=p.size()-40) return std::unexpected(PacketError::invalid_length);
        if (p[6]!=58 || p[40]!=2 || p[41]!=0) return std::unexpected(PacketError::unsupported_protocol);
        if (checksum6(p,40)) return std::unexpected(PacketError::invalid_checksum);
        IcmpPtb6View v;
        std::copy_n(p.begin()+8,16,v.source.begin()); std::copy_n(p.begin()+24,16,v.destination.begin());
        v.next_hop_mtu=(std::uint32_t{read16(p,44)}<<16)|read16(p,46);
        v.quote=p.subspan(48);
        return v;
    }
    auto make_icmp_ptb4(IcmpPtb4View v, std::size_t mtu) -> std::expected<Bytes,PacketError> {
        auto cap=std::min<std::size_t>(mtu,576);
        if (cap<28 || v.quote.size()>cap-28) return std::unexpected(PacketError::too_large);
        Bytes p(28+v.quote.size(),0); p[0]=0x45; put16(p,2,static_cast<std::uint16_t>(p.size()));
        put16(p,6,0x4000); p[8]=64; p[9]=1;
        std::copy(v.source.begin(),v.source.end(),p.begin()+12); std::copy(v.destination.begin(),v.destination.end(),p.begin()+16);
        put16(p,10,internet_checksum(std::span(p).first(20)));
        p[20]=3; p[21]=4; put16(p,26,v.next_hop_mtu);
        std::copy(v.quote.begin(),v.quote.end(),p.begin()+28);
        put16(p,22,internet_checksum(std::span(p).subspan(20)));
        return p;
    }
    auto make_icmp_ptb6(IcmpPtb6View v, std::size_t mtu) -> std::expected<Bytes,PacketError> {
        auto cap=std::min<std::size_t>(mtu,1280);
        if (cap<48 || v.quote.size()>cap-48) return std::unexpected(PacketError::too_large);
        Bytes p(48+v.quote.size(),0); p[0]=0x60; put16(p,4,static_cast<std::uint16_t>(p.size()-40)); p[6]=58; p[7]=64;
        std::copy(v.source.begin(),v.source.end(),p.begin()+8); std::copy(v.destination.begin(),v.destination.end(),p.begin()+24);
        p[40]=2; p[41]=0; put16(p,44,static_cast<std::uint16_t>(v.next_hop_mtu>>16)); put16(p,46,static_cast<std::uint16_t>(v.next_hop_mtu));
        std::copy(v.quote.begin(),v.quote.end(),p.begin()+48);
        put16(p,42,checksum6(p));
        return p;
    }

    auto udp_administratively_prohibited(std::span<std::uint8_t const> original,std::size_t mtu)
        -> std::optional<Bytes> {
        if (original.size()<28) return {};
        auto version=original[0]>>4;
        if (version!=4 && version!=6) return {};
        bool v6=version==6;
        auto header=v6 ? 40u : 20u;
        if (original.size()<header+8 || mtu<header+8) return {};
        auto address_size=v6 ? 16u : 4u;
        auto source_offset=v6 ? 8u : 12u;
        auto source=original.subspan(source_offset,address_size);
        auto destination=original.subspan(source_offset+address_size,address_size);
        auto unicast=[v6](std::span<std::uint8_t const> address) {
            return (v6 ? address.front()!=0xff : address.front()<224 && address.front()!=0) &&
                std::ranges::any_of(address,[](auto byte) {return byte!=0;});
        };
        if (!unicast(source) || !unicast(destination)) return {};
        auto quote=std::min(original.size(),std::min<std::size_t>(mtu,v6 ? 1280 : 576)-header-8);
        auto minimum=v6 ? 48u : (original[0]&15u)*4+8;
        if (quote<minimum) return {};
        Bytes reply(header+8+quote);
        std::ranges::copy(destination,reply.begin()+source_offset);
        std::ranges::copy(source,reply.begin()+source_offset+address_size);
        std::ranges::copy(original.first(quote),reply.begin()+header+8);
        reply[header]=v6 ? 1 : 3;
        reply[header+1]=v6 ? 1 : 13;
        if (v6) {
            reply[0]=0x60;reply[6]=58;reply[7]=64;
            put16(reply,4,static_cast<std::uint16_t>(reply.size()-header));
        } else {
            reply[0]=0x45;reply[8]=64;reply[9]=1;
            put16(reply,2,static_cast<std::uint16_t>(reply.size()));
            put16(reply,10,internet_checksum(std::span(reply).first(header)));
        }
        put16(reply,header+2,v6 ? checksum6(reply) : internet_checksum(std::span(reply).subspan(header)));
        return reply;
    }
}
