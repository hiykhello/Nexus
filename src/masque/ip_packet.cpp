module masque.ip_packet;
import std;

namespace masque {
    auto inspect_ip_packet(std::span<std::uint8_t const> input) noexcept -> std::expected<IpPacketView,IpPacketError> {
        if(input.empty())return std::unexpected(IpPacketError::malformed);
        auto u16=[&](std::size_t offset) {return (std::size_t(input[offset])<<8)|input[offset+1];};
        IpPacketView view;view.version=input[0]>>4;view.packet=input;
        if(view.version==4) {
            if(input.size()<20)return std::unexpected(IpPacketError::malformed);
            auto header=std::size_t(input[0]&15)*4;
            if(header<20 || header>input.size() || u16(2)!=input.size() || input.size()<header)return std::unexpected(IpPacketError::malformed);
            std::uint32_t sum=0;
            for(std::size_t i=0;i<header;i+=2)sum+=u16(i);
            while(sum>>16)sum=(sum&0xffff)+(sum>>16);
            if(sum!=0xffff)return std::unexpected(IpPacketError::checksum);
            for(std::size_t i=20;i<header;) {
                auto type=input[i];if(!type)break;if(type==1) {++i;continue;}
                if(i+2>header || input[i+1]<2 || input[i+1]>header-i)return std::unexpected(IpPacketError::malformed);
                if(type==131 || type==137)view.routed=true;
                i+=input[i+1];
            }
            auto fragment=u16(6);view.fragmented=(fragment&0x3fff)!=0;view.noninitial_fragment=(fragment&0x1fff)!=0;
            view.protocol=input[9];view.hop_limit=input[8];
            std::copy_n(input.begin()+12,4,view.source.begin());std::copy_n(input.begin()+16,4,view.destination.begin());
            return view;
        }
        if(view.version!=6 || input.size()<40 || u16(4)+40!=input.size())return std::unexpected(IpPacketError::malformed);
        std::copy_n(input.begin()+8,16,view.source.begin());std::copy_n(input.begin()+24,16,view.destination.begin());
        view.hop_limit=input[7];auto next=input[6];std::size_t offset=40;bool fragment_seen=false;
        while(ipv6_extension(next)) {
            if(next==253 || next==254)return std::unexpected(IpPacketError::unsupported);
            if(next==0 && offset!=40)return std::unexpected(IpPacketError::malformed);
            if(offset+2>input.size())return std::unexpected(IpPacketError::malformed);
            auto current=next;next=input[offset];std::size_t length=0;
            if(current==44) {
                if(fragment_seen || offset+8>input.size())return std::unexpected(IpPacketError::malformed);
                fragment_seen=true;view.fragmented=true;view.noninitial_fragment=(u16(offset+2)&0xfff8)!=0;length=8;
            } else if(current==51) {
                length=(std::size_t(input[offset+1])+2)*4;
                if(length<12)return std::unexpected(IpPacketError::malformed);
            } else {
                length=(std::size_t(input[offset+1])+1)*8;
                if(current==139 && length<40)return std::unexpected(IpPacketError::malformed);
            }
            if(length>input.size()-offset)return std::unexpected(IpPacketError::malformed);
            if(current==43 && input[offset+3])view.routed=true;
            if(current==0 || current==60) {
                for(auto pos=offset+2;pos<offset+length;) {
                    auto type=input[pos];if(!type) {++pos;continue;}
                    if(pos+2>offset+length || input[pos+1]>offset+length-pos-2)return std::unexpected(IpPacketError::malformed);
                    // Mobile IPv6 Home Address can change the source seen by
                    // the destination's upper layer; do not grant it solely
                    // from the outer source address.
                    if(type==0xc9)view.source_override=true;
                    pos+=std::size_t(input[pos+1])+2;
                }
            }
            offset+=length;
            if(view.noninitial_fragment && ipv6_extension(next))return std::unexpected(IpPacketError::fragment_protocol_unknown);
            if(view.noninitial_fragment)break;
        }
        // ESP's encrypted trailer hides its inner Next Header; use protocol 50
        // as the outer payload protocol. No extension contents are decrypted.
        view.protocol=next;return view;
    }
}
