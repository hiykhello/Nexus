export module dns.response_addresses;
import std;
import dns.message;
import rules;

export namespace dns {
    namespace detail {
    template<class Visitor>
    [[nodiscard]] inline auto visit_response_addresses(Response const& response,Visitor&& visitor)
        -> std::expected<std::size_t,MessageError> {
        if(response.rcode!=0)return std::size_t{};
        auto wire=std::span(response.wire);
        if(wire.size()>65535 || response.records.size()>128)return std::unexpected(MessageError::limit);
        std::size_t count=0;
        auto append=[&](std::size_t pos,std::size_t size) -> bool {
            if(count>=16384 || pos>wire.size() || size>wire.size()-pos)return false;
            ++count;visitor(wire.subspan(pos,size));return true;
        };
        for(auto const& record:response.records) {
            if(record.section!=Section::answer || (record.type!=1 && record.type!=28 && record.type!=65))continue;
            // CHAOS A records use a domain name and a 16-bit address.
            if(record.type==1 && record.klass==3)continue;
            if(record.data_offset>wire.size() || record.data_length>wire.size()-record.data_offset)
                return std::unexpected(MessageError::malformed);
            auto pos=record.data_offset,end=pos+record.data_length;
            if(record.type==1 || record.type==28) {
                auto size=record.type==1 ? 4u : 16u;
                if(record.data_length!=size)return std::unexpected(MessageError::malformed);
                if(!append(pos,size))return std::unexpected(MessageError::limit);
                continue;
            }
            // HTTPS has a two-byte priority followed by a wire domain name.
            if(end-pos<3)return std::unexpected(MessageError::malformed);
            pos+=2;auto cursor=pos;bool jumped=false;unsigned jumps=0;std::size_t name_size=0;
            for(;;) {
                if(cursor>=wire.size() || (!jumped && cursor>=end))return std::unexpected(MessageError::malformed);
                auto length=wire[cursor++];
                if((length&0xc0)==0xc0) {
                    if(cursor>=wire.size() || (!jumped && cursor>=end) || ++jumps>128)return std::unexpected(MessageError::malformed);
                    auto target=(std::size_t(length&0x3f)<<8)|wire[cursor++];
                    if(target>=cursor-2)return std::unexpected(MessageError::malformed);
                    if(!jumped){pos=cursor;jumped=true;}cursor=target;continue;
                }
                if(length&0xc0 || ++name_size>255)return std::unexpected(MessageError::malformed);
                if(!length){if(!jumped)pos=cursor;break;}
                if(cursor+length>wire.size() || (!jumped && cursor+length>end) || name_size+length>255)
                    return std::unexpected(MessageError::malformed);
                name_size+=length;cursor+=length;
            }
            while(pos<end) {
                if(end-pos<4)return std::unexpected(MessageError::malformed);
                auto key=std::uint16_t((std::uint16_t(wire[pos])<<8)|wire[pos+1]);
                auto length=std::size_t((std::uint16_t(wire[pos+2])<<8)|wire[pos+3]);pos+=4;
                if(length>end-pos)return std::unexpected(MessageError::malformed);
                auto size=key==4 ? 4u : key==6 ? 16u : 0u;
                if(size) {
                    if(length%size)return std::unexpected(MessageError::malformed);
                    for(auto i=std::size_t{};i<length;i+=size)if(!append(pos+i,size))return std::unexpected(MessageError::limit);
                }
                pos+=length;
            }
        }
        return count;
    }
    }
    // Counting shares the same validation as extraction and allocates no list.
    [[nodiscard]] inline auto response_address_count(Response const& response) -> std::expected<std::size_t,MessageError> {
        return detail::visit_response_addresses(response,[](auto) noexcept {});
    }
    // Optionally reserve a previously validated count before populating the
    // list, so the owner can reserve its memory budget first.
    [[nodiscard]] inline auto response_addresses(Response const& response,std::size_t reserved=0)
        -> std::expected<std::vector<rules::ProgramAddress>,MessageError> {
        std::vector<rules::ProgramAddress> addresses;
        if(reserved>16384)return std::unexpected(MessageError::limit);
        addresses.reserve(reserved);
        auto visited=detail::visit_response_addresses(response,[&](auto bytes) {
            rules::ProgramAddress address{};address.size=static_cast<std::uint8_t>(bytes.size());
            std::ranges::copy(bytes,address.bytes.begin());addresses.push_back(address);
        });
        if(!visited)return std::unexpected(visited.error());
        return addresses;
    }
}
