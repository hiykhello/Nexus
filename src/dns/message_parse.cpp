module dns.message;
import std;
import dns.message_wire;

namespace dns {
    using namespace message_wire;
    namespace {
    auto parse_response_impl(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected,Bytes* owned)
        -> std::expected<Response, MessageError> {
        if (data.size() > 65535) return std::unexpected(MessageError::limit);
        if (data.size() < 12) return std::unexpected(MessageError::malformed);
        auto flags = get16(data, 2);
        if (get16(data, 0) != id || !(flags & 0x8000) || (flags & 0x7800) || get16(data, 4) != 1)
            return std::unexpected(MessageError::mismatch);
        auto expected_name = encode_name(expected.name);
        if (!expected_name) return std::unexpected(expected_name.error());
        std::size_t expected_pos = 0;
        NameBoundaries expected_boundaries;
        auto canonical = name_at(*expected_name, expected_pos, expected_boundaries);
        std::size_t pos = 12;
        NameBoundaries boundaries;
        auto name = name_at(data, pos, boundaries);
        if (!name) return std::unexpected(name.error());
        if (pos + 4 > data.size()) return std::unexpected(MessageError::malformed);
        if (*name != *canonical || get16(data, pos) != expected.type || get16(data, pos+2) != expected.klass)
            return std::unexpected(MessageError::mismatch);
        pos += 4;
        if (flags & 0x0200) return std::unexpected(MessageError::truncated);
        std::array counts{get16(data, 6),get16(data, 8),get16(data, 10)};
        if (std::size_t(counts[0]) + counts[1] + counts[2] > 128) return std::unexpected(MessageError::limit);
        Response result{flags, static_cast<std::uint16_t>(flags & 15), {}, {}, {}};
        for (std::size_t section = 0; section < counts.size(); ++section) {
            for (std::size_t i = 0; i < counts[section]; ++i) {
                auto owner_start=pos;
                auto owner = name_at(data, pos, boundaries);
                if (!owner) return std::unexpected(owner.error());
                if (pos + 10 > data.size()) return std::unexpected(MessageError::malformed);
                auto type = get16(data, pos), klass = get16(data, pos+2);
                auto ttl = get32(data, pos+4); auto length = get16(data, pos+8); pos += 10;
                if (length > data.size() - pos) return std::unexpected(MessageError::malformed);
                if (type==41) {
                    if (section!=2 || result.edns || *owner!="." || data[owner_start]!=0)
                        return std::unexpected(MessageError::malformed);
                    std::size_t option=pos, end=pos+length, count=0;
                    while (option<end) {
                        if (end-option<4) return std::unexpected(MessageError::malformed);
                        auto size=get16(data,option+2);
                        option+=4;
                        if (size>end-option) return std::unexpected(MessageError::malformed);
                        option+=size;
                        ++count;
                    }
                    result.rcode |= static_cast<std::uint16_t>((ttl >> 24) << 4);
                    result.edns=Edns{klass,static_cast<std::uint8_t>(ttl >> 16),static_cast<std::uint16_t>(ttl),count};
                }
                std::optional<std::string> cname;
                if (type==2 || type==3 || type==4 || type==5 || type==7 || type==8 || type==9 || type==12 || type==14 || type==15 || type==17 || type==18 || type==21 || type==26 || type==36 || type==39 || type==6 || type==33 || (type==1 && klass==3)) {
                    auto name_end = pos;
                    if (type==15 || type==18 || type==21 || type==26 || type==36) {
                        if (length < 2) return std::unexpected(MessageError::malformed);
                        name_end += 2;
                    }
                    if (type == 33) {
                        if (length < 6) return std::unexpected(MessageError::malformed);
                        name_end += 6;
                    }
                    auto decoded = name_at(data, name_end, boundaries);
                    if (!decoded || name_end > pos + length) return std::unexpected(MessageError::malformed);
                    if (type==6 || type==14 || type==17 || type==26) {
                        auto mailbox = name_at(data, name_end, boundaries);
                        if (!mailbox || name_end > pos + length || pos + length - name_end != (type==6 ? 20u : 0u))
                            return std::unexpected(MessageError::malformed);
                    } else if (type==1 && klass==3) {
                        if(pos+length-name_end!=2)return std::unexpected(MessageError::malformed);
                    } else if (name_end != pos + length) return std::unexpected(MessageError::malformed);
                    if (type == 5) cname = std::move(*decoded);
                } else if(type==13 || type==16 || type==99) {
                    auto text=pos,end=pos+length;
                    unsigned count=0;
                    while(text<end) {
                        auto size=std::size_t(data[text++]);
                        if(size>end-text)return std::unexpected(MessageError::malformed);
                        text+=size;++count;
                    }
                    if((type==13 && count!=2) || (type!=13 && !count))return std::unexpected(MessageError::malformed);
                } else if(type==257) {
                    if(length<2 || std::size_t(data[pos+1])>length-2)return std::unexpected(MessageError::malformed);
                } else if (type==35 || type==46 || type==47 || type==64 || type==65) {
                    auto name_end=pos;
                    auto prefix=type==35 ? 4u : type==46 ? 18u : type==47 ? 0u : 2u;
                    if(length<prefix)return std::unexpected(MessageError::malformed);
                    name_end+=prefix;
                    if(type==35) for(unsigned n=0;n<3;++n) {
                        if(name_end>=pos+length || std::size_t(data[name_end])+1>pos+length-name_end)
                            return std::unexpected(MessageError::malformed);
                        name_end+=std::size_t(data[name_end])+1;
                    }
                    auto decoded=name_at(data,name_end,boundaries);
                    if(!decoded || name_end>pos+length || (type==35 && name_end!=pos+length))
                        return std::unexpected(MessageError::malformed);
                }
                result.records.push_back({std::move(*owner),type,klass,ttl,static_cast<Section>(section),pos,length,std::move(cname)});
                pos += length;
            }
        }
        if (pos != data.size()) return std::unexpected(MessageError::malformed);
        if(owned)result.wire=std::move(*owned);
        else result.wire.assign(data.begin(),data.end());
        return result;
    }
    }
    auto parse_response(std::span<std::uint8_t const> data,std::uint16_t id,Question const& expected)
        -> std::expected<Response,MessageError> {
        return parse_response_impl(data,id,expected,nullptr);
    }
    auto parse_owned_response(Bytes message,std::uint16_t id,Question const& expected)
        -> std::expected<Response,MessageError> {
        return parse_response_impl(message,id,expected,&message);
    }
}
