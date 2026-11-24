module dns.message;
import std;
import dns.message_wire;

namespace dns {
    using namespace message_wire;
    namespace {
    auto validate_response_encoding(Response const& response) -> std::expected<void,MessageError> {
        auto const& wire=response.wire;
        if(wire.size()<12 || wire.size()>65535 || !(get16(wire,2)&0x8000)) return std::unexpected(MessageError::malformed);
        for(auto const& record:response.records) {
            if(record.data_offset<10 || record.data_offset>wire.size() || record.data_length>wire.size()-record.data_offset)
                return std::unexpected(MessageError::malformed);
            auto header=record.data_offset-10;
            if(get16(wire,header)!=record.type || get16(wire,header+2)!=record.klass || get32(wire,header+4)!=record.ttl || get16(wire,header+8)!=record.data_length)
                return std::unexpected(MessageError::malformed);
        }
        return {};
    }
    auto rewrite_response_wire(Bytes& output,std::span<Record const> records,std::uint16_t id,std::optional<std::uint32_t> ttl) -> void {
        output[0]=static_cast<std::uint8_t>(id>>8);output[1]=static_cast<std::uint8_t>(id);
        if(ttl) for(auto const& record:records) {
            if(record.type==41)continue;
            auto offset=record.data_offset-6;
            for(unsigned i=0;i<4;++i)output[offset+i]=static_cast<std::uint8_t>(*ttl>>(24-8*i));
        }
    }
    }
    auto copy_response_wire(Response const& response,std::uint16_t id,std::optional<std::uint32_t> ttl) -> std::expected<Bytes,MessageError> {
        if(auto valid=validate_response_encoding(response);!valid)return std::unexpected(valid.error());
        auto output=response.wire;rewrite_response_wire(output,response.records,id,ttl);return output;
    }
    namespace {
        struct RdataNames {
            std::size_t prefix=0;
            unsigned count=0;
            bool compress=false;
        };

        auto name_fields(Record const& record,std::span<std::uint8_t const> source)
            -> std::optional<RdataNames> {
            switch (record.type) {
                case 1: return record.klass==3 ? RdataNames{0,1,false} : RdataNames{};
                case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12:
                    return RdataNames{0,1,true};
                case 6: case 14: return RdataNames{0,2,true};
                case 15: return RdataNames{2,1,true};
                case 17: return RdataNames{0,2,false};
                case 18: case 21: case 36: case 64: case 65: return RdataNames{2,1,false};
                case 26: return RdataNames{2,2,false};
                case 33: return RdataNames{6,1,false};
                case 39: case 47: return RdataNames{0,1,false};
                case 46: return RdataNames{18,1,false};
                case 35: {
                    std::size_t pos=4;
                    for (unsigned field=0;field<3;++field) {
                        if (pos>=source.size() || source[pos]>=source.size()-pos) return {};
                        pos+=1+source[pos];
                    }
                    return RdataNames{pos,1,false};
                }
                default: return RdataNames{};
            }
        }

        class Encoder {
            std::map<std::string,std::uint16_t,std::less<>> suffixes_;
            NameBoundaries boundaries_;
            std::span<std::uint8_t const> wire_;
        public:
            Bytes output;
            explicit Encoder(std::span<std::uint8_t const> wire) : wire_(wire),output(wire.begin(),wire.begin()+12) {
                output.reserve(wire.size());
            }
            auto copy(std::size_t first,std::size_t last) -> void {
                output.insert(output.end(),wire_.begin()+first,wire_.begin()+last);
            }
            auto name(std::size_t& cursor,std::size_t limit,bool compress) -> bool {
                auto start=cursor;
                auto decoded=name_at(wire_,cursor,boundaries_);
                if (!decoded || cursor>limit) return false;
                if (!compress) {
                    // A raw name in opaque or non-compressible RDATA must
                    // have no pointer that could become stale after re-encoding.
                    auto pos=start;
                    while (pos<cursor && wire_[pos]) {
                        if (wire_[pos]&0xc0) return false;
                        pos+=1+wire_[pos];
                    }
                    auto offset=output.size();
                    std::string_view suffix=*decoded;
                    for (auto pos=start;pos<cursor && wire_[pos];pos+=1+wire_[pos]) {
                        if (offset+pos-start<16384)
                            suffixes_.try_emplace(std::string(suffix),offset+pos-start);
                        suffix.remove_prefix(std::min(suffix.size(),std::size_t(wire_[pos])+1));
                    }
                    copy(start,cursor);
                    return true;
                }
                if (*decoded!=".") {
                    std::string_view suffix=*decoded;
                    while (!suffix.empty()) {
                        if (auto known=suffixes_.find(suffix);known!=suffixes_.end()) {
                            put16(output,static_cast<std::uint16_t>(0xc000u|known->second));
                            return true;
                        }
                        if (output.size()<16384)
                            suffixes_.try_emplace(std::string(suffix),output.size());
                        auto end=suffix.find('.');
                        auto label=suffix.substr(0,end);
                        output.push_back(static_cast<std::uint8_t>(label.size()));
                        output.insert(output.end(),label.begin(),label.end());
                        if (end==suffix.npos) break;
                        suffix.remove_prefix(end+1);
                    }
                }
                output.push_back(0);
                return true;
            }
            auto record(Record const& rr,std::size_t& cursor,std::optional<std::uint32_t> ttl) -> bool {
                auto header=rr.data_offset-10;
                if (header<cursor || !name(cursor,header,rr.type!=41) || cursor!=header) return false;
                copy(header,rr.data_offset);
                auto target=output.size();
                if (ttl && rr.type!=41)
                    for (unsigned i=0;i<4;++i) output[target-6+i]=static_cast<std::uint8_t>(*ttl>>(24-8*i));
                auto end=rr.data_offset+rr.data_length;
                auto fields=name_fields(rr,wire_.subspan(rr.data_offset,rr.data_length));
                if (!fields || fields->prefix>rr.data_length) return false;
                cursor=rr.data_offset+fields->prefix;
                copy(rr.data_offset,cursor);
                for (unsigned i=0;i<fields->count;++i)
                    if (!name(cursor,end,fields->compress)) return false;
                copy(cursor,end);
                cursor=end;
                auto length=output.size()-target;
                if (length>65535 || output.size()>65535) return false;
                output[target-2]=static_cast<std::uint8_t>(length>>8);
                output[target-1]=static_cast<std::uint8_t>(length);
                return true;
            }
        };
    }

    auto encode_response(Response const& response,std::uint16_t id,std::optional<std::uint32_t> ttl)
        -> std::expected<Bytes,MessageError> {
        if (auto valid=validate_response_encoding(response);!valid) return std::unexpected(valid.error());
        // Preserve layout for message signatures and for legacy input whose
        // non-compressible fields already contain pointers.
        if (std::ranges::any_of(response.records,[](auto const& record) {return record.type==24 || record.type==250;}))
            return copy_response_wire(response,id,ttl);
        Encoder encoder(response.wire);
        auto cursor=std::size_t{12};
        if (!encoder.name(cursor,response.wire.size(),false) || response.wire.size()-cursor<4)
            return std::unexpected(MessageError::malformed);
        encoder.copy(cursor,cursor+4);
        cursor+=4;
        for (auto const& rr:response.records)
            if (!encoder.record(rr,cursor,ttl)) return copy_response_wire(response,id,ttl);
        if (cursor!=response.wire.size() || encoder.output.size()>response.wire.size())
            return copy_response_wire(response,id,ttl);
        encoder.output[0]=static_cast<std::uint8_t>(id>>8);
        encoder.output[1]=static_cast<std::uint8_t>(id);
        return std::move(encoder.output);
    }

    auto rewrite_response(Response& response,std::uint16_t id,std::optional<std::uint32_t> ttl) -> std::expected<void,MessageError> {
        if(auto valid=validate_response_encoding(response);!valid)return std::unexpected(valid.error());
        rewrite_response_wire(response.wire,response.records,id,ttl);
        if(ttl)for(auto& record:response.records)if(record.type!=41)record.ttl=*ttl;
        return {};
    }
}
