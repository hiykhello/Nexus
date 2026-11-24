export module dns.response_match;
import std;
import dns.message;
import dns.policy;
import rules;
import rules.domain_pattern;

export namespace dns {
    // A missing response yields an unknown match.
    // Record matching is existential. OPT belongs to the additional section.
    enum class ResponseTruth : std::uint8_t { no, yes, unknown };
    using ResponseCondition=policy::ResponseCondition;
    [[nodiscard]] inline auto valid_response_condition(ResponseCondition const& value) noexcept -> bool {
        if (!value.authenticated_data && !value.rcode && !value.section && !value.record_type && !value.address && !value.address_private && !value.address_any && !value.record_name && !value.record_class && !value.record_ttl_min && !value.record_ttl_max && !value.record_data && value.cname.empty()) return false;
        for (auto const& c : value.cname) {
            if (c.pattern.empty()) return false;
            if (c.kind==policy::DnsPattern::regex && (!c.compiled_regex || c.suffix)) return false;
        }
        if (value.rcode && *value.rcode>4095) return false;
        if (value.record_type && !*value.record_type) return false;
        if (value.record_class && !*value.record_class) return false;
        if (value.record_ttl_min && value.record_ttl_max && *value.record_ttl_min>*value.record_ttl_max) return false;
        if (value.address && ((value.address->size!=4 && value.address->size!=16) || value.address->bits>value.address->size*8)) return false;
        if (value.section && *value.section!=policy::ResponseSection::answer && *value.section!=policy::ResponseSection::authority && *value.section!=policy::ResponseSection::additional) return false;
        return true;
    }
    // Compare uncompressed configured RDATA with the parsed wire record.
    // Domain names in the common name-bearing RR types may use compression.
    [[nodiscard]] inline auto record_data_matches(Response const& response,Record const& record,
        std::span<std::uint8_t const> expected) noexcept -> bool {
        if (record.data_offset>response.wire.size() || record.data_length>response.wire.size()-record.data_offset) return false;
        auto data=std::span(response.wire);auto pos=record.data_offset, end=pos+record.data_length, out=std::size_t{};
        auto raw=[&](std::size_t count) {
            if (count>end-pos || count>expected.size()-out) return false;
            for (std::size_t i=0;i<count;++i) if (data[pos+i]!=expected[out+i]) return false;
            pos+=count;out+=count;return true;
        };
        auto name=[&]() {
            auto cursor=pos;bool jumped=false;unsigned jumps=0;
            for (;;) {
                if (cursor>=data.size() || (!jumped && cursor>=end)) return false;
                auto length=data[cursor++];
                if ((length&0xc0)==0xc0) {
                    if (cursor>=data.size() || (!jumped && cursor>=end) || ++jumps>128) return false;
                    auto target=(std::size_t(length&0x3f)<<8)|data[cursor++];
                    if (target>=cursor-2) return false;
                    if (!jumped) { pos=cursor;jumped=true; }
                    cursor=target;continue;
                }
                if ((length&0xc0) || out>=expected.size() || expected[out++]!=length) return false;
                if (!length) { if (!jumped) pos=cursor;return true; }
                if (cursor+length>data.size() || (!jumped && cursor+length>end) || length>expected.size()-out) return false;
                for (unsigned i=0;i<length;++i) {
                    auto fold=[](std::uint8_t c) { return c>='A' && c<='Z' ? c+32 : c; };
                    if (fold(data[cursor++])!=fold(expected[out++])) return false;
                }
            }
        };
        auto text=[&]() { return pos<end && raw(std::size_t(data[pos])+1); };
        switch (record.type) {
        case 1: if(record.klass==3) {if(!name() || !raw(2))return false;} else if(!raw(end-pos))return false;break;
        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 39: if (!name()) return false;break;
        case 15: case 18: case 21: case 36: if (!raw(2) || !name()) return false;break;
        case 14: case 17: if (!name() || !name()) return false;break;
        case 26: if (!raw(2) || !name() || !name()) return false;break;
        case 33: if (!raw(6) || !name()) return false;break;
        case 35: if (!raw(4) || !text() || !text() || !text() || !name()) return false;break;
        case 6: if (!name() || !name() || !raw(20)) return false;break;
        case 46: if (!raw(18) || !name() || !raw(end-pos)) return false;break;
        case 47: if (!name() || !raw(end-pos)) return false;break;
        case 64: case 65: if (!raw(2) || !name() || !raw(end-pos)) return false;break;
        default: if (!raw(end-pos)) return false;break;
        }
        return pos==end && out==expected.size();
    }
    [[nodiscard]] inline auto match_response(ResponseCondition const& condition,Response const* response) noexcept -> ResponseTruth {
        if (!valid_response_condition(condition) || !response) return ResponseTruth::unknown;
        bool matched=(!condition.rcode || *condition.rcode==response->rcode) &&
            (!condition.authenticated_data || *condition.authenticated_data==bool(response->flags&authenticated_data_flag));
        if (matched && (condition.record_type || condition.section || condition.record_name || condition.record_class || condition.record_ttl_min || condition.record_ttl_max || condition.record_data))
            matched=std::ranges::any_of(response->records,[&](Record const& record) {
                return (!condition.section || static_cast<std::uint8_t>(record.section)==static_cast<std::uint8_t>(*condition.section)) &&
                    (!condition.record_type || record.type==*condition.record_type) &&
                    (!condition.record_name || record.name==*condition.record_name) &&
                    (!condition.record_class || record.klass==*condition.record_class) &&
                    (!condition.record_ttl_min || (record.type!=41 && record.ttl>=*condition.record_ttl_min)) &&
                    (!condition.record_ttl_max || (record.type!=41 && record.ttl<=*condition.record_ttl_max)) &&
                    (!condition.record_data || record_data_matches(*response,record,*condition.record_data));
            });
        if (matched && (condition.address || condition.address_private || condition.address_any)) {
            for (auto const& record:response->records) {
                if (record.section!=Section::answer || record.klass!=1 || (record.type!=1 && record.type!=28)) continue;
                auto size=record.type==1 ? 4u : 16u;
                if (record.data_length!=size || record.data_offset>response->wire.size() ||
                    record.data_length>response->wire.size()-record.data_offset) return ResponseTruth::unknown;
            }
            matched=std::ranges::any_of(response->records,[&](Record const& record) {
                if (record.section!=Section::answer || record.klass!=1 || (record.type!=1 && record.type!=28)) return false;
                auto* bytes=response->wire.data()+record.data_offset;
                if (condition.address_any || (condition.address_private && rules::is_private_address({bytes,record.data_length}))) return true;
                if (!condition.address || condition.address->size!=record.data_length) return false;
                auto const& prefix=*condition.address;
                auto whole=prefix.bits/8,remaining=prefix.bits%8;
                for (unsigned i=0;i<whole;++i) if (bytes[i]!=prefix.address[i]) return false;
                return !remaining || ((bytes[whole]^prefix.address[whole]) & (0xffu << (8-remaining)))==0;
            });
        }
        if (matched && !condition.cname.empty()) {
            for (auto const& c : condition.cname) {
                bool hit=std::ranges::any_of(response->records,[&](Record const& record) {
                    if (record.section!=Section::answer || record.type!=5 || !record.cname) return false;
                    std::string_view target=*record.cname;
                    if (target.size()>1 && target.ends_with('.')) target.remove_suffix(1);
                    if (c.kind==policy::DnsPattern::regex)
                        return c.compiled_regex && c.compiled_regex->search(target,true);
                    auto kind=c.kind==policy::DnsPattern::keyword ? rules::DomainPattern::keyword :
                        c.kind==policy::DnsPattern::wildcard ? rules::DomainPattern::wildcard :
                        c.suffix ? rules::DomainPattern::suffix : rules::DomainPattern::exact;
                    return rules::domain_pattern_matches(kind,target,c.pattern);
                });
                if (c.invert) hit=!hit;
                if (!hit) { matched=false; break; }
            }
        }
        if (condition.invert) matched=!matched;
        return matched ? ResponseTruth::yes : ResponseTruth::no;
    }
}

export namespace dns {
    // Age a wire copy using the immutable parsed records. Validate all record
    // headers before writing; OPT's TTL contains flags and is never aged.
    [[nodiscard]] inline auto age_response_wire(Response const& response,Bytes& wire,std::uint64_t elapsed_seconds,std::uint16_t new_id,
        std::optional<std::uint32_t> maximum_ttl={}) noexcept -> bool {
        if (wire.size()<12) return false;
        auto read16=[&](std::size_t pos) { return std::uint16_t((std::uint16_t(wire[pos])<<8)|wire[pos+1]); };
        auto read32=[&](std::size_t pos) { return (std::uint32_t(wire[pos])<<24)|(std::uint32_t(wire[pos+1])<<16)|
            (std::uint32_t(wire[pos+2])<<8)|wire[pos+3]; };
        for (auto const& record:response.records) {
            if (record.data_offset<10 || record.data_offset>wire.size() ||
                record.data_length>wire.size()-record.data_offset) return false;
            auto header=record.data_offset-10;
            if (read16(header)!=record.type || read16(header+2)!=record.klass ||
                read32(header+4)!=record.ttl || read16(header+8)!=record.data_length) return false;
        }
        wire[0]=static_cast<std::uint8_t>(new_id>>8);wire[1]=static_cast<std::uint8_t>(new_id);
        for (auto const& record:response.records) {
            if (record.type==41) continue;
            auto ttl=elapsed_seconds>=record.ttl ? 0 : record.ttl-static_cast<std::uint32_t>(elapsed_seconds);
            if (maximum_ttl) ttl=std::min(ttl,*maximum_ttl);
            auto pos=record.data_offset-6;
            for (unsigned i=0;i<4;++i) wire[pos+i]=static_cast<std::uint8_t>(ttl>>(24-8*i));
        }
        return true;
    }
    // Keep parsed TTLs in sync for callers retaining the full response.
    [[nodiscard]] inline auto age_response(Response& response,std::uint64_t elapsed_seconds,std::uint16_t new_id,
        std::optional<std::uint32_t> maximum_ttl={}) noexcept -> bool {
        if(!age_response_wire(response,response.wire,elapsed_seconds,new_id,maximum_ttl))return false;
        for(auto& record:response.records) {
            if(record.type==41)continue;
            record.ttl=elapsed_seconds>=record.ttl ? 0 : record.ttl-static_cast<std::uint32_t>(elapsed_seconds);
            if(maximum_ttl)record.ttl=std::min(record.ttl,*maximum_ttl);
        }
        return true;
    }
}
