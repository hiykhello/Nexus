module nexus.dns.fakeip_response;
import std;
import nexus.dns.fakeip;
namespace nexus::dns {
    namespace {
    struct Query { std::string domain; std::size_t question_end; std::optional<std::uint16_t> edns_size; };
    auto parse_query(std::span<std::uint8_t const> query) -> std::expected<Query,FakeIpDnsError> {
        if (query.size()<12 || query.size()>512) return std::unexpected(FakeIpDnsError::malformed);
        auto get16=[&](std::size_t i) { return static_cast<std::uint16_t>((unsigned{query[i]}<<8)|query[i+1]); };
        auto flags=get16(2);
        if ((flags & ~0x0100u)!=0 || get16(4)!=1 || get16(6)!=0 || get16(8)!=0 || get16(10)>1)
            return std::unexpected(FakeIpDnsError::unsupported);
        std::size_t pos=12, wire_name=1;
        std::string domain;
        while (true) {
            if (pos>=query.size()) return std::unexpected(FakeIpDnsError::malformed);
            auto length=query[pos++];
            if ((length&0xc0)!=0) return std::unexpected(FakeIpDnsError::unsupported);
            if (!length) break;
            if (length>63 || length>query.size()-pos || (wire_name+=length+1)>255)
                return std::unexpected(FakeIpDnsError::malformed);
            if (!domain.empty()) domain.push_back('.');
            for (std::size_t i=0;i<length;++i) {
                auto c=query[pos++];
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-'))
                    return std::unexpected(FakeIpDnsError::invalid_name);
                domain.push_back(static_cast<char>(c));
            }
        }
        if (query.size()-pos<4) return std::unexpected(FakeIpDnsError::malformed);
        if (get16(pos)!=1 || get16(pos+2)!=1) return std::unexpected(FakeIpDnsError::unsupported);
        if (domain.empty()) return std::unexpected(FakeIpDnsError::invalid_name);
        pos+=4;
        if (get16(10)==0) {
            if (query.size()!=pos) return std::unexpected(FakeIpDnsError::malformed);
            return Query{std::move(domain),pos,{}};
        }
        if (query.size()-pos!=11) return std::unexpected(FakeIpDnsError::malformed);
        if (query[pos]!=0 || get16(pos+1)!=41 || get16(pos+3)<512 ||
            query[pos+5]!=0 || query[pos+6]!=0 || get16(pos+7)!=0 || get16(pos+9)!=0)
            return std::unexpected(FakeIpDnsError::unsupported);
        return Query{std::move(domain),pos,std::min<std::uint16_t>(get16(pos+3),1232)};
    }
    }
    auto validate_fakeip_query(std::span<std::uint8_t const> query) -> std::expected<void,FakeIpDnsError> {
        auto result=parse_query(query);
        if (!result) return std::unexpected(result.error());
        return {};
    }
    auto fakeip_response(FakeIpPool& pool,std::span<std::uint8_t const> query,std::uint64_t view,
        std::chrono::steady_clock::time_point now) -> std::expected<std::unique_ptr<FakeIpResponse>,FakeIpDnsError> {
        auto parsed=parse_query(query);
        if (!parsed) return std::unexpected(parsed.error());
        auto ttl=pool.ttl().count();
        if (ttl>std::numeric_limits<std::uint32_t>::max()) return std::unexpected(FakeIpDnsError::exhausted);
        // Allocate the entire response before mutating the pool.
        std::vector<std::uint8_t> answer(query.begin(),query.begin()+parsed->question_end);
        answer.reserve(query.size()+16);
        answer[2]=static_cast<std::uint8_t>(0x80 | (query[2] & 1));
        answer[3]=0x80; answer[6]=0; answer[7]=1;
        answer.insert(answer.end(),{0xc0,0x0c,0,1,0,1,
            static_cast<std::uint8_t>(ttl>>24),static_cast<std::uint8_t>(ttl>>16),
            static_cast<std::uint8_t>(ttl>>8),static_cast<std::uint8_t>(ttl),0,4,0,0,0,0});
        auto address_offset=answer.size()-4;
        if (parsed->edns_size) {
            auto size=*parsed->edns_size;
            answer.insert(answer.end(),{0,0,41,static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size),0,0,0,0,0,0});
        }
        auto lease=pool.publish(parsed->domain,view,now);
        if (!lease) {
            switch (lease.error()) {
                case FakeIpError::invalid_name: return std::unexpected(FakeIpDnsError::invalid_name);
                case FakeIpError::full: return std::unexpected(FakeIpDnsError::full);
                case FakeIpError::time_reversed: case FakeIpError::time_overflow: return std::unexpected(FakeIpDnsError::clock);
                default: return std::unexpected(FakeIpDnsError::exhausted);
            }
        }
        for (std::size_t i=0;i<4;++i) answer[address_offset+i]=static_cast<std::uint8_t>(lease->address>>(24-8*i));
        auto pinned=pool.pin(*lease,now);
        if (!pinned) return std::unexpected(FakeIpDnsError::exhausted);
        // If allocation fails, the retained pin prevents unsafe reuse.
        return std::unique_ptr<FakeIpResponse>(new FakeIpResponse(pool,*lease,std::move(answer)));
    }
}
