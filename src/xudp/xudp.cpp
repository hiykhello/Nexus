module xudp;
import std;
namespace xudp {
    namespace {
        auto valid(Address const& a) noexcept -> bool {
            if (!a.port) return false;
            switch (a.family) { case Family::ipv4: return a.length==4; case Family::ipv6: return a.length==16; case Family::domain: return a.length!=0; }
            return false;
        }
        auto append_address(std::vector<std::uint8_t>& out,Address const& a) -> void {
            out.push_back(a.port>>8); out.push_back(a.port);
            out.push_back(a.family==Family::ipv4 ? 1 : a.family==Family::domain ? 2 : 3);
            if (a.family==Family::domain) out.push_back(a.length);
            out.insert(out.end(),a.bytes.begin(),a.bytes.begin()+a.length);
        }
        auto read_address(std::span<std::uint8_t const> bytes,std::size_t& pos) noexcept -> std::optional<Address> {
            if (bytes.size()-pos<3) return {};
            Address out; out.port=(std::uint16_t(bytes[pos])<<8)|bytes[pos+1]; auto type=bytes[pos+2]; pos+=3;
            if (type==1) { out.family=Family::ipv4; out.length=4; }
            else if (type==3) { out.family=Family::ipv6; out.length=16; }
            else if (type==2) { if (pos==bytes.size()) return {}; out.family=Family::domain; out.length=bytes[pos++]; }
            else return {};
            if (!valid(out) || bytes.size()-pos<out.length) return {};
            std::copy_n(bytes.begin()+pos,out.length,out.bytes.begin()); pos+=out.length; return out;
        }
    }
    auto parse(std::span<std::uint8_t const> input,std::size_t max_payload) noexcept -> Result {
        Result out;
        if (input.size()<2) return out;
        auto meta=(std::size_t(input[0])<<8)|input[1];
        if (meta<4 || meta>512) { out.status=Status::invalid; return out; }
        if (input.size()<2+meta) return out;
        auto bytes=input.subspan(2,meta); auto kind=bytes[2], options=bytes[3];
        if (kind<1 || kind>4 || (options & ~3)) { out.status=Status::invalid; return out; }
        out.frame.session=(std::uint16_t(bytes[0])<<8)|bytes[1]; out.frame.kind=static_cast<Kind>(kind);
        out.frame.has_data=options&1; out.frame.error=options&2;
        std::size_t pos=4;
        if (out.frame.kind==Kind::open || (out.frame.kind==Kind::data && pos<bytes.size() && bytes[pos]==2)) {
            if (pos==bytes.size() || bytes[pos++]!=2) { out.status=Status::invalid; return out; }
            auto address=read_address(bytes,pos); if (!address) { out.status=Status::invalid; return out; }
            out.frame.address=*address;
            if (out.frame.kind==Kind::open && out.frame.has_data && bytes.size()-pos>=8) {
                std::array<std::uint8_t,8> id{}; std::copy_n(bytes.begin()+pos,8,id.begin()); out.frame.global_id=id;
            }
        }
        auto offset=2+meta;
        if (out.frame.has_data) {
            if (input.size()-offset<2) return out;
            auto length=(std::size_t(input[offset])<<8)|input[offset+1];
            if (length>max_payload) { out.status=Status::too_large; return out; }
            offset+=2; if (input.size()-offset<length) return out;
            out.frame.payload=input.subspan(offset,length); offset+=length;
        }
        out.status=Status::ready; out.consumed=offset; return out;
    }
    auto encode(Frame const& frame) -> std::expected<std::vector<std::uint8_t>,Status> {
        auto kind=static_cast<unsigned>(frame.kind);
        if (kind<1 || kind>4 || frame.payload.size()>65535 || (!frame.has_data && !frame.payload.empty()) ||
            (frame.kind==Kind::open && !frame.address) || (frame.address && (!valid(*frame.address) || (frame.kind!=Kind::open && frame.kind!=Kind::data))) ||
            (frame.global_id && (frame.kind!=Kind::open || !frame.has_data))) return std::unexpected(Status::invalid);
        std::vector<std::uint8_t> result{0,0,static_cast<std::uint8_t>(frame.session>>8),static_cast<std::uint8_t>(frame.session),static_cast<std::uint8_t>(kind),static_cast<std::uint8_t>((frame.has_data?1:0)|(frame.error?2:0))};
        if (frame.address) { result.push_back(2); append_address(result,*frame.address); }
        if (frame.global_id) result.insert(result.end(),frame.global_id->begin(),frame.global_id->end());
        auto length=result.size()-2; result[0]=length>>8; result[1]=length;
        if (frame.has_data) { result.push_back(frame.payload.size()>>8); result.push_back(frame.payload.size()); result.insert(result.end(),frame.payload.begin(),frame.payload.end()); }
        return result;
    }
    auto Decoder::feed(std::span<std::uint8_t const> input) -> Result {
        Result result; result.status=status_;
        if (status_!=Status::incomplete) return result;
        while (true) {
            std::size_t target=2;
            if (bytes_.size()>=2) {
                auto meta=(std::size_t(bytes_[0])<<8)|bytes_[1];
                if (meta<4 || meta>512) { status_=Status::invalid; break; }
                target=2+meta;
                if (bytes_.size()>=target) {
                    auto parsed=parse(bytes_,max_payload_);
                    if (parsed.status==Status::invalid || parsed.status==Status::too_large) { status_=parsed.status; break; }
                    if (parsed.status==Status::ready) { status_=Status::ready; frame_size_=parsed.consumed; break; }
                    if (bytes_.size()<target+2) target+=2;
                    else { auto length=(std::size_t(bytes_[target])<<8)|bytes_[target+1]; if (length>max_payload_) { status_=Status::too_large; break; } target+=2+length; }
                }
            }
            auto count=std::min(target-bytes_.size(),input.size()-result.consumed);
            bytes_.insert(bytes_.end(),input.begin()+result.consumed,input.begin()+result.consumed+count); result.consumed+=count;
            if (!count) break;
        }
        result.status=status_; if (status_==Status::ready) result.frame=parse(bytes_,max_payload_).frame;
        return result;
    }
    auto Decoder::frame() const noexcept -> std::optional<Frame> { if (status_!=Status::ready) return {}; return parse(bytes_,max_payload_).frame; }
    auto Decoder::consume() noexcept -> bool { if (status_!=Status::ready || frame_size_!=bytes_.size()) return false; bytes_.clear(); frame_size_=0; status_=Status::incomplete; return true; }
}
