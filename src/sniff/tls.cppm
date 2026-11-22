export module sniff.tls;
import std;

export namespace sniff {
    enum class TlsStatus { need_more, matched, not_tls, malformed, too_large, truncated };
    struct TlsStep {
        TlsStatus status;
        std::size_t consumed=0;
        // Points into the scratch buffer supplied to feed().
        std::optional<std::string_view> server_name;
        // An ECH extension may be real or GREASE. The visible name, if any,
        // is from the outer ClientHello and need not be the inner name.
        bool ech_offered=false;
    };

    // Reads one plaintext ClientHello, including handshakes split across TLS
    // records. The caller retains the original wire for replay and supplies a
    // stable, bounded scratch buffer, disjoint from input, for the reassembled
    // handshake body. Any returned name borrows that buffer.
    class TlsSniffer {
        std::array<std::uint8_t,5> record_{};
        std::array<std::uint8_t,4> handshake_{};
        std::size_t record_header_=0, record_remaining_=0, handshake_header_=0;
        std::size_t body_size_=0, body_written_=0;
        std::uint8_t* scratch_data_=nullptr;
        std::size_t scratch_size_=0;
        bool scratch_bound_=false, body_known_=false, saw_record_=false, ech_offered_=false;
        TlsStatus state_=TlsStatus::need_more;
        std::optional<std::string_view> server_name_;

        static auto valid_name(std::string_view name) noexcept -> bool;
        auto parse() noexcept -> TlsStatus;
    public:
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input,std::span<std::uint8_t> scratch) noexcept -> TlsStep;
        [[nodiscard]] auto finish() noexcept -> TlsStatus;
    };
}

module :private;

namespace sniff {
    auto TlsSniffer::valid_name(std::string_view name) noexcept -> bool {
        if (name.empty() || name.size()>253) return false;
        std::size_t start=0;
        bool non_numeric=false;
        for (std::size_t i=0;i<=name.size();++i) {
            if (i==name.size() || name[i]=='.') {
                if (i==start || i-start>63 || name[start]=='-' || name[i-1]=='-') return false;
                start=i+1;
            } else {
                char c=name[i];
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return false;
                non_numeric|=!(c>='0' && c<='9');
            }
        }
        return non_numeric;
    }
    auto TlsSniffer::parse() noexcept -> TlsStatus {
        auto body=std::span(scratch_data_,body_size_);
        std::size_t pos=0;
        auto take=[&](std::size_t n) -> std::span<std::uint8_t const> {
            if (n>body.size()-pos) return {};
            auto out=body.subspan(pos,n); pos+=n; return out;
        };
        auto u8=[&](std::size_t& value) -> bool { auto b=take(1); if (b.empty()) return false; value=b[0]; return true; };
        auto u16=[&](std::size_t& value) -> bool { auto b=take(2); if (b.empty()) return false; value=(std::size_t(b[0])<<8)|b[1]; return true; };
        auto version=take(2);
        if (version.size()!=2 || version[0]!=3 || version[1]>3 || take(32).size()!=32) return TlsStatus::malformed;
        std::size_t n=0;
        if (!u8(n) || n>32 || take(n).size()!=n) return TlsStatus::malformed;
        if (!u16(n) || n<2 || n%2 || take(n).size()!=n) return TlsStatus::malformed;
        if (!u8(n) || !n || take(n).size()!=n) return TlsStatus::malformed;
        // Older ClientHello messages may omit extensions altogether.
        if (pos==body.size()) return TlsStatus::matched;
        if (!u16(n) || n!=body.size()-pos) return TlsStatus::malformed;
        std::bitset<65536> seen;
        while (pos<body.size()) {
            std::size_t type=0,len=0;
            if (!u16(type) || !u16(len) || len>body.size()-pos || seen.test(type)) return TlsStatus::malformed;
            seen.set(type);
            auto extension=take(len);
            if (type==0xfe0d) ech_offered_=true;
            if (type!=0) continue;
            if (extension.size()<2) return TlsStatus::malformed;
            auto list_size=(std::size_t(extension[0])<<8)|extension[1];
            if (list_size!=extension.size()-2 || !list_size) return TlsStatus::malformed;
            std::size_t off=2;
            bool host_seen=false;
            while (off<extension.size()) {
                if (extension.size()-off<3) return TlsStatus::malformed;
                auto name_type=extension[off++];
                auto size=(std::size_t(extension[off])<<8)|extension[off+1]; off+=2;
                if (!size || size>extension.size()-off) return TlsStatus::malformed;
                if (name_type==0) {
                    if (host_seen) return TlsStatus::malformed;
                    host_seen=true;
                    std::string_view name(reinterpret_cast<char const*>(extension.data()+off),size);
                    if (!valid_name(name)) return TlsStatus::malformed;
                    server_name_=name;
                }
                off+=size;
            }
        }
        return TlsStatus::matched;
    }
    auto TlsSniffer::feed(std::span<std::uint8_t const> input,std::span<std::uint8_t> scratch) noexcept -> TlsStep {
        if (state_!=TlsStatus::need_more) return {state_,0,server_name_,ech_offered_};
        if (!scratch_bound_) { scratch_data_=scratch.data(); scratch_size_=scratch.size(); scratch_bound_=true; }
        else if (scratch.data()!=scratch_data_ || scratch.size()!=scratch_size_) {
            state_=TlsStatus::malformed; return {state_,0,{}};
        }
        std::size_t pos=0;
        while (pos<input.size()) {
            if (!record_remaining_) {
                while (record_header_<record_.size() && pos<input.size()) record_[record_header_++]=input[pos++];
                if (record_header_<record_.size()) break;
                auto length=(std::size_t(record_[3])<<8)|record_[4];
                if (record_[0]!=22) { state_=saw_record_ ? TlsStatus::malformed : TlsStatus::not_tls; break; }
                if (record_[1]!=3 || record_[2]>3 || !length || length>16384) { state_=TlsStatus::malformed; break; }
                saw_record_=true; record_remaining_=length; record_header_=0;
            }
            while (handshake_header_<handshake_.size() && record_remaining_ && pos<input.size()) {
                handshake_[handshake_header_++]=input[pos++]; --record_remaining_;
            }
            if (handshake_header_<handshake_.size()) continue;
            if (!body_known_) {
                if (handshake_[0]!=1) { state_=TlsStatus::not_tls; break; }
                body_size_=(std::size_t(handshake_[1])<<16)|(std::size_t(handshake_[2])<<8)|handshake_[3];
                if (body_size_>scratch_size_) { state_=TlsStatus::too_large; break; }
                if (!body_size_) { state_=TlsStatus::malformed; break; }
                body_known_=true;
            }
            auto count=std::min({record_remaining_,input.size()-pos,body_size_-body_written_});
            std::copy_n(input.begin()+pos,count,scratch_data_+body_written_);
            pos+=count; body_written_+=count; record_remaining_-=count;
            if (body_written_==body_size_) {
                state_=parse();
                if (state_!=TlsStatus::matched) {server_name_.reset();ech_offered_=false;}
                break;
            }
        }
        return {state_,pos,server_name_,ech_offered_};
    }
    auto TlsSniffer::finish() noexcept -> TlsStatus {
        if (state_==TlsStatus::need_more) state_=TlsStatus::truncated;
        return state_;
    }
}
