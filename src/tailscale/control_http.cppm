export module tailscale.control_http;
import std;
import http.header;

export namespace tailscale::control_http {
    using Clock=std::chrono::steady_clock;
    inline constexpr std::size_t initiation_bytes=101,max_authority_bytes=512;
    inline constexpr std::size_t early_protocol_limit=10<<20,max_early_payload=64<<10,max_map_frame=4<<20;
    inline constexpr std::string_view upgrade_protocol="tailscale-control-protocol";
    enum class Error { state,closed,timeout,capacity,overlap,authority,initiation,header,status,upgrade,body,size,truncated };
    struct Feed {std::size_t consumed=0;bool ready=false;std::optional<Error> error;};
    namespace detail {
        inline auto equal_ci(std::string_view a,std::string_view b) noexcept -> bool {
            return a.size()==b.size() && std::ranges::equal(a,b,[](char x,char y) {
                auto lower=[](char c) {return c>='A' && c<='Z' ? char(c+'a'-'A') : c;};return lower(x)==lower(y);
            });
        }
        inline auto overlaps(std::span<std::uint8_t> output,void const* data,std::size_t size) noexcept -> bool {
            if (output.empty() || !size) return false;
            auto first=reinterpret_cast<std::uintptr_t>(output.data()),second=reinterpret_cast<std::uintptr_t>(data);
            return first<=second ? second-first<output.size() : first-second<size;
        }
        inline auto valid_authority(std::string_view value) noexcept -> bool {
            if (value.empty() || value.size()>max_authority_bytes) return false;
            // The owner supplies a canonical URL authority, distinct from its
            // resolved dial address. This codec rejects injection/separators.
            for (unsigned char c:value) if (c<33 || c>126 || std::string_view("/?#@,\\\"<>{}").contains(char(c))) return false;
            return true;
        }
        inline auto connection_upgrade(std::string_view value) noexcept -> bool {
            bool upgrade=false;
            for (;;) {
                auto comma=value.find(',');auto token=http::trim_header_ows(value.substr(0,comma));
                if (token.empty() || !std::ranges::all_of(token,http::header_token) || equal_ci(token,"close")) return false;
                if (equal_ci(token,"upgrade")) upgrade=true;
                if (comma==value.npos) return upgrade;value.remove_prefix(comma+1);
            }
        }
        inline auto response(std::string_view input) noexcept -> std::expected<void,Error> {
            auto header=http::inspect_header(input);if (header.status!=http::HeaderStatus::complete) return std::unexpected(Error::header);
            auto line=header.first;
            if (!line.starts_with("HTTP/1.1 ") || line.size()<12 || (line.size()>12 && line[12]!=' ') ||
                !std::ranges::all_of(line.substr(9,3),[](char c) {return c>='0' && c<='9';}) || !http::valid_header_field_value(line))
                return std::unexpected(Error::header);
            if (line.substr(9,3)!="101") return std::unexpected(Error::status);
            bool connection=false,upgrade=false,length=false;http::HeaderFieldCursor cursor(header.field_lines);
            for (;;) {
                auto next=cursor.next();if (next.status==http::HeaderFieldStatus::end) break;
                if (next.status!=http::HeaderFieldStatus::field) return std::unexpected(Error::header);
                auto [name,value]=next.field;
                if (equal_ci(name,"connection")) {
                    if (connection || !connection_upgrade(value)) return std::unexpected(Error::upgrade);connection=true;
                } else if (equal_ci(name,"upgrade")) {
                    // Match official controlhttp's exact response value.
                    if (upgrade || value!=upgrade_protocol) return std::unexpected(Error::upgrade);upgrade=true;
                } else if (equal_ci(name,"content-length")) {
                    if (length || value!="0") return std::unexpected(Error::body);length=true;
                } else if (equal_ci(name,"transfer-encoding") || equal_ci(name,"expect") || equal_ci(name,"trailer")) return std::unexpected(Error::body);
            }
            if (!connection || !upgrade) return std::unexpected(Error::upgrade);return {};
        }
        inline auto base64(std::span<std::uint8_t> output,std::span<std::uint8_t const,initiation_bytes> input) noexcept -> void {
            constexpr std::string_view alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::size_t source=0,destination=0;
            while (source<input.size()) {
                auto remain=input.size()-source;auto a=input[source++];unsigned b=remain>1 ? input[source++] : 0,c=remain>2 ? input[source++] : 0;
                output[destination++]=alphabet[a>>2];output[destination++]=alphabet[((a&3)<<4)|(b>>4)];
                output[destination++]=remain>1 ? alphabet[((b&15)<<2)|(c>>6)] : '=';output[destination++]=remain>2 ? alphabet[c&63] : '=';
            }
        }
    }
    // The 101-byte Noise initiation is sent only in this header, with standard
    // padded base64. After Upgrade, continue the same handshake; never resend
    // it as a body or raw stream prefix. All validation precedes output writes.
    inline auto encode_upgrade_request(std::span<std::uint8_t> output,std::string_view authority,
        std::span<std::uint8_t const,initiation_bytes> initiation) noexcept -> std::expected<std::size_t,Error> {
        constexpr std::string_view first="POST /ts2021 HTTP/1.1\r\nHost: ";
        constexpr std::string_view middle="\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nX-Tailscale-Handshake: ";
        constexpr std::string_view last="\r\nContent-Length: 0\r\n\r\n";
        constexpr std::size_t encoded=4*((initiation_bytes+2)/3);
        if (!detail::valid_authority(authority)) return std::unexpected(Error::authority);
        if (initiation[2]!=1 || initiation[3]!=0 || initiation[4]!=96) return std::unexpected(Error::initiation);
        auto size=first.size()+authority.size()+middle.size()+encoded+last.size();
        if (output.size()<size) return std::unexpected(Error::capacity);
        auto destination=output.first(size);
        if (detail::overlaps(destination,authority.data(),authority.size()) || detail::overlaps(destination,initiation.data(),initiation.size())) return std::unexpected(Error::overlap);
        std::size_t used=0;
        auto append=[&](std::string_view text) {std::ranges::copy(text,destination.begin()+used);used+=text.size();};
        append(first);append(authority);append(middle);detail::base64(destination.subspan(used,encoded),initiation);used+=encoded;append(last);return used;
    }
    // No socket/task ownership. The host passes the same absolute budget as
    // dialing/TLS/Noise, then forwards every unconsumed byte to Noise first.
    // HTTP 101 completion alone never publishes an authenticated identity.
    class UpgradeResponseDecoder {
        std::array<char,http::max_header_bytes> bytes_{};
        std::size_t size_=0;
        Clock::time_point started_,deadline_,last_;
        bool ready_=false,closed_=false;
        std::optional<Error> failed_;
    public:
        UpgradeResponseDecoder(Clock::time_point started,Clock::time_point deadline) noexcept : started_(started),deadline_(deadline),last_(started) {}
        UpgradeResponseDecoder(UpgradeResponseDecoder const&)=delete;
        auto operator=(UpgradeResponseDecoder const&) -> UpgradeResponseDecoder& = delete;
        auto feed(std::span<std::uint8_t const> input,Clock::time_point now) noexcept -> Feed {
            if (closed_) return {0,false,Error::closed};if (failed_) return {0,false,*failed_};if (ready_) return {0,true,{}};
            if (deadline_<=started_ || now<last_ || now>=deadline_) {failed_=Error::timeout;return {0,false,*failed_};}last_=now;
            std::size_t consumed=0;
            while (consumed<input.size()) {
                bytes_[size_++]=static_cast<char>(input[consumed++]);
                if (size_>=4 && std::string_view(bytes_.data()+size_-4,4)=="\r\n\r\n") {
                    auto parsed=detail::response({bytes_.data(),size_});if (!parsed) failed_=parsed.error();else ready_=true;
                    return {consumed,ready_,failed_};
                }
                if (size_==bytes_.size()) {failed_=Error::size;return {consumed,false,failed_};}
            }
            return {consumed,false,{}};
        }
        auto eof() noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::closed);closed_=true;
            if (failed_) return std::unexpected(*failed_);if (!ready_) return std::unexpected(Error::truncated);return {};
        }
        auto close() noexcept -> void {closed_=true;}
    };
    enum class PrefaceKind { pending,http2,early,failed,closed };
    // Feed authenticated Noise plaintext only. If the first nine bytes are
    // ordinary H2, prefix() returns them unchanged before further H2 input.
    // Early JSON is an opaque view: its typed parser must validate it before
    // use. Views are used before eof/close; storage remains caller-owned.
    class EarlyPrefaceDecoder {
        std::span<std::uint8_t> storage_;
        std::array<std::uint8_t,9> header_{};
        std::size_t header_used_=0,size_=0,used_=0;
        Clock::time_point started_,deadline_,last_;
        PrefaceKind kind_=PrefaceKind::pending;
        std::optional<Error> failed_;
        auto fail(Error error) noexcept -> void {kind_=PrefaceKind::failed;failed_=error;}
    public:
        EarlyPrefaceDecoder(std::span<std::uint8_t> storage,Clock::time_point started,Clock::time_point deadline) noexcept
            : storage_(storage),started_(started),deadline_(deadline),last_(started) {}
        EarlyPrefaceDecoder(EarlyPrefaceDecoder const&)=delete;
        auto operator=(EarlyPrefaceDecoder const&) -> EarlyPrefaceDecoder& = delete;
        auto kind() const noexcept -> PrefaceKind {return kind_;}
        auto prefix() const noexcept -> std::span<std::uint8_t const> {return kind_==PrefaceKind::http2 ? std::span(header_) : std::span<std::uint8_t const>{};}
        auto payload() const noexcept -> std::optional<std::span<std::uint8_t const>> {
            return kind_==PrefaceKind::early ? std::optional(std::span<std::uint8_t const>(storage_.first(size_))) : std::nullopt;
        }
        auto feed(std::span<std::uint8_t const> input,Clock::time_point now) noexcept -> Feed {
            if (kind_==PrefaceKind::closed) return {0,false,Error::closed};if (failed_) return {0,false,*failed_};
            if (kind_!=PrefaceKind::pending) return {0,true,{}};
            if (deadline_<=started_ || now<last_ || now>=deadline_) {fail(Error::timeout);return {0,false,failed_};}last_=now;
            if (detail::overlaps(storage_,input.data(),input.size())) {fail(Error::overlap);return {0,false,failed_};}
            std::size_t consumed=0;
            if (header_used_<header_.size()) {
                auto size=std::min(input.size(),header_.size()-header_used_);std::copy_n(input.begin(),size,header_.begin()+header_used_);
                header_used_+=size;consumed+=size;input=input.subspan(size);if (header_used_<header_.size()) return {consumed,false,{}};
                constexpr std::array<std::uint8_t,5> magic{0xff,0xff,0xff,'T','S'};
                if (!std::ranges::equal(std::span(header_).first(5),magic)) {kind_=PrefaceKind::http2;return {consumed,true,{}};}
                for (auto byte:std::span(header_).subspan(5)) size_=(size_<<8)|byte;
                if (size_>max_early_payload) {fail(Error::size);return {consumed,false,failed_};}
                if (size_>storage_.size()) {fail(Error::capacity);return {consumed,false,failed_};}
            }
            auto size=std::min(input.size(),size_-used_);std::copy_n(input.begin(),size,storage_.begin()+used_);used_+=size;consumed+=size;
            if (used_==size_) kind_=PrefaceKind::early;return {consumed,kind_==PrefaceKind::early,{}};
        }
        auto eof() noexcept -> std::expected<void,Error> {
            if (kind_==PrefaceKind::closed) return std::unexpected(Error::closed);
            auto ready=kind_==PrefaceKind::http2 || kind_==PrefaceKind::early;kind_=PrefaceKind::closed;
            if (failed_) return std::unexpected(*failed_);if (!ready) return std::unexpected(Error::truncated);return {};
        }
        auto close() noexcept -> void {kind_=PrefaceKind::closed;}
    };
    // Map HTTP response DATA consists of nonempty LE32 length-prefixed
    // messages. Compression is negotiated separately. This decoder never
    // merges messages, allocates payload storage, or installs peer policy.
    class MapFrameDecoder {
        std::span<std::uint8_t> storage_;
        std::array<std::uint8_t,4> header_{};
        std::size_t header_used_=0,size_=0,used_=0;
        bool ready_=false,closed_=false;
        std::optional<Error> failed_;
    public:
        explicit MapFrameDecoder(std::span<std::uint8_t> storage) noexcept : storage_(storage) {}
        MapFrameDecoder(MapFrameDecoder const&)=delete;
        auto operator=(MapFrameDecoder const&) -> MapFrameDecoder& = delete;
        auto payload() const noexcept -> std::optional<std::span<std::uint8_t const>> {
            return ready_ && !closed_ ? std::optional(std::span<std::uint8_t const>(storage_.first(size_))) : std::nullopt;
        }
        auto feed(std::span<std::uint8_t const> input) noexcept -> Feed {
            if (closed_) return {0,false,Error::closed};if (failed_) return {0,false,*failed_};if (ready_) return {0,true,{}};
            if (detail::overlaps(storage_,input.data(),input.size())) {failed_=Error::overlap;return {0,false,failed_};}
            std::size_t consumed=0;
            if (header_used_<header_.size()) {
                auto size=std::min(input.size(),header_.size()-header_used_);std::copy_n(input.begin(),size,header_.begin()+header_used_);
                header_used_+=size;consumed+=size;input=input.subspan(size);if (header_used_<header_.size()) return {consumed,false,{}};
                for (unsigned i=0;i<4;++i) size_|=std::size_t(header_[i])<<(8*i);
                if (!size_ || size_>max_map_frame) {failed_=Error::size;return {consumed,false,failed_};}
                if (size_>storage_.size()) {failed_=Error::capacity;return {consumed,false,failed_};}
            }
            auto size=std::min(input.size(),size_-used_);std::copy_n(input.begin(),size,storage_.begin()+used_);used_+=size;consumed+=size;
            ready_=used_==size_;return {consumed,ready_,{}};
        }
        auto consume() noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::closed);if (failed_) return std::unexpected(*failed_);if (!ready_) return std::unexpected(Error::state);
            header_used_=size_=used_=0;ready_=false;return {};
        }
        auto eof() noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::closed);closed_=true;
            if (failed_) return std::unexpected(*failed_);if (header_used_) return std::unexpected(Error::truncated);return {};
        }
        auto close() noexcept -> void {closed_=true;}
    };
}
