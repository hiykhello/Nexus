export module httpupgrade;
import std;
import http.header;

export namespace httpupgrade {
    inline constexpr std::size_t max_path_bytes=4096,max_host_bytes=512,max_extra_fields=64;
    enum class Status { incomplete,accepted,malformed,too_large,method,path,host,upgrade,body,status,truncated,closed };
    struct Field { std::string name,value; };
    struct Parsed { Status status=Status::incomplete; std::size_t consumed=0; };
    namespace detail {
        inline auto equal_ci(std::string_view a,std::string_view b) noexcept -> bool {
            return a.size()==b.size() && std::ranges::equal(a,b,[](char x,char y) {
                auto lower=[](char c) { return c>='A' && c<='Z' ? char(c+('a'-'A')) : c; };
                return lower(x)==lower(y);
            });
        }
        inline auto hex(char c) noexcept -> int {
            if (c>='0' && c<='9') return c-'0';
            if (c>='a' && c<='f') return c-'a'+10;
            if (c>='A' && c<='F') return c-'A'+10;
            return -1;
        }
        // Host is an HTTP authority, never the dial destination. Keep it
        // opaque and case preserving, but reject separators and injection.
        inline auto valid_host(std::string_view host) noexcept -> bool {
            if (host.empty() || host.size()>max_host_bytes) return false;
            for (unsigned char c:host)
                if (c<33 || c>126 || std::string_view("/?#@,\\\"<>{}").contains(char(c))) return false;
            auto port=std::string_view{};
            if (host.front()=='[') {
                auto bracket=host.find(']');
                if (bracket==host.npos || bracket<3 || host.substr(1,bracket-1).find(':')==host.npos) return false;
                for (char c:host.substr(1,bracket-1)) if (hex(c)<0 && c!=':' && c!='.') return false;
                auto rest=host.substr(bracket+1);
                if (!rest.empty()) { if (rest.front()!=':') return false; port=rest.substr(1); if (port.empty()) return false; }
            } else {
                if (host.contains('[') || host.contains(']')) return false;
                auto colon=host.find(':');
                auto name=host.substr(0,colon);
                if (name.empty()) return false;
                for (char c:name) if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='.' || c=='-' || c=='_')) return false;
                if (colon!=host.npos) { port=host.substr(colon+1); if (port.empty()) return false; }
            }
            if (!port.empty()) {
                unsigned value=0;
                auto [end,error]=std::from_chars(port.data(),port.data()+port.size(),value);
                if (error!=std::errc{} || end!=port.data()+port.size() || !value || value>65535) return false;
            }
            return true;
        }
        inline auto valid_path(std::string_view path) noexcept -> bool {
            return !path.empty() && path.size()<=max_path_bytes && path.front()=='/' &&
                std::ranges::none_of(path,[](unsigned char c) { return c<32 || c==127; });
        }
        inline auto valid_target(std::string_view target) noexcept -> bool {
            if (target.empty() || target.size()>max_path_bytes || target.front()!='/') return false;
            for (std::size_t i=0;i<target.size();++i) {
                auto c=static_cast<unsigned char>(target[i]);
                if (c<33 || c>126 || c=='#') return false;
                if (c=='%') {
                    if (i+2>=target.size() || hex(target[i+1])<0 || hex(target[i+2])<0) return false;
                    auto decoded=hex(target[i+1])*16+hex(target[i+2]);
                    if (decoded<32 || decoded==127) return false;
                    i+=2;
                }
            }
            return true;
        }
        inline auto path_matches(std::string_view target,std::string_view expected) noexcept -> bool {
            target=target.substr(0,target.find('?'));
            std::size_t offset=0;
            for (std::size_t i=0;i<target.size();++i) {
                auto c=static_cast<unsigned char>(target[i]);
                if (c=='%') { c=static_cast<unsigned char>(hex(target[i+1])*16+hex(target[i+2])); i+=2; }
                if (offset>=expected.size() || c!=static_cast<unsigned char>(expected[offset++])) return false;
            }
            return offset==expected.size();
        }
        inline auto reserved(std::string_view name) noexcept -> bool {
            return equal_ci(name,"host") || equal_ci(name,"connection") || equal_ci(name,"upgrade") ||
                equal_ci(name,"content-length") || equal_ci(name,"transfer-encoding") || equal_ci(name,"expect") ||
                equal_ci(name,"trailer") || equal_ci(name,"proxy-connection") ||
                (name.size()>=14 && equal_ci(name.substr(0,14),"sec-websocket-"));
        }
        inline auto valid_extra_fields(std::span<Field const> fields) noexcept -> bool {
            if (fields.size()>max_extra_fields) return false;
            for (auto const& field:fields) {
                if (field.name.empty() || !std::ranges::all_of(field.name,http::header_token) || reserved(field.name) ||
                    !http::valid_header_field_value(field.value) || field.name.size()+field.value.size()+2>http::max_header_line_bytes) return false;
            }
            return true;
        }
        inline auto append_fields(std::string& wire,std::span<Field const> fields) -> bool {
            for (auto const& field:fields) {
                if (wire.size()+field.name.size()+field.value.size()+4>http::max_header_bytes-2) return false;
                wire.append(field.name); wire.append(": "); wire.append(field.value); wire.append("\r\n");
            }
            wire.append("\r\n"); return wire.size()<=http::max_header_bytes;
        }
        inline auto fields(http::HeaderView const& header,bool request,std::string_view host,bool websocket) noexcept -> Status {
            bool host_seen=false,connection=false,upgrade=false,length=false;
            http::HeaderFieldCursor cursor(header.field_lines);
            for (;;) {
                auto next=cursor.next();
                if (next.status==http::HeaderFieldStatus::end) break;
                if (next.status!=http::HeaderFieldStatus::field) return Status::malformed;
                auto [name,value]=next.field;
                if (equal_ci(name,"host")) {
                    if (host_seen || !valid_host(value)) return Status::host;
                    if (request && !host.empty() && value!=host) return Status::host;
                    host_seen=true;
                } else if (equal_ci(name,"connection")) {
                    if (connection || !equal_ci(value,"upgrade")) return Status::upgrade;
                    connection=true;
                } else if (equal_ci(name,"upgrade")) {
                    if (upgrade || !equal_ci(value,"websocket")) return Status::upgrade;
                    upgrade=true;
                } else if (equal_ci(name,"content-length")) {
                    if (length || value!="0") return Status::body;
                    length=true;
                } else if (equal_ci(name,"transfer-encoding") || equal_ci(name,"expect") || equal_ci(name,"trailer")) return Status::body;
                else if (!websocket && !request && name.size()>=14 && equal_ci(name.substr(0,14),"sec-websocket-")) return Status::upgrade;
            }
            if (request && !host_seen) return Status::host;
            return connection && upgrade ? Status::accepted : Status::upgrade;
        }
    }
    // Client target is an origin-form request target, including optional query
    // and percent encoding. Server path is the decoded path; query is ignored.
    // The configured host is matched exactly, as in the fixed sing-box peer.
    class Profile {
        bool client_=false,websocket_=false;
        std::string host_,path_,wire_;
    public:
        static auto client(std::string_view host,std::string_view target="/",std::span<Field const> headers={},bool websocket=false) -> std::expected<Profile,Status> {
            if (!detail::valid_host(host)) return std::unexpected(Status::host);
            if (!detail::valid_target(target)) return std::unexpected(Status::path);
            if (!detail::valid_extra_fields(headers)) return std::unexpected(Status::malformed);
            Profile result; result.client_=true; result.websocket_=websocket; result.host_=host; result.path_=target;
            result.wire_="GET "; result.wire_.append(target); result.wire_.append(" HTTP/1.1\r\nHost: "); result.wire_.append(host);
            result.wire_.append("\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n");
            if (!detail::append_fields(result.wire_,headers)) return std::unexpected(Status::too_large);
            return result;
        }
        static auto server(std::string_view host={},std::string_view path="/",std::span<Field const> headers={},bool websocket=false) -> std::expected<Profile,Status> {
            if (!host.empty() && !detail::valid_host(host)) return std::unexpected(Status::host);
            if (!detail::valid_path(path)) return std::unexpected(Status::path);
            if (!detail::valid_extra_fields(headers)) return std::unexpected(Status::malformed);
            Profile result; result.websocket_=websocket; result.host_=host; result.path_=path;
            result.wire_="HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n";
            if (!detail::append_fields(result.wire_,headers)) return std::unexpected(Status::too_large);
            return result;
        }
        auto is_client() const noexcept -> bool { return client_; }
        auto websocket() const noexcept -> bool {return websocket_;}
        auto host() const noexcept -> std::string_view { return host_; }
        auto path() const noexcept -> std::string_view { return path_; }
        auto wire() const noexcept -> std::string_view { return wire_; }
    };
    inline auto parse_request(std::string_view input,Profile const& profile,bool websocket=false) noexcept -> Parsed {
        if (profile.is_client()) return {Status::malformed};
        auto header=http::inspect_header(input);
        if (header.status==http::HeaderStatus::incomplete) return {};
        if (header.status==http::HeaderStatus::too_large) return {Status::too_large};
        if (header.status!=http::HeaderStatus::complete) return {Status::malformed};
        auto first=header.first.find(' '),second=first==header.first.npos ? header.first.npos : header.first.find(' ',first+1);
        if (first==header.first.npos || second==header.first.npos || !first || second==first+1 ||
            header.first.find(' ',second+1)!=header.first.npos || header.first.substr(second+1)!="HTTP/1.1") return {Status::malformed};
        if (header.first.substr(0,first)!="GET") return {Status::method};
        auto target=header.first.substr(first+1,second-first-1);
        if (!detail::valid_target(target)) return {Status::malformed};
        if (!detail::path_matches(target,profile.path())) return {Status::path};
        auto status=detail::fields(header,true,profile.host(),websocket);
        return {status,status==Status::accepted ? header.consumed : 0};
    }
    inline auto parse_response(std::string_view input,bool websocket=false) noexcept -> Parsed {
        auto header=http::inspect_header(input);
        if (header.status==http::HeaderStatus::incomplete) return {};
        if (header.status==http::HeaderStatus::too_large) return {Status::too_large};
        if (header.status!=http::HeaderStatus::complete) return {Status::malformed};
        auto line=header.first;
        if (!line.starts_with("HTTP/1.1 ") || line.size()<12 || !std::ranges::all_of(line.substr(9,3),[](char c) { return c>='0' && c<='9'; }) ||
            (line.size()>12 && line[12]!=' ') || !http::valid_header_field_value(line)) return {Status::malformed};
        if (line.substr(9,3)!="101") return {Status::status};
        auto status=detail::fields(header,false,{},websocket);
        return {status,status==Status::accepted ? header.consumed : 0};
    }
    struct FeedResult { Status status=Status::incomplete; std::size_t consumed=0; };
    // Retain only the header, stop exactly after CRLFCRLF and leave all tunnel
    // bytes with the caller. Work and storage are bounded by the shared H1
    // limits; arbitrarily fragmented input does not trigger repeated parsing.
    class HeaderDecoder {
        Profile const& profile_;
        std::array<char,http::max_header_bytes> input_{};
        std::size_t size_=0;
        Status status_=Status::incomplete;
    public:
        explicit HeaderDecoder(Profile const& profile) noexcept : profile_(profile) {}
        HeaderDecoder(HeaderDecoder const&)=delete;
        auto operator=(HeaderDecoder const&) -> HeaderDecoder& = delete;
        auto feed(std::span<std::uint8_t const> input) noexcept -> FeedResult {
            if (status_!=Status::incomplete) return {status_,0};
            std::size_t consumed=0;
            while (consumed<input.size()) {
                input_[size_++]=static_cast<char>(input[consumed++]);
                if (size_>=4 && std::string_view(input_.data()+size_-4,4)=="\r\n\r\n") {
                    auto header=std::string_view(input_.data(),size_);
                    status_=profile_.is_client() ? parse_response(header).status : parse_request(header,profile_).status;
                    return {status_,consumed};
                }
                if (size_==input_.size()) { status_=Status::too_large; return {status_,consumed}; }
            }
            return {status_,consumed};
        }
        auto status() const noexcept -> Status { return status_; }
        auto finish() noexcept -> Status { if (status_==Status::incomplete) status_=Status::truncated; return status_; }
        auto close() noexcept -> void { status_=Status::closed; }
    };
}
