export module masque.connect_ip;
import std;
import platform.ip_address;
import http.header;
import masque.ip_control;

export namespace masque {
    enum class ConnectIpError { malformed,not_connect_ip,failed_response,invalid_path,invalid_target,invalid_protocol };
    struct ConnectIpRequest {std::string_view scheme,authority,path;};
    // Borrowed header views must be copied before asynchronous policy or DNS.
    inline auto parse_connect_ip_request(std::span<http::HeaderField const> fields) noexcept -> std::expected<ConnectIpRequest,ConnectIpError> {
        std::string_view method,protocol,scheme,authority,path;
        bool m=false,p=false,s=false,a=false,t=false;
        for(auto const& field:fields) {
            auto set=[&](bool& seen,std::string_view& value) {if(seen)return false;seen=true;value=field.value;return true;};
            if(field.name==":method") {if(!set(m,method))return std::unexpected(ConnectIpError::malformed);}
            else if(field.name==":protocol") {if(!set(p,protocol))return std::unexpected(ConnectIpError::malformed);}
            else if(field.name==":scheme") {if(!set(s,scheme))return std::unexpected(ConnectIpError::malformed);}
            else if(field.name==":authority") {if(!set(a,authority))return std::unexpected(ConnectIpError::malformed);}
            else if(field.name==":path") {if(!set(t,path))return std::unexpected(ConnectIpError::malformed);}
            else if(field.name=="content-length" || field.name=="content-type" || field.name=="transfer-encoding" ||
                    (!field.name.empty() && field.name.front()==':'))return std::unexpected(ConnectIpError::malformed);
        }
        if(!m || !p || !s || !a || !t || scheme.empty() || authority.empty() || path.empty() || path.front()!='/')return std::unexpected(ConnectIpError::malformed);
        if(method!="CONNECT" || protocol!="connect-ip")return std::unexpected(ConnectIpError::not_connect_ip);
        return ConnectIpRequest{scheme,authority,path};
    }
    // Called on final response headers; informational responses are handled
    // separately by the HTTP owner. A Capsule-Protocol field is recommended,
    // not mandatory when the endpoint understands the connect-ip token.
    inline auto parse_connect_ip_response(std::span<http::HeaderField const> fields) noexcept -> std::expected<unsigned,ConnectIpError> {
        std::string_view status;bool seen=false;
        for(auto const& field:fields) {
            if(field.name==":status") {if(seen)return std::unexpected(ConnectIpError::malformed);seen=true;status=field.value;}
            else if(field.name=="content-length" || field.name=="content-type" || field.name=="transfer-encoding" ||
                    (!field.name.empty() && field.name.front()==':'))return std::unexpected(ConnectIpError::malformed);
        }
        if(!seen || status.size()!=3 || !std::ranges::all_of(status,[](char c){return c>='0' && c<='9';}))return std::unexpected(ConnectIpError::malformed);
        auto code=unsigned(status[0]-'0')*100+unsigned(status[1]-'0')*10+unsigned(status[2]-'0');
        if(code<200 || code>=300)return std::unexpected(ConnectIpError::failed_response);
        if(code==204 || code==205 || code==206)return std::unexpected(ConnectIpError::malformed);
        return code;
    }
    enum class IpTargetKind { any,prefix,hostname };
    struct ConnectIpScope {
        IpTargetKind kind=IpTargetKind::any;
        AddressEntry prefix{}; // request_id is unused
        std::string hostname;
        std::optional<std::uint8_t> protocol;
    };
    namespace ip_uri_detail {
        inline auto hex(char c) noexcept -> int {if(c>='0' && c<='9')return c-'0';if(c>='a' && c<='f')return c-'a'+10;if(c>='A' && c<='F')return c-'A'+10;return -1;}
        inline auto decode(std::string_view encoded,std::span<char> out,bool target) noexcept -> std::optional<std::size_t> {
            std::size_t size=0;
            for(std::size_t i=0;i<encoded.size();++i) {
                unsigned char c=encoded[i];
                if(c=='%') {if(i+2>=encoded.size())return {};auto a=hex(encoded[i+1]),b=hex(encoded[i+2]);if(a<0 || b<0)return {};c=static_cast<unsigned char>((a<<4)|b);i+=2;}
                else if(c==':' || c=='/' || c=='?' || c=='#')return {};
                if(c<=0x20 || c>=0x7f || c=='%' || c=='?' || c=='#' || c=='[' || c==']' || c=='@' || c=='\\' ||
                   (!target && (c==':' || c=='/')) || size==out.size())return {};
                out[size++]=static_cast<char>(c);
            }
            return size;
        }
        inline auto dns_name(std::string_view name) noexcept -> bool {
            if(name.ends_with('.'))name.remove_suffix(1);
            if(name.empty() || name.size()>253 || name.ends_with('.'))return false;
            bool numeric=true;
            for(char c:name)if((c<'0' || c>'9') && c!='.')numeric=false;
            if(numeric)return false; // do not reinterpret invalid numeric IP text as DNS
            while(!name.empty()) {
                auto pos=name.find('.');auto label=name.substr(0,pos);
                if(label.empty() || label.size()>63 || label.front()=='-' || label.back()=='-' ||
                   !std::ranges::all_of(label,[](unsigned char c){return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-';}))return false;
                if(pos==name.npos)break;name.remove_prefix(pos+1);
            }
            return true;
        }
    }
    // Only the RFC 9484 default template. A hostname is not an authorization:
    // the owner must resolve it before replying and constrain each result.
    inline auto parse_default_ip_path(std::string_view path) -> std::expected<ConnectIpScope,ConnectIpError> {
        constexpr std::string_view base="/.well-known/masque/ip/";
        if(path.size()<=base.size() || !path.starts_with(base) || !path.ends_with('/'))return std::unexpected(ConnectIpError::invalid_path);
        path.remove_prefix(base.size());path.remove_suffix(1);auto split=path.find('/');
        if(split==path.npos || path.find('/',split+1)!=path.npos)return std::unexpected(ConnectIpError::invalid_path);
        auto target=path.substr(0,split),proto=path.substr(split+1);
        std::array<char,260> buffer{};auto size=ip_uri_detail::decode(target,std::span(buffer).first(buffer.size()-1),true);
        if(!size || !*size)return std::unexpected(ConnectIpError::invalid_target);
        std::string_view name(buffer.data(),*size);ConnectIpScope scope;
        if(name!="*") {
            auto slash=name.find('/');auto host=name.substr(0,slash);
            if(host.empty() || (slash!=name.npos && name.find('/',slash+1)!=name.npos))return std::unexpected(ConnectIpError::invalid_target);
            auto& prefix=scope.prefix;
            if(auto parsed=platform::parse_ip_address(host)) {prefix.address=parsed->bytes;prefix.version=parsed->size==4 ? 4 : 6;}
            if(prefix.version) {
                auto bits=unsigned(ip_address_bytes(prefix.version)*8);unsigned requested=bits;
                if(slash!=name.npos) {
                    auto text=name.substr(slash+1);
                    if(text.empty() || text.size()>3 || !std::ranges::all_of(text,[](char c){return c>='0' && c<='9';}))return std::unexpected(ConnectIpError::invalid_target);
                    auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),requested);
                    if(error!=std::errc{} || end!=text.data()+text.size() || requested>bits)return std::unexpected(ConnectIpError::invalid_target);
                }
                prefix.prefix_length=static_cast<std::uint8_t>(requested);
                if(!valid_prefix(std::span(prefix.address).first(ip_address_bytes(prefix.version)),prefix.prefix_length))return std::unexpected(ConnectIpError::invalid_target);
                scope.kind=IpTargetKind::prefix;
            } else {
                if(slash!=name.npos || !ip_uri_detail::dns_name(name))return std::unexpected(ConnectIpError::invalid_target);
                scope.kind=IpTargetKind::hostname;scope.hostname=name;
            }
        }
        std::array<char,4> protocol{};auto length=ip_uri_detail::decode(proto,protocol,false);
        if(!length || !*length)return std::unexpected(ConnectIpError::invalid_protocol);
        std::string_view text(protocol.data(),*length);
        if(text!="*") {
            if(text.size()>3 || !std::ranges::all_of(text,[](char c){return c>='0' && c<='9';}))return std::unexpected(ConnectIpError::invalid_protocol);
            unsigned number=0;auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),number);
            if(error!=std::errc{} || end!=text.data()+text.size() || number>255)return std::unexpected(ConnectIpError::invalid_protocol);
            scope.protocol=static_cast<std::uint8_t>(number);
        }
        return scope;
    }
    // Encode the default template without letting decoded delimiters change
    // its structure. Prefix scopes retain the exact canonical prefix.
    inline auto write_default_ip_path(ConnectIpScope const& scope) -> std::expected<std::string,ConnectIpError> {
        std::string target;
        if(scope.kind==IpTargetKind::any)target="*";
        else if(scope.kind==IpTargetKind::hostname) {
            if(!ip_uri_detail::dns_name(scope.hostname))return std::unexpected(ConnectIpError::invalid_target);
            target=scope.hostname;
        } else if(scope.kind==IpTargetKind::prefix) {
            auto const& prefix=scope.prefix;auto size=ip_address_bytes(prefix.version);
            if(!size || !valid_prefix(std::span(prefix.address).first(size),prefix.prefix_length))return std::unexpected(ConnectIpError::invalid_target);
            auto text=platform::format_ip_address(std::span(prefix.address).first(size));
            if(!text)return std::unexpected(ConnectIpError::invalid_target);
            for(char c:*text) {if(c==':')target+="%3A";else target+=c;}
            target+="%2F";target+=std::to_string(prefix.prefix_length);
        } else return std::unexpected(ConnectIpError::invalid_target);
        auto proto=scope.protocol ? std::to_string(*scope.protocol) : std::string("*");
        return std::string("/.well-known/masque/ip/")+target+"/"+proto+"/";
    }
}
