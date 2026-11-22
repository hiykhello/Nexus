export module http.sniff;
import std;
import http.header;
import platform.ip_address;

export namespace http {
    enum class SniffStatus { need_more, matched, not_http, malformed, too_large };
    // Domain borrows the cumulative input; numeric authorities do not supply
    // a domain. Bytes remain the caller's property and are not consumed.
    enum class SniffNameKind { unknown, domain, numeric, ambiguous, unsupported };
    struct HttpSniffResult { SniffStatus status; std::optional<std::string_view> domain; SniffNameKind name_kind=SniffNameKind::unknown; };

    class HttpSniffer {
        std::size_t scan_=0;
        static auto equal_ci(std::string_view a,std::string_view b) noexcept -> bool {
            return a.size()==b.size() && std::equal(a.begin(),a.end(),b.begin(),[](char x,char y) {
                if (x>='A' && x<='Z') x=static_cast<char>(x+('a'-'A'));
                if (y>='A' && y<='Z') y=static_cast<char>(y+('a'-'A'));
                return x==y;
            });
        }
        static auto domain(std::string_view name) noexcept -> bool {
            if (name.empty() || name.size()>253) return false;
            std::size_t start=0;
            for (std::size_t i=0;i<=name.size();++i) {
                if (i==name.size() || name[i]=='.') {
                    if (i==start || i-start>63 || name[start]=='-' || name[i-1]=='-') return false;
                    start=i+1;
                } else {
                    char c=name[i];
                    if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return false;
                }
            }
            return true;
        }
        static auto authority(std::string_view value,std::optional<std::string_view>& name,
            std::optional<std::uint16_t>* parsed_port=nullptr) noexcept -> bool {
            if (value.empty()) return false;
            std::string_view host,port;
            if (value.front()=='[') {
                auto end=value.find(']');
                if (end==value.npos || end==1) return false;
                host=value.substr(1,end-1);
                auto ip=platform::parse_ip_address(host);
                if (!ip || ip->size!=16) return false;
                auto rest=value.substr(end+1);
                if (!rest.empty()) { if (rest.front()!=':') return false; port=rest.substr(1); }
                if (!rest.empty() && port.empty()) return false;
            } else {
                auto split=value.find(':');
                host=value.substr(0,split);
                if (!domain(host)) return false;
                if (split!=value.npos) { port=value.substr(split+1); if (port.empty()) return false; }
                if (std::all_of(host.begin(),host.end(),[](char c) { return (c>='0' && c<='9') || c=='.'; })) {
                    auto ip=platform::parse_ip_address(host);
                    if (!ip || ip->size!=4) return false;
                } else name=host;
            }
            if (!port.empty()) {
                unsigned parsed=0;
                auto [end,error]=std::from_chars(port.data(),port.data()+port.size(),parsed);
                if (error!=std::errc{} || end!=port.data()+port.size() || !parsed || parsed>65535) return false;
                if (parsed_port) *parsed_port=static_cast<std::uint16_t>(parsed);
            }
            return true;
        }
    public:
        // Resubmit the unchanged cumulative prefix, including already parsed
        // bytes. The caller handles EOF, deadlines, replay and buffer limits.
        [[nodiscard]] auto inspect(std::string_view input) noexcept -> HttpSniffResult {
            auto end=input.find("\r\n\r\n",std::min(scan_,input.size()));
            if (end==input.npos) {
                scan_=input.size()>3 ? input.size()-3 : 0;
                return {input.size()>=max_header_bytes ? SniffStatus::too_large : SniffStatus::need_more,{}};
            }
            auto header=inspect_header(input);
            if (header.status==HeaderStatus::too_large) return {SniffStatus::too_large,{}};
            if (header.status!=HeaderStatus::complete) return {SniffStatus::malformed,{}};
            auto line=header.first;
            auto first=line.find(' '),second=first==line.npos ? line.npos : line.find(' ',first+1);
            if (first==line.npos || !first || second==line.npos || second==first+1 ||
                line.find(' ',second+1)!=line.npos || !std::all_of(line.begin(),line.begin()+first,header_token) ||
                (line.substr(second+1)!="HTTP/1.1" && line.substr(second+1)!="HTTP/1.0")) return {SniffStatus::not_http,{}};
            auto target=line.substr(first+1,second-first-1);
            if (std::any_of(target.begin(),target.end(),[](unsigned char c) { return c<33 || c==127; }))
                return {SniffStatus::malformed,{}};
            std::optional<std::string_view> name;
            std::optional<std::uint16_t> host_port;
            bool seen=false;
            HeaderFieldCursor fields(header.field_lines);
            for (;;) {
                auto field=fields.next();
                if (field.status==HeaderFieldStatus::end) break;
                if (field.status==HeaderFieldStatus::malformed) return {SniffStatus::malformed,{}};
                if (equal_ci(field.field.name,"host")) {
                    if (seen || !authority(field.field.value,name,&host_port)) return {SniffStatus::malformed,{}};
                    seen=true;
                }
            }
            if (line.substr(second+1)=="HTTP/1.1" && !seen) return {SniffStatus::malformed,{}};
            // When a request target carries its own authority, use a domain
            // only if it agrees with Host. A conflicting pair is untrusted
            // metadata, not a reason to pick one side for routing.
            auto kind=name ? SniffNameKind::domain : seen ? SniffNameKind::numeric : SniffNameKind::unknown;
            auto method=line.substr(0,first);
            std::optional<std::string_view> target_name;
            std::optional<std::uint16_t> target_port;
            if (method=="CONNECT") {
                auto port=target.front()=='[' ? target.find(']') : target.find(':');
                if (port==target.npos || (target.front()=='[' && (port+1>=target.size() || target[port+1]!=':')) ||
                    !authority(target,target_name,&target_port)) return {SniffStatus::malformed,{}};
                if (seen && (!name || !target_name || !equal_ci(*name,*target_name) || !host_port || host_port!=target_port)) {
                    target_name.reset();kind=SniffNameKind::ambiguous;
                } else kind=target_name ? SniffNameKind::domain : SniffNameKind::numeric;
                name=target_name;
            } else if (auto scheme=target.find("://");scheme!=target.npos) {
                if (!equal_ci(target.substr(0,scheme),"http") && !equal_ci(target.substr(0,scheme),"https")) {
                    name.reset();kind=SniffNameKind::unsupported;
                }
                else {
                    auto rest=target.substr(scheme+3);auto end=rest.find_first_of("/?#");
                    if (!authority(rest.substr(0,end),target_name,&target_port)) return {SniffStatus::malformed,{}};
                    auto default_port=equal_ci(target.substr(0,scheme),"https") ? 443u : 80u;
                    if (seen && (!name || !target_name || !equal_ci(*name,*target_name) ||
                        host_port.value_or(default_port)!=target_port.value_or(default_port))){
                        target_name.reset();kind=SniffNameKind::ambiguous;
                    } else kind=target_name ? SniffNameKind::domain : SniffNameKind::numeric;
                    name=target_name;
                }
            }
            return {SniffStatus::matched,name,kind};
        }
    };
}
