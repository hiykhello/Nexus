export module http.sniff;
import std;
import http.header;
import platform.ip_address;

export namespace http {
    enum class SniffStatus { need_more, matched, not_http, malformed, too_large };
    // Domain borrows the cumulative input; numeric authorities do not supply
    // a domain. Bytes remain the caller's property and are not consumed.
    enum class SniffNameKind { unknown, domain, numeric, ambiguous, unsupported };
    struct HttpSniffResult { SniffStatus status; std::optional<std::string_view> domain; SniffNameKind name_kind=SniffNameKind::unknown; std::optional<std::string_view> user_agent={}; };

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
        struct ParsedAuthority {
            enum class Kind { domain, ipv4, ipv6 } kind=Kind::domain;
            std::string_view host;
            std::array<std::uint8_t,16> address{};
            std::optional<std::uint16_t> port;
        };
        static auto is_numeric_or_hex_label(std::string_view label) noexcept -> bool {
            if (label.empty()) return false;
            if (std::ranges::all_of(label,[](char c) { return c>='0' && c<='9'; })) return true;
            if (label.size()>2 && label[0]=='0' && (label[1]=='x' || label[1]=='X'))
                return std::ranges::all_of(label.substr(2),[](char c) {
                    return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');
                });
            return false;
        }
        static auto is_alternate_numeric_ipv4(std::string_view host) noexcept -> bool {
            std::size_t labels=0;
            bool all_num=true;
            std::string_view last;
            for (std::size_t start=0;start<=host.size();) {
                auto dot=host.find('.',start);
                auto label=dot==host.npos ? host.substr(start) : host.substr(start,dot-start);
                ++labels;
                last=label;
                if (!is_numeric_or_hex_label(label)) all_num=false;
                if (dot==host.npos) break;
                start=dot+1;
            }
            return (labels>=1 && labels<=4 && all_num) || is_numeric_or_hex_label(last);
        }
        static auto same_host(ParsedAuthority const& a,ParsedAuthority const& b) noexcept -> bool {
            if (a.kind!=b.kind) return false;
            if (a.kind==ParsedAuthority::Kind::domain) return equal_ci(a.host,b.host);
            return a.address==b.address;
        }
        static auto parse_authority(std::string_view value) noexcept -> std::optional<ParsedAuthority> {
            if (value.empty()) return {};
            ParsedAuthority out;
            std::string_view host,port;
            if (value.front()=='[') {
                auto end=value.find(']');
                if (end==value.npos || end==1) return {};
                host=value.substr(1,end-1);
                auto ip=platform::parse_ip_address(host);
                if (!ip || ip->size!=16) return {};
                out.kind=ParsedAuthority::Kind::ipv6;
                out.address=ip->bytes;
                auto rest=value.substr(end+1);
                if (!rest.empty()) { if (rest.front()!=':') return {}; port=rest.substr(1); }
                if (!rest.empty() && port.empty()) return {};
            } else {
                auto split=value.find(':');
                host=value.substr(0,split);
                if (!domain(host)) return {};
                if (split!=value.npos) { port=value.substr(split+1); if (port.empty()) return {}; }
                if (auto ip=platform::parse_ip_address(host); ip && ip->size==4) {
                    out.kind=ParsedAuthority::Kind::ipv4;
                    out.address=ip->bytes;
                } else if (is_alternate_numeric_ipv4(host)) {
                    return {};
                } else {
                    out.kind=ParsedAuthority::Kind::domain;
                    out.host=host;
                }
            }
            if (!port.empty()) {
                unsigned parsed=0;
                auto [end,error]=std::from_chars(port.data(),port.data()+port.size(),parsed);
                if (error!=std::errc{} || end!=port.data()+port.size() || !parsed || parsed>65535) return {};
                out.port=static_cast<std::uint16_t>(parsed);
            }
            return out;
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
            std::optional<ParsedAuthority> host_auth;
            std::optional<std::string_view> user_agent;
            HeaderFieldCursor fields(header.field_lines);
            for (;;) {
                auto field=fields.next();
                if (field.status==HeaderFieldStatus::end) break;
                if (field.status==HeaderFieldStatus::malformed) return {SniffStatus::malformed,{}};
                if (equal_ci(field.field.name,"host")) {
                    if (host_auth) return {SniffStatus::malformed,{}};
                    host_auth=parse_authority(field.field.value);
                    if (!host_auth) return {SniffStatus::malformed,{}};
                } else if (equal_ci(field.field.name,"user-agent") && !user_agent) {
                    user_agent=field.field.value;
                }
            }
            if (line.substr(second+1)=="HTTP/1.1" && !host_auth) return {SniffStatus::malformed,{}};
            // When a request target carries its own authority, use a domain
            // only if it agrees with Host. A conflicting pair is untrusted
            // metadata, not a reason to pick one side for routing.
            std::optional<std::string_view> name=(host_auth && host_auth->kind==ParsedAuthority::Kind::domain)
                ? std::optional{host_auth->host} : std::nullopt;
            auto kind=host_auth
                ? (host_auth->kind==ParsedAuthority::Kind::domain ? SniffNameKind::domain : SniffNameKind::numeric)
                : SniffNameKind::unknown;
            auto method=line.substr(0,first);
            if (method=="CONNECT") {
                auto port=target.front()=='[' ? target.find(']') : target.find(':');
                if (port==target.npos || (target.front()=='[' && (port+1>=target.size() || target[port+1]!=':')))
                    return {SniffStatus::malformed,{}};
                auto target_auth=parse_authority(target);
                if (!target_auth || !target_auth->port) return {SniffStatus::malformed,{}};
                if (host_auth && (!same_host(*host_auth,*target_auth) || (host_auth->port && host_auth->port!=target_auth->port))) {
                    name.reset(); kind=SniffNameKind::ambiguous;
                } else if (target_auth->kind==ParsedAuthority::Kind::domain) {
                    name=target_auth->host; kind=SniffNameKind::domain;
                } else {
                    name.reset(); kind=SniffNameKind::numeric;
                }
            } else if (!target.empty() && target.front()!='/' && target!="*" &&
                       target.find("://")!=target.npos &&
                       target.substr(0,target.find("://")).find_first_of("/?#")==target.npos) {
                auto scheme=target.find("://");
                if (!equal_ci(target.substr(0,scheme),"http") && !equal_ci(target.substr(0,scheme),"https")) {
                    name.reset();kind=SniffNameKind::unsupported;
                }
                else {
                    auto rest=target.substr(scheme+3);auto end=rest.find_first_of("/?#");
                    auto target_auth=parse_authority(rest.substr(0,end));
                    if (!target_auth) return {SniffStatus::malformed,{}};
                    auto default_port=equal_ci(target.substr(0,scheme),"https") ? 443u : 80u;
                    if (host_auth && (!same_host(*host_auth,*target_auth) ||
                        host_auth->port.value_or(default_port)!=target_auth->port.value_or(default_port))) {
                        name.reset(); kind=SniffNameKind::ambiguous;
                    } else if (target_auth->kind==ParsedAuthority::Kind::domain) {
                        name=target_auth->host; kind=SniffNameKind::domain;
                    } else {
                        name.reset(); kind=SniffNameKind::numeric;
                    }
                }
            }
            return {SniffStatus::matched,name,kind,user_agent};
        }
    };
}
