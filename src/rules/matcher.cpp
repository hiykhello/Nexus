module rules;
import std;
import platform.ip_address;
import rules.domain_pattern;
import rules.regex;

#include "any_index.hpp"

namespace rules {
    auto valid_domain(std::string_view name) -> bool;

    Matcher::Matcher() = default;
    Matcher::Matcher(Matcher const& other)
        : uses_source_uid_(other.uses_source_uid_), uses_process_(other.uses_process_), entries_(other.entries_), texts_(other.texts_), regexes_(other.regexes_), children_(other.children_), roots_(other.roots_), domains_(other.domains_), suffixes_(other.suffixes_),
          ipv4_(other.ipv4_), ipv6_(other.ipv6_), any_indexes_(other.any_indexes_), unindexed_(other.unindexed_) {
        std::size_t text_index=0;
        for (auto& entry:entries_)
            if (entry.kind==Kind::domain || entry.kind==Kind::suffix || entry.kind==Kind::keyword || entry.kind==Kind::wildcard || entry.kind==Kind::inbound || entry.kind==Kind::auth_user || entry.kind==Kind::process_name || entry.kind==Kind::process_path || entry.kind==Kind::source_interface)
                entry.text=texts_[text_index++];
        for (auto* index : {&domains_, &suffixes_})
            for (auto& item : *index) item.text=entries_[roots_[item.rule]].text;
    }
    Matcher::Matcher(Matcher&&) noexcept = default;
    auto Matcher::operator=(Matcher const& other) -> Matcher& {
        if (this!=&other) *this=Matcher(other);
        return *this;
    }
    auto Matcher::operator=(Matcher&&) noexcept -> Matcher& = default;
    Matcher::~Matcher() = default;

    namespace {
        constexpr unsigned AF_INET = 4;
        constexpr unsigned AF_INET6 = 6;

        auto address(std::string_view text, std::array<std::uint8_t, 16>& out) -> unsigned {
            auto parsed = platform::parse_ip_address(text);
            if (!parsed) return 0;
            out = parsed->bytes;
            return parsed->size == 4 ? AF_INET : AF_INET6;
        }

        auto network_address(std::array<std::uint8_t,16> candidate, unsigned bits) noexcept
            -> std::array<std::uint8_t,16> {
            auto bytes=bits/8;
            auto remaining=bits%8;
            if (remaining) {
                candidate[bytes] &= static_cast<std::uint8_t>(0xffU << (8-remaining));
                ++bytes;
            }
            std::fill(candidate.begin()+bytes,candidate.end(),0);
            return candidate;
        }

        auto prefix_matches(std::array<std::uint8_t, 16> const& network,
                            std::array<std::uint8_t, 16> const& candidate, unsigned bits) -> bool {
            auto bytes = bits / 8;
            if (!std::equal(network.begin(), network.begin() + bytes, candidate.begin())) return false;
            auto remaining = bits % 8;
            if (remaining == 0) return true;
            auto mask = static_cast<std::uint8_t>(0xffU << (8 - remaining));
            return (network[bytes] & mask) == (candidate[bytes] & mask);
        }

        // Mirrors sing's !IsPublicAddr on a valid numeric netip.Addr. The Go
        // predicates unmap IPv4-in-IPv6 for the ranges, but IsUnspecified
        // itself distinguishes ::ffff:0.0.0.0 from native 0.0.0.0.
        auto private_address(std::array<std::uint8_t,16> const& bytes,unsigned family) noexcept -> bool {
            auto mapped=family==AF_INET6 &&
                std::all_of(bytes.begin(),bytes.begin()+10,[](auto byte) { return byte==0; }) &&
                bytes[10]==0xff && bytes[11]==0xff;
            if (family==AF_INET || mapped) {
                auto offset=mapped ? 12u : 0u;
                auto a=bytes[offset], b=bytes[offset+1];
                return a==10 || (a==172 && (b&0xf0)==16) || (a==192 && b==168) ||
                    a==127 || (a==169 && b==254) || (a&0xf0)==0xe0 ||
                    (!mapped && a==0 && b==0 && bytes[2]==0 && bytes[3]==0);
            }
            auto zero_prefix=std::all_of(bytes.begin(),bytes.end()-1,[](auto byte) { return byte==0; });
            return (bytes[0]&0xfe)==0xfc || (bytes[0]==0xfe && (bytes[1]&0xc0)==0x80) || bytes[0]==0xff ||
                (zero_prefix && (bytes[15]==0 || bytes[15]==1));
        }
    }

    auto is_private_address(std::span<std::uint8_t const> address) noexcept -> bool {
        if (address.size()!=4 && address.size()!=16) return false;
        std::array<std::uint8_t,16> bytes{};
        std::ranges::copy(address,bytes.begin());
        return private_address(bytes,address.size()==4 ? AF_INET : AF_INET6);
    }

    auto normalize_matcher_set(RuleSet set,std::vector<BoundedRegex>& expressions) -> std::expected<RuleSet, Error>;

    auto Matcher::compile(RuleSet const& set) -> std::expected<Matcher, Error> {
        Matcher result;
        auto normalized=normalize_matcher_set(set,result.regexes_);
        if (!normalized) return std::unexpected(std::move(normalized.error()));
        static_assert(max_rules<=std::numeric_limits<std::uint16_t>::max());
        result.roots_.reserve(normalized->rules.size());
        auto count_texts=[&](auto&& self,Rule const& rule) -> std::size_t {
            std::size_t count=rule.type=="domain" || rule.type=="domain-suffix" ||
                rule.type=="domain-keyword" || rule.type=="domain-wildcard" || rule.type=="inbound" || rule.type=="auth-user" || rule.type=="process-name" || rule.type=="process-path" || rule.type=="source-interface";
            for (auto const& child:rule.children) count+=self(self,child);
            return count;
        };
        std::size_t text_count=0;
        for (auto const& rule:normalized->rules) text_count+=count_texts(count_texts,rule);
        result.texts_.reserve(text_count);
        std::uint16_t regex_index=0;
        auto append=[&](auto&& self,Rule const& rule) -> std::size_t {
            auto index=result.entries_.size();
            result.entries_.emplace_back();
            Entry entry;
            if (rule.type=="domain-suffix" || rule.type=="domain" || rule.type=="domain-keyword" || rule.type=="domain-wildcard" || rule.type=="inbound" || rule.type=="auth-user" || rule.type=="process-name" || rule.type=="process-path" || rule.type=="source-interface") {
                entry.kind=rule.type=="domain" ? Kind::domain : rule.type=="domain-suffix" ? Kind::suffix :
                    rule.type=="domain-keyword" ? Kind::keyword : rule.type=="domain-wildcard" ? Kind::wildcard :
                    rule.type=="inbound" ? Kind::inbound : rule.type=="process-name" ? Kind::process_name :
                    rule.type=="process-path" ? Kind::process_path :
                    rule.type=="source-interface" ? Kind::source_interface : Kind::auth_user;
                result.uses_process_ |= entry.kind==Kind::process_name || entry.kind==Kind::process_path;
                result.texts_.push_back(rule.value);
                entry.text=result.texts_.back();
            } else if (rule.type=="domain-regex" || rule.type=="process-path-regex") {
                entry.kind=rule.type=="domain-regex" ? Kind::domain_regex : Kind::process_path_regex;
                entry.regex=regex_index++;
                result.uses_process_ |= entry.kind==Kind::process_path_regex;
            } else if (rule.type=="ip-cidr" || rule.type=="source-ip-cidr") {
                entry.kind=rule.type=="ip-cidr" ? Kind::ip : Kind::source_ip;
                auto slash=rule.value.find('/');
                auto prefix=std::string_view(rule.value).substr(slash+1);
                entry.ip.family=address(std::string_view(rule.value).substr(0,slash),entry.ip.address);
                (void)std::from_chars(prefix.data(),prefix.data()+prefix.size(),entry.ip.prefix);
            } else if (rule.type=="ip-version") {
                entry.kind=Kind::ip_version;
                entry.ip_version=rule.value=="4" ? 4 : 6;
            } else if (rule.type=="ip-is-private" || rule.type=="source-ip-is-private") {
                entry.kind=rule.type=="ip-is-private" ? Kind::ip_is_private : Kind::source_private;
            } else if (rule.type=="port" || rule.type=="port-range" || rule.type=="source-port" || rule.type=="source-port-range") {
                entry.kind=rule.type.starts_with("source-") ? Kind::source_port : Kind::port;
                auto dash=rule.value.find('-');
                auto end=dash==std::string::npos ? rule.value.size() : dash;
                unsigned first=0,last=0;
                (void)std::from_chars(rule.value.data(),rule.value.data()+end,first);
                if (dash==std::string::npos) last=first;
                else (void)std::from_chars(rule.value.data()+dash+1,rule.value.data()+rule.value.size(),last);
                entry.port={static_cast<std::uint16_t>(first),static_cast<std::uint16_t>(last)};
            } else if (rule.type=="source-uid") {
                entry.kind=Kind::source_uid;
                entry.source_uid=*parse_source_uid(rule.value);
                result.uses_source_uid_=true;
            } else if (rule.type=="query-type") {
                entry.kind=Kind::query_type;
                unsigned value=0;
                (void)std::from_chars(rule.value.data(),rule.value.data()+rule.value.size(),value);
                entry.query_type=static_cast<std::uint16_t>(value);
            } else if (rule.type=="dscp") {
                entry.kind=Kind::dscp;
                entry.dscp_mask=*parse_dscp_list(rule.value);
            } else if (rule.type=="source-mac" || rule.type=="gateway-mac") {
                entry.kind=rule.type=="source-mac" ? Kind::source_mac : Kind::gateway_mac;
                entry.mac=*parse_mac(rule.value);
            } else if (rule.type=="tls-ech" || (rule.type=="protocol" && rule.value=="tls-ech")) {
                entry.kind=Kind::tls_ech;
                entry.offered=rule.value!="false";
            } else if (rule.type=="protocol") {
                entry.kind=Kind::protocol;
                entry.protocol=*parse_protocol(rule.value);
            } else if (rule.type=="network") {
                entry.kind=Kind::network;
                entry.network=rule.value=="tcp" ? Network::tcp : Network::udp;
            } else {
                entry.kind=rule.type=="and" ? Kind::all : rule.type=="or" ? Kind::any : Kind::negate;
                auto first=result.children_.size();
                result.children_.resize(first+rule.children.size());
                for (std::size_t i=0;i<rule.children.size();++i) {
                    auto child=self(self,rule.children[i]);
                    result.children_[first+i]=static_cast<std::uint16_t>(child);
                }
                auto any_idx=entry.kind==Kind::any && rule.children.size()>=16 ?
                    any_detail::compile_any_index(result.entries_,result.children_,static_cast<std::uint32_t>(first),
                        static_cast<std::uint32_t>(rule.children.size()),Kind::ip,Kind::domain,Kind::suffix,result.any_indexes_) :
                    std::numeric_limits<std::uint32_t>::max();
                entry.children={static_cast<std::uint32_t>(first),static_cast<std::uint32_t>(rule.children.size()),any_idx};
            }
            result.entries_[index]=std::move(entry);
            return index;
        };
        for (auto const& rule:normalized->rules) result.roots_.push_back(append(append,rule));
        for (std::size_t i=0;i<result.roots_.size();++i) {
            auto const& entry=result.entries_[result.roots_[i]];
            if (entry.kind==Kind::domain) result.domains_.push_back({entry.text,i});
            else if (entry.kind==Kind::suffix) result.suffixes_.push_back({entry.text,i});
            else if (entry.kind==Kind::ip) {
                auto& index=entry.ip.family==AF_INET ? result.ipv4_ : result.ipv6_;
                auto group=std::ranges::find(index,entry.ip.prefix,&IpGroup::prefix);
                if (group==index.end()) {
                    index.push_back({entry.ip.prefix,{}});
                    group=std::prev(index.end());
                }
                group->entries.push_back({network_address(entry.ip.address,entry.ip.prefix),i});
            } else result.unindexed_.push_back(i);
        }
        auto sort_domain=[&](auto& index) {
            std::ranges::sort(index,[&](IndexedDomain const& a,IndexedDomain const& b) {
                return std::tie(a.text,a.rule)<std::tie(b.text,b.rule);
            });
        };
        sort_domain(result.domains_);
        sort_domain(result.suffixes_);
        auto sort_ip=[](IpIndex& index) {
            for (auto& group:index) {
                std::ranges::sort(group.entries,[](IndexedIp const& a,IndexedIp const& b) {
                    return std::tie(a.address,a.rule)<std::tie(b.address,b.rule);
                });
            }
        };
        sort_ip(result.ipv4_);
        sort_ip(result.ipv6_);
        return result;
    }

    auto Matcher::prepare(MatchInput input) -> std::expected<Prepared, Error> {
        if (input.domain) {
            if (input.domain->ends_with('.')) input.domain->remove_suffix(1);
            if (!valid_domain(*input.domain))
                return std::unexpected(Error{ErrorCode::invalid_query,"invalid ASCII domain"});
        }
        Prepared prepared{input};
        if (input.ip && !(prepared.family=address(*input.ip,prepared.address)))
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid IP address"});
        if (input.source_ip && !(prepared.source_family=address(*input.source_ip,prepared.source_address)))
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid source IP address"});
        if (input.source_ip_bytes) {
            auto bytes=*input.source_ip_bytes;
            if (input.source_ip || (bytes.size()!=4 && bytes.size()!=16))
                return std::unexpected(Error{ErrorCode::invalid_query,"invalid source IP address"});
            prepared.source_family=bytes.size()==4 ? AF_INET : AF_INET6;
            std::ranges::copy(bytes,prepared.source_address.begin());
        }
        if (input.source_port && !*input.source_port)
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid source port"});
        if (input.port && !*input.port)
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid destination port"});
        if (input.dscp && *input.dscp>63)
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid DSCP"});
        if (input.query_type && !*input.query_type)
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid DNS query type"});
        if (input.network && *input.network!=Network::tcp && *input.network!=Network::udp)
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid network"});
        if (input.protocol && (*input.protocol<Protocol::http || *input.protocol>Protocol::quic))
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid protocol"});
        if (input.inbound && (input.inbound->empty() || input.inbound->size()>255 || input.inbound->find('\0')!=std::string_view::npos))
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid inbound name"});
        if (input.auth_user && (input.auth_user->empty() || input.auth_user->size()>255 || input.auth_user->find('\0')!=std::string_view::npos))
            return std::unexpected(Error{ErrorCode::invalid_query,"invalid authenticated user"});
        return prepared;
    }

    auto Matcher::evaluate(std::size_t index,Prepared const& input) const noexcept -> Truth {
        auto const& entry=entries_[index];
        if(input.candidates && (entry.kind==Kind::ip || entry.kind==Kind::ip_version || entry.kind==Kind::ip_is_private)) {
            auto candidate=input;candidate.candidates.reset();
            for(auto const& address:*input.candidates) {
                candidate.address=address.bytes;candidate.family=address.size==4 ? AF_INET : AF_INET6;
                // Evaluation only checks presence; bytes are already parsed.
                candidate.input.ip=std::string_view{};
                if(evaluate(index,candidate)==Truth::yes)return Truth::yes;
            }
            return Truth::no;
        }
        switch (entry.kind) {
        case Kind::process_name:
        case Kind::process_path: {
            if (!input.input.process_path) return Truth::unknown;
            auto path=*input.input.process_path;
            auto value=entry.kind==Kind::process_path ? path : path.substr(path.rfind('/')+1);
            return value==entry.text ? Truth::yes : Truth::no;
        }
        case Kind::domain_regex:
            if (!input.input.domain) return input.domain_absent ? Truth::no : Truth::unknown;
            return regexes_[entry.regex].search(*input.input.domain,true) ? Truth::yes : Truth::no;
        case Kind::process_path_regex:
            if (!input.input.process_path || input.input.process_path->size()>4095) return Truth::unknown;
            return regexes_[entry.regex].search(*input.input.process_path) ? Truth::yes : Truth::no;
        case Kind::source_interface:
            if (!input.input.source_interface) return Truth::unknown;
            return *input.input.source_interface==entry.text ? Truth::yes : Truth::no;
        case Kind::inbound:
            if (!input.input.inbound) return Truth::unknown;
            return *input.input.inbound==entry.text ? Truth::yes : Truth::no;
        case Kind::auth_user:
            if (!input.input.auth_user) return Truth::unknown;
            return *input.input.auth_user==entry.text ? Truth::yes : Truth::no;
        case Kind::domain:
        case Kind::suffix:
        case Kind::keyword:
        case Kind::wildcard: {
            if (!input.input.domain) return input.domain_absent ? Truth::no : Truth::unknown;
            auto kind=entry.kind==Kind::domain ? DomainPattern::exact : entry.kind==Kind::suffix ? DomainPattern::suffix :
                entry.kind==Kind::keyword ? DomainPattern::keyword : DomainPattern::wildcard;
            return domain_pattern_matches(kind,*input.input.domain,entry.text) ? Truth::yes : Truth::no;
        }
        case Kind::ip:
        case Kind::source_ip: {
            bool source=entry.kind==Kind::source_ip;
            if (source ? !input.source_family : !input.input.ip) return Truth::unknown;
            auto const& addr=source ? input.source_address : input.address;
            auto family=source ? input.source_family : input.family;
            if (entry.ip.family==family && prefix_matches(entry.ip.address,addr,entry.ip.prefix)) return Truth::yes;
            if (input.match_mapped_ipv4 && entry.ip.family==AF_INET && family==AF_INET6 &&
                std::all_of(addr.begin(),addr.begin()+10,[](auto byte) { return byte==0; }) &&
                addr[10]==0xff && addr[11]==0xff) {
                std::array<std::uint8_t,16> mapped{};
                std::copy(addr.begin()+12,addr.end(),mapped.begin());
                if (prefix_matches(entry.ip.address,mapped,entry.ip.prefix)) return Truth::yes;
            }
            return Truth::no;
        }
        case Kind::ip_version:
            if (!input.input.ip) return Truth::unknown;
            return (entry.ip_version==4 ? input.family==AF_INET : input.family==AF_INET6) ? Truth::yes : Truth::no;
        case Kind::ip_is_private:
            if (!input.input.ip) return Truth::unknown;
            return private_address(input.address,input.family) ? Truth::yes : Truth::no;
        case Kind::source_private:
            if (!input.source_family) return Truth::unknown;
            return private_address(input.source_address,input.source_family) ? Truth::yes : Truth::no;
        case Kind::port:
            if (!input.input.port) return Truth::unknown;
            return *input.input.port>=entry.port.first && *input.input.port<=entry.port.last ? Truth::yes : Truth::no;
        case Kind::source_uid:
            if (!input.input.source_uid) return Truth::unknown;
            return *input.input.source_uid==entry.source_uid ? Truth::yes : Truth::no;
        case Kind::source_port:
            if (!input.input.source_port) return Truth::unknown;
            return *input.input.source_port>=entry.port.first && *input.input.source_port<=entry.port.last ? Truth::yes : Truth::no;
        case Kind::network:
            if (!input.input.network) return Truth::unknown;
            return *input.input.network==entry.network ? Truth::yes : Truth::no;
        case Kind::dscp:
            if (!input.input.dscp) return Truth::unknown;
            return (entry.dscp_mask & (std::uint64_t{1}<<*input.input.dscp)) ? Truth::yes : Truth::no;
        case Kind::source_mac:
        case Kind::gateway_mac: {
            auto const& address=entry.kind==Kind::source_mac ? input.input.source_mac : input.input.gateway_mac;
            return !address ? Truth::unknown : *address==entry.mac ? Truth::yes : Truth::no;
        }
        case Kind::tls_ech:
            if (input.input.protocol!=Protocol::tls || !input.input.tls_ech) return Truth::unknown;
            return *input.input.tls_ech==entry.offered ? Truth::yes : Truth::no;
        case Kind::protocol:
            if (!input.input.protocol) return Truth::unknown;
            return *input.input.protocol==entry.protocol ? Truth::yes : Truth::no;
        case Kind::query_type:
            if (!input.input.query_type) return Truth::unknown;
            return *input.input.query_type==entry.query_type ? Truth::yes : Truth::no;
        case Kind::negate: {
            auto child=evaluate(children_[entry.children.first],input);
            return child==Truth::unknown ? child : child==Truth::yes ? Truth::no : Truth::yes;
        }
        case Kind::all:
        case Kind::any: {
            bool unknown=false;
            if (entry.kind==Kind::any && entry.children.any_index<any_indexes_.size()) {
                auto const& idx=any_indexes_[entry.children.any_index];
                if (idx.has_domain) {
                    if (input.input.domain) {
                        if (any_detail::match_any_domain(entries_,idx,*input.input.domain)) return Truth::yes;
                    } else if (!input.domain_absent) unknown=true;
                }
                if (idx.has_ip) {
                    if (input.candidates) {
                        for (auto const& c:*input.candidates)
                            if (any_detail::match_any_ip_one(idx,c.bytes,c.size==4 ? AF_INET : AF_INET6,input.match_mapped_ipv4))
                                return Truth::yes;
                    } else if (input.input.ip) {
                        if (any_detail::match_any_ip_one(idx,input.address,input.family,input.match_mapped_ipv4))
                            return Truth::yes;
                    } else unknown=true;
                }
                for (auto cid:idx.remainder) {
                    auto value=evaluate(cid,input);
                    if (value==Truth::yes) return Truth::yes;
                    unknown|=value==Truth::unknown;
                }
                return unknown ? Truth::unknown : Truth::no;
            }
            auto last=entry.children.first+entry.children.count;
            for (auto child=entry.children.first;child<last;++child) {
                auto value=evaluate(children_[child],input);
                if (entry.kind==Kind::all && value==Truth::no) return Truth::no;
                if (entry.kind==Kind::any && value==Truth::yes) return Truth::yes;
                unknown|=value==Truth::unknown;
            }
            return unknown ? Truth::unknown : entry.kind==Kind::all ? Truth::yes : Truth::no;
        }
        }
        std::terminate();
    }

    auto Matcher::first_match(Prepared const& prepared) const noexcept -> std::optional<std::size_t> {
        return first_match(prepared,0,roots_.size());
    }

    auto Matcher::first_match(Prepared const& prepared,std::size_t first,std::size_t last) const noexcept
        -> std::optional<std::size_t> {
        if (last-first<=4) {
            for (auto i=first;i<last;++i)
                if (evaluate(roots_[i],prepared)==Truth::yes) return i;
            return {};
        }
        auto best=last;
        auto domain_lookup=[&](auto const& index,std::string_view key) {
            auto found=std::lower_bound(index.begin(),index.end(),key,
                [first](IndexedDomain const& item,std::string_view value) {
                    return item.text<value || (item.text==value && item.rule<first);
                });
            if (found!=index.end() && found->text==key && found->rule<last) best=std::min(best,found->rule);
        };
        if (prepared.input.domain && (!domains_.empty() || !suffixes_.empty())) {
            std::array<char,253> normalized;
            auto name=*prepared.input.domain;
            if (std::ranges::any_of(name,[](char c) { return c>='A' && c<='Z'; })) {
                for (std::size_t i=0;i<name.size();++i) {
                    auto c=name[i];
                    normalized[i]=c>='A' && c<='Z' ? static_cast<char>(c+('a'-'A')) : c;
                }
                name=std::string_view(normalized.data(),name.size());
            }
            domain_lookup(domains_,name);
            if (!suffixes_.empty()) for (;;) {
                domain_lookup(suffixes_,name);
                auto dot=name.find('.');
                if (dot==std::string_view::npos) break;
                name.remove_prefix(dot+1);
            }
        }
        auto ip_lookup=[&](IpIndex const& index,std::array<std::uint8_t,16> const& address) {
            for (auto const& group:index) {
                auto network=network_address(address,group.prefix);
                auto found=std::lower_bound(group.entries.begin(),group.entries.end(),network,
                    [first](IndexedIp const& item,auto const& value) {
                        return item.address<value || (item.address==value && item.rule<first);
                    });
                if (found!=group.entries.end() && found->address==network && found->rule<last)
                    best=std::min(best,found->rule);
            }
        };
        if (prepared.input.ip) {
            if (prepared.family==AF_INET) ip_lookup(ipv4_,prepared.address);
            else {
                ip_lookup(ipv6_,prepared.address);
                if (prepared.match_mapped_ipv4 &&
                    std::all_of(prepared.address.begin(),prepared.address.begin()+10,[](auto byte) { return byte==0; }) &&
                    prepared.address[10]==0xff && prepared.address[11]==0xff) {
                    std::array<std::uint8_t,16> mapped{};
                    std::copy(prepared.address.begin()+12,prepared.address.end(),mapped.begin());
                    ip_lookup(ipv4_,mapped);
                }
            }
        }
        for (auto it=std::lower_bound(unindexed_.begin(),unindexed_.end(),first);it!=unindexed_.end();++it) {
            auto i=*it;
            if (i>=best) break;
            if (evaluate(roots_[i],prepared)==Truth::yes) { best=i; break; }
        }
        if (best==last) return {};
        return best;
    }

}
