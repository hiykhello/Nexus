module rules;
import std;
import platform.ip_address;
import rules.regex;

namespace rules {
    auto Rule::operator==(Rule const& other) const -> bool {
        return type == other.type && value == other.value && children == other.children;
    }

    auto RuleSet::operator==(RuleSet const& other) const -> bool {
        if (version != other.version || rules.size() != other.rules.size()) return false;
        for (std::size_t i = 0; i < rules.size(); ++i) {
            if (!(rules[i] == other.rules[i])) return false;
        }
        return true;
    }

    auto valid_domain(std::string_view name) -> bool {
        if (name.empty() || name.size() > 253) return false;
        std::size_t label_start = 0;
        for (std::size_t i = 0; i <= name.size(); ++i) {
            if (i == name.size() || name[i] == '.') {
                auto length = i - label_start;
                if (length == 0 || length > 63 || name[label_start] == '-' || name[i - 1] == '-') return false;
                label_start = i + 1;
                continue;
            }
            unsigned char c = static_cast<unsigned char>(name[i]);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                return false;
        }
        return true;
    }

    auto parse_mac(std::string_view text) noexcept -> std::optional<MacAddress> {
        if (text.size()!=17) return {};
        MacAddress result{};
        for (std::size_t i=0;i<result.size();++i) {
            auto* start=text.data()+3*i;
            unsigned byte=0;
            auto [end,error]=std::from_chars(start,start+2,byte,16);
            if (error!=std::errc{} || end!=start+2 || (i<5 && start[2]!=':')) return {};
            result[i]=static_cast<std::uint8_t>(byte);
        }
        return result;
    }

    auto parse_dscp(std::string_view text) noexcept -> std::optional<std::uint8_t> {
        unsigned value=0;
        auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value);
        if (error!=std::errc{} || end!=text.data()+text.size() || value>63) return {};
        return static_cast<std::uint8_t>(value);
    }

    auto parse_dscp_list(std::string_view text) noexcept -> std::optional<std::uint64_t> {
        std::uint64_t mask=0;
        for (;;) {
            auto comma=text.find(',');
            auto value=parse_dscp(text.substr(0,comma));
            if (!value) return {};
            mask|=std::uint64_t{1}<<*value;
            if (comma==text.npos) return mask;
            text.remove_prefix(comma+1);
        }
    }

    auto parse_protocol(std::string_view value) noexcept -> std::optional<Protocol> {
        if (value=="http") return Protocol::http;
        if (value=="tls") return Protocol::tls;
        if (value=="tls-ech") return Protocol::tls_ech;
        if (value=="dns") return Protocol::dns;
        if (value=="ssh") return Protocol::ssh;
        if (value=="stun") return Protocol::stun;
        if (value=="quic") return Protocol::quic;
        if (value=="bittorrent") return Protocol::bittorrent;
        if (value=="dtls") return Protocol::dtls;
        if (value=="rdp") return Protocol::rdp;
        if (value=="ntp") return Protocol::ntp;
        return {};
    }

    auto parse_protocol_list(std::string_view text) noexcept -> std::optional<std::uint32_t> {
        if (text.empty()) return {};
        std::uint32_t mask = 0;
        for (;;) {
            auto comma = text.find(',');
            auto item = text.substr(0, comma);
            auto proto = parse_protocol(item);
            if (!proto) return {};
            auto bit = protocol_mask(*proto);
            if (mask & bit) return {};
            mask |= bit;
            if (comma == std::string_view::npos) return mask;
            text.remove_prefix(comma + 1);
            if (text.empty()) return {};
        }
    }

    auto valid_client_name(std::string_view name) noexcept -> bool {
        return !name.empty() && name.size() <= 64 && std::ranges::all_of(name, [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        });
    }

    auto valid_source_interface(std::string_view name) noexcept -> bool {
        // Linux dev_valid_name/IFNAMSIZ, independent of the build platform.
        return !name.empty() && name.size()<16 && name!="." && name!=".." &&
            std::ranges::none_of(name,[](unsigned char c) {
                return c=='/' || c==':' || c==0 || c==' ' || (c>=9 && c<=13);
            });
    }

    namespace {
        auto invalid(std::string message) -> std::unexpected<Error> {
            return std::unexpected(Error{ErrorCode::invalid_rule, std::move(message)});
        }

        auto normalize_domain(std::string& name) -> bool {
            if (!valid_domain(name)) return false;
            for (std::size_t i = 0; i < name.size(); ++i) {
                unsigned char c = static_cast<unsigned char>(name[i]);
                if (c >= 'A' && c <= 'Z') name[i] = static_cast<char>(c + ('a' - 'A'));
            }
            return true;
        }

        auto normalize_keyword(std::string& value) -> bool {
            if (value.empty() || value.size()>253) return false;
            for (auto& c:value) {
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') ||
                      (c>='0' && c<='9') || c=='-' || c=='.')) return false;
                if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
            }
            return true;
        }

        auto valid_cidr(std::string const& value) -> bool {
            if (value.find('\0') != std::string::npos) return false;
            auto slash = value.find('/');
            if (slash == std::string::npos || slash == 0 || slash + 1 == value.size()) return false;
            if (value.find('/', slash + 1) != std::string::npos) return false;
            auto address = value.substr(0, slash);
            auto prefix = std::string_view(value).substr(slash + 1);
            unsigned bits = 0;
            auto [end, error] = std::from_chars(prefix.data(), prefix.data() + prefix.size(), bits);
            if (error != std::errc{} || end != prefix.data() + prefix.size()) return false;
            auto parsed = platform::parse_ip_address(address);
            return parsed && bits <= (parsed->size == 4 ? 32U : 128U);
        }

        auto valid_port(std::string_view text) -> bool {
            unsigned value=0;
            auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value);
            return !text.empty() && error==std::errc{} && end==text.data()+text.size() && value>0 && value<=65535;
        }

        struct Normalization {
            std::size_t nodes=0;
            std::size_t regex_states=0;
            std::vector<BoundedRegex>* programs=nullptr;
        };
        auto normalize(Rule rule,unsigned depth,Normalization& state) -> std::expected<Rule, Error> {
            if (depth>max_rule_depth || ++state.nodes>max_rules)
                return std::unexpected(Error{ErrorCode::limit,"rule nesting or count exceeds limit"});
            if (rule.type=="all") rule.type="and";
            if (rule.type=="any") rule.type="or";
            if (rule.type=="and" || rule.type=="or" || rule.type=="not") {
                if (!rule.value.empty() || rule.children.empty() || (rule.type=="not" && rule.children.size()!=1))
                    return invalid("invalid logical rule operands");
                for (auto& child:rule.children) {
                    auto normalized=normalize(std::move(child),depth+1,state);
                    if (!normalized) return std::unexpected(std::move(normalized.error()));
                    child=std::move(*normalized);
                }
                return rule;
            }
            if (!rule.children.empty()) return invalid("predicate cannot have children");
            if (rule.type=="domain-suffix" || rule.type=="domain") {
                if (!normalize_domain(rule.value)) return invalid("invalid ASCII domain");
            } else if (rule.type=="domain-keyword") {
                if (!normalize_keyword(rule.value)) return invalid("invalid domain keyword");
            } else if (rule.type=="domain-wildcard") {
                if (rule.value.size()>253 || !rule.value.starts_with("*.") ||
                    !valid_domain(std::string_view(rule.value).substr(2))) return invalid("invalid domain wildcard");
                for (auto& c:rule.value) if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
            } else if (rule.type=="domain-regex" || rule.type=="process-path-regex" || rule.type=="package-name-regex") {
                auto program=BoundedRegex::compile(rule.value);
                if (!program) return invalid(std::string(program.error()));
                state.regex_states+=program->state_count();
                if (state.regex_states>2048)
                    return std::unexpected(Error{ErrorCode::limit,"regular expressions exceed total state limit"});
                if (state.programs) state.programs->push_back(std::move(*program));
            } else if (rule.type=="ip-cidr" || rule.type=="source-ip-cidr" || rule.type=="default-interface-address") {
                if (!valid_cidr(rule.value)) return invalid("invalid IPv4/IPv6 CIDR");
            } else if (rule.type=="network-interface-address") {
                auto colon=rule.value.find(':');
                if (colon==std::string::npos || !parse_network_type(std::string_view(rule.value).substr(0,colon)) ||
                    !valid_cidr(rule.value.substr(colon+1)))
                    return invalid("invalid network-interface-address");
            } else if (rule.type=="ip-version") {
                if (rule.value!="4" && rule.value!="6") return invalid("invalid IP version");
            } else if (rule.type=="ip-is-private" || rule.type=="source-ip-is-private" ||
                       rule.type=="ip-is-cgnat" || rule.type=="source-ip-is-cgnat" ||
                       rule.type=="ip-accept-any" || rule.type=="source-ip-accept-any") {
                if (rule.value!="true") return invalid(rule.type+" requires true");
            } else if (rule.type=="network-is-expensive" || rule.type=="network-is-constrained") {
                if (rule.value!="true" && rule.value!="false") return invalid(rule.type+" requires a boolean");
            } else if (rule.type=="network-type") {
                if (!parse_network_type(rule.value)) return invalid("invalid network-type");
            } else if (rule.type=="process-path" || rule.type=="process-name") {
                if (rule.value.empty() || rule.value.size()>4095 || rule.value.contains('\0') ||
                    (rule.type=="process-path" ? !rule.value.starts_with('/') || rule.value.ends_with('/')
                                               : rule.value.contains('/') || rule.value.size()>255))
                    return invalid("invalid process predicate");
            } else if (rule.type=="source-interface") {
                if (!valid_source_interface(rule.value)) return invalid("invalid source interface");
            } else if (rule.type=="source-uid" || rule.type=="source-gid") {
                auto uid=parse_source_uid(rule.value);
                if (!uid) return invalid("invalid source UID/GID");
                rule.value=std::to_string(*uid);
            } else if (rule.type=="query-type") {
                if (!valid_port(rule.value)) return invalid("invalid DNS query type");
            } else if (rule.type=="port" || rule.type=="source-port") {
                if (!valid_port(rule.value)) return invalid("invalid destination port");
            } else if (rule.type=="port-range" || rule.type=="source-port-range") {
                auto dash=rule.value.find('-');
                if (dash==std::string::npos || rule.value.find('-',dash+1)!=std::string::npos ||
                    !valid_port(std::string_view(rule.value).substr(0,dash)) ||
                    !valid_port(std::string_view(rule.value).substr(dash+1))) return invalid("invalid destination port range");
                unsigned first=0,last=0;
                std::from_chars(rule.value.data(),rule.value.data()+dash,first);
                std::from_chars(rule.value.data()+dash+1,rule.value.data()+rule.value.size(),last);
                if (first>last) return invalid("invalid destination port range");
            } else if (rule.type=="rule-set") {
                if (state.programs) return invalid("unbound rule-set reference");
                if (rule.value.empty() || rule.value.size()>255 || rule.value.contains('\0'))
                    return invalid("invalid rule-set tag");
            } else if (rule.type=="dscp") {
                if (rule.value.size()>255 || !parse_dscp_list(rule.value))
                    return invalid("dscp requires values in 0..63");
            } else if (rule.type=="source-mac" || rule.type=="gateway-mac" || rule.type=="wifi-bssid") {
                if (!parse_mac(rule.value)) return invalid("invalid MAC address");
                std::ranges::transform(rule.value,rule.value.begin(),[](char c) {
                    return c>='A' && c<='F' ? static_cast<char>(c+('a'-'A')) : c;
                });
            } else if (rule.type=="tls-ech") {
                if (rule.value!="true" && rule.value!="false") return invalid("tls-ech requires a boolean");
            } else if (rule.type=="protocol") {
                if (!parse_protocol(rule.value)) return invalid("invalid protocol");
            } else if (rule.type=="route-mode") {
                if (!parse_route_mode(rule.value)) return invalid("invalid route-mode");
            } else if (rule.type=="network") {
                if (rule.value!="tcp" && rule.value!="udp" && rule.value!="icmp") return invalid("invalid network");
            } else if (rule.type=="client") {
                if (!valid_client_name(rule.value)) return invalid("invalid client name");
                for (auto& c : rule.value) if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
            } else if (rule.type=="inbound" || rule.type=="auth-user" ||
                       rule.type=="wifi-ssid" || rule.type=="source-user" || rule.type=="package-name") {
                if (rule.value.empty() || rule.value.size()>255 || rule.value.find('\0')!=std::string::npos)
                    return invalid("invalid metadata name");
            } else return invalid("unsupported rule type: "+rule.type);
            return rule;
        }
    }

    auto parse_source_uid(std::string_view text) noexcept -> std::optional<std::uint32_t> {
        if (text.empty()) return {};
        std::uint32_t value=0;
        auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value);
        if (error!=std::errc{} || end!=text.data()+text.size() || value==std::numeric_limits<std::uint32_t>::max())
            return {};
        return value;
    }

    auto normalize_rule(Rule rule) -> std::expected<Rule, Error> {
        Normalization state;
        return normalize(std::move(rule),1,state);
    }

    namespace {
        auto normalize_rules(RuleSet set,Normalization state) -> std::expected<RuleSet, Error> {
            if (set.version!=2) return invalid("unsupported rule schema version");
            if (set.rules.size()>max_rules)
                return std::unexpected(Error{ErrorCode::limit,"rule nesting or count exceeds limit"});
            for (auto& entry:set.rules) {
                auto normalized=normalize(std::move(entry),1,state);
                if (!normalized) return std::unexpected(std::move(normalized.error()));
                entry=std::move(*normalized);
            }
            return set;
        }
    }
    auto normalize_set(RuleSet set) -> std::expected<RuleSet, Error> {
        return normalize_rules(std::move(set),{});
    }
    auto normalize_matcher_set(RuleSet set,std::vector<BoundedRegex>& expressions) -> std::expected<RuleSet, Error> {
        return normalize_rules(std::move(set),{.programs=&expressions});
    }
}
