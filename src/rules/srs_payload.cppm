// Parser for the decompressed SRS rule stream.
export module rules.srs_payload;
import std;
import platform.ip_address;
import rules;
import rules.regex;
import rules.srs_domain;

export namespace rules {
    [[nodiscard]] auto decode_srs_payload(std::span<std::uint8_t const> bytes, bool ip_cidr_match_source=false,
        bool lenient=false) -> std::expected<RuleSet,Error>;
}

namespace rules {
    namespace {
        using srs_detail::Reader;
        using srs_detail::failure;
        using srs_detail::read_domain_set;
        struct Field {
            std::string_view type;
            unsigned group;
            std::size_t text_limit=253;
        };
        auto scalar_field(std::uint8_t item) noexcept -> std::optional<Field> {
            switch (item) {
            case 0: return Field{"query-type",5,0};
            case 1: return Field{"network",0};
            case 3: return Field{"domain-keyword",1};
            case 4: return Field{"domain-regex",1,255};
            case 7: return Field{"source-port",2,0};
            case 8: return Field{"source-port-range",2};
            case 9: return Field{"port",3,0};
            case 10: return Field{"port-range",3};
            case 11: return Field{"process-name",6,255};
            case 12: return Field{"process-path",7,4095};
            case 17: return Field{"process-path-regex",8,255};
            default: return {};
            }
        }
        // Go counts UTF-8 runes and process paths may contain non-ASCII
        // bytes. Restrict the imported pattern to atoms that only consume
        // ASCII, so byte and rune matching have the same result.
        auto portable_process_regex(std::string_view pattern) noexcept -> bool {
            bool escaped=false,in_class=false;
            for (std::size_t i=0;i<pattern.size();++i) {
                auto ch=pattern[i];
                if (static_cast<unsigned char>(ch)>=128) return false;
                if (std::exchange(escaped,false)) continue;
                if (ch=='\\') escaped=true;
                else if (ch==']') in_class=false;
                else if (!in_class) {
                    if (ch=='.') return false;
                    if (ch=='[') {
                        if (i+1<pattern.size() && pattern[i+1]=='^') return false;
                        in_class=true;
                    }
                }
            }
            return true;
        }
        auto grouped(Reader& reader,std::vector<Rule> rules,std::string_view op) -> std::expected<Rule,Error> {
            if(rules.empty())return failure("SRS condition has no values");
            if(rules.size()==1)return std::move(rules.front());
            if(!reader.take_node())return std::unexpected(Error{ErrorCode::limit,"SRS rule count exceeds limit"});
            return Rule{std::string(op),{},std::move(rules)};
        }
        auto read_ip_set(Reader& reader,std::vector<Rule>& group,bool source) -> std::expected<void,Error> {
            auto version=reader.byte();
            if(!version || *version!=1)return failure("unsupported SRS IP set version");
            std::uint64_t count=0;
            for(unsigned i=0;i<8;++i) {
                auto b=reader.byte();if(!b)return failure("truncated SRS IP set count");
                count=(count<<8)|*b;
            }
            if(!count || count>max_rules)return failure("invalid SRS IP set count");
            for(std::uint64_t i=0;i<count;++i) {
                auto length=reader.varint();
                if(!length || (*length!=4 && *length!=16) || *length>reader.input.size()-reader.offset)
                    return failure("invalid SRS IP range start");
                std::array<std::uint8_t,16> first{},last{};
                std::copy_n(reader.input.begin()+reader.offset,*length,first.begin());reader.offset+=*length;
                auto end_length=reader.varint();
                if(!end_length || *end_length!=*length || *end_length>reader.input.size()-reader.offset)
                    return failure("invalid SRS IP range end");
                std::copy_n(reader.input.begin()+reader.offset,*length,last.begin());reader.offset+=*length;
                auto size=static_cast<std::size_t>(*length);
                if(std::lexicographical_compare(last.begin(),last.begin()+size,first.begin(),first.begin()+size))
                    return failure("reversed SRS IP range");
                for(;;) {
                    unsigned host=0;auto end=first;
                    // Grow the largest aligned CIDR block contained in the range.
                    for(unsigned bit=0;bit<size*8;++bit) {
                        auto index=size-1-bit/8;auto mask=static_cast<std::uint8_t>(1u<<(bit%8));
                        if(first[index]&mask)break;
                        auto candidate=end;candidate[index]|=mask;
                        if(std::lexicographical_compare(last.begin(),last.begin()+size,candidate.begin(),candidate.begin()+size))break;
                        end=candidate;++host;
                    }
                    if(!reader.take_node())return std::unexpected(Error{ErrorCode::limit,"SRS rule count exceeds limit"});
                    auto text=platform::format_ip_address(std::span(first).first(size));
                    if(!text)return failure("invalid SRS IP address");
                    group.push_back({source ? "source-ip-cidr" : "ip-cidr",
                        *text+"/"+std::to_string(size*8-host),{}});
                    if(std::equal(end.begin(),end.begin()+size,last.begin()))break;
                    first=end;
                    for(auto j=size;j>0;--j)if(++first[j-1])break;
                }
            }
            return {};
        }
        auto skip_bytes(Reader& reader, std::size_t count) -> bool {
            if (count > reader.input.size() - reader.offset) return false;
            reader.offset += count;
            return true;
        }
        auto skip_string_list(Reader& reader) -> bool {
            auto count = reader.varint();
            if (!count || *count > max_rules) return false;
            for (std::uint64_t i = 0; i < *count; ++i) {
                auto len = reader.varint();
                if (!len || !skip_bytes(reader, static_cast<std::size_t>(*len))) return false;
            }
            return true;
        }
        auto skip_prefix(Reader& reader) -> bool {
            auto len = reader.varint();
            if (!len || (*len != 4 && *len != 16)) return false;
            return skip_bytes(reader, static_cast<std::size_t>(*len) + 1);
        }
        auto skip_adguard_set(Reader& reader) -> bool {
            if (!reader.byte()) return false;
            for (int w = 0; w < 2; ++w) {
                auto words = reader.varint();
                if (!words || *words > (reader.input.size() - reader.offset) / 8) return false;
                if (!skip_bytes(reader, static_cast<std::size_t>(*words) * 8)) return false;
            }
            auto labels = reader.varint();
            if (!labels || !skip_bytes(reader, static_cast<std::size_t>(*labels))) return false;
            return true;
        }
        auto skip_unsupported_item(Reader& reader, std::uint8_t item) -> std::expected<void, Error> {
            if (!reader.lenient) return failure("unsupported SRS condition " + std::to_string(item));
            switch (item) {
            case 13: case 14: case 15: case 23:
                if (!skip_string_list(reader)) return failure("invalid SRS skipped string condition");
                return {};
            case 16:
                if (!skip_adguard_set(reader)) return failure("invalid SRS AdGuard set");
                return {};
            case 18: {
                auto n = reader.varint();
                if (!n || !skip_bytes(reader, static_cast<std::size_t>(*n)))
                    return failure("invalid SRS network_type condition");
                return {};
            }
            case 19: case 20: return {};
            case 21: {
                auto map_sz = reader.varint();
                if (!map_sz || *map_sz > 256) return failure("invalid SRS interface map");
                for (std::uint64_t i = 0; i < *map_sz; ++i) {
                    if (!reader.byte()) return failure("truncated SRS interface key");
                    auto pc = reader.varint();
                    if (!pc || *pc > max_rules) return failure("invalid SRS prefix count");
                    for (std::uint64_t j = 0; j < *pc; ++j)
                        if (!skip_prefix(reader)) return failure("invalid SRS interface prefix");
                }
                return {};
            }
            case 22: {
                auto pc = reader.varint();
                if (!pc || *pc > max_rules) return failure("invalid SRS prefix count");
                for (std::uint64_t j = 0; j < *pc; ++j)
                    if (!skip_prefix(reader)) return failure("invalid SRS default interface prefix");
                return {};
            }
            default:
                return failure("unsupported SRS condition " + std::to_string(item));
            }
        }

        auto read_rule(Reader& reader,unsigned depth) -> std::expected<std::optional<Rule>,Error> {
            if(depth>max_rule_depth)return std::unexpected(Error{ErrorCode::limit,"SRS rule nesting exceeds limit"});
            auto type=reader.byte();if(!type)return failure("truncated SRS rule");
            if(*type==1) {
                auto mode=reader.byte();auto count=reader.varint();
                if(!mode || *mode>1 || !count || !*count || *count>max_rules)return failure("invalid SRS logical rule");
                std::vector<Rule> children;
                for(std::uint64_t i=0;i<*count;++i) {
                    auto child=read_rule(reader,depth+1);if(!child)return std::unexpected(std::move(child.error()));
                    if(*child) children.push_back(std::move(**child));
                }
                auto invert=reader.byte();if(!invert || *invert>1)return failure("invalid SRS inversion");
                if(children.empty()) {
                    if(reader.lenient) return std::optional<Rule>{};
                    return failure("SRS condition has no values");
                }
                auto result=grouped(reader,std::move(children),*mode ? "or" : "and");if(!result)return std::unexpected(std::move(result.error()));
                if(*invert) {
                    if(!reader.take_node())return std::unexpected(Error{ErrorCode::limit,"SRS rule count exceeds limit"});
                    return std::optional<Rule>{Rule{"not",{},std::vector<Rule>{std::move(*result)}}};
                }
                return std::optional<Rule>{std::move(*result)};
            }
            if(*type!=0)return failure("unknown SRS rule type");
            std::array<std::vector<Rule>,9> groups;
            std::array<bool,256> seen{};
            for(;;) {
                auto item=reader.byte();if(!item)return failure("truncated SRS condition");
                if(*item==255)break;
                if(seen[*item])return failure("duplicate SRS condition");seen[*item]=true;
                if(*item==2) {
                    auto parsed=read_domain_set(reader,groups[1]);
                    if(!parsed)return std::unexpected(std::move(parsed.error()));
                    continue;
                }
                if(*item==5 || *item==6) {
                    bool source=*item==5 || reader.ip_cidr_match_source;
                    auto parsed=read_ip_set(reader,groups[source ? 4 : 1],source);
                    if(!parsed)return std::unexpected(std::move(parsed.error()));
                    continue;
                }
                auto field=scalar_field(*item);
                if (!field) {
                    if (auto skipped = skip_unsupported_item(reader, *item); !skipped)
                        return std::unexpected(std::move(skipped.error()));
                    continue;
                }
                auto count=reader.varint();if(!count || !*count || *count>max_rules)return failure("invalid SRS condition count");
                for(std::uint64_t i=0;i<*count;++i) {
                    if(!reader.take_node())return std::unexpected(Error{ErrorCode::limit,"SRS rule count exceeds limit"});
                    std::string value;
                    if (!field->text_limit) {
                        auto hi=reader.byte(),lo=reader.byte();if(!hi || !lo)return failure("truncated SRS number");
                        value=std::to_string((unsigned(*hi)<<8)|*lo);
                    } else {
                        auto text=reader.string(field->text_limit);if(!text)return failure("invalid SRS string");value=std::move(*text);
                    }
                    if(*item==8 || *item==10) {
                        auto colon=value.find(':');
                        if(colon==std::string::npos || colon==0 || value.find(':',colon+1)!=std::string::npos)
                            return failure("SRS port range including zero or malformed range is unsupported");
                        if(colon+1==value.size())value.append("65535");
                        value[colon]='-';
                    }
                    if (*item==17 && !portable_process_regex(value)) {
                        if (reader.lenient) continue;
                        return failure("SRS process regex must consume only ASCII characters");
                    }
                    if(*item==3) {
                        if (reader.lenient) {
                            for (auto& c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
                        } else if(std::ranges::any_of(value,[](char c){return c>='A' && c<='Z';}))
                            return failure("unsupported SRS uppercase domain keyword");
                    }
                    if ((*item == 4 || *item == 17) && reader.lenient && !BoundedRegex::compile(value)) continue;
                    groups[field->group].push_back({std::string(field->type),std::move(value),{}});
                }
            }
            auto invert=reader.byte();if(!invert || *invert>1)return failure("invalid SRS inversion");
            std::vector<Rule> parts;
            for(auto& group:groups)if(!group.empty()) {
                auto part=grouped(reader,std::move(group),"or");if(!part)return std::unexpected(std::move(part.error()));
                parts.push_back(std::move(*part));
            }
            if(parts.empty()) {
                if(reader.lenient) return std::optional<Rule>{};
                return failure("SRS condition has no values");
            }
            auto result=grouped(reader,std::move(parts),"and");if(!result)return std::unexpected(std::move(result.error()));
            if(*invert) {
                if(!reader.take_node())return std::unexpected(Error{ErrorCode::limit,"SRS rule count exceeds limit"});
                return std::optional<Rule>{Rule{"not",{},std::vector<Rule>{std::move(*result)}}};
            }
            return std::optional<Rule>{std::move(*result)};
        }
    }
    auto decode_srs_payload(std::span<std::uint8_t const> bytes, bool ip_cidr_match_source, bool lenient) -> std::expected<RuleSet,Error> {
        if(bytes.size()>max_input_bytes)return std::unexpected(Error{ErrorCode::limit,"SRS payload exceeds 32 MiB"});
        Reader reader{bytes,0,0,ip_cidr_match_source,lenient};auto count=reader.varint();
        if(!count || !*count || *count>max_rules)return failure("invalid SRS rule count");
        RuleSet result{{},2};
        for(std::uint64_t i=0;i<*count;++i) {
            auto rule=read_rule(reader,1);if(!rule)return std::unexpected(std::move(rule.error()));
            if(*rule) result.rules.push_back(std::move(**rule));
        }
        if(reader.offset!=bytes.size())return failure("trailing SRS payload bytes");
        // Compile validates both the translated predicates and the final tree
        // depth, including grouping and inversion nodes introduced above.
        auto normalized=normalize_set(std::move(result));if(!normalized)return std::unexpected(std::move(normalized.error()));
        auto checked=Matcher::compile(*normalized);if(!checked)return std::unexpected(std::move(checked.error()));
        return normalized;
    }
}
