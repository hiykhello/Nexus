export module dns.policy;
import std;
import rules;
import rules.domain_pattern;

export namespace policy {
    enum class DnsPattern : std::uint8_t { name, keyword, wildcard };
    enum class DnsAction : std::uint8_t { route, reject, route_options, evaluate, respond, predefined };
    enum class ResponseSection : std::uint8_t { answer, authority, additional };
    struct PredefinedRecord {
        ResponseSection section;
        std::string name;
        std::uint16_t type,klass;
        std::uint32_t ttl;
        std::vector<std::uint8_t> data;
    };
    struct PredefinedResponse { std::uint8_t rcode=0;std::vector<PredefinedRecord> records; };
    struct ResponsePrefix { std::array<std::uint8_t,16> address{};std::uint8_t size=0,bits=0; };
    struct ResponseCondition {
        std::optional<std::uint16_t> rcode;
        std::optional<ResponseSection> section;
        std::optional<std::uint16_t> record_type;
        bool invert=false;
        std::optional<ResponsePrefix> address;
        bool address_private=false,address_any=false;
        std::optional<std::string> record_name;
        std::optional<std::uint16_t> record_class;
        std::optional<std::uint32_t> record_ttl_min,record_ttl_max;
        std::optional<std::vector<std::uint8_t>> record_data;
        std::optional<bool> authenticated_data;
    };
    // Borrowed for synchronous question selection. The network is the
    // originating business flow, independent of the DNS transport.
    struct DnsContext {
        std::optional<rules::Network> network;
        std::optional<std::uint16_t> source_port;
        std::optional<std::span<std::uint8_t const>> source_ip_bytes;
        std::optional<std::string_view> inbound,auth_user;
        std::optional<bool> query_dnssec;
        std::optional<bool> query_checking_disabled;
        std::optional<bool> query_authenticated_data;
        bool subnet_known=false;
        std::optional<ResponsePrefix> query_subnet;
        std::uint16_t query_class=1;
        // Present empty means a response with no address answers.
        std::optional<std::span<rules::ProgramAddress const>> response_addresses;
        std::optional<std::string_view> source_interface;
    };
    struct DnsRule {
        std::string domain;
        bool suffix=false;
        std::size_t server=0;
        std::optional<std::uint16_t> query_type;
        std::optional<std::uint16_t> query_class;
        DnsPattern pattern=DnsPattern::name;
        DnsAction action=DnsAction::route;
        bool match_all=false;
        bool invert=false;
        bool reject_drop=false;
        std::optional<bool> disable_cache;
#ifdef NEXUS_DNS_RESPONSE
        std::optional<bool> query_dnssec;
        std::optional<bool> query_checking_disabled;
        std::optional<bool> query_authenticated_data;
        std::optional<ResponsePrefix> query_subnet;
        bool match_response=false;
        bool race=false,speculative=false;
        std::optional<ResponseCondition> response;
        std::optional<PredefinedResponse> predefined;
        std::optional<std::uint32_t> timeout_ms;
        std::optional<std::uint32_t> rewrite_ttl;
        std::optional<ResponsePrefix> client_subnet;
        bool remove_client_subnet=false;
#else
        static constexpr std::optional<bool> query_dnssec{};
        static constexpr std::optional<bool> query_checking_disabled{};
        static constexpr std::optional<bool> query_authenticated_data{};
        static constexpr std::optional<ResponsePrefix> query_subnet{};
        static constexpr bool match_response=false;
        static constexpr bool race=false,speculative=false;
        static constexpr std::optional<ResponseCondition> response{};
        static constexpr std::optional<PredefinedResponse> predefined{};
        static constexpr std::optional<std::uint32_t> timeout_ms{};
        static constexpr std::optional<std::uint32_t> rewrite_ttl{};
        static constexpr std::optional<ResponsePrefix> client_subnet{};
        static constexpr bool remove_client_subnet=false;
#endif
        // All context predicates must match. Compiled at configuration time,
        // with the same unknown and source-address semantics as traffic rules.
        std::vector<rules::Rule> context;
        std::optional<rules::Matcher> context_matcher;
        bool has_rule_set=false, rule_set_needs_source=false, rule_set_needs_auth_user=false, rule_set_needs_response=false;
        std::optional<rules::Matcher> rule_set_matcher;
        // Empty optionals denote the anonymous evaluate slot.
        std::optional<std::string> evaluate_tag,match_response_tag;
    };
    struct DnsDecision {
        DnsAction action=DnsAction::route;
        std::size_t server=0;
        bool disable_cache=false;
        auto operator==(DnsDecision const&) const -> bool = default;
    };
    // Before any family performs I/O, reject a definitely matched terminal
    // question-only reject. Response-dependent predicates are unknown until
    // evaluated, so a negative or route whose result may change is a barrier.
    inline auto dns_preflight_reject(std::span<DnsRule const> entries,std::string_view name,std::uint16_t type,
        DnsContext const& context={}) noexcept -> bool;
#ifdef NEXUS_DNS_RESPONSE
    inline auto dns_has_response_program(std::span<DnsRule const> rules) noexcept -> bool {
        return std::ranges::any_of(rules,[](auto const& rule) {
            return rule.match_response || rule.timeout_ms || rule.rewrite_ttl || rule.client_subnet || rule.remove_client_subnet || rule.action==DnsAction::evaluate || rule.action==DnsAction::respond || rule.action==DnsAction::predefined;
        });
    }
    inline auto dns_has_concurrent_rules(std::span<DnsRule const> rules) noexcept -> bool {
        return std::ranges::any_of(rules,[](auto const& rule){return rule.race || rule.speculative;});
    }
#endif
    struct DnsContextRequirements { bool source=false,auth_user=false; };
    inline constexpr std::size_t max_named_dns_responses=16;
    [[nodiscard]] inline auto validate_dns_response_tags(std::span<DnsRule const> entries) noexcept -> bool {
        std::array<std::string_view,max_named_dns_responses> names{};std::size_t count=0;
        for(auto const& rule:entries) {
            if(rule.match_response_tag && std::ranges::find(std::span(names).first(count),*rule.match_response_tag)==std::span(names).first(count).end())return false;
            if(rule.evaluate_tag) {
                if(count==names.size() || std::ranges::find(std::span(names).first(count),*rule.evaluate_tag)!=std::span(names).first(count).end())return false;
                names[count++]=*rule.evaluate_tag;
            }
        }
        return true;
    }
    // The concurrent walk keeps every response generation until the request
    // ends, since an armed rule can still refer to an older anonymous slot.
    [[nodiscard]] inline auto validate_dns_concurrency(std::span<DnsRule const> entries) noexcept -> bool {
        if(!std::ranges::any_of(entries,[](auto const& rule){return rule.race || rule.speculative;}))return true;
        std::size_t queries=0,races=0;
        for(auto const& rule:entries) {
            queries+=rule.action==DnsAction::evaluate || (rule.action==DnsAction::route && rule.speculative);
            races+=rule.race;
        }
        return queries<=32 && races<=64;
    }
    inline auto dns_context_requirements(std::span<DnsRule const> entries) noexcept -> DnsContextRequirements {
        DnsContextRequirements result;
        for (auto const& rule:entries) for (auto const& field:rule.context) {
            result.source |= field.type!="source-interface" && field.type.starts_with("source-");
            result.auth_user |= field.type=="auth-user";
        }
        for (auto const& rule:entries) {
            result.source |= rule.rule_set_needs_source;
            result.auth_user |= rule.rule_set_needs_auth_user;
        }
        return result;
    }
    // Destination address predicates require an explicit response context.
    // Target ports cannot be derived from DNS and remain unsupported.
    inline auto bind_dns_rule_set(DnsRule& rule,rules::RuleSet set) -> bool {
        if (!rule.has_rule_set || set.rules.empty()) return false;
        auto normalized=rules::normalize_set(std::move(set));
        if (!normalized) return false;
        set=std::move(*normalized);
        bool source=false,auth=false,response=false;
        auto supported=[&](auto&& self,rules::Rule const& node) -> bool {
            if (node.type=="and" || node.type=="or" || node.type=="not")
                return std::ranges::all_of(node.children,[&](auto const& child){return self(self,child);});
            source |= node.type!="source-interface" && node.type.starts_with("source-");
            auth |= node.type=="auth-user";
            response |= node.type=="ip-cidr" || node.type=="ip-is-private" || node.type=="ip-version";
            return node.type=="domain" || node.type=="domain-suffix" || node.type=="domain-keyword" ||
                node.type=="domain-wildcard" || node.type=="domain-regex" ||
                node.type=="query-type" || node.type=="network" || node.type=="source-ip-cidr" || node.type=="source-ip-is-private" ||
                node.type=="source-port" || node.type=="source-port-range" || node.type=="source-interface" ||
                node.type=="inbound" || node.type=="auth-user" ||
                (rule.match_response && (node.type=="ip-cidr" || node.type=="ip-is-private" || node.type=="ip-version"));
        };
        if (!std::ranges::all_of(set.rules,[&](auto const& node){return supported(supported,node);})) return false;
        if (set.rules.size()>1) set.rules={rules::Rule{"or","",std::move(set.rules)}};
        set.version=2;
        auto compiled=rules::Matcher::compile(set);
        if (!compiled) return false;
        rule.rule_set_matcher=std::move(*compiled);rule.rule_set_needs_source=source;rule.rule_set_needs_auth_user=auth;rule.rule_set_needs_response=response;
        return true;
    }
    inline auto normalize_dns_owner(std::string& name) -> bool {
        if (name==".") return true;
        if (name.ends_with('.')) name.pop_back();
        if (name.empty() || name.size()>253) return false;
        std::size_t length=0;
        for (auto& c:name) {
            auto byte=static_cast<unsigned char>(c);
            if (c=='.') { if (!length || length>63) return false;length=0;continue; }
            if (byte<33 || byte>126 || c=='\\' || ++length>63) return false;
            if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
        }
        return length!=0;
    }
    inline auto normalize_dns_rule(DnsRule& rule,std::size_t servers,bool allow_unloaded_rule_set=false) -> bool {
#ifndef NEXUS_DNS_RESPONSE
        if (rule.action==DnsAction::evaluate || rule.action==DnsAction::respond || rule.action==DnsAction::predefined) return false;
#endif
        if ((rule.action!=DnsAction::route && rule.action!=DnsAction::reject && rule.action!=DnsAction::route_options && rule.action!=DnsAction::evaluate && rule.action!=DnsAction::respond && rule.action!=DnsAction::predefined) ||
            ((rule.action==DnsAction::route || rule.action==DnsAction::evaluate) ? rule.server>=servers : rule.server!=0) ||
            (rule.action==DnsAction::route_options && !rule.disable_cache && !rule.timeout_ms && !rule.rewrite_ttl && !rule.client_subnet && !rule.remove_client_subnet) ||
            (rule.rewrite_ttl && rule.action!=DnsAction::route && rule.action!=DnsAction::route_options && rule.action!=DnsAction::evaluate) ||
            ((rule.client_subnet || rule.remove_client_subnet) && rule.action!=DnsAction::route && rule.action!=DnsAction::route_options && rule.action!=DnsAction::evaluate) ||
            (rule.client_subnet && rule.remove_client_subnet) ||
            (rule.reject_drop && rule.action!=DnsAction::reject) ||
            ((rule.action==DnsAction::reject || rule.action==DnsAction::respond || rule.action==DnsAction::predefined) && rule.disable_cache) ||
            ((rule.action==DnsAction::reject || rule.action==DnsAction::respond || rule.action==DnsAction::predefined) && rule.timeout_ms) ||
            (rule.timeout_ms && !*rule.timeout_ms) ||
            ((rule.action==DnsAction::predefined)!=rule.predefined.has_value()) ||
            (rule.query_type && !*rule.query_type) || (rule.query_class && !*rule.query_class) || rule.context.size()>8 ||
            (rule.has_rule_set && !rule.rule_set_matcher && !allow_unloaded_rule_set) || (!rule.has_rule_set && rule.rule_set_matcher) ||
            (rule.rule_set_needs_response && !rule.match_response) ||
            (rule.race && (!rule.match_response || rule.speculative || (rule.action!=DnsAction::route && rule.action!=DnsAction::respond && rule.action!=DnsAction::reject && rule.action!=DnsAction::predefined))) ||
            (rule.speculative && rule.action!=DnsAction::route && rule.action!=DnsAction::evaluate) ||
            (rule.evaluate_tag && (rule.action!=DnsAction::evaluate || rule.evaluate_tag->empty() || rule.evaluate_tag->size()>255 || rule.evaluate_tag->find('\0')!=std::string::npos)) ||
            (rule.match_response_tag && (!rule.match_response || rule.match_response_tag->empty() || rule.match_response_tag->size()>255 || rule.match_response_tag->find('\0')!=std::string::npos))) return false;
        if (rule.response && (!rule.match_response || (!rule.response->authenticated_data && !rule.response->rcode && !rule.response->section && !rule.response->record_type && !rule.response->address && !rule.response->address_private && !rule.response->address_any && !rule.response->record_name && !rule.response->record_class && !rule.response->record_ttl_min && !rule.response->record_ttl_max && !rule.response->record_data) ||
            (rule.response->rcode && *rule.response->rcode>4095) ||
            (rule.response->record_type && !*rule.response->record_type) ||
            (rule.response->record_class && !*rule.response->record_class) ||
            (rule.response->record_ttl_min && rule.response->record_ttl_max && *rule.response->record_ttl_min>*rule.response->record_ttl_max) ||
            (rule.response->record_data && rule.response->record_data->size()>4096) ||
            (rule.response->address && ((rule.response->address->size!=4 && rule.response->address->size!=16) || rule.response->address->bits>rule.response->address->size*8)) ||
            (rule.response->section && *rule.response->section!=ResponseSection::answer &&
             *rule.response->section!=ResponseSection::authority && *rule.response->section!=ResponseSection::additional))) return false;
#ifdef NEXUS_DNS_RESPONSE
        if (rule.client_subnet) {
            auto const& subnet=*rule.client_subnet;
            if ((subnet.size!=4 && subnet.size!=16) || subnet.bits>subnet.size*8) return false;
            auto bytes=(std::size_t(subnet.bits)+7)/8;
            if (subnet.bits%8 && (subnet.address[bytes-1] & ((1u<<(8-subnet.bits%8))-1u))) return false;
            if (std::ranges::any_of(std::span(subnet.address).subspan(bytes),[](auto c){return c!=0;})) return false;
        }
        if (rule.response && rule.response->record_name && !normalize_dns_owner(*rule.response->record_name)) return false;
        if (rule.predefined) {
            if (rule.predefined->rcode>15 || rule.predefined->records.size()>128) return false;
            for (auto& record:rule.predefined->records) {
                if (!record.type || record.type==41 || !record.klass || record.data.size()>4096 ||
                    (record.section!=ResponseSection::answer && record.section!=ResponseSection::authority && record.section!=ResponseSection::additional)) return false;
                if (record.name!="@" && !normalize_dns_owner(record.name)) return false;
            }
        }
#endif
        rule.context_matcher.reset();
        for (auto const& field:rule.context)
            if (!field.children.empty() || (field.type!="network" && field.type!="source-ip-cidr" &&
                field.type!="source-ip-is-private" && field.type!="source-port" && field.type!="source-port-range" &&
                field.type!="source-interface" && field.type!="inbound" && field.type!="auth-user")) return false;
        if (!rule.context.empty()) {
            rules::Rule expression{"and","",rule.context};
            auto matcher=rules::Matcher::compile({{std::move(expression)},2});
            if (!matcher) return false;
            rule.context_matcher=std::move(*matcher);
        }
        if(rule.query_subnet && ((rule.query_subnet->size!=4 && rule.query_subnet->size!=16) || rule.query_subnet->bits>rule.query_subnet->size*8)) return false;
        if (rule.match_all) return rule.domain.empty() && !rule.query_type && !rule.query_class && !rule.query_dnssec && !rule.query_checking_disabled && !rule.query_authenticated_data && !rule.query_subnet && rule.context.empty() && !rule.has_rule_set && !rule.suffix && rule.pattern==DnsPattern::name;
        if (rule.domain.empty()) return (rule.query_type.has_value() || rule.query_class.has_value() || rule.query_dnssec.has_value() || rule.query_checking_disabled.has_value() || rule.query_authenticated_data.has_value() || rule.query_subnet.has_value() || !rule.context.empty() || rule.has_rule_set) && !rule.suffix && rule.pattern==DnsPattern::name;
        if (rule.pattern==DnsPattern::keyword) {
            if (rule.suffix || rule.domain.size()>253) return false;
            for (auto& c:rule.domain) {
                if (c<33 || c>126 || c=='\\') return false;
                if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
            }
            return true;
        }
        if ((rule.pattern!=DnsPattern::name && rule.pattern!=DnsPattern::wildcard) ||
            (rule.pattern==DnsPattern::wildcard && rule.suffix)) return false;
        auto normalized=rules::normalize_rule({rule.pattern==DnsPattern::wildcard ? "domain-wildcard" : "domain-suffix",rule.domain});
        if (!normalized) return false;
        rule.domain=std::move(normalized->value);
        return true;
    }
    // DNS questions have their own wire-name validation. Match these borrowed
    // ASCII names directly; traffic hostname validation would reject labels
    // that the existing DNS transport accepts.
    inline auto dns_question_truth(DnsRule const& rule,std::string_view name,std::uint16_t type,DnsContext const& context={}) noexcept -> std::optional<rules::Matcher::Truth> {
        using Truth=rules::Matcher::Truth;
        if (!rule.context.empty() && ((context.source_port && !*context.source_port) ||
            (context.source_ip_bytes && context.source_ip_bytes->size()!=4 && context.source_ip_bytes->size()!=16) ||
            (context.network && *context.network!=rules::Network::tcp && *context.network!=rules::Network::udp))) return {};
        if (!rule.context.empty()) for (auto value:{context.inbound,context.auth_user})
            if (value && (value->empty() || value->size()>255 || value->find('\0')!=std::string_view::npos)) return {};
        if (rule.query_type && *rule.query_type!=type) return Truth::no;
        if (rule.query_class && *rule.query_class!=context.query_class) return Truth::no;
        if (!rule.domain.empty()) {
            auto kind=rule.pattern==DnsPattern::keyword ? rules::DomainPattern::keyword :
                rule.pattern==DnsPattern::wildcard ? rules::DomainPattern::wildcard :
                rule.suffix ? rules::DomainPattern::suffix : rules::DomainPattern::exact;
            if (!rules::domain_pattern_matches(kind,name,rule.domain)) return Truth::no;
        }
        auto truth=Truth::yes;
        for (auto [wanted,actual] : {std::pair{rule.query_dnssec,context.query_dnssec},
                 std::pair{rule.query_checking_disabled,context.query_checking_disabled},
                 std::pair{rule.query_authenticated_data,context.query_authenticated_data}}) {
            if (!wanted) continue;
            if (!actual) truth=Truth::unknown;
            else if (*actual!=*wanted) return Truth::no;
        }
        if(rule.query_subnet) {
            if(!context.subnet_known) truth=Truth::unknown;
            else if(!context.query_subnet) return Truth::no;
            else {
                auto const& actual=*context.query_subnet;auto const& wanted=*rule.query_subnet;
                if((actual.size!=4 && actual.size!=16) || actual.bits>actual.size*8) return {};
                if(actual.size!=wanted.size || actual.bits<wanted.bits) return Truth::no;
                auto whole=wanted.bits/8,remaining=wanted.bits%8;
                for(unsigned i=0;i<whole;++i) if(actual.address[i]!=wanted.address[i]) return Truth::no;
                if(remaining && ((actual.address[whole]^wanted.address[whole]) & (0xffu<<(8-remaining)))) return Truth::no;
            }
        }
        if (rule.has_rule_set) {
            if (!rule.rule_set_matcher) return {};
            auto domain=rules::valid_domain(name) ? std::optional(name) : std::nullopt;
            auto qtype=type ? std::optional(type) : std::nullopt;
            auto result=rule.rule_set_matcher->match_truth_mapped({.domain=domain,.network=context.network,.source_port=context.source_port,
                .source_ip_bytes=context.source_ip_bytes,.inbound=context.inbound,.auth_user=context.auth_user,
                .query_type=qtype,.source_interface=context.source_interface},
                rule.match_response ? context.response_addresses : std::nullopt);
            if (!result) return {};
            if (*result==Truth::no) return Truth::no;
            if (*result==Truth::unknown) truth=Truth::unknown;
        }
        if (rule.context.empty()) return truth;
        if (!rule.context_matcher) return {};
        auto result=rule.context_matcher->match_truth_mapped({.network=context.network,.source_port=context.source_port,
            .source_ip_bytes=context.source_ip_bytes,.inbound=context.inbound,.auth_user=context.auth_user,
            .source_interface=context.source_interface});
        if (!result) return {};
        if(*result==Truth::no) return Truth::no;
        return truth==Truth::unknown ? Truth::unknown : *result;
    }
    inline auto dns_rule_matches(DnsRule const& rule,std::string_view name,std::uint16_t type,DnsContext const& context={}) noexcept -> bool {
        auto truth=dns_question_truth(rule,name,type,context);
        if (!truth || *truth==rules::Matcher::Truth::unknown) return false;
        return rule.invert ? *truth==rules::Matcher::Truth::no : *truth==rules::Matcher::Truth::yes;
    }
    inline auto dns_preflight_reject(std::span<DnsRule const> entries,std::string_view name,std::uint16_t type,
        DnsContext const& context) noexcept -> bool {
        using Truth=rules::Matcher::Truth;
        for (auto const& rule:entries) {
            auto question=dns_question_truth(rule,name,type,context);if (!question) return false;
            if (rule.match_response) {
                if (*question==Truth::no && !rule.invert) continue;
                return false;
            }
            auto value=*question;
            if (rule.invert && value!=Truth::unknown) value=value==Truth::yes ? Truth::no : Truth::yes;
            if (value!=Truth::yes) continue;
            if (rule.action==DnsAction::reject) return true;
            if (rule.action==DnsAction::route || rule.action==DnsAction::respond || rule.action==DnsAction::predefined) return false;
        }
        return false;
    }
    // Call only after configuration validation has ruled out response rules.
    inline auto select_question_dns_action(std::span<DnsRule const> rules,std::string_view name,
        std::uint16_t type,std::size_t fallback,bool disable_cache=false,DnsContext const& context={}) noexcept -> DnsDecision {
        for (auto const& rule:rules) {
            if (!dns_rule_matches(rule,name,type,context)) continue;
            if (rule.disable_cache) disable_cache=*rule.disable_cache;
            if (rule.action!=DnsAction::route_options) return {rule.action,rule.server,disable_cache};
        }
        return {DnsAction::route,fallback,disable_cache};
    }
    inline auto select_dns_action(std::span<DnsRule const> rules,std::string_view name,
        std::uint16_t type,std::size_t fallback,bool disable_cache=false,DnsContext const& context={}) noexcept -> DnsDecision {
#ifdef NEXUS_DNS_RESPONSE
        if (dns_has_response_program(rules)) return {DnsAction::reject,0,disable_cache};
#endif
        return select_question_dns_action(rules,name,type,fallback,disable_cache,context);
    }
}
