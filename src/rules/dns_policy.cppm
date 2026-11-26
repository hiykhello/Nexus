export module dns.policy;
import std;
import rules;
import rules.domain_pattern;
import rules.regex;
export import :types;

export namespace policy {
    inline auto dns_preflight_reject(std::span<DnsRule const> entries,std::string_view name,std::uint16_t type,
        DnsContext const& context={}) noexcept -> bool;
#ifdef NEXUS_DNS_RESPONSE
    inline auto dns_has_response_program(std::span<DnsRule const> rules) noexcept -> bool {
        return std::ranges::any_of(rules,[](auto const& rule) {
            return rule.match_response || rule.timeout_ms || rule.rewrite_ttl || rule.client_subnet ||
                rule.remove_client_subnet || rule.action==DnsAction::evaluate ||
                rule.action==DnsAction::respond || rule.action==DnsAction::predefined;
        });
    }
    inline auto dns_has_concurrent_rules(std::span<DnsRule const> rules) noexcept -> bool {
        return std::ranges::any_of(rules,[](auto const& rule){return rule.race || rule.speculative;});
    }
#endif
    struct DnsContextRequirements {
        bool source=false, auth_user=false, source_uid=false, process=false, network_state=false;
    };
    inline constexpr std::size_t max_named_dns_responses=16;

    [[nodiscard]] inline auto validate_dns_response_tags(std::span<DnsRule const> entries) noexcept -> bool {
        std::array<std::string_view,max_named_dns_responses> names{};
        std::size_t count=0;
        for (auto const& rule:entries) {
            if (rule.match_response_tag && std::ranges::find(std::span(names).first(count),*rule.match_response_tag)==std::span(names).first(count).end())
                return false;
            if (rule.evaluate_tag) {
                if (count==names.size() || std::ranges::find(std::span(names).first(count),*rule.evaluate_tag)!=std::span(names).first(count).end())
                    return false;
                names[count++]=*rule.evaluate_tag;
            }
        }
        return true;
    }

    [[nodiscard]] inline auto validate_dns_concurrency(std::span<DnsRule const> entries) noexcept -> bool {
        if (!std::ranges::any_of(entries,[](auto const& rule){return rule.race || rule.speculative;})) return true;
        std::size_t queries=0, races=0;
        for (auto const& rule:entries) {
            queries+=rule.action==DnsAction::evaluate || (rule.action==DnsAction::route && rule.speculative);
            races+=rule.race;
        }
        return queries<=32 && races<=64;
    }

    [[nodiscard]] inline auto is_dns_context_predicate(std::string_view type) noexcept -> bool {
        return type=="network" || type=="source-ip-cidr" || type=="source-ip-is-private" ||
            type=="source-ip-is-cgnat" || type=="source-ip-accept-any" || type=="source-port" ||
            type=="source-port-range" || type=="source-interface" || type=="inbound" || type=="auth-user" ||
            type=="network-type" || type=="network-is-expensive" || type=="network-is-constrained" ||
            type=="wifi-ssid" || type=="wifi-bssid" || type=="default-interface-address" ||
            type=="network-interface-address" || type=="source-uid" || type=="source-gid" ||
            type=="source-user" || type=="process-name" || type=="process-path" ||
            type=="process-path-regex" || type=="package-name" || type=="package-name-regex" ||
            type=="route-mode" || type=="client";
    }

    inline auto dns_context_requirements(std::span<DnsRule const> entries) noexcept -> DnsContextRequirements {
        DnsContextRequirements result;
        auto mark=[&](std::string_view type) noexcept {
            result.source |= type!="source-interface" && type.starts_with("source-");
            result.auth_user |= type=="auth-user";
            result.source_uid |= type=="source-uid" || type=="source-gid" || type=="source-user";
            result.process |= type=="process-name" || type=="process-path" || type=="process-path-regex" ||
                type=="package-name" || type=="package-name-regex";
            result.network_state |= type=="network-type" || type=="network-is-expensive" ||
                type=="network-is-constrained" || type=="wifi-ssid" || type=="wifi-bssid" ||
                type=="default-interface-address" || type=="network-interface-address";
        };
        for (auto const& rule:entries) {
            for (auto const& field:rule.context) mark(field.type);
            result.source |= rule.rule_set_needs_source || rule.inline_needs_source;
            result.auth_user |= rule.rule_set_needs_auth_user || rule.inline_needs_auth_user;
            result.source_uid |= rule.rule_set_needs_source_uid || rule.inline_needs_source_uid;
            result.process |= rule.rule_set_needs_process || rule.inline_needs_process;
            result.network_state |= rule.rule_set_needs_network || rule.inline_needs_network;
        }
        return result;
    }

    struct DnsPredicateScan {
        bool source=false, auth=false, response=false, uid=false, proc=false, net=false;
        std::size_t nodes=0;
    };

    [[nodiscard]] inline auto scan_dns_predicate_tree(rules::Rule const& node,bool allow_response_ip,
        unsigned depth,DnsPredicateScan& scan) noexcept -> bool {
        if (depth>rules::max_rule_depth || ++scan.nodes>rules::max_rules) return false;
        if (node.type=="and" || node.type=="or" || node.type=="not") {
            if (node.children.empty() || (node.type=="not" && node.children.size()!=1)) return false;
            return std::ranges::all_of(node.children,[&](auto const& child){
                return scan_dns_predicate_tree(child,allow_response_ip,depth+1,scan);
            });
        }
        scan.source |= node.type!="source-interface" && node.type.starts_with("source-");
        scan.auth |= node.type=="auth-user";
        scan.uid |= node.type=="source-uid" || node.type=="source-gid" || node.type=="source-user";
        scan.proc |= node.type=="process-name" || node.type=="process-path" || node.type=="process-path-regex" ||
            node.type=="package-name" || node.type=="package-name-regex";
        scan.net |= node.type=="network-type" || node.type=="network-is-expensive" || node.type=="network-is-constrained" ||
            node.type=="wifi-ssid" || node.type=="wifi-bssid" || node.type=="default-interface-address" ||
            node.type=="network-interface-address";
        bool is_ip = node.type=="ip-cidr" || node.type=="ip-is-private" || node.type=="ip-is-cgnat" ||
            node.type=="ip-accept-any" || node.type=="ip-version";
        scan.response |= is_ip;
        return is_dns_context_predicate(node.type) || node.type=="domain" || node.type=="domain-suffix" ||
            node.type=="domain-keyword" || node.type=="domain-wildcard" || node.type=="domain-regex" ||
            node.type=="query-type" || (allow_response_ip && is_ip);
    }

    inline auto bind_dns_rule_set(DnsRule& rule,rules::RuleSet set) -> bool {
        if (!rule.has_rule_set || set.rules.empty()) return false;
        auto normalized=rules::normalize_set(std::move(set));
        if (!normalized) return false;
        set=std::move(*normalized);
        DnsPredicateScan scan;
        if (!std::ranges::all_of(set.rules,[&](auto const& node){return scan_dns_predicate_tree(node,rule.match_response,1,scan);})) return false;
        if (set.rules.size()>1) set.rules={rules::Rule{"or","",std::move(set.rules)}};
        set.version=2;
        auto compiled=rules::Matcher::compile(set);
        if (!compiled) return false;
        rule.rule_set_matcher=std::move(*compiled);
        rule.rule_set_needs_source=scan.source;
        rule.rule_set_needs_auth_user=scan.auth;
        rule.rule_set_needs_response=scan.response;
        rule.rule_set_needs_source_uid=scan.uid;
        rule.rule_set_needs_process=scan.proc;
        rule.rule_set_needs_network=scan.net;
        return true;
    }

    inline auto normalize_dns_owner(std::string& name) -> bool {
        if (name==".") return true;
        if (name.ends_with('.')) name.pop_back();
        if (name.empty() || name.size()>253) return false;
        std::size_t length=0;
        for (auto& c:name) {
            auto byte=static_cast<unsigned char>(c);
            if (c=='.') { if (!length || length>63) return false; length=0; continue; }
            if (byte<33 || byte>126 || c=='\\' || ++length>63) return false;
            if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
        }
        return length!=0;
    }

    inline auto normalize_dns_rule(DnsRule& rule,std::size_t servers,bool allow_unloaded_rule_set=false) -> bool {
#ifndef NEXUS_DNS_RESPONSE
        if (rule.action==DnsAction::evaluate || rule.action==DnsAction::respond || rule.action==DnsAction::predefined) return false;
#endif
        if ((rule.action!=DnsAction::route && rule.action!=DnsAction::reject && rule.action!=DnsAction::route_options &&
             rule.action!=DnsAction::evaluate && rule.action!=DnsAction::respond && rule.action!=DnsAction::predefined) ||
            ((rule.action==DnsAction::route || rule.action==DnsAction::evaluate) ? rule.server>=servers : rule.server!=0) ||
            (rule.action==DnsAction::route_options && !rule.disable_cache && !rule.timeout_ms && !rule.rewrite_ttl &&
             !rule.client_subnet && !rule.remove_client_subnet && !rule.strategy) ||
            (rule.strategy && rule.action!=DnsAction::route && rule.action!=DnsAction::route_options && rule.action!=DnsAction::evaluate) ||
            (rule.reject_rcode && (rule.action!=DnsAction::reject || rule.reject_drop || *rule.reject_rcode>15)) ||
            (rule.rewrite_ttl && rule.action!=DnsAction::route && rule.action!=DnsAction::route_options && rule.action!=DnsAction::evaluate) ||
            ((rule.client_subnet || rule.remove_client_subnet) && rule.action!=DnsAction::route && rule.action!=DnsAction::route_options && rule.action!=DnsAction::evaluate) ||
            (rule.client_subnet && rule.remove_client_subnet) ||
            (rule.reject_drop && rule.action!=DnsAction::reject) ||
            ((rule.action==DnsAction::reject || rule.action==DnsAction::respond || rule.action==DnsAction::predefined) && rule.disable_cache) ||
            ((rule.action==DnsAction::reject || rule.action==DnsAction::respond || rule.action==DnsAction::predefined) && rule.timeout_ms) ||
            (rule.timeout_ms && !*rule.timeout_ms) ||
            ((rule.action==DnsAction::predefined)!=rule.predefined.has_value()) ||
            (rule.query_type && !*rule.query_type) || (rule.query_class && !*rule.query_class) || rule.context.size()>24 ||
            (rule.has_rule_set && !rule.rule_set_matcher && !allow_unloaded_rule_set) || (!rule.has_rule_set && rule.rule_set_matcher) ||
            (rule.rule_set_needs_response && !rule.match_response) ||
            (rule.race && (!rule.match_response || rule.speculative || (rule.action!=DnsAction::route && rule.action!=DnsAction::respond && rule.action!=DnsAction::reject && rule.action!=DnsAction::predefined))) ||
            (rule.speculative && rule.action!=DnsAction::route && rule.action!=DnsAction::evaluate) ||
            (rule.evaluate_tag && (rule.action!=DnsAction::evaluate || rule.evaluate_tag->empty() || rule.evaluate_tag->size()>255 || rule.evaluate_tag->find('\0')!=std::string::npos)) ||
            (rule.match_response_tag && (!rule.match_response || rule.match_response_tag->empty() || rule.match_response_tag->size()>255 || rule.match_response_tag->find('\0')!=std::string::npos)))
            return false;
        if (rule.response && (!rule.match_response || (!rule.response->authenticated_data && !rule.response->rcode && !rule.response->section &&
             !rule.response->record_type && !rule.response->address && !rule.response->address_private && !rule.response->address_any &&
             !rule.response->record_name && !rule.response->record_class && !rule.response->record_ttl_min && !rule.response->record_ttl_max &&
             !rule.response->record_data && rule.response->cname.empty()) ||
            (rule.response->rcode && *rule.response->rcode>4095) ||
            (rule.response->record_type && !*rule.response->record_type) ||
            (rule.response->record_class && !*rule.response->record_class) ||
            (rule.response->record_ttl_min && rule.response->record_ttl_max && *rule.response->record_ttl_min>*rule.response->record_ttl_max) ||
            (rule.response->record_data && rule.response->record_data->size()>4096) ||
            (rule.response->address && ((rule.response->address->size!=4 && rule.response->address->size!=16) || rule.response->address->bits>rule.response->address->size*8)) ||
            (rule.response->section && *rule.response->section!=ResponseSection::answer &&
             *rule.response->section!=ResponseSection::authority && *rule.response->section!=ResponseSection::additional)))
            return false;
#ifdef NEXUS_DNS_RESPONSE
        if (rule.client_subnet) {
            auto const& subnet=*rule.client_subnet;
            if ((subnet.size!=4 && subnet.size!=16) || subnet.bits>subnet.size*8) return false;
            auto bytes=(std::size_t(subnet.bits)+7)/8;
            if (subnet.bits%8 && (subnet.address[bytes-1] & ((1u<<(8-subnet.bits%8))-1u))) return false;
            if (std::ranges::any_of(std::span(subnet.address).subspan(bytes),[](auto c){return c!=0;})) return false;
        }
        if (rule.response) {
            if (rule.response->record_name && !normalize_dns_owner(*rule.response->record_name)) return false;
            for (auto& cname:rule.response->cname) {
                cname.compiled_regex.reset();
                if (cname.pattern.empty()) return false;
                if (cname.kind==DnsPattern::regex) {
                    if (cname.suffix || cname.pattern.size()>255) return false;
                    auto re=rules::BoundedRegex::compile(cname.pattern);
                    if (!re) return false;
                    cname.compiled_regex=std::move(*re);
                } else if (cname.kind==DnsPattern::keyword) {
                    if (cname.suffix || cname.pattern.size()>253) return false;
                    for (auto& c:cname.pattern) {
                        if (c<33 || c>126 || c=='\\') return false;
                        if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
                    }
                } else {
                    if (cname.kind==DnsPattern::wildcard && cname.suffix) return false;
                    auto norm=rules::normalize_rule({cname.kind==DnsPattern::wildcard ? "domain-wildcard" :
                        cname.suffix ? "domain-suffix" : "domain",cname.pattern});
                    if (!norm) return false;
                    cname.pattern=std::move(norm->value);
                }
            }
        }
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
        rule.inline_matcher.reset();
        rule.inline_needs_source=rule.inline_needs_auth_user=rule.inline_needs_response=false;
        rule.inline_needs_source_uid=rule.inline_needs_process=rule.inline_needs_network=false;
        rule.domain_regex.reset();
        for (auto& field:rule.context) {
            if (!field.children.empty() || !is_dns_context_predicate(field.type)) return false;
        }
        if (!rule.context.empty()) {
            rules::Rule expression{"and","",rule.context};
            auto matcher=rules::Matcher::compile({{std::move(expression)},2});
            if (!matcher) return false;
            rule.context_matcher=std::move(*matcher);
        }
        if (rule.inline_predicate) {
            auto norm=rules::normalize_rule(*rule.inline_predicate);
            if (!norm) return false;
            DnsPredicateScan scan;
            if (!scan_dns_predicate_tree(*norm,rule.match_response,1,scan)) return false;
            auto matcher=rules::Matcher::compile({{*norm},2});
            if (!matcher) return false;
            rule.inline_predicate=std::move(*norm);
            rule.inline_matcher=std::move(*matcher);
            rule.inline_needs_source=scan.source;
            rule.inline_needs_auth_user=scan.auth;
            rule.inline_needs_response=scan.response;
            rule.inline_needs_source_uid=scan.uid;
            rule.inline_needs_process=scan.proc;
            rule.inline_needs_network=scan.net;
        }
        if (rule.query_subnet && ((rule.query_subnet->size!=4 && rule.query_subnet->size!=16) || rule.query_subnet->bits>rule.query_subnet->size*8)) return false;
        if (rule.match_all) return rule.domain.empty() && !rule.query_type && !rule.query_class && !rule.query_dnssec && !rule.query_checking_disabled && !rule.query_authenticated_data && !rule.query_subnet && rule.context.empty() && !rule.has_rule_set && !rule.inline_predicate && !rule.suffix && rule.pattern==DnsPattern::name;
        if (rule.domain.empty()) return (rule.query_type.has_value() || rule.query_class.has_value() || rule.query_dnssec.has_value() || rule.query_checking_disabled.has_value() || rule.query_authenticated_data.has_value() || rule.query_subnet.has_value() || !rule.context.empty() || rule.has_rule_set || rule.inline_predicate.has_value()) && !rule.suffix && rule.pattern==DnsPattern::name;
        if (rule.pattern==DnsPattern::keyword) {
            if (rule.suffix || rule.domain.size()>253) return false;
            for (auto& c:rule.domain) {
                if (c<33 || c>126 || c=='\\') return false;
                if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
            }
            return true;
        }
        if (rule.pattern==DnsPattern::regex) {
            if (rule.suffix || rule.domain.size()>255) return false;
            auto compiled=rules::BoundedRegex::compile(rule.domain);
            if (!compiled) return false;
            rule.domain_regex=std::move(*compiled);
            return true;
        }
        if ((rule.pattern!=DnsPattern::name && rule.pattern!=DnsPattern::wildcard) ||
            (rule.pattern==DnsPattern::wildcard && rule.suffix)) return false;
        auto normalized=rules::normalize_rule({rule.pattern==DnsPattern::wildcard ? "domain-wildcard" : "domain-suffix",rule.domain});
        if (!normalized) return false;
        rule.domain=std::move(normalized->value);
        return true;
    }

    inline auto dns_context_to_match_input(std::optional<std::string_view> domain,std::optional<std::uint16_t> query_type,
        DnsContext const& context) noexcept -> rules::MatchInput {
        return {
            .domain=domain, .network=context.network, .source_port=context.source_port,
            .source_ip_bytes=context.source_ip_bytes, .inbound=context.inbound, .auth_user=context.auth_user,
            .query_type=query_type, .source_uid=context.source_uid,
            .process_path=context.process_path ? context.process_path : context.process_name,
            .source_interface=context.source_interface, .route_mode=context.route_mode,
            .network_type=context.network_type,
            .network_is_expensive=context.network_is_expensive, .network_is_constrained=context.network_is_constrained,
            .wifi_ssid=context.wifi_ssid, .wifi_bssid=context.wifi_bssid,
            .default_interface_addresses=context.default_interface_addresses.empty() ?
                std::optional<std::span<rules::ProgramAddress const>>{} :
                std::optional<std::span<rules::ProgramAddress const>>{context.default_interface_addresses},
            .network_interface_addresses=context.network_interface_addresses.empty() ?
                std::optional<std::span<rules::NetworkInterfaceAddress const>>{} :
                std::optional<std::span<rules::NetworkInterfaceAddress const>>{context.network_interface_addresses},
            .source_gid=context.source_gid, .source_user=context.source_user,
            .package_name=context.package_name, .client=context.client,
            .process_paths=context.process_paths,
        };
    }

    inline auto dns_question_truth(DnsRule const& rule,std::string_view name,std::uint16_t type,DnsContext const& context={}) noexcept -> std::optional<rules::Matcher::Truth> {
        using Truth=rules::Matcher::Truth;
        if (!rule.context.empty() && ((context.source_port && !*context.source_port) ||
            (context.source_ip_bytes && context.source_ip_bytes->size()!=4 && context.source_ip_bytes->size()!=16) ||
            (context.network && *context.network!=rules::Network::tcp && *context.network!=rules::Network::udp && *context.network!=rules::Network::icmp))) return {};
        if (!rule.context.empty()) for (auto value:{context.inbound,context.auth_user})
            if (value && (value->empty() || value->size()>255 || value->find('\0')!=std::string_view::npos)) return {};
        if (rule.query_type && *rule.query_type!=type) return Truth::no;
        if (rule.query_class && *rule.query_class!=context.query_class) return Truth::no;
        if (!rule.domain.empty()) {
            if (rule.pattern==DnsPattern::regex) {
                if (!rule.domain_regex || !rule.domain_regex->search(name,true)) return Truth::no;
            } else {
                auto kind=rule.pattern==DnsPattern::keyword ? rules::DomainPattern::keyword :
                    rule.pattern==DnsPattern::wildcard ? rules::DomainPattern::wildcard :
                    rule.suffix ? rules::DomainPattern::suffix : rules::DomainPattern::exact;
                if (!rules::domain_pattern_matches(kind,name,rule.domain)) return Truth::no;
            }
        }
        auto truth=Truth::yes;
        for (auto [wanted,actual] : {std::pair{rule.query_dnssec,context.query_dnssec},
                 std::pair{rule.query_checking_disabled,context.query_checking_disabled},
                 std::pair{rule.query_authenticated_data,context.query_authenticated_data}}) {
            if (!wanted) continue;
            if (!actual) truth=Truth::unknown;
            else if (*actual!=*wanted) return Truth::no;
        }
        if (rule.query_subnet) {
            if (!context.subnet_known) truth=Truth::unknown;
            else if (!context.query_subnet) return Truth::no;
            else {
                auto const& actual=*context.query_subnet; auto const& wanted=*rule.query_subnet;
                if ((actual.size!=4 && actual.size!=16) || actual.bits>actual.size*8) return {};
                if (actual.size!=wanted.size || actual.bits<wanted.bits) return Truth::no;
                auto whole=wanted.bits/8, remaining=wanted.bits%8;
                for (unsigned i=0;i<whole;++i) if (actual.address[i]!=wanted.address[i]) return Truth::no;
                if (remaining && ((actual.address[whole]^wanted.address[whole]) & (0xffu<<(8-remaining)))) return Truth::no;
            }
        }
        if (rule.has_rule_set) {
            if (!rule.rule_set_matcher) return {};
            auto domain=rules::valid_domain(name) ? std::optional(name) : std::nullopt;
            auto qtype=type ? std::optional(type) : std::nullopt;
            auto result=rule.rule_set_matcher->match_truth_mapped(
                dns_context_to_match_input(domain,qtype,context),
                rule.match_response ? context.response_addresses : std::nullopt);
            if (!result) return {};
            if (*result==Truth::no) return Truth::no;
            if (*result==Truth::unknown) truth=Truth::unknown;
        }
        if (rule.inline_predicate) {
            if (!rule.inline_matcher) return {};
            auto domain=rules::valid_domain(name) ? std::optional(name) : std::nullopt;
            auto qtype=type ? std::optional(type) : std::nullopt;
            auto result=rule.inline_matcher->match_truth_mapped(
                dns_context_to_match_input(domain,qtype,context),
                rule.match_response ? context.response_addresses : std::nullopt);
            if (!result) return {};
            if (*result==Truth::no) return Truth::no;
            if (*result==Truth::unknown) truth=Truth::unknown;
        }
        if (rule.context.empty()) return truth;
        if (!rule.context_matcher) return {};
        auto result=rule.context_matcher->match_truth_mapped(dns_context_to_match_input({},std::nullopt,context));
        if (!result) return {};
        if (*result==Truth::no) return Truth::no;
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
            auto question=dns_question_truth(rule,name,type,context); if (!question) return false;
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

    inline auto select_question_dns_action(std::span<DnsRule const> rules,std::string_view name,
        std::uint16_t type,std::size_t fallback,bool disable_cache=false,DnsContext const& context={}) noexcept -> DnsDecision {
        std::optional<rules::DnsRuleStrategy> strategy;
        for (std::size_t i=0;i<rules.size();++i) {
            auto const& rule=rules[i];
            if (!dns_rule_matches(rule,name,type,context)) continue;
            if (rule.disable_cache) disable_cache=*rule.disable_cache;
            if (rule.strategy) strategy=rule.strategy;
            if (rule.action!=DnsAction::route_options)
                return {rule.action,rule.server,disable_cache,rule.strategy ? rule.strategy : strategy,rule.reject_rcode,i};
        }
        return {DnsAction::route,fallback,disable_cache,strategy,{},{}};
    }

    inline auto select_dns_action(std::span<DnsRule const> rules,std::string_view name,
        std::uint16_t type,std::size_t fallback,bool disable_cache=false,DnsContext const& context={}) noexcept -> DnsDecision {
#ifdef NEXUS_DNS_RESPONSE
        if (dns_has_response_program(rules)) return {DnsAction::reject,0,disable_cache};
#endif
        return select_question_dns_action(rules,name,type,fallback,disable_cache,context);
    }
}
