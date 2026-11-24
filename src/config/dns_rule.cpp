module config;
import std;
import platform.ip_address;
import glaze;
import config.kdl_common;
import config.dns_predefined;
import rules;

namespace config {
    namespace g = ::glaze;
    using namespace config::kdl;
    using namespace config::dns_detail;
    auto parse_dns_rule(g::KdlNode const& child,
        std::vector<std::pair<DnsRule,std::string>>& pending,
        std::vector<std::pair<std::size_t,std::pair<std::string,bool>>>& references)
        -> std::expected<void,std::string> {
        DnsRule rule;
        auto set=text_property(child,"rule-set");auto set_field=property(child,"rule-set");
        auto ip_source_field=property(child,"ip-cidr-match-source");
        auto ip_source=ip_source_field && !ip_source_field->tag ? std::get_if<bool>(&ip_source_field->data) : nullptr;
        if((set_field && (!set || !valid_name(*set))) || (ip_source_field && (!ip_source || !set)))return error("invalid DNS rule-set reference");
        rule.has_rule_set=bool(set);
        unsigned domains=0;
        for (auto field:{"domain","domain-suffix","domain-keyword","domain-wildcard","domain-regex"}) {
            if (!property(child,field)) continue;
            auto value=text_property(child,field);
            if (!value || value->empty() || ++domains>1) return error("invalid DNS domain condition");
            rule.domain=*value;
            rule.suffix=std::string_view(field)=="domain-suffix";
            rule.pattern=std::string_view(field)=="domain-keyword" ? policy::DnsPattern::keyword :
                std::string_view(field)=="domain-wildcard" ? policy::DnsPattern::wildcard :
                std::string_view(field)=="domain-regex" ? policy::DnsPattern::regex : policy::DnsPattern::name;
        }
        auto server=text_property(child,"server");
        auto type=property(child,"query-type");
        auto query_class=property(child,"query-class");
        auto action=property(child,"action");
        auto response_match=property(child,"match-response");
        auto race=property(child,"race");auto speculative=property(child,"speculative");
        auto evaluate_tag=property(child,"tag");
        auto query_dnssec=property(child,"query-dnssec");
        auto query_cd=property(child,"query-checking-disabled");
        auto query_ad=property(child,"query-authenticated-data");
        auto query_subnet=property(child,"query-client-subnet");
        auto client_subnet=property(child,"client-subnet");
        auto remove_client_subnet=property(child,"remove-client-subnet");
        auto timeout=property(child,"timeout-ms");
        auto rewrite_ttl=property(child,"rewrite-ttl");
        auto reject_method=property(child,"reject-method");
        auto reject_rcode=property(child,"reject-rcode");
        auto strategy_prop=property(child,"strategy");
        if(reject_method) {
            auto method=string(*reject_method);
            if(!method || (*method!="reply" && *method!="drop"))return error("invalid DNS reject-method");
            rule.reject_drop=*method=="drop";
        }
        if(reject_rcode) {
            std::optional<std::uint64_t> rc=integer(*reject_rcode);
            if(!rc) if(auto text=string(*reject_rcode)) {
                std::string up(*text);
                for(auto& c:up)c=static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                if(up=="NOERROR")rc=0;else if(up=="FORMERR")rc=1;else if(up=="SERVFAIL")rc=2;
                else if(up=="NXDOMAIN")rc=3;else if(up=="NOTIMP")rc=4;else if(up=="REFUSED")rc=5;
            }
            if(!rc || *rc>15)return error("invalid DNS reject-rcode");
            rule.reject_rcode=static_cast<std::uint8_t>(*rc);
        }
        if(strategy_prop) {
            auto s=string(*strategy_prop);
            auto parsed=s ? rules::parse_dns_rule_strategy(*s) : std::nullopt;
            if(!parsed)return error("invalid DNS rule strategy");
            rule.strategy=*parsed;
        }
#ifdef NEXUS_DNS_RESPONSE
        if(race) {
            if(race->tag || !std::holds_alternative<bool>(race->data))return error("DNS race requires a boolean");
            rule.race=std::get<bool>(race->data);
        }
        if(speculative) {
            if(speculative->tag || !std::holds_alternative<bool>(speculative->data))return error("DNS speculative requires a boolean");
            rule.speculative=std::get<bool>(speculative->data);
        }
        if(client_subnet) {
            auto text=string(*client_subnet);if(!text)return error("invalid DNS client-subnet");
            auto slash=text->find('/');auto host=text->substr(0,slash);
            policy::ResponsePrefix prefix;
            if (auto parsed=platform::parse_ip_address(host)) { prefix.address=parsed->bytes; prefix.size=parsed->size; }
            if(!prefix.size)return error("invalid DNS client-subnet");
            unsigned bits=prefix.size*8;
            if(slash!=std::string::npos) {
                auto value=std::string_view(*text).substr(slash+1);
                auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),bits);
                if(value.empty() || ec!=std::errc{} || end!=value.data()+value.size() || bits>prefix.size*8)return error("invalid DNS client-subnet");
            }
            prefix.bits=static_cast<std::uint8_t>(bits);
            auto whole=bits/8,remaining=bits%8;
            if(remaining)prefix.address[whole++] &= static_cast<std::uint8_t>(0xffu<<(8-remaining));
            std::fill(prefix.address.begin()+whole,prefix.address.end(),0);
            rule.client_subnet=prefix;
        }
        if(remove_client_subnet) {
            if(remove_client_subnet->tag || !std::holds_alternative<bool>(remove_client_subnet->data))return error("DNS remove-client-subnet requires a boolean");
            rule.remove_client_subnet=std::get<bool>(remove_client_subnet->data);
            if(rule.remove_client_subnet && rule.client_subnet)return error("DNS client-subnet conflicts with remove-client-subnet");
        }
        if (rewrite_ttl) {
            auto value=integer(*rewrite_ttl);
            if (!value || *value>0xffffffffu) return error("invalid DNS rewrite-ttl");
            rule.rewrite_ttl=static_cast<std::uint32_t>(*value);
        }
        if(query_subnet) {
            auto text=string(*query_subnet);if(!text)return error("invalid DNS query client subnet");
            auto slash=text->find('/');if(slash==std::string::npos || !slash || slash+1==text->size())return error("invalid DNS query client subnet");
            auto host=text->substr(0,slash);auto bits_text=std::string_view(*text).substr(slash+1);unsigned bits=0;
            auto [end,ec]=std::from_chars(bits_text.data(),bits_text.data()+bits_text.size(),bits);
            policy::ResponsePrefix prefix;
            if (auto parsed=platform::parse_ip_address(host)) { prefix.address=parsed->bytes; prefix.size=parsed->size; }
            if(!prefix.size || ec!=std::errc{} || end!=bits_text.data()+bits_text.size() || bits>prefix.size*8)return error("invalid DNS query client subnet");
            prefix.bits=static_cast<std::uint8_t>(bits);rule.query_subnet=prefix;
        }
        for (auto [value,field] : {std::pair{query_dnssec,&rule.query_dnssec},
                 std::pair{query_cd,&rule.query_checking_disabled},
                 std::pair{query_ad,&rule.query_authenticated_data}}) {
            if (!value) continue;
            if (value->tag || !std::holds_alternative<bool>(value->data))
                return error("DNS query-dnssec, query-checking-disabled and query-authenticated-data require booleans");
            *field=std::get<bool>(value->data);
        }
        if (timeout) {
            auto value=integer(*timeout);
            if (!value || !*value || *value>0xffffffffu) return error("invalid DNS timeout-ms");
            rule.timeout_ms=static_cast<std::uint32_t>(*value);
        }
#else
        if (timeout || query_dnssec || query_cd || query_ad || query_subnet || rewrite_ttl || client_subnet || remove_client_subnet || race || speculative) return error("DNS query context rules are unavailable in this build");
#endif
#ifdef NEXUS_DNS_RESPONSE
        if (response_match) {
            if(response_match->tag)return error("invalid DNS match-response");
            if(auto value=std::get_if<bool>(&response_match->data))rule.match_response=*value;
            else if(auto value=string(*response_match);value && valid_name(*value)) {rule.match_response=true;rule.match_response_tag=*value;}
            else return error("DNS match-response requires a boolean or nonempty tag");
        }
        if(evaluate_tag) {auto value=string(*evaluate_tag);if(!value || !valid_name(*value))return error("invalid DNS evaluate tag");rule.evaluate_tag=*value;}
#endif
        auto rcode=property(child,"response-rcode");
        auto response_ad=property(child,"response-authenticated-data");
        auto rrtype=property(child,"response-record-type");
        auto section=property(child,"response-section");
        auto response_ip=property(child,"response-ip-cidr");
        auto response_private=property(child,"response-ip-is-private");
        auto response_any=property(child,"response-ip-accept-any");
        auto rrname=property(child,"response-record-name");
        auto rrclass=property(child,"response-record-class");
        auto rrdata=property(child,"response-record-data-hex");
        auto ttl_min=property(child,"response-record-ttl-min"),ttl_max=property(child,"response-record-ttl-max");
        auto cname_d=property(child,"response-cname-domain"),cname_s=property(child,"response-cname-domain-suffix"),
             cname_k=property(child,"response-cname-domain-keyword"),cname_r=property(child,"response-cname-domain-regex");
#ifdef NEXUS_DNS_RESPONSE
        if (rcode || response_ad || rrtype || section || response_ip || response_private || response_any || rrname || rrclass || rrdata || ttl_min || ttl_max || cname_d || cname_s || cname_k || cname_r) {
            if (!rule.match_response) return error("DNS response fields require match-response");
            rule.response.emplace();
            if (response_ad) {
                if (response_ad->tag || !std::holds_alternative<bool>(response_ad->data))
                    return error("DNS response-authenticated-data requires a boolean");
                rule.response->authenticated_data=std::get<bool>(response_ad->data);
            }
            for (auto [value,field]:{std::pair{response_private,&rule.response->address_private},std::pair{response_any,&rule.response->address_any}}) {
                if (!value) continue;
                if (value->tag || !std::holds_alternative<bool>(value->data)) return error("DNS response IP condition requires a boolean");
                *field=std::get<bool>(value->data);
            }
            if (response_ip) {
                auto text=string(*response_ip);if (!text) return error("invalid DNS response IP CIDR");
                auto slash=text->find('/');if (slash==std::string::npos || slash==0 || slash+1==text->size()) return error("invalid DNS response IP CIDR");
                auto host=text->substr(0,slash);auto bits_text=std::string_view(*text).substr(slash+1);unsigned bits=0;
                auto [end,ec]=std::from_chars(bits_text.data(),bits_text.data()+bits_text.size(),bits);
                policy::ResponsePrefix prefix;
                if (auto parsed=platform::parse_ip_address(host)) { prefix.address=parsed->bytes; prefix.size=parsed->size; }
                if (!prefix.size || ec!=std::errc{} || end!=bits_text.data()+bits_text.size() || bits>prefix.size*8) return error("invalid DNS response IP CIDR");
                prefix.bits=static_cast<std::uint8_t>(bits);rule.response->address=prefix;
            }
            if (rcode) { auto value=integer(*rcode);if (!value || *value>4095) return error("invalid DNS response rcode");rule.response->rcode=static_cast<std::uint16_t>(*value); }
            if (rrname) { auto value=string(*rrname);if (!value || value->empty()) return error("invalid DNS response record name");rule.response->record_name=*value; }
            if (rrclass) { auto value=integer(*rrclass);if (!value || !*value || *value>65535) return error("invalid DNS response record class");rule.response->record_class=static_cast<std::uint16_t>(*value); }
            for (auto [input,field]:{std::pair{ttl_min,&rule.response->record_ttl_min},std::pair{ttl_max,&rule.response->record_ttl_max}}) {
                if (!input) continue;auto value=integer(*input);
                if (!value || *value>0xffffffffu) return error("invalid DNS response record TTL");
                *field=static_cast<std::uint32_t>(*value);
            }
            if (rrdata) {
                auto text=string(*rrdata);auto bytes=text ? hex_bytes(*text) : std::nullopt;
                if (!bytes) return error("invalid DNS response record data");
                rule.response->record_data=std::move(*bytes);
            }
            if (rrtype) {
                auto value=parse_dns_rrtype(*rrtype);
                if (!value) return error("invalid DNS response record condition");
                rule.response->record_type=*value;
            }
            if (section) {
                auto where=string(*section);
                if (!where) return error("invalid DNS response section");
                if (*where=="answer") rule.response->section=policy::ResponseSection::answer;
                else if (*where=="authority") rule.response->section=policy::ResponseSection::authority;
                else if (*where=="additional") rule.response->section=policy::ResponseSection::additional;
                else return error("invalid DNS response section");
            }
            for (auto [prop,kind,sfx] : {
                std::tuple{cname_d,policy::DnsPattern::name,false},
                std::tuple{cname_s,policy::DnsPattern::name,true},
                std::tuple{cname_k,policy::DnsPattern::keyword,false},
                std::tuple{cname_r,policy::DnsPattern::regex,false}}) {
                if (!prop) continue;
                auto val=string(*prop);
                if (!val || val->empty()) return error("invalid DNS response CNAME condition");
                rule.response->cname.push_back({*val,kind,sfx,false,{}});
            }
        }
#endif
#ifndef NEXUS_DNS_RESPONSE
        if (response_match || evaluate_tag || rcode || response_ad || rrtype || section || response_ip || response_private || response_any || rrname || rrclass || rrdata || ttl_min || ttl_max || cname_d || cname_s || cname_k || cname_r) return error("DNS response rules are unavailable in this build");
#endif
        auto inverted=property(child,"invert");
        if (inverted) {
            if (inverted->tag || !std::holds_alternative<bool>(inverted->data)) return error("DNS invert requires a boolean");
            rule.invert=std::get<bool>(inverted->data);
        }
        for (auto field:{"network","source-ip-cidr","source-ip-is-private","source-ip-is-cgnat","source-ip-accept-any",
            "source-port","source-port-range","source-interface","inbound","auth-user",
            "network-type","network-is-expensive","network-is-constrained","wifi-ssid","wifi-bssid",
            "default-interface-address","source-uid","source-gid","source-user",
            "process-name","process-path","process-path-regex","package-name","route-mode","client"}) {
            auto value=property(child,field);
            if (!value) continue;
            std::string text;
            std::string_view key=field;
            if (key=="source-port") {
                auto port=integer(*value);
                if (!port || !*port || *port>65535) return error("invalid DNS source-port");
                text=std::to_string(*port);
            } else if (key=="source-uid" || key=="source-gid") {
                auto id=integer(*value);
                if (!id || *id>0xffffffffu) return error("invalid DNS source UID/GID");
                text=std::to_string(*id);
            } else if (key=="source-ip-is-private" || key=="source-ip-is-cgnat" || key=="source-ip-accept-any") {
                if (value->tag || !std::holds_alternative<bool>(value->data) || !std::get<bool>(value->data))
                    return error("DNS source IP flag requires true");
                text="true";
            } else if (key=="network-is-expensive" || key=="network-is-constrained") {
                if (value->tag || !std::holds_alternative<bool>(value->data))
                    return error("DNS network flag requires a boolean");
                text=std::get<bool>(value->data) ? "true" : "false";
            } else {
                auto name=string(*value);
                if (!name) return error("invalid DNS context condition");
                text=*name;
            }
            rule.context.push_back({field,std::move(text)});
        }
        if (action) {
            auto name=string(*action);
            if (!name || (*name!="route" && *name!="reject" && *name!="route-options" && *name!="evaluate" && *name!="respond" && *name!="predefined")) return error("unsupported DNS action");
#ifndef NEXUS_DNS_RESPONSE
            if (*name=="evaluate" || *name=="respond" || *name=="predefined") return error("DNS response rules are unavailable in this build");
#endif
            rule.action=*name=="reject" ? policy::DnsAction::reject :
                *name=="route-options" ? policy::DnsAction::route_options :
                *name=="evaluate" ? policy::DnsAction::evaluate : *name=="respond" ? policy::DnsAction::respond :
                *name=="predefined" ? policy::DnsAction::predefined : policy::DnsAction::route;
            rule.match_all=!domains && !type && !query_class && !query_dnssec && !query_cd && !query_ad && !query_subnet && rule.context.empty() && !rule.has_rule_set;
        }
        auto predefined_rcode=property(child,"predefined-rcode");
        if (auto parsed=parse_dns_predefined(child,predefined_rcode,rule); !parsed)
            return std::unexpected(std::move(parsed.error()));
        auto server_field=property(child,"server");
        auto cache=property(child,"disable-cache");
        if (cache) {
            if (cache->tag || !std::holds_alternative<bool>(cache->data)) return error("DNS disable-cache requires a boolean");
            rule.disable_cache=std::get<bool>(cache->data);
        }
        auto fields=domains+bool(type)+bool(query_class)+bool(action)+bool(server_field)+bool(cache)+bool(inverted)+bool(response_match)+bool(evaluate_tag)+bool(race)+bool(speculative)+bool(timeout)+bool(rewrite_ttl)+bool(reject_method)+bool(reject_rcode)+bool(strategy_prop)+bool(query_dnssec)+bool(query_cd)+bool(query_ad)+bool(query_subnet)+bool(client_subnet)+bool(remove_client_subnet)+bool(rcode)+bool(response_ad)+bool(rrtype)+bool(section)+bool(response_ip)+bool(response_private)+bool(response_any)+bool(rrname)+bool(rrclass)+bool(rrdata)+bool(ttl_min)+bool(ttl_max)+bool(cname_d)+bool(cname_s)+bool(cname_k)+bool(cname_r)+bool(predefined_rcode)+bool(set_field)+bool(ip_source_field)+rule.context.size();
        if (child.tag || !child.arguments.empty() || child.properties.size()!=fields ||
            (!domains && !type && !query_class && !action && !query_dnssec && !query_cd && !query_ad && !query_subnet && rule.context.empty() && !set) || pending.size()>=256 ||
            (reject_method && rule.action!=policy::DnsAction::reject) ||
            ((client_subnet || remove_client_subnet) && rule.action!=policy::DnsAction::route && rule.action!=policy::DnsAction::route_options && rule.action!=policy::DnsAction::evaluate) ||
            ((rule.action==policy::DnsAction::route || rule.action==policy::DnsAction::evaluate) ? !server || !valid_name(*server) : bool(server_field)))
            return error("invalid DNS question rule");
        if (type) {
            auto number=parse_dns_rrtype(*type);
            if (!number) return error("invalid DNS query-type");
            rule.query_type=*number;
        }
        if(query_class) {
            auto number=integer(*query_class);
            if(auto text=string(*query_class)) {
                if(*text=="IN")number=1;else if(*text=="CH")number=3;else if(*text=="HS")number=4;else if(*text=="ANY")number=255;
            }
            if(!number || !*number || *number>65535)return error("invalid DNS query-class");
            rule.query_class=static_cast<std::uint16_t>(*number);
        }
        if (!policy::normalize_dns_rule(rule,1,true)) return error("invalid DNS question rule");
        if(set)references.push_back({pending.size(),{*set,ip_source && *ip_source}});
        pending.push_back({std::move(rule),server ? *server : ""});
        return {};
    }
}
