module config;
import std;
import platform.ip_address;
import nexus.thirdparty.glaze;
import rules;
import rules.kdl_predicate;

namespace config {
    namespace g=nex::glaze;
    namespace {
#include "dns_fields.hpp"
#include "rule_set_parse.hpp"
    }
    auto parse_dns_rule(g::KdlNode const& child,
        std::vector<std::pair<DnsRule,std::string>>& pending,
        std::vector<std::pair<std::size_t,std::pair<std::string,bool>>>& references)
        -> std::expected<void,std::string>;
    auto dns_ipv4(std::string_view text) -> std::optional<std::array<std::uint8_t,4>> {
        std::array<std::uint8_t,4> bytes{};
        for (std::size_t i=0;i<bytes.size();++i) {
            auto dot=text.find('.');
            auto part=text.substr(0,dot);
            if (part.empty() || part.size()>3 || (part.size()>1 && part.front()=='0')) return {};
            unsigned value=0;
            auto [end,ec]=std::from_chars(part.data(),part.data()+part.size(),value);
            if (ec!=std::errc{} || end!=part.data()+part.size() || value>255) return {};
            bytes[i]=static_cast<std::uint8_t>(value);
            if (i==3) { if (dot!=text.npos) return {}; }
            else { if (dot==text.npos) return {}; text.remove_prefix(dot+1); }
        }
        return bytes;
    }
    auto dns_ipv6(std::string_view text) -> std::optional<std::array<std::uint8_t,16>> {
        auto parsed=platform::parse_ip_address(text);
        if (!parsed || parsed->size!=16) return {};
        return parsed->bytes;
    }
    auto parse_dns_address(Node const& node, bool default_port) -> std::expected<DnsUpstream, std::string> {
        auto host=text_property(node,"host");
        auto address=host ? dns_ipv4(*host) : std::nullopt;
        std::array<std::uint8_t,16> bytes{};
        bool is_v6=false;
        if (address) std::copy(address->begin(),address->end(),bytes.begin());
        else if (auto ipv6=host ? dns_ipv6(*host) : std::nullopt) { bytes=*ipv6; is_v6=true; }
        auto value=property(node,"port");
        auto port=value ? integer(*value) : (default_port ? std::optional<std::uint64_t>{53} : std::nullopt);
        if ((!address && !is_v6) || !port || !*port || *port>65535)
            return error("DNS server requires numeric IP host without zone and port 1..65535");
        return DnsUpstream{bytes,is_v6,static_cast<std::uint16_t>(*port)};
    }
    auto dns_hostname(std::string_view name) -> bool {
        if (name.empty() || name.size()>253) return false;
        std::size_t start=0;
        for (std::size_t i=0;i<=name.size();++i) {
            if (i==name.size() || name[i]=='.') {
                if (i==start || i-start>63 || name[start]=='-' || name[i-1]=='-') return false;
                start=i+1;
            } else {
                auto c=static_cast<unsigned char>(name[i]);
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return false;
            }
        }
        return true;
    }
#include "dns_fakeip.hpp"

    auto parse_dns(Node const& node) -> std::expected<DnsRouting, std::string> {
        if (node.tag || !node.arguments.empty() || !node.properties.empty()) return error("dns takes no arguments or properties");
        DnsRouting result;
        std::vector<std::pair<DnsRule,std::string>> pending;
        struct NamedFile {std::string name;BlockRules file;};
        std::vector<NamedFile> rule_files;
        std::vector<std::pair<std::size_t,std::pair<std::string,bool>>> rule_references;
        std::vector<std::pair<std::size_t,std::string>> dependencies;
        std::optional<std::string> final, fakeip_server;
        bool strategy_seen=false, cache_seen=false, edns_seen=false, reverse_seen=false, flush_seen=false;
        std::vector<Node const*> children;
        std::vector<std::pair<std::string,std::string>> views;
        bool servers_seen=false, legacy_server=false; for (auto const& child : node.children) {
            if (child.name=="servers") {
                if (servers_seen || legacy_server || child.tag || !child.arguments.empty() || !child.properties.empty())
                    return error("invalid or duplicate DNS servers block");
                servers_seen=true;
                for (auto const& server : child.children) {
                    if (server.name!="server") return error("servers accepts only server nodes");
                    children.push_back(&server);
                }
            } else {
                if (child.name=="server") {
                    if (servers_seen) return error("cannot mix servers block and top-level DNS server nodes");
                    legacy_server=true;
                }
                children.push_back(&child);
            }
        }
        for (auto const* item : children) {
            auto const& child=*item;
            if (child.name=="listen") {
                auto host=text_property(child,"host");auto value=property(child,"port");auto port=value ? integer(*value) : std::nullopt;
                if(result.listen || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=2 || !host || !port || !*port || *port>65535)return error("invalid DNS listen endpoint");
                DnsListen listen;listen.port=static_cast<std::uint16_t>(*port);
                if(auto address=dns_ipv4(*host))std::ranges::copy(*address,listen.address.begin());
                else if(auto address=dns_ipv6(*host)){listen.address=*address;listen.ipv6=true;}
                else return error("DNS listen host must be a numeric IP without a zone");
                result.listen=listen;
            } else if (child.name=="fake-ip") {
                if (result.fakeip) return error("duplicate DNS fake-ip");
                auto parsed=parse_fakeip(child);
                if (!parsed) return error(std::move(parsed.error()));
                result.fakeip=std::move(parsed->first);
                fakeip_server=std::move(parsed->second);
            } else if (child.name=="server") {
                auto name=argument(child);
                auto type=text_property(child,"type");
                if (!name || !valid_name(*name) || !type || !child.children.empty() || result.servers.size()>=64 ||
                    std::ranges::any_of(result.servers,[&](auto const& server) { return server.name==*name; }))
                    return error("invalid or duplicate DNS server name");
                std::optional<DnsUpstream> upstream;
                if (*type=="local" && child.properties.size()==1) {
                    // The existing system resolver is the local server.
                } else if (*type=="udp" || *type=="tcp" || *type=="tls" || *type=="https" || *type=="quic" || *type=="https3") {
                    auto https3=*type=="https3";
                    auto https=*type=="https" || https3;
                    auto quic=*type=="quic";
                    auto tls=*type=="tls" || https || quic;
                    auto early_field=property(child,"early-data");
                    auto early=early_field && !early_field->tag ? std::get_if<bool>(&early_field->data) : nullptr;
                    if (early_field && (!quic || !early)) return error("DNS early-data requires a boolean on a QUIC server");
                    auto path=text_property(child,"path");
                    if (property(child,"path") && (!https || !path || path->empty() || path->size()>2048))
                        return error("invalid DNS HTTPS path");
                    auto server_name=text_property(child,"server-name");
                    auto ca_file=text_property(child,"ca-file");
                    if (tls && (!server_name || !dns_hostname(*server_name) || !ca_file || ca_file->empty() ||
                        !ca_file->starts_with('/') || ca_file->contains('\0')))
                        return error("DNS TLS requires server-name and an absolute ca-file");
                    auto host=text_property(child,"host");
                    auto resolver=text_property(child,"domain-resolver");
                    auto interface=text_property(child,"bind-interface");
                    auto detour=text_property(child,"detour");
                    if (property(child,"detour") && (!tls || !detour || !valid_name(*detour) || interface))
                        return error("DNS detour requires an encrypted server without a separate bind-interface");
                    auto parsed=parse_dns_address(child,true);
                    auto expected=2u+bool(property(child,"port"))+bool(property(child,"domain-resolver"))+bool(interface)+bool(detour)+bool(early_field);
                    if (!host || child.properties.size()!=expected+2*unsigned(tls)+unsigned(bool(path))) return error("invalid DNS server fields");
                    if (parsed) {
                        if (resolver || property(child,"domain-resolver")) return error("numeric DNS server must not have domain-resolver");
                        upstream=*parsed;
                    } else {
                        auto value=property(child,"port");
                        auto port=value ? integer(*value) : std::optional<std::uint64_t>{53};
                        bool numeric_like=std::ranges::all_of(*host,[](char c) { return (c>='0' && c<='9') || c=='.'; });
                        auto hostname=std::string_view(*host);
                        if (hostname.ends_with('.')) hostname.remove_suffix(1);
                        if (!dns_hostname(hostname) || numeric_like || !resolver || !valid_name(*resolver) || !port || !*port || *port>65535)
                            return error("DNS hostname requires domain-resolver and a valid port");
                        upstream=DnsUpstream{};
                        upstream->host=*host;
                        upstream->port=static_cast<std::uint16_t>(*port);
                        dependencies.emplace_back(result.servers.size(),*resolver);
                    }
                    if (interface) {
                        auto& binding=upstream->binding;
                        if (interface->empty() || interface->size()>=binding.bind_interface.size() || interface->contains('\0'))
                            return error("invalid DNS bind-interface");
                        std::ranges::copy(*interface,binding.bind_interface.begin());
                        if (!binding.valid()) return error("invalid DNS bind-interface");
                    }
                    upstream->tcp=*type!="udp" && !quic && !https3;
                    if (tls) {
                        if (detour) upstream->detour=*detour;
                        if (!property(child,"port")) upstream->port=https ? 443 : 853;
                        upstream->tls=DnsTls{*server_name,*ca_file,https3 ? DnsSecurity::https3 :
                            https ? DnsSecurity::https : quic ? DnsSecurity::quic : DnsSecurity::tls,
                            https ? (path ? *path : "/dns-query") : std::string{}, early && *early};
                    }
                } else return error("unsupported DNS server type or fields");
                result.servers.push_back({*name,upstream});
            } else if (child.name=="view") {
                auto name=argument(child), fallback=text_property(child,"final");
                if (!name || !valid_name(*name) || !fallback || !valid_name(*fallback) ||
                    child.properties.size()!=1 || !child.children.empty() || views.size()>=64 ||
                    std::ranges::any_of(views,[&](auto const& entry){return entry.first==*name;}))
                    return error("invalid or duplicate DNS view");
                views.emplace_back(*name,*fallback);
            } else if (child.name=="rule-set") {
                auto parsed=parse_rule_set_spec(child);
                if (!parsed || rule_files.size()>=256 ||
                    std::ranges::any_of(rule_files,[&](auto const& file){return file.name==parsed->first;}))
                    return error(parsed ? "duplicate or too many DNS rule-set entries" : parsed.error());
                rule_files.push_back({std::move(parsed->first),std::move(parsed->second)});
            } else if (child.name=="rule") {
                auto parsed=parse_dns_rule(child,pending,rule_references);
                if (!parsed) return std::unexpected(std::move(parsed.error()));
            } else if (child.name=="final") {
                auto name=scalar(child);
                if (final || !name || !valid_name(*name)) return error("invalid DNS final server");
                final=*name;
            } else if (child.name=="strategy") {
                auto value=scalar(child);
                if (strategy_seen || !value) return error("invalid DNS strategy");
                if (*value=="prefer_ipv4") result.strategy=DnsStrategy::prefer_ipv4;
                else if (*value=="prefer_ipv6") result.strategy=DnsStrategy::prefer_ipv6;
                else if (*value=="ipv4_only") result.strategy=DnsStrategy::ipv4_only;
                else if (*value=="ipv6_only") result.strategy=DnsStrategy::ipv6_only;
                else return error("unsupported DNS strategy");
                strategy_seen=true;
            } else if (child.name=="optimistic-cache-seconds") {
                if (child.tag || !child.properties.empty() || !child.children.empty() || child.arguments.size()!=1)
                    return error("DNS optimistic-cache-seconds requires one integer from 1 through 3600");
                auto seconds=integer(child.arguments.front());
                if (result.optimistic_cache_seconds || !seconds || !*seconds || *seconds>3600)
                    return error("DNS optimistic-cache-seconds requires one integer from 1 through 3600");
                result.optimistic_cache_seconds=static_cast<std::uint32_t>(*seconds);
            } else if (child.name=="message-cache-directory") {
                auto path=scalar(child);
                if (!result.message_cache_directory.empty() || !path || !path->starts_with('/') || path->contains('\0') || path->ends_with('/'))
                    return error("message-cache-directory requires one absolute directory path");
                result.message_cache_directory=*path;
            } else if (child.name=="disable-cache") {
                if (cache_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.size()!=1 || child.arguments[0].tag || !std::holds_alternative<bool>(child.arguments[0].data))
                    return error("disable-cache requires one boolean");
                result.disable_cache=std::get<bool>(child.arguments[0].data);
                cache_seen=true;
            } else if (child.name=="edns") {
                if (edns_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.size()!=1 || child.arguments[0].tag || !std::holds_alternative<bool>(child.arguments[0].data))
                    return error("edns requires one boolean");
                result.edns=std::get<bool>(child.arguments[0].data);
                edns_seen=true;
            } else if (child.name=="reverse-mapping") {
                if (reverse_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.size()!=1 || child.arguments[0].tag || !std::holds_alternative<bool>(child.arguments[0].data))
                    return error("reverse-mapping requires one boolean");
                result.reverse_mapping=std::get<bool>(child.arguments[0].data);
                reverse_seen=true;
            } else if (child.name=="cache-flush-interval-ms") {
                auto ms=child.arguments.size()==1 ? integer(child.arguments.front()) : std::nullopt;
                if (flush_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    !ms || *ms<1000 || *ms>3600000)
                    return error("cache-flush-interval-ms requires an integer from 1000 through 3600000");
                result.cache_flush_interval_ms=static_cast<std::uint32_t>(*ms);
                flush_seen=true;
            } else return error("unsupported DNS node: " + child.name);
        }
        if (result.servers.empty()) return error("dns requires at least one server");
        auto index=[&](std::string const& name) -> std::optional<std::size_t> {
            auto found=std::ranges::find(result.servers,name,&DnsServer::name);
            if (found==result.servers.end()) return {};
            return static_cast<std::size_t>(found-result.servers.begin());
        };
        for (auto& [name,fallback] : views) {
            if (index(name)) return error("DNS view conflicts with server: "+name);
            auto selected=index(fallback);
            if (!selected) return error("DNS view "+name+" final server not found: "+fallback);
            result.views.push_back({std::move(name),*selected});
        }
        result.final=0;
        if (final) {
            auto selected=index(*final);
            if (!selected) return error("DNS final server not found");
            result.final=*selected;
        }
        for (auto& [rule,server] : pending) {
            if (rule.action==policy::DnsAction::route || rule.action==policy::DnsAction::evaluate) {
                auto selected=index(server);
                if (!selected) return error("DNS rule server not found");
                rule.server=*selected;
            }
            result.rules.push_back(std::move(rule));
        }
        if(!policy::validate_dns_response_tags(result.rules))return error("DNS evaluate tags must be unique and referenced only after their definition");
        if(!policy::validate_dns_concurrency(result.rules))return error("DNS concurrent rules exceed query or race capacity");
        for(auto const& [index,reference]:rule_references) {
            auto file=std::ranges::find(rule_files,reference.first,&NamedFile::name);
            if(file==rule_files.end())return error("DNS rule-set reference not found");
            if(reference.second && file->file.format!=RuleFormat::srs)return error("DNS ip-cidr-match-source requires SRS format");
            auto selected=file->file;selected.ip_cidr_match_source=reference.second;
            result.rule_files.push_back({index,std::move(selected)});
        }
        for(auto const& file:rule_files)
            if(std::ranges::none_of(rule_references,[&](auto const& reference){return reference.second.first==file.name;}))return error("unreferenced DNS rule-set");
        for (auto const& [server,name] : dependencies) {
            auto selected=index(name);
            if (!selected) return error("DNS domain-resolver not found");
            result.servers[server].upstream->resolver=*selected;
        }
        std::vector<policy::DependencyEdge> edges;
        edges.reserve(dependencies.size());
        for (std::size_t i=0;i<result.servers.size();++i)
            if (result.servers[i].upstream && result.servers[i].upstream->resolver)
                edges.push_back({i,*result.servers[i].upstream->resolver});
        if (!policy::dependency_order(result.servers.size(),edges))
            return error("circular DNS domain-resolver dependency");
        if (!result.message_cache_directory.empty()) {
            if (!result.listen || result.disable_cache || result.fakeip)
                return error("message-cache-directory requires a DNS listener with cache enabled and without fake-ip");
        }
        if (result.listen && (!result.disable_cache || result.fakeip)) {
            auto policy=node;
            std::erase_if(policy.children,[](auto const& field) {
                return field.name=="listen" || field.name=="message-cache-directory";
            });
            auto encoded=g::write_kdl(g::KdlDocument{std::move(policy)});
            if (!encoded) return error("cannot encode the DNS message cache policy");
            result.message_cache_policy=std::move(*encoded);
        }
        if (result.fakeip) {
            if (!result.listen) return error("fake-ip requires a DNS message listen endpoint");
            auto upstream=std::ranges::find(result.servers,*fakeip_server,&DnsServer::name);
            if (upstream==result.servers.end()) return error("fake-ip server is unknown");
            result.fakeip->upstream=static_cast<std::size_t>(upstream-result.servers.begin());
        }
        return result;
    }
}
