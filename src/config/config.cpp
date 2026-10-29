module;
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
module nexus.config;
import std;
import nexus.thirdparty.glaze;
namespace nexus::config {
    namespace g = nex::glaze;
    namespace {
        using Node = g::KdlNode;
        using Value = g::KdlValue;
        auto error(std::string text) -> std::unexpected<std::string> { return std::unexpected(std::move(text)); }
        auto string(Value const& value) -> std::string const* {
            return value.tag ? nullptr : std::get_if<std::string>(&value.data);
        }
        auto argument(Node const& node) -> std::string const* {
            if (node.tag || node.arguments.size() != 1) return nullptr;
            return string(node.arguments.front());
        }
        auto property(Node const& node, std::string_view name) -> Value const* {
            for (auto const& [key, value] : node.properties) if (key == name) return &value;
            return nullptr;
        }
        auto text_property(Node const& node, std::string_view name) -> std::string const* {
            auto value = property(node, name);
            return value ? string(*value) : nullptr;
        }
        auto scalar(Node const& node) -> std::string const* {
            return node.properties.empty() && node.children.empty() ? argument(node) : nullptr;
        }
        auto integer(Value const& value) -> std::optional<std::uint64_t> {
            if (value.tag) return {};
            if (auto number = std::get_if<std::uint64_t>(&value.data)) return *number;
            if (auto number = std::get_if<std::int64_t>(&value.data); number && *number >= 0)
                return static_cast<std::uint64_t>(*number);
            return {};
        }
        auto valid_name(std::string_view name) -> bool {
            return !name.empty() && name.size() <= 255 && name.find('\0') == std::string_view::npos;
        }
        auto absolute_path(std::string_view path) -> bool {
            return !path.empty() && path.front() == '/' && path.find('\0') == path.npos;
        }
        auto endpoint_name(std::string_view name) -> bool {
            return !name.empty() && name.size() <= 253 && std::all_of(name.begin(), name.end(),
                [](unsigned char c) { return c >= 33 && c <= 126; });
        }
        auto ipv4(std::string_view text) -> std::optional<std::array<std::uint8_t,4>> {
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
        auto dns_address(Node const& node, bool default_port) -> std::expected<DnsUpstream, std::string> {
            auto host=text_property(node,"host");
            auto address=host ? ipv4(*host) : std::nullopt;
            std::array<std::uint8_t,16> bytes{};
            bool is_v6=false;
            if (address) std::copy(address->begin(),address->end(),bytes.begin());
            else if (host && host->find('\0')==host->npos && host->find('%')==host->npos &&
                     ::inet_pton(AF_INET6,host->c_str(),bytes.data())==1) is_v6=true;
            auto value=property(node,"port");
            auto port=value ? integer(*value) : (default_port ? std::optional<std::uint64_t>{53} : std::nullopt);
            if ((!address && !is_v6) || !port || !*port || *port>65535)
                return error("DNS server requires numeric IP host without zone and port 1..65535");
            return DnsUpstream{bytes,is_v6,static_cast<std::uint16_t>(*port)};
        }
        auto dns_domain(std::string_view name) -> bool {
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
        auto dns(Node const& node) -> std::expected<DnsRouting, std::string> {
            if (node.tag || !node.arguments.empty() || !node.properties.empty()) return error("dns takes no arguments or properties");
            DnsRouting result;
            std::vector<std::pair<DnsRule,std::string>> pending;
            std::vector<std::pair<std::size_t,std::string>> dependencies;
            std::optional<std::string> final;
            bool strategy_seen=false, cache_seen=false, edns_seen=false;
            std::vector<Node const*> children;
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
                if (child.name=="server") {
                    auto name=argument(child);
                    auto type=text_property(child,"type");
                    if (!name || !valid_name(*name) || !type || !child.children.empty() || result.servers.size()>=64 ||
                        std::ranges::any_of(result.servers,[&](auto const& server) { return server.name==*name; }))
                        return error("invalid or duplicate DNS server name");
                    std::optional<DnsUpstream> upstream;
                    if (*type=="local" && child.properties.size()==1) {
                        // The existing system resolver is the local server.
                    } else if (*type=="udp" || *type=="tcp") {
                        auto host=text_property(child,"host");
                        auto resolver=text_property(child,"domain-resolver");
                        auto parsed=dns_address(child,true);
                        auto expected=2u+(property(child,"port") ? 1u : 0u)+(property(child,"domain-resolver") ? 1u : 0u);
                        if (!host || child.properties.size()!=expected) return error("invalid DNS server fields");
                        if (parsed) {
                            if (resolver || property(child,"domain-resolver")) return error("numeric DNS server must not have domain-resolver");
                            upstream=*parsed;
                        } else {
                            auto value=property(child,"port");
                            auto port=value ? integer(*value) : std::optional<std::uint64_t>{53};
                            bool numeric_like=std::ranges::all_of(*host,[](char c) { return (c>='0' && c<='9') || c=='.'; });
                            if (!dns_domain(*host) || numeric_like || !resolver || !valid_name(*resolver) || !port || !*port || *port>65535)
                                return error("DNS hostname requires domain-resolver and a valid port");
                            upstream=DnsUpstream{};
                            upstream->host=*host;
                            upstream->port=static_cast<std::uint16_t>(*port);
                            dependencies.emplace_back(result.servers.size(),*resolver);
                        }
                        upstream->tcp=*type=="tcp";
                    } else return error("unsupported DNS server type or fields");
                    result.servers.push_back({*name,upstream});
                } else if (child.name=="rule") {
                    auto domain=text_property(child,"domain");
                    auto suffix=text_property(child,"domain-suffix");
                    auto server=text_property(child,"server");
                    if (child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=2 ||
                        bool(domain)==bool(suffix) || !server || !valid_name(*server) || pending.size()>=256 ||
                        !dns_domain(domain ? *domain : *suffix)) return error("invalid DNS domain rule");
                    auto value=domain ? *domain : *suffix;
                    for (auto& c : value) if (c>='A' && c<='Z') c+=('a'-'A');
                    pending.push_back({DnsRule{std::move(value),bool(suffix),0},*server});
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
                } else return error("unsupported DNS node: " + child.name);
            }
            if (result.servers.empty()) return error("dns requires at least one server");
            auto index=[&](std::string const& name) -> std::optional<std::size_t> {
                auto found=std::ranges::find(result.servers,name,&DnsServer::name);
                if (found==result.servers.end()) return {};
                return static_cast<std::size_t>(found-result.servers.begin());
            };
            result.final=0;
            if (final) {
                auto selected=index(*final);
                if (!selected) return error("DNS final server not found");
                result.final=*selected;
            }
            for (auto& [rule,server] : pending) {
                auto selected=index(server);
                if (!selected) return error("DNS rule server not found");
                rule.server=*selected;
                result.rules.push_back(std::move(rule));
            }
            for (auto const& [server,name] : dependencies) {
                auto selected=index(name);
                if (!selected) return error("DNS domain-resolver not found");
                result.servers[server].upstream->resolver=*selected;
            }
            for (std::size_t start=0;start<result.servers.size();++start) {
                std::vector<bool> visited(result.servers.size());
                auto current=start;
                while (result.servers[current].upstream && result.servers[current].upstream->resolver) {
                    if (visited[current]) return error("circular DNS domain-resolver dependency");
                    visited[current]=true;
                    current=*result.servers[current].upstream->resolver;
                }
            }
            return result;
        }
        auto vless_outbound(Node const& node) -> std::expected<VlessOutbound, std::string> {
            VlessOutbound result;
            bool server_seen=false, auth_seen=false, tls_seen=false;
            for (auto const& child : node.children) {
                if (child.name == "server") {
                    auto host = text_property(child, "host");
                    auto value = property(child, "port");
                    auto port = value ? integer(*value) : std::nullopt;
                    if (server_seen || child.tag || !child.arguments.empty() || !child.children.empty() ||
                        child.properties.size()!=2 || !host || !endpoint_name(*host) || !port || !*port || *port>65535)
                        return error("vless requires one server with host and port 1..65535");
                    result.host=*host; result.port=static_cast<std::uint16_t>(*port); server_seen=true;
                } else if (child.name == "bootstrap-resolver") {
                    auto value=scalar(child);
                    if (result.bootstrap_resolver || !value || !valid_name(*value)) return error("invalid vless bootstrap-resolver");
                    result.bootstrap_resolver=*value;
                } else if (child.name == "authentication") {
                    if (auth_seen || child.tag || !child.arguments.empty() || !child.properties.empty() || child.children.size()!=1 ||
                        child.children.front().name!="uuid-file") return error("vless requires one uuid-file");
                    auto path=scalar(child.children.front());
                    if (!path || !absolute_path(*path)) return error("vless uuid-file must be absolute");
                    result.uuid_file=*path; auth_seen=true;
                } else if (child.name == "tls") {
                    if (tls_seen || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid vless tls");
                    bool name_seen=false, ca_seen=false, verify_seen=false, key_exchange_seen=false;
                    for (auto const& field : child.children) {
                        if (field.name=="server-name") {
                            auto value=scalar(field);
                            if (name_seen || !value || !endpoint_name(*value)) return error("invalid vless tls server-name");
                            result.server_name=*value; name_seen=true;
                        } else if (field.name=="ca-file") {
                            auto value=scalar(field);
                            if (ca_seen || !value || !absolute_path(*value)) return error("vless tls ca-file must be absolute");
                            result.ca_file=*value; ca_seen=true;
                        } else if (field.name=="key-exchange") {
                            auto value=scalar(field);
                            if (key_exchange_seen || !value || (*value!="x25519" && *value!="x25519-mlkem768" && *value!="x25519-mlkem768-only"))
                                return error("vless tls key-exchange must be x25519, x25519-mlkem768 or x25519-mlkem768-only");
                            result.key_exchange=*value=="x25519" ? TlsKeyExchange::x25519 :
                                *value=="x25519-mlkem768" ? TlsKeyExchange::x25519_mlkem768 : TlsKeyExchange::x25519_mlkem768_only;
                            key_exchange_seen=true;
                        } else if (field.name=="verify") {
                            if (verify_seen || field.tag || !field.properties.empty() || !field.children.empty() || field.arguments.size()!=1 ||
                                field.arguments[0].tag || !std::holds_alternative<bool>(field.arguments[0].data) || !std::get<bool>(field.arguments[0].data))
                                return error("vless tls requires verify #true");
                            verify_seen=true;
                        } else return error("unsupported vless tls node: " + field.name);
                    }
                    if (!name_seen || !ca_seen || !verify_seen) return error("vless tls requires server-name, ca-file and verify #true");
                    tls_seen=true;
                } else return error("unsupported vless node: " + child.name);
            }
            if (!server_seen || !auth_seen || !tls_seen) return error("vless requires server, authentication and tls");
            return result;
        }
#include "shadowsocks.hpp"
        auto version(Node const& node) -> bool {
            return !node.tag && node.properties.empty() && node.children.empty() && node.arguments.size() == 1 &&
                   integer(node.arguments.front()) == 1;
        }
#include "inbound.hpp"
#include "routing.hpp"
    }
#include "groups.hpp"
    auto parse_kdl(std::string_view input) -> std::expected<Config, std::string> {
        if (input.size() > max_config_bytes) return error("configuration exceeds 1 MiB");
        auto document = g::read_kdl<g::KdlDocument>(input);
        if (!document) return error(g::format_error(document.error(), input));
        if (auto result=normalize_groups(*document); !result) return std::unexpected(result.error());
        bool version_seen = false, role_seen = false, inbound_seen = false, workers_seen = false, dns_seen = false;
        std::optional<std::string> direct, block;
        std::optional<Route> route;
        Config result;
        std::vector<Node const*> nodes;
        bool inbounds_block=false, outbounds_block=false, legacy_inbound=false, legacy_outbound=false;
        for (auto const& node : *document) {
            if (node.name=="inbounds" || node.name=="outbounds") {
                bool is_inbound=node.name=="inbounds";
                auto& seen=is_inbound ? inbounds_block : outbounds_block;
                bool legacy=is_inbound ? legacy_inbound : legacy_outbound;
                if (seen || legacy || node.tag || !node.arguments.empty() || !node.properties.empty())
                    return error("invalid or duplicate " + node.name + " block");
                seen=true;
                for (auto const& child : node.children) {
                    if (child.name!=(is_inbound ? "inbound" : "outbound")) return error("invalid child in " + node.name);
                    nodes.push_back(&child);
                }
            } else {
                if (node.name=="inbound") {
                    if (inbounds_block) return error("cannot mix inbounds block and top-level inbound nodes");
                    legacy_inbound=true;
                } else if (node.name=="outbound") {
                    if (outbounds_block) return error("cannot mix outbounds block and top-level outbound nodes");
                    legacy_outbound=true;
                }
                nodes.push_back(&node);
            }
        }
        for (auto const* item : nodes) {
            auto const& node=*item;
            if (node.name == "schema-version") {
                if (version_seen || !version(node)) return error("expected one schema-version 1");
                version_seen = true;
            } else if (node.name == "role") {
                auto value = scalar(node);
                if (role_seen || !value || (*value != "client" && *value != "server")) return error("expected one client or server role");
                role_seen = true;
            } else if (node.name == "workers") {
                auto value=node.arguments.size()==1 ? integer(node.arguments.front()) : std::nullopt;
                if (workers_seen || node.tag || !node.properties.empty() || !node.children.empty() || !value || *value<1 || *value>16)
                    return error("workers must be an integer from 1 to 16");
                result.workers=static_cast<unsigned>(*value); workers_seen=true;
            } else if (node.name == "dns-upstream") {
                auto parsed=dns_address(node,false);
                if (dns_seen || node.tag || !node.arguments.empty() || !node.children.empty() ||
                    node.properties.size()!=2 || !parsed)
                    return error("dns-upstream requires numeric IP host without zone and port 1..65535");
                result.dns_upstream=*parsed; dns_seen=true;
            } else if (node.name == "dns") {
                if (dns_seen) return error("only one DNS configuration is supported");
                auto parsed=dns(node);
                if (!parsed) return std::unexpected(parsed.error());
                result.dns=std::move(*parsed); dns_seen=true;
            } else if (node.name == "inbound") {
                auto name=argument(node);
                if (!name || result.inbounds.size()>=16 || std::ranges::any_of(result.inbounds,
                    [&](auto const& entry) { return entry.name==*name; })) return error("invalid or duplicate inbound name");
                Config parsed_inbound;
                auto port = inbound(node, parsed_inbound);
                if (!port) return std::unexpected(port.error());
                if (std::ranges::any_of(result.inbounds,[&](auto const& entry) { return entry.port==*port; }))
                    return error("inbound listen ports must be unique");
                result.inbounds.push_back({*name,*port,parsed_inbound.inbound,std::move(parsed_inbound.password_auth),std::move(parsed_inbound.vless_inbound),std::move(parsed_inbound.shadowsocks_inbound),parsed_inbound.listen_ipv6});
                if (!inbound_seen) {
                    result.port=*port; result.inbound=result.inbounds.back().type;
                    result.listen_ipv6=result.inbounds.back().listen_ipv6;
                    result.password_auth=result.inbounds.back().password_auth;
                }
                inbound_seen = true;
            } else if (node.name == "outbound") {
                auto name = argument(node);
                auto type = text_property(node, "type");
                if (!name || !valid_name(*name) || !type || node.properties.size() != 1)
                    return error("outbound requires a name and type");
                if (*type == "direct" && !direct && node.children.empty()) direct = *name;
                else if (*type == "block" && !block && node.children.empty()) block = *name;
                else if (*type == "vless" && result.vless_outbounds.size()<16) {
                    auto parsed=vless_outbound(node);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.vless_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if (*type == "shadowsocks" && result.shadowsocks_outbounds.size()<16) {
                    auto parsed=shadowsocks_outbound(node);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.shadowsocks_outbounds.push_back({*name,std::move(*parsed)});
                }
                else return error("unsupported or duplicate outbound type");
            } else if (node.name == "routing") {
                if (route) return error("only one routing node is supported");
                auto parsed = routing(node);
                if (!parsed) return std::unexpected(parsed.error());
                route = std::move(*parsed);
            } else return error("unsupported configuration node: " + node.name);
        }
        if (!version_seen || !role_seen || !inbound_seen || !direct || !route)
            return error("schema-version, role, inbound, direct outbound and routing are required");
        if (block && *block==*direct) return error("outbound names must be unique");
        if (result.vless_outbounds.size()+result.shadowsocks_outbounds.size()>16) return error("too many tunnel outbounds");
        for (std::size_t i=0;i<result.vless_outbounds.size();++i) {
            auto& outbound_config=result.vless_outbounds[i].config;
            if (outbound_config.bootstrap_resolver) {
                if (!result.dns || !dns_domain(outbound_config.host) || ipv4(outbound_config.host))
                    return error("vless bootstrap-resolver requires DNS configuration and a domain server host");
                auto found=std::ranges::find(result.dns->servers,*outbound_config.bootstrap_resolver,&DnsServer::name);
                if (found==result.dns->servers.end()) return error("vless bootstrap-resolver not found");
                outbound_config.bootstrap_index=static_cast<std::size_t>(found-result.dns->servers.begin());
            }
            auto const& name=result.vless_outbounds[i].name;
            if (name==*direct || (block && name==*block) ||
                std::ranges::any_of(std::span(result.vless_outbounds).first(i),[&](auto const& other) { return other.name==name; }))
                return error("outbound names must be unique");
            if (route->default_outbound!=name && std::ranges::none_of(route->rules,[&](auto const& rule) { return rule.outbound==name; }))
                return error("vless must be referenced by routing");
        }
        if (auto valid=validate_shadowsocks(result,*direct,block,*route); !valid) return std::unexpected(valid.error());
        auto outbound=[&](std::string const& name) -> std::optional<std::size_t> {
            if (name==*direct) return 0;
            if (block && name==*block) return 1;
            auto found=std::ranges::find(result.vless_outbounds,name,&NamedVlessOutbound::name);
            if (found!=result.vless_outbounds.end()) return static_cast<std::size_t>(found-result.vless_outbounds.begin())+2;
            auto ss=std::ranges::find(result.shadowsocks_outbounds,name,&NamedShadowsocksOutbound::name);
            if (ss==result.shadowsocks_outbounds.end()) return {};
            return static_cast<std::size_t>(ss-result.shadowsocks_outbounds.begin())+2+result.vless_outbounds.size();
        };
        auto fallback=outbound(*route->default_outbound);
        if (!fallback || *fallback==1) return error("default-outbound must name a direct or tunnel outbound");
        result.default_outbound=*fallback;
        result.default_action=*fallback>=2 ? RouteAction::vless : RouteAction::direct;
        if (!result.vless_outbounds.empty()) result.vless=result.vless_outbounds.front().config;
        for (auto const& rule : route->rules) {
            auto selected=outbound(rule.outbound);
            if (!selected) return error("rule outbound not found");
            auto file=std::ranges::find(route->files,rule.set,&NamedRouteFile::name);
            auto action=*selected==0 ? RouteAction::direct : *selected==1 ? RouteAction::block : RouteAction::vless;
            result.routes.push_back({file->file,action,*selected});
        }
        if (!result.routes.empty()) {
            result.block_rules=result.routes.front().file;
            result.rule_action=result.routes.front().action;
        }
        return result;
    }
}
