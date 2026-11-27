module config;
import std;
import logging.options;
import glaze;
import config.kdl_common;
import config.rule_set_parse;
import http.header;
import http.connect;
import platform.ip_address;
import rules;
import rules.kdl_predicate;
import config.routing;
namespace config {
    namespace g = ::glaze;
    auto parse_logging(g::KdlNode const&) -> std::expected<logging::Config,std::string>;
    auto is_extra_top_level(std::string_view) noexcept -> bool;
    auto parse_extra_top_level(kdl::Node const&,Config&) -> std::expected<void,std::string>;
    auto logging_paths(g::KdlDocument const&) -> std::vector<std::string>;
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_hostname(std::string_view) -> bool;
    auto parse_dns(g::KdlNode const&) -> std::expected<DnsRouting,std::string>;
    auto parse_tcp_dial_option(g::KdlNode const&,TcpSocketOptions&) -> std::expected<bool,std::string>;
    auto parse_direct_dial(g::KdlNode const&,Config&) -> std::expected<void,std::string>;
    auto apply_routing_defaults(Config&) -> std::expected<void,std::string>;
    auto parse_trojan_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_trojan_outbound(g::KdlNode const&) -> std::expected<TrojanOutbound,std::string>;
    auto validate_trojan(Config&,std::string_view,std::optional<std::string> const&) -> std::expected<void,std::string>;
    auto parse_anytls_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_httpupgrade_transport(g::KdlNode const&) -> std::expected<HttpUpgradeTransport,std::string>;
    auto parse_vless_transport(g::KdlNode const&,bool) -> std::expected<std::variant<HttpUpgradeTransport,GrpcTransport,xhttp::Profile>,std::string>;
    auto parse_anytls_outbound(g::KdlNode const&) -> std::expected<AnyTlsOutbound,std::string>;
    auto validate_anytls(Config&,std::string_view,std::optional<std::string> const&) -> std::expected<void,std::string>;
    auto parse_masque_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_snell_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_snell_outbound(g::KdlNode const&) -> std::expected<SnellOutbound,std::string>;
    auto parse_tcp_proxy_outbound(g::KdlNode const&,TcpProxyProtocol) -> std::expected<TcpProxyOutbound,std::string>;
    auto parse_hysteria2_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_hysteria2_outbound(g::KdlNode const&) -> std::expected<Hysteria2Outbound,std::string>;
    auto validate_hysteria2(Config&,std::string_view,std::optional<std::string> const&) -> std::expected<void,std::string>;
    auto parse_shadowtls_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_shadowtls_outbound(g::KdlNode const&) -> std::expected<ShadowTlsOutbound,std::string>;
    auto parse_tuic_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_tuic_outbound(g::KdlNode const&) -> std::expected<TuicOutbound,std::string>;
    auto parse_vless_outbound(g::KdlNode const&) -> std::expected<VlessOutbound,std::string>;
    auto parse_tun_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto tun_endpoints_overlap(std::optional<TunInbound> const&,std::optional<TunInbound> const&) noexcept -> bool;
    auto configure_tun_strict_route(Config&) -> std::expected<void,std::string>;
    auto validate_tun_rule_set_refs(Config const&,std::span<std::string const>,bool,std::span<std::string const>) -> std::expected<void,std::string>;
    auto parse_masque_outbound(g::KdlNode const&) -> std::expected<MasqueOutbound,std::string>;
    auto parse_wireguard_outbound(g::KdlNode const&) -> std::expected<WireGuardOutbound,std::string>;
    auto parse_ssh_outbound(g::KdlNode const&) -> std::expected<SshOutbound,std::string>;
    auto parse_naive_inbound(g::KdlNode const&) -> std::expected<InboundConfig,std::string>;
    auto parse_naive_outbound(g::KdlNode const&) -> std::expected<NaiveOutbound,std::string>;
    auto parse_openvpn_outbound(g::KdlNode const&) -> std::expected<OpenVpnOutbound,std::string>;
    auto parse_openconnect_outbound(g::KdlNode const&) -> std::expected<OpenConnectOutbound,std::string>;
    auto validate_naive_outbounds(Config&,std::string_view,std::optional<std::string> const&,
                                  bool (*)(void const*,std::string_view),void const*) -> std::expected<void,std::string>;
    auto validate_extra_outbounds(Config&,std::string_view,std::optional<std::string> const&,
                                  bool (*)(void const*,std::string_view),void const*) -> std::expected<void,std::string>;
    auto validate_quic_ech(QuicEchOptions const&,std::string_view,bool) -> std::expected<void,std::string>;
    using namespace config::kdl;
    using routing_detail::Route;
    using routing_detail::NamedRouteFile;
    using routing_detail::valid_fakeip_routing;
    using routing_detail::routing;
    using routing_detail::referenced_outbound;
    auto shadowsocks_outbound(kdl::Node const&) -> std::expected<ShadowsocksOutbound, std::string>;
    auto validate_shadowsocks(Config&, std::string const&, std::optional<std::string> const&, Route const&) -> std::expected<void, std::string>;
    auto inbound(kdl::Node const&, Config&) -> std::expected<std::uint16_t, std::string>;
    auto fixed_tcp_inbound(kdl::Node const&, Config&) -> std::expected<std::uint16_t, std::string>;
    auto fixed_udp_inbound(kdl::Node const&, Config&) -> std::expected<std::uint16_t, std::string>;
    auto inbound_with_limits(kdl::Node const&, Config&, kdl::Node const*&) -> std::expected<std::uint16_t, std::string>;
    auto parse_user_limits(InboundConfig&, kdl::Node const*) -> std::expected<void, std::string>;
    auto parse_http_clients(kdl::Node const&) -> std::expected<std::vector<NamedHttpClient>, std::string>;
    auto parse_state_options(kdl::Node const&) -> std::expected<StateOptions, std::string>;
    auto apply_state_options(Config&) -> std::expected<void, std::string>;
    auto parse_certificate_block(kdl::Node const&) -> std::expected<CertificateConfig, std::string>;
    auto parse_ntp_block(kdl::Node const&) -> std::expected<NtpConfig, std::string>;
    auto apply_certificate_defaults(Config&) -> std::expected<void, std::string>;
    auto normalize_groups(g::KdlDocument&) -> std::expected<void, std::string>;
    auto parse_outbound_selector(g::KdlNode const&, std::string_view, std::string_view) -> std::expected<OutboundSelector, std::string>;
    auto is_process_option(std::string_view) noexcept -> bool;
    auto parse_process_option(kdl::Node const&, Config&) -> std::expected<void, std::string>;
    auto parse_workers_node(kdl::Node const&, Config&, bool&) -> std::expected<void, std::string>;
    auto parse_kdl(std::string_view input) -> std::expected<Config, std::string> {
        auto document = kdl::read_document(input,max_config_bytes);
        if (!document) return std::unexpected(document.error());
        if (auto result=normalize_groups(*document); !result) return std::unexpected(result.error());
        bool version_seen = false, role_seen = false, inbound_seen = false, workers_seen = false, dns_seen = false;
        std::optional<std::string> direct, block;
        std::optional<Route> route;
        Config result; result.host_parallelism = detect_host_parallelism();
        std::vector<Node const*> nodes;
        bool inbounds_block=false, outbounds_block=false;
        for (auto const& node : *document) {
            if (node.name=="inbounds" || node.name=="outbounds") {
                bool is_inbound=node.name=="inbounds";
                auto& seen=is_inbound ? inbounds_block : outbounds_block;
                if (seen || node.tag || !node.arguments.empty() || !node.properties.empty())
                    return error("invalid or duplicate " + node.name + " block");
                seen=true;
                for (auto const& child : node.children) {
                    if (child.name!=(is_inbound ? "inbound" : "outbound")) return error("invalid child in " + node.name);
                    nodes.push_back(&child);
                }
            } else if (node.name=="inbound" || node.name=="outbound") {
                return error("top-level " + node.name + " is removed; wrap in " + node.name + "s { ... }");
            } else {
                nodes.push_back(&node);
            }
        }
        for (auto const* item : nodes) {
            auto const& node=*item;
            if (node.name == "schema-version") {
                if (version_seen || !version(node)) return error("expected one schema-version 1");
                version_seen = true;
            } else if (node.name == "role") {
                auto value = kdl::deployment_role(node);
                if (role_seen || !value) return error("expected one client or server role");
                role_seen = true;
            } else if (node.name == "log") {
                if (result.log) return error("duplicate log block");
                auto parsed = parse_logging(node);
                if (!parsed) return std::unexpected(parsed.error());
                result.log = std::move(*parsed);
            } else if (node.name == "state") {
                if (result.state) return error("duplicate state block");
                auto parsed=parse_state_options(node);
                if (!parsed) return std::unexpected(parsed.error());
                result.state=std::move(*parsed);
            } else if (node.name == "certificate") {
                if (result.certificate) return error("duplicate certificate block");
                auto parsed=parse_certificate_block(node);
                if (!parsed) return std::unexpected(parsed.error());
                result.certificate=std::move(*parsed);
            } else if (node.name == "ntp") {
                if (result.ntp) return error("duplicate ntp block");
                auto parsed=parse_ntp_block(node);
                if (!parsed) return std::unexpected(parsed.error());
                result.ntp=std::move(*parsed);
            } else if (is_extra_top_level(node.name)) {
                if (auto ok=parse_extra_top_level(node,result); !ok) return std::unexpected(ok.error());
            } else if (node.name == "workers") {
                if (auto ok = parse_workers_node(node, result, workers_seen); !ok) return std::unexpected(std::move(ok.error()));
            } else if (is_process_option(node.name)) {
                if (auto parsed=parse_process_option(node,result); !parsed) return std::unexpected(std::move(parsed.error()));
            } else if (node.name == "dns") {
                if (dns_seen) return error("only one DNS configuration is supported");
                auto parsed=parse_dns(node);
                if (!parsed) return std::unexpected(parsed.error());
                result.dns=std::move(*parsed); dns_seen=true;
            } else if (node.name == "http-clients") {
                if(!result.http_clients.empty())return error("duplicate http-clients block");
                auto clients=parse_http_clients(node);
                if(!clients)return std::unexpected(clients.error());
                result.http_clients=std::move(*clients);
            } else if (node.name == "inbound") {
                auto name=argument(node);
                if (!name || result.inbounds.size()>=16 || std::ranges::any_of(result.inbounds,
                    [&](auto const& entry) { return entry.name==*name; })) return error("invalid or duplicate inbound name");
                Config parsed_inbound;
                Node const* limit=nullptr;
                auto port=inbound_with_limits(node,parsed_inbound,limit);
                if (!port) return std::unexpected(port.error());
                auto listen_address=[](bool ipv6,auto const& explicit_addr,auto const& hy2,auto const& snell,auto const& masque,auto const& shadowtls,auto const& tuic,auto const& redirect,auto const& fudp,auto const& naive,auto const& http) {
                    std::array<std::uint8_t,16> address{};
                    if (explicit_addr) return *explicit_addr;
                    if (hy2) return hy2->listen_address;
                    if (snell) return snell->listen_address;
                    if (masque) return masque->listen_address;
                    if (shadowtls) return shadowtls->listen_address;
                    if (tuic) return tuic->listen_address;
                    if (redirect) return *redirect;
                    if (fudp) return fudp->listen_address;
                    if (naive) return naive->listen_address;
                    if (http && http->has_tls) return http->listen_address;
                    if (ipv6) address[15]=1;
                    else {address[0]=127;address[3]=1;}
                    return address;
                };
                auto uses_tcp=[](Inbound kind,auto const& naive,auto const& http,bool transparent_udp) noexcept {
                    if (transparent_udp) return true;
                    if (kind==Inbound::naive) return !naive || naive->protocol!=NaiveProtocol::h3;
                    if (kind==Inbound::http) return !http || !http->has_tls || http->http2 || !http->http3;
                    return kind!=Inbound::hysteria2 && kind!=Inbound::masque && kind!=Inbound::tuic && kind!=Inbound::fixed_udp;
                };
                auto uses_udp=[](Inbound kind,auto const& naive,auto const& http,bool transparent_udp) noexcept {
                    if (transparent_udp) return true;
                    if (kind==Inbound::naive) return naive && naive->protocol!=NaiveProtocol::h2;
                    if (kind==Inbound::http) return http && http->has_tls && http->http3;
                    return kind==Inbound::hysteria2 || kind==Inbound::masque || kind==Inbound::tuic || kind==Inbound::fixed_udp;
                };
                auto address=listen_address(parsed_inbound.listen_ipv6,parsed_inbound.listen_address,parsed_inbound.hysteria2_inbound,parsed_inbound.snell_inbound,parsed_inbound.masque_inbound,parsed_inbound.shadowtls_inbound,parsed_inbound.tuic_inbound,parsed_inbound.redirect_inbound,parsed_inbound.fixed_udp_inbound,parsed_inbound.naive_inbound,parsed_inbound.http_inbound);
                auto wildcard=[](auto const& value) {return std::ranges::all_of(value,[](auto byte){return byte==0;});};
                auto right_tcp=uses_tcp(parsed_inbound.inbound,parsed_inbound.naive_inbound,parsed_inbound.http_inbound,parsed_inbound.transparent_udp);
                auto right_udp=uses_udp(parsed_inbound.inbound,parsed_inbound.naive_inbound,parsed_inbound.http_inbound,parsed_inbound.transparent_udp);
                if (std::ranges::any_of(result.inbounds,[&](auto const& entry) {
                    if (entry.type==Inbound::tun || parsed_inbound.inbound==Inbound::tun)
                        return tun_endpoints_overlap(entry.tun,parsed_inbound.tun_inbound);
                    if (!entry.unix_path.empty() || !parsed_inbound.unix_path.empty())
                        return entry.unix_path==parsed_inbound.unix_path;
                    if (entry.listen.netns!=parsed_inbound.listen.netns) return false;
                    if (entry.port!=*port || entry.listen_ipv6!=parsed_inbound.listen_ipv6) return false;
                    auto left_tcp=uses_tcp(entry.type,entry.naive,entry.http,entry.transparent_udp);
                    auto left_udp=uses_udp(entry.type,entry.naive,entry.http,entry.transparent_udp);
                    if (!((left_tcp && right_tcp) || (left_udp && right_udp))) return false;
                    auto existing=listen_address(entry.listen_ipv6,entry.listen_address,entry.hysteria2,entry.snell,entry.masque,entry.shadowtls,entry.tuic,entry.redirect_address,entry.fixed_udp,entry.naive,entry.http);
                    return existing==address || wildcard(existing) || wildcard(address);
                })) return error("inbound listen endpoints overlap");
                result.inbounds.push_back({*name,*port,parsed_inbound.inbound,std::move(parsed_inbound.password_auth),std::move(parsed_inbound.vless_inbound),std::move(parsed_inbound.shadowsocks_inbound),parsed_inbound.listen_ipv6,std::move(parsed_inbound.trojan_inbound),std::move(parsed_inbound.anytls_inbound),std::move(parsed_inbound.hysteria2_inbound),std::move(parsed_inbound.snell_inbound),std::move(parsed_inbound.masque_inbound),std::move(parsed_inbound.shadowtls_inbound),std::move(parsed_inbound.tuic_inbound),std::move(parsed_inbound.tun_inbound),parsed_inbound.redirect_inbound,parsed_inbound.listen_address,std::move(parsed_inbound.redirect_host),std::move(parsed_inbound.listen_host),parsed_inbound.transparent_udp});
                auto& entry=result.inbounds.back();
                entry.fixed_tcp=std::move(parsed_inbound.fixed_tcp_inbound);
                entry.fixed_udp=std::move(parsed_inbound.fixed_udp_inbound);
                entry.unix_path=std::move(parsed_inbound.unix_path);
                entry.udp_advertise_ip=parsed_inbound.udp_advertise_ip;
                entry.naive=std::move(parsed_inbound.naive_inbound);
                entry.http=std::move(parsed_inbound.http_inbound); entry.listen=std::move(parsed_inbound.listen);
                if (auto limits=parse_user_limits(entry,limit); !limits)
                    return std::unexpected(limits.error());
                if (!inbound_seen) {
                    result.port=*port; result.inbound=result.inbounds.back().type;
                    result.listen_ipv6=result.inbounds.back().listen_ipv6;
                    result.password_auth=result.inbounds.back().password_auth; result.listen=result.inbounds.back().listen;
                }
                inbound_seen = true;
            } else if (node.name == "outbound") {
                auto name = argument(node);
                auto type = text_property(node, "type");
                if (!name || !valid_name(*name) || !type || node.properties.size() != 1)
                    return error("outbound requires a name and type");
                if (*type == "direct" && !direct) {
                    if (auto dial=parse_direct_dial(node,result); !dial) return std::unexpected(dial.error());
                    direct=*name;
                }
                else if (*type == "block" && !block && node.children.empty()) block = *name;
                else if ((*type=="selector" || *type=="fallback" || *type=="url-test" || *type=="load-balance") && result.selectors.size()<max_tunnel_outbounds) {
                    auto selector=parse_outbound_selector(node,*name,*type);
                    if (!selector) return std::unexpected(selector.error());
                    result.selectors.push_back(std::move(*selector));
                }
                else if (*type == "vless" && result.vless_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_vless_outbound(node);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.vless_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if (*type == "shadowsocks" && result.shadowsocks_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=shadowsocks_outbound(node);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.shadowsocks_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if (*type=="trojan" && result.trojan_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_trojan_outbound(node);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.trojan_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if (*type=="anytls" && result.anytls_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_anytls_outbound(node);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.anytls_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="hysteria2" && result.hysteria2_outbounds.size()<max_tunnel_outbounds){
                    auto parsed=parse_hysteria2_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.hysteria2_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="snell" && result.snell_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_snell_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.snell_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if ((*type=="socks5" || *type=="http-connect" || *type=="socks4" || *type=="socks4a") && result.tcp_proxy_outbounds.size()<max_tunnel_outbounds) {
                    auto protocol=*type=="socks5" ? TcpProxyProtocol::socks5 :
                        *type=="socks4" ? TcpProxyProtocol::socks4 :
                        *type=="socks4a" ? TcpProxyProtocol::socks4a : TcpProxyProtocol::http_connect;
                    auto parsed=parse_tcp_proxy_outbound(node,protocol);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.tcp_proxy_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="shadowtls" && result.shadowtls_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_shadowtls_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.shadowtls_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="tuic" && result.tuic_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_tuic_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.tuic_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="masque" && result.masque_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_masque_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.masque_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="wireguard" && result.wireguard_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_wireguard_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.wireguard_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="ssh" && result.ssh_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_ssh_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.ssh_outbounds.push_back({*name,std::move(*parsed)});
                } else if(*type=="naive" && result.naive_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_naive_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.naive_outbounds.push_back({*name,std::move(*parsed)});
                } else if(*type=="openvpn" && result.openvpn_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_openvpn_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.openvpn_outbounds.push_back({*name,std::move(*parsed)});
                } else if(*type=="openconnect" && result.openconnect_outbounds.size()<max_tunnel_outbounds) {
                    auto parsed=parse_openconnect_outbound(node);if(!parsed)return std::unexpected(parsed.error());
                    result.openconnect_outbounds.push_back({*name,std::move(*parsed)});
                }
                else if(*type=="tailscale" && result.tailscale_outbounds.empty()) {
                    if(node.children.size()!=1 || node.children[0].name!="endpoint-file")
                        return error("Tailscale outbound requires one endpoint-file");
                    auto file=scalar(node.children[0]);
                    if(!file || !absolute_path(*file))return error("Tailscale endpoint-file must be absolute");
                    result.tailscale_outbounds.push_back({*name,std::move(*file)});
                }
                else return error("unsupported or duplicate outbound type");
            } else if (node.name == "routing") {
                if (route) return error("only one routing node is supported");
                auto parsed = routing(node);
                if (!parsed) return std::unexpected(parsed.error());
                route = std::move(*parsed);
            } else return error("unsupported configuration node: " + node.name);
        }
        if (auto applied=apply_state_options(result); !applied) return std::unexpected(applied.error());
        if (auto certs=apply_certificate_defaults(result); !certs) return std::unexpected(certs.error());
        if (result.log) result.log_protected_paths = logging_paths(*document);
        if (!version_seen || !role_seen || !inbound_seen || !direct || !route)
            return error("schema-version, role, inbound, direct outbound and routing are required");
        if (auto bound=bind_outbound_selectors(result,*direct,block); !bound) return std::unexpected(bound.error());
        for(auto& client:result.http_clients) {
            if(!result.dns) return error("HTTP client requires a DNS block");
            auto group=std::ranges::find(result.selectors,client.outbound,&OutboundSelector::name);
            if (group!=result.selectors.end() && (group->uses_probe || group->uses_balance))
                return error("HTTP client requires a manual outbound group");
            auto outbound=outbound_index(result,*direct,block,client.outbound);
            if(!outbound || *outbound==1) return error("HTTP client outbound is not available");
            client.outbound_index=*outbound;
            auto resolver=std::ranges::find(result.dns->servers,client.resolver,&DnsServer::name);
            if(resolver==result.dns->servers.end())return error("HTTP client domain-resolver not found");
            client.resolver_index=static_cast<std::size_t>(resolver-result.dns->servers.begin());
        }
        if (route->default_http_client) {
            if (std::ranges::find(result.http_clients,*route->default_http_client,&NamedHttpClient::name)==result.http_clients.end())
                return error("routing default-http-client not found in http-clients");
            result.default_http_client=*route->default_http_client;
        }
        std::map<std::string,std::string> remote_sha256;
        auto bind_remote_client=[&](BlockRules& spec) -> std::expected<void,std::string> {
            if (spec.url.empty()) return {};
            if (spec.http_client.empty()) spec.http_client=result.default_http_client;
            if (spec.http_client.empty() ||
                std::ranges::find(result.http_clients,spec.http_client,&NamedHttpClient::name)==result.http_clients.end())
                return error("remote rule-set requires a configured http-client or routing default-http-client");
            auto [it,inserted]=remote_sha256.emplace(kdl::normalize_remote_url(spec.url),spec.sha256);
            if (!inserted && it->second!=spec.sha256)
                return error("conflicting sha256 declarations for remote rule-set URL: "+spec.url);
            return {};
        };
        for (auto& file : route->files)
            if (auto ok=bind_remote_client(file.file); !ok) return std::unexpected(std::move(ok.error()));
        if (result.dns) for (auto& entry : result.dns->rule_files)
            if (auto ok=bind_remote_client(entry.file); !ok) return std::unexpected(std::move(ok.error()));
        if (block && *block==*direct) return error("outbound names must be unique");
        for (auto& inbound_config:result.inbounds) {
            if (!inbound_config.vless || !inbound_config.vless->reality) continue;
            auto& reality=*inbound_config.vless->reality;
            if (!reality.fallback_resolver) continue;
            if (!result.dns || !dns_hostname(reality.fallback_host) || dns_ipv4(reality.fallback_host))
                return error("Reality fallback-resolver requires DNS configuration and a domain fallback host");
            auto found=std::ranges::find(result.dns->servers,*reality.fallback_resolver,&DnsServer::name);
            if (found==result.dns->servers.end()) return error("Reality fallback-resolver not found");
            reality.fallback_resolver_index=static_cast<std::size_t>(found-result.dns->servers.begin());
        }
        if (result.tunnel_count()>max_tunnel_outbounds) return error("too many tunnel outbounds");
        for (std::size_t i=0;i<result.vless_outbounds.size();++i) {
            auto& outbound_config=result.vless_outbounds[i].config;
            if (outbound_config.bootstrap_resolver) {
                if (!result.dns || !dns_hostname(outbound_config.host) || dns_ipv4(outbound_config.host))
                    return error("vless bootstrap-resolver requires DNS configuration and a domain server host");
                outbound_config.bootstrap_index=result.dns->resolver_index(*outbound_config.bootstrap_resolver);
                if (!outbound_config.bootstrap_index) return error("vless domain-resolver references unknown DNS server or view: "+*outbound_config.bootstrap_resolver);
            }
            if (auto ok=validate_quic_ech(outbound_config.ech,outbound_config.server_name,result.dns.has_value()); !ok) return std::unexpected(ok.error());
            auto const& name=result.vless_outbounds[i].name;
            if (name==*direct || (block && name==*block) ||
                std::ranges::any_of(std::span(result.vless_outbounds).first(i),[&](auto const& other) { return other.name==name; }))
                return error("outbound names must be unique");
            if (!referenced_outbound(result,*route,name)) return error("vless must be referenced by routing or a detour");
        }
        if (auto valid=validate_shadowsocks(result,*direct,block,*route); !valid) return std::unexpected(valid.error());
        if (auto valid=validate_trojan(result,*direct,block); !valid) return std::unexpected(valid.error());
        for (auto const& named:result.trojan_outbounds)
            if (!referenced_outbound(result,*route,named.name)) return error("Trojan must be referenced by routing or a detour");
        if (auto valid=validate_anytls(result,*direct,block); !valid) return std::unexpected(valid.error());
        for (auto const& named:result.anytls_outbounds)
            if (!referenced_outbound(result,*route,named.name)) return error("AnyTLS must be referenced by routing or a detour");
        if(auto valid=validate_hysteria2(result,*direct,block);!valid)return std::unexpected(valid.error());
        for(auto const& named:result.hysteria2_outbounds)
            if(!referenced_outbound(result,*route,named.name))return error("Hysteria2 must be referenced by routing or a detour");
        for(std::size_t i=0;i<result.snell_outbounds.size();++i){auto& entry=result.snell_outbounds[i];auto& c=entry.config;
            if(entry.name==*direct||(block&&entry.name==*block)||std::ranges::any_of(result.vless_outbounds,[&](auto const& x){return x.name==entry.name;})||
               std::ranges::any_of(result.shadowsocks_outbounds,[&](auto const& x){return x.name==entry.name;})||std::ranges::any_of(result.trojan_outbounds,[&](auto const& x){return x.name==entry.name;})||
               std::ranges::any_of(result.anytls_outbounds,[&](auto const& x){return x.name==entry.name;})||std::ranges::any_of(result.hysteria2_outbounds,[&](auto const& x){return x.name==entry.name;})||std::ranges::any_of(std::span(result.snell_outbounds).first(i),[&](auto const& x){return x.name==entry.name;}))return error("outbound names must be unique");
            if(!referenced_outbound(result,*route,entry.name))return error("Snell must be referenced by routing or a detour");
            if(c.bootstrap_resolver){if(!result.dns||!dns_hostname(c.host)||dns_ipv4(c.host))return error("Snell bootstrap-resolver requires DNS and domain server");
                c.bootstrap_index=result.dns->resolver_index(*c.bootstrap_resolver);
                if (!c.bootstrap_index) return error("Snell domain-resolver references unknown DNS server or view: "+*c.bootstrap_resolver);}
        }
        struct RefCheck { Config const& cfg; Route const& r; };
        RefCheck ref_ctx{result,*route};
        if (auto valid=validate_extra_outbounds(result,*direct,block,[](void const* p,std::string_view n) {
            auto const& ctx=*static_cast<RefCheck const*>(p);
            return referenced_outbound(ctx.cfg,ctx.r,n);
        },&ref_ctx); !valid) return std::unexpected(valid.error());
        result.defaults=std::move(route->defaults);
        if (auto applied=apply_routing_defaults(result); !applied) return std::unexpected(applied.error());
        auto outbound=[&](std::string const& name) -> std::optional<std::size_t> {
            return outbound_index(result,*direct,block,name);
        };
        if (auto valid=bind_outbound_dependencies(result,*direct,block); !valid) return std::unexpected(valid.error());
        if(!result.tailscale_outbounds.empty() &&
           (result.workers==0 || result.workers>16 || result.inbounds.size()!=1 ||
            (result.inbounds.front().type!=Inbound::socks5 && result.inbounds.front().type!=Inbound::mixed)))
            return error("Tailscale outbound requires 1..16 workers and one SOCKS5 or mixed inbound");
        if (auto valid=configure_tun_strict_route(result); !valid) return std::unexpected(valid.error());
        auto fallback=outbound(*route->default_outbound);
        if (!fallback || *fallback==1) return error("default-outbound must name a direct or tunnel outbound");
        if (std::ranges::any_of(result.inbounds,[](auto const& entry) {
            return !entry.unix_path.empty() || (entry.fixed_tcp && !entry.fixed_tcp->unix_path.empty());
        }) && (*fallback!=0 || !route->rules.empty() || route->ordered_tcp ||
               result.direct_tcp_options.configured() || result.direct_network))
            return error("fixed-tcp Unix streams require a plain direct outbound");
        result.default_outbound=*fallback;
        result.default_outbound_name=*route->default_outbound;
        result.direct_outbound_name=*direct;
        result.block_outbound_name=block;
        result.default_action=*fallback>=2 ? RouteAction::vless : RouteAction::direct;
        if (!result.vless_outbounds.empty()) result.vless=result.vless_outbounds.front().config;
        for (auto const& rule : route->rules) {
            auto selected=outbound(rule.outbound);
            if (!selected) return error("rule outbound not found");
            auto file=std::ranges::find(route->files,rule.set,&NamedRouteFile::name);
            auto action=*selected==0 ? RouteAction::direct : *selected==1 ? RouteAction::block : RouteAction::vless;
            auto selected_file=file->file;selected_file.ip_cidr_match_source=rule.ip_cidr_match_source;
            result.routes.push_back({std::move(selected_file),action,*selected,rule.outbound});
        }
        if (auto checked=valid_fakeip_routing(result,*route); !checked) return std::unexpected(std::move(checked.error()));
        auto tun_dns_tcp=std::ranges::any_of(result.inbounds,[](auto const& entry) {
            return entry.tun && entry.tun->dns_hijack_tcp;
        });
        auto dns_hijack=route->ordered_tcp && std::ranges::any_of(route->ordered_tcp->rules,[](auto const& rule) {
            return rule.action==OrderedTcpAction::hijack_dns;
        });
        if (tun_dns_tcp && (!dns_hijack || !result.dns))
            return error("TUN dns-hijack-tcp requires DNS and an ordered hijack-dns rule");
        {
            std::vector<std::string> avail, used_r;
            avail.reserve(route->files.size()); for (auto const& f : route->files) avail.push_back(f.name);
            used_r.reserve(route->rules.size()); for (auto const& r : route->rules) used_r.push_back(r.set);
            if (auto ok=validate_tun_rule_set_refs(result,avail,!route->ordered_tcp,used_r); !ok) return std::unexpected(ok.error());
        }
        if(route->ordered_tcp) {
            auto bad_in=[](auto const& e){return e.type!=Inbound::socks5&&e.type!=Inbound::mixed&&e.type!=Inbound::http&&e.type!=Inbound::naive&&e.type!=Inbound::fixed_tcp&&e.type!=Inbound::fixed_udp&&e.type!=Inbound::trojan&&e.type!=Inbound::anytls&&e.type!=Inbound::vless&&e.type!=Inbound::shadowsocks&&e.type!=Inbound::redirect&&e.type!=Inbound::tproxy&&!(e.tun&&!e.tun->connect_ip_outbound);};
            if(std::ranges::any_of(result.inbounds,bad_in)) return error("tcp-program requires SOCKS5, Mixed, HTTP, fixed-tcp/udp, Trojan, AnyTLS, Shadowsocks, ordinary VLESS, transparent TCP or routed TUN inbounds");
            if(std::ranges::any_of(result.inbounds,[](auto const& e){return e.vless&&(e.vless->vision||e.vless->grpc||e.vless->xhttp);})) return error("tcp-program does not support VLESS Vision, gRPC or XHTTP");
            auto dns_udp_in=[](auto const& e){return e.type==Inbound::socks5||e.type==Inbound::mixed||e.type==Inbound::fixed_udp||e.type==Inbound::trojan||e.type==Inbound::vless||e.type==Inbound::anytls||(e.type==Inbound::tproxy&&e.transparent_udp)||(e.tun&&!e.tun->connect_ip_outbound);};
            auto dns_udp_inbounds=std::ranges::all_of(result.inbounds,dns_udp_in);
            if (dns_hijack && (!result.dns || (!route->ordered_tcp->udp && !tun_dns_tcp) ||
                (route->ordered_tcp->udp && !dns_udp_inbounds)))
                return error("hijack-dns requires DNS and an enabled interception path");
            OrderedTcpConfig program{route->ordered_tcp->timeout,route->ordered_tcp->skip,route->ordered_tcp->udp,{}};
            for (auto const& file:route->files) program.sets.emplace_back(file.name,file.file);
            for(auto const& rule:route->ordered_tcp->rules) {
                std::optional<BlockRules> file;
                if(rule.set) {file=std::ranges::find(route->files,*rule.set,&NamedRouteFile::name)->file;file->ip_cidr_match_source=rule.ip_cidr_match_source;}
                std::size_t index=0;
                if(rule.outbound) {auto selected=outbound(*rule.outbound);if(!selected)return error("tcp-program outbound not found");index=*selected;}
                program.rules.push_back({std::move(file),rule.action,rule.domain,index,rule.connect_timeout_ms,rule.outbound,rule.route_only,rule.predicates,rule.set,rule.reject_method,rule.reject_no_drop,rule.tls_record_fragment,rule.tls_fragment_min,rule.tls_fragment_max,rule.tcp_prefix,rule.tcp_prefix_len,rule.udp_timeout_ms,rule.udp_adaptive_timeout,rule.override_address,rule.override_port,rule.tls_fragment_fallback_delay_ms,rule.extra});
            }
            result.ordered_tcp=std::move(program);
            if (auto bound=routing_detail::bind_ordered_resolve_servers(result); !bound) return error(std::move(bound.error()));
        }
        // This MASQUE slice uses its explicit CIDR allowlist and system local
        // resolver; other routing/DNS programs are not yet wired to it.
        if(std::ranges::any_of(result.inbounds,[](auto const& entry){return entry.masque.has_value();}) &&
           (result.inbounds.size()!=1 || result.dns || !result.routes.empty() || result.ordered_tcp || result.default_outbound!=0 || result.tunnel_count() || block || result.direct_network || result.direct_tcp_options.configured() || result.direct_connect_timeout_ms!=10000))
            return error("MASQUE currently requires a single inbound, direct default, local DNS and no global routing options");
        if (!result.routes.empty()) {
            result.block_rules=result.routes.front().file;
            result.rule_action=result.routes.front().action;
        }
        return result;
    }
}
