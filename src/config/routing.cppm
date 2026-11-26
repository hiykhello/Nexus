// Routing KDL parser and outbound reference check module for config.
export module config.routing;
import std;
import glaze;
import config;
import config.kdl_common;
import config.rule_set_parse;
import platform.ip_address;
import platform.socket_options;
import rules;
import rules.kdl_predicate;

export namespace config::routing_detail {
    using namespace config::kdl;

    struct NamedRouteFile { std::string name; BlockRules file; };
    struct PendingRouteRule { std::string set, outbound; bool ip_cidr_match_source; };
    struct PendingOrderedTcpRule {
        std::optional<std::string> set;
        std::optional<std::string> outbound;
        OrderedTcpAction action;
        OrderedTcpDomain domain;
        bool ip_cidr_match_source;
        std::uint32_t connect_timeout_ms;
        bool route_only;
        rules::RuleSet predicates;
        rules::RejectMethod reject_method = rules::RejectMethod::default_rst;
        bool reject_no_drop = false, tls_record_fragment = false;
        std::uint16_t tls_fragment_min = 0, tls_fragment_max = 0;
        std::array<std::uint8_t, 64> tcp_prefix{};
        std::uint8_t tcp_prefix_len = 0;
        std::uint32_t udp_timeout_ms = 0;
        bool udp_adaptive_timeout = false;
        std::optional<std::string> override_address{};
        std::uint16_t override_port = 0;
        std::uint32_t tls_fragment_fallback_delay_ms = 0;
        OrderedTcpActionExtra extra{};
    };
    struct PendingOrderedTcp { std::uint32_t timeout; bool skip; bool udp; std::vector<PendingOrderedTcpRule> rules; };
    struct Route {
        std::vector<NamedRouteFile> files;
        std::vector<PendingRouteRule> rules;
        std::optional<std::string> default_outbound;
        std::optional<std::string> default_http_client;
        std::optional<PendingOrderedTcp> ordered_tcp;
        RoutingDefaults defaults{};
    };

    inline auto referenced_outbound(Config const& config, Route const& route, std::string_view name) -> bool {
        auto through = [&](auto const& entry) { return entry.config.detour && *entry.config.detour == name; };
        return std::ranges::find(config.http_clients, name, &NamedHttpClient::outbound) != config.http_clients.end() ||
            (config.dns && std::ranges::any_of(config.dns->servers, [&](auto const& server) {
                return server.upstream && server.upstream->detour == name;
            })) ||
            route.default_outbound == name ||
            std::ranges::any_of(route.rules, [&](auto const& rule) { return rule.outbound == name; }) ||
            (route.ordered_tcp && std::ranges::any_of(route.ordered_tcp->rules, [&](auto const& rule) {
                return rule.outbound && *rule.outbound == name;
            })) ||
            std::ranges::any_of(config.selectors, [&](auto const& selector) {
                return std::ranges::find(selector.members, name) != selector.members.end();
            }) ||
            std::ranges::any_of(config.vless_outbounds, through) ||
            std::ranges::any_of(config.shadowsocks_outbounds, through) ||
            std::ranges::any_of(config.trojan_outbounds, through) ||
            std::ranges::any_of(config.anytls_outbounds, [&](auto const& entry) {
                return entry.config.connection.detour && *entry.config.connection.detour == name;
            }) ||
            std::ranges::any_of(config.hysteria2_outbounds, [&](auto const& entry) {
                return entry.config.connection.detour && *entry.config.connection.detour == name;
            }) ||
            std::ranges::any_of(config.snell_outbounds, through) ||
            std::ranges::any_of(config.shadowtls_outbounds, [&](auto const& entry) {
                return entry.config.connection.detour && *entry.config.connection.detour == name;
            }) ||
            std::ranges::any_of(config.tuic_outbounds, through) ||
            std::ranges::any_of(config.masque_outbounds, through) ||
            std::ranges::any_of(config.wireguard_outbounds, through) ||
            std::ranges::any_of(config.ssh_outbounds, through) ||
            std::ranges::any_of(config.naive_outbounds, through) ||
            std::ranges::any_of(config.openvpn_outbounds, through) ||
            std::ranges::any_of(config.openconnect_outbounds, through) ||
            std::ranges::any_of(config.tcp_proxy_outbounds, through);
    }

    inline auto valid_fakeip_routing(Config const& config, Route const& route) -> std::expected<void, std::string> {
        if (config.dns && config.dns->fakeip) {
            if (std::ranges::any_of(config.inbounds, [](auto const& inbound) {
                return inbound.type != Inbound::socks5 && inbound.type != Inbound::mixed && inbound.type != Inbound::http &&
                    inbound.type != Inbound::naive && inbound.type != Inbound::redirect &&
                    inbound.type != Inbound::tproxy &&
                    !(inbound.tun && !inbound.tun->connect_ip_outbound && !inbound.tun->endpoint_independent_nat);
            })) return error("fake-ip requires SOCKS5, Mixed, HTTP, REDIRECT, TPROXY or routed TUN with endpoint-dependent UDP");
        } else if (route.ordered_tcp && std::ranges::any_of(route.ordered_tcp->rules, [](auto const& rule) {
            return rule.domain == OrderedTcpDomain::fakeip;
        })) return error("fakeip domain-source requires DNS fake-ip configuration");
        if (route.ordered_tcp && std::ranges::any_of(route.ordered_tcp->rules, [](auto const& rule) {
            return rule.domain == OrderedTcpDomain::reverse_dns;
        }) && (!config.dns || !config.dns->reverse_mapping))
            return error("reverse domain-source requires DNS reverse-mapping configuration");
        return {};
    }

    inline auto routing(Node const& node) -> std::expected<Route, std::string> {
        if (node.tag || !node.arguments.empty() || !node.properties.empty())
            return error("routing takes no arguments or properties");
        Route route;
        bool auto_detect_seen = false, default_iface_seen = false, default_mark_seen = false;
        bool default_resolver_seen = false, default_strategy_seen = false, default_net_type_seen = false, find_process_seen = false;
        auto parse_net_type = [](std::string_view name) noexcept -> std::optional<platform::network::Type> {
            using enum platform::network::Type;
            if (name == "ethernet") return ethernet;
            if (name == "wifi") return wifi;
            if (name == "cellular") return cellular;
            if (name == "vpn") return vpn;
            if (name == "other") return other;
            return {};
        };
        for (auto const& child : node.children) {
            if (child.name == "auto-detect-interface" || child.name == "find-process") {
                auto flag = boolean(child);
                auto& seen = child.name == "auto-detect-interface" ? auto_detect_seen : find_process_seen;
                if (seen || !flag) return error("invalid or duplicate routing " + child.name);
                if (child.name == "auto-detect-interface") route.defaults.auto_detect_interface = *flag;
                else route.defaults.find_process = *flag;
                seen = true;
            } else if (child.name == "default-interface") {
                auto value = scalar(child);
                platform::SocketBinding validator;
                if (default_iface_seen || !value || value->empty() || value->size() >= validator.bind_interface.size() || value->contains('\0'))
                    return error("invalid or duplicate routing default-interface");
                std::ranges::copy(*value, validator.bind_interface.begin());
                if (validator.interface_name() != *value || !validator.valid())
                    return error("invalid routing default-interface name");
                route.defaults.default_interface = *value;
                default_iface_seen = true;
            } else if (child.name == "default-mark") {
                auto value = integer(child);
                if (default_mark_seen || !value || *value > std::numeric_limits<std::uint32_t>::max())
                    return error("invalid or duplicate routing default-mark");
                route.defaults.default_mark = static_cast<std::uint32_t>(*value);
                default_mark_seen = true;
            } else if (child.name == "default-domain-resolver") {
                auto value = scalar(child);
                if (default_resolver_seen || !value || !valid_name(*value))
                    return error("invalid or duplicate routing default-domain-resolver");
                route.defaults.default_domain_resolver = *value;
                default_resolver_seen = true;
            } else if (child.name == "default-network-type") {
                auto value = scalar(child);
                auto parsed = value ? parse_net_type(*value) : std::nullopt;
                if (default_net_type_seen || !parsed)
                    return error("invalid or duplicate routing default-network-type");
                route.defaults.default_network_type = *parsed;
                default_net_type_seen = true;
            } else if (child.name == "default-network-strategy") {
                auto value = argument(child);
                auto fb_prop = text_property(child, "fallback");
                auto delay_prop = property(child, "fallback-delay-ms");
                auto delay_val = delay_prop ? integer(*delay_prop) : std::nullopt;
                std::size_t expected_props = std::size_t{bool(fb_prop)} + bool(delay_prop);
                if (default_strategy_seen || !value || !child.children.empty() || child.properties.size() != expected_props)
                    return error("invalid or duplicate routing default-network-strategy");
                using enum platform::network::Strategy;
                platform::network::Strategy strat;
                if (*value == "require") strat = require;
                else if (*value == "prefer") strat = prefer;
                else if (*value == "fallback") strat = fallback;
                else if (*value == "hybrid") strat = hybrid;
                else return error("routing default-network-strategy must be require, prefer, fallback or hybrid");
                std::optional<platform::network::Type> fb_type;
                if (fb_prop) {
                    fb_type = parse_net_type(*fb_prop);
                    if (!fb_type || strat == require) return error("invalid routing default-network-strategy fallback");
                }
                if (delay_prop && (!delay_val || *delay_val > 60000 || (strat != hybrid && !*delay_val)))
                    return error("invalid routing default-network-strategy fallback-delay-ms");
                auto delay = delay_val ? std::chrono::milliseconds(*delay_val) :
                    (strat == hybrid ? std::chrono::milliseconds(0) :
                     strat == fallback ? std::chrono::milliseconds(500) : std::chrono::milliseconds(300));
                route.defaults.default_network_strategy = platform::network::Policy{
                    strat, route.defaults.default_network_type.value_or(platform::network::Type::ethernet),
                    fb_type, {}, delay};
                default_strategy_seen = true;
            } else if (child.name == "rule-set") {
                auto parsed = parse_rule_set_spec(child);
                if (!parsed || route.files.size() >= 256 ||
                    std::ranges::any_of(route.files, [&](auto const& file) { return file.name == parsed->first; }))
                    return error(parsed ? "duplicate or too many rule-set entries" : parsed.error());
                route.files.push_back({std::move(parsed->first), std::move(parsed->second)});
            } else if (child.name == "default-http-client") {
                auto value = scalar(child);
                if (route.default_http_client || !value || !valid_name(*value))
                    return error("invalid or duplicate default-http-client");
                route.default_http_client = *value;
            } else if (child.name == "rule") {
                auto kind = text_property(child, "kind"), value = text_property(child, "value"), outbound = text_property(child, "outbound");
                auto ip_source_value = property(child, "ip-cidr-match-source");
                auto ip_source = ip_source_value && !ip_source_value->tag ? std::get_if<bool>(&ip_source_value->data) : nullptr;
                if (child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size() != 3 + bool(ip_source_value) ||
                    (ip_source_value && !ip_source) || !kind || *kind != "rule-set" || !value || !valid_name(*value) ||
                    !outbound || !valid_name(*outbound) || route.rules.size() >= 256)
                    return error("invalid rule-set rule");
                route.rules.push_back({*value, *outbound, ip_source && *ip_source});
            } else if (child.name == "tcp-program") {
                auto timeout = property(child, "sniff-timeout-ms");
                auto number = timeout ? integer(*timeout) : std::nullopt;
                auto unknown = text_property(child, "unknown");
                auto udp_value = property(child, "udp");
                auto udp = udp_value && !udp_value->tag ? std::get_if<bool>(&udp_value->data) : nullptr;
                if (route.ordered_tcp || child.tag || !child.arguments.empty() || child.properties.size() != 2 + bool(udp_value) ||
                    (udp_value && !udp) || !number || !*number || *number > 10000 || !unknown || (*unknown != "skip" && *unknown != "pause"))
                    return error("invalid tcp-program options");
                PendingOrderedTcp program{static_cast<std::uint32_t>(*number), *unknown == "skip", udp && *udp, {}};
                std::size_t predicate_count = 0;
                for (auto const& item : child.children) {
                    auto action = text_property(item, "action"), set = text_property(item, "rule-set"),
                         outbound = text_property(item, "outbound"), source = text_property(item, "domain-source");
                    auto timeout_value = property(item, "connect-timeout-ms");
                    auto connect_timeout = timeout_value ? integer(*timeout_value) : std::nullopt;
                    auto ip_source_value = property(item, "ip-cidr-match-source");
                    auto ip_source = ip_source_value && !ip_source_value->tag ? std::get_if<bool>(&ip_source_value->data) : nullptr;
                    auto route_only_value = property(item, "route-only");
                    auto method_prop = text_property(item, "method");
                    auto no_drop_val = property(item, "no-drop");
                    auto no_drop_flag = no_drop_val && !no_drop_val->tag ? std::get_if<bool>(&no_drop_val->data) : nullptr;
                    auto frag_val = property(item, "tls-record-fragment");
                    auto frag_flag = frag_val && !frag_val->tag ? std::get_if<bool>(&frag_val->data) : nullptr;
                    auto fmin_val = property(item, "tls-fragment-min");
                    auto fmax_val = property(item, "tls-fragment-max");
                    auto fmin = fmin_val ? integer(*fmin_val) : std::nullopt;
                    auto fmax = fmax_val ? integer(*fmax_val) : std::nullopt;
                    auto prefix_prop = text_property(item, "tcp-prefix");
                    auto udp_to_val = property(item, "udp-timeout-ms");
                    auto udp_to = udp_to_val ? integer(*udp_to_val) : std::nullopt;
                    auto udp_ad_val = property(item, "udp-adaptive-timeout");
                    auto udp_ad_flag = udp_ad_val && !udp_ad_val->tag ? std::get_if<bool>(&udp_ad_val->data) : nullptr;
                    auto ov_addr = text_property(item, "override-address");
                    auto ov_port_val = property(item, "override-port");
                    auto ov_port = ov_port_val ? integer(*ov_port_val) : std::nullopt;
                    auto fdelay_val = property(item, "tls-fragment-fallback-delay-ms");
                    auto fdelay = fdelay_val ? integer(*fdelay_val) : std::nullopt;
                    auto strat_val = property(item, "strategy");
                    auto srv_val = property(item, "server");
                    auto dcache_val = property(item, "disable-cache");
                    auto rttl_val = property(item, "rewrite-ttl");
                    auto csub_val = property(item, "client-subnet");
                    auto sniffer_val = property(item, "sniffer");
                    auto ovdest_val = property(item, "override-destination");
                    auto sniffto_val = property(item, "sniff-timeout-ms");
                    auto udpunmap_val = property(item, "udp-disable-domain-unmapping");
                    auto property_action = bool(action);
                    auto expected_props = property_action + bool(set) + bool(outbound) + bool(source) + bool(ip_source_value) +
                        bool(timeout_value) + bool(route_only_value) + bool(method_prop) + bool(no_drop_val) + bool(frag_val) +
                        bool(fmin_val) + bool(fmax_val) + bool(prefix_prop) + bool(udp_to_val) + bool(udp_ad_val) +
                        bool(ov_addr) + bool(ov_port_val) + bool(fdelay_val) +
                        bool(strat_val) + bool(srv_val) + bool(dcache_val) + bool(rttl_val) + bool(csub_val) +
                        bool(sniffer_val) + bool(ovdest_val) + bool(sniffto_val) + bool(udpunmap_val);
                    if (item.name != "rule" || item.tag || !item.arguments.empty() ||
                        item.properties.size() != expected_props ||
                        (ip_source_value && (!ip_source || !set)) || (no_drop_val && !no_drop_flag) ||
                        (frag_val && !frag_flag) || (udp_ad_val && !udp_ad_flag) || program.rules.size() >= 256)
                        return error("invalid tcp-program rule");
                    rules::RuleSet predicates{.version = 2};
                    for (auto const& operand : item.children) {
                        if (operand.name == "action") {
                            if (action || route_only_value || !(action = argument(operand)) || !operand.children.empty())
                                return error("invalid or duplicate tcp-program action");
                            route_only_value = property(operand, "route-only");
                            if (operand.properties.size() != bool(route_only_value))
                                return error("invalid tcp-program action options");
                        } else {
                            auto predicate = rules::decode_kdl_predicate(operand, 1, predicate_count);
                            if (!predicate) return error(std::move(predicate.error().message));
                            predicates.rules.push_back(std::move(*predicate));
                        }
                    }
                    if (!action || (set && !predicates.rules.empty()))
                        return error("tcp-program requires one action and one predicate form");
                    if (predicates.rules.size() > 1) {
                        auto operands = std::move(predicates.rules);
                        predicates.rules = {{"and", {}, std::move(operands)}};
                    }
                    auto normalized = rules::normalize_set(std::move(predicates));
                    if (!normalized) return error(std::move(normalized.error().message));
                    OrderedTcpAction kind;
                    if (*action == "sniff") kind = OrderedTcpAction::sniff;
                    else if (*action == "resolve") kind = OrderedTcpAction::resolve;
                    else if (*action == "route") kind = OrderedTcpAction::route;
                    else if (*action == "bypass") kind = OrderedTcpAction::bypass;
                    else if (*action == "reject") kind = OrderedTcpAction::reject;
                    else if (*action == "route-options") kind = OrderedTcpAction::route_options;
                    else if (*action == "hijack-dns") kind = OrderedTcpAction::hijack_dns;
                    else return error("unsupported tcp-program action");
                    if ((set && !valid_name(*set)) || (outbound && !valid_name(*outbound)) ||
                        (!outbound && kind == OrderedTcpAction::route) ||
                        (outbound && kind != OrderedTcpAction::route && kind != OrderedTcpAction::bypass))
                        return error("invalid tcp-program rule target");
                    auto route_only = route_only_value && !route_only_value->tag ? std::get_if<bool>(&route_only_value->data) : nullptr;
                    if (route_only_value && (!route_only || kind != OrderedTcpAction::resolve))
                        return error("route-only requires a boolean resolve option");
                    auto reject_method = rules::RejectMethod::default_rst;
                    if (method_prop) {
                        if (kind != OrderedTcpAction::reject || (*method_prop != "default" && *method_prop != "drop"))
                            return error("reject method must be default or drop on a reject rule");
                        reject_method = *method_prop == "drop" ? rules::RejectMethod::drop : rules::RejectMethod::default_rst;
                    }
                    if (no_drop_val && kind != OrderedTcpAction::reject)
                        return error("no-drop requires a reject rule");
                    bool tls_frag = frag_flag && *frag_flag;
                    std::uint16_t frag_min = 0, frag_max = 0;
                    if (fmin_val || fmax_val) {
                        if (!tls_frag || !fmin || !fmax || !*fmin || *fmin > *fmax || *fmax > 16384)
                            return error("invalid tls-fragment-min/max range");
                        frag_min = static_cast<std::uint16_t>(*fmin);
                        frag_max = static_cast<std::uint16_t>(*fmax);
                    } else if (tls_frag) { frag_min = 16; frag_max = 64; }
                    if (fdelay_val && (!tls_frag || !fdelay || !*fdelay || *fdelay > 10000))
                        return error("tls-fragment-fallback-delay-ms must be 1..10000 with tls-record-fragment=true");
                    if (ov_addr && (ov_addr->empty() || (!platform::parse_ip_address(*ov_addr) && !rules::valid_domain(*ov_addr))))
                        return error("override-address must be a valid IP or domain");
                    if (ov_port_val && (!ov_port || !*ov_port || *ov_port > 65535))
                        return error("override-port must be 1..65535");
                    std::array<std::uint8_t, 64> tcp_prefix{};
                    std::uint8_t tcp_prefix_len = 0;
                    if (prefix_prop) {
                        auto parsed_len = parse_hex_bytes(*prefix_prop, tcp_prefix);
                        if (!parsed_len) return error("tcp-prefix requires valid hex bytes up to 64 bytes");
                        tcp_prefix_len = static_cast<std::uint8_t>(*parsed_len);
                    }
                    bool has_evasion = tls_frag || tcp_prefix_len > 0;
                    bool has_override = bool(ov_addr) || bool(ov_port_val);
                    bool udp_adaptive = udp_ad_flag && *udp_ad_flag;
                    if (udp_to_val && (!udp_to || *udp_to < 1000 || *udp_to > 3600000))
                        return error("udp-timeout-ms must be 1000..3600000");
                    OrderedTcpActionExtra extra;
                    if (strat_val || srv_val || dcache_val || rttl_val || csub_val) {
                        if (kind != OrderedTcpAction::resolve)
                            return error("resolve options require a resolve action");
                        if (strat_val) {
                            auto s = string(*strat_val);
                            extra.resolve_strategy = s ? rules::parse_dns_rule_strategy(*s) : std::nullopt;
                            if (!extra.resolve_strategy) return error("invalid resolve strategy");
                        }
                        if (srv_val) {
                            auto s = string(*srv_val);
                            if (!s || !valid_name(*s)) return error("invalid resolve server");
                            extra.resolve_server_name = *s;
                        }
                        if (dcache_val) {
                            if (dcache_val->tag || !std::holds_alternative<bool>(dcache_val->data))
                                return error("resolve disable-cache requires a boolean");
                            extra.resolve_disable_cache = std::get<bool>(dcache_val->data);
                        }
                        if (rttl_val) {
                            auto v = integer(*rttl_val);
                            if (!v || *v > 0xffffffffu) return error("invalid resolve rewrite-ttl");
                            extra.resolve_rewrite_ttl = static_cast<std::uint32_t>(*v);
                        }
                        if (csub_val) {
                            auto s = string(*csub_val);
                            if (!s) return error("invalid resolve client-subnet");
                            auto slash = s->find('/');
                            auto parsed_ip = platform::parse_ip_address(s->substr(0, slash));
                            if (!parsed_ip) return error("invalid resolve client-subnet IP");
                            unsigned bits = parsed_ip->size * 8u;
                            if (slash != std::string::npos) {
                                auto rem = std::string_view(*s).substr(slash + 1);
                                auto [end, ec] = std::from_chars(rem.data(), rem.data() + rem.size(), bits);
                                if (rem.empty() || ec != std::errc{} || end != rem.data() + rem.size() || bits > parsed_ip->size * 8u)
                                    return error("invalid resolve client-subnet prefix");
                            }
                            rules::SubnetPrefix sp{.address = parsed_ip->bytes, .size = parsed_ip->size, .bits = static_cast<std::uint8_t>(bits)};
                            auto whole = bits / 8, rem_bits = bits % 8;
                            if (rem_bits) sp.address[whole++] &= static_cast<std::uint8_t>(0xffu << (8 - rem_bits));
                            std::fill(sp.address.begin() + whole, sp.address.end(), 0);
                            extra.resolve_client_subnet = sp;
                        }
                    }
                    if (sniffer_val || ovdest_val || sniffto_val) {
                        if (kind != OrderedTcpAction::sniff)
                            return error("sniff options require a sniff action");
                        if (sniffer_val) {
                            auto s = string(*sniffer_val);
                            auto mask = s ? rules::parse_protocol_list(*s) : std::nullopt;
                            if (!mask || !*mask) return error("invalid sniff sniffer list");
                            extra.sniff_protocols = *mask;
                        }
                        if (ovdest_val) {
                            if (ovdest_val->tag || !std::holds_alternative<bool>(ovdest_val->data))
                                return error("sniff override-destination requires a boolean");
                            extra.sniff_override_destination = std::get<bool>(ovdest_val->data);
                        }
                        if (sniffto_val) {
                            auto v = integer(*sniffto_val);
                            if (!v || !*v || *v > 10000) return error("sniff-timeout-ms must be 1..10000");
                            extra.sniff_timeout_ms = static_cast<std::uint32_t>(*v);
                        }
                    }
                    if (udpunmap_val) {
                        if (udpunmap_val->tag || !std::holds_alternative<bool>(udpunmap_val->data))
                            return error("udp-disable-domain-unmapping requires a boolean");
                        extra.udp_disable_domain_unmapping = std::get<bool>(udpunmap_val->data);
                    }
                    bool has_udp_opt = bool(udp_to_val) || udp_adaptive || bool(udpunmap_val);
                    auto permits_timeout = kind == OrderedTcpAction::route_options || kind == OrderedTcpAction::route ||
                        kind == OrderedTcpAction::bypass;
                    if ((has_evasion || has_udp_opt || has_override) && kind != OrderedTcpAction::route_options &&
                        kind != OrderedTcpAction::route && kind != OrderedTcpAction::bypass)
                        return error("route options require route-options, route or bypass");
                    if ((kind == OrderedTcpAction::route_options && !timeout_value && !has_evasion && !has_udp_opt && !has_override) ||
                        (timeout_value && (!permits_timeout || !connect_timeout || !*connect_timeout || *connect_timeout > 3600000)))
                        return error("invalid route connection timeout");
                    auto domain = OrderedTcpDomain::explicit_target;
                    if (source) {
                        if (!set && normalized->rules.empty()) return error("domain-source requires a predicate");
                        if (*source == "explicit") domain = OrderedTcpDomain::explicit_target;
                        else if (*source == "fakeip") domain = OrderedTcpDomain::fakeip;
                        else if (*source == "reverse") domain = OrderedTcpDomain::reverse_dns;
                        else if (*source == "sniffed") domain = OrderedTcpDomain::sniffed;
                        else return error("invalid tcp-program domain-source");
                    }
                    program.rules.push_back({set ? std::optional(*set) : std::nullopt,
                        outbound ? std::optional(*outbound) : std::nullopt, kind, domain, ip_source && *ip_source,
                        static_cast<std::uint32_t>(connect_timeout.value_or(0)), route_only && *route_only,
                        std::move(*normalized), reject_method, no_drop_flag && *no_drop_flag, tls_frag, frag_min, frag_max,
                        tcp_prefix, tcp_prefix_len, static_cast<std::uint32_t>(udp_to.value_or(0)), udp_adaptive,
                        ov_addr ? std::optional(*ov_addr) : std::nullopt, static_cast<std::uint16_t>(ov_port.value_or(0)),
                        static_cast<std::uint32_t>(fdelay.value_or(0)), std::move(extra)});
                }
                route.ordered_tcp = std::move(program);
            } else if (child.name == "default-outbound") {
                auto value = scalar(child);
                if (route.default_outbound || !value || !valid_name(*value))
                    return error("one default-outbound is required");
                route.default_outbound = *value;
            } else return error("unsupported routing node: " + child.name);
        }
        if (route.defaults.default_network_strategy && route.defaults.default_network_type) {
            route.defaults.default_network_strategy->preferred = *route.defaults.default_network_type;
            if (route.defaults.default_network_strategy->fallback == route.defaults.default_network_strategy->preferred)
                return error("routing default-network-type cannot equal default-network-strategy fallback");
        }
        if (!route.default_outbound) return error("routing requires default-outbound");
        for (auto const& rule : route.rules)
            if (auto file = std::ranges::find(route.files, rule.set, &NamedRouteFile::name); file == route.files.end())
                return error("rule-set reference not found");
            else if (rule.ip_cidr_match_source && file->file.format != RuleFormat::srs && file->file.format != RuleFormat::nxmm)
                return error("ip-cidr-match-source requires SRS or NXMM format");
        if (route.ordered_tcp) {
            if (!route.rules.empty()) return error("tcp-program cannot be combined with rule-set routing rules");
            for (auto const& rule : route.ordered_tcp->rules)
                if (rule.set) {
                    auto file = std::ranges::find(route.files, *rule.set, &NamedRouteFile::name);
                    if (file == route.files.end()) return error("tcp-program rule-set not found");
                    if (rule.ip_cidr_match_source && file->file.format != RuleFormat::srs && file->file.format != RuleFormat::nxmm)
                        return error("ip-cidr-match-source requires SRS or NXMM format");
                }
        }
        return route;
    }

    inline auto bind_ordered_resolve_servers(Config& result) -> std::expected<void, std::string> {
        if (!result.ordered_tcp) return {};
        for (auto& rule : result.ordered_tcp->rules) {
            if (!rule.extra.resolve_server_name) continue;
            if (!result.dns) return error("resolve server requires dns configuration");
            auto it = std::ranges::find(result.dns->servers, *rule.extra.resolve_server_name, &DnsServer::name);
            if (it == result.dns->servers.end())
                return error("resolve DNS server not found: " + *rule.extra.resolve_server_name);
            rule.extra.resolve_server = static_cast<std::size_t>(it - result.dns->servers.begin());
        }
        return {};
    }
}
