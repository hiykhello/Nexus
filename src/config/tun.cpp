module config;
import std;
import config.kdl_common;
import platform.socket_options;
import nexus.thirdparty.glaze;

namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;

    namespace {
        using namespace config::kdl;

        auto valid_interface_name(std::string_view name) -> bool {
            if (name.empty() || name.size() > 15 || name == "." || name == "..") return false;
            return std::ranges::all_of(name, [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
            });
        }

        auto valid_cidr(std::string_view text, bool ipv6) -> bool {
            auto slash = text.find('/');
            if (slash == std::string_view::npos || text.find('/', slash + 1) != std::string_view::npos) return false;
            auto ip = text.substr(0, slash), pfx = text.substr(slash + 1);
            if (ip.empty() || pfx.empty() || pfx.size() > 3) return false;
            if (pfx.size() > 1 && pfx.front() == '0') return false;
            unsigned bits = 0;
            auto [end, ec] = std::from_chars(pfx.data(), pfx.data() + pfx.size(), bits);
            if (ec != std::errc{} || end != pfx.data() + pfx.size()) return false;
            if (ipv6) return dns_ipv6(ip).has_value() && bits >= 1 && bits <= 128;
            return dns_ipv4(ip).has_value() && bits >= 1 && bits <= 32;
        }
    }

    auto parse_tun_inbound(Node const& node) -> std::expected<InboundConfig, std::string> {
        auto tag = argument(node);
        auto type = text_property(node, "type");
        if (!tag || !valid_name(*tag) || node.properties.size() != 1 || !type || *type != "tun")
            return error("invalid TUN inbound");
        InboundConfig result{*tag, 0, Inbound::tun};
        TunInbound cfg;
        bool if_seen = false, v4_seen = false, v6_seen = false, mtu_seen = false;
        bool auto_seen = false, strict_seen = false, stack_seen = false;
        bool flows_seen = false, buf_seen = false, udp_seen = false, mark_seen = false, nat_seen = false;
        bool filter_seen=false,reject_seen=false,dns_tcp_seen=false,reply_fragment_seen=false;
        bool private_seen=false, redirect_seen=false, mptcp_seen=false, mq_seen=false;

        for (auto const& child : node.children) {
            if (child.name == "interface-name") {
                auto v = scalar(child);
                if (if_seen || !v || !valid_interface_name(*v)) return error("invalid TUN interface-name");
                cfg.interface_name = *v; if_seen = true;
            } else if (child.name == "device-fd") {
                auto value = child.arguments.size() == 1 ? integer(child.arguments.front()) : std::nullopt;
                auto ownership = text_property(child, "ownership");
                if (cfg.device_fd || child.tag || !child.children.empty() || !value ||
                    *value < 3 || *value > std::numeric_limits<int>::max() ||
                    (!child.properties.empty() && (child.properties.size() != 1 || !ownership ||
                        (*ownership != "borrow" && *ownership != "adopt"))))
                    return error("TUN device-fd requires an fd >= 3 and optional borrow or adopt ownership");
                cfg.device_fd = TunInbound::DeviceFd{static_cast<int>(*value), ownership && *ownership == "adopt"};
            } else if (child.name == "connect-ip-outbound") {
                auto v = scalar(child);
                if (cfg.connect_ip_outbound || !v || !valid_name(*v)) return error("invalid TUN connect-ip-outbound");
                cfg.connect_ip_outbound = *v;
            } else if (child.name == "connect-ip-route") {
                auto v = scalar(child);
                if (!v || cfg.connect_ip_routes.size() == 16 ||
                    !valid_cidr(*v, v->find(':') != std::string::npos)) return error("invalid TUN connect-ip-route");
                cfg.connect_ip_routes.push_back(*v);
            } else if (child.name=="include-routing-mark" || child.name=="exclude-routing-mark") {
                auto& filter=child.name=="include-routing-mark" ? cfg.include_routing_mark : cfg.exclude_routing_mark;
                auto mark=child.arguments.size()==1 ? integer(child.arguments.front()) : std::nullopt;
                auto mask_value=property(child,"mask");
                auto mask=child.properties.empty() ? std::optional<std::uint64_t>(0xffffffffU) :
                    child.properties.size()==1 && mask_value ? integer(*mask_value) : std::nullopt;
                if (filter || child.tag || !child.children.empty() || !mark || *mark>0xffffffffU ||
                    !mask || !*mask || *mask>0xffffffffU || (*mark & ~*mask))
                    return error("invalid TUN "+child.name);
                filter=platform::RoutingMarkFilter{static_cast<std::uint32_t>(*mark),static_cast<std::uint32_t>(*mask)};
            } else if (child.name=="route-exclude-private") {
                auto value=boolean(child);
                if (private_seen || !value) return error("invalid TUN route-exclude-private");
                cfg.route_exclude_private=*value;
                private_seen=true;
            } else if (child.name=="route-exclude") {
                auto value=scalar(child);
                if (!value || cfg.route_excludes.size()==16 ||
                    !valid_cidr(*value,value->find(':')!=std::string::npos))
                    return error("invalid TUN route-exclude");
                cfg.route_excludes.push_back(*value);
            } else if (child.name == "inet4-address") {
                auto v = scalar(child);
                if (v4_seen || !v || !valid_cidr(*v, false)) return error("invalid TUN inet4-address");
                cfg.inet4_address = *v; v4_seen = true;
            } else if (child.name == "inet6-address") {
                auto v = scalar(child);
                if (v6_seen || !v || !valid_cidr(*v, true)) return error("invalid TUN inet6-address");
                cfg.inet6_address = *v; v6_seen = true;
            } else if (child.name == "mtu") {
                auto v = child.arguments.size() == 1 ? integer(child.arguments.front()) : std::nullopt;
                if (mtu_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    !v || *v < 68 || *v > 65535)
                    return error("TUN mtu must be 68..65535");
                cfg.mtu = static_cast<std::uint16_t>(*v); mtu_seen = true;
            } else if (child.name=="auto-redirect") {
                auto value=boolean(child);
                if (redirect_seen || !value) return error("invalid TUN auto-redirect");
                cfg.auto_redirect=*value;
                redirect_seen=true;
            } else if (child.name == "auto-route") {
                auto v = boolean(child);
                if (auto_seen || !v) return error("invalid TUN auto-route");
                cfg.auto_route = *v; auto_seen = true;
            } else if (child.name=="host-dns") {
                auto value=scalar(child);
                if (cfg.host_dns_resolved || !value || *value!="resolved")
                    return error("TUN host-dns requires one resolved value");
                cfg.host_dns_resolved=true;
            } else if (child.name == "strict-route") {
                auto v = boolean(child);
                if (strict_seen || !v) return error("invalid TUN strict-route");
                cfg.strict_route = *v; strict_seen = true;
            } else if (child.name == "stack") {
                auto v = scalar(child);
                if (stack_seen || !v || *v != "system")
                    return error("TUN stack must be system");
                cfg.stack = *v; stack_seen = true;
            } else if (child.name == "tcp-flows") {
                auto v = child.arguments.size() == 1 ? integer(child.arguments.front()) : std::nullopt;
                if (flows_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    !v || *v < 1 || *v > 65535)
                    return error("TUN tcp-flows must be 1..65535");
                cfg.tcp_flows = static_cast<std::size_t>(*v); flows_seen = true;
            } else if (child.name == "tcp-buffer") {
                auto v = child.arguments.size() == 1 ? integer(child.arguments.front()) : std::nullopt;
                if (buf_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    !v || *v < 4096 || *v > 16 * 1024 * 1024)
                    return error("TUN tcp-buffer must be 4096..16777216");
                cfg.tcp_buffer = static_cast<std::size_t>(*v); buf_seen = true;
            } else if (child.name == "udp-idle-ms") {
                auto v = child.arguments.size() == 1 ? integer(child.arguments.front()) : std::nullopt;
                if (udp_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    !v || *v < 1000 || *v > 3600000)
                    return error("TUN udp-idle-ms must be 1000..3600000");
                cfg.udp_idle_ms = static_cast<std::uint32_t>(*v); udp_seen = true;
            } else if (child.name == "socket-mark") {
                auto v = child.arguments.size() == 1 ? integer(child.arguments.front()) : std::nullopt;
                if (mark_seen || child.tag || !child.properties.empty() || !child.children.empty() ||
                    !v || *v > 0xffffffffULL)
                    return error("invalid TUN socket-mark");
                cfg.socket_mark = static_cast<std::uint32_t>(*v); mark_seen = true;
            } else if (child.name == "endpoint-independent-nat") {
                auto v = boolean(child);
                if (nat_seen || !v) return error("invalid TUN endpoint-independent-nat");
                cfg.endpoint_independent_nat = *v; nat_seen = true;
            } else if (child.name=="dns-hijack-tcp") {
                auto value=boolean(child);
                if (dns_tcp_seen || !value) return error("invalid TUN dns-hijack-tcp");
                cfg.dns_hijack_tcp=*value;
                dns_tcp_seen=true;
            } else if (child.name=="udp-reply-fragment") {
                auto value=boolean(child);
                if (reply_fragment_seen || !value) return error("invalid TUN udp-reply-fragment");
                cfg.udp_reply_fragment=*value;
                reply_fragment_seen=true;
            } else if (child.name=="udp-filtering") {
                auto value=scalar(child);
                if (filter_seen || !value) return error("invalid TUN udp-filtering");
                if (*value=="address-port-dependent") cfg.udp_filtering=TunUdpFiltering::address_port_dependent;
                else if (*value=="address-dependent") cfg.udp_filtering=TunUdpFiltering::address_dependent;
                else if (*value=="endpoint-independent") cfg.udp_filtering=TunUdpFiltering::endpoint_independent;
                else return error("invalid TUN udp-filtering");
                filter_seen=true;
            } else if (child.name=="udp-reject") {
                auto value=scalar(child);
                if (reject_seen || !value || (*value!="drop" && *value!="icmp")) return error("invalid TUN udp-reject");
                cfg.udp_reject_icmp=*value=="icmp";
                reject_seen=true;
            } else if (child.name=="exclude-mptcp") {
                auto value=boolean(child);
                if (mptcp_seen || !value) return error("invalid TUN exclude-mptcp");
                cfg.exclude_mptcp=*value; mptcp_seen=true;
            } else if (child.name=="multi-queue") {
                auto value=boolean(child);
                if (mq_seen || !value) return error("invalid TUN multi-queue");
                cfg.multi_queue=*value; mq_seen=true;
            } else if (child.name=="exclude-package") {
                auto value=scalar(child);
                auto valid_pkg=[](std::string_view p) {
                    return !p.empty() && p.size()<=128 && p.contains('.') && std::ranges::all_of(p,[](unsigned char c) {
                        return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='.' || c=='_';
                    });
                };
                if (!value || !valid_pkg(*value) || cfg.exclude_packages.size()>=64 ||
                    std::ranges::contains(cfg.exclude_packages,*value))
                    return error("invalid or duplicate TUN exclude-package");
                cfg.exclude_packages.push_back(*value);
            } else {
                return error("unsupported TUN inbound field: " + child.name);
            }
        }
        if (cfg.exclude_mptcp && !cfg.auto_redirect)
            return error("TUN exclude-mptcp requires auto-redirect");
        if (!cfg.exclude_packages.empty() && cfg.strict_route)
            return error("TUN strict-route is not supported on mobile exclude-package configurations");
        if (cfg.auto_redirect) {
            if (!cfg.auto_route || cfg.device_fd || cfg.connect_ip_outbound || (strict_seen && !cfg.strict_route))
                return error("TUN auto-redirect requires auto-route and managed routed TUN strict-route");
            cfg.strict_route=true;
        }
        if (cfg.device_fd) {
            if (cfg.strict_route)
                return error("TUN strict-route is not permitted with external mobile/platform device-fd");
            if (cfg.connect_ip_outbound || v4_seen || v6_seen || cfg.auto_route)
                return error("TUN device-fd requires host-managed addresses and routes on a routed TUN inbound");
            if (!if_seen) cfg.interface_name.clear();
        }
#if !defined(__linux__)
        if (cfg.strict_route)
            return error("TUN strict-route is only supported on Linux hosts");
#endif
        if (cfg.connect_ip_outbound) {
            if (cfg.connect_ip_routes.empty() || v4_seen || v6_seen || auto_seen || strict_seen ||
                stack_seen || flows_seen || buf_seen || udp_seen || nat_seen || filter_seen || reject_seen || dns_tcp_seen || reply_fragment_seen)
                return error("CONNECT-IP TUN requires explicit connect-ip-route entries and uses peer address assignment");
            if (!mtu_seen) cfg.mtu = 1280;
        } else if (!cfg.connect_ip_routes.empty()) return error("connect-ip-route requires connect-ip-outbound");
        if (cfg.strict_route && !cfg.auto_route)
            return error("TUN strict-route requires auto-route");
        if (cfg.host_dns_resolved && !cfg.strict_route)
            return error("TUN host-dns requires strict-route");
        if (!cfg.route_excludes.empty() && (!cfg.strict_route || cfg.connect_ip_outbound))
            return error("TUN route-exclude requires routed TUN strict-route");
        if ((private_seen || cfg.include_routing_mark || cfg.exclude_routing_mark) &&
            (!cfg.strict_route || cfg.connect_ip_outbound))
            return error("TUN mark filters and route-exclude-private require routed TUN strict-route");
        for (auto const& prefix : cfg.route_excludes)
            if (!(prefix.contains(':') ? cfg.inet6_address : cfg.inet4_address))
                return error("TUN route-exclude requires an address in the same family");
        if (cfg.auto_route && !cfg.inet4_address && !cfg.inet6_address)
            return error("TUN auto-route requires inet4-address or inet6-address");
        result.tun = std::move(cfg);
        return result;
    }

    auto tun_endpoints_overlap(std::optional<TunInbound> const& existing,
        std::optional<TunInbound> const& requested) noexcept -> bool {
        if (!existing || !requested) return false;
        return (!existing->interface_name.empty() && existing->interface_name==requested->interface_name) ||
            (existing->device_fd && requested->device_fd &&
                existing->device_fd->number==requested->device_fd->number);
    }

    auto configure_tun_host_dns(Config const& config,TunInbound& tun)
        -> std::expected<void,std::string> {
        if (!tun.host_dns_resolved) return {};
        if (!config.dns || !config.dns->listen || config.dns->listen->port!=53)
            return std::unexpected("TUN host-dns requires a DNS listener on port 53 bound to a TUN address");
        auto const& listener=*config.dns->listen;
        auto const& configured=listener.ipv6 ? tun.inet6_address : tun.inet4_address;
        if (configured) {
            auto host=configured->substr(0,configured->find('/'));
            if (listener.ipv6) {
                if (auto ip=dns_ipv6(host);ip && *ip==listener.address) {
                    tun.host_dns_server=std::move(host);
                    return {};
                }
            } else if (auto ip=dns_ipv4(host);ip && std::ranges::equal(*ip,std::span(listener.address).first(4))) {
                tun.host_dns_server=std::move(host);
                return {};
            }
        }
        return std::unexpected("TUN host-dns requires a DNS listener on port 53 bound to a TUN address");
    }

    auto configure_tun_strict_route(Config& config) -> std::expected<void, std::string> {
        auto found = std::ranges::find_if(config.inbounds, [](auto const& entry) {
            return entry.tun && entry.tun->strict_route;
        });
        if (found == config.inbounds.end()) return {};
        if (config.inbounds.size() != 1)
            return std::unexpected("TUN strict-route requires a single inbound");
        auto& tun = *found->tun;
        constexpr std::uint32_t default_mark = 0x6e780001;
        auto mark = tun.socket_mark.value_or(default_mark);
        if (!mark) return std::unexpected("TUN strict-route requires a nonzero socket-mark");
        auto apply_mark = [&](platform::SocketBinding& binding) {
            auto& binding_mark = binding.routing_mark;
            if (binding_mark && *binding_mark != mark) return false;
            binding_mark = mark;
            return true;
        };
        if (!apply_mark(config.direct_tcp_options.binding))
            return std::unexpected("TUN strict-route and direct outbound require the same routing mark");
        if (config.dns_upstream && !apply_mark(config.dns_upstream->binding))
            return std::unexpected("TUN strict-route and DNS upstream require the same routing mark");
        if (config.dns)
            for (auto& server : config.dns->servers)
                if (server.upstream && !apply_mark(server.upstream->binding))
                    return std::unexpected("TUN strict-route and DNS server require the same routing mark: " + server.name);

        auto mark_outbounds = [&](auto& outbounds) -> std::expected<void, std::string> {
            for (auto& entry : outbounds) {
                auto& outbound = [&]() -> auto& {
                    if constexpr (requires { entry.config.connection; }) return entry.config.connection;
                    else return entry.config;
                }();
                if (outbound.detour_index && *outbound.detour_index >= 2) continue;
                if ((!dns_ipv4(outbound.host) && !dns_ipv6(outbound.host)) ||
                    (!outbound.detour_index && !apply_mark(outbound.tcp_options.binding)))
                    return std::unexpected("TUN strict-route requires a numeric server and matching routing mark for " + entry.name);
            }
            return {};
        };
        std::expected<void, std::string> result;
        auto apply = [&](auto&... outbounds) { return ((result = mark_outbounds(outbounds)).has_value() && ...); };
        if (!apply(config.vless_outbounds, config.shadowsocks_outbounds, config.trojan_outbounds,
                config.anytls_outbounds, config.hysteria2_outbounds, config.snell_outbounds,
                config.shadowtls_outbounds, config.tuic_outbounds, config.masque_outbounds, config.wireguard_outbounds, config.tcp_proxy_outbounds))
            return result;
        if (auto host_dns=configure_tun_host_dns(config,tun); !host_dns) return host_dns;
        tun.socket_mark = mark;
        config.tun_inbound = tun;
        return {};
    }
}
