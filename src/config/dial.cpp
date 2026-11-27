module config;
import std;
import glaze;
import config.kdl_common;
import platform.ip_address;
import platform.socket_options;

namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;
    auto dns_hostname(std::string_view) -> bool;
    namespace {
        using Node=glaze::KdlNode;
        auto scalar(Node const& node) -> glaze::KdlValue const* {
            if (node.tag || node.arguments.size()!=1 || !node.children.empty() || !node.properties.empty() || node.arguments.front().tag)
                return nullptr;
            return &node.arguments.front();
        }
        auto integer(Node const& node) -> std::optional<std::uint64_t> {
            auto value=scalar(node);
            if (!value) return {};
            if (auto number=std::get_if<std::uint64_t>(&value->data)) return *number;
            if (auto number=std::get_if<std::int64_t>(&value->data); number && *number>=0) return static_cast<std::uint64_t>(*number);
            return {};
        }
        auto parse_iface_name(std::string_view text) noexcept -> bool {
            platform::SocketBinding validator;
            if (text.empty() || text.size() >= validator.bind_interface.size() || text.contains('\0')) return false;
            std::ranges::copy(text, validator.bind_interface.begin());
            return validator.interface_name() == text && validator.valid();
        }
    }
    auto parse_tcp_dial_option(glaze::KdlNode const& node,TcpSocketOptions& options) -> std::expected<bool,std::string> {
        if (node.name=="netns" || node.name=="protect-path") {
            auto value=scalar(node); auto path=value ? std::get_if<std::string>(&value->data) : nullptr;
            auto& target=node.name=="netns" ? options.binding.network_namespace : options.binding.protect_path;
            if (!path || path->empty() || !target.empty())
                return std::unexpected(node.name + " requires a nonempty absolute path and cannot repeat");
            target=*path;
            if (!options.binding.valid()) return std::unexpected("invalid " + node.name + " path");
        } else if (node.name=="bind-interface") {
            auto value=scalar(node); auto text=value ? std::get_if<std::string>(&value->data) : nullptr;
            if (!text || text->empty() || text->size()>=options.binding.bind_interface.size() ||
                text->find('\0')!=text->npos || options.binding.bind_interface.front())
                return std::unexpected("bind-interface requires a nonempty interface name of at most 15 bytes and cannot repeat");
            std::ranges::copy(*text,options.binding.bind_interface.begin());
        } else if (node.name=="inet4-bind-address" || node.name=="inet6-bind-address") {
            auto value=scalar(node); auto text=value ? std::get_if<std::string>(&value->data) : nullptr;
            auto ipv4=node.name=="inet4-bind-address";
            if (!text || text->empty() || text->find_first_of("[]%")!=text->npos || text->find('\0')!=text->npos ||
                (ipv4 && (options.binding.inet4_bind_address || text->find(':')!=text->npos)) ||
                (!ipv4 && options.binding.inet6_bind_address)) return std::unexpected("invalid or repeated " + node.name);
            if (ipv4) {
                auto address=dns_ipv4(*text);
                if (!address) return std::unexpected("inet4-bind-address requires a numeric IPv4 address without port");
                options.binding.inet4_bind_address=*address;
            } else {
                auto address=dns_ipv6(*text);
                if (!address || (std::ranges::all_of(std::span(*address).first<10>(),[](auto c) { return c==0; }) &&
                    (*address)[10]==255 && (*address)[11]==255))
                    return std::unexpected("inet6-bind-address requires a numeric unscoped IPv6 address without IPv4 mapping");
                options.binding.inet6_bind_address=*address;
            }
        } else if (node.name=="udp-bind-port") {
            auto value=integer(node);
            if (!value || *value>std::numeric_limits<std::uint16_t>::max() || options.binding.udp_bind_port)
                return std::unexpected("udp-bind-port requires an unsigned 16-bit integer and cannot repeat");
            options.binding.udp_bind_port=static_cast<std::uint16_t>(*value);
        } else if (node.name=="routing-mark") {
            auto value=integer(node);
            if (!value || *value>std::numeric_limits<std::uint32_t>::max() || options.binding.routing_mark)
                return std::unexpected("routing-mark requires an unsigned 32-bit integer and cannot repeat");
            options.binding.routing_mark=static_cast<std::uint32_t>(*value);
        } else if (node.name=="reuse-addr" || node.name=="bind-address-no-port" || node.name=="udp-fragment") {
            auto value=scalar(node); auto flag=value ? std::get_if<bool>(&value->data) : nullptr;
            auto& target=node.name=="reuse-addr" ? options.binding.reuse_addr :
                node.name=="udp-fragment" ? options.binding.udp_fragment : options.bind_address_no_port;
            if (!flag || target) return std::unexpected(node.name + " requires one boolean and cannot repeat");
            target=*flag;
        } else if (node.name=="multipath-tcp") {
            auto value=scalar(node);auto flag=value ? std::get_if<bool>(&value->data) : nullptr;
            if(!flag || options.multipath_tcp)return std::unexpected("multipath-tcp requires one boolean and cannot repeat");
            options.multipath_tcp=*flag;
        } else if (node.name=="tcp-keepalive") {
            auto value=scalar(node);
            auto flag=value ? std::get_if<bool>(&value->data) : nullptr;
            if (!flag || options.keepalive) return std::unexpected("tcp-keepalive requires one boolean and cannot repeat");
            options.keepalive=*flag;
        } else {
            std::optional<std::uint32_t>* target=nullptr;
            std::uint32_t maximum=32767;
            if (node.name=="tcp-keepalive-idle-seconds") target=&options.keepalive_idle_seconds;
            else if (node.name=="tcp-keepalive-interval-seconds") target=&options.keepalive_interval_seconds;
            else if (node.name=="tcp-keepalive-count") { target=&options.keepalive_count; maximum=127; }
            else return false;
            auto value=integer(node);
            if (*target || !value || !*value || *value>maximum)
                return std::unexpected("invalid or repeated " + node.name);
            *target=static_cast<std::uint32_t>(*value);
        }
        if (!options.valid()) return std::unexpected("invalid physical socket settings or disabled tcp-keepalive conflicts with probe settings");
        return true;
    }
    namespace {
        namespace network=platform::network;

        auto network_type(std::string const* name) noexcept -> std::optional<network::Type> {
            using enum network::Type;
            if (!name) return {};
            if (*name=="ethernet") return ethernet;
            if (*name=="wifi") return wifi;
            if (*name=="cellular") return cellular;
            if (*name=="vpn") return vpn;
            if (*name=="other") return other;
            return {};
        }

        auto network_policy(Node const& node) -> std::expected<network::Policy,std::string> {
            auto strategy=kdl::text_property(node,"strategy");
            auto preferred=network_type(kdl::text_property(node,"type"));
            auto fallback=network_type(kdl::text_property(node,"fallback"));
            auto prefer=strategy && *strategy=="prefer";
            auto is_fallback=strategy && *strategy=="fallback";
            auto is_hybrid=strategy && *strategy=="hybrid";
            auto delay_value=kdl::property(node,"fallback-delay-ms");
            auto delay=delay_value ? kdl::integer(*delay_value) : std::nullopt;
            if (delay_value && (!delay || *delay>60000 || (!is_hybrid && !*delay))) return std::unexpected("invalid fallback-delay-ms");
            auto expected_props=(prefer ? 3U : ((is_fallback || is_hybrid) ? 2U+bool(fallback) : 2U))+bool(delay);
            if (node.tag || !node.arguments.empty() || (!prefer && !is_fallback && !is_hybrid && (!strategy || *strategy!="require")) ||
                !preferred || node.properties.size()!=expected_props || (prefer && !fallback) ||
                (!prefer && !is_fallback && !is_hybrid && fallback) || preferred==fallback ||
                node.children.empty() || node.children.size()>16)
                return std::unexpected("invalid direct network strategy, type, or fallback");
            auto strat=prefer ? network::Strategy::prefer : is_fallback ? network::Strategy::fallback :
                is_hybrid ? network::Strategy::hybrid : network::Strategy::require;
            network::Policy result{strat,*preferred,fallback,{}};
            result.fallback_delay=delay ? std::chrono::milliseconds(*delay) :
                (is_hybrid ? std::chrono::milliseconds(0) : is_fallback ? std::chrono::milliseconds(500) : std::chrono::milliseconds(300));
            for (auto const& child:node.children) {
                auto name=kdl::argument(child);
                auto type=network_type(kdl::text_property(child,"type"));
                if (!name || !parse_iface_name(*name) ||
                    child.name!="interface" || child.properties.size()!=1 || !child.children.empty() ||
                    !type || (!is_fallback && !is_hybrid && *type!=*preferred && type!=fallback) ||
                    std::ranges::find(result.interfaces,*name,&network::Interface::name)!=result.interfaces.end())
                    return std::unexpected("invalid or repeated direct network interface");
                result.interfaces.push_back({std::string(*name),*type});
            }
            auto has=[&](network::Type type) { return std::ranges::find(result.interfaces,type,&network::Interface::type)!=result.interfaces.end(); };
            if (!has(*preferred) || (fallback && !has(*fallback))) return std::unexpected("direct network types require configured interfaces");
            return result;
        }
    }

    auto parse_direct_dial(Node const& node,Config& result) -> std::expected<void,std::string> {
        bool timeout_seen=false;
        auto& options=result.direct_tcp_options;
        for (auto const& child:node.children) {
            if (child.name=="connect-timeout-ms") {
                auto value=integer(child);
                if (timeout_seen || !value || !*value || *value>3600000) return std::unexpected("invalid direct connect-timeout-ms");
                result.direct_connect_timeout_ms=static_cast<std::uint32_t>(*value); timeout_seen=true;
            } else if(child.name=="tcp-fast-open") {
                auto value=scalar(child);auto flag=value ? std::get_if<bool>(&value->data) : nullptr;
                if(!flag || options.tcp_fast_open)return std::unexpected("tcp-fast-open requires one boolean and cannot repeat");
                options.tcp_fast_open=*flag;
            } else if (child.name=="network") {
                if (result.direct_network) return std::unexpected("duplicate direct network policy");
                auto policy=network_policy(child);
                if (!policy) return std::unexpected(std::move(policy.error()));
                result.direct_network=std::move(*policy);
            } else {
                auto parsed=parse_tcp_dial_option(child,options);
                if (!parsed) return std::unexpected(parsed.error());
                if (!*parsed) return std::unexpected("unsupported direct node: " + child.name);
            }
        }
        if (result.direct_network && (!options.binding.interface_name().empty() || !options.binding.network_namespace.empty() ||
            options.binding.inet4_bind_address || options.binding.inet6_bind_address))
            return std::unexpected("direct network policy conflicts with bind-interface, netns, or bind-address");
        return {};
    }

    auto parse_listen_option(glaze::KdlNode const& node, ListenOptions& listen) -> std::expected<bool, std::string> {
        auto set_keepalive_param = [&](std::string_view key, glaze::KdlValue const& val) -> std::expected<void, std::string> {
            auto num = kdl::integer(val);
            std::optional<std::uint32_t>* target = nullptr;
            std::uint32_t max_v = 32767;
            if (key == "idle-s" || key == "tcp-keepalive-idle-seconds") target = &listen.tcp_keepalive_idle_s;
            else if (key == "interval-s" || key == "tcp-keepalive-interval-seconds") target = &listen.tcp_keepalive_interval_s;
            else if (key == "count" || key == "tcp-keepalive-count") { target = &listen.tcp_keepalive_count; max_v = 127; }
            else return std::unexpected("unsupported tcp-keepalive option: " + std::string(key));
            if (*target || !num || !*num || *num > max_v)
                return std::unexpected("invalid or repeated listen " + std::string(key));
            *target = static_cast<std::uint32_t>(*num);
            return {};
        };
        if (node.name == "bind-interface") {
            auto v = scalar(node); auto text = v ? std::get_if<std::string>(&v->data) : nullptr;
            if (!text || !listen.bind_interface.empty() || !parse_iface_name(*text))
                return std::unexpected("listen bind-interface requires a valid nonempty interface name and cannot repeat");
            listen.bind_interface = *text;
        } else if (node.name == "routing-mark") {
            auto v = integer(node);
            if (!v || *v > std::numeric_limits<std::uint32_t>::max() || listen.routing_mark)
                return std::unexpected("listen routing-mark requires an unsigned 32-bit integer and cannot repeat");
            listen.routing_mark = static_cast<std::uint32_t>(*v);
        } else if (node.name == "netns") {
            auto v = scalar(node); auto path = v ? std::get_if<std::string>(&v->data) : nullptr;
            if (!path || path->empty() || !listen.netns.empty() || !kdl::absolute_path(*path) || path->size() >= 4096)
                return std::unexpected("listen netns requires an absolute path and cannot repeat");
            listen.netns = *path;
        } else if (node.name == "tcp-fast-open" || node.name == "multipath-tcp" ||
                   node.name == "reuse-addr" || node.name == "udp-fragment") {
            auto v = scalar(node); auto flag = v ? std::get_if<bool>(&v->data) : nullptr;
            auto& target = node.name == "tcp-fast-open" ? listen.tcp_fast_open :
                node.name == "multipath-tcp" ? listen.multipath_tcp :
                node.name == "reuse-addr" ? listen.reuse_addr : listen.udp_fragment;
            if (!flag || target) return std::unexpected("listen " + node.name + " requires one boolean and cannot repeat");
            target = *flag;
        } else if (node.name == "udp-timeout-ms") {
            auto v = integer(node);
            if (!v || *v < 1000 || *v > 3600000 || listen.udp_timeout_ms)
                return std::unexpected("listen udp-timeout-ms must be 1000..3600000 and cannot repeat");
            listen.udp_timeout_ms = static_cast<std::uint32_t>(*v);
        } else if (node.name == "detour") {
            auto v = scalar(node); auto text = v ? std::get_if<std::string>(&v->data) : nullptr;
            if (!text || !kdl::valid_name(*text) || listen.detour)
                return std::unexpected("listen detour requires a valid inbound name and cannot repeat");
            listen.detour = *text;
        } else if (node.name == "tcp-keepalive") {
            if (node.tag || listen.tcp_keepalive)
                return std::unexpected("invalid or repeated listen tcp-keepalive");
            if (node.arguments.size() > 1) return std::unexpected("listen tcp-keepalive takes at most one boolean");
            if (node.arguments.size() == 1) {
                auto const& arg = node.arguments.front();
                auto flag = arg.tag ? nullptr : std::get_if<bool>(&arg.data);
                if (!flag) return std::unexpected("listen tcp-keepalive argument must be a boolean");
                listen.tcp_keepalive = *flag;
            } else {
                if (node.properties.empty() && node.children.empty())
                    return std::unexpected("listen tcp-keepalive requires a boolean or probe parameters");
                listen.tcp_keepalive = true;
            }
            for (auto const& [k, val] : node.properties)
                if (auto ok = set_keepalive_param(k, val); !ok) return std::unexpected(std::move(ok.error()));
            for (auto const& c : node.children) {
                auto v = scalar(c);
                if (!v) return std::unexpected("invalid listen tcp-keepalive child: " + c.name);
                if (auto ok = set_keepalive_param(c.name, *v); !ok) return std::unexpected(std::move(ok.error()));
            }
        } else if (node.name == "tcp-keepalive-idle-seconds" || node.name == "tcp-keepalive-interval-seconds" ||
                   node.name == "tcp-keepalive-count") {
            auto v = scalar(node);
            if (!v) return std::unexpected("invalid listen " + node.name);
            if (auto ok = set_keepalive_param(node.name, *v); !ok) return std::unexpected(std::move(ok.error()));
        } else {
            return false;
        }
        if (!listen.valid()) return std::unexpected("invalid listen socket options or disabled tcp-keepalive conflict");
        return true;
    }

    auto extract_listen_options(glaze::KdlNode const& node, ListenOptions& listen) -> std::expected<glaze::KdlNode, std::string> {
        glaze::KdlNode filtered = node;
        filtered.children.clear();
        filtered.children.reserve(node.children.size());
        for (auto const& child : node.children) {
            auto matched = parse_listen_option(child, listen);
            if (!matched) return std::unexpected(std::move(matched.error()));
            if (!*matched) filtered.children.push_back(child);
        }
        return filtered;
    }

    auto apply_routing_defaults(Config& config) -> std::expected<void, std::string> {
        auto& d = config.defaults;
        if (!d.configured()) return {};
        if (d.default_domain_resolver) {
            if (!config.dns) return std::unexpected("dns default resolver requires a dns block");
            auto idx = config.dns->resolver_index(*d.default_domain_resolver);
            if (!idx) return std::unexpected("dns default resolver not found: " + *d.default_domain_resolver);
            d.default_domain_resolver_index = *idx;
        }
        auto inherit_binding = [&](platform::SocketBinding& b, bool has_explicit_network) -> void {
            if (d.default_mark && !b.routing_mark) b.routing_mark = *d.default_mark;
            bool const can_pick_iface = b.interface_name().empty() && b.network_namespace.empty() &&
                !b.network && !b.interface_index && !has_explicit_network;
            if (!d.default_interface.empty() && can_pick_iface) {
                std::ranges::copy(d.default_interface, b.bind_interface.begin());
            } else if (can_pick_iface) {
                if (d.default_network_strategy && !b.network_strategy) {
                    b.network_strategy = d.default_network_strategy->strategy;
                    b.network_type = d.default_network_type.value_or(d.default_network_strategy->preferred);
                } else if (d.default_network_type && !b.network_type) {
                    b.network_type = *d.default_network_type;
                }
                if (d.auto_detect_interface) b.auto_detect_interface = true;
            }
        };
        inherit_binding(config.direct_tcp_options.binding, config.direct_network.has_value());
        if (d.default_network_strategy && !config.direct_network &&
            config.direct_tcp_options.binding.interface_name().empty() &&
            config.direct_tcp_options.binding.network_namespace.empty() &&
            !config.direct_tcp_options.binding.inet4_bind_address &&
            !config.direct_tcp_options.binding.inet6_bind_address) {
            config.direct_network = *d.default_network_strategy;
        }
        auto inherit_outbound = [&](auto& outbounds) -> void {
            for (auto& entry : outbounds) {
                auto& ob = [&]() -> auto& {
                    if constexpr (requires { entry.config.connection; }) return entry.config.connection;
                    else return entry.config;
                }();
                if (!ob.detour) inherit_binding(ob.tcp_options.binding, false);
                if (d.default_domain_resolver && d.default_domain_resolver_index && !ob.bootstrap_resolver &&
                    dns_hostname(ob.host) && !platform::parse_ip_address(ob.host)) {
                    ob.bootstrap_resolver = *d.default_domain_resolver;
                    ob.bootstrap_index = *d.default_domain_resolver_index;
                }
            }
        };
        inherit_outbound(config.vless_outbounds);
        inherit_outbound(config.shadowsocks_outbounds);
        inherit_outbound(config.trojan_outbounds);
        inherit_outbound(config.anytls_outbounds);
        inherit_outbound(config.hysteria2_outbounds);
        inherit_outbound(config.snell_outbounds);
        inherit_outbound(config.shadowtls_outbounds);
        inherit_outbound(config.tuic_outbounds);
        inherit_outbound(config.masque_outbounds);
        inherit_outbound(config.wireguard_outbounds);
        inherit_outbound(config.ssh_outbounds);
        inherit_outbound(config.naive_outbounds);
        inherit_outbound(config.openvpn_outbounds);
        inherit_outbound(config.openconnect_outbounds);
        inherit_outbound(config.tcp_proxy_outbounds);
        return {};
    }
}
