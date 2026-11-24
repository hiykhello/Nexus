module config;
import std;
import glaze;
import config.kdl_common;
import platform.socket_options;

namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;
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
            auto delay_value=kdl::property(node,"fallback-delay-ms");
            auto delay=delay_value ? kdl::integer(*delay_value) : std::nullopt;
            if (delay_value && (!delay || !*delay || *delay>60000)) return std::unexpected("invalid fallback-delay-ms");
            auto expected_props=(prefer ? 3U : (is_fallback ? 2U+bool(fallback) : 2U))+bool(delay);
            if (node.tag || !node.arguments.empty() || (!prefer && !is_fallback && (!strategy || *strategy!="require")) ||
                !preferred || node.properties.size()!=expected_props || (prefer && !fallback) ||
                (!prefer && !is_fallback && fallback) || preferred==fallback ||
                node.children.empty() || node.children.size()>16)
                return std::unexpected("invalid direct network strategy, type, or fallback");
            auto strat=prefer ? network::Strategy::prefer : is_fallback ? network::Strategy::fallback : network::Strategy::require;
            network::Policy result{strat,*preferred,fallback,{}};
            result.fallback_delay=delay ? std::chrono::milliseconds(*delay) :
                (is_fallback ? std::chrono::milliseconds(500) : std::chrono::milliseconds(300));
            for (auto const& child:node.children) {
                auto name=kdl::argument(child);
                auto type=network_type(kdl::text_property(child,"type"));
                platform::SocketBinding validator;
                if (!name || name->empty() || name->size()>=validator.bind_interface.size() ||
                    child.name!="interface" || child.properties.size()!=1 || !child.children.empty() ||
                    !type || (!is_fallback && *type!=*preferred && type!=fallback) ||
                    std::ranges::find(result.interfaces,*name,&network::Interface::name)!=result.interfaces.end())
                    return std::unexpected("invalid or repeated direct network interface");
                std::ranges::copy(*name,validator.bind_interface.begin());
                if (validator.interface_name()!=*name || !validator.valid())
                    return std::unexpected("invalid direct network interface name");
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
        if (result.direct_network && (!options.binding.interface_name().empty() || !options.binding.network_namespace.empty()))
            return std::unexpected("direct network policy conflicts with bind-interface or netns");
        return {};
    }
}
