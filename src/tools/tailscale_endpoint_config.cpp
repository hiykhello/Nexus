module cli.tailscale_endpoint;
import std;
import config.kdl_common;
import platform.ip_address;

namespace cli::tailscale_endpoint {
    namespace {
        namespace k = config::kdl;

        auto url(std::string_view value, std::string& authority, std::string& server_name, std::uint16_t& server_port) -> bool {
            if (!value.starts_with("https://")) return false;
            value.remove_prefix(8);
            if (value.ends_with('/')) value.remove_suffix(1);
            auto colon = value.find(':');
            auto name = value.substr(0, colon);
            if (name.empty() || name.size() > 253 || platform::parse_ip_address(name)) return false;
            for (auto part : name | std::views::split('.')) {
                std::string_view label(part);
                if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-' ||
                    !std::ranges::all_of(label, [](char c) {
                        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
                    })) return false;
            }
            if (name.back() == '.') return false;
            std::uint16_t port = 443;
            if (colon != value.npos) {
                auto text = value.substr(colon + 1);
                auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), port);
                if (ec != std::errc{} || end != text.data() + text.size() || !port) return false;
            }
            authority = value;
            server_name = name;
            server_port = port;
            return true;
        }

        auto address(std::string_view text) -> std::optional<net::UdpEndpoint> {
            auto ip = platform::parse_ip_address(text);
            if (!ip) return {};
            auto family = static_cast<std::uint8_t>(ip->size == 4 ? 4 : 6);
            if (family == 4 && ip->bytes[0] >= 224) return {};
            if (family == 6 && (ip->bytes[0] == 255 || (ip->bytes[0] == 254 && (ip->bytes[1] & 192) == 128))) return {};
            return net::UdpEndpoint{family,ip->bytes,0};
        }

        auto read_pin(std::string_view text, std::array<std::uint8_t,32>& output) -> bool {
            if (!text.starts_with("mkey:") || text.size() != 69) return false;
            text.remove_prefix(5);
            for (auto& byte : output) {
                unsigned value = 0;
                auto [end, ec] = std::from_chars(text.data(), text.data() + 2, value, 16);
                if (ec != std::errc{} || end != text.data() + 2) return false;
                byte = static_cast<std::uint8_t>(value);
                text.remove_prefix(2);
            }
            return std::ranges::any_of(output, [](auto byte) { return byte != 0; });
        }

        auto relay(k::Node const& node) -> std::expected<RelayConfig,std::string> {
            if (node.tag || !node.arguments.empty() || !node.properties.empty())
                return std::unexpected("invalid Tailscale derp block");
            RelayConfig options;
            std::set<std::string_view> fields;
            for (auto const& field : node.children) {
                auto value = k::scalar(field);
                if (!fields.emplace(field.name).second) return std::unexpected("duplicate DERP field: " + field.name);
                if (field.name == "server-url" && value && url(*value, options.authority, options.server_name, options.server.port)) continue;
                if (field.name == "server-address" && value) {
                    auto ip = address(*value);
                    if (ip && std::ranges::any_of(ip->address, [](auto byte) { return byte != 0; })) {
                        options.server.family = ip->family;
                        options.server.address = ip->address;
                        continue;
                    }
                }
                if (field.name == "server-key" && value && read_pin(*value,options.pin)) continue;
                if (field.name == "ca-file" && value && k::absolute_path(*value)) { options.ca_file = *value; continue; }
                if (field.name == "region-id") {
                    auto region = k::integer(field);
                    if (region && *region && *region <= 65535) { options.region = static_cast<std::uint16_t>(*region); continue; }
                }
                return std::unexpected("invalid DERP field: " + field.name);
            }
            if (options.authority.empty() || !options.server.family || !options.region || options.ca_file.empty() || !fields.contains("server-key"))
                return std::unexpected("DERP requires a region, TLS endpoint and server pin");
            return options;
        }

        auto endpoint(k::Node const& node) -> std::expected<Config,std::string> {
            auto name = k::argument(node);
            if (!name || !k::valid_name(*name) || node.properties.size() != 1)
                return std::unexpected("invalid Tailscale endpoint");
            Config options;
            options.name = *name;
            std::set<std::string_view> fields;
            std::optional<std::uint16_t> listen_port;
            for (auto const& field : node.children) {
                auto value = k::scalar(field);
                if (field.name == "derp-candidate") {
                    auto candidate = relay(field);
                    if (!candidate) return std::unexpected(candidate.error());
                    if (options.relay_candidates.size() == 8 ||
                        std::ranges::any_of(options.relay_candidates, [&](auto const& previous) {
                            return candidate->region == previous.region && candidate->server == previous.server &&
                                candidate->server_name == previous.server_name;
                        })) return std::unexpected("too many or duplicate Tailscale DERP candidates");
                    options.relay_candidates.push_back(std::move(*candidate));
                    continue;
                }
                if (!fields.emplace(field.name).second) return std::unexpected("duplicate Tailscale field: " + field.name);
                if (field.name == "control-url" && value && url(*value,options.authority,options.server_name,options.control.port)) continue;
                if (field.name == "derp") {
                    auto parsed = relay(field);
                    if (!parsed) return std::unexpected(parsed.error());
                    options.relay.emplace(std::move(*parsed));
                    continue;
                }
                if (field.name == "control-address" && value) {
                    auto ip = address(*value);
                    if (ip && std::ranges::any_of(ip->address, [](auto byte) { return byte != 0; })) {
                        options.control.family = ip->family;
                        options.control.address = ip->address;
                        continue;
                    }
                }
                if (field.name == "control-key" && value && read_pin(*value,options.pin)) continue;
                if (field.name == "ca-file" && value && k::absolute_path(*value)) { options.ca_file = *value; continue; }
                if (field.name == "auth-key-file" && value && k::absolute_path(*value)) { options.auth_key_file = *value; continue; }
                if (field.name == "state-dir" && value && k::absolute_path(*value)) { options.state_dir = *value; continue; }
                if (field.name == "hostname" && value && k::valid_name(*value)) { options.name = *value; continue; }
                if (field.name == "interface-name" && value && value->size() <= 15 && k::valid_name(*value)) {
                    options.interface = *value;
                    continue;
                }
                if (field.name == "mtu") {
                    auto mtu = k::integer(field);
                    if (mtu && *mtu >= 1280 && *mtu <= 1500) { options.mtu = static_cast<std::uint16_t>(*mtu); continue; }
                }
                if (field.name == "ephemeral" || field.name == "accept-routes" || field.name == "discover-paths") {
                    auto enabled = k::boolean(field);
                    if (enabled) {
                        if (field.name == "ephemeral") options.ephemeral=*enabled;
                        else if (field.name == "accept-routes") options.accept_routes=*enabled;
                        else options.discover_paths=*enabled;
                        continue;
                    }
                }
                if (field.name == "stun-server" && !field.tag && field.arguments.empty() && field.children.empty() &&
                    field.properties.size()==2) {
                    auto host=k::text_property(field,"host");
                    auto port=k::property(field,"port");
                    auto number=port ? k::integer(*port) : std::nullopt;
                    if(host && number && *number && *number<=65535) {
                        auto server=address(*host);
                        if(server && std::ranges::any_of(server->address,[](auto byte){return byte!=0;})) {
                            server->port=static_cast<std::uint16_t>(*number);
                            options.stun_server=*server;
                            continue;
                        }
                    }
                }
                if (field.name=="listen-port") {
                    auto port=k::integer(field);
                    if (!port || *port>65535) return std::unexpected("Tailscale listen-port must be 0..65535");
                    listen_port=static_cast<std::uint16_t>(*port);
                    continue;
                }
                if (field.name == "listen" && !field.tag && field.arguments.empty() && field.children.empty() &&
                    (field.properties.size()==1 || field.properties.size()==2)) {
                    auto host = k::text_property(field, "host");
                    auto port_property = k::property(field, "port");
                    auto port = port_property ? k::integer(*port_property) : std::nullopt;
                    if (host && field.properties.size()==1+bool(port_property) && (!port_property || port) && port.value_or(0)<=65535) {
                        if (auto ip = address(*host); ip && std::ranges::any_of(ip->address, [](auto byte) { return byte != 0; })) {
                            options.listen = *ip;
                            options.listen.port = static_cast<std::uint16_t>(port.value_or(0));
                            continue;
                        }
                    }
                }
                return std::unexpected("invalid Tailscale field: " + field.name);
            }
            if (listen_port) {
                if (std::ranges::any_of(node.children,[](auto const& field) {
                    return field.name=="listen" && k::property(field,"port");
                })) return std::unexpected("Tailscale listen-port duplicates listen port");
                options.listen.port=*listen_port;
            }
            if (options.relay && !options.relay_candidates.empty())
                return std::unexpected("Tailscale derp and derp-candidate cannot be combined");
            if (options.stun_server && !options.discover_paths)
                return std::unexpected("Tailscale stun-server requires discover-paths");
            if (options.interface.empty() || options.authority.empty() || !options.control.family || !options.listen.family ||
                options.auth_key_file.empty() || options.ca_file.empty() || !fields.contains("control-key") ||
                (options.state_dir.empty() && !options.ephemeral))
                return std::unexpected("Tailscale endpoint requires control TLS, a control pin, listen, credentials and device configuration");
            return options;
        }
    }

    auto parse(std::string_view input) -> std::expected<std::optional<Config>,std::string> {
        auto document = k::read_document(input);
        if (!document) return std::unexpected(document.error());
        auto selected = std::ranges::find_if(*document, [](auto const& node) {
            auto type = k::text_property(node, "type");
            return node.name == "endpoint" && type && *type == "tailscale";
        });
        if (selected == document->end()) return std::nullopt;
        bool version = false, role = false;
        for (auto const& node : *document) {
            if (&node == &*selected) continue;
            if (!version && node.name == "schema-version" && k::version(node)) { version = true; continue; }
            if (!role && node.name == "role" && k::deployment_role(node) == "client") { role = true; continue; }
            return std::unexpected("Tailscale endpoint requires one client role, schema-version 1 and endpoint");
        }
        if (!version || !role) return std::unexpected("Tailscale endpoint requires role client and schema-version 1");
        auto result = endpoint(*selected);
        if (!result) return std::unexpected(result.error());
        return std::move(*result);
    }
}
