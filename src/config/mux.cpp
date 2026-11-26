// KDL parser for inbound and outbound generic multiplex configuration.
module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    using namespace config::kdl;

    auto parse_outbound_multiplex(Node const& node) -> std::expected<MultiplexConfig, std::string> {
        if (node.tag || !node.arguments.empty() || !node.properties.empty())
            return error("multiplex block accepts no arguments or inline properties");
        MultiplexConfig cfg;
        cfg.enabled = true;
        bool seen_enabled = false, seen_proto = false, seen_max_conn = false;
        bool seen_min_streams = false, seen_max_streams = false, seen_padding = false, seen_only_tcp = false;
        for (auto const& child : node.children) {
            if (child.name == "enabled") {
                auto v = boolean(child);
                if (seen_enabled || !v) return error("invalid multiplex enabled flag");
                cfg.enabled = *v;
                seen_enabled = true;
            } else if (child.name == "protocol") {
                auto v = scalar(child);
                if (seen_proto || !v) return error("invalid multiplex protocol");
                if (*v == "smux" || *v == "smux-v2") cfg.protocol = MultiplexProtocol::smux_v2;
                else if (*v == "smux-v1") cfg.protocol = MultiplexProtocol::smux_v1;
                else if (*v == "h2mux") cfg.protocol = MultiplexProtocol::h2mux;
                else return error("unsupported multiplex protocol: " + *v);
                seen_proto = true;
            } else if (child.name == "max-connections") {
                auto v = integer(child);
                if (seen_max_conn || !v || *v < 1 || *v > 64) return error("multiplex max-connections must be 1..64");
                cfg.max_connections = static_cast<std::uint32_t>(*v);
                seen_max_conn = true;
            } else if (child.name == "min-streams") {
                auto v = integer(child);
                if (seen_min_streams || !v || *v < 1 || *v > 1024) return error("multiplex min-streams must be 1..1024");
                cfg.min_streams = static_cast<std::uint32_t>(*v);
                seen_min_streams = true;
            } else if (child.name == "max-streams") {
                auto v = integer(child);
                if (seen_max_streams || !v || *v > 1024) return error("multiplex max-streams must be 0..1024");
                cfg.max_streams = static_cast<std::uint32_t>(*v);
                seen_max_streams = true;
            } else if (child.name == "padding") {
                auto v = boolean(child);
                if (seen_padding || !v) return error("invalid multiplex padding flag");
                cfg.padding = *v;
                seen_padding = true;
            } else if (child.name == "only-tcp") {
                auto v = boolean(child);
                if (seen_only_tcp || !v) return error("invalid multiplex only-tcp flag");
                cfg.only_tcp = *v;
                seen_only_tcp = true;
            } else {
                return error("unsupported multiplex field: " + child.name);
            }
        }
        if (seen_min_streams && !seen_max_streams) cfg.max_streams = 0;
        if (cfg.max_streams > 0 && cfg.min_streams > cfg.max_streams)
            return error("multiplex min-streams cannot exceed max-streams");
        return cfg;
    }

    auto parse_inbound_multiplex(Node const& node) -> std::expected<InboundMultiplexConfig, std::string> {
        if (node.tag || !node.arguments.empty() || !node.properties.empty())
            return error("inbound multiplex block accepts no arguments or inline properties");
        InboundMultiplexConfig cfg;
        cfg.enabled = true;
        bool seen_enabled = false, seen_padding = false, seen_max_streams = false;
        for (auto const& child : node.children) {
            if (child.name == "enabled") {
                auto v = boolean(child);
                if (seen_enabled || !v) return error("invalid inbound multiplex enabled flag");
                cfg.enabled = *v;
                seen_enabled = true;
            } else if (child.name == "padding") {
                auto v = boolean(child);
                if (seen_padding || !v) return error("invalid inbound multiplex padding flag");
                cfg.padding = *v;
                seen_padding = true;
            } else if (child.name == "max-streams") {
                auto v = integer(child);
                if (seen_max_streams || !v || *v < 1 || *v > 1024)
                    return error("inbound multiplex max-streams must be 1..1024");
                cfg.max_streams = static_cast<std::uint32_t>(*v);
                seen_max_streams = true;
            } else {
                return error("unsupported inbound multiplex field: " + child.name);
            }
        }
        return cfg;
    }
}
