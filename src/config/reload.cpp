// Startup-only process option parser & SIGHUP reload identity implementation.
module config;
import std;
import glaze;
import config.kdl_common;
import http.connect;

namespace config {
    using namespace config::kdl;
    auto normalize_groups(g::KdlDocument&) -> std::expected<void, std::string>;

    auto is_process_option(std::string_view name) noexcept -> bool {
        return name == "shutdown-grace-ms" || name == "sessions-per-listener" ||
            name == "tcp-splice-pipes" || name == "control";
    }

    auto parse_process_option(Node const& node, Config& config) -> std::expected<void, std::string> {
        if (node.name == "shutdown-grace-ms") {
            auto value = kdl::integer(node);
            if (config.shutdown_grace_ms || !value || *value > 30000)
                return error("shutdown-grace-ms must be an integer from 0 to 30000");
            config.shutdown_grace_ms = static_cast<std::uint32_t>(*value);
            return {};
        }
        if (node.name == "sessions-per-listener") {
            auto value = kdl::integer(node);
            if (config.sessions_per_listener || !value || !*value || *value > 4096)
                return error("sessions-per-listener must be an integer from 1 to 4096");
            config.sessions_per_listener = static_cast<std::uint32_t>(*value);
            return {};
        }
        if (node.name == "tcp-splice-pipes") {
            auto value = kdl::integer(node);
            if (config.tcp_splice_pipes || !value || *value > 256)
                return error("tcp-splice-pipes must be an integer from 0 to 256");
            config.tcp_splice_pipes = static_cast<std::uint32_t>(*value);
            return {};
        }
        auto socket = text_property(node, "socket");
        auto reader = property(node, "read-uid");
        auto state = property(node, "selector-state-directory");
        auto directory = text_property(node, "selector-state-directory");
        auto http_prop = property(node, "http-listen");
        auto http_listen = text_property(node, "http-listen");
        auto token_prop = property(node, "bearer-token-file");
        auto token_file = text_property(node, "bearer-token-file");
        auto metrics_prop = property(node, "metrics");
        auto dash_prop = property(node, "dashboard-root");
        auto dash_root = text_property(node, "dashboard-root");
        auto cors_prop = property(node, "cors-allow-origin");
        auto cors_text = text_property(node, "cors-allow-origin");
        auto uid = reader ? kdl::integer(*reader) : std::nullopt;
        auto expected_props = std::size_t{bool(socket)} + bool(reader) + bool(state) + bool(http_prop) +
            bool(token_prop) + bool(metrics_prop) + bool(dash_prop) + bool(cors_prop);
        bool has_cors_children = !node.children.empty();
        if (!config.control_socket.empty() || config.control_http || node.tag || !node.arguments.empty() ||
            node.properties.size() != expected_props || (!socket && !http_prop))
            return error("control requires socket and/or http-listen");
        std::vector<std::string> cors_origins;
        auto add_cors_origin = [&](std::string_view raw) -> std::expected<void, std::string> {
            while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t')) raw.remove_prefix(1);
            while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t')) raw.remove_suffix(1);
            if (raw.empty() || raw.size() > 256 ||
                std::ranges::any_of(raw, [](unsigned char c) { return c <= 0x20 || c >= 0x7f; }))
                return error("control cors-allow-origin contains an invalid origin");
            if (raw != "*") {
                std::string_view rest;
                if (raw.starts_with("http://")) rest = raw.substr(7);
                else if (raw.starts_with("https://")) rest = raw.substr(8);
                else return error("control cors-allow-origin must be '*' or an http(s):// origin");
                if (rest.empty() || rest.contains('/') || rest.contains('?') || rest.contains('#'))
                    return error("control cors-allow-origin must be an exact origin without path");
            }
            if (cors_origins.size() >= 32)
                return error("control cors-allow-origin exceeds 32 entries");
            if (std::ranges::find(cors_origins, raw) == cors_origins.end())
                cors_origins.emplace_back(raw);
            return {};
        };
        if (cors_prop) {
            if (!cors_text || cors_text->empty())
                return error("control cors-allow-origin must be a non-empty string");
            std::string_view rem(*cors_text);
            for (;;) {
                auto comma = rem.find(',');
                auto part = comma == std::string_view::npos ? rem : rem.substr(0, comma);
                if (auto ok = add_cors_origin(part); !ok) return ok;
                if (comma == std::string_view::npos) break;
                rem.remove_prefix(comma + 1);
            }
        }
        for (auto const& child : node.children) {
            if (child.name != "cors-allow-origin" || child.tag || !child.properties.empty() ||
                !child.children.empty() || child.arguments.empty())
                return error("control only supports cors-allow-origin child nodes");
            for (auto const& arg : child.arguments) {
                if (arg.tag) return error("control cors-allow-origin must be a string");
                auto const* s = std::get_if<std::string>(&arg.data);
                if (!s) return error("control cors-allow-origin must be a string");
                if (auto ok = add_cors_origin(*s); !ok) return ok;
            }
        }
        if (socket && (!socket->starts_with('/') || socket->ends_with('/') || socket->contains('\0')))
            return error("control socket must be an absolute path");
        if (state && (!directory || !absolute_path(*directory) || directory->ends_with('/')))
            return error("control selector-state-directory must be an absolute directory path");
        if (reader && (!socket || !uid || *uid >= std::numeric_limits<std::uint32_t>::max()))
            return error("control read-uid requires socket and a valid numeric UID");
        if (http_prop) {
            if (!http_listen) return error("control http-listen must be a host:port string");
            auto parsed = http::parse_destination_authority(*http_listen);
            if (parsed.status != http::ConnectStatus::accepted || parsed.kind == http::HostKind::domain || !parsed.port)
                return error("control http-listen must be an IPv4 or IPv6 literal with port");
            bool ipv6 = parsed.kind == http::HostKind::ipv6;
            bool loopback = ipv6 ?
                (std::ranges::all_of(std::span(parsed.address).first(15), [](auto b) { return b == 0; }) && parsed.address[15] == 1) :
                (parsed.address[0] == 127);
            std::string host_lit;
            if (http_listen->starts_with('[')) {
                auto end = http_listen->find(']');
                host_lit = http_listen->substr(1, end - 1);
            } else {
                host_lit = http_listen->substr(0, http_listen->rfind(':'));
            }
            if (token_prop && (!token_file || !absolute_path(*token_file) || token_file->ends_with('/')))
                return error("control bearer-token-file must be an absolute file path");
            if (dash_prop && (!dash_root || dash_root->empty() || dash_root->contains('\0') || dash_root->contains("..")))
                return error("control dashboard-root must be a valid directory path");
            if (!loopback && !token_file)
                return error("non-loopback control http-listen requires bearer-token-file");
            bool metrics_on = false;
            if (metrics_prop) {
                if (metrics_prop->tag) return error("control metrics must be a boolean");
                auto b = std::get_if<bool>(&metrics_prop->data);
                if (!b) return error("control metrics must be a boolean");
                metrics_on = *b;
            }
            config.control_http = ControlHttpConfig{std::move(host_lit), parsed.port,
                token_file ? *token_file : std::string{}, metrics_on, ipv6,
                dash_root ? *dash_root : std::string{}, std::move(cors_origins)};
        } else if (token_prop || metrics_prop || dash_prop || cors_prop || has_cors_children) {
            return error("control bearer-token-file, metrics, dashboard-root and cors-allow-origin require http-listen");
        }
        if (socket) config.control_socket = *socket;
        if (uid) config.control_read_uid = static_cast<std::uint32_t>(*uid);
        if (directory) config.selector_state_directory = *directory;
        return {};
    }

    namespace {
        auto strip_reload_base(auto& doc) -> void {
            std::erase_if(doc, [](auto const& node) { return node.name == "log"; });
            auto remove_selection = [](Node& outbound) {
                auto type = text_property(outbound, "type");
                if (outbound.name == "outbound" && type && *type == "selector")
                    std::erase_if(outbound.children, [](auto const& field) { return field.name == "selected"; });
            };
            for (auto& node : doc) {
                if (node.name == "outbounds")
                    for (auto& child : node.children) remove_selection(child);
                else remove_selection(node);
            }
        }
        auto strip_dns_policy_scope(auto& doc) -> void {
            std::erase_if(doc, [](auto const& node) { return node.name == "inbound" || node.name == "inbounds"; });
            for (auto& node : doc)
                if (node.name == "dns")
                    std::erase_if(node.children, [](auto const& field) { return field.name == "listen"; });
        }
        auto strip_process_scope(auto& doc) -> void {
            std::erase_if(doc, [](auto const& node) { return node.name == "dns"; });
        }
        auto strip_tun_live_scope(auto& doc) -> void {
            std::erase_if(doc, [](auto const& node) { return node.name == "routing"; });
            for (auto& node : doc)
                if (node.name == "dns")
                    std::erase_if(node.children, [](auto const& field) {
                        return field.name != "listen" && field.name != "fake-ip";
                    });
            std::erase_if(doc, [](auto const& node) { return node.name == "dns" && node.children.empty(); });
        }
    }

    auto reload_identity(std::string_view input, ReloadIdentity scope) -> std::expected<std::string, std::string> {
        auto document = kdl::read_document(input, max_config_bytes);
        if (!document) return std::unexpected(std::move(document.error()));
        if (auto normalized = normalize_groups(*document); !normalized)
            return std::unexpected(std::move(normalized.error()));
        strip_reload_base(*document);
        if (scope == ReloadIdentity::tun_live) {
            strip_tun_live_scope(*document);
        } else {
            if (scope != ReloadIdentity::full) strip_dns_policy_scope(*document);
            if (scope == ReloadIdentity::process) strip_process_scope(*document);
        }
        auto encoded = g::write_kdl(*document);
        if (!encoded) return error("cannot compare reload configuration");
        return std::move(*encoded);
    }

    auto reload_identities(std::string_view input) -> std::expected<ReloadIdentities, std::string> {
        auto document = kdl::read_document(input, max_config_bytes);
        if (!document) return std::unexpected(std::move(document.error()));
        if (auto normalized = normalize_groups(*document); !normalized)
            return std::unexpected(std::move(normalized.error()));
        strip_reload_base(*document);
        auto full = g::write_kdl(*document);
        if (!full) return error("cannot compare reload configuration");
        auto tun_doc = *document;
        strip_tun_live_scope(tun_doc);
        auto tun_live = g::write_kdl(tun_doc);
        if (!tun_live) return error("cannot compare reload configuration");
        strip_dns_policy_scope(*document);
        auto dns_policy = g::write_kdl(*document);
        if (!dns_policy) return error("cannot compare reload configuration");
        strip_process_scope(*document);
        auto process = g::write_kdl(*document);
        if (!process) return error("cannot compare reload configuration");
        return ReloadIdentities{std::move(*full), std::move(*dns_policy), std::move(*process), std::move(*tun_live)};
    }
}
