// Inbound configuration parser implementation.
module config;
import std;
import glaze;
import config.kdl_common;
import http.connect;
import platform.ip_address;

namespace config {
    using namespace config::kdl;
    auto parse_trojan_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_anytls_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_vless_transport(g::KdlNode const&, bool)
        -> std::expected<std::variant<HttpUpgradeTransport, GrpcTransport, xhttp::Profile>, std::string>;
    auto parse_masque_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_snell_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_hysteria2_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_shadowtls_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_tuic_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_tun_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_naive_inbound(g::KdlNode const&) -> std::expected<InboundConfig, std::string>;
    auto parse_inbound_multiplex(g::KdlNode const&) -> std::expected<InboundMultiplexConfig, std::string>;
    auto extract_listen_options(g::KdlNode const&, ListenOptions&) -> std::expected<g::KdlNode, std::string>;
    auto parse_shared_inbound_tls_field(g::KdlNode const&, std::string&, std::string&, std::vector<std::string>&, bool&, bool&)
        -> std::expected<bool, std::string>;
    auto extract_delegated_inbound_tls(g::KdlNode const&, std::string&, std::string&, std::vector<std::string>&, bool&)
        -> std::expected<g::KdlNode, std::string>;
    namespace {
        struct LocalSharedTls {
            std::string certificate_provider, ech_key_file;
            std::vector<std::string> alpn;
            bool cert_hot_reload = false, reload_seen = false;
        };
        auto apply_shared_tls(auto& dst, LocalSharedTls&& s) -> void {
            if (!s.certificate_provider.empty()) { dst.certificate_file.clear(); dst.private_key_file.clear(); }
            dst.certificate_provider = std::move(s.certificate_provider);
            dst.ech_key_file = std::move(s.ech_key_file);
            dst.alpn = std::move(s.alpn);
            dst.cert_hot_reload = s.cert_hot_reload;
        }
    }

    auto fixed_tcp_inbound(Node const& node, Config& result) -> std::expected<std::uint16_t, std::string> {
        auto name = argument(node);
        if (!name || !valid_name(*name) || node.properties.size() != 1 || node.children.size() != 2)
            return error("fixed-tcp inbound requires listen and target");
        std::uint16_t listen_port = 0;
        for (auto const& field : node.children) {
            if (auto unix_path = text_property(field, "unix-path")) {
                if (field.tag || !field.arguments.empty() || !field.children.empty() || field.properties.size() != 1 ||
                    unix_path->size() < 2 || unix_path->size() > 107 || unix_path->find('\0') != std::string::npos ||
                    (unix_path->front() != '/' && unix_path->front() != '@'))
                    return error("unix-path requires an absolute path or Linux @name of at most 107 bytes");
                if (field.name == "listen" && !listen_port && result.unix_path.empty()) result.unix_path = *unix_path;
                else if (field.name == "target" && !result.fixed_tcp_inbound) result.fixed_tcp_inbound.emplace("", 0, *unix_path);
                else return error("duplicate or invalid fixed-tcp unix-path");
                continue;
            }
            auto host = text_property(field, "host");
            auto port = property(field, "port");
            auto number = port ? integer(*port) : std::nullopt;
            if (field.tag || !field.arguments.empty() || !field.children.empty() ||
                field.properties.size() != 2 || !host || !number || !*number || *number > 65535)
                return error("fixed-tcp endpoint requires host and port 1..65535");
            if (field.name == "listen" && !listen_port && result.unix_path.empty() && (*host == "127.0.0.1" || *host == "::1")) {
                listen_port = static_cast<std::uint16_t>(*number);
                result.listen_ipv6 = *host == "::1";
            } else if (field.name == "target" && !result.fixed_tcp_inbound && endpoint_name(*host)) {
                auto authority = host->contains(':') ? "[" + *host + "]:" + std::to_string(*number) :
                    *host + ":" + std::to_string(*number);
                if (http::parse_destination_authority(authority).status != http::ConnectStatus::accepted)
                    return error("invalid fixed-tcp target");
                result.fixed_tcp_inbound.emplace(*host, static_cast<std::uint16_t>(*number));
            } else return error("fixed-tcp requires one loopback listen and one target");
        }
        if ((!listen_port && result.unix_path.empty()) || !result.fixed_tcp_inbound)
            return error("fixed-tcp inbound requires listen and target");
        result.inbound = Inbound::fixed_tcp;
        return listen_port;
    }

    auto fixed_udp_inbound(Node const& node, Config& result) -> std::expected<std::uint16_t, std::string> {
        auto name = argument(node);
        if (!name || !valid_name(*name) || node.properties.size() != 1 || node.children.size() < 2 || node.children.size() > 3)
            return error("fixed-udp inbound requires listen and target");
        std::uint16_t listen_port = 0;
        FixedUdpInbound cfg;
        bool listen_seen = false, target_seen = false, idle_seen = false;
        for (auto const& field : node.children) {
            if (field.name == "idle-timeout-ms") {
                auto v = field.arguments.size() == 1 ? integer(field.arguments.front()) : std::nullopt;
                if (idle_seen || field.tag || !field.properties.empty() || !field.children.empty() || !v || *v < 1000 || *v > 3600000)
                    return error("fixed-udp idle-timeout-ms must be 1000..3600000");
                cfg.idle_timeout_ms = static_cast<std::uint32_t>(*v);
                idle_seen = true;
                continue;
            }
            auto host = text_property(field, "host");
            auto port = property(field, "port");
            auto number = port ? integer(*port) : std::nullopt;
            if (field.tag || !field.arguments.empty() || !field.children.empty() ||
                field.properties.size() != 2 || !host || !number || !*number || *number > 65535)
                return error("fixed-udp endpoint requires host and port 1..65535");
            if (field.name == "listen" && !listen_seen) {
                auto addr = platform::parse_ip_address(*host);
                if (!addr) return error("fixed-udp listen requires numeric IP without zone");
                result.listen_ipv6 = addr->size == 16;
                cfg.listen_address = addr->bytes;
                cfg.listen_host = *host;
                listen_port = static_cast<std::uint16_t>(*number);
                listen_seen = true;
            } else if (field.name == "target" && !target_seen && endpoint_name(*host)) {
                auto authority = host->contains(':') ? "[" + *host + "]:" + std::to_string(*number) :
                    *host + ":" + std::to_string(*number);
                if (http::parse_destination_authority(authority).status != http::ConnectStatus::accepted)
                    return error("invalid fixed-udp target");
                cfg.target_host = *host;
                cfg.target_port = static_cast<std::uint16_t>(*number);
                target_seen = true;
            } else return error("fixed-udp requires one listen and one target");
        }
        if (!listen_seen || !target_seen) return error("fixed-udp inbound requires listen and target");
        result.inbound = Inbound::fixed_udp;
        result.fixed_udp_inbound = std::move(cfg);
        return listen_port;
    }

    auto inbound(Node const& raw_node, Config& result) -> std::expected<std::uint16_t, std::string> {
        auto name = argument(raw_node);
        auto type = text_property(raw_node, "type");
        ListenOptions listen_opts{};
        Node filtered_node;
        Node const* active = &raw_node;
        if (type && *type != "tun") {
            auto extracted = extract_listen_options(raw_node, listen_opts);
            if (!extracted) return std::unexpected(std::move(extracted.error()));
            filtered_node = std::move(*extracted);
            active = &filtered_node;
        }
        auto const& node = *active;
        auto finish = [&](std::expected<std::uint16_t, std::string> port) -> std::expected<std::uint16_t, std::string> {
            if (!port) return port;
            result.listen = listen_opts;
            auto set_l = [&](auto& opt) { if (opt) opt->listen = listen_opts; };
            set_l(result.vless_inbound); set_l(result.shadowsocks_inbound); set_l(result.trojan_inbound);
            set_l(result.anytls_inbound); set_l(result.snell_inbound); set_l(result.hysteria2_inbound);
            set_l(result.masque_inbound); set_l(result.shadowtls_inbound); set_l(result.tuic_inbound);
            set_l(result.http_inbound); set_l(result.naive_inbound);
            if (result.fixed_udp_inbound) {
                result.fixed_udp_inbound->listen = listen_opts;
                if (listen_opts.udp_timeout_ms && result.fixed_udp_inbound->idle_timeout_ms == 60000)
                    result.fixed_udp_inbound->idle_timeout_ms = *listen_opts.udp_timeout_ms;
            }
            return port;
        };
        if (type && *type == "fixed-tcp") return finish(fixed_tcp_inbound(node, result));
        if (type && *type == "fixed-udp") return finish(fixed_udp_inbound(node, result));
        if (type && (*type == "redirect" || *type == "tproxy")) {
            if (!name || !valid_name(*name) || node.properties.size() != 1 || node.children.empty() || node.children.size() > 2)
                return error("transparent inbound requires one numeric listen endpoint");
            auto found = std::ranges::find(node.children, std::string_view("listen"), &Node::name);
            if (found == node.children.end()) return error("transparent inbound requires listen");
            auto const& listen = *found;
            auto host = text_property(listen, "host");
            auto port = property(listen, "port");
            auto address = host ? platform::parse_ip_address(*host) : std::nullopt;
            auto number = port ? integer(*port) : std::nullopt;
            if (listen.name != "listen" || listen.tag || !listen.arguments.empty() || !listen.children.empty() ||
                listen.properties.size() != 2 || !address || !number || !*number || *number > 65535)
                return error("transparent inbound requires a numeric listen host and port 1..65535");
            result.inbound = *type == "redirect" ? Inbound::redirect : Inbound::tproxy;
            result.listen_ipv6 = address->size == 16;
            result.redirect_inbound = address->bytes;
            result.redirect_host = *host;
            if (node.children.size() == 2) {
                auto const& udp = node.children[found == node.children.begin() ? 1 : 0];
                if (*type != "tproxy" || udp.name != "udp" || udp.tag || !udp.properties.empty() ||
                    !udp.children.empty() || udp.arguments.size() != 1 || udp.arguments[0].tag ||
                    !std::holds_alternative<bool>(udp.arguments[0].data))
                    return error("tproxy udp requires one boolean");
                result.transparent_udp = std::get<bool>(udp.arguments[0].data);
            }
            return finish(static_cast<std::uint16_t>(*number));
        }
        if (type && *type == "masque") {
            LocalSharedTls stls;
            auto stripped = extract_delegated_inbound_tls(node, stls.certificate_provider, stls.ech_key_file, stls.alpn, stls.cert_hot_reload);
            if (!stripped) return std::unexpected(stripped.error());
            auto entry = parse_masque_inbound(*stripped);
            if (!entry) return std::unexpected(entry.error());
            apply_shared_tls(*entry->masque, std::move(stls));
            result.inbound = Inbound::masque; result.listen_ipv6 = entry->listen_ipv6;
            result.masque_inbound = std::move(entry->masque); return finish(entry->port);
        }
        if (type && *type == "shadowtls") {
            auto entry = parse_shadowtls_inbound(node); if (!entry) return std::unexpected(entry.error());
            result.inbound = Inbound::shadowtls; result.listen_ipv6 = entry->listen_ipv6;
            result.shadowtls_inbound = std::move(entry->shadowtls); return finish(entry->port);
        }
        if (type && *type == "tuic") {
            auto entry = parse_tuic_inbound(node); if (!entry) return std::unexpected(entry.error());
            result.inbound = Inbound::tuic; result.listen_ipv6 = entry->listen_ipv6;
            result.tuic_inbound = std::move(entry->tuic); return finish(entry->port);
        }
        if (type && *type == "tun") {
            auto entry = parse_tun_inbound(node); if (!entry) return std::unexpected(entry.error());
            result.inbound = Inbound::tun; result.tun_inbound = std::move(entry->tun); return entry->port;
        }
        if (type && *type == "snell") {
            auto entry = parse_snell_inbound(node); if (!entry) return std::unexpected(entry.error());
            result.inbound = Inbound::snell; result.listen_ipv6 = entry->listen_ipv6;
            result.snell_inbound = std::move(entry->snell); return finish(entry->port);
        }
        if (type && *type == "hysteria2") {
            auto entry = parse_hysteria2_inbound(node); if (!entry) return std::unexpected(entry.error());
            auto& h = *entry->hysteria2;
            if (h.certificate_provider.empty()) h.certificate_provider = h.connection.certificate_provider;
            if (h.ech_key_file.empty()) h.ech_key_file = h.connection.ech_key_file;
            if (h.alpn.empty()) h.alpn = h.connection.alpn;
            h.cert_hot_reload = h.cert_hot_reload || h.connection.cert_hot_reload;
            result.inbound = Inbound::hysteria2; result.listen_ipv6 = entry->listen_ipv6;
            result.hysteria2_inbound = std::move(entry->hysteria2); return finish(entry->port);
        }
        if (type && *type == "anytls") {
            auto entry = parse_anytls_inbound(node); if (!entry) return std::unexpected(entry.error());
            result.inbound = Inbound::anytls; result.listen_ipv6 = entry->listen_ipv6;
            result.anytls_inbound = std::move(entry->anytls); return finish(entry->port);
        }
        if (type && *type == "trojan") {
            auto entry = parse_trojan_inbound(node); if (!entry) return std::unexpected(entry.error());
            result.inbound = Inbound::trojan; result.listen_ipv6 = entry->listen_ipv6;
            result.trojan_inbound = std::move(entry->trojan); return finish(entry->port);
        }
        if (type && *type == "naive") {
            LocalSharedTls stls;
            auto stripped = extract_delegated_inbound_tls(node, stls.certificate_provider, stls.ech_key_file, stls.alpn, stls.cert_hot_reload);
            if (!stripped) return std::unexpected(stripped.error());
            auto entry = parse_naive_inbound(*stripped);
            if (!entry) return std::unexpected(entry.error());
            apply_shared_tls(*entry->naive, std::move(stls));
            result.inbound = Inbound::naive; result.listen_ipv6 = entry->listen_ipv6;
            result.naive_inbound = std::move(entry->naive); return finish(entry->port);
        }
        if (!name || !valid_name(*name) || node.properties.size() != 1 || !type ||
            (*type != "socks5" && *type != "mixed" && *type != "http" && *type != "vless" && *type != "shadowsocks"))
            return error("inbound requires a name and a supported type");
        auto tcp_proxy = *type == "socks5" || *type == "mixed" || *type == "http";
        bool listen_seen = false, auth_seen = false, tls_seen = false, flow_seen = false;
        bool http2_seen = false, http3_seen = false, connect_udp_seen = false, hs_seen = false, idle_seen = false, mem_seen = false;
        std::string listen_host_str;
        std::optional<platform::IpAddress> listen_ip_parsed;
        HttpInbound http_cfg;
        VlessInbound vless;
        ShadowsocksInbound ss;
        std::uint16_t port = 0;
        for (auto const& child : node.children) {
            if (child.name == "udp-advertise-ip" && (*type == "socks5" || *type == "mixed")) {
                auto text = scalar(child);
                auto ip = text ? platform::parse_ip_address(*text) : std::nullopt;
                if (result.udp_advertise_ip || !ip || !std::ranges::any_of(ip->view(), [](auto byte) { return byte != 0; }) ||
                    (ip->size == 4 && ip->bytes[0] >= 224) || (ip->size == 16 && ip->bytes[0] == 255))
                    return error("udp-advertise-ip requires one unicast IPv4 or IPv6 address");
                result.udp_advertise_ip = *ip;
            } else if (child.name == "listen") {
                if (listen_seen || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size() != 2)
                    return error("inbound requires one listen with host and port");
                auto host = text_property(child, "host");
                auto port_value = property(child, "port");
                auto number = port_value ? integer(*port_value) : std::nullopt;
                auto parsed_ip = host ? platform::parse_ip_address(*host) : std::nullopt;
                if (!host || !number || *number == 0 || *number > 65535 || !parsed_ip)
                    return error("listen requires a supported numeric host and port 1..65535");
                (void)tcp_proxy;
                result.listen_ipv6 = parsed_ip->size == 16;
                result.listen_host = *host;
                result.listen_address = parsed_ip->bytes;
                listen_host_str = *host;
                listen_ip_parsed = *parsed_ip;
                port = static_cast<std::uint16_t>(*number);
                listen_seen = true;
            } else if (*type == "http" && child.name == "tls") {
                if (tls_seen || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid HTTP inbound TLS");
                LocalSharedTls stls;
                for (auto const& f : child.children) {
                    auto matched = parse_shared_inbound_tls_field(f, stls.certificate_provider, stls.ech_key_file, stls.alpn, stls.cert_hot_reload, stls.reload_seen);
                    if (!matched) return std::unexpected(matched.error());
                    if (*matched) continue;
                    auto v = scalar(f);
                    if (!v || !absolute_path(*v)) return error("HTTP TLS requires absolute file paths");
                    if (f.name == "certificate-file" && http_cfg.certificate_file.empty()) http_cfg.certificate_file = *v;
                    else if (f.name == "private-key-file" && http_cfg.private_key_file.empty()) http_cfg.private_key_file = *v;
                    else return error("unsupported or duplicate HTTP TLS field");
                }
                if (!stls.certificate_provider.empty()) {
                    if (!http_cfg.certificate_file.empty() || !http_cfg.private_key_file.empty() || stls.cert_hot_reload)
                        return error("HTTP TLS certificate-provider cannot be combined with static cert/key or cert-hot-reload");
                } else if (http_cfg.certificate_file.empty() || http_cfg.private_key_file.empty())
                    return error("HTTP TLS requires certificate-file and private-key-file or certificate-provider");
                apply_shared_tls(http_cfg, std::move(stls)); http_cfg.has_tls = true; tls_seen = true;
            } else if (*type == "http" && (child.name == "http2" || child.name == "http3" || child.name == "connect-udp")) {
                auto v = boolean(child);
                if (!v) return error("invalid HTTP inbound protocol flag");
                if (child.name == "http2" && !std::exchange(http2_seen, true)) http_cfg.http2 = *v;
                else if (child.name == "http3" && !std::exchange(http3_seen, true)) http_cfg.http3 = *v;
                else if (child.name == "connect-udp" && !std::exchange(connect_udp_seen, true)) http_cfg.connect_udp = *v;
                else return error("duplicate HTTP inbound flag");
            } else if (*type == "http" && (child.name == "handshake-timeout-ms" || child.name == "idle-timeout-ms" || child.name == "native-bytes")) {
                auto v = integer(child);
                if (!v) return error("invalid HTTP inbound integer option");
                if (child.name == "handshake-timeout-ms" && !std::exchange(hs_seen, true) && *v > 0 && *v <= 3600000)
                    http_cfg.handshake_timeout_ms = static_cast<std::uint32_t>(*v);
                else if (child.name == "idle-timeout-ms" && !std::exchange(idle_seen, true) && *v > 0 && *v <= 86400000)
                    http_cfg.idle_timeout_ms = static_cast<std::uint32_t>(*v);
                else if (child.name == "native-bytes" && !std::exchange(mem_seen, true) && *v >= 65536 && *v <= 1024ull * 1024 * 1024)
                    http_cfg.native_bytes = static_cast<std::size_t>(*v);
                else return error("invalid or duplicate HTTP inbound option");
            } else if (child.name == "transport" && *type == "vless") {
                if (vless.transport || vless.grpc || vless.xhttp) return error("duplicate vless transport");
                auto parsed = parse_vless_transport(child, false);
                if (!parsed) return std::unexpected(parsed.error());
                if (auto grpc = std::get_if<GrpcTransport>(&*parsed)) vless.grpc = std::move(*grpc);
                else if (auto split = std::get_if<xhttp::Profile>(&*parsed)) vless.xhttp = std::move(*split);
                else vless.transport = std::move(std::get<HttpUpgradeTransport>(*parsed));
            } else if (child.name == "multiplex" && (*type == "vless" || *type == "shadowsocks")) {
                auto parsed = parse_inbound_multiplex(child);
                if (!parsed) return std::unexpected(parsed.error());
                if (*type == "vless") {
                    if (vless.multiplex) return error("duplicate vless multiplex");
                    vless.multiplex = std::move(*parsed);
                } else {
                    if (ss.multiplex) return error("duplicate shadowsocks multiplex");
                    ss.multiplex = std::move(*parsed);
                }
            } else if (*type == "shadowsocks" && (child.name == "method" || child.name == "key-file")) {
                auto value = scalar(child);
                if (!value) return error("invalid shadowsocks inbound field");
                if (child.name == "method" && ss.method.empty() && (*value == "2022-blake3-aes-128-gcm" ||
                    *value == "2022-blake3-aes-256-gcm" || *value == "2022-blake3-chacha20-poly1305")) ss.method = *value;
                else if (child.name == "key-file" && ss.key_file.empty() && absolute_path(*value)) ss.key_file = *value;
                else return error("invalid or duplicate shadowsocks inbound field");
            } else if (child.name == "authentication" && *type == "shadowsocks") {
                if (child.tag || !child.arguments.empty() || !child.properties.empty() ||
                    child.children.empty() || child.children.size() > max_tunnel_outbounds || !ss.users.empty())
                    return error("invalid shadowsocks authentication");
                std::unordered_set<std::string_view> seen_names, seen_paths;
                for (auto const& user : child.children) {
                    auto uname = argument(user), path = text_property(user, "key-file");
                    if (user.tag || user.name != "user" || !uname || !valid_name(*uname) || !path ||
                        !absolute_path(*path) || user.properties.size() != 1 || !user.children.empty() ||
                        !seen_names.insert(*uname).second || !seen_paths.insert(*path).second)
                        return error("invalid or duplicate shadowsocks user");
                    ss.users.push_back({std::move(*uname), std::move(*path)});
                }
            } else if (child.name == "flow" && *type == "vless") {
                auto value = scalar(child);
                if (flow_seen || !value || *value != "xtls-rprx-vision") return error("invalid vless inbound flow");
                vless.vision = true; flow_seen = true;
            } else if (child.name == "authentication" && *type == "vless") {
                if (auth_seen || child.tag || !child.arguments.empty() || !child.properties.empty())
                    return error("invalid vless authentication");
                std::unordered_set<std::string_view> seen_names;
                for (auto const& user : child.children) {
                    auto user_name = argument(user), path = text_property(user, "uuid-file");
                    if (user.name != "user" || !user_name || !valid_name(*user_name) || !path || !absolute_path(*path) ||
                        user.properties.size() != 1 || !user.children.empty() || vless.users.size() >= max_tunnel_outbounds ||
                        !seen_names.insert(*user_name).second)
                        return error("invalid or duplicate vless user");
                    vless.users.push_back({*user_name, *path});
                }
                if (vless.users.empty()) return error("vless requires at least one user");
                auth_seen = true;
            } else if (child.name == "tls" && *type == "vless") {
                if (tls_seen || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid vless tls");
                LocalSharedTls stls;
                for (auto const& field : child.children) {
                    if (field.name == "reality") {
                        if (vless.reality || field.tag || !field.arguments.empty() || !field.properties.empty())
                            return error("invalid inbound Reality");
                        VlessInbound::Reality reality;
                        bool skew_seen = false;
                        for (auto const& item : field.children) {
                            if (item.name == "max-time-difference") {
                                auto value = item.arguments.size() == 1 ? integer(item.arguments.front()) : std::nullopt;
                                if (skew_seen || item.tag || !item.properties.empty() || !item.children.empty() || !value || *value > 0xffffffffULL)
                                    return error("invalid Reality time difference");
                                reality.max_time_difference_seconds = *value;
                                skew_seen = true;
                                continue;
                            }
                            if (item.name == "fallback") {
                                auto host = text_property(item, "host");
                                auto value = property(item, "port");
                                auto fport = value ? integer(*value) : std::nullopt;
                                if (!reality.fallback_host.empty() || item.tag || !item.arguments.empty() || !item.children.empty() || item.properties.size() != 2 ||
                                    !host || !endpoint_name(*host) || !fport || !*fport || *fport > 65535)
                                    return error("invalid Reality fallback");
                                reality.fallback_host = *host;
                                reality.fallback_port = static_cast<std::uint16_t>(*fport);
                                continue;
                            }
                            auto value = scalar(item);
                            if (!value) return error("invalid inbound Reality field");
                            if (item.name == "fallback-resolver" && !reality.fallback_resolver && valid_name(*value))
                                reality.fallback_resolver = *value;
                            else if (item.name == "private-key-file" && reality.private_key_file.empty() && absolute_path(*value))
                                reality.private_key_file = *value;
                            else if (item.name == "certificate-file" && reality.certificate_file.empty() && absolute_path(*value))
                                reality.certificate_file = *value;
                            else if (item.name == "signing-key-file" && reality.signing_key_file.empty() && absolute_path(*value))
                                reality.signing_key_file = *value;
                            else if (item.name == "server-name" && endpoint_name(*value) && reality.server_names.size() < 4096 &&
                                     !std::ranges::contains(reality.server_names, *value))
                                reality.server_names.push_back(*value);
                            else if (item.name == "short-id" && value->size() <= 16 && value->size() % 2 == 0 && reality.short_ids.size() < 4096) {
                                std::array<std::uint8_t, 8> id{};
                                auto hex = [](char c) -> int {
                                    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                                };
                                for (std::size_t i = 0; i < value->size() / 2; ++i) {
                                    auto a = hex((*value)[2 * i]), b = hex((*value)[2 * i + 1]);
                                    if (a < 0 || b < 0) return error("invalid Reality short ID");
                                    id[i] = static_cast<std::uint8_t>((a << 4) | b);
                                }
                                if (std::ranges::contains(reality.short_ids, id)) return error("duplicate Reality short ID");
                                reality.short_ids.push_back(id);
                            } else return error("unsupported or duplicate inbound Reality field");
                        }
                        if (reality.private_key_file.empty() || (reality.certificate_file.empty() != reality.signing_key_file.empty()) ||
                            reality.fallback_host.empty() || reality.server_names.empty() || reality.short_ids.empty())
                            return error("inbound Reality missing required fields");
                        vless.reality = std::move(reality);
                        continue;
                    }
                    auto matched = parse_shared_inbound_tls_field(field, stls.certificate_provider, stls.ech_key_file, stls.alpn, stls.cert_hot_reload, stls.reload_seen);
                    if (!matched) return std::unexpected(matched.error());
                    if (*matched) continue;
                    auto path = scalar(field);
                    if (!path || !absolute_path(*path)) return error("vless tls requires absolute file paths");
                    if (field.name == "certificate-file" && vless.certificate_file.empty()) vless.certificate_file = *path;
                    else if (field.name == "private-key-file" && vless.private_key_file.empty()) vless.private_key_file = *path;
                    else return error("unsupported or duplicate vless tls field");
                }
                if (vless.reality) {
                    if (!vless.certificate_file.empty() || !vless.private_key_file.empty() || !stls.certificate_provider.empty() || stls.cert_hot_reload)
                        return error("vless tls cannot combine Reality with certificate files or certificate-provider");
                } else if (!stls.certificate_provider.empty()) {
                    if (!vless.certificate_file.empty() || !vless.private_key_file.empty() || stls.cert_hot_reload)
                        return error("vless tls certificate-provider cannot be combined with static cert/key or cert-hot-reload");
                } else if (vless.certificate_file.empty() || vless.private_key_file.empty())
                    return error("vless tls requires certificate and key, certificate-provider, or Reality");
                apply_shared_tls(vless, std::move(stls)); tls_seen = true;
            } else if (child.name == "authentication") {
                auto mode = argument(child);
                if (auth_seen || !mode || !child.children.empty()) return error("invalid authentication");
                if (*mode == "none" && child.properties.empty()) {
                } else if (*mode == "password" && tcp_proxy && child.properties.size() == 2) {
                    auto username = text_property(child, "username");
                    auto path = text_property(child, "password-file");
                    auto valid_user = username && !username->empty() && username->size() <= 255 &&
                        std::all_of(username->begin(), username->end(), [](unsigned char c) { return c >= 32 && c <= 126; }) &&
                        (*type == "socks5" || !username->contains(':'));
                    if (!valid_user || !path || path->empty() || path->front() != '/' || path->find('\0') != path->npos)
                        return error("password authentication requires username and absolute password-file");
                    result.password_auth = PasswordAuth{*username, *path};
                } else return error("unsupported authentication for inbound");
                auth_seen = true;
            } else return error("unsupported inbound node: " + child.name);
        }
        if (!listen_seen || (*type == "shadowsocks" ? ss.method.empty() || ss.key_file.empty() || auth_seen : !auth_seen) ||
            (*type == "vless" && !tls_seen && !vless.xhttp))
            return error("inbound is missing required fields");
        if (*type == "http") {
            if (!http_cfg.has_tls) {
                if (http2_seen || http3_seen || connect_udp_seen || hs_seen || idle_seen || mem_seen)
                    return error("HTTP/2, HTTP/3 and TLS timeouts require HTTP inbound tls");
            } else {
                if (http_cfg.connect_udp && !http_cfg.http3) return error("HTTP inbound connect-udp requires http3 #true");
                if (!http_cfg.http2 && !http_cfg.http3) return error("TLS HTTP inbound requires http2 or http3");
                http_cfg.listen_host = std::move(listen_host_str);
                http_cfg.listen_address = listen_ip_parsed->bytes;
                result.http_inbound = std::move(http_cfg);
            }
        }
        if (ss.method == "2022-blake3-chacha20-poly1305" && !ss.users.empty())
            return error("shadowsocks multi-user authentication requires an AES method");
        if ((vless.transport || vless.grpc) && (vless.vision || vless.reality))
            return error("HTTPUpgrade/gRPC requires ordinary VLESS TLS");
        if (vless.xhttp && (vless.vision || (vless.xhttp->endpoint.version == xhttp::HttpVersion::http3 && (!tls_seen || vless.reality))))
            return error("invalid VLESS XHTTP TLS or flow options");
        if (vless.multiplex && vless.multiplex->enabled && (vless.vision || vless.xhttp))
            return error("VLESS inbound multiplex cannot be combined with vision or xhttp");
        result.inbound = *type == "mixed" ? Inbound::mixed : *type == "http" ? Inbound::http :
            *type == "vless" ? Inbound::vless : *type == "shadowsocks" ? Inbound::shadowsocks : Inbound::socks5;
        if (*type == "vless") result.vless_inbound = std::move(vless);
        if (*type == "shadowsocks") result.shadowsocks_inbound = std::move(ss);
        return finish(port);
    }
}
