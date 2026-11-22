// Private parsers for top-level certificate and ntp blocks, included in config.cpp.
#pragma once

        auto parse_certificate_block(Node const& node) -> std::expected<CertificateConfig, std::string> {
            if (node.tag || !node.arguments.empty() || !node.properties.empty())
                return error("certificate takes only child nodes");
            CertificateConfig cfg{};
            bool ca_seen = false, store_seen = false;
            for (auto const& child : node.children) {
                auto val = scalar(child);
                if (child.name == "ca-file") {
                    if (ca_seen || !val || !absolute_path(*val))
                        return error("certificate ca-file requires one absolute path");
                    cfg.ca_file = *val;
                    ca_seen = true;
                } else if (child.name == "store") {
                    if (store_seen || !val || (*val != "system" && *val != "custom"))
                        return error("certificate store must be system or custom");
                    cfg.system_store = (*val == "system");
                    store_seen = true;
                } else {
                    return error("unsupported certificate field: " + child.name);
                }
            }
            if (cfg.ca_file.empty() && cfg.system_store) {
                for (std::string_view p : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"}) {
                    std::error_code ec;
                    if (std::filesystem::is_regular_file(p, ec) && !ec) {
                        cfg.ca_file = std::string(p);
                        break;
                    }
                }
            }
            if (cfg.ca_file.empty()) return error("certificate block requires ca-file or an available system CA bundle");
            return cfg;
        }

        auto parse_ntp_block(Node const& node) -> std::expected<NtpConfig, std::string> {
            if (node.tag || !node.arguments.empty() || !node.properties.empty())
                return error("ntp takes only child nodes");
            NtpConfig cfg{};
            bool server_seen = false, interval_seen = false, timeout_seen = false;
            for (auto const& child : node.children) {
                if (child.name == "server") {
                    auto host = text_property(child, "host");
                    auto pv = property(child, "port");
                    auto port = pv ? integer(*pv) : std::optional<std::uint64_t>{123};
                    if (server_seen || child.tag || !child.arguments.empty() || !child.children.empty() ||
                        child.properties.size() != 1u + bool(pv) || !host || !endpoint_name(*host) ||
                        !port || !*port || *port > 65535)
                        return error("invalid ntp server");
                    cfg.host = *host;
                    cfg.port = static_cast<std::uint16_t>(*port);
                    server_seen = true;
                } else if (child.name == "interval-ms") {
                    auto v = integer(child);
                    if (interval_seen || !v || *v < 1000 || *v > 86400000) return error("ntp interval-ms must be 1000..86400000");
                    cfg.interval_ms = static_cast<std::uint32_t>(*v);
                    interval_seen = true;
                } else if (child.name == "timeout-ms") {
                    auto v = integer(child);
                    if (timeout_seen || !v || *v < 100 || *v > 30000) return error("ntp timeout-ms must be 100..30000");
                    cfg.timeout_ms = static_cast<std::uint32_t>(*v);
                    timeout_seen = true;
                } else {
                    return error("unsupported ntp field: " + child.name);
                }
            }
            if (!server_seen) return error("ntp requires a server");
            return cfg;
        }

        auto apply_certificate_defaults(Config& config) -> std::expected<void, std::string> {
            std::string_view fallback = config.certificate ? std::string_view(config.certificate->ca_file) : std::string_view{};
            auto fill = [&](std::string& ca, std::string_view label) -> std::expected<void, std::string> {
                if (ca.empty() && !fallback.empty()) ca = std::string(fallback);
                if (ca.empty()) return error(std::string(label) + " requires authenticated TLS ca-file");
                return {};
            };
            for (auto& e : config.vless_outbounds)
                if (!e.config.reality && (!e.config.xhttp || !e.config.server_name.empty()))
                    if (auto ok = fill(e.config.ca_file, "vless"); !ok) return ok;
            for (auto& e : config.trojan_outbounds) if (auto ok = fill(e.config.ca_file, "Trojan"); !ok) return ok;
            for (auto& e : config.anytls_outbounds) if (auto ok = fill(e.config.connection.ca_file, "AnyTLS"); !ok) return ok;
            for (auto& e : config.hysteria2_outbounds) if (auto ok = fill(e.config.connection.ca_file, "Hysteria2"); !ok) return ok;
            for (auto& e : config.shadowtls_outbounds) if (auto ok = fill(e.config.connection.ca_file, "ShadowTLS"); !ok) return ok;
            for (auto& e : config.tuic_outbounds) if (auto ok = fill(e.config.ca_file, "TUIC"); !ok) return ok;
            for (auto& e : config.masque_outbounds) if (auto ok = fill(e.config.ca_file, "MASQUE"); !ok) return ok;
            for (auto& e : config.naive_outbounds) if (auto ok = fill(e.config.ca_file, "NaiveProxy"); !ok) return ok;
            for (auto& e : config.tcp_proxy_outbounds)
                if (e.config.tls) if (auto ok = fill(e.config.tls->ca_file, "HTTP CONNECT"); !ok) return ok;
            return {};
        }
