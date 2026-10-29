// Private implementation: included within nexus::config after KDL helpers.
#pragma once
        auto inbound(Node const& node, Config& result) -> std::expected<std::uint16_t, std::string> {
            auto name = argument(node);
            auto type = text_property(node, "type");
            if (!name || !valid_name(*name) || node.properties.size() != 1 || !type || (*type != "socks5" && *type != "mixed" && *type != "vless" && *type != "shadowsocks"))
                return error("inbound requires a name and a supported type");
            bool listen_seen = false, auth_seen = false, tls_seen = false;
            VlessInbound vless;
            ShadowsocksInbound ss;
            std::uint16_t port = 0;
            for (auto const& child : node.children) {
                if (child.name == "listen") {
                    if (listen_seen || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size() != 2)
                        return error("inbound requires one listen with host and port");
                    auto host = text_property(child, "host");
                    auto port_value = property(child, "port");
                    auto number = port_value ? integer(*port_value) : std::nullopt;
                    if (!host || (*host != "127.0.0.1" && !(*host=="::1" && (*type=="socks5" || *type=="mixed"))) ||
                        !number || *number == 0 || *number > 65535)
                        return error("listen requires a supported loopback host and port 1..65535");
                    result.listen_ipv6=*host=="::1";
                    port = static_cast<std::uint16_t>(*number);
                    listen_seen = true;
                } else if (*type=="shadowsocks" && (child.name=="method" || child.name=="key-file")) {
                    auto value=scalar(child);
                    if (!value) return error("invalid shadowsocks inbound field");
                    if (child.name=="method" && ss.method.empty() && (*value=="2022-blake3-aes-128-gcm" || *value=="2022-blake3-aes-256-gcm")) ss.method=*value;
                    else if (child.name=="key-file" && ss.key_file.empty() && absolute_path(*value)) ss.key_file=*value;
                    else return error("invalid or duplicate shadowsocks inbound field");
                } else if (child.name == "authentication" && *type == "vless") {
                    if (auth_seen || child.tag || !child.arguments.empty() || !child.properties.empty())
                        return error("invalid vless authentication");
                    for (auto const& user : child.children) {
                        auto user_name=argument(user); auto path=text_property(user,"uuid-file");
                        if (user.name!="user" || !user_name || !valid_name(*user_name) || !path || !absolute_path(*path) ||
                            user.properties.size()!=1 || !user.children.empty() || vless.users.size()>=64 ||
                            std::ranges::any_of(vless.users,[&](auto const& existing) { return existing.name==*user_name; }))
                            return error("invalid or duplicate vless user");
                        vless.users.push_back({*user_name,*path});
                    }
                    if (vless.users.empty()) return error("vless requires at least one user");
                    auth_seen=true;
                } else if (child.name == "tls" && *type == "vless") {
                    if (tls_seen || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid vless tls");
                    for (auto const& field : child.children) {
                        auto path=scalar(field);
                        if (!path || !absolute_path(*path)) return error("vless tls requires absolute file paths");
                        if (field.name=="certificate-file" && vless.certificate_file.empty()) vless.certificate_file=*path;
                        else if (field.name=="private-key-file" && vless.private_key_file.empty()) vless.private_key_file=*path;
                        else return error("unsupported or duplicate vless tls field");
                    }
                    if (vless.certificate_file.empty() || vless.private_key_file.empty()) return error("vless tls requires certificate and private key");
                    tls_seen=true;
                } else if (child.name == "authentication") {
                    auto mode = argument(child);
                    if (auth_seen || !mode || !child.children.empty()) return error("invalid authentication");
                    if (*mode == "none" && child.properties.empty()) {
                        // Explicit unauthenticated mode.
                    } else if (*mode == "password" && *type == "socks5" && child.properties.size() == 2) {
                        auto username = text_property(child, "username");
                        auto path = text_property(child, "password-file");
                        auto valid_user = username && !username->empty() && username->size() <= 255 &&
                            std::all_of(username->begin(), username->end(), [](unsigned char c) { return c >= 32 && c <= 126; });
                        if (!valid_user || !path || path->empty() || path->front() != '/' || path->find('\0') != path->npos)
                            return error("password authentication requires username and absolute password-file");
                        result.password_auth = PasswordAuth{*username, *path};
                    } else return error("unsupported authentication for inbound");
                    auth_seen = true;
                } else return error("unsupported inbound node: " + child.name);
            }
            if (!listen_seen || (*type=="shadowsocks" ? ss.method.empty() || ss.key_file.empty() || auth_seen : !auth_seen) || (*type=="vless" && !tls_seen)) return error("inbound is missing required fields");
            result.inbound = *type == "mixed" ? Inbound::mixed : *type == "vless" ? Inbound::vless : *type=="shadowsocks" ? Inbound::shadowsocks : Inbound::socks5;
            if (*type=="vless") result.vless_inbound=std::move(vless);
            if (*type=="shadowsocks") result.shadowsocks_inbound=std::move(ss);
            return port;
        }
