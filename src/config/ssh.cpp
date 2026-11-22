module config;
import std;
import nexus.thirdparty.glaze;
import config.kdl_common;

namespace config {
    namespace g = nex::glaze;
    auto parse_tcp_dial_option(g::KdlNode const&, TcpSocketOptions&) -> std::expected<bool, std::string>;

    namespace {
        using namespace config::kdl;

        auto b64_idx(unsigned char c) noexcept -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        }

        auto parse_ssh_sha256_pin(std::string_view text) -> std::optional<std::array<std::uint8_t, 32>> {
            if (text.starts_with("SHA256:") || text.starts_with("sha256:")) {
                auto b = text.substr(7);
                std::vector<std::uint8_t> out;
                std::uint32_t acc = 0;
                int bits = 0;
                bool pad = false;
                for (unsigned char c : b) {
                    if (c == '=') { pad = true; continue; }
                    if (pad) return {};
                    int v = b64_idx(c);
                    if (v < 0) return {};
                    acc = (acc << 6) | static_cast<std::uint32_t>(v);
                    bits += 6;
                    if (bits >= 8) {
                        bits -= 8;
                        out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xffu));
                    }
                }
                if (out.size() != 32 || bits >= 6 || (bits > 0 && (acc & ((1u << bits) - 1u)) != 0)) return {};
                std::array<std::uint8_t, 32> fp{};
                std::ranges::copy(out, fp.begin());
                return fp;
            }
            if (text.size() != 64 && text.size() != 95) return {};
            std::array<std::uint8_t, 32> fp{};
            auto stride = text.size() == 64 ? 2u : 3u;
            for (std::size_t i = 0; i < fp.size(); ++i) {
                auto p = text.data() + i * stride;
                auto [end, ec] = std::from_chars(p, p + 2, fp[i], 16);
                if (ec != std::errc{} || end != p + 2 || (stride == 3 && i + 1 < fp.size() && p[2] != ':')) return {};
            }
            return fp;
        }
    }

    auto parse_ssh_outbound(Node const& node) -> std::expected<SshOutbound, std::string> {
        SshOutbound cfg;
        bool server = false, user = false, cipher = false, to = false, ka = false, maxs = false, tfo = false;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                auto h = text_property(child, "host");
                auto pv = property(child, "port");
                auto port = pv ? integer(*pv) : std::optional<std::uint64_t>{22};
                if (server || child.tag || !child.arguments.empty() || !child.children.empty() ||
                    child.properties.size() != 1u + bool(pv) || !h || !endpoint_name(*h) ||
                    !port || !*port || *port > 65535)
                    return error("SSH server requires host and optional port 1..65535");
                cfg.host = *h;
                cfg.port = static_cast<std::uint16_t>(*port);
                server = true;
            } else if (child.name == "user") {
                auto v = scalar(child);
                if (user || !v || v->empty() || v->size() > 128 || v->contains('\0'))
                    return error("invalid SSH user");
                cfg.user = *v;
                user = true;
            } else if (child.name == "password-file") {
                auto v = scalar(child);
                if (cfg.password_file || !v || !absolute_path(*v))
                    return error("SSH password-file must be an absolute path");
                cfg.password_file = *v;
            } else if (child.name == "private-key-file") {
                auto v = scalar(child);
                if (cfg.private_key_file || !v || !absolute_path(*v))
                    return error("SSH private-key-file must be an absolute path");
                cfg.private_key_file = *v;
            } else if (child.name == "host-key-sha256") {
                if (child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.empty() || child.arguments.size() > 16 - cfg.host_key_sha256.size())
                    return error("SSH host-key-sha256 requires 1..16 fingerprints");
                for (auto const& arg : child.arguments) {
                    auto t = string(arg);
                    auto fp = t ? parse_ssh_sha256_pin(*t) : std::nullopt;
                    if (!fp) return error("invalid SSH host-key-sha256 fingerprint");
                    cfg.host_key_sha256.push_back(*fp);
                }
            } else if (child.name == "cipher") {
                auto v = scalar(child);
                if (cipher || !v || (*v != "chacha20-poly1305@openssh.com" &&
                    *v != "aes256-gcm@openssh.com" && *v != "aes128-gcm@openssh.com"))
                    return error("invalid SSH cipher");
                cfg.cipher = *v;
                cipher = true;
            } else if (child.name == "connect-timeout-ms") {
                auto v = connect_timeout(child);
                if (to || !v) return error("invalid SSH connect-timeout-ms");
                cfg.connect_timeout_ms = *v;
                to = true;
            } else if (child.name == "keepalive-interval-ms") {
                auto v = integer(child);
                if (ka || !v || *v > 3600000) return error("SSH keepalive-interval-ms must be 0..3600000");
                cfg.keepalive_interval_ms = static_cast<std::uint32_t>(*v);
                ka = true;
            } else if (child.name == "max-sessions") {
                auto v = integer(child);
                if (maxs || !v || *v < 1 || *v > 256) return error("SSH max-sessions must be 1..256");
                cfg.max_sessions = static_cast<std::size_t>(*v);
                maxs = true;
            } else if (child.name == "tcp-fast-open") {
                auto v = boolean(child);
                if (tfo || !v) return error("SSH tcp-fast-open requires a boolean");
                cfg.tcp_fast_open = *v;
                tfo = true;
            } else if (child.name == "bootstrap-resolver" || child.name == "domain-resolver") {
                auto v = scalar(child);
                if (cfg.bootstrap_resolver || !v || !valid_name(*v)) return error("invalid SSH bootstrap-resolver");
                cfg.bootstrap_resolver = *v;
            } else if (child.name == "detour") {
                auto v = scalar(child);
                if (cfg.detour || !v || !valid_name(*v)) return error("invalid SSH detour");
                cfg.detour = *v;
            } else {
                auto opt = parse_tcp_dial_option(child, cfg.tcp_options);
                if (!opt) return std::unexpected(opt.error());
                if (!*opt) return error("unsupported SSH outbound field: " + child.name);
            }
        }
        if (!server || !user || cfg.host_key_sha256.empty() || (!cfg.password_file && !cfg.private_key_file))
            return error("SSH outbound requires server, user, host-key-sha256 and password-file or private-key-file");
        return cfg;
    }
}
