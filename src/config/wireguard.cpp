module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    namespace g = ::glaze;
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;
    auto parse_tcp_dial_option(g::KdlNode const&,TcpSocketOptions&) -> std::expected<bool,std::string>;

    namespace {
        using namespace config::kdl;

        auto b64_val(unsigned char c) noexcept -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        }

        auto decode_reserved_b64(std::string_view text) -> std::optional<std::array<std::uint8_t, 3>> {
            if (text.size() != 4) return std::nullopt;
            int a = b64_val(static_cast<unsigned char>(text[0]));
            int b = b64_val(static_cast<unsigned char>(text[1]));
            int c = b64_val(static_cast<unsigned char>(text[2]));
            int d = b64_val(static_cast<unsigned char>(text[3]));
            if (a < 0 || b < 0 || c < 0 || d < 0) return std::nullopt;
            std::uint32_t v = (std::uint32_t(a) << 18) | (std::uint32_t(b) << 12) | (std::uint32_t(c) << 6) | std::uint32_t(d);
            return std::array<std::uint8_t, 3>{
                static_cast<std::uint8_t>((v >> 16) & 0xffu),
                static_cast<std::uint8_t>((v >> 8) & 0xffu),
                static_cast<std::uint8_t>(v & 0xffu)};
        }

        auto parse_endpoint(Node const& child, std::string& host, std::uint16_t& port) -> std::expected<void, std::string> {
            auto h = text_property(child, "host");
            auto p = property(child, "port");
            auto pv = p ? integer(*p) : std::nullopt;
            if (child.tag || !child.arguments.empty() || !child.children.empty() ||
                child.properties.size() != 2 || !h || !endpoint_name(*h) || !pv || !*pv || *pv > 65535)
                return error("WireGuard server requires host and port 1..65535");
            host = *h; port = static_cast<std::uint16_t>(*pv);
            return {};
        }

        auto strip_cidr(std::string_view text) -> std::optional<std::string_view> {
            auto slash = text.find('/');
            if (slash == std::string_view::npos) return text;
            auto ps = text.substr(slash + 1);
            unsigned pfx = 0;
            auto [end, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), pfx);
            if (ec != std::errc{} || end != ps.data() + ps.size()) return std::nullopt;
            auto ip = text.substr(0, slash);
            bool v6 = ip.find(':') != std::string_view::npos;
            if (pfx > (v6 ? 128u : 32u)) return std::nullopt;
            return ip;
        }
    }

    auto parse_wireguard_outbound(Node const& node) -> std::expected<WireGuardOutbound, std::string> {
        WireGuardOutbound cfg;
        bool server = false, priv = false, pub = false, psk = false, v4_seen = false, v6_seen = false;
        bool mtu_seen = false, ka_seen = false, res_seen = false, to_seen = false;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                if (server) return error("duplicate WireGuard server");
                if (auto ok = parse_endpoint(child, cfg.host, cfg.port); !ok) return std::unexpected(ok.error());
                server = true;
            } else if (child.name == "private-key-file") {
                auto v = scalar(child);
                if (priv || !v || !absolute_path(*v)) return error("WireGuard private-key-file must be absolute");
                cfg.private_key_file = *v; priv = true;
            } else if (child.name == "peer-public-key-file") {
                auto v = scalar(child);
                if (pub || !v || !absolute_path(*v)) return error("WireGuard peer-public-key-file must be absolute");
                cfg.peer_public_key_file = *v; pub = true;
            } else if (child.name == "preshared-key-file") {
                auto v = scalar(child);
                if (psk || !v || !absolute_path(*v)) return error("WireGuard preshared-key-file must be absolute");
                cfg.preshared_key_file = *v; psk = true;
            } else if (child.name == "local-address") {
                auto v = scalar(child);
                auto ip = v ? strip_cidr(*v) : std::nullopt;
                if (!ip) return error("invalid WireGuard local-address");
                if (auto a4 = dns_ipv4(*ip)) {
                    if (v4_seen) return error("duplicate WireGuard IPv4 local-address");
                    cfg.local_v4 = *a4; cfg.has_v4 = true; v4_seen = true;
                } else if (auto a6 = dns_ipv6(*ip)) {
                    if (v6_seen) return error("duplicate WireGuard IPv6 local-address");
                    cfg.local_v6 = *a6; cfg.has_v6 = true; v6_seen = true;
                } else return error("invalid WireGuard local-address");
            } else if (child.name == "reserved") {
                if (res_seen || child.tag || !child.properties.empty() || !child.children.empty())
                    return error("invalid WireGuard reserved");
                if (child.arguments.size() == 1 && !child.arguments[0].tag) {
                    auto* s = std::get_if<std::string>(&child.arguments[0].data);
                    auto b = s ? decode_reserved_b64(*s) : std::nullopt;
                    if (!b) return error("WireGuard reserved string must be 4-char base64");
                    cfg.reserved = *b; cfg.warp = true; res_seen = true;
                } else if (child.arguments.size() == 3) {
                    for (std::size_t i = 0; i < 3; ++i) {
                        auto v = child.arguments[i].tag ? std::nullopt : integer(child.arguments[i]);
                        if (!v || *v > 255) return error("WireGuard reserved bytes must be 0..255");
                        cfg.reserved[i] = static_cast<std::uint8_t>(*v);
                    }
                    cfg.warp = true; res_seen = true;
                } else return error("WireGuard reserved requires 3 integers or 1 base64 string");
            } else if (child.name == "mtu") {
                auto v = integer(child);
                if (mtu_seen || !v || *v < 68 || *v > 1500) return error("WireGuard mtu must be 68..1500");
                cfg.mtu = static_cast<std::uint16_t>(*v); mtu_seen = true;
            } else if (child.name == "persistent-keepalive") {
                auto v = integer(child);
                if (ka_seen || !v || *v > 65535) return error("WireGuard persistent-keepalive must be 0..65535");
                cfg.keepalive_s = static_cast<std::uint16_t>(*v); ka_seen = true;
            } else if (child.name == "connect-timeout-ms") {
                auto v = connect_timeout(child);
                if (to_seen || !v) return error("invalid WireGuard connect-timeout-ms");
                cfg.connect_timeout_ms = *v; to_seen = true;
            } else if (child.name == "bootstrap-resolver" || child.name=="domain-resolver") {
                auto v = scalar(child);
                if (cfg.bootstrap_resolver || !v || !valid_name(*v)) return error("invalid WireGuard bootstrap-resolver");
                cfg.bootstrap_resolver = *v;
            } else if (child.name == "detour") {
                auto v = scalar(child);
                if (cfg.detour || !v || !valid_name(*v)) return error("invalid WireGuard detour");
                cfg.detour = *v;
            } else {
                auto opt = parse_tcp_dial_option(child, cfg.tcp_options);
                if (!opt) return std::unexpected(opt.error());
                if (!*opt) return error("unsupported WireGuard outbound field: " + child.name);
            }
        }
        if (!server || !priv || !pub)
            return error("WireGuard outbound requires server, private-key-file and peer-public-key-file");
        if (cfg.tcp_options.tcp_configured()) return error("TCP-only dial options are not valid for WireGuard");
        if (!v4_seen && v6_seen) cfg.has_v4 = false;
        return cfg;
    }
}
