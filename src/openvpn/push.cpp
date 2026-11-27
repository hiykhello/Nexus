module openvpn.wire;
import std;
import platform.ip_address;
import corosio;

namespace openvpn {
    namespace {
        auto split_ws(std::string_view sv) -> std::vector<std::string_view> {
            std::vector<std::string_view> out;
            std::size_t i = 0;
            while (i < sv.size()) {
                while (i < sv.size() && (sv[i] == ' ' || sv[i] == '\t')) ++i;
                auto s = i;
                while (i < sv.size() && sv[i] != ' ' && sv[i] != '\t') ++i;
                if (i > s) out.push_back(sv.substr(s, i - s));
            }
            return out;
        }

        auto eq_icase(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                unsigned char ca = static_cast<unsigned char>(a[i]);
                unsigned char cb = static_cast<unsigned char>(b[i]);
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                if (ca != cb) return false;
            }
            return true;
        }

        auto parse_v4(std::string_view text) -> std::optional<std::array<std::uint8_t, 4>> {
            auto ip = platform::parse_ip_address(text);
            if (!ip || ip->size != 4) return std::nullopt;
            std::array<std::uint8_t, 4> out{};
            std::ranges::copy(ip->view(), out.begin());
            return out;
        }

        auto parse_v6(std::string_view text) -> std::optional<std::array<std::uint8_t, 16>> {
            auto ip = platform::parse_ip_address(text);
            if (!ip || ip->size != 16) return std::nullopt;
            std::array<std::uint8_t, 16> out{};
            std::ranges::copy(ip->view(), out.begin());
            return out;
        }

        auto format_v4(std::array<std::uint8_t, 4> const& ip) -> std::string {
            corosio::ipv4_address::bytes_type b{};
            std::ranges::copy(ip, b.begin());
            return corosio::ipv4_address(b).to_string();
        }

        auto format_v6(std::array<std::uint8_t, 16> const& ip) -> std::string {
            return corosio::ipv6_address(ip).to_string();
        }

        auto parse_u32(std::string_view s) noexcept -> std::optional<std::uint32_t> {
            std::uint32_t v = 0;
            auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            if (ec != std::errc{} || end != s.data() + s.size()) return std::nullopt;
            return v;
        }

        auto mask_from_prefix_v4(unsigned prefix) noexcept -> std::array<std::uint8_t, 4> {
            std::uint32_t m = prefix == 0 ? 0u : (~std::uint32_t{0} << (32u - prefix));
            return {static_cast<std::uint8_t>(m >> 24), static_cast<std::uint8_t>(m >> 16),
                    static_cast<std::uint8_t>(m >> 8), static_cast<std::uint8_t>(m)};
        }
    }

    auto parse_push_reply(std::string_view text) -> std::expected<PushConfig, std::string> {
        while (!text.empty() && (text.back() == '\0' || text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
            text.remove_suffix(1);
        if (text != "PUSH_REPLY" && !text.starts_with("PUSH_REPLY,")) return std::unexpected("expected PUSH_REPLY");
        PushConfig cfg;
        std::size_t pos = 10;
        while (pos < text.size()) {
            if (text[pos] == ',') ++pos;
            auto next = text.find(',', pos);
            auto item = (next == std::string_view::npos) ? text.substr(pos) : text.substr(pos, next - pos);
            pos = (next == std::string_view::npos) ? text.size() : next;
            auto toks = split_ws(item);
            if (toks.empty()) continue;

            if (toks[0] == "ifconfig" && toks.size() >= 3) {
                auto ip = parse_v4(toks[1]);
                if (!ip) return std::unexpected("invalid PUSH_REPLY IPv4 address");
                cfg.local_v4 = *ip;
                if (auto mask = parse_v4(toks[2])) cfg.netmask_v4 = *mask;
            } else if (toks[0] == "ifconfig-ipv6" && toks.size() >= 2) {
                auto addr = toks[1];
                std::uint8_t pfx = 64;
                if (auto slash = addr.find('/'); slash != std::string_view::npos) {
                    auto p = parse_u32(addr.substr(slash + 1));
                    if (!p || *p > 128) return std::unexpected("invalid PUSH_REPLY IPv6 prefix");
                    pfx = static_cast<std::uint8_t>(*p);
                    addr = addr.substr(0, slash);
                }
                auto ip = parse_v6(addr);
                if (!ip) return std::unexpected("invalid PUSH_REPLY IPv6 address");
                cfg.local_v6 = *ip;
                cfg.prefix_v6 = pfx;
                if (toks.size() >= 3) {
                    if (auto gw = parse_v6(toks[2])) cfg.gateway_v6 = *gw;
                }
            } else if (toks[0] == "route-gateway" && toks.size() >= 2) {
                if (auto gw = parse_v4(toks[1])) cfg.gateway_v4 = *gw;
            } else if (toks[0] == "route" && toks.size() >= 2) {
                RouteV4 r{};
                auto net_str = toks[1];
                if (auto slash = net_str.find('/'); slash != std::string_view::npos) {
                    auto p = parse_u32(net_str.substr(slash + 1));
                    if (!p || *p > 32) return std::unexpected("invalid PUSH_REPLY route prefix");
                    r.netmask = mask_from_prefix_v4(*p);
                    net_str = net_str.substr(0, slash);
                }
                auto net = parse_v4(net_str);
                if (!net) return std::unexpected("invalid PUSH_REPLY route network");
                r.network = *net;
                if (toks.size() >= 3) {
                    if (auto mask = parse_v4(toks[2])) r.netmask = *mask;
                }
                if (toks.size() >= 4) {
                    if (auto gw = parse_v4(toks[3])) r.gateway = *gw;
                }
                cfg.routes_v4.push_back(r);
            } else if (toks[0] == "route-ipv6" && toks.size() >= 2) {
                auto cidr = toks[1];
                std::uint8_t pfx = 128;
                if (auto slash = cidr.find('/'); slash != std::string_view::npos) {
                    auto p = parse_u32(cidr.substr(slash + 1));
                    if (!p || *p > 128) return std::unexpected("invalid PUSH_REPLY route-ipv6 prefix");
                    pfx = static_cast<std::uint8_t>(*p);
                    cidr = cidr.substr(0, slash);
                }
                auto net = parse_v6(cidr);
                if (!net) return std::unexpected("invalid PUSH_REPLY route-ipv6 network");
                RouteV6 r{*net, pfx, std::nullopt};
                if (toks.size() >= 3) {
                    if (auto gw = parse_v6(toks[2])) r.gateway = *gw;
                }
                cfg.routes_v6.push_back(r);
            } else if (toks[0] == "redirect-gateway") {
                cfg.redirect_gateway = true;
                for (std::size_t i = 1; i < toks.size(); ++i) {
                    if (eq_icase(toks[i], "ipv6")) cfg.redirect_gateway_v6 = true;
                }
            } else if (toks[0] == "dhcp-option" && toks.size() >= 3) {
                if (eq_icase(toks[1], "DNS")) {
                    cfg.dns_servers.emplace_back(toks[2]);
                } else if (eq_icase(toks[1], "DOMAIN") || eq_icase(toks[1], "DOMAIN-SEARCH")) {
                    cfg.search_domains.emplace_back(toks[2]);
                }
            } else if (toks[0] == "topology" && toks.size() >= 2) {
                if (eq_icase(toks[1], "subnet")) cfg.topology_subnet = true;
            } else if (toks[0] == "peer-id" && toks.size() >= 2) {
                auto pid = parse_u32(toks[1]);
                if (!pid || *pid > 0xffffffu) return std::unexpected("invalid PUSH_REPLY peer-id");
                cfg.peer_id = *pid;
            } else if (toks[0] == "cipher" && toks.size() >= 2) {
                if (eq_icase(toks[1], "AES-256-GCM")) cfg.cipher = Cipher::aes_256_gcm;
                else if (eq_icase(toks[1], "CHACHA20-POLY1305")) cfg.cipher = Cipher::chacha20_poly1305;
                else return std::unexpected("unsupported PUSH_REPLY cipher");
            } else if (toks[0] == "tun-mtu" && toks.size() >= 2) {
                auto mtu = parse_u32(toks[1]);
                if (!mtu || *mtu < 576 || *mtu > 9000) return std::unexpected("invalid PUSH_REPLY tun-mtu");
                cfg.mtu = static_cast<std::uint16_t>(*mtu);
            } else if (toks[0] == "ping" && toks.size() >= 2) {
                if (auto v = parse_u32(toks[1]); v && *v <= 65535) cfg.ping_s = static_cast<std::uint16_t>(*v);
            } else if (toks[0] == "ping-restart" && toks.size() >= 2) {
                if (auto v = parse_u32(toks[1]); v && *v <= 65535) cfg.ping_restart_s = static_cast<std::uint16_t>(*v);
            }
        }
        return cfg;
    }

    auto encode_push_reply(PushConfig const& cfg) -> std::string {
        std::string out = "PUSH_REPLY";
        if (cfg.topology_subnet) out += ",topology subnet";
        if (cfg.gateway_v4) out += std::format(",route-gateway {}", format_v4(*cfg.gateway_v4));
        if (cfg.local_v4) {
            auto mask = cfg.netmask_v4.value_or(std::array<std::uint8_t, 4>{255, 255, 255, 0});
            out += std::format(",ifconfig {} {}", format_v4(*cfg.local_v4), format_v4(mask));
        }
        if (cfg.local_v6) {
            out += std::format(",ifconfig-ipv6 {}/{}", format_v6(*cfg.local_v6), cfg.prefix_v6);
            if (cfg.gateway_v6) out += std::format(" {}", format_v6(*cfg.gateway_v6));
        }
        if (cfg.redirect_gateway) {
            out += cfg.redirect_gateway_v6 ? ",redirect-gateway def1 ipv6" : ",redirect-gateway def1";
        }
        for (auto const& r : cfg.routes_v4) {
            out += std::format(",route {} {}", format_v4(r.network), format_v4(r.netmask));
            if (r.gateway) out += std::format(" {}", format_v4(*r.gateway));
        }
        for (auto const& r : cfg.routes_v6) {
            out += std::format(",route-ipv6 {}/{}", format_v6(r.network), r.prefix_len);
            if (r.gateway) out += std::format(" {}", format_v6(*r.gateway));
        }
        auto safe_tok = [](std::string_view s) noexcept -> bool {
            if (s.empty()) return false;
            return std::ranges::none_of(s, [](char c) { return c == ',' || c == '\r' || c == '\n' || c == '\0'; });
        };
        for (auto const& dns : cfg.dns_servers) if (safe_tok(dns)) out += std::format(",dhcp-option DNS {}", dns);
        for (auto const& dom : cfg.search_domains) if (safe_tok(dom)) out += std::format(",dhcp-option DOMAIN {}", dom);
        if (cfg.mtu) out += std::format(",tun-mtu {}", *cfg.mtu);
        if (cfg.ping_s) out += std::format(",ping {}", *cfg.ping_s);
        if (cfg.ping_restart_s) out += std::format(",ping-restart {}", *cfg.ping_restart_s);
        if (cfg.peer_id) out += std::format(",peer-id {}", *cfg.peer_id);
        if (cfg.cipher) {
            out += ",cipher ";
            out += (*cfg.cipher == Cipher::chacha20_poly1305) ? "CHACHA20-POLY1305" : "AES-256-GCM";
        }
        return out;
    }
}
