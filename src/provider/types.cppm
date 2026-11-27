export module provider.types;
import std;
import rules.regex;

export namespace provider {
    struct SubscriptionUserinfo {
        std::optional<std::uint64_t> upload;
        std::optional<std::uint64_t> download;
        std::optional<std::uint64_t> total;
        std::optional<std::uint64_t> expire;
        auto operator==(SubscriptionUserinfo const&) const -> bool = default;
    };

    enum class ProxyProtocol {
        vless, trojan, shadowsocks, hysteria2, tuic, anytls,
        snell, naive, ssh, socks5, http_connect, wireguard
    };

    enum class ProviderFormat {
        auto_detect, uri_list, base64_uri, clash_yaml, singbox_json, sip008_json
    };

    struct ParsedProxy {
        std::string tag;
        ProxyProtocol protocol = ProxyProtocol::vless;
        std::string host;
        std::uint16_t port = 0;
        std::string username, secret, method;
        std::string sni, ca_file, certificate_sha256, fingerprint;
        std::vector<std::string> alpn;
        bool tls_enabled = true;
        bool skip_cert_verify = false;
        std::string transport, path, host_header, service_name, xhttp_mode, flow;
        std::string reality_public_key, reality_short_id;
        bool udp = true, uot = false;
        std::string obfs, obfs_password;
        std::string hy2_ports;
        std::uint32_t hy2_hop_interval_ms = 0, hy2_up_mbps = 0, hy2_down_mbps = 0;
        std::string congestion_control, udp_relay_mode;
        int snell_version = 5;
        std::string naive_protocol = "h2";
        bool padding = true;
        bool mux_enabled = false;
        std::string mux_protocol = "h2mux";
        std::string detour;
        std::string wg_private_key, wg_peer_public_key, wg_preshared_key;
        std::string wg_local_ipv4, wg_local_ipv6;
        std::uint16_t wg_mtu = 1420;
        std::array<std::uint8_t, 3> wg_reserved{};
    };

    struct ProviderFilter {
        std::string include_regex, exclude_regex, tag_prefix, detour, ca_file;
        std::vector<std::string> include_regexes, exclude_regexes;
        auto operator==(ProviderFilter const&) const -> bool = default;
    };

    // Compiles a provider include/exclude regex up to 4096 bytes into bounded Thompson NFAs
    // (splitting long top-level '|' alternations into <=255B / <=192-state chunks while preserving ReDoS bounds).
    [[nodiscard]] inline auto compile_filter_regex(std::string_view pattern)
        -> std::expected<std::vector<rules::BoundedRegex>, std::string> {
        if (pattern.empty() || pattern.size() > 4096 || pattern.contains('\0'))
            return std::unexpected("invalid regular expression");
        if (pattern.size() <= 255) {
            if (auto r = rules::BoundedRegex::compile(pattern)) {
                std::vector<rules::BoundedRegex> out;
                out.push_back(std::move(*r));
                return out;
            }
        }
        auto unescaped = [](std::string_view s, std::size_t pos) noexcept -> bool {
            std::size_t bs = 0;
            while (pos > bs && s[pos - 1 - bs] == '\\') ++bs;
            return (bs % 2) == 0;
        };
        auto wraps_whole_group = [&](std::string_view s) noexcept -> bool {
            if (s.size() < 2 || s.front() != '(' || s.back() != ')') return false;
            int depth = 0;
            bool in_class = false;
            for (std::size_t i = 0; i < s.size(); ++i) {
                char c = s[i];
                if (c == '\\' && i + 1 < s.size()) { ++i; continue; }
                if (in_class) { if (c == ']') in_class = false; continue; }
                if (c == '[') { in_class = true; continue; }
                if (c == '(') ++depth;
                else if (c == ')') {
                    --depth;
                    if (depth == 0) return i + 1 == s.size();
                    if (depth < 0) return false;
                }
            }
            return false;
        };
        std::string prefix, suffix;
        std::string_view body = pattern;
        bool const lead = body.starts_with('^');
        bool const trail = !body.empty() && body.back() == '$' && unescaped(body, body.size() - 1);
        auto inner = body.substr(lead ? 1 : 0, body.size() - (lead ? 1 : 0) - (trail ? 1 : 0));
        if (wraps_whole_group(inner)) {
            prefix = lead ? "^(" : "(";
            suffix = trail ? ")$" : ")";
            body = inner.substr(1, inner.size() - 2);
        }
        std::vector<std::string_view> branches;
        {
            int depth = 0;
            bool in_class = false;
            std::size_t start = 0;
            for (std::size_t i = 0; i < body.size(); ++i) {
                char c = body[i];
                if (c == '\\' && i + 1 < body.size()) { ++i; continue; }
                if (in_class) { if (c == ']') in_class = false; continue; }
                if (c == '[') { in_class = true; continue; }
                if (c == '(') ++depth;
                else if (c == ')') { if (--depth < 0) return std::unexpected("invalid regular expression"); }
                else if (c == '|' && depth == 0) {
                    branches.push_back(body.substr(start, i - start));
                    start = i + 1;
                }
            }
            if (in_class || depth != 0) return std::unexpected("invalid regular expression");
            branches.push_back(body.substr(start));
        }
        if (branches.size() < 2)
            return std::unexpected("regular expression exceeds bounded NFA limit");
        std::vector<rules::BoundedRegex> out;
        std::string cur_body;
        std::optional<rules::BoundedRegex> cur_re;
        for (auto b : branches) {
            if (b.empty()) return std::unexpected("invalid empty regex alternation branch");
            std::string cand = prefix;
            if (!cur_body.empty()) { cand.append(cur_body); cand.push_back('|'); }
            cand.append(b);
            cand.append(suffix);
            if (cand.size() <= 255) {
                if (auto r = rules::BoundedRegex::compile(cand)) {
                    if (!cur_body.empty()) cur_body.push_back('|');
                    cur_body.append(b);
                    cur_re = std::move(*r);
                    continue;
                }
            }
            if (cur_re) {
                if (out.size() >= 64) return std::unexpected("regular expression exceeds chunk limit");
                out.push_back(std::move(*cur_re));
                cur_body.clear();
                cur_re.reset();
            }
            std::string single = prefix;
            single.append(b);
            single.append(suffix);
            auto r = rules::BoundedRegex::compile(single);
            if (!r) return std::unexpected(std::string(r.error()));
            cur_body.assign(b);
            cur_re = std::move(*r);
        }
        if (cur_re) {
            if (out.size() >= 64) return std::unexpected("regular expression exceeds chunk limit");
            out.push_back(std::move(*cur_re));
        }
        return out;
    }

    struct ParsedGroup {
        std::string name;
        std::string type = "selector";
        std::vector<std::string> members, use_providers;
        std::string probe_url = "https://www.gstatic.com/generate_204";
        std::uint32_t interval_ms = 300000;
        std::uint32_t tolerance_ms = 50;
    };

    struct ParsedRule {
        std::string kind, value, target;
        bool invert = false;
    };

    struct ParsedDocument {
        ProviderFormat detected_format = ProviderFormat::auto_detect;
        std::vector<ParsedProxy> proxies;
        std::vector<ParsedGroup> groups;
        std::vector<ParsedRule> rules;
        std::vector<std::string> dns_servers;
        std::string default_outbound = "direct";
        std::uint16_t inbound_port = 7890;
        std::string inbound_type = "mixed";
        std::vector<std::string> warnings;
    };

    struct ConvertOptions {
        ProviderFormat format = ProviderFormat::auto_detect;
        std::string secrets_dir;
        bool inline_placeholders = false;
        std::string inbound_listen = "127.0.0.1:7890";
        std::string inbound_type = "mixed";
        std::string default_group;
        std::string ca_file;
        ProviderFilter filter;
    };
}
