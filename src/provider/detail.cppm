module provider:detail;
import std;
import encoding.base64;
import encoding.hex;
import platform.ip_address;
import rules.regex;
import provider.types;

namespace provider::detail {
    inline auto trim(std::string_view s) noexcept -> std::string_view {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
        return s;
    }

    inline auto lower_ascii(std::string_view s) -> std::string {
        std::string out(s);
        for (auto& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        return out;
    }

    inline auto hex_val(char c) noexcept -> int {
        return encoding::hex_value(c);
    }

    inline auto hex_encode(std::span<std::uint8_t const> bytes) -> std::string {
        return encoding::hex_encode(bytes);
    }

    inline auto percent_decode(std::string_view in) -> std::string {
        std::string out;
        out.reserve(in.size());
        for (std::size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '%' && i + 2 < in.size()) {
                int hi = hex_val(in[i + 1]), lo = hex_val(in[i + 2]);
                if (hi >= 0 && lo >= 0) {
                    out.push_back(static_cast<char>((hi << 4) | lo));
                    i += 2;
                    continue;
                }
            }
            out.push_back(in[i]);
        }
        return out;
    }

    inline auto base64_decode(std::string_view in) -> std::optional<std::string> {
        return encoding::decode_base64_flexible(in);
    }

    inline auto split_host_port(std::string_view hp) -> std::expected<std::pair<std::string, std::uint16_t>, std::string> {
        auto parsed = platform::split_host_port(hp);
        if (!parsed) return std::unexpected("invalid host:port");
        return std::pair{std::string(parsed->host), parsed->port};
    }

    inline auto sanitize_tag(std::string_view raw, std::string_view fallback) -> std::string {
        std::string out;
        for (unsigned char c : raw) {
            if (std::isalnum(c) || c == '-' || c == '_') out.push_back(static_cast<char>(c));
            else if (c == ' ' || c == '.' || c == '+' || c == '/') out.push_back('-');
        }
        while (!out.empty() && out.front() == '-') out.erase(out.begin());
        while (!out.empty() && out.back() == '-') out.pop_back();
        if (out.empty()) out = std::string(fallback);
        if (out.size() > 64) out.resize(64);
        if (out == "direct" || out == "block") out += "-node";
        return out;
    }

    inline auto kdl_escape(std::string_view s) -> std::string {
        std::string out;
        out.reserve(s.size() + 2);
        out.push_back('"');
        for (char c : s) {
            if (c == '\\' || c == '"') out.push_back('\\');
            if (c != '\r' && c != '\n' && c != '\0') out.push_back(c);
        }
        out.push_back('"');
        return out;
    }

    inline auto normalize_reality_pbk(std::string_view pbk) -> std::optional<std::string> {
        if (pbk.size() == 64 && std::ranges::all_of(pbk, [](char c) { return hex_val(c) >= 0; }))
            return lower_ascii(pbk);
        if (auto raw = base64_decode(pbk); raw && raw->size() == 32)
            return hex_encode({reinterpret_cast<std::uint8_t const*>(raw->data()), raw->size()});
        return std::nullopt;
    }

    struct YamlVal {
        enum class Kind { null_v, bool_v, int_v, str_v, arr_v, map_v } kind = Kind::null_v;
        bool bval = false;
        std::int64_t ival = 0;
        std::string sval;
        std::vector<YamlVal> arr;
        std::vector<std::pair<std::string, YamlVal>> map;

        [[nodiscard]] auto get(std::string_view key) const noexcept -> YamlVal const*;
        auto set(std::string key, YamlVal val) -> void;
        [[nodiscard]] auto as_str() const -> std::string;
        [[nodiscard]] auto as_int() const -> std::optional<std::int64_t>;
        [[nodiscard]] auto as_bool(bool def = false) const noexcept -> bool;
    };

    inline auto protocol_kdl_name(ProxyProtocol p) noexcept -> std::string_view {
        switch (p) {
        case ProxyProtocol::vless: return "vless";
        case ProxyProtocol::trojan: return "trojan";
        case ProxyProtocol::shadowsocks: return "shadowsocks";
        case ProxyProtocol::hysteria2: return "hysteria2";
        case ProxyProtocol::tuic: return "tuic";
        case ProxyProtocol::anytls: return "anytls";
        case ProxyProtocol::snell: return "snell";
        case ProxyProtocol::naive: return "naive";
        case ProxyProtocol::ssh: return "ssh";
        case ProxyProtocol::socks5: return "socks5";
        case ProxyProtocol::http_connect: return "http-connect";
        case ProxyProtocol::wireguard: return "wireguard";
        }
        return "vless";
    }

    inline auto json_escape(std::string_view s) -> std::string {
        std::string out;
        out.reserve(s.size() + 2);
        out.push_back('"');
        auto is_cont = [](unsigned char b) noexcept { return (b & 0xC0u) == 0x80u; };
        for (std::size_t i = 0; i < s.size();) {
            auto c = static_cast<unsigned char>(s[i]);
            if (c < 0x80u) {
                switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20u) out += std::format("\\u{:04x}", unsigned(c));
                    else out.push_back(static_cast<char>(c));
                    break;
                }
                ++i;
            } else if (c >= 0xC2u && c <= 0xDFu && i + 1 < s.size() &&
                       is_cont(static_cast<unsigned char>(s[i + 1]))) {
                out.append(s.data() + i, 2);
                i += 2;
            } else if (c >= 0xE0u && c <= 0xEFu && i + 2 < s.size()) {
                auto b1 = static_cast<unsigned char>(s[i + 1]);
                auto b2 = static_cast<unsigned char>(s[i + 2]);
                bool ok = is_cont(b1) && is_cont(b2) && !(c == 0xE0u && b1 < 0xA0u) && !(c == 0xEDu && b1 >= 0xA0u);
                if (ok) { out.append(s.data() + i, 3); i += 3; }
                else { out += "\\ufffd"; ++i; }
            } else if (c >= 0xF0u && c <= 0xF4u && i + 3 < s.size()) {
                auto b1 = static_cast<unsigned char>(s[i + 1]);
                auto b2 = static_cast<unsigned char>(s[i + 2]);
                auto b3 = static_cast<unsigned char>(s[i + 3]);
                bool ok = is_cont(b1) && is_cont(b2) && is_cont(b3) && !(c == 0xF0u && b1 < 0x90u) && !(c == 0xF4u && b1 >= 0x90u);
                if (ok) { out.append(s.data() + i, 4); i += 4; }
                else { out += "\\ufffd"; ++i; }
            } else {
                out += "\\ufffd";
                ++i;
            }
        }
        out.push_back('"');
        return out;
    }

    struct StagedSecret {
        std::string unique;
        std::string path;
        std::string content;
    };

    [[nodiscard]] auto stage_provider_secret(ConvertOptions const& opts,
        std::set<std::string> const& committed_secrets, std::set<std::string>& pending_secrets,
        std::vector<StagedSecret>& staged, std::string_view hint, std::string_view content)
        -> std::expected<std::string, std::string>;

    [[nodiscard]] auto commit_provider_secrets(ConvertOptions const& opts,
        std::set<std::string>& committed_secrets, std::vector<StagedSecret> const& staged,
        std::vector<std::string>* written_paths = nullptr)
        -> std::expected<void, std::string>;

    [[nodiscard]] auto parse_yaml_dom(std::string_view body) -> std::expected<YamlVal, std::string>;
    [[nodiscard]] auto parse_uri_list(std::string_view body, bool was_base64)
        -> std::expected<ParsedDocument, std::string>;
    [[nodiscard]] auto parse_clash_yaml(std::string_view body)
        -> std::expected<ParsedDocument, std::string>;
    [[nodiscard]] auto parse_singbox_or_sip008(std::string_view body, ProviderFormat hint)
        -> std::expected<ParsedDocument, std::string>;
}
