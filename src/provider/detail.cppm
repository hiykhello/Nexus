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

    [[nodiscard]] auto parse_yaml_dom(std::string_view body) -> std::expected<YamlVal, std::string>;
    [[nodiscard]] auto parse_uri_list(std::string_view body, bool was_base64)
        -> std::expected<ParsedDocument, std::string>;
    [[nodiscard]] auto parse_clash_yaml(std::string_view body)
        -> std::expected<ParsedDocument, std::string>;
    [[nodiscard]] auto parse_singbox_or_sip008(std::string_view body, ProviderFormat hint)
        -> std::expected<ParsedDocument, std::string>;
}
