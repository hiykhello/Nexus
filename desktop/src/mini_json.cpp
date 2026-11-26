module desktop.mini_json;

import std;

namespace desktop {
    namespace {
        constexpr int kMaxJsonDepth = 64;

        auto append_utf8_cp(std::string& out, std::uint32_t cp) -> void {
            if (cp <= 0x7Fu) {
                out.push_back(static_cast<char>(cp));
            } else if (cp <= 0x7FFu) {
                out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            } else if (cp <= 0xFFFFu) {
                out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            } else if (cp <= 0x10FFFFu) {
                out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            }
        }

        class Parser {
            std::string_view sv_;
            std::size_t pos_ = 0;

            auto skip_ws() noexcept -> void {
                while (pos_ < sv_.size()) {
                    char c = sv_[pos_];
                    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++pos_;
                    else break;
                }
            }

            auto peek() const noexcept -> char { return pos_ < sv_.size() ? sv_[pos_] : '\0'; }

            auto parse_hex4() -> std::expected<std::uint16_t, std::string> {
                if (pos_ + 4 > sv_.size()) return std::unexpected("truncated \\u escape");
                std::uint16_t val = 0;
                for (int i = 0; i < 4; ++i) {
                    char c = sv_[pos_++];
                    val <<= 4;
                    if (c >= '0' && c <= '9') val |= static_cast<std::uint16_t>(c - '0');
                    else if (c >= 'a' && c <= 'f') val |= static_cast<std::uint16_t>(10 + c - 'a');
                    else if (c >= 'A' && c <= 'F') val |= static_cast<std::uint16_t>(10 + c - 'A');
                    else return std::unexpected("invalid hex digit in \\u escape");
                }
                return val;
            }

            auto parse_string() -> std::expected<std::string, std::string> {
                if (peek() != '"') return std::unexpected("expected '\"'");
                ++pos_;
                std::string out;
                while (pos_ < sv_.size()) {
                    unsigned char uc = static_cast<unsigned char>(sv_[pos_++]);
                    if (uc == '"') return out;
                    if (uc < 0x20u) return std::unexpected("unescaped control character in JSON string");
                    if (uc != '\\') { out.push_back(static_cast<char>(uc)); continue; }
                    if (pos_ >= sv_.size()) return std::unexpected("unterminated escape sequence");
                    char esc = sv_[pos_++];
                    switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        auto hi = parse_hex4();
                        if (!hi) return std::unexpected(hi.error());
                        std::uint32_t cp = *hi;
                        if (cp >= 0xD800u && cp <= 0xDBFFu) {
                            if (pos_ + 2 > sv_.size() || sv_[pos_] != '\\' || sv_[pos_ + 1] != 'u') {
                                return std::unexpected("missing low surrogate");
                            }
                            pos_ += 2;
                            auto lo = parse_hex4();
                            if (!lo) return std::unexpected(lo.error());
                            if (*lo < 0xDC00u || *lo > 0xDFFFu) return std::unexpected("invalid low surrogate");
                            cp = 0x10000u + (((cp - 0xD800u) << 10) | (*lo - 0xDC00u));
                        } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                            return std::unexpected("unexpected lone low surrogate");
                        }
                        append_utf8_cp(out, cp);
                        break;
                    }
                    default: return std::unexpected("invalid JSON escape character");
                    }
                }
                return std::unexpected("unterminated JSON string");
            }

            auto parse_number() -> std::expected<JsonValue, std::string> {
                std::size_t start = pos_;
                if (peek() == '-') ++pos_;
                if (pos_ >= sv_.size() || !std::isdigit(static_cast<unsigned char>(sv_[pos_]))) {
                    return std::unexpected("invalid JSON number");
                }
                if (sv_[pos_] == '0') ++pos_;
                else while (pos_ < sv_.size() && std::isdigit(static_cast<unsigned char>(sv_[pos_]))) ++pos_;
                bool is_float = false;
                if (pos_ < sv_.size() && sv_[pos_] == '.') {
                    is_float = true;
                    ++pos_;
                    if (pos_ >= sv_.size() || !std::isdigit(static_cast<unsigned char>(sv_[pos_]))) {
                        return std::unexpected("invalid fractional JSON number");
                    }
                    while (pos_ < sv_.size() && std::isdigit(static_cast<unsigned char>(sv_[pos_]))) ++pos_;
                }
                if (pos_ < sv_.size() && (sv_[pos_] == 'e' || sv_[pos_] == 'E')) {
                    is_float = true;
                    ++pos_;
                    if (pos_ < sv_.size() && (sv_[pos_] == '+' || sv_[pos_] == '-')) ++pos_;
                    if (pos_ >= sv_.size() || !std::isdigit(static_cast<unsigned char>(sv_[pos_]))) {
                        return std::unexpected("invalid exponent in JSON number");
                    }
                    while (pos_ < sv_.size() && std::isdigit(static_cast<unsigned char>(sv_[pos_]))) ++pos_;
                }
                auto tok = sv_.substr(start, pos_ - start);
                if (!is_float) {
                    std::int64_t v = 0;
                    auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v, 10);
                    if (ec == std::errc{} && ptr == tok.data() + tok.size()) return JsonValue(v);
                }
                double dv = 0.0;
                auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), dv);
                if (ec != std::errc{} || ptr != tok.data() + tok.size() || !std::isfinite(dv)) {
                    return std::unexpected("JSON number out of range");
                }
                return JsonValue(dv);
            }

            auto parse_array(int depth) -> std::expected<JsonValue, std::string> {
                ++pos_;
                JsonArray arr;
                skip_ws();
                if (peek() == ']') { ++pos_; return JsonValue(std::move(arr)); }
                for (;;) {
                    auto elem = parse_value(depth + 1);
                    if (!elem) return std::unexpected(elem.error());
                    arr.push_back(std::move(*elem));
                    skip_ws();
                    if (peek() == ']') { ++pos_; return JsonValue(std::move(arr)); }
                    if (peek() != ',') return std::unexpected("expected ',' or ']' in JSON array");
                    ++pos_;
                    skip_ws();
                }
            }

            auto parse_object(int depth) -> std::expected<JsonValue, std::string> {
                ++pos_;
                JsonObject obj;
                skip_ws();
                if (peek() == '}') { ++pos_; return JsonValue(std::move(obj)); }
                for (;;) {
                    skip_ws();
                    auto key = parse_string();
                    if (!key) return std::unexpected(key.error());
                    skip_ws();
                    if (peek() != ':') return std::unexpected("expected ':' in JSON object");
                    ++pos_;
                    auto val = parse_value(depth + 1);
                    if (!val) return std::unexpected(val.error());
                    bool updated = false;
                    for (auto& kv : obj) {
                        if (kv.first == *key) { kv.second = std::move(*val); updated = true; break; }
                    }
                    if (!updated) obj.emplace_back(std::move(*key), std::move(*val));
                    skip_ws();
                    if (peek() == '}') { ++pos_; return JsonValue(std::move(obj)); }
                    if (peek() != ',') return std::unexpected("expected ',' or '}' in JSON object");
                    ++pos_;
                }
            }

        public:
            explicit Parser(std::string_view sv) : sv_(sv) {}

            auto parse_value(int depth = 0) -> std::expected<JsonValue, std::string> {
                if (depth > kMaxJsonDepth) return std::unexpected("JSON nesting depth exceeded");
                skip_ws();
                if (pos_ >= sv_.size()) return std::unexpected("unexpected end of JSON");
                char c = sv_[pos_];
                if (c == '"') {
                    auto s = parse_string();
                    if (!s) return std::unexpected(s.error());
                    return JsonValue(std::move(*s));
                }
                if (c == '[') return parse_array(depth);
                if (c == '{') return parse_object(depth);
                if (c == 't' && sv_.substr(pos_).starts_with("true")) { pos_ += 4; return JsonValue(true); }
                if (c == 'f' && sv_.substr(pos_).starts_with("false")) { pos_ += 5; return JsonValue(false); }
                if (c == 'n' && sv_.substr(pos_).starts_with("null")) { pos_ += 4; return JsonValue(nullptr); }
                if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
                return std::unexpected("unexpected token in JSON");
            }

            auto ensure_eof() -> std::expected<void, std::string> {
                skip_ws();
                if (pos_ != sv_.size()) return std::unexpected("trailing characters after JSON root");
                return {};
            }
        };

        auto write_json_rec(std::string& out, JsonValue const& v, bool pretty, int indent) -> void {
            auto pad = [&](int n) { if (pretty) out.append(static_cast<std::size_t>(n) * 2, ' '); };
            if (std::holds_alternative<std::monostate>(v.data)) { out += "null"; return; }
            if (v.is_bool()) { out += std::get<bool>(v.data) ? "true" : "false"; return; }
            if (v.is_i64()) { out += std::to_string(std::get<std::int64_t>(v.data)); return; }
            if (v.is_double()) {
                double d = std::get<double>(v.data);
                out += std::isfinite(d) ? std::format("{}", d) : "0";
                return;
            }
            if (v.is_string()) {
                out.push_back('"');
                out += json_escape_utf8(std::get<std::string>(v.data));
                out.push_back('"');
                return;
            }
            if (v.is_array()) {
                auto const& arr = std::get<JsonArray>(v.data);
                if (arr.empty()) { out += "[]"; return; }
                out.push_back('[');
                if (pretty) out.push_back('\n');
                for (std::size_t i = 0; i < arr.size(); ++i) {
                    pad(indent + 1);
                    write_json_rec(out, arr[i], pretty, indent + 1);
                    if (i + 1 < arr.size()) out.push_back(',');
                    if (pretty) out.push_back('\n');
                }
                pad(indent);
                out.push_back(']');
                return;
            }
            auto const& obj = std::get<JsonObject>(v.data);
            if (obj.empty()) { out += "{}"; return; }
            out.push_back('{');
            if (pretty) out.push_back('\n');
            for (std::size_t i = 0; i < obj.size(); ++i) {
                pad(indent + 1);
                out.push_back('"');
                out += json_escape_utf8(obj[i].first);
                out += pretty ? "\": " : "\":";
                write_json_rec(out, obj[i].second, pretty, indent + 1);
                if (i + 1 < obj.size()) out.push_back(',');
                if (pretty) out.push_back('\n');
            }
            pad(indent);
            out.push_back('}');
        }
    }

    auto json_escape_utf8(std::string_view text) -> std::string {
        std::string out;
        out.reserve(text.size() + 8);
        std::size_t i = 0;
        while (i < text.size()) {
            unsigned char b0 = static_cast<unsigned char>(text[i]);
            if (b0 < 0x80u) {
                ++i;
                switch (static_cast<char>(b0)) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (b0 < 0x20u) out += std::format("\\u{:04x}", b0);
                    else out.push_back(static_cast<char>(b0));
                    break;
                }
                continue;
            }
            std::size_t seq_len = 0;
            std::uint32_t cp = 0;
            if ((b0 & 0xE0u) == 0xC0u) { seq_len = 2; cp = b0 & 0x1Fu; }
            else if ((b0 & 0xF0u) == 0xE0u) { seq_len = 3; cp = b0 & 0x0Fu; }
            else if ((b0 & 0xF8u) == 0xF0u) { seq_len = 4; cp = b0 & 0x07u; }
            bool valid = (seq_len >= 2 && i + seq_len <= text.size());
            if (valid) {
                for (std::size_t k = 1; k < seq_len; ++k) {
                    unsigned char bk = static_cast<unsigned char>(text[i + k]);
                    if ((bk & 0xC0u) != 0x80u) { valid = false; break; }
                    cp = (cp << 6) | (bk & 0x3Fu);
                }
                if (valid) {
                    if ((seq_len == 2 && cp < 0x80u) || (seq_len == 3 && (cp < 0x800u || (cp >= 0xD800u && cp <= 0xDFFFu))) ||
                        (seq_len == 4 && (cp < 0x10000u || cp > 0x10FFFFu))) {
                        valid = false;
                    }
                }
            }
            if (valid) {
                out.append(text.data() + i, seq_len);
                i += seq_len;
            } else {
                out += "\\ufffd";
                ++i;
            }
        }
        return out;
    }

    auto json_parse(std::string_view input) -> std::expected<JsonValue, std::string> {
        Parser p(input);
        auto root = p.parse_value(0);
        if (!root) return std::unexpected(root.error());
        if (auto eof = p.ensure_eof(); !eof) return std::unexpected(eof.error());
        return root;
    }

    auto json_stringify(JsonValue const& value, bool pretty) -> std::string {
        std::string out;
        write_json_rec(out, value, pretty, 0);
        if (pretty) out.push_back('\n');
        return out;
    }

    auto json_find(JsonObject const& obj, std::string_view key) noexcept -> JsonValue const* {
        for (auto const& kv : obj) if (kv.first == key) return &kv.second;
        return nullptr;
    }

    auto json_get_string(JsonObject const& obj, std::string_view key, std::string_view fallback) -> std::string {
        if (auto const* v = json_find(obj, key); v && v->is_string()) return std::get<std::string>(v->data);
        return std::string(fallback);
    }

    auto json_get_bool(JsonObject const& obj, std::string_view key, bool fallback) noexcept -> bool {
        if (auto const* v = json_find(obj, key); v && v->is_bool()) return std::get<bool>(v->data);
        return fallback;
    }

    auto json_get_i64(JsonObject const& obj, std::string_view key, std::int64_t fallback) noexcept -> std::int64_t {
        if (auto const* v = json_find(obj, key)) {
            if (v->is_i64()) return std::get<std::int64_t>(v->data);
            if (v->is_double()) {
                double d = std::get<double>(v->data);
                if (std::isfinite(d) && d >= -9223372036854775808.0 && d < 9223372036854775808.0) {
                    return static_cast<std::int64_t>(d);
                }
            }
        }
        return fallback;
    }

    auto json_get_string_vec(JsonObject const& obj, std::string_view key) -> std::vector<std::string> {
        std::vector<std::string> out;
        if (auto const* v = json_find(obj, key); v && v->is_array()) {
            for (auto const& elem : std::get<JsonArray>(v->data)) {
                if (elem.is_string()) out.push_back(std::get<std::string>(elem.data));
            }
        }
        return out;
    }

    auto json_get_string_map(JsonObject const& obj, std::string_view key) -> std::vector<std::pair<std::string, std::string>> {
        std::vector<std::pair<std::string, std::string>> out;
        if (auto const* v = json_find(obj, key); v && v->is_object()) {
            for (auto const& kv : std::get<JsonObject>(v->data)) {
                if (kv.second.is_string()) out.emplace_back(kv.first, std::get<std::string>(kv.second.data));
            }
        }
        return out;
    }

    auto json_from_string_vec(std::vector<std::string> const& items) -> JsonValue {
        JsonArray arr;
        arr.reserve(items.size());
        for (auto const& s : items) arr.emplace_back(s);
        return JsonValue(std::move(arr));
    }

    auto json_from_string_map(std::vector<std::pair<std::string, std::string>> const& items) -> JsonValue {
        JsonObject obj;
        obj.reserve(items.size());
        for (auto const& kv : items) obj.emplace_back(kv.first, JsonValue(kv.second));
        return JsonValue(std::move(obj));
    }
}
