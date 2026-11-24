module provider;
import std;
import :detail;

namespace provider::detail {
    auto YamlVal::get(std::string_view key) const noexcept -> YamlVal const* {
        if (kind != Kind::map_v) return nullptr;
        for (auto const& [k, v] : map) if (k == key) return &v;
        return nullptr;
    }

    auto YamlVal::set(std::string key, YamlVal val) -> void {
        kind = Kind::map_v;
        for (auto& [k, v] : map) { if (k == key) { v = std::move(val); return; } }
        map.emplace_back(std::move(key), std::move(val));
    }

    auto YamlVal::as_str() const -> std::string {
        if (kind == Kind::str_v) return sval;
        if (kind == Kind::int_v) return std::to_string(ival);
        if (kind == Kind::bool_v) return bval ? "true" : "false";
        return {};
    }

    auto YamlVal::as_int() const -> std::optional<std::int64_t> {
        if (kind == Kind::int_v) return ival;
        if (kind == Kind::str_v && !sval.empty()) {
            std::int64_t v = 0;
            auto [e, ec] = std::from_chars(sval.data(), sval.data() + sval.size(), v);
            if (ec == std::errc{} && e == sval.data() + sval.size()) return v;
        }
        return std::nullopt;
    }

    auto YamlVal::as_bool(bool def) const noexcept -> bool {
        if (kind == Kind::bool_v) return bval;
        if (kind == Kind::int_v) return ival != 0;
        if (kind == Kind::str_v) {
            auto l = lower_ascii(sval);
            return l == "true" || l == "yes" || l == "1";
        }
        return def;
    }

    namespace {
        auto strip_yaml_comment(std::string_view line) -> std::string_view {
            char quote = 0;
            for (std::size_t i = 0; i < line.size(); ++i) {
                char c = line[i];
                if (quote) {
                    if (quote == '"' && c == '\\' && i + 1 < line.size()) { ++i; continue; }
                    if (c == '\'' && quote == '\'' && i + 1 < line.size() && line[i + 1] == '\'') { ++i; continue; }
                    if (c == quote) quote = 0;
                    continue;
                }
                if (c == '"' || c == '\'') { quote = c; continue; }
                if (c == '#' && (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t'))
                    return line.substr(0, i);
            }
            return line;
        }

        auto unquote_yaml(std::string_view s, bool& was_quoted) -> std::string {
            s = trim(s);
            was_quoted = false;
            if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
                was_quoted = true;
                std::string out;
                for (std::size_t i = 1; i + 1 < s.size(); ++i) {
                    if (s[i] == '\\' && i + 2 < s.size()) {
                        char e = s[++i];
                        if (e == 'n') out.push_back('\n');
                        else if (e == 't') out.push_back('\t');
                        else if (e == 'r') out.push_back('\r');
                        else out.push_back(e);
                    } else out.push_back(s[i]);
                }
                return out;
            }
            if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'') {
                was_quoted = true;
                std::string out;
                for (std::size_t i = 1; i + 1 < s.size(); ++i) {
                    if (s[i] == '\'' && i + 2 < s.size() && s[i + 1] == '\'') { out.push_back('\''); ++i; }
                    else out.push_back(s[i]);
                }
                return out;
            }
            return std::string(s);
        }

        auto scalar_val(std::string_view raw) -> YamlVal {
            bool quoted = false;
            std::string s = unquote_yaml(raw, quoted);
            if (!quoted) {
                auto l = lower_ascii(s);
                if (s.empty() || l == "null" || s == "~") return YamlVal{YamlVal::Kind::null_v};
                if (l == "true" || l == "yes") return YamlVal{YamlVal::Kind::bool_v, true};
                if (l == "false" || l == "no") return YamlVal{YamlVal::Kind::bool_v, false};
                std::int64_t iv = 0;
                auto [e, ec] = std::from_chars(s.data(), s.data() + s.size(), iv);
                if (ec == std::errc{} && e == s.data() + s.size())
                    return YamlVal{YamlVal::Kind::int_v, false, iv};
            }
            return YamlVal{YamlVal::Kind::str_v, false, 0, std::move(s)};
        }

        auto parse_flow_impl(std::string_view& s, unsigned depth) -> std::expected<YamlVal, std::string>;

        auto parse_flow_token(std::string_view& s, std::string_view stop_chars) -> std::string {
            s = trim(s);
            if (!s.empty() && (s.front() == '"' || s.front() == '\'')) {
                char q = s.front();
                std::size_t i = 1;
                while (i < s.size()) {
                    if (q == '"' && s[i] == '\\' && i + 1 < s.size()) { i += 2; continue; }
                    if (q == '\'' && s[i] == '\'' && i + 1 < s.size() && s[i + 1] == '\'') { i += 2; continue; }
                    if (s[i] == q) { ++i; break; }
                    ++i;
                }
                auto tok = s.substr(0, i);
                s.remove_prefix(i);
                return std::string(tok);
            }
            std::size_t i = 0;
            while (i < s.size() && !stop_chars.contains(s[i])) ++i;
            auto tok = s.substr(0, i);
            s.remove_prefix(i);
            return std::string(tok);
        }

        auto parse_flow_impl(std::string_view& s, unsigned depth) -> std::expected<YamlVal, std::string> {
            if (depth > 32) return std::unexpected("YAML flow nesting exceeds limit");
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
            if (s.empty()) return YamlVal{YamlVal::Kind::null_v};
            if (s.front() == '[') {
                s.remove_prefix(1);
                YamlVal arr{YamlVal::Kind::arr_v};
                for (;;) {
                    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
                    if (s.empty()) return std::unexpected("unterminated YAML flow sequence");
                    if (s.front() == ']') { s.remove_prefix(1); return arr; }
                    auto item = parse_flow_impl(s, depth + 1);
                    if (!item) return item;
                    arr.arr.push_back(std::move(*item));
                    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
                    if (!s.empty() && s.front() == ',') { s.remove_prefix(1); continue; }
                    if (!s.empty() && s.front() == ']') { s.remove_prefix(1); return arr; }
                    return std::unexpected("expected ',' or ']' in YAML flow sequence");
                }
            }
            if (s.front() == '{') {
                s.remove_prefix(1);
                YamlVal obj{YamlVal::Kind::map_v};
                for (;;) {
                    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
                    if (s.empty()) return std::unexpected("unterminated YAML flow mapping");
                    if (s.front() == '}') { s.remove_prefix(1); return obj; }
                    auto raw_key = parse_flow_token(s, ":},");
                    bool q = false;
                    std::string key = unquote_yaml(raw_key, q);
                    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
                    if (s.empty() || s.front() != ':') return std::unexpected("expected ':' in YAML flow mapping");
                    s.remove_prefix(1);
                    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
                    YamlVal val{YamlVal::Kind::null_v};
                    if (!s.empty() && s.front() != ',' && s.front() != '}') {
                        auto parsed = parse_flow_impl(s, depth + 1);
                        if (!parsed) return parsed;
                        val = std::move(*parsed);
                    }
                    obj.set(std::move(key), std::move(val));
                    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
                    if (!s.empty() && s.front() == ',') { s.remove_prefix(1); continue; }
                    if (!s.empty() && s.front() == '}') { s.remove_prefix(1); return obj; }
                    return std::unexpected("expected ',' or '}' in YAML flow mapping");
                }
            }
            return scalar_val(parse_flow_token(s, ",]}"));
        }

        auto find_kv_colon(std::string_view text) noexcept -> std::optional<std::size_t> {
            char quote = 0;
            int flow = 0;
            for (std::size_t i = 0; i < text.size(); ++i) {
                char c = text[i];
                if (quote) {
                    if (quote == '"' && c == '\\' && i + 1 < text.size()) { ++i; continue; }
                    if (c == quote) quote = 0;
                    continue;
                }
                if (c == '"' || c == '\'') { quote = c; continue; }
                if (c == '{' || c == '[') { ++flow; continue; }
                if (c == '}' || c == ']') { if (flow > 0) --flow; continue; }
                if (flow == 0 && c == ':' && (i + 1 == text.size() || text[i + 1] == ' ' || text[i + 1] == '\t')) return i;
            }
            return std::nullopt;
        }

        struct YamlLine { int indent = 0; std::string text; };

        auto tokenize_yaml_lines(std::string_view src) -> std::vector<YamlLine> {
            std::vector<YamlLine> out;
            while (!src.empty()) {
                auto nl = src.find('\n');
                auto raw = nl == std::string_view::npos ? src : src.substr(0, nl);
                src = nl == std::string_view::npos ? std::string_view{} : src.substr(nl + 1);
                if (!raw.empty() && raw.back() == '\r') raw.remove_suffix(1);
                auto clean = strip_yaml_comment(raw);
                int ind = 0;
                while (ind < static_cast<int>(clean.size()) && (clean[ind] == ' ' || clean[ind] == '\t')) ++ind;
                auto body = trim(clean.substr(static_cast<std::size_t>(ind)));
                if (body.empty() || body == "---" || body == "...") continue;
                out.push_back({ind, std::string(body)});
            }
            return out;
        }

        auto parse_block(std::vector<YamlLine> const& lines, std::size_t& idx, int min_indent, unsigned depth)
            -> std::expected<YamlVal, std::string>;

        auto parse_inline_or_nested(std::string_view val_sv, std::vector<YamlLine> const& lines,
                                    std::size_t& idx, int parent_indent, unsigned depth)
            -> std::expected<YamlVal, std::string> {
            val_sv = trim(val_sv);
            if (!val_sv.empty()) {
                if (val_sv.front() == '{' || val_sv.front() == '[') {
                    constexpr std::size_t kMaxFlowBytes = 1024 * 1024;
                    if (val_sv.size() > kMaxFlowBytes)
                        return std::unexpected("YAML flow collection exceeds size limit");
                    std::string buf(val_sv);
                    int d = 0;
                    char q = 0;
                    auto scan = [&](std::string_view chunk) noexcept {
                        for (std::size_t i = 0; i < chunk.size(); ++i) {
                            char c = chunk[i];
                            if (q) {
                                if (q == '"' && c == '\\' && i + 1 < chunk.size()) ++i;
                                else if (q == '\'' && c == '\'' && i + 1 < chunk.size() && chunk[i + 1] == '\'') ++i;
                                else if (c == q) q = 0;
                                continue;
                            }
                            if (c == '"' || c == '\'') { q = c; continue; }
                            if (c == '{' || c == '[') ++d;
                            else if (c == '}' || c == ']') --d;
                        }
                    };
                    scan(val_sv);
                    while ((d > 0 || q != 0) && idx < lines.size()) {
                        auto const& next = lines[idx++].text;
                        if (buf.size() + 1 + next.size() > kMaxFlowBytes)
                            return std::unexpected("YAML flow collection exceeds size limit");
                        buf.push_back(' ');
                        buf.append(next);
                        scan(next);
                    }
                    std::string_view sv(buf);
                    return parse_flow_impl(sv, depth + 1);
                }
                return scalar_val(val_sv);
            }
            if (idx < lines.size() && (lines[idx].indent > parent_indent ||
                (lines[idx].indent == parent_indent && lines[idx].text.starts_with('-'))))
                return parse_block(lines, idx, lines[idx].indent, depth + 1);
            return YamlVal{YamlVal::Kind::null_v};
        }

        auto parse_block(std::vector<YamlLine> const& lines, std::size_t& idx, int min_indent, unsigned depth)
            -> std::expected<YamlVal, std::string> {
            if (depth > 32) return std::unexpected("YAML block nesting exceeds limit");
            if (idx >= lines.size()) return YamlVal{YamlVal::Kind::null_v};
            bool is_seq = lines[idx].text == "-" || lines[idx].text.starts_with("- ");
            int base = lines[idx].indent;
            if (base < min_indent) return YamlVal{YamlVal::Kind::null_v};
            if (is_seq) {
                YamlVal arr{YamlVal::Kind::arr_v};
                while (idx < lines.size() && lines[idx].indent == base &&
                       (lines[idx].text == "-" || lines[idx].text.starts_with("- "))) {
                    std::string item_line = lines[idx].text.size() > 1 ? std::string(trim(std::string_view(lines[idx].text).substr(1))) : std::string{};
                    ++idx;
                    if (item_line.empty()) {
                        if (idx < lines.size() && lines[idx].indent > base) {
                            auto sub = parse_block(lines, idx, lines[idx].indent, depth + 1);
                            if (!sub) return sub;
                            arr.arr.push_back(std::move(*sub));
                        } else arr.arr.push_back(YamlVal{YamlVal::Kind::null_v});
                    } else if (!item_line.starts_with('{') && !item_line.starts_with('[') &&
                               find_kv_colon(item_line)) {
                        auto colon = find_kv_colon(item_line);
                        YamlVal obj{YamlVal::Kind::map_v};
                        bool q = false;
                        auto k = unquote_yaml(std::string_view(item_line).substr(0, *colon), q);
                        auto v = trim(std::string_view(item_line).substr(*colon + 1));
                        auto val = parse_inline_or_nested(v, lines, idx, base + 1, depth + 1);
                        if (!val) return val;
                        obj.set(std::move(k), std::move(*val));
                        if (idx < lines.size() && lines[idx].indent > base && !lines[idx].text.starts_with("- ")) {
                            auto rest = parse_block(lines, idx, lines[idx].indent, depth + 1);
                            if (!rest) return rest;
                            if (rest->kind == YamlVal::Kind::map_v)
                                for (auto& [rk, rv] : rest->map) obj.set(std::move(rk), std::move(rv));
                        }
                        arr.arr.push_back(std::move(obj));
                    } else {
                        auto val = parse_inline_or_nested(item_line, lines, idx, base, depth + 1);
                        if (!val) return val;
                        arr.arr.push_back(std::move(*val));
                    }
                }
                return arr;
            }
            YamlVal obj{YamlVal::Kind::map_v};
            while (idx < lines.size() && lines[idx].indent == base) {
                if (lines[idx].text == "-" || lines[idx].text.starts_with("- ")) break;
                auto colon = find_kv_colon(lines[idx].text);
                if (!colon) return std::unexpected("expected ':' in YAML mapping near: " + lines[idx].text);
                bool q = false;
                auto k = unquote_yaml(std::string_view(lines[idx].text).substr(0, *colon), q);
                auto v = trim(std::string_view(lines[idx].text).substr(*colon + 1));
                ++idx;
                auto val = parse_inline_or_nested(v, lines, idx, base, depth + 1);
                if (!val) return val;
                obj.set(std::move(k), std::move(*val));
            }
            return obj;
        }
    }

    auto parse_yaml_dom(std::string_view body) -> std::expected<YamlVal, std::string> {
        auto lines = tokenize_yaml_lines(body);
        std::size_t idx = 0;
        return parse_block(lines, idx, 0, 0);
    }
}
