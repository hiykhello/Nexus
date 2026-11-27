// Private HTTP/JSON formatting & parsing helpers for control_api HTTP server.
export module control_api.http_format;
import std;
import control_api.types;
import encoding.hex;
import encoding.json;

export namespace control_api::http_detail {
    inline auto json_escape(std::string_view in) -> std::string {
        return encoding::json_quote(in);
    }

    inline auto parse_json_string_at(std::string_view body, std::size_t& pos, std::string& out) -> bool {
        auto skip_ws = [&]() noexcept {
            while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\r' || body[pos] == '\n'))
                ++pos;
        };
        skip_ws();
        if (pos >= body.size() || body[pos] != '"') return false;
        ++pos;
        out.clear();
        while (pos < body.size()) {
            unsigned char uc = static_cast<unsigned char>(body[pos++]);
            if (uc == '"') return true;
            if (uc < 0x20) return false;
            if (uc != '\\') { out.push_back(static_cast<char>(uc)); continue; }
            if (pos >= body.size()) return false;
            char e = body[pos++];
            switch (e) {
            case '"': case '\\': case '/': out.push_back(e); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                if (pos + 4 > body.size()) return false;
                unsigned cp = 0;
                auto [end, ec] = std::from_chars(body.data() + pos, body.data() + pos + 4, cp, 16);
                if (ec != std::errc{} || end != body.data() + pos + 4) return false;
                pos += 4;
                if (cp >= 0xd800 && cp <= 0xdbff && pos + 6 <= body.size() && body[pos] == '\\' && body[pos + 1] == 'u') {
                    unsigned lo = 0;
                    auto [e2, ec2] = std::from_chars(body.data() + pos + 2, body.data() + pos + 6, lo, 16);
                    if (ec2 == std::errc{} && e2 == body.data() + pos + 6 && lo >= 0xdc00 && lo <= 0xdfff) {
                        cp = 0x10000u + (((cp - 0xd800u) << 10) | (lo - 0xdc00u));
                        pos += 6;
                    }
                }
                if (cp < 0x80) out.push_back(static_cast<char>(cp));
                else if (cp < 0x800) { out.push_back(static_cast<char>(0xc0 | (cp >> 6))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
                else if (cp < 0x10000) { out.push_back(static_cast<char>(0xe0 | (cp >> 12))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
                else { out.push_back(static_cast<char>(0xf0 | (cp >> 18))); out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
                break;
            }
            default: return false;
            }
        }
        return false;
    }

    inline auto skip_json_value_at(std::string_view body, std::size_t& pos, unsigned depth) -> bool {
        if (depth > 32) return false;
        auto skip_ws = [&]() noexcept {
            while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\r' || body[pos] == '\n'))
                ++pos;
        };
        skip_ws();
        if (pos >= body.size()) return false;
        char c = body[pos];
        if (c == '"') { std::string tmp; return parse_json_string_at(body, pos, tmp); }
        if (c == '{') {
            ++pos; skip_ws();
            if (pos < body.size() && body[pos] == '}') { ++pos; return true; }
            for (;;) {
                std::string k;
                if (!parse_json_string_at(body, pos, k)) return false;
                skip_ws(); if (pos >= body.size() || body[pos++] != ':') return false;
                if (!skip_json_value_at(body, pos, depth + 1)) return false;
                skip_ws(); if (pos >= body.size()) return false;
                if (body[pos] == '}') { ++pos; return true; }
                if (body[pos++] != ',') return false;
            }
        }
        if (c == '[') {
            ++pos; skip_ws();
            if (pos < body.size() && body[pos] == ']') { ++pos; return true; }
            for (;;) {
                if (!skip_json_value_at(body, pos, depth + 1)) return false;
                skip_ws(); if (pos >= body.size()) return false;
                if (body[pos] == ']') { ++pos; return true; }
                if (body[pos++] != ',') return false;
            }
        }
        if (body.substr(pos).starts_with("true")) { pos += 4; return true; }
        if (body.substr(pos).starts_with("false")) { pos += 5; return true; }
        if (body.substr(pos).starts_with("null")) { pos += 4; return true; }
        if (c == '-' || (c >= '0' && c <= '9')) {
            if (body[pos] == '-') ++pos;
            if (pos >= body.size() || body[pos] < '0' || body[pos] > '9') return false;
            while (pos < body.size() && body[pos] >= '0' && body[pos] <= '9') ++pos;
            if (pos < body.size() && body[pos] == '.') {
                ++pos;
                if (pos >= body.size() || body[pos] < '0' || body[pos] > '9') return false;
                while (pos < body.size() && body[pos] >= '0' && body[pos] <= '9') ++pos;
            }
            if (pos < body.size() && (body[pos] == 'e' || body[pos] == 'E')) {
                ++pos;
                if (pos < body.size() && (body[pos] == '+' || body[pos] == '-')) ++pos;
                if (pos >= body.size() || body[pos] < '0' || body[pos] > '9') return false;
                while (pos < body.size() && body[pos] >= '0' && body[pos] <= '9') ++pos;
            }
            return true;
        }
        return false;
    }

    inline auto is_valid_json_object(std::string_view body) -> bool {
        std::size_t pos = 0;
        auto skip_ws = [&]() noexcept {
            while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\r' || body[pos] == '\n'))
                ++pos;
        };
        skip_ws();
        if (pos >= body.size() || body[pos] != '{') return false;
        if (!skip_json_value_at(body, pos, 0)) return false;
        skip_ws();
        return pos == body.size();
    }

    inline auto find_json_field_pos(std::string_view body, std::string_view key) -> std::optional<std::size_t> {
        std::size_t pos = 0;
        auto skip_ws = [&]() noexcept {
            while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\r' || body[pos] == '\n'))
                ++pos;
        };
        skip_ws();
        if (pos >= body.size() || body[pos++] != '{') return {};
        skip_ws();
        if (pos < body.size() && body[pos] == '}') return {};
        std::string cur_key;
        for (;;) {
            if (!parse_json_string_at(body, pos, cur_key)) return {};
            skip_ws();
            if (pos >= body.size() || body[pos++] != ':') return {};
            skip_ws();
            if (cur_key == key) return pos;
            if (!skip_json_value_at(body, pos, 1)) return {};
            skip_ws();
            if (pos >= body.size()) return {};
            if (body[pos] == '}') return {};
            if (body[pos++] != ',') return {};
        }
    }

    inline auto extract_json_string(std::string_view body, std::string_view key) -> std::optional<std::string> {
        auto pos = find_json_field_pos(body, key);
        if (!pos || *pos >= body.size() || body[*pos] != '"') return {};
        std::string val;
        return parse_json_string_at(body, *pos, val) ? std::optional<std::string>(std::move(val)) : std::nullopt;
    }

    inline auto extract_json_uint(std::string_view body, std::string_view key) -> std::optional<std::uint64_t> {
        auto pos = find_json_field_pos(body, key);
        if (!pos || *pos >= body.size()) return {};
        std::size_t start = *pos, end = start;
        if (body[end] < '0' || body[end] > '9') return {};
        if (body[end] == '0' && end + 1 < body.size() && body[end + 1] >= '0' && body[end + 1] <= '9') return {};
        while (end < body.size() && body[end] >= '0' && body[end] <= '9') ++end;
        if (end < body.size() && body[end] != ',' && body[end] != '}' &&
            body[end] != ' ' && body[end] != '\t' && body[end] != '\r' && body[end] != '\n') return {};
        std::uint64_t value = 0;
        auto [ptr, ec] = std::from_chars(body.data() + start, body.data() + end, value);
        if (ec != std::errc{} || ptr != body.data() + end) return {};
        return value;
    }

    inline auto url_decode_once(std::string_view in, bool allow_slash = false) -> std::optional<std::string> {
        std::string out;
        out.reserve(in.size());
        for (std::size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '%') {
                if (i + 2 >= in.size()) return {};
                int hi = encoding::hex_value(in[i + 1]), lo = encoding::hex_value(in[i + 2]);
                if (hi < 0 || lo < 0) return {};
                char ch = static_cast<char>((hi << 4) | lo);
                if (ch == '\0' || (!allow_slash && ch == '/')) return {};
                out.push_back(ch);
                i += 2;
            } else {
                out.push_back(in[i]);
            }
        }
        return out;
    }

    inline auto build_http_response(int status, std::string_view reason, std::string_view content_type,
        std::string_view body) -> std::string {
        return std::format(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
            status, reason, content_type, body.size(), body);
    }

    inline auto json_error(int status, std::string_view reason, std::string_view code, std::string_view msg) -> std::string {
        auto body = std::format("{{\"error\":{{\"code\":{},\"message\":{}}}}}\n",
            json_escape(code), json_escape(msg));
        return build_http_response(status, reason, "application/json", body);
    }

    inline auto render_status_json(control_api::ControlSnapshot const& snap) -> std::string {
        std::uint64_t up = 0, down = 0;
        std::size_t active = 0;
        for (auto const& l : snap.listeners) {
            up += l.upload_bytes;
            down += l.download_bytes;
            active += l.active_sessions;
        }
        return std::format(
            "{{\"instance\":{},\"state\":\"running\",\"workers\":{},\"listeners\":{},"
            "\"control_generation\":\"{}\",\"active_sessions\":{},"
            "\"upload_bytes_total\":\"{}\",\"download_bytes_total\":\"{}\"}}\n",
            json_escape(snap.instance), snap.workers, snap.listeners.size(),
            snap.control_generation, active, up, down);
    }

    inline auto render_mode_json(control_api::ControlSnapshot const& snap) -> std::string {
        return std::format("{{\"mode\":{},\"outbound\":{}}}\n",
            json_escape(snap.route_mode), json_escape(snap.global_outbound));
    }

    inline auto render_outbounds_json(control_api::ControlSnapshot const& snap) -> std::string {
        std::string out = "{\"groups\":[";
        for (std::size_t i = 0; i < snap.groups.size(); ++i) {
            if (i) out.push_back(',');
            auto const& g = snap.groups[i];
            out += std::format("{{\"name\":{},\"mode\":{},\"selected\":{},\"override\":{},\"members\":[",
                json_escape(g.name), json_escape(g.mode), json_escape(g.selected),
                g.manual_override ? "true" : "false");
            for (std::size_t j = 0; j < g.members.size(); ++j) {
                if (j) out.push_back(',');
                auto const& m = g.members[j];
                out += std::format("{{\"name\":{},\"state\":{}", json_escape(m.name), json_escape(m.state));
                if (m.latency_ms) out += std::format(",\"latency_ms\":{}", *m.latency_ms);
                if (m.ewma_ms) out += std::format(",\"ewma_ms\":{}", *m.ewma_ms);
                if (m.last_status) out += std::format(",\"last_status\":{}", *m.last_status);
                if (m.breaker_open) out += ",\"breaker_open\":true";
                out.push_back('}');
            }
            out += "]}";
        }
        out += "]}\n";
        return out;
    }

    inline auto render_connection_object(control_api::ConnectionMetric const& c) -> std::string {
        std::string out = std::format(
            "{{\"id\":\"{}\",\"listener\":{},\"protocol\":{},\"path\":{},\"destination_port\":{},"
            "\"upload_bytes\":\"{}\",\"download_bytes\":\"{}\",\"duration_ms\":{},\"can_close\":{}",
            c.id, c.listener, json_escape(c.protocol), json_escape(c.path),
            c.destination_port, c.upload_bytes, c.download_bytes, c.duration_ms,
            c.can_close ? "true" : "false");
        if (!c.inbound.empty()) out += std::format(",\"inbound\":{}", json_escape(c.inbound));
        if (!c.source.empty()) out += std::format(",\"source\":{}", json_escape(c.source));
        if (!c.target.empty()) out += std::format(",\"target\":{}", json_escape(c.target));
        if (!c.outbound.empty()) out += std::format(",\"outbound\":{}", json_escape(c.outbound));
        if (!c.route_mode.empty()) out += std::format(",\"route_mode\":{}", json_escape(c.route_mode));
        if (!c.route_rule.empty()) out += std::format(",\"route_rule\":{}", json_escape(c.route_rule));
        if (!c.process_path.empty()) out += std::format(",\"process_path\":{}", json_escape(c.process_path));
        if (c.source_uid) out += std::format(",\"source_uid\":{}", *c.source_uid);
        out.push_back('}');
        return out;
    }

    inline auto render_connections_json(control_api::ControlSnapshot const& snap) -> std::string {
        std::string out = "{\"connections\":[";
        for (std::size_t i = 0; i < snap.connections.size(); ++i) {
            if (i) out.push_back(',');
            out += render_connection_object(snap.connections[i]);
        }
        out += "]}\n";
        return out;
    }

    inline auto render_connection_detail_json(control_api::ConnectionMetric const& c) -> std::string {
        return render_connection_object(c) + "\n";
    }

    inline auto extract_bearer_token(std::string_view headers) noexcept -> std::string_view {
        auto rest = headers;
        while (!rest.empty()) {
            auto eol = rest.find("\r\n");
            auto line = rest.substr(0, eol);
            if (auto colon = line.find(':'); colon != std::string_view::npos) {
                auto name = line.substr(0, colon);
                if (name.size() == 13 && std::ranges::equal(name, std::string_view("authorization"),
                    [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == b; })) {
                    auto val = line.substr(colon + 1);
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.remove_prefix(1);
                    if (val.starts_with("Bearer ")) return val.substr(7);
                }
            }
            if (eol == std::string_view::npos) break;
            rest.remove_prefix(eol + 2);
        }
        return {};
    }

    inline auto parse_content_length(std::string_view head) noexcept -> std::optional<std::size_t> {
        auto first_eol = head.find("\r\n");
        if (first_eol == std::string_view::npos) return std::size_t{0};
        auto rest = head.substr(first_eol + 2);
        std::optional<std::size_t> seen;
        while (!rest.empty()) {
            auto eol = rest.find("\r\n");
            auto line = rest.substr(0, eol);
            if (auto colon = line.find(':'); colon != std::string_view::npos) {
                auto name = line.substr(0, colon);
                if (name.size() == 14 && std::ranges::equal(name, std::string_view("content-length"),
                    [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == b; })) {
                    auto v = line.substr(colon + 1);
                    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
                    if (v.empty() || !std::ranges::all_of(v, [](unsigned char c) { return c >= '0' && c <= '9'; }))
                        return std::nullopt;
                    std::size_t parsed = 0;
                    auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), parsed);
                    if (ec != std::errc{} || end != v.data() + v.size()) return std::nullopt;
                    if (seen && *seen != parsed) return std::nullopt;
                    seen = parsed;
                }
            }
            if (eol == std::string_view::npos) break;
            rest.remove_prefix(eol + 2);
        }
        return seen.value_or(0);
    }

    inline auto find_query_param_raw(std::string_view query, std::string_view key) noexcept -> std::optional<std::string_view> {
        while (!query.empty()) {
            auto amp = query.find('&');
            auto pair = amp == std::string_view::npos ? query : query.substr(0, amp);
            if (auto eq = pair.find('='); eq != std::string_view::npos && pair.substr(0, eq) == key) return pair.substr(eq + 1);
            if (amp == std::string_view::npos) break;
            query.remove_prefix(amp + 1);
        }
        return std::nullopt;
    }

    inline auto parse_query_param(std::string_view query, std::string_view key) -> std::optional<std::string> {
        auto raw = find_query_param_raw(query, key);
        return raw ? url_decode_once(*raw, true) : std::nullopt;
    }

    struct ParsedLogWire {
        std::string latest_seq{"0"};
        std::string evicted{"0"};
        std::string last_entry_seq;
        std::vector<std::string> entry_jsons;
    };

    inline auto parse_logs_wire(std::string_view wire) -> ParsedLogWire {
        auto kv = [](std::string_view line, std::string_view key) -> std::string_view {
            auto needle = std::string(key) + "=";
            auto pos = line.find(needle);
            if (pos == std::string_view::npos) return {};
            auto val = line.substr(pos + needle.size());
            auto sp = val.find(' ');
            return sp == std::string_view::npos ? val : val.substr(0, sp);
        };
        ParsedLogWire parsed;
        auto nl = wire.find('\n');
        auto head = nl == std::string_view::npos ? wire : wire.substr(0, nl);
        auto rest = nl == std::string_view::npos ? std::string_view{} : wire.substr(nl + 1);
        if (auto v = kv(head, "latest"); !v.empty()) parsed.latest_seq = std::string(v);
        if (auto v = kv(head, "evicted"); !v.empty()) parsed.evicted = std::string(v);
        while (!rest.empty()) {
            auto end = rest.find('\n');
            auto line = end == std::string_view::npos ? rest : rest.substr(0, end);
            rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 1);
            if (line.empty()) continue;
            auto seq = kv(line, "seq");
            auto ts = kv(line, "ts");
            auto lvl = kv(line, "level");
            auto dom = kv(line, "domain");
            auto ev = kv(line, "event");
            auto sess = kv(line, "session");
            std::string_view msg;
            if (auto mp = line.find("msg="); mp != std::string_view::npos) {
                msg = line.substr(mp + 4);
                if (msg.size() >= 2 && msg.front() == '"' && msg.back() == '"')
                    msg = msg.substr(1, msg.size() - 2);
            }
            if (!seq.empty()) parsed.last_entry_seq.assign(seq);
            parsed.entry_jsons.push_back(std::format(
                "{{\"seq\":{},\"timestamp_ns\":{},\"level\":{},\"domain\":{},\"event\":{},\"session\":{},\"message\":{}}}",
                seq.empty() ? "0" : seq, ts.empty() ? "0" : ts, json_escape(lvl), json_escape(dom),
                ev.empty() ? "0" : ev, sess.empty() ? "0" : sess, json_escape(msg)));
        }
        return parsed;
    }

    inline auto advance_log_cursor(std::string& cursor, ParsedLogWire const& parsed) -> void {
        auto to_u64 = [](std::string_view s) noexcept -> std::optional<std::uint64_t> {
            if (s.empty()) return std::nullopt;
            std::uint64_t v = 0;
            auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            return (ec == std::errc{} && end == s.data() + s.size()) ? std::optional(v) : std::nullopt;
        };
        auto cur = to_u64(cursor).value_or(0);
        auto const& next_str = !parsed.entry_jsons.empty() ? parsed.last_entry_seq : parsed.latest_seq;
        if (auto next = to_u64(next_str); next && *next > cur) cursor = next_str;
    }

    inline auto render_logs_json(std::string_view wire) -> std::string {
        auto parsed = parse_logs_wire(wire);
        std::string out = std::format("{{\"latest_seq\":{},\"evicted\":{},\"entries\":[",
            parsed.latest_seq, parsed.evicted);
        for (std::size_t i = 0; i < parsed.entry_jsons.size(); ++i) {
            if (i) out.push_back(',');
            out += parsed.entry_jsons[i];
        }
        out += "]}\n";
        return out;
    }

    inline auto build_log_command_args(std::string_view query) -> std::expected<std::vector<std::string>, std::string> {
        std::vector<std::string> owned{"logs"};
        for (std::string_view key : {"since", "level", "domain", "search", "limit"}) {
            auto raw = find_query_param_raw(query, key);
            if (!raw) continue;
            auto v = url_decode_once(*raw, true);
            if (!v) return std::unexpected("invalid-query");
            if (!v->empty()) owned.push_back(std::string(key) + "=" + *v);
        }
        return owned;
    }

    inline auto format_sse_logs(std::string_view wire, std::string& cursor) -> std::string {
        auto parsed = parse_logs_wire(wire);
        advance_log_cursor(cursor, parsed);
        std::string out;
        for (auto const& item : parsed.entry_jsons) {
            out += "event: log\ndata: ";
            out += item;
            out += "\n\n";
        }
        return out;
    }

    inline auto render_diagnostics_json(control_api::ControlSnapshot const& snap) -> std::string {
        return std::format(
            "{{\"instance\":{},\"control_generation\":\"{}\",\"authorized_requests\":{},"
            "\"unauthorized_requests\":{},\"expired_requests\":{},\"reply_failed\":{},"
            "\"listeners\":{},\"active_connections\":{}}}\n",
            json_escape(snap.instance), snap.control_generation, snap.authorized_requests,
            snap.unauthorized_requests, snap.expired_requests, snap.reply_failed,
            snap.listeners.size(), snap.connections.size());
    }

    inline auto render_events_json(std::string_view wire) -> std::string {
        auto kv = [](std::string_view line, std::string_view key) -> std::string_view {
            auto needle = std::string(key) + "=";
            auto pos = line.find(needle);
            if (pos == std::string_view::npos) return {};
            auto val = line.substr(pos + needle.size());
            auto sp = val.find(' ');
            return sp == std::string_view::npos ? val : val.substr(0, sp);
        };
        auto nl = wire.find('\n');
        auto head = nl == std::string_view::npos ? wire : wire.substr(0, nl);
        auto rest = nl == std::string_view::npos ? std::string_view{} : wire.substr(nl + 1);
        auto next_v = kv(head, "next");
        auto latest_v = kv(head, "latest");
        std::string out = std::format("{{\"instance\":{},\"next\":{},\"latest\":{},\"gap\":{},\"events\":[",
            json_escape(kv(head, "instance")),
            next_v.empty() ? "0" : next_v,
            latest_v.empty() ? "0" : latest_v,
            kv(head, "gap") == "1" ? "true" : "false");
        bool first = true;
        while (!rest.empty()) {
            auto end = rest.find('\n');
            auto line = end == std::string_view::npos ? rest : rest.substr(0, end);
            rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 1);
            if (line.empty()) continue;
            if (!first) out.push_back(',');
            first = false;
            auto id_v = kv(line, "id");
            auto ev_v = kv(line, "event");
            auto gen_v = kv(line, "control-generation");
            auto op_v = kv(line, "operation");
            out += std::format("{{\"id\":{},\"event\":{},\"control_generation\":{}",
                id_v.empty() ? "0" : id_v, json_escape(ev_v), gen_v.empty() ? "0" : gen_v);
            if (!op_v.empty()) out += std::format(",\"operation\":{}", op_v);
            out.push_back('}');
        }
        out += "]}\n";
        return out;
    }
}
