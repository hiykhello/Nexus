// Private HTTP/JSON formatting & parsing helpers included inside control_api/http_server.cpp.
#pragma once

namespace {
    auto json_escape(std::string_view in) -> std::string {
        std::string out;
        out.reserve(in.size() + 2);
        out.push_back('"');
        for (unsigned char c : in) {
            if (c == '"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else if (c == '\r') out += "\\r";
            else if (c == '\t') out += "\\t";
            else if (c >= 0x20) out.push_back(static_cast<char>(c));
        }
        out.push_back('"');
        return out;
    }

    auto extract_json_string(std::string_view body, std::string_view key) -> std::optional<std::string> {
        auto needle = std::format("\"{}\"", key);
        auto pos = body.find(needle);
        if (pos == std::string_view::npos) return {};
        pos = body.find(':', pos + needle.size());
        if (pos == std::string_view::npos) return {};
        pos = body.find('"', pos + 1);
        if (pos == std::string_view::npos) return {};
        std::string val;
        for (std::size_t i = pos + 1; i < body.size(); ++i) {
            char c = body[i];
            if (c == '\\' && i + 1 < body.size()) { val.push_back(body[++i]); continue; }
            if (c == '"') return val;
            val.push_back(c);
        }
        return {};
    }

    auto url_decode_once(std::string_view in) -> std::optional<std::string> {
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        std::string out;
        out.reserve(in.size());
        for (std::size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '%') {
                if (i + 2 >= in.size()) return {};
                int hi = hex(in[i + 1]), lo = hex(in[i + 2]);
                if (hi < 0 || lo < 0) return {};
                char ch = static_cast<char>((hi << 4) | lo);
                if (ch == '\0' || ch == '/') return {};
                out.push_back(ch);
                i += 2;
            } else {
                out.push_back(in[i]);
            }
        }
        return out;
    }

    auto build_http_response(int status, std::string_view reason, std::string_view content_type,
        std::string_view body) -> std::string {
        return std::format(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
            status, reason, content_type, body.size(), body);
    }

    auto json_error(int status, std::string_view reason, std::string_view code, std::string_view msg) -> std::string {
        auto body = std::format("{{\"error\":{{\"code\":{},\"message\":{}}}}}\n",
            json_escape(code), json_escape(msg));
        return build_http_response(status, reason, "application/json", body);
    }

    auto render_status_json(control_api::ControlSnapshot const& snap) -> std::string {
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

    auto render_outbounds_json(control_api::ControlSnapshot const& snap) -> std::string {
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

    auto render_connection_object(control_api::ConnectionMetric const& c) -> std::string {
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

    auto render_connections_json(control_api::ControlSnapshot const& snap) -> std::string {
        std::string out = "{\"connections\":[";
        for (std::size_t i = 0; i < snap.connections.size(); ++i) {
            if (i) out.push_back(',');
            out += render_connection_object(snap.connections[i]);
        }
        out += "]}\n";
        return out;
    }

    auto render_connection_detail_json(control_api::ConnectionMetric const& c) -> std::string {
        return render_connection_object(c) + "\n";
    }

    auto parse_query_param(std::string_view query, std::string_view key) -> std::optional<std::string> {
        while (!query.empty()) {
            auto amp = query.find('&');
            auto pair = amp == std::string_view::npos ? query : query.substr(0, amp);
            if (auto eq = pair.find('='); eq != std::string_view::npos && pair.substr(0, eq) == key) {
                return url_decode_once(pair.substr(eq + 1));
            }
            if (amp == std::string_view::npos) break;
            query.remove_prefix(amp + 1);
        }
        return std::nullopt;
    }

    struct ParsedLogWire {
        std::string latest_seq{"0"};
        std::string evicted{"0"};
        std::vector<std::string> entry_jsons;
    };

    auto parse_logs_wire(std::string_view wire) -> ParsedLogWire {
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
            parsed.entry_jsons.push_back(std::format(
                "{{\"seq\":{},\"timestamp_ns\":{},\"level\":{},\"domain\":{},\"event\":{},\"session\":{},\"message\":{}}}",
                seq.empty() ? "0" : seq, ts.empty() ? "0" : ts, json_escape(lvl), json_escape(dom),
                ev.empty() ? "0" : ev, sess.empty() ? "0" : sess, json_escape(msg)));
        }
        return parsed;
    }

    auto render_logs_json(std::string_view wire) -> std::string {
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

    auto build_log_command_args(std::string_view query) -> std::vector<std::string> {
        std::vector<std::string> owned{"logs"};
        for (std::string_view key : {"since", "level", "domain", "search", "limit"}) {
            if (auto v = parse_query_param(query, key); v && !v->empty())
                owned.push_back(std::string(key) + "=" + *v);
        }
        return owned;
    }

    auto format_sse_logs(std::string_view wire, std::string& cursor) -> std::string {
        auto parsed = parse_logs_wire(wire);
        cursor = std::move(parsed.latest_seq);
        std::string out;
        for (auto const& item : parsed.entry_jsons) {
            out += "event: log\ndata: ";
            out += item;
            out += "\n\n";
        }
        return out;
    }

    auto render_diagnostics_json(control_api::ControlSnapshot const& snap) -> std::string {
        return std::format(
            "{{\"instance\":{},\"control_generation\":\"{}\",\"authorized_requests\":{},"
            "\"unauthorized_requests\":{},\"expired_requests\":{},\"reply_failed\":{},"
            "\"listeners\":{},\"active_connections\":{}}}\n",
            json_escape(snap.instance), snap.control_generation, snap.authorized_requests,
            snap.unauthorized_requests, snap.expired_requests, snap.reply_failed,
            snap.listeners.size(), snap.connections.size());
    }

    auto render_events_json(std::string_view wire) -> std::string {
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
