// Extra HTTP control plane routes: CORS, /v1/rules, /v1/dns/query, FakeIP & cache flush.
export module control_api.http_extra_routes;

import std;
import control_api.http_format;
import control_api.http_stream;
import control_api.types;

export namespace control_api::http_detail {
    inline constexpr auto kDnsQueryPollInterval = std::chrono::milliseconds(10);
    inline constexpr auto kDnsQueryHardCap = std::chrono::seconds(12);

    inline auto extract_header_value(std::string_view headers, std::string_view target_lower) noexcept -> std::string_view {
        auto rest = headers;
        while (!rest.empty()) {
            auto eol = rest.find("\r\n");
            auto line = rest.substr(0, eol);
            if (auto colon = line.find(':'); colon != std::string_view::npos) {
                auto name = line.substr(0, colon);
                if (name.size() == target_lower.size() && std::ranges::equal(name, target_lower,
                    [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == b; })) {
                    auto val = line.substr(colon + 1);
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.remove_prefix(1);
                    while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) val.remove_suffix(1);
                    return val;
                }
            }
            if (eol == std::string_view::npos) break;
            rest.remove_prefix(eol + 2);
        }
        return {};
    }

    inline auto match_cors_origin(std::span<std::string const> allowed, std::string_view origin) noexcept
        -> std::optional<std::string_view> {
        if (allowed.empty() || origin.empty()) return std::nullopt;
        if (std::ranges::any_of(origin, [](unsigned char c) { return c <= 0x20 || c >= 0x7f; }))
            return std::nullopt;
        bool has_wildcard = false;
        for (auto const& entry : allowed) {
            if (entry == origin) return std::string_view(entry);
            if (entry == "*") has_wildcard = true;
        }
        if (has_wildcard) return std::string_view("*");
        return std::nullopt;
    }

    inline auto cors_preflight_response(std::string_view matched_origin) -> std::string {
        return std::format(
            "HTTP/1.1 204 No Content\r\n"
            "Access-Control-Allow-Origin: {}\r\n"
            "Vary: Origin\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
            "Access-Control-Max-Age: 600\r\n"
            "Content-Length: 0\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n",
            matched_origin);
    }

    inline auto inject_cors_headers(std::string response, std::string_view matched_origin) -> std::string {
        if (matched_origin.empty()) return response;
        auto pos = response.find("\r\n\r\n");
        if (pos == std::string::npos) return response;
        auto extra = std::format("\r\nAccess-Control-Allow-Origin: {}\r\nVary: Origin", matched_origin);
        response.insert(pos, extra);
        return response;
    }

    inline auto render_rules_json(control_api::ControlSnapshot const& snap) -> std::string {
        std::string out = "{\"rules\":[";
        for (std::size_t i = 0; i < snap.rules.size(); ++i) {
            if (i) out.push_back(',');
            auto const& r = snap.rules[i];
            out += std::format("{{\"index\":{},\"type\":{},\"action\":{},\"target\":{},\"summary\":{}}}",
                r.index, json_escape(r.type), json_escape(r.action),
                json_escape(r.target), json_escape(r.summary));
        }
        out += "]}\n";
        return out;
    }

    inline auto handle_fakeip_flush(StreamCommandFn command) -> std::string {
        std::array<std::string_view, 1> args{"flush-fakeip"};
        auto res = command(args);
        if (!res) {
            int code = res.error() == "fakeip-unavailable" ? 409 : 500;
            return json_error(code, code == 409 ? "Conflict" : "Internal Server Error",
                res.error(), res.error());
        }
        std::string_view flushed = "0";
        if (res->starts_with("flushed=")) {
            flushed = std::string_view(*res).substr(8);
            while (!flushed.empty() && (flushed.back() == '\n' || flushed.back() == '\r')) flushed.remove_suffix(1);
        }
        return build_http_response(200, "OK", "application/json",
            std::format("{{\"flushed\":{},\"fakeip\":true}}\n", flushed.empty() ? "0" : flushed));
    }

    inline auto parse_json_bool(std::string_view body, std::string_view key) -> std::optional<bool> {
        auto pos = find_json_field_pos(body, key);
        if (!pos || *pos >= body.size()) return std::nullopt;
        auto rest = body.substr(*pos);
        auto valid_term = [](std::string_view tail) noexcept -> bool {
            if (tail.empty()) return true;
            char c = tail.front();
            return c == ',' || c == '}' || c == ' ' || c == '\t' || c == '\r' || c == '\n';
        };
        if (rest.starts_with("true") && valid_term(rest.substr(4))) return true;
        if (rest.starts_with("false") && valid_term(rest.substr(5))) return false;
        return std::nullopt;
    }

    inline auto parse_wire_selected(std::string_view wire) -> std::optional<std::string> {
        auto nl = wire.find('\n');
        auto line = nl == std::string_view::npos ? wire : wire.substr(0, nl);
        std::size_t pos = line.starts_with("selected=") ? 0 : line.find(" selected=");
        if (pos == std::string_view::npos) return std::nullopt;
        pos += line[pos] == ' ' ? 10 : 9;
        if (pos >= line.size()) return std::nullopt;
        if (line[pos] == '"') {
            std::string val;
            if (parse_json_string_at(line, pos, val)) return val;
            return std::nullopt;
        }
        auto sp = line.find(' ', pos);
        auto tok = sp == std::string_view::npos ? line.substr(pos) : line.substr(pos, sp - pos);
        return tok.empty() ? std::nullopt : std::optional<std::string>(std::string(tok));
    }

    inline auto parse_group_select_tag(std::string_view method, std::string_view path) noexcept
        -> std::optional<std::string_view> {
        if (method == "PUT" && path.starts_with("/v1/groups/")) {
            auto tag = path.substr(11);
            if (!tag.empty() && !tag.contains('/')) return tag;
        }
        if (method == "POST" && path.size() > 18 && path.starts_with("/v1/groups/") && path.ends_with("/select")) {
            auto tag = path.substr(11, path.size() - 18);
            if (!tag.empty() && !tag.contains('/')) return tag;
        }
        return std::nullopt;
    }

    inline auto handle_group_select(std::string_view raw_tag, std::string_view body,
        StreamSnapshotFn fetch, StreamCommandFn command) -> std::string {
        auto tag = url_decode_once(raw_tag);
        if (!tag || tag->empty())
            return json_error(400, "Bad Request", "invalid-group", "expected group name");
        if (!is_valid_json_object(body))
            return json_error(400, "Bad Request", "invalid-body", "expected JSON object");
        std::optional<bool> auto_flag;
        if (find_json_field_pos(body, "auto")) {
            auto_flag = parse_json_bool(body, "auto");
            if (!auto_flag)
                return json_error(400, "Bad Request", "invalid-body", "expected boolean \"auto\"");
        }
        std::optional<std::string> member;
        if (find_json_field_pos(body, "member")) {
            member = extract_json_string(body, "member");
            if (!member || member->empty())
                return json_error(400, "Bad Request", "invalid-body", "expected non-empty string \"member\"");
        }
        bool is_auto = false;
        std::string arg_member;
        if (auto_flag.value_or(false)) {
            if (member && *member != "--auto")
                return json_error(400, "Bad Request", "invalid-body", "cannot specify both \"auto\":true and \"member\"");
            is_auto = true;
            arg_member = "--auto";
        } else {
            if (!member)
                return json_error(400, "Bad Request", "invalid-body", "expected {\"member\":\"...\"} or {\"auto\":true}");
            is_auto = (*member == "--auto");
            arg_member = *member;
        }
        std::array<std::string_view, 3> args{"select", *tag, arg_member};
        auto res = command(args);
        if (!res) {
            int code = res.error() == "unknown-group" ? 404 : 409;
            return json_error(code, code == 404 ? "Not Found" : "Conflict", res.error(), res.error());
        }
        std::string resolved;
        if (auto parsed = parse_wire_selected(*res); parsed && !parsed->empty() && *parsed != "--auto") {
            resolved = std::move(*parsed);
        } else if (is_auto) {
            auto snap = fetch(SnapshotFields::groups, std::nullopt);
            if (auto it = std::ranges::find(snap.groups, *tag, &control_api::GroupMetric::name);
                it != snap.groups.end() && it->selected != "--auto") {
                resolved = it->selected;
            }
        } else {
            resolved = arg_member;
        }
        return build_http_response(200, "OK", "application/json",
            std::format("{{\"group\":{},\"selected\":{},\"result\":{}}}\n",
                json_escape(*tag), json_escape(resolved), json_escape(*res)));
    }

    inline auto handle_clear_cache(std::string_view query, std::string_view body, StreamCommandFn command) -> std::string {
        auto valid_target = [](std::string_view t) noexcept -> bool {
            return t == "all" || t == "dns" || t == "rulesets" || t == "fakeip";
        };
        std::string target = "all";
        bool has_scope = false;
        if (auto raw_scope = find_query_param_raw(query, "scope")) {
            auto decoded = url_decode_once(*raw_scope, true);
            if (!decoded)
                return json_error(400, "Bad Request", "invalid-target", "malformed scope query parameter");
            if (!decoded->empty()) {
                target = std::move(*decoded);
                has_scope = true;
            }
        }
        std::string_view trimmed = body;
        while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t' || trimmed.front() == '\r' || trimmed.front() == '\n'))
            trimmed.remove_prefix(1);
        while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t' || trimmed.back() == '\r' || trimmed.back() == '\n'))
            trimmed.remove_suffix(1);
        if (!trimmed.empty()) {
            if (!is_valid_json_object(trimmed))
                return json_error(400, "Bad Request", "invalid-body", "expected JSON object");
            if (find_json_field_pos(trimmed, "target")) {
                auto t = extract_json_string(trimmed, "target");
                if (!t || !valid_target(*t))
                    return json_error(400, "Bad Request", "invalid-target",
                        "expected target/scope in {\"all\",\"dns\",\"rulesets\",\"fakeip\"}");
                if (!has_scope) target = std::move(*t);
            }
        }
        if (!valid_target(target)) {
            return json_error(400, "Bad Request", "invalid-target",
                "expected target/scope in {\"all\",\"dns\",\"rulesets\",\"fakeip\"}");
        }
        std::array<std::string_view, 2> args{"clear-cache", target};
        auto res = command(args);
        if (!res) return json_error(409, "Conflict", res.error(), res.error());
        return build_http_response(200, "OK", "application/json",
            std::format("{{\"target\":{},\"cleared\":true,\"detail\":{}}}\n",
                json_escape(target), json_escape(*res)));
    }

    struct DnsQueryParams {
        std::string name;
        std::uint16_t qtype = 1;
        std::string type_name{"A"};
        std::string server;
    };

    inline auto valid_dns_query_name(std::string_view name) noexcept -> bool {
        if (name.ends_with('.')) name.remove_suffix(1);
        if (name.empty() || name.size() > 253) return false;
        std::size_t label = 0;
        for (unsigned char c : name) {
            if (c == '.') {
                if (!label || label > 63) return false;
                label = 0;
                continue;
            }
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return false;
            ++label;
        }
        return label > 0 && label <= 63;
    }

    inline auto parse_dns_qtype(std::string_view raw) -> std::optional<std::pair<std::uint16_t, std::string>> {
        if (raw.empty()) return std::pair{std::uint16_t{1}, std::string("A")};
        std::string up(raw);
        for (char& c : up) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        struct Entry { std::string_view name; std::uint16_t code; };
        constexpr std::array<Entry, 12> table{{
            {"A", 1}, {"NS", 2}, {"CNAME", 5}, {"SOA", 6}, {"PTR", 12},
            {"MX", 15}, {"TXT", 16}, {"AAAA", 28}, {"SRV", 33},
            {"SVCB", 64}, {"HTTPS", 65}, {"CAA", 257},
        }};
        for (auto const& e : table) {
            if (up == e.name) return std::pair{e.code, std::string(e.name)};
        }
        std::uint16_t num = 0;
        auto [end, ec] = std::from_chars(up.data(), up.data() + up.size(), num);
        if (ec == std::errc{} && end == up.data() + up.size() && num >= 1 && num != 41)
            return std::pair{num, "TYPE" + std::to_string(num)};
        return std::nullopt;
    }

    inline auto parse_dns_query_params(std::string_view query) -> std::expected<DnsQueryParams, std::string> {
        auto name = parse_query_param(query, "name");
        if (!name || !valid_dns_query_name(*name)) return std::unexpected("invalid-name");
        auto raw_type = parse_query_param(query, "type").value_or(std::string{});
        auto qt = parse_dns_qtype(raw_type);
        if (!qt) return std::unexpected("invalid-qtype");
        std::string server;
        if (auto srv = parse_query_param(query, "server"); srv && !srv->empty()) {
            if (srv->size() > 64 || std::ranges::any_of(*srv, [](unsigned char c) { return c <= 0x20 || c >= 0x7f; }))
                return std::unexpected("invalid-server");
            server = std::move(*srv);
        }
        return DnsQueryParams{std::move(*name), qt->first, std::move(qt->second), std::move(server)};
    }

    inline auto dns_query_error_response(std::string_view code) -> std::string {
        if (code == "invalid-name" || code == "invalid-qtype" || code == "invalid-server" || code == "invalid-id")
            return json_error(400, "Bad Request", code, code);
        if (code == "unknown-server" || code == "unknown-query")
            return json_error(404, "Not Found", code, code);
        if (code == "dns-query-busy")
            return json_error(429, "Too Many Requests", code, "DNS query queue is full");
        if (code == "dns-timeout")
            return json_error(504, "Gateway Timeout", code, "DNS query timed out");
        return json_error(409, "Conflict", code, code);
    }

    inline auto parse_pending_query_id(std::string_view wire) noexcept -> std::optional<std::uint64_t> {
        if (!wire.starts_with("id=")) return std::nullopt;
        auto rest = wire.substr(3);
        auto sp = rest.find_first_of(" \r\n");
        auto tok = sp == std::string_view::npos ? rest : rest.substr(0, sp);
        std::uint64_t id = 0;
        auto [end, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), id);
        if (ec != std::errc{} || end != tok.data() + tok.size() || !id) return std::nullopt;
        return id;
    }

    inline auto start_deferred_dns_query(Peer& peer, std::string_view query,
        StreamClock::time_point now, StreamCommandFn command) -> void {
        auto params = parse_dns_query_params(query);
        if (!params) {
            peer.out = inject_cors_headers(dns_query_error_response(params.error()), peer.cors_origin);
            peer.out_offset = 0;
            peer.writing = true;
            return;
        }
        auto qtype_str = std::to_string(params->qtype);
        std::expected<std::string, std::string> res;
        if (!params->server.empty()) {
            std::array<std::string_view, 4> args{"dns-query", params->name, qtype_str, params->server};
            res = command(args);
        } else {
            std::array<std::string_view, 3> args{"dns-query", params->name, qtype_str};
            res = command(args);
        }
        if (!res) {
            peer.out = inject_cors_headers(dns_query_error_response(res.error()), peer.cors_origin);
            peer.out_offset = 0;
            peer.writing = true;
            return;
        }
        if (res->starts_with('{')) {
            auto body = res->ends_with('\n') ? *res : (*res + "\n");
            peer.out = inject_cors_headers(build_http_response(200, "OK", "application/json", body), peer.cors_origin);
            peer.out_offset = 0;
            peer.writing = true;
            return;
        }
        auto qid = parse_pending_query_id(*res);
        if (!qid) {
            peer.out = inject_cors_headers(dns_query_error_response("dns-unavailable"), peer.cors_origin);
            peer.out_offset = 0;
            peer.writing = true;
            return;
        }
        peer.pending_dns_query_id = *qid;
        peer.probe_hard_deadline = now + kDnsQueryHardCap;
        peer.deadline = peer.probe_hard_deadline;
        peer.next_stream_poll = now;
    }

    inline auto poll_deferred_dns_query(Peer& peer, StreamClock::time_point now, StreamCommandFn command) -> void {
        auto id_str = std::to_string(peer.pending_dns_query_id);
        std::array<std::string_view, 2> args{"dns-query-result", id_str};
        auto res = command(args);
        if (!res) {
            peer.out = inject_cors_headers(dns_query_error_response(res.error()), peer.cors_origin);
            peer.out_offset = 0;
            peer.pending_dns_query_id = 0;
            peer.writing = true;
            peer.deadline = now + kPeerIoTimeout;
            return;
        }
        if (res->starts_with("state=pending")) {
            peer.deadline = std::min(peer.probe_hard_deadline, now + std::chrono::seconds(5));
            peer.next_stream_poll = now + kDnsQueryPollInterval;
            return;
        }
        auto body = res->ends_with('\n') ? *res : (*res + "\n");
        peer.out = inject_cors_headers(build_http_response(200, "OK", "application/json", body), peer.cors_origin);
        peer.out_offset = 0;
        peer.pending_dns_query_id = 0;
        peer.writing = true;
        peer.deadline = now + kPeerIoTimeout;
    }

    inline auto handle_direct_dns_query(std::string_view query, StreamCommandFn command) -> std::string {
        auto params = parse_dns_query_params(query);
        if (!params) return dns_query_error_response(params.error());
        auto qtype_str = std::to_string(params->qtype);
        std::expected<std::string, std::string> res;
        if (!params->server.empty()) {
            std::array<std::string_view, 4> args{"dns-query", params->name, qtype_str, params->server};
            res = command(args);
        } else {
            std::array<std::string_view, 3> args{"dns-query", params->name, qtype_str};
            res = command(args);
        }
        if (!res) return dns_query_error_response(res.error());
        if (res->starts_with('{')) {
            auto body = res->ends_with('\n') ? *res : (*res + "\n");
            return build_http_response(200, "OK", "application/json", body);
        }
        if (auto qid = parse_pending_query_id(*res)) {
            auto id_str = std::to_string(*qid);
            std::array<std::string_view, 2> rargs{"dns-query-result", id_str};
            if (auto r = command(rargs); r && r->starts_with('{')) {
                auto body = r->ends_with('\n') ? *r : (*r + "\n");
                return build_http_response(200, "OK", "application/json", body);
            }
            return build_http_response(202, "Accepted", "application/json",
                std::format("{{\"id\":{},\"name\":{},\"type\":{},\"state\":\"pending\"}}\n",
                    *qid, json_escape(params->name), json_escape(params->type_name)));
        }
        return dns_query_error_response("dns-unavailable");
    }
}
