// Private SSE streaming and deferred outbound-probe peer helpers for control_api HTTP server.
export module control_api.http_stream;

import std;
import control_api.http_format;
import control_api.http_socket;
import control_api.types;
import functional;

export namespace control_api::http_detail {
    using StreamClock = std::chrono::steady_clock;
    using StreamCommandFn = functional::function_ref<std::expected<std::string, std::string>(std::span<std::string_view const>)>;
    using StreamSnapshotFn = functional::function_ref<ControlSnapshot(SnapshotFields, std::optional<std::uint64_t>)>;

    inline constexpr auto kSseKeepalive = std::chrono::seconds(15);
    inline constexpr auto kSseStallDeadline = std::chrono::seconds(30);
    inline constexpr auto kPeerIoTimeout = std::chrono::seconds(2);
    inline constexpr auto kProbePollInterval = std::chrono::milliseconds(10);
    inline constexpr auto kProbeHardCap = std::chrono::seconds(65);
    inline constexpr std::string_view kDefaultProbeUrl = "https://www.gstatic.com/generate_204";
    inline constexpr std::string_view kSseHeaders =
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n";

    enum class StreamKind : std::uint8_t { none, logs, status, connections };

    struct Peer {
        Fd fd{Fd::kInvalidHandle};
        std::string in;
        std::string out;
        std::size_t out_offset = 0;
        bool writing = false;
        StreamKind stream = StreamKind::none;
        std::string stream_cursor{"0"};
        std::vector<std::string> stream_filters;
        std::chrono::milliseconds stream_interval{100};
        std::uint64_t pending_probe_id = 0;
        StreamClock::time_point deadline{};
        StreamClock::time_point probe_hard_deadline{};
        StreamClock::time_point next_stream_poll{};
        StreamClock::time_point last_sse_write{};

        [[nodiscard]] auto is_streaming() const noexcept -> bool { return stream != StreamKind::none; }
        [[nodiscard]] auto has_pending_probe() const noexcept -> bool { return pending_probe_id != 0; }
    };

    struct ParsedHttpRequest {
        std::string_view method, path, query, headers, body;
        bool valid = false;
    };

    inline auto parse_http_request_head(std::string_view raw, std::size_t hdr_end) noexcept -> ParsedHttpRequest {
        auto head = raw.substr(0, hdr_end);
        auto body = raw.substr(hdr_end + 4);
        auto first_eol = head.find("\r\n");
        auto req_line = head.substr(0, first_eol);
        auto sp1 = req_line.find(' ');
        auto sp2 = sp1 == std::string_view::npos ? std::string_view::npos : req_line.find(' ', sp1 + 1);
        if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) return {};
        auto method = req_line.substr(0, sp1);
        auto target = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
        std::string_view path = target, query;
        if (auto q = target.find('?'); q != std::string_view::npos) {
            path = target.substr(0, q);
            query = target.substr(q + 1);
        }
        auto headers = first_eol == std::string_view::npos ? std::string_view{} : head.substr(first_eol + 2);
        return {method, path, query, headers, body, true};
    }

    inline auto detect_stream_kind(std::string_view method, std::string_view path, std::string_view query) -> StreamKind {
        if (method != "GET") return StreamKind::none;
        auto flag = parse_query_param(query, "stream");
        if (!flag || (*flag != "1" && *flag != "true")) return StreamKind::none;
        if (path == "/v1/logs") return StreamKind::logs;
        if (path == "/v1/status") return StreamKind::status;
        if (path == "/v1/connections") return StreamKind::connections;
        return StreamKind::none;
    }

    inline auto parse_stream_interval_ms(std::string_view query) -> std::chrono::milliseconds {
        auto raw = parse_query_param(query, "interval_ms");
        if (!raw || raw->empty()) return std::chrono::milliseconds(1000);
        std::uint64_t val = 0;
        auto [end, ec] = std::from_chars(raw->data(), raw->data() + raw->size(), val);
        if (ec != std::errc{} || end != raw->data() + raw->size()) return std::chrono::milliseconds(1000);
        return std::chrono::milliseconds(std::clamp<std::uint64_t>(val, 200u, 10000u));
    }

    inline auto format_sse_frame(std::string_view event_name, std::string json_line) -> std::string {
        while (!json_line.empty() && (json_line.back() == '\n' || json_line.back() == '\r'))
            json_line.pop_back();
        std::string out;
        out.reserve(event_name.size() + json_line.size() + 18);
        out += "event: ";
        out += event_name;
        out += "\ndata: ";
        out += json_line;
        out += "\n\n";
        return out;
    }

    inline auto render_stream_snapshot_frame(StreamKind kind, StreamSnapshotFn fetch_snap) -> std::string {
        if (kind == StreamKind::status) {
            return format_sse_frame("status",
                render_status_json(fetch_snap(SnapshotFields::meta | SnapshotFields::listeners, std::nullopt)));
        }
        if (kind == StreamKind::connections) {
            return format_sse_frame("connections",
                render_connections_json(fetch_snap(SnapshotFields::connections, std::nullopt)));
        }
        return {};
    }

    inline auto setup_sse_peer(Peer& peer, StreamKind kind, std::string_view query,
        StreamClock::time_point now, StreamSnapshotFn fetch_snap) -> void {
        peer.stream = kind;
        peer.out.assign(kSseHeaders);
        peer.out_offset = 0;
        peer.writing = true;
        peer.last_sse_write = now;
        peer.deadline = now + kSseStallDeadline;
        if (kind == StreamKind::logs) {
            if (auto v = parse_query_param(query, "since"); v && !v->empty()) peer.stream_cursor = *v;
            for (std::string_view k : {"level", "domain", "search"})
                if (auto v = parse_query_param(query, k); v && !v->empty())
                    peer.stream_filters.push_back(std::string(k) + "=" + *v);
            peer.stream_interval = std::chrono::milliseconds(100);
            peer.next_stream_poll = now;
        } else {
            peer.stream_interval = parse_stream_interval_ms(query);
            peer.out += render_stream_snapshot_frame(kind, fetch_snap);
            peer.next_stream_poll = now + peer.stream_interval;
        }
    }

    inline auto tick_sse_peer(Peer& peer, StreamClock::time_point now,
        StreamSnapshotFn fetch_snap, StreamCommandFn command) -> void {
        peer.next_stream_poll = now + peer.stream_interval;
        if (peer.stream == StreamKind::logs) {
            std::vector<std::string> owned{"logs", "since=" + peer.stream_cursor, "limit=64"};
            owned.insert(owned.end(), peer.stream_filters.begin(), peer.stream_filters.end());
            std::vector<std::string_view> args;
            args.reserve(owned.size());
            for (auto const& s : owned) args.emplace_back(s);
            if (auto res = command(args); res) {
                peer.out = format_sse_logs(*res, peer.stream_cursor);
                if (peer.out.empty() && now - peer.last_sse_write >= kSseKeepalive)
                    peer.out = ": keepalive\n\n";
                peer.out_offset = 0;
            }
            return;
        }
        peer.out = render_stream_snapshot_frame(peer.stream, fetch_snap);
        if (peer.out.empty() && now - peer.last_sse_write >= kSseKeepalive)
            peer.out = ": keepalive\n\n";
        peer.out_offset = 0;
    }

    struct ProbeRequestParams {
        std::string url{kDefaultProbeUrl};
        std::uint32_t timeout_ms = 5000;
        std::string mode{"http"};
    };

    inline auto is_outbound_probe_route(std::string_view method, std::string_view path) noexcept -> bool {
        return method == "POST" && path.size() > 20 &&
            path.starts_with("/v1/outbounds/") && path.ends_with("/probe");
    }

    inline auto probe_error_response(std::string_view code) -> std::string {
        if (code == "unknown-outbound" || code == "unknown-probe")
            return json_error(404, "Not Found", code, code);
        if (code == "invalid-probe-url" || code == "invalid-body" || code == "invalid-timeout" ||
            code == "invalid-mode" || code == "invalid-outbound" || code == "invalid-id")
            return json_error(400, "Bad Request", code, code);
        if (code == "probe-busy")
            return json_error(429, "Too Many Requests", code, "probe queue is full");
        return json_error(409, "Conflict", code, code);
    }

    inline auto parse_probe_body(std::string_view body) -> std::expected<ProbeRequestParams, std::string> {
        while (!body.empty() && (body.front() == ' ' || body.front() == '\t' || body.front() == '\r' || body.front() == '\n'))
            body.remove_prefix(1);
        while (!body.empty() && (body.back() == ' ' || body.back() == '\t' || body.back() == '\r' || body.back() == '\n'))
            body.remove_suffix(1);
        ProbeRequestParams params{};
        if (body.empty()) return params;
        if (!is_valid_json_object(body)) return std::unexpected("invalid-body");
        if (find_json_field_pos(body, "url")) {
            auto u = extract_json_string(body, "url");
            if (!u || u->empty()) return std::unexpected("invalid-probe-url");
            params.url = std::move(*u);
        }
        if (find_json_field_pos(body, "timeout_ms")) {
            auto t = extract_json_uint(body, "timeout_ms");
            if (!t || *t == 0 || *t > 3600000u) return std::unexpected("invalid-timeout");
            params.timeout_ms = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(*t, 200u, 30000u));
        }
        if (find_json_field_pos(body, "mode")) {
            auto m = extract_json_string(body, "mode");
            if (!m || (*m != "http" && *m != "h2-ping")) return std::unexpected("invalid-mode");
            params.mode = std::move(*m);
        }
        return params;
    }

    struct ParsedProbeWire {
        std::uint64_t id = 0;
        std::string outbound;
        std::string resolved;
        std::string state;
        std::optional<std::uint64_t> latency_ms;
        std::optional<std::uint16_t> status_code;
        std::string url;
    };

    inline auto parse_probe_wire(std::string_view wire) -> ParsedProbeWire {
        ParsedProbeWire out{};
        auto nl = wire.find('\n');
        auto line = nl == std::string_view::npos ? wire : wire.substr(0, nl);
        while (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        while (!line.empty()) {
            while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
            if (line.empty()) break;
            auto sp = line.find(' ');
            auto tok = sp == std::string_view::npos ? line : line.substr(0, sp);
            line = sp == std::string_view::npos ? std::string_view{} : line.substr(sp + 1);
            auto eq = tok.find('=');
            if (eq == std::string_view::npos) continue;
            auto k = tok.substr(0, eq), v = tok.substr(eq + 1);
            if (k == "id") {
                std::uint64_t n = 0;
                auto [e, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
                if (ec == std::errc{} && e == v.data() + v.size()) out.id = n;
            } else if (k == "outbound") {
                out.outbound = std::string(v);
            } else if (k == "resolved") {
                out.resolved = std::string(v);
            } else if (k == "state") {
                out.state = std::string(v);
            } else if (k == "latency-ms") {
                std::uint64_t n = 0;
                auto [e, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
                if (ec == std::errc{} && e == v.data() + v.size()) out.latency_ms = n;
            } else if (k == "status-code") {
                std::uint16_t n = 0;
                auto [e, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
                if (ec == std::errc{} && e == v.data() + v.size()) out.status_code = n;
            } else if (k == "url") {
                out.url = std::string(v);
            }
        }
        return out;
    }

    inline auto render_probe_result_json(ParsedProbeWire const& r) -> std::string {
        std::string out = std::format("{{\"outbound\":{},\"resolved_outbound\":{},\"state\":{},\"latency_ms\":",
            json_escape(r.outbound), json_escape(r.resolved), json_escape(r.state));
        if (r.latency_ms) out += std::to_string(*r.latency_ms);
        else out += "null";
        if (r.status_code) out += std::format(",\"status_code\":{}", *r.status_code);
        out += std::format(",\"url\":{}}}\n", json_escape(r.url));
        return out;
    }

    inline auto invoke_outbound_probe(std::string_view path, std::string_view body, StreamCommandFn command)
        -> std::expected<std::pair<ParsedProbeWire, std::uint32_t>, std::string> {
        auto raw_tag = path.substr(14, path.size() - 20);
        auto tag = url_decode_once(raw_tag);
        if (!tag || tag->empty() || tag->contains('/'))
            return std::unexpected(probe_error_response("invalid-outbound"));
        auto params = parse_probe_body(body);
        if (!params) return std::unexpected(probe_error_response(params.error()));
        auto timeout_str = std::to_string(params->timeout_ms);
        std::array<std::string_view, 5> args{"probe-outbound", *tag, params->url, timeout_str, params->mode};
        auto enqueued = command(args);
        if (!enqueued) return std::unexpected(probe_error_response(enqueued.error()));
        auto parsed = parse_probe_wire(*enqueued);
        if (!parsed.id) return std::unexpected(probe_error_response("probe-unavailable"));
        if (parsed.url.empty()) parsed.url = params->url;
        return std::pair{std::move(parsed), params->timeout_ms};
    }

    inline auto start_deferred_probe(Peer& peer, std::string_view path, std::string_view body,
        StreamClock::time_point now, StreamCommandFn command) -> void {
        auto started = invoke_outbound_probe(path, body, command);
        if (!started) {
            peer.out = std::move(started.error());
            peer.out_offset = 0;
            peer.writing = true;
            return;
        }
        peer.pending_probe_id = started->first.id;
        peer.probe_hard_deadline = now + kProbeHardCap;
        peer.deadline = std::min(peer.probe_hard_deadline,
            now + std::chrono::milliseconds(started->second) + std::chrono::seconds(2));
        peer.next_stream_poll = now;
    }

    inline auto poll_deferred_probe(Peer& peer, StreamClock::time_point now, StreamCommandFn command) -> void {
        auto id_str = std::to_string(peer.pending_probe_id);
        std::array<std::string_view, 2> args{"probe-result", id_str};
        auto res = command(args);
        if (!res) {
            peer.out = probe_error_response(res.error());
            peer.out_offset = 0;
            peer.pending_probe_id = 0;
            peer.writing = true;
            peer.deadline = now + kPeerIoTimeout;
            return;
        }
        auto parsed = parse_probe_wire(*res);
        if (parsed.state == "pending") {
            peer.deadline = std::min(peer.probe_hard_deadline, now + std::chrono::seconds(5));
            peer.next_stream_poll = now + kProbePollInterval;
            return;
        }
        peer.out = build_http_response(200, "OK", "application/json", render_probe_result_json(parsed));
        peer.out_offset = 0;
        peer.pending_probe_id = 0;
        peer.writing = true;
        peer.deadline = now + kPeerIoTimeout;
    }

    inline auto handle_direct_outbound_probe(std::string_view path, std::string_view body,
        StreamCommandFn command) -> std::string {
        auto started = invoke_outbound_probe(path, body, command);
        if (!started) return std::move(started.error());
        auto id_str = std::to_string(started->first.id);
        std::array<std::string_view, 2> args{"probe-result", id_str};
        if (auto res = command(args); res) {
            auto parsed = parse_probe_wire(*res);
            if (parsed.state != "pending")
                return build_http_response(200, "OK", "application/json", render_probe_result_json(parsed));
        }
        auto const& p = started->first;
        return build_http_response(202, "Accepted", "application/json",
            std::format("{{\"id\":{},\"outbound\":{},\"resolved_outbound\":{},\"state\":\"pending\",\"url\":{}}}\n",
                p.id, json_escape(p.outbound), json_escape(p.resolved), json_escape(p.url)));
    }

    inline auto flush_peer_writes(Peer& peer, StreamClock::time_point now) noexcept -> bool {
        while (peer.out_offset < peer.out.size()) {
            std::size_t n = 0;
            auto status = send_nonblocking(peer.fd,
                std::span<char const>(peer.out.data() + peer.out_offset, peer.out.size() - peer.out_offset), n);
            if (status == SocketIoStatus::ok) {
                peer.out_offset += n;
                if (peer.is_streaming() && n > 0) {
                    peer.last_sse_write = now;
                    peer.deadline = now + kSseStallDeadline;
                }
            } else {
                return status == SocketIoStatus::closed;
            }
        }
        return !peer.is_streaming() && peer.out_offset >= peer.out.size();
    }

    inline auto compute_peers_poll_delay(std::span<Peer const> peers, StreamClock::time_point now) noexcept
        -> std::optional<std::chrono::milliseconds> {
        if (peers.empty()) return std::nullopt;
        std::chrono::milliseconds min_wait(100);
        for (auto const& p : peers) {
            if ((!p.is_streaming() && !p.has_pending_probe()) || p.out_offset < p.out.size())
                return std::chrono::milliseconds(5);
            auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(p.next_stream_poll - now);
            min_wait = std::min(min_wait, std::max(rem, std::chrono::milliseconds(1)));
        }
        return min_wait;
    }
}
