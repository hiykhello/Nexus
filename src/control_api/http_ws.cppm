// RFC 6455 multiplexed WebSocket transport (/v1/ws) for control_api HTTP server.
export module control_api.http_ws;

import std;
import control_api.http_extra_routes;
import control_api.http_format;
import control_api.http_socket;
import control_api.http_stream;
import control_api.types;
import crypto;
import encoding.base64;

export namespace control_api::http_detail {
    inline constexpr std::string_view kWsMagicGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    inline constexpr std::size_t kMaxWsPeers = 16;
    inline constexpr std::size_t kMaxWsFrameBytes = 64 * 1024;
    inline constexpr std::size_t kMaxWsOutBytes = 512 * 1024;
    inline constexpr auto kWsAuthTimeout = std::chrono::seconds(5);
    inline constexpr auto kWsIdleTimeout = std::chrono::seconds(60);
    inline constexpr auto kWsPingInterval = std::chrono::seconds(20);
    inline constexpr auto kWsLogPollInterval = std::chrono::milliseconds(100);

    inline constexpr std::uint8_t kWsChanLogs = 1u << 0;
    inline constexpr std::uint8_t kWsChanConnections = 1u << 1;
    inline constexpr std::uint8_t kWsChanMetrics = 1u << 2;

    enum class WsAuthState : std::uint8_t { pending_auth, authenticated };
    enum class WsDecodeStatus : std::uint8_t { need_more, frame, protocol_error, too_large };

    struct WsDecodedFrame { std::uint8_t opcode = 0; bool fin = true; std::string payload; };
    struct WsUpgradeResult { bool upgraded = false, authenticated = false, auth_failed = false; std::string http_response; };

    struct WsPeer {
        Fd fd{Fd::kInvalidHandle};
        std::string in, out;
        std::size_t out_offset = 0;
        WsAuthState auth = WsAuthState::pending_auth;
        std::uint8_t channels = 0, frag_opcode = 0;
        std::string log_cursor{"0"}, frag_buf;
        std::vector<std::string> log_filters;
        std::chrono::milliseconds interval{1000};
        bool frag_active = false, closing = false;
        StreamClock::time_point auth_deadline{}, idle_deadline{}, next_log_poll{}, next_snap_poll{}, last_ping_sent{};
    };

    inline auto ws_iequals(std::string_view a, std::string_view b) noexcept -> bool {
        return a.size() == b.size() && std::ranges::equal(a, b, [](char x, char y) {
            return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
        });
    }

    inline auto ws_trim(std::string_view s) noexcept -> std::string_view {
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
        return s;
    }

    inline auto header_has_token_ci(std::string_view val, std::string_view token_lower) noexcept -> bool {
        while (!val.empty()) {
            auto comma = val.find(',');
            if (ws_iequals(ws_trim(comma == std::string_view::npos ? val : val.substr(0, comma)), token_lower)) return true;
            if (comma == std::string_view::npos) break;
            val.remove_prefix(comma + 1);
        }
        return false;
    }

    inline auto query_has_forbidden_secret(std::string_view query) noexcept -> bool {
        while (!query.empty()) {
            auto amp = query.find('&');
            auto pair = amp == std::string_view::npos ? query : query.substr(0, amp);
            auto eq = pair.find('=');
            auto key = eq == std::string_view::npos ? pair : pair.substr(0, eq);
            if (ws_iequals(key, "token") || ws_iequals(key, "secret")) return true;
            if (amp == std::string_view::npos) break;
            query.remove_prefix(amp + 1);
        }
        return false;
    }

    inline auto is_loopback_origin(std::string_view origin) noexcept -> bool {
        if (origin.size() < 9 || origin.size() > 256) return false;
        if (std::ranges::any_of(origin, [](unsigned char c) { return c <= 0x20 || c >= 0x7f; })) return false;
        std::string_view rest = origin.starts_with("http://") ? origin.substr(7)
            : (origin.starts_with("https://") ? origin.substr(8) : std::string_view{});
        if (rest.empty() || rest.contains('/') || rest.contains('@') || rest.contains('?') || rest.contains('#')) return false;
        auto all_digits = [](std::string_view p) noexcept {
            return !p.empty() && std::ranges::all_of(p, [](unsigned char c) { return c >= '0' && c <= '9'; });
        };
        if (rest.front() == '[') {
            auto rb = rest.find(']');
            if (rb == std::string_view::npos) return false;
            auto tail = rest.substr(rb + 1);
            if (!tail.empty() && (tail.front() != ':' || !all_digits(tail.substr(1)))) return false;
            return rest.substr(0, rb + 1) == "[::1]";
        }
        std::string_view host = rest;
        if (auto colon = rest.find(':'); colon != std::string_view::npos) {
            if (!all_digits(rest.substr(colon + 1))) return false;
            host = rest.substr(0, colon);
        }
        return host == "127.0.0.1" || ws_iequals(host, "localhost");
    }

    inline auto ws_origin_allowed(std::span<std::string const> cors_allow_origins, std::string_view origin) noexcept -> bool {
        return origin.empty() || is_loopback_origin(origin) || match_cors_origin(cors_allow_origins, origin).has_value();
    }

    inline auto compute_ws_accept(std::string_view sec_ws_key) -> std::optional<std::string> {
        if (sec_ws_key.size() != 24) return std::nullopt;
        std::vector<std::uint8_t> decoded;
        if (!encoding::decode_base64_strict(sec_ws_key, decoded) || decoded.size() != 16) return std::nullopt;
        std::array<char, 24 + kWsMagicGuid.size()> buf{};
        std::ranges::copy(sec_ws_key, buf.begin());
        std::ranges::copy(kWsMagicGuid, buf.begin() + 24);
        std::array<std::uint8_t, 20> digest{};
        unsigned digest_len = 0;
        if (!boringssl::EVP_Digest(buf.data(), buf.size(), digest.data(), &digest_len,
                boringssl::EVP_sha1(), nullptr) || digest_len != digest.size()) return std::nullopt;
        return encoding::encode_base64(digest);
    }

    inline auto evaluate_ws_upgrade(ParsedHttpRequest const& req, std::span<std::uint8_t const> expected_token,
        std::span<std::string const> cors_allow_origins) -> WsUpgradeResult {
        if (req.method != "GET")
            return {false, false, false, json_error(405, "Method Not Allowed", "method-not-allowed", "WebSocket requires GET")};
        if (query_has_forbidden_secret(req.query))
            return {false, false, true, json_error(400, "Bad Request", "url-token-forbidden", "token must not be passed in URL query")};
        if (!ws_origin_allowed(cors_allow_origins, extract_header_value(req.headers, "origin")))
            return {false, false, false, json_error(403, "Forbidden", "origin-denied", "WebSocket origin is not allowed")};
        if (!header_has_token_ci(extract_header_value(req.headers, "upgrade"), "websocket") ||
            !header_has_token_ci(extract_header_value(req.headers, "connection"), "upgrade")) {
            constexpr std::string_view body = "{\"error\":{\"code\":\"upgrade-required\",\"message\":\"expected Upgrade: websocket\"}}\n";
            return {false, false, false, std::format(
                "HTTP/1.1 426 Upgrade Required\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                "Content-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}", body.size(), body)};
        }
        auto accept = extract_header_value(req.headers, "sec-websocket-version") == "13"
            ? compute_ws_accept(extract_header_value(req.headers, "sec-websocket-key")) : std::nullopt;
        if (!accept)
            return {false, false, false, json_error(400, "Bad Request", "invalid-websocket-handshake", "invalid Sec-WebSocket headers")};
        bool authed = expected_token.empty();
        if (!authed && !extract_header_value(req.headers, "authorization").empty()) {
            auto provided = extract_bearer_token(req.headers);
            auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(provided.data()), provided.size());
            if (provided.empty() || !crypto::constant_time_equal(expected_token, bytes))
                return {false, false, true, json_error(401, "Unauthorized", "unauthorized", "invalid bearer token")};
            authed = true;
        }
        return {true, authed, false, std::format(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            *accept)};
    }

    inline auto try_upgrade_ws_peer(Peer& peer, ParsedHttpRequest const& req, std::size_t hdr_end, std::size_t content_len,
        std::vector<WsPeer>& ws_peers, std::span<std::uint8_t const> expected_token,
        std::span<std::string const> cors_allow_origins, StreamClock::time_point now,
        std::uint64_t& authorized, std::uint64_t& unauthorized) -> bool {
        if (content_len > 0) {
            peer.out = inject_cors_headers(json_error(400, "Bad Request", "invalid-websocket-handshake", "GET /v1/ws forbids body"), peer.cors_origin);
            peer.writing = true;
            return false;
        }
        auto up = evaluate_ws_upgrade(req, expected_token, cors_allow_origins);
        if (up.auth_failed) ++unauthorized;
        if (!up.upgraded) {
            peer.out = inject_cors_headers(std::move(up.http_response), peer.cors_origin);
            peer.writing = true;
            return false;
        }
        if (ws_peers.size() >= kMaxWsPeers) {
            peer.out = json_error(503, "Service Unavailable", "ws-capacity", "too many WebSocket peers");
            peer.writing = true;
            return false;
        }
        if (up.authenticated) ++authorized;
        WsPeer wp{};
        wp.fd = std::move(peer.fd);
        wp.out = std::move(up.http_response);
        wp.auth = up.authenticated ? WsAuthState::authenticated : WsAuthState::pending_auth;
        if (peer.in.size() > hdr_end + 4) wp.in.assign(peer.in.substr(hdr_end + 4));
        wp.auth_deadline = now + kWsAuthTimeout;
        wp.idle_deadline = now + kWsIdleTimeout;
        wp.last_ping_sent = now;
        ws_peers.push_back(std::move(wp));
        return true;
    }

    inline auto encode_ws_frame(std::uint8_t opcode, std::string_view payload) -> std::string {
        std::string out;
        out.reserve(payload.size() + 10);
        out.push_back(static_cast<char>(0x80u | (opcode & 0x0fu)));
        if (payload.size() < 126) {
            out.push_back(static_cast<char>(payload.size()));
        } else if (payload.size() <= 0xffffu) {
            out.push_back(static_cast<char>(126));
            out.push_back(static_cast<char>((payload.size() >> 8) & 0xffu));
            out.push_back(static_cast<char>(payload.size() & 0xffu));
        } else {
            out.push_back(static_cast<char>(127));
            std::uint64_t n = static_cast<std::uint64_t>(payload.size());
            for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<char>((n >> shift) & 0xffu));
        }
        out.append(payload);
        return out;
    }

    inline auto encode_ws_close_frame(std::uint16_t code, std::string_view reason = {}) -> std::string {
        if (reason.size() > 123) reason = reason.substr(0, 123);
        std::string body; body.reserve(2 + reason.size());
        body.push_back(static_cast<char>((code >> 8) & 0xffu));
        body.push_back(static_cast<char>(code & 0xffu));
        body.append(reason);
        return encode_ws_frame(0x8, body);
    }

    inline auto decode_ws_client_frame(std::string& in, WsDecodedFrame& out,
        std::size_t max_bytes = kMaxWsFrameBytes) -> WsDecodeStatus {
        if (in.size() < 2) return WsDecodeStatus::need_more;
        auto b0 = static_cast<std::uint8_t>(in[0]), b1 = static_cast<std::uint8_t>(in[1]);
        if ((b0 & 0x70u) != 0 || (b1 & 0x80u) == 0) return WsDecodeStatus::protocol_error;
        bool fin = (b0 & 0x80u) != 0;
        std::uint8_t op = b0 & 0x0fu;
        if (op != 0x0 && op != 0x1 && op != 0x2 && op != 0x8 && op != 0x9 && op != 0xA)
            return WsDecodeStatus::protocol_error;
        std::uint64_t len = b1 & 0x7fu;
        std::size_t hdr = 2;
        if (op >= 0x8 && (!fin || len >= 126)) return WsDecodeStatus::protocol_error;
        if (len == 126) {
            if (in.size() < 4) return WsDecodeStatus::need_more;
            len = (std::uint64_t{static_cast<std::uint8_t>(in[2])} << 8) | static_cast<std::uint8_t>(in[3]);
            hdr = 4;
        } else if (len == 127) {
            if (in.size() < 10) return WsDecodeStatus::need_more;
            if ((static_cast<std::uint8_t>(in[2]) & 0x80u) != 0) return WsDecodeStatus::protocol_error;
            len = 0;
            for (std::size_t i = 0; i < 8; ++i) len = (len << 8) | static_cast<std::uint8_t>(in[2 + i]);
            hdr = 10;
        }
        if (len > max_bytes) return WsDecodeStatus::too_large;
        std::size_t total = hdr + 4 + static_cast<std::size_t>(len);
        if (in.size() < total) return WsDecodeStatus::need_more;
        std::array<std::uint8_t, 4> mask{};
        for (std::size_t i = 0; i < 4; ++i) mask[i] = static_cast<std::uint8_t>(in[hdr + i]);
        out.fin = fin; out.opcode = op;
        out.payload.resize(static_cast<std::size_t>(len));
        for (std::size_t i = 0; i < out.payload.size(); ++i)
            out.payload[i] = static_cast<char>(static_cast<std::uint8_t>(in[hdr + 4 + i]) ^ mask[i & 3u]);
        in.erase(0, total);
        return WsDecodeStatus::frame;
    }

    inline auto extract_json_string_array(std::string_view body, std::string_view key)
        -> std::optional<std::vector<std::string>> {
        auto pos = find_json_field_pos(body, key);
        if (!pos || *pos >= body.size() || body[*pos] != '[') return std::nullopt;
        std::size_t p = *pos + 1;
        auto skip_ws = [&]() noexcept {
            while (p < body.size() && (body[p] == ' ' || body[p] == '\t' || body[p] == '\r' || body[p] == '\n')) ++p;
        };
        std::vector<std::string> items;
        skip_ws();
        if (p < body.size() && body[p] == ']') return items;
        for (;;) {
            std::string item;
            if (!parse_json_string_at(body, p, item) || items.size() >= 16) return std::nullopt;
            items.push_back(std::move(item));
            skip_ws();
            if (p >= body.size()) return std::nullopt;
            if (body[p] == ']') return items;
            if (body[p++] != ',') return std::nullopt;
        }
    }

    inline auto format_ws_channels_reply(std::uint8_t channels) -> std::string {
        std::string out = "{\"type\":\"subscribed\",\"channels\":[";
        bool first = true;
        auto add = [&](std::uint8_t bit, std::string_view name) {
            if (!(channels & bit)) return;
            if (!first) out.push_back(',');
            first = false; out.push_back('"'); out.append(name); out.push_back('"');
        };
        add(kWsChanLogs, "logs"); add(kWsChanConnections, "connections"); add(kWsChanMetrics, "metrics");
        return out + "]}";
    }

    inline auto ws_strip_trailing_nl(std::string s) -> std::string {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    }

    inline auto queue_ws_text(WsPeer& peer, std::string_view json) -> void { peer.out += encode_ws_frame(0x1, json); }
    inline auto queue_ws_close(WsPeer& peer, std::uint16_t code, std::string_view reason = {}) -> void {
        if (peer.closing) return;
        peer.closing = true;
        peer.out += encode_ws_close_frame(code, reason);
    }

    inline auto push_ws_logs(WsPeer& peer, StreamCommandFn command) -> void {
        std::vector<std::string> owned{"logs", "since=" + peer.log_cursor, "limit=64"};
        owned.insert(owned.end(), peer.log_filters.begin(), peer.log_filters.end());
        std::vector<std::string_view> args; args.reserve(owned.size());
        for (auto const& s : owned) args.emplace_back(s);
        if (auto res = command(args); res) {
            auto parsed = parse_logs_wire(*res);
            advance_log_cursor(peer.log_cursor, parsed);
            for (auto const& entry : parsed.entry_jsons)
                queue_ws_text(peer, std::format("{{\"type\":\"log\",\"data\":{}}}", entry));
        }
    }

    inline auto push_ws_snapshots(WsPeer& peer, std::uint8_t mask, StreamSnapshotFn fetch_snap) -> void {
        if (mask & kWsChanConnections) {
            auto body = ws_strip_trailing_nl(render_connections_json(fetch_snap(SnapshotFields::connections, std::nullopt)));
            queue_ws_text(peer, std::format("{{\"type\":\"connections\",\"data\":{}}}", body));
        }
        if (mask & kWsChanMetrics) {
            auto body = ws_strip_trailing_nl(render_status_json(fetch_snap(SnapshotFields::meta | SnapshotFields::listeners, std::nullopt)));
            queue_ws_text(peer, std::format("{{\"type\":\"metrics\",\"data\":{}}}", body));
        }
    }

    inline auto handle_ws_text_message(WsPeer& peer, std::string_view text, std::span<std::uint8_t const> expected_token,
        StreamClock::time_point now, StreamSnapshotFn fetch_snap, StreamCommandFn command,
        std::uint64_t& authorized, std::uint64_t& unauthorized) -> void {
        if (!is_valid_json_object(text)) {
            if (peer.auth == WsAuthState::pending_auth) { ++unauthorized; queue_ws_close(peer, 4401, "unauthorized"); }
            else queue_ws_text(peer, "{\"type\":\"error\",\"code\":\"invalid-json\",\"message\":\"expected JSON object\"}");
            return;
        }
        auto type = extract_json_string(text, "type");
        if (peer.auth == WsAuthState::pending_auth) {
            auto tok = (type && *type == "auth") ? extract_json_string(text, "token") : std::nullopt;
            bool ok = tok && crypto::constant_time_equal(expected_token,
                std::span(reinterpret_cast<std::uint8_t const*>(tok->data()), tok->size()));
            if (!ok) { ++unauthorized; queue_ws_close(peer, 4401, "unauthorized"); return; }
            ++authorized;
            peer.auth = WsAuthState::authenticated;
            queue_ws_text(peer, "{\"type\":\"auth_ok\"}");
            return;
        }
        if (!type || type->empty()) {
            queue_ws_text(peer, "{\"type\":\"error\",\"code\":\"missing-type\",\"message\":\"missing message type\"}");
            return;
        }
        if (*type == "auth") { queue_ws_text(peer, "{\"type\":\"auth_ok\"}"); return; }
        if (*type == "ping") { queue_ws_text(peer, "{\"type\":\"pong\"}"); return; }
        if (*type == "subscribe") {
            auto list = extract_json_string_array(text, "channels");
            if (!list || list->empty()) {
                queue_ws_text(peer, "{\"type\":\"error\",\"code\":\"invalid-channels\",\"message\":\"expected non-empty channels array\"}");
                return;
            }
            std::uint8_t added = 0;
            for (auto const& ch : *list) {
                if (ch == "logs") added |= kWsChanLogs;
                else if (ch == "connections") added |= kWsChanConnections;
                else if (ch == "metrics") added |= kWsChanMetrics;
                else {
                    queue_ws_text(peer, std::format("{{\"type\":\"error\",\"code\":\"invalid-channel\",\"message\":{}}}",
                        json_escape("unknown channel: " + ch)));
                    return;
                }
            }
            if (find_json_field_pos(text, "since")) {
                if (auto s = extract_json_uint(text, "since")) peer.log_cursor = std::to_string(*s);
                else if (auto ss = extract_json_string(text, "since"); ss && !ss->empty() && ss->size() <= 20 &&
                    std::ranges::all_of(*ss, [](unsigned char c) { return c >= '0' && c <= '9'; })) peer.log_cursor = *ss;
                else { queue_ws_text(peer, "{\"type\":\"error\",\"code\":\"invalid-since\",\"message\":\"expected unsigned integer since\"}"); return; }
            }
            if (auto ms = extract_json_uint(text, "interval_ms"))
                peer.interval = std::chrono::milliseconds(std::clamp<std::uint64_t>(*ms, 200u, 10000u));
            peer.channels |= added;
            queue_ws_text(peer, format_ws_channels_reply(peer.channels));
            if (added & kWsChanLogs) { push_ws_logs(peer, command); peer.next_log_poll = now + kWsLogPollInterval; }
            if (added & (kWsChanConnections | kWsChanMetrics)) { push_ws_snapshots(peer, added, fetch_snap); peer.next_snap_poll = now + peer.interval; }
            return;
        }
        if (*type == "unsubscribe") {
            auto list = extract_json_string_array(text, "channels");
            if (!list) { queue_ws_text(peer, "{\"type\":\"error\",\"code\":\"invalid-channels\",\"message\":\"expected channels array\"}"); return; }
            for (auto const& ch : *list) {
                if (ch == "logs") peer.channels &= static_cast<std::uint8_t>(~kWsChanLogs);
                else if (ch == "connections") peer.channels &= static_cast<std::uint8_t>(~kWsChanConnections);
                else if (ch == "metrics") peer.channels &= static_cast<std::uint8_t>(~kWsChanMetrics);
            }
            queue_ws_text(peer, format_ws_channels_reply(peer.channels));
            return;
        }
        queue_ws_text(peer, "{\"type\":\"error\",\"code\":\"unknown-type\",\"message\":\"unsupported message type\"}");
    }

    inline auto process_ws_peer_input(WsPeer& peer, std::span<std::uint8_t const> expected_token,
        StreamClock::time_point now, StreamSnapshotFn fetch_snap, StreamCommandFn command,
        std::uint64_t& authorized, std::uint64_t& unauthorized) -> void {
        while (!peer.closing) {
            WsDecodedFrame frame{};
            auto st = decode_ws_client_frame(peer.in, frame);
            if (st == WsDecodeStatus::need_more) break;
            if (st == WsDecodeStatus::too_large) { queue_ws_close(peer, 1009, "message too big"); break; }
            if (st == WsDecodeStatus::protocol_error) { queue_ws_close(peer, 1002, "protocol error"); break; }
            peer.idle_deadline = now + kWsIdleTimeout;
            if (frame.opcode == 0x8) { queue_ws_close(peer, 1000); break; }
            if (frame.opcode == 0x9) { peer.out += encode_ws_frame(0xA, frame.payload); continue; }
            if (frame.opcode == 0xA) continue;
            if (frame.opcode == 0x2) { queue_ws_close(peer, 1003, "binary unsupported"); break; }
            if (frame.opcode == 0x0) {
                if (!peer.frag_active) { queue_ws_close(peer, 1002, "unexpected continuation"); break; }
                if (peer.frag_buf.size() + frame.payload.size() > kMaxWsFrameBytes) { queue_ws_close(peer, 1009, "message too big"); break; }
                peer.frag_buf.append(frame.payload);
                if (!frame.fin) continue;
                peer.frag_active = false;
                auto full = std::move(peer.frag_buf); peer.frag_buf.clear();
                handle_ws_text_message(peer, full, expected_token, now, fetch_snap, command, authorized, unauthorized);
                continue;
            }
            if (peer.frag_active) { queue_ws_close(peer, 1002, "unfinished fragment"); break; }
            if (!frame.fin) { peer.frag_active = true; peer.frag_opcode = frame.opcode; peer.frag_buf = std::move(frame.payload); continue; }
            handle_ws_text_message(peer, frame.payload, expected_token, now, fetch_snap, command, authorized, unauthorized);
        }
    }

    inline auto tick_ws_peer(WsPeer& peer, StreamClock::time_point now, StreamSnapshotFn fetch_snap,
        StreamCommandFn command, std::uint64_t& unauthorized, std::uint64_t& expired) -> bool {
        if (!peer.closing && peer.auth == WsAuthState::pending_auth && now >= peer.auth_deadline) {
            ++unauthorized; ++expired;
            queue_ws_close(peer, 4401, "auth timeout");
        }
        if (now >= peer.idle_deadline) { ++expired; return false; }
        if (!peer.closing && peer.auth == WsAuthState::authenticated && peer.out.size() - peer.out_offset < kMaxWsOutBytes / 2) {
            if ((peer.channels & kWsChanLogs) && now >= peer.next_log_poll) {
                push_ws_logs(peer, command); peer.next_log_poll = now + kWsLogPollInterval;
            }
            if ((peer.channels & (kWsChanConnections | kWsChanMetrics)) && now >= peer.next_snap_poll) {
                push_ws_snapshots(peer, peer.channels, fetch_snap); peer.next_snap_poll = now + peer.interval;
            }
            if (now - peer.last_ping_sent >= kWsPingInterval) {
                peer.out += encode_ws_frame(0x9, {}); peer.last_ping_sent = now;
            }
        }
        return true;
    }

    inline auto flush_ws_peer_writes(WsPeer& peer) noexcept -> bool {
        if (peer.out.size() - peer.out_offset > kMaxWsOutBytes) return false;
        while (peer.out_offset < peer.out.size()) {
            std::size_t n = 0;
            auto st = send_nonblocking(peer.fd,
                std::span<char const>(peer.out.data() + peer.out_offset, peer.out.size() - peer.out_offset), n);
            if (st == SocketIoStatus::ok) peer.out_offset += n;
            else return st != SocketIoStatus::closed;
        }
        if (peer.out_offset >= peer.out.size()) { peer.out.clear(); peer.out_offset = 0; }
        return !peer.closing;
    }

    inline auto poll_ws_peers(std::vector<WsPeer>& peers, std::span<std::uint8_t const> expected_token,
        StreamClock::time_point now, StreamSnapshotFn fetch_snap, StreamCommandFn command,
        std::uint64_t& authorized, std::uint64_t& unauthorized, std::uint64_t& expired) -> void {
        for (auto it = peers.begin(); it != peers.end();) {
            bool alive = true;
            if (!it->closing) {
                char buf[4096];
                for (int reads = 0; reads < 4 && !it->closing; ++reads) {
                    std::size_t n = 0;
                    auto st = recv_nonblocking(it->fd, buf, n);
                    if (st == SocketIoStatus::closed) { alive = false; break; }
                    if (st == SocketIoStatus::would_block || n == 0) break;
                    if (it->in.size() + n > kMaxWsFrameBytes + 32) { queue_ws_close(*it, 1009, "message too big"); break; }
                    it->in.append(buf, n);
                    process_ws_peer_input(*it, expected_token, now, fetch_snap, command, authorized, unauthorized);
                }
            }
            if (alive && !it->in.empty() && !it->closing)
                process_ws_peer_input(*it, expected_token, now, fetch_snap, command, authorized, unauthorized);
            if (alive) alive = tick_ws_peer(*it, now, fetch_snap, command, unauthorized, expired);
            if (alive) alive = flush_ws_peer_writes(*it);
            if (!alive) it = peers.erase(it); else ++it;
        }
    }

    inline auto compute_ws_peers_poll_delay(std::span<WsPeer const> peers, StreamClock::time_point now) noexcept
        -> std::optional<std::chrono::milliseconds> {
        if (peers.empty()) return std::nullopt;
        std::chrono::milliseconds min_wait(50);
        for (auto const& p : peers) {
            if (p.out_offset < p.out.size() || !p.in.empty()) return std::chrono::milliseconds(5);
            auto clamp_rem = [&](StreamClock::time_point t) {
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(t - now);
                min_wait = std::min(min_wait, std::max(rem, std::chrono::milliseconds(5)));
            };
            if (p.auth == WsAuthState::pending_auth) clamp_rem(p.auth_deadline);
            if (p.channels & kWsChanLogs) clamp_rem(p.next_log_poll);
            if (p.channels & (kWsChanConnections | kWsChanMetrics)) clamp_rem(p.next_snap_poll);
        }
        return min_wait;
    }
}
