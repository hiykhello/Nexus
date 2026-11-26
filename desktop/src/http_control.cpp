module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

module desktop.http_control;

import std;

namespace desktop {
    namespace {
        auto parse_u64(std::string_view token) noexcept -> std::uint64_t {
            std::uint64_t value = 0;
            auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
            return ec == std::errc{} ? value : 0;
        }

        auto has_header_forbidden(std::string_view sv, bool forbid_space) noexcept -> bool {
            for (unsigned char c : sv) {
                if (c == '\r' || c == '\n' || c == '\0' || c < 0x20 || c == 0x7F) return true;
                if (forbid_space && (c == ' ' || c == '\t')) return true;
            }
            return false;
        }

        auto decode_json_string_at(std::string_view s, std::size_t quote_pos, std::size_t& next_pos) -> std::string {
            std::string out;
            std::size_t i = quote_pos + 1;
            while (i < s.size()) {
                char c = s[i++];
                if (c == '"') {
                    next_pos = i;
                    return out;
                }
                if (c == '\\' && i < s.size()) {
                    char esc = s[i++];
                    switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u':
                        if (i + 4 <= s.size()) {
                            unsigned int cp = 0;
                            auto [p, ec] = std::from_chars(s.data() + i, s.data() + i + 4, cp, 16);
                            if (ec == std::errc{} && p == s.data() + i + 4) {
                                i += 4;
                                if (cp < 0x80) out.push_back(static_cast<char>(cp));
                                else if (cp < 0x800) {
                                    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                                } else {
                                    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                                }
                                break;
                            }
                        }
                        out.push_back('u');
                        break;
                    default: out.push_back(esc); break;
                    }
                } else {
                    out.push_back(c);
                }
            }
            next_pos = s.size();
            return out;
        }

        // Finds a key's value offset strictly at depth 1 of a JSON object (ignoring nested objects/arrays).
        auto find_json_value_pos(std::string_view obj, std::string_view key) -> std::size_t {
            int depth = 0;
            std::size_t i = 0;
            while (i < obj.size()) {
                char c = obj[i];
                if (c == '{' || c == '[') { ++depth; ++i; continue; }
                if (c == '}' || c == ']') { --depth; ++i; continue; }
                if (c == '"') {
                    std::size_t next = i;
                    auto str = decode_json_string_at(obj, i, next);
                    std::size_t j = next;
                    while (j < obj.size() && (obj[j] == ' ' || obj[j] == '\t' || obj[j] == '\r' || obj[j] == '\n')) ++j;
                    if (depth == 1 && j < obj.size() && obj[j] == ':' && str == key) {
                        ++j;
                        while (j < obj.size() && (obj[j] == ' ' || obj[j] == '\t' || obj[j] == '\r' || obj[j] == '\n')) ++j;
                        return j;
                    }
                    i = next;
                    continue;
                }
                ++i;
            }
            return std::string_view::npos;
        }

        auto extract_json_string(std::string_view obj, std::string_view key) -> std::string {
            auto pos = find_json_value_pos(obj, key);
            if (pos == std::string_view::npos || pos >= obj.size() || obj[pos] != '"') return {};
            std::size_t next = pos;
            return decode_json_string_at(obj, pos, next);
        }

        auto extract_json_bool(std::string_view obj, std::string_view key) -> bool {
            auto pos = find_json_value_pos(obj, key);
            if (pos == std::string_view::npos) return false;
            return obj.substr(pos).starts_with("true");
        }

        auto extract_json_i64(std::string_view obj, std::string_view key, std::int64_t fallback) -> std::int64_t {
            auto pos = find_json_value_pos(obj, key);
            if (pos == std::string_view::npos) return fallback;
            std::int64_t value = fallback;
            auto [ptr, ec] = std::from_chars(obj.data() + pos, obj.data() + obj.size(), value);
            return ec == std::errc{} ? value : fallback;
        }

        auto find_matching(std::string_view text, std::size_t open_pos, char open_ch, char close_ch) -> std::size_t {
            int depth = 0;
            bool in_str = false;
            for (std::size_t i = open_pos; i < text.size(); ++i) {
                char c = text[i];
                if (in_str) {
                    if (c == '\\' && i + 1 < text.size()) { ++i; continue; }
                    if (c == '"') in_str = false;
                    continue;
                }
                if (c == '"') { in_str = true; continue; }
                if (c == open_ch) ++depth;
                else if (c == close_ch && --depth == 0) return i;
            }
            return std::string_view::npos;
        }
    }

    auto parse_openmetrics_summary(std::string_view text) -> MetricsSnapshot {
        MetricsSnapshot out{};
        while (!text.empty()) {
            auto nl = text.find('\n');
            auto line = nl == std::string_view::npos ? text : text.substr(0, nl);
            text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.empty() || line.front() == '#') continue;
            auto brace_end = line.find('}');
            auto search_from = brace_end == std::string_view::npos ? 0u : brace_end + 1u;
            auto sp = line.find(' ', search_from);
            if (sp == std::string_view::npos) continue;
            auto metric = line.substr(0, sp);
            auto rest = line.substr(sp + 1);
            while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.remove_prefix(1);
            auto val_end = rest.find_first_of(" \t");
            auto val = parse_u64(val_end == std::string_view::npos ? rest : rest.substr(0, val_end));
            if (metric == "nexus_control_generation") out.control_generation = val;
            else if (metric.starts_with("nexus_active_sessions")) out.active_sessions += val;
            else if (metric.starts_with("nexus_traffic_upload_bytes_total")) out.upload_bytes += val;
            else if (metric.starts_with("nexus_traffic_download_bytes_total")) out.download_bytes += val;
        }
        return out;
    }

    // parse_outbounds_json, parse_outbound_probe_json, parse_rules_json,
    // parse_dns_query_json, parse_fakeip_flush_json, parse_log_entry_json
    // live in http_control_extra.cpp.

    namespace {
        auto parse_one_connection(std::string_view obj) -> ActiveConnectionSnapshot {
            ActiveConnectionSnapshot c{};
            auto id_str = extract_json_string(obj, "id");
            c.id = id_str.empty() ? static_cast<std::uint64_t>(extract_json_i64(obj, "id", 0)) : parse_u64(id_str);
            c.listener = static_cast<std::uint32_t>(extract_json_i64(obj, "listener", 0));
            c.inbound = extract_json_string(obj, "inbound");
            c.protocol = extract_json_string(obj, "protocol");
            c.path = extract_json_string(obj, "path");
            c.source = extract_json_string(obj, "source");
            c.target = extract_json_string(obj, "target");
            c.outbound = extract_json_string(obj, "outbound");
            c.route_mode = extract_json_string(obj, "route_mode");
            c.route_rule = extract_json_string(obj, "route_rule");
            c.process_path = extract_json_string(obj, "process_path");
            c.source_uid = extract_json_i64(obj, "source_uid", -1);
            c.destination_port = static_cast<std::uint16_t>(extract_json_i64(obj, "destination_port", 0));
            auto dur_str = extract_json_string(obj, "duration_ms");
            c.duration_ms = dur_str.empty() ? static_cast<std::uint64_t>(extract_json_i64(obj, "duration_ms", 0)) : parse_u64(dur_str);
            auto up_str = extract_json_string(obj, "upload_bytes");
            auto down_str = extract_json_string(obj, "download_bytes");
            c.upload_bytes = up_str.empty() ? static_cast<std::uint64_t>(extract_json_i64(obj, "upload_bytes", 0)) : parse_u64(up_str);
            c.download_bytes = down_str.empty() ? static_cast<std::uint64_t>(extract_json_i64(obj, "download_bytes", 0)) : parse_u64(down_str);
            c.can_close = extract_json_bool(obj, "can_close");
            return c;
        }
    }

    auto parse_connections_json(std::string_view json) -> std::vector<ActiveConnectionSnapshot> {
        std::vector<ActiveConnectionSnapshot> out;
        auto pos = json.find("\"connections\"");
        if (pos == std::string_view::npos) return out;
        auto arr_start = json.find('[', pos);
        if (arr_start == std::string_view::npos) return out;
        auto arr_end = find_matching(json, arr_start, '[', ']');
        if (arr_end == std::string_view::npos) return out;

        std::size_t cursor = arr_start + 1;
        while (cursor < arr_end) {
            auto obj_start = json.find('{', cursor);
            if (obj_start == std::string_view::npos || obj_start >= arr_end) break;
            auto obj_end = find_matching(json, obj_start, '{', '}');
            if (obj_end == std::string_view::npos || obj_end > arr_end) break;
            out.push_back(parse_one_connection(json.substr(obj_start, obj_end - obj_start + 1)));
            cursor = obj_end + 1;
        }
        return out;
    }

    auto parse_connection_detail_json(std::string_view json) -> std::optional<ActiveConnectionSnapshot> {
        auto obj_start = json.find('{');
        if (obj_start == std::string_view::npos) return std::nullopt;
        auto obj_end = find_matching(json, obj_start, '{', '}');
        if (obj_end == std::string_view::npos) return std::nullopt;
        auto parsed = parse_one_connection(json.substr(obj_start, obj_end - obj_start + 1));
        if (parsed.id == 0) return std::nullopt;
        return parsed;
    }

    auto parse_logs_json(std::string_view json) -> LogsSnapshot {
        LogsSnapshot out{};
        auto latest_str = extract_json_string(json, "latest_seq");
        out.latest_seq = latest_str.empty() ? static_cast<std::uint64_t>(extract_json_i64(json, "latest_seq", 0)) : parse_u64(latest_str);
        auto ev_str = extract_json_string(json, "evicted");
        out.evicted = ev_str.empty() ? static_cast<std::uint64_t>(extract_json_i64(json, "evicted", 0)) : parse_u64(ev_str);
        auto pos = json.find("\"entries\"");
        if (pos == std::string_view::npos) return out;
        auto arr_start = json.find('[', pos);
        if (arr_start == std::string_view::npos) return out;
        auto arr_end = find_matching(json, arr_start, '[', ']');
        if (arr_end == std::string_view::npos) return out;
        std::size_t cursor = arr_start + 1;
        while (cursor < arr_end) {
            auto obj_start = json.find('{', cursor);
            if (obj_start == std::string_view::npos || obj_start >= arr_end) break;
            auto obj_end = find_matching(json, obj_start, '{', '}');
            if (obj_end == std::string_view::npos || obj_end > arr_end) break;
            auto obj = json.substr(obj_start, obj_end - obj_start + 1);
            LogEntrySnapshot entry{};
            auto seq_str = extract_json_string(obj, "seq");
            entry.seq = seq_str.empty() ? static_cast<std::uint64_t>(extract_json_i64(obj, "seq", 0)) : parse_u64(seq_str);
            entry.level = extract_json_string(obj, "level");
            entry.domain = extract_json_string(obj, "domain");
            auto ev_code = extract_json_i64(obj, "event_code", -1);
            if (ev_code < 0) ev_code = extract_json_i64(obj, "event", 0);
            entry.event_code = static_cast<std::uint32_t>(std::max<std::int64_t>(0, ev_code));
            entry.message = extract_json_string(obj, "message");
            out.entries.push_back(std::move(entry));
            cursor = obj_end + 1;
        }
        return out;
    }

    auto HttpControlClient::request(this HttpControlClient const& self,
                                    std::string_view method,
                                    std::string_view path,
                                    std::string_view body,
                                    std::optional<std::chrono::milliseconds> timeout_override) -> HttpReply {
        std::string host;
        std::uint16_t port = 0;
        std::string bearer_token;
        std::chrono::milliseconds base_timeout{2000};
        {
            std::scoped_lock lk(self.mu_);
            host = self.host_;
            port = self.port_;
            bearer_token = self.bearer_token_;
            base_timeout = self.timeout_;
        }
        auto const eff_timeout = timeout_override.value_or(base_timeout);
        if (host.empty() || port == 0 || method.empty() || path.empty() || path.front() != '/' ||
            has_header_forbidden(method, true) || has_header_forbidden(path, true) ||
            has_header_forbidden(host, true) || has_header_forbidden(bearer_token, false)) {
            return {false, 0, "invalid HTTP control request"};
        }
        std::string host_hdr = (host.contains(':') && !host.starts_with('['))
            ? std::format("[{}]:{}", host, port)
            : std::format("{}:{}", host, port);
        std::string req = std::format(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            method, path, host_hdr);
        if (!bearer_token.empty()) {
            req += std::format("Authorization: Bearer {}\r\n", bearer_token);
        }
        if (!body.empty()) {
            req += std::format("Content-Type: application/json\r\nContent-Length: {}\r\n", body.size());
        }
        req += "\r\n";
        req += body;

#ifdef _WIN32
        static bool const wsa_ready = [] {
            WSADATA wsa{};
            return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
        }();
        if (!wsa_ready) return {false, 0, "WSAStartup failed"};
#endif
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        auto port_str = std::to_string(port);
        if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
            return {false, 0, "failed to resolve control host"};
        }

#ifdef _WIN32
        SOCKET fd = INVALID_SOCKET;
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            SOCKET s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s == INVALID_SOCKET) continue;
            DWORD ms = static_cast<DWORD>(eff_timeout.count());
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char const*>(&ms), sizeof(ms));
            ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char const*>(&ms), sizeof(ms));
            if (::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
                fd = s;
                break;
            }
            ::closesocket(s);
        }
        ::freeaddrinfo(res);
        if (fd == INVALID_SOCKET) return {false, 0, "connect failed"};
        auto close_sock = [&] { ::closesocket(fd); };
#else
        int fd = -1;
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
#ifdef SOCK_CLOEXEC
            int s = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
#else
            int s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s >= 0) (void)::fcntl(s, F_SETFD, FD_CLOEXEC);
#endif
            if (s < 0) continue;
#ifdef SO_NOSIGPIPE
            int one = 1;
            (void)::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
            timeval tv{};
            tv.tv_sec = static_cast<time_t>(eff_timeout.count() / 1000);
            tv.tv_usec = static_cast<suseconds_t>((eff_timeout.count() % 1000) * 1000);
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int rc = 0;
            do {
                rc = ::connect(s, ai->ai_addr, ai->ai_addrlen);
            } while (rc != 0 && errno == EINTR);
            if (rc == 0) {
                fd = s;
                break;
            }
            ::close(s);
        }
        ::freeaddrinfo(res);
        if (fd < 0) return {false, 0, "connect failed"};
        auto close_sock = [&] { ::close(fd); };
#endif

        std::size_t sent = 0;
        while (sent < req.size()) {
#ifdef _WIN32
            auto n = ::send(fd, req.data() + sent, static_cast<int>(req.size() - sent), 0);
#else
#ifdef MSG_NOSIGNAL
            constexpr int kSendFlags = MSG_NOSIGNAL;
#else
            constexpr int kSendFlags = 0;
#endif
            auto n = ::send(fd, req.data() + sent, req.size() - sent, kSendFlags);
            if (n < 0 && errno == EINTR) continue;
#endif
            if (n <= 0) { close_sock(); return {false, 0, "send failed"}; }
            sent += static_cast<std::size_t>(n);
        }

        std::string raw;
        char buf[4096];
        for (;;) {
#ifdef _WIN32
            auto n = ::recv(fd, buf, static_cast<int>(sizeof(buf)), 0);
#else
            auto n = ::recv(fd, buf, sizeof(buf), 0);
#endif
#ifndef _WIN32
            if (n < 0 && errno == EINTR) continue;
#endif
            if (n == 0) break;
            if (n < 0) { close_sock(); return {false, 0, "recv failed"}; }
            if (raw.size() + static_cast<std::size_t>(n) > 256u * 1024u) {
                close_sock();
                return {false, 0, "HTTP reply exceeds 256 KiB limit"};
            }
            raw.append(buf, static_cast<std::size_t>(n));
        }
        close_sock();

        auto sep = raw.find("\r\n\r\n");
        if (sep == std::string::npos) return {false, 0, "malformed HTTP response"};
        auto status_line = std::string_view(raw).substr(0, raw.find("\r\n"));
        auto sp1 = status_line.find(' ');
        if (sp1 == std::string_view::npos) return {false, 0, "malformed HTTP status line"};
        int code = 0;
        auto code_sv = status_line.substr(sp1 + 1);
        std::from_chars(code_sv.data(), code_sv.data() + code_sv.size(), code);
        auto resp_body = raw.substr(sep + 4);
        return {code >= 200 && code < 300, code, std::move(resp_body)};
    }
}
