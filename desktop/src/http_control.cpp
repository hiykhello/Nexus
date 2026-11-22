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

        auto extract_json_string(std::string_view obj, std::string_view key) -> std::string {
            auto needle = std::format("\"{}\":", key);
            auto pos = obj.find(needle);
            if (pos == std::string_view::npos) return {};
            pos += needle.size();
            while (pos < obj.size() && (obj[pos] == ' ' || obj[pos] == '\t')) ++pos;
            if (pos >= obj.size() || obj[pos] != '"') return {};
            ++pos;
            std::string out;
            while (pos < obj.size() && obj[pos] != '"') {
                if (obj[pos] == '\\' && pos + 1 < obj.size()) ++pos;
                out.push_back(obj[pos++]);
            }
            return out;
        }

        auto extract_json_bool(std::string_view obj, std::string_view key) -> bool {
            auto needle = std::format("\"{}\":", key);
            auto pos = obj.find(needle);
            if (pos == std::string_view::npos) return false;
            pos += needle.size();
            while (pos < obj.size() && obj[pos] == ' ') ++pos;
            return obj.substr(pos).starts_with("true");
        }

        auto extract_json_i64(std::string_view obj, std::string_view key, std::int64_t fallback) -> std::int64_t {
            auto needle = std::format("\"{}\":", key);
            auto pos = obj.find(needle);
            if (pos == std::string_view::npos) return fallback;
            pos += needle.size();
            while (pos < obj.size() && obj[pos] == ' ') ++pos;
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
            auto sp = line.rfind(' ');
            if (sp == std::string_view::npos) continue;
            auto metric = line.substr(0, sp);
            auto val = parse_u64(line.substr(sp + 1));
            if (metric == "nexus_control_generation") out.control_generation = val;
            else if (metric.starts_with("nexus_active_sessions")) out.active_sessions += val;
            else if (metric.starts_with("nexus_traffic_upload_bytes_total")) out.upload_bytes += val;
            else if (metric.starts_with("nexus_traffic_download_bytes_total")) out.download_bytes += val;
        }
        return out;
    }

    auto parse_outbounds_json(std::string_view json) -> std::vector<OutboundGroupSnapshot> {
        std::vector<OutboundGroupSnapshot> groups;
        auto pos = json.find("\"groups\"");
        if (pos == std::string_view::npos) return groups;
        auto arr_start = json.find('[', pos);
        if (arr_start == std::string_view::npos) return groups;
        auto arr_end = find_matching(json, arr_start, '[', ']');
        if (arr_end == std::string_view::npos) return groups;

        std::size_t cursor = arr_start + 1;
        while (cursor < arr_end) {
            auto obj_start = json.find('{', cursor);
            if (obj_start == std::string_view::npos || obj_start >= arr_end) break;
            auto obj_end = find_matching(json, obj_start, '{', '}');
            if (obj_end == std::string_view::npos || obj_end > arr_end) break;
            auto obj = json.substr(obj_start, obj_end - obj_start + 1);

            OutboundGroupSnapshot grp{};
            grp.tag = extract_json_string(obj, "name");
            if (grp.tag.empty()) grp.tag = extract_json_string(obj, "tag");
            grp.mode = extract_json_string(obj, "mode");
            grp.active = extract_json_string(obj, "selected");
            if (grp.active.empty()) grp.active = extract_json_string(obj, "active");
            grp.manual_override = extract_json_bool(obj, "override");

            if (auto mpos = obj.find("\"members\""); mpos != std::string_view::npos) {
                if (auto ma = obj.find('[', mpos); ma != std::string_view::npos) {
                    if (auto me = find_matching(obj, ma, '[', ']'); me != std::string_view::npos) {
                        std::size_t mc = ma + 1;
                        while (mc < me) {
                            auto ms = obj.find('{', mc);
                            if (ms == std::string_view::npos || ms >= me) break;
                            auto mend = find_matching(obj, ms, '{', '}');
                            if (mend == std::string_view::npos || mend > me) break;
                            auto mobj = obj.substr(ms, mend - ms + 1);
                            OutboundMemberSnapshot m{};
                            m.name = extract_json_string(mobj, "name");
                            m.state = extract_json_string(mobj, "state");
                            m.latency_ms = extract_json_i64(mobj, "latency_ms", -1);
                            m.selected = (!grp.active.empty() && m.name == grp.active);
                            m.overridden = m.selected && grp.manual_override;
                            if (!m.name.empty()) grp.members.push_back(std::move(m));
                            mc = mend + 1;
                        }
                    }
                }
            }
            if (!grp.tag.empty()) groups.push_back(std::move(grp));
            cursor = obj_end + 1;
        }
        return groups;
    }

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
            entry.event_code = static_cast<std::uint32_t>(extract_json_i64(obj, "event_code", 0));
            entry.message = extract_json_string(obj, "message");
            out.entries.push_back(std::move(entry));
            cursor = obj_end + 1;
        }
        return out;
    }

    auto HttpControlClient::request(this HttpControlClient const& self,
                                    std::string_view method,
                                    std::string_view path,
                                    std::string_view body) -> HttpReply {
        if (self.host_.empty() || self.port_ == 0 || path.empty() || path.front() != '/' ||
            path.contains('\r') || path.contains('\n')) {
            return {false, 0, "invalid HTTP control request"};
        }
        std::string req = std::format(
            "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n",
            method, path, self.host_, self.port_);
        if (!self.bearer_token_.empty()) {
            req += std::format("Authorization: Bearer {}\r\n", self.bearer_token_);
        }
        if (!body.empty()) {
            req += std::format("Content-Type: application/json\r\nContent-Length: {}\r\n", body.size());
        }
        req += "\r\n";
        req += body;

#ifdef _WIN32
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return {false, 0, "WSAStartup failed"};
#endif
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        auto port_str = std::to_string(self.port_);
        if (::getaddrinfo(self.host_.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
            return {false, 0, "failed to resolve control host"};
        }

        auto fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#ifdef _WIN32
        if (fd == INVALID_SOCKET) { ::freeaddrinfo(res); return {false, 0, "socket() failed"}; }
        DWORD ms = static_cast<DWORD>(self.timeout_.count());
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char const*>(&ms), sizeof(ms));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char const*>(&ms), sizeof(ms));
        auto close_sock = [&] { ::closesocket(fd); ::freeaddrinfo(res); };
#else
        if (fd < 0) { ::freeaddrinfo(res); return {false, 0, std::strerror(errno)}; }
        timeval tv{};
        tv.tv_sec = static_cast<time_t>(self.timeout_.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((self.timeout_.count() % 1000) * 1000);
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        auto close_sock = [&] { ::close(fd); ::freeaddrinfo(res); };
#endif

        if (::connect(fd, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
            close_sock();
            return {false, 0, "connect failed"};
        }

        std::size_t sent = 0;
        while (sent < req.size()) {
#ifdef _WIN32
            auto n = ::send(fd, req.data() + sent, static_cast<int>(req.size() - sent), 0);
#else
            auto n = ::send(fd, req.data() + sent, req.size() - sent, MSG_NOSIGNAL);
#endif
            if (n <= 0) { close_sock(); return {false, 0, "send failed"}; }
            sent += static_cast<std::size_t>(n);
        }

        std::string raw;
        char buf[4096];
        for (;;) {
            auto n = ::recv(fd, buf, sizeof(buf), 0);
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
