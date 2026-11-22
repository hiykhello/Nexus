module;
#include <cstring>

module control_api;

import std;
import config;
import control_api.http_socket;
import control_api.types;
import crypto;
import metrics;
import platform.ip_address;
import rulefile;

namespace control_api {
#include "http_format.hpp"
#include "dashboard_static.hpp"
    namespace {
        constexpr std::size_t kMaxPeers = 16;
        constexpr std::size_t kMaxRequestBytes = 8192;
        constexpr std::size_t kMaxWriteBytes = kMaxDashboardFileBytes + 8192;
        constexpr auto kPeerTimeout = std::chrono::seconds(2);

        auto secure_wipe(std::span<std::uint8_t> bytes) noexcept -> void {
            for (auto& b : bytes) {
                volatile auto* p = &b;
                *p = 0;
            }
            std::atomic_signal_fence(std::memory_order_seq_cst);
        }
    }

    struct HttpControlServer::Impl {
        using Clock = std::chrono::steady_clock;
        struct Peer {
            Fd fd;
            std::string in;
            std::string out;
            std::size_t out_offset = 0;
            bool writing = false;
            bool streaming = false;
            std::string stream_cursor{"0"};
            std::vector<std::string> stream_filters;
            Clock::time_point deadline{};
            Clock::time_point next_stream_poll{};
        };

        Fd listen_fd;
        bool metrics_enabled = false;
        std::filesystem::path dashboard_root;
        std::vector<std::uint8_t> token;
        std::vector<Peer> peers;
        std::uint64_t authorized = 0, unauthorized = 0, expired = 0;

        ~Impl() {
            if (!token.empty()) secure_wipe(token);
        }

        auto check_auth(std::string_view headers, std::string_view query) -> bool {
            if (query.contains("token=")) {
                ++unauthorized;
                return false;
            }
            if (token.empty()) {
                ++authorized;
                return true;
            }
            std::string_view provided;
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
                        if (val.starts_with("Bearer ")) provided = val.substr(7);
                    }
                }
                if (eol == std::string_view::npos) break;
                rest.remove_prefix(eol + 2);
            }
            auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(provided.data()), provided.size());
            bool ok = !provided.empty() && crypto::constant_time_equal(token, bytes);
            if (ok) ++authorized;
            else ++unauthorized;
            return ok;
        }

        auto handle_request(std::string_view raw, SnapshotBuilder snapshot, CommandHandler command) -> std::string {
            auto header_end = raw.find("\r\n\r\n");
            if (header_end == std::string_view::npos) return json_error(400, "Bad Request", "bad-request", "malformed HTTP");
            auto head = raw.substr(0, header_end);
            auto body = raw.substr(header_end + 4);
            auto first_eol = head.find("\r\n");
            auto req_line = head.substr(0, first_eol);
            auto sp1 = req_line.find(' ');
            auto sp2 = sp1 == std::string_view::npos ? std::string_view::npos : req_line.find(' ', sp1 + 1);
            if (sp1 == std::string_view::npos || sp2 == std::string_view::npos)
                return json_error(400, "Bad Request", "bad-request", "invalid request line");

            auto method = req_line.substr(0, sp1);
            auto target = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
            std::string_view path = target, query;
            if (auto q = target.find('?'); q != std::string_view::npos) {
                path = target.substr(0, q);
                query = target.substr(q + 1);
            }
            auto headers = first_eol == std::string_view::npos ? std::string_view{} : head.substr(first_eol + 2);
            bool is_api = path == "/v1" || path.starts_with("/v1/") || path == "/metrics";
            if (!is_api && !dashboard_root.empty())
                return serve_dashboard_request(dashboard_root, method, path);
            if (!check_auth(headers, query))
                return json_error(401, "Unauthorized", "unauthorized", "missing or invalid bearer token");

            auto snap = snapshot();
            snap.authorized_requests += authorized;
            snap.unauthorized_requests += unauthorized;
            snap.expired_requests += expired;

            if (method == "GET" && path == "/v1/health")
                return build_http_response(200, "OK", "application/json",
                    std::format("{{\"status\":\"ok\",\"instance\":{}}}\n", json_escape(snap.instance)));
            if (method == "GET" && path == "/v1/status")
                return build_http_response(200, "OK", "application/json", render_status_json(snap));
            if (method == "GET" && path == "/v1/outbounds")
                return build_http_response(200, "OK", "application/json", render_outbounds_json(snap));
            if (method == "GET" && path == "/v1/connections")
                return build_http_response(200, "OK", "application/json", render_connections_json(snap));
            if (method == "GET" && path.starts_with("/v1/connections/")) {
                auto id_str = path.substr(16);
                std::uint64_t cid = 0;
                auto [end, ec] = std::from_chars(id_str.data(), id_str.data() + id_str.size(), cid);
                if (id_str.empty() || id_str.contains('/') || ec != std::errc{} || end != id_str.data() + id_str.size() || !cid)
                    return json_error(400, "Bad Request", "invalid-id", "expected numeric connection id");
                auto it = std::ranges::find(snap.connections, cid, &ConnectionMetric::id);
                if (it == snap.connections.end())
                    return json_error(404, "Not Found", "unknown-connection", "connection not found");
                return build_http_response(200, "OK", "application/json", render_connection_detail_json(*it));
            }
            if (method == "GET" && path == "/v1/logs") {
                auto owned = build_log_command_args(query);
                std::vector<std::string_view> args;
                args.reserve(owned.size());
                for (auto const& s : owned) args.emplace_back(s);
                auto res = command(args);
                if (!res) return json_error(400, "Bad Request", res.error(), res.error());
                return build_http_response(200, "OK", "application/json", render_logs_json(*res));
            }
            if (method == "GET" && path == "/v1/diagnostics")
                return build_http_response(200, "OK", "application/json", render_diagnostics_json(snap));
            if (method == "GET" && path == "/v1/events") {
                std::string_view cursor = "0";
                if (query.starts_with("cursor=")) {
                    auto v = query.substr(7);
                    auto amp = v.find('&');
                    cursor = amp == std::string_view::npos ? v : v.substr(0, amp);
                }
                std::array<std::string_view, 2> args{"events", cursor};
                auto res = command(args);
                if (!res) return json_error(400, "Bad Request", res.error(), res.error());
                return build_http_response(200, "OK", "application/json", render_events_json(*res));
            }
            if (method == "GET" && path == "/metrics") {
                if (!metrics_enabled || !metrics::available())
                    return json_error(404, "Not Found", "metrics-disabled", "OpenMetrics endpoint is disabled");
                return build_http_response(200, "OK",
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    metrics::render_openmetrics(snap));
            }
            if (method == "PUT" && path.starts_with("/v1/groups/")) {
                auto tag = url_decode_once(path.substr(11));
                auto member = extract_json_string(body, "member");
                if (!tag || tag->empty() || !member || member->empty())
                    return json_error(400, "Bad Request", "invalid-body", "expected {\"member\":\"...\"}");
                std::array<std::string_view, 3> args{"select", *tag, *member};
                auto res = command(args);
                if (!res) {
                    int code = res.error() == "unknown-group" ? 404 : 409;
                    return json_error(code, code == 404 ? "Not Found" : "Conflict", res.error(), res.error());
                }
                return build_http_response(200, "OK", "application/json",
                    std::format("{{\"group\":{},\"selected\":{},\"result\":{}}}\n",
                        json_escape(*tag), json_escape(*member), json_escape(*res)));
            }
            if (method == "POST" && path == "/v1/log-level") {
                auto level = extract_json_string(body, "level");
                auto domain = extract_json_string(body, "domain").value_or("global");
                if (!level || level->empty() || domain.empty())
                    return json_error(400, "Bad Request", "invalid-body", "expected {\"level\":\"...\"}");
                std::array<std::string_view, 3> args{"log-level", domain, *level};
                auto res = command(args);
                if (!res) return json_error(400, "Bad Request", "invalid-log-level", res.error());
                return build_http_response(200, "OK", "application/json",
                    std::format("{{\"domain\":{},\"level\":{}}}\n", json_escape(domain), json_escape(*level)));
            }
            if (method == "POST" && path == "/v1/reload") {
                std::array<std::string_view, 1> args{"reload"};
                auto res = command(args);
                if (!res) return json_error(409, "Conflict", res.error(), res.error());
                return build_http_response(202, "Accepted", "application/json",
                    std::format("{{\"state\":\"pending\",\"detail\":{}}}\n", json_escape(*res)));
            }
            if (method == "POST" && path == "/v1/state/clear-cache") {
                auto target = extract_json_string(body, "target").value_or("all");
                if (target != "all" && target != "dns" && target != "rulesets") {
                    return json_error(400, "Bad Request", "invalid-target",
                        "expected target in {\"all\",\"dns\",\"rulesets\"}");
                }
                std::array<std::string_view, 2> args{"clear-cache", target};
                auto res = command(args);
                if (!res) return json_error(409, "Conflict", res.error(), res.error());
                return build_http_response(200, "OK", "application/json",
                    std::format("{{\"target\":{},\"cleared\":true,\"detail\":{}}}\n",
                        json_escape(target), json_escape(*res)));
            }
            if (method == "POST" && path == "/v1/network-change") {
                auto gen = extract_json_string(body, "generation");
                std::expected<std::string, std::string> res;
                if (gen && !gen->empty()) {
                    std::array<std::string_view, 2> args{"network-change", *gen};
                    res = command(args);
                } else {
                    std::array<std::string_view, 1> args{"network-change"};
                    res = command(args);
                }
                if (!res) return json_error(409, "Conflict", res.error(), res.error());
                return build_http_response(200, "OK", "application/json",
                    std::format("{{\"accepted\":true,\"detail\":{}}}\n", json_escape(*res)));
            }
            if (method == "POST" && path.starts_with("/v1/groups/") && path.ends_with("/probe")) {
                auto raw_tag = path.substr(11, path.size() - 17);
                auto tag = url_decode_once(raw_tag);
                if (!tag || tag->empty())
                    return json_error(400, "Bad Request", "invalid-group", "expected group name");
                std::array<std::string_view, 2> args{"probe", *tag};
                auto res = command(args);
                if (!res) {
                    int code = res.error() == "unknown-group" ? 404 : 409;
                    return json_error(code, code == 404 ? "Not Found" : "Conflict", res.error(), res.error());
                }
                return build_http_response(202, "Accepted", "application/json",
                    std::format("{{\"group\":{},\"probe\":\"triggered\"}}\n", json_escape(*tag)));
            }
            if (method == "DELETE" && path == "/v1/connections") {
                std::array<std::string_view, 1> args{"close-all"};
                auto res = command(args);
                if (!res) return json_error(409, "Conflict", res.error(), res.error());
                std::string_view count = "0";
                if (res->starts_with("closed=")) {
                    count = std::string_view(*res).substr(7);
                    while (!count.empty() && (count.back() == '\n' || count.back() == '\r')) count.remove_suffix(1);
                }
                return build_http_response(200, "OK", "application/json",
                    std::format("{{\"closed\":{}}}\n", count.empty() ? "0" : count));
            }
            if (method == "DELETE" && path.starts_with("/v1/connections/")) {
                auto id = path.substr(16);
                if (id.empty() || id.contains('/'))
                    return json_error(400, "Bad Request", "invalid-id", "expected numeric connection id");
                std::array<std::string_view, 2> args{"close-any", id};
                auto res = command(args);
                if (!res) {
                    int code = res.error() == "unknown-connection" ? 404 : (res.error() == "invalid-id" ? 400 : 409);
                    return json_error(code, code == 404 ? "Not Found" : (code == 400 ? "Bad Request" : "Conflict"),
                        res.error(), res.error());
                }
                return build_http_response(200, "OK", "application/json",
                    std::format("{{\"id\":{},\"closed\":true}}\n", json_escape(id)));
            }
            return json_error(404, "Not Found", "not-found", "unknown control endpoint");
        }
    };

    HttpControlServer::HttpControlServer() = default;
    HttpControlServer::~HttpControlServer() { stop(); }
    HttpControlServer::HttpControlServer(HttpControlServer&&) noexcept = default;
    auto HttpControlServer::operator=(HttpControlServer&&) noexcept -> HttpControlServer& = default;

    auto HttpControlServer::active(this HttpControlServer const& self) noexcept -> bool {
        return self.impl_ && self.impl_->listen_fd.valid();
    }

    auto HttpControlServer::start(this HttpControlServer& self, config::ControlHttpConfig const& cfg)
        -> std::expected<void, std::string> {
        if (cfg.metrics && !metrics::available()) {
            return std::unexpected("metrics-openmetrics feature is not enabled in this build");
        }
        auto impl = std::make_unique<Impl>();
        impl->metrics_enabled = cfg.metrics;
        if (!cfg.dashboard_root.empty()) {
            auto root = init_dashboard_root(cfg.dashboard_root);
            if (!root) return std::unexpected(std::move(root.error()));
            impl->dashboard_root = std::move(*root);
        }
        if (!cfg.bearer_token_file.empty()) {
            auto secret = rulefile::read_private_file(cfg.bearer_token_file);
            if (!secret) return std::unexpected("control bearer-token-file: " + secret.error());
            auto raw = secret->bytes();
            std::string_view view(raw.data(), raw.size());
            if (!view.empty() && view.back() == '\n') view.remove_suffix(1);
            if (view.size() < 16 || view.size() > 512)
                return std::unexpected("control bearer token must be 16..512 bytes");
            impl->token.assign(reinterpret_cast<std::uint8_t const*>(view.data()),
                reinterpret_cast<std::uint8_t const*>(view.data()) + view.size());
        }
        auto parsed_ip = platform::parse_ip_address(cfg.host);
        if (!parsed_ip || (parsed_ip->size == 16) != cfg.ipv6)
            return std::unexpected("control http invalid listen address");
        auto sock = create_listen_socket(cfg.ipv6, *parsed_ip, cfg.port);
        if (!sock) return std::unexpected(sock.error());
        impl->listen_fd = std::move(*sock);
        self.impl_ = std::move(impl);
        return {};
    }

    auto HttpControlServer::poll(this HttpControlServer& self, SnapshotBuilder snapshot, CommandHandler command) -> void {
        if (!self.impl_ || !self.impl_->listen_fd.valid()) return;
        auto& impl = *self.impl_;
        auto now = Impl::Clock::now();

        while (impl.peers.size() < kMaxPeers) {
            auto c = accept_nonblocking(impl.listen_fd);
            if (!c.valid()) break;
            impl.peers.push_back(Impl::Peer{std::move(c), {}, {}, 0, false, false, "0", {}, now + kPeerTimeout, {}});
        }

        for (auto it = impl.peers.begin(); it != impl.peers.end();) {
            if (now >= it->deadline) {
                ++impl.expired;
                it = impl.peers.erase(it);
                continue;
            }
            bool done = false;
            if (!it->writing) {
                char buf[2048];
                std::size_t n = 0;
                auto status = recv_nonblocking(it->fd, buf, n);
                if (status == SocketIoStatus::ok) {
                    if (it->in.size() + n > kMaxRequestBytes) {
                        it->out = json_error(413, "Payload Too Large", "request-too-large", "request exceeds 8 KiB");
                        it->writing = true;
                    } else {
                        it->in.append(buf, n);
                        auto hdr_end = it->in.find("\r\n\r\n");
                        if (hdr_end != std::string::npos) {
                            std::size_t content_len = 0;
                            auto head = std::string_view(it->in).substr(0, hdr_end);
                            auto cl_pos = head.find("Content-Length:");
                            if (cl_pos == std::string_view::npos) cl_pos = head.find("content-length:");
                            if (cl_pos != std::string_view::npos) {
                                auto v = head.substr(cl_pos + 15);
                                while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                                auto eol = v.find("\r\n");
                                v = v.substr(0, eol);
                                (void)std::from_chars(v.data(), v.data() + v.size(), content_len);
                            }
                            if (content_len > 4096) {
                                it->out = json_error(413, "Payload Too Large", "body-too-large", "body exceeds 4 KiB");
                                it->writing = true;
                            } else if (it->in.size() >= hdr_end + 4 + content_len) {
                                auto req = std::string_view(it->in);
                                auto f_eol = req.find("\r\n");
                                auto rl = req.substr(0, f_eol);
                                if (rl.starts_with("GET /v1/logs?") && (rl.contains("stream=1") || rl.contains("stream=true"))) {
                                    auto sp1 = rl.find(' '), sp2 = rl.find(' ', sp1 + 1);
                                    auto tgt = sp2 == std::string_view::npos ? std::string_view{} : rl.substr(sp1 + 1, sp2 - sp1 - 1);
                                    auto q = tgt.contains('?') ? tgt.substr(tgt.find('?') + 1) : std::string_view{};
                                    auto hdrs = f_eol == std::string_view::npos ? std::string_view{} : req.substr(f_eol + 2, hdr_end - f_eol - 2);
                                    if (!impl.check_auth(hdrs, q)) {
                                        it->out = json_error(401, "Unauthorized", "unauthorized", "missing or invalid bearer token");
                                    } else {
                                        if (auto v = parse_query_param(q, "since"); v && !v->empty()) it->stream_cursor = *v;
                                        for (std::string_view k : {"level", "domain", "search"})
                                            if (auto v = parse_query_param(q, k); v && !v->empty())
                                                it->stream_filters.push_back(std::string(k) + "=" + *v);
                                        it->out = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
                                        it->streaming = true;
                                        it->deadline = now + std::chrono::seconds(30);
                                        it->next_stream_poll = now;
                                    }
                                    it->writing = true;
                                } else {
                                    it->out = impl.handle_request(it->in, snapshot, command);
                                    if (it->out.size() > kMaxWriteBytes)
                                        it->out = json_error(500, "Internal Server Error", "reply-too-large", "reply cap");
                                    it->writing = true;
                                }
                            }
                        }
                    }
                } else if (status == SocketIoStatus::closed) {
                    done = true;
                }
            }
            if (!done && it->streaming && it->out_offset >= it->out.size() && now >= it->next_stream_poll) {
                it->next_stream_poll = now + std::chrono::milliseconds(100);
                std::vector<std::string> owned{"logs", "since=" + it->stream_cursor, "limit=64"};
                owned.insert(owned.end(), it->stream_filters.begin(), it->stream_filters.end());
                std::vector<std::string_view> args;
                for (auto const& s : owned) args.emplace_back(s);
                if (auto res = command(args); res) {
                    it->out = format_sse_logs(*res, it->stream_cursor);
                    it->out_offset = 0;
                }
            }
            if (!done && it->writing) {
                while (it->out_offset < it->out.size()) {
                    std::size_t n = 0;
                    auto status = send_nonblocking(it->fd,
                        std::span<char const>(it->out.data() + it->out_offset, it->out.size() - it->out_offset), n);
                    if (status == SocketIoStatus::ok) it->out_offset += n;
                    else { if (status == SocketIoStatus::closed) done = true; break; }
                }
                if (!it->streaming && it->out_offset >= it->out.size()) done = true;
            }
            if (done) it = impl.peers.erase(it); else ++it;
        }
    }

    auto HttpControlServer::stop(this HttpControlServer& self) noexcept -> void { self.impl_.reset(); }
}
