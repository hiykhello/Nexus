module;
#include <cstring>

module control_api;

import std;
import config;
import control_api.http_socket;
import control_api.ssmapi_bridge;
import control_api.types;
import control_api.http_format;
import control_api.http_stream;
import control_api.http_extra_routes;
import control_api.dashboard_static;
import control_api.http_ws;
import crypto;
import metrics;
import platform.ip_address;
import rulefile;

namespace control_api {
    using namespace http_detail;
    namespace {
        constexpr std::size_t kMaxPeers = 16;
        constexpr std::size_t kMaxRequestBytes = 8192;
        constexpr std::size_t kMaxWriteBytes = kMaxDashboardFileBytes + 8192;
        constexpr auto kPeerTimeout = std::chrono::seconds(2);
    }

    struct HttpControlServer::Impl {
        using Clock = StreamClock;

        Fd listen_fd;
        bool metrics_enabled = false;
        bool ssmapi_enabled = false;
        std::string ssmapi_prefix{"/ssmapi"};
        SsmApiBridge ssmapi;
        std::filesystem::path dashboard_root;
        std::vector<std::uint8_t> token;
        std::vector<std::string> cors_allow_origins;
        std::vector<Peer> peers;
        std::vector<WsPeer> ws_peers;
        std::uint64_t authorized = 0, unauthorized = 0, expired = 0;

        ~Impl() {
            if (!token.empty()) crypto::cleanse(token);
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
            auto provided = extract_bearer_token(headers);
            auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(provided.data()), provided.size());
            bool ok = !provided.empty() && crypto::constant_time_equal(token, bytes);
            if (ok) ++authorized;
            else ++unauthorized;
            return ok;
        }

        auto fetch_snapshot(ScopedSnapshotBuilder snapshot, SnapshotFields f,
            std::optional<std::uint64_t> cid = std::nullopt) const -> ControlSnapshot {
            auto snap = snapshot(f, cid);
            snap.authorized_requests += authorized;
            snap.unauthorized_requests += unauthorized;
            snap.expired_requests += expired;
            return snap;
        }

        auto handle_request(std::string_view raw, ScopedSnapshotBuilder snapshot, CommandHandler command) -> std::string {
            auto header_end = raw.find("\r\n\r\n");
            if (header_end == std::string_view::npos) return json_error(400, "Bad Request", "bad-request", "malformed HTTP");
            auto req = parse_http_request_head(raw, header_end);
            if (!req.valid) return json_error(400, "Bad Request", "invalid-request", "invalid request line");
            auto [method, path, query, headers, body, _] = req;
            auto target = query.empty() ? std::string(path) : (std::string(path) + "?" + std::string(query));
            bool is_ssmapi = ssmapi_enabled && (path == ssmapi_prefix || path.starts_with(ssmapi_prefix + "/"));
            bool is_api = is_ssmapi || path == "/v1" || path.starts_with("/v1/") || path == "/metrics";
            if (!is_api) {
                if (!dashboard_root.empty())
                    return serve_dashboard_request(dashboard_root, method, path);
                if (has_embedded_dashboard())
                    return serve_embedded_dashboard_request(method, path, headers);
            }
            auto req_origin = extract_header_value(headers, "origin");
            auto matched_cors = match_cors_origin(cors_allow_origins, req_origin);
            auto with_cors = [&](std::string resp) -> std::string {
                return matched_cors ? inject_cors_headers(std::move(resp), *matched_cors) : std::move(resp);
            };
            if (is_api && method == "OPTIONS" && !cors_allow_origins.empty()) {
                if (!matched_cors)
                    return json_error(403, "Forbidden", "cors-origin-denied", "origin is not allowed");
                return cors_preflight_response(*matched_cors);
            }
            if (path == "/v1/ws") {
                auto up = evaluate_ws_upgrade(req, token, cors_allow_origins);
                if (up.auth_failed) ++unauthorized;
                else if (up.authenticated) ++authorized;
                return up.upgraded ? std::move(up.http_response) : with_cors(std::move(up.http_response));
            }
            if (!check_auth(headers, query))
                return with_cors(json_error(401, "Unauthorized", "unauthorized", "missing or invalid bearer token"));

            if (is_ssmapi) {
                if (auto res = ssmapi.dispatch(ssmapi_prefix, method, target, body)) {
                    auto const* reason = res->first == 201 ? "Created" : res->first == 204 ? "No Content" :
                        res->first == 400 ? "Bad Request" : res->first == 404 ? "Not Found" : "OK";
                    return with_cors(build_http_response(res->first, reason, "application/json",
                        res->second.empty() ? std::string{} : res->second + "\n"));
                }
            }

            auto fetch = [&](SnapshotFields f, std::optional<std::uint64_t> cid = std::nullopt) -> ControlSnapshot {
                return fetch_snapshot(snapshot, f, cid);
            };

            if (method == "GET" && path == "/v1/health")
                return with_cors(build_http_response(200, "OK", "application/json",
                    std::format("{{\"status\":\"ok\",\"instance\":{}}}\n", json_escape(fetch(SnapshotFields::meta).instance))));
            if (method == "GET" && path == "/v1/status")
                return with_cors(build_http_response(200, "OK", "application/json",
                    render_status_json(fetch(SnapshotFields::meta | SnapshotFields::listeners))));
            if (method == "GET" && path == "/v1/mode")
                return with_cors(build_http_response(200, "OK", "application/json", render_mode_json(fetch(SnapshotFields::meta))));
            if (method == "GET" && path == "/v1/outbounds")
                return with_cors(build_http_response(200, "OK", "application/json",
                    render_outbounds_json(fetch(SnapshotFields::meta | SnapshotFields::groups))));
            if (method == "GET" && path == "/v1/rules")
                return with_cors(build_http_response(200, "OK", "application/json",
                    render_rules_json(fetch(SnapshotFields::rules))));
            if (method == "GET" && path == "/v1/dns/query")
                return with_cors(handle_direct_dns_query(query, command));
            if (method == "GET" && path == "/v1/connections")
                return with_cors(build_http_response(200, "OK", "application/json",
                    render_connections_json(fetch(SnapshotFields::connections))));
            if (method == "GET" && path.starts_with("/v1/connections/")) {
                auto id_str = path.substr(16);
                std::uint64_t cid = 0;
                auto [end, ec] = std::from_chars(id_str.data(), id_str.data() + id_str.size(), cid);
                if (id_str.empty() || id_str.contains('/') || ec != std::errc{} || end != id_str.data() + id_str.size() || !cid)
                    return with_cors(json_error(400, "Bad Request", "invalid-id", "expected numeric connection id"));
                auto snap = fetch(SnapshotFields::connections, cid);
                auto it = std::ranges::find(snap.connections, cid, &ConnectionMetric::id);
                if (it == snap.connections.end())
                    return with_cors(json_error(404, "Not Found", "unknown-connection", "connection not found"));
                return with_cors(build_http_response(200, "OK", "application/json", render_connection_detail_json(*it)));
            }
            if (method == "GET" && path == "/v1/logs") {
                auto owned = build_log_command_args(query);
                if (!owned) return with_cors(json_error(400, "Bad Request", owned.error(), "malformed query parameter"));
                std::vector<std::string_view> args;
                args.reserve(owned->size());
                for (auto const& s : *owned) args.emplace_back(s);
                auto res = command(args);
                if (!res) return with_cors(json_error(400, "Bad Request", res.error(), res.error()));
                return with_cors(build_http_response(200, "OK", "application/json", render_logs_json(*res)));
            }
            if (method == "GET" && path == "/v1/diagnostics")
                return with_cors(build_http_response(200, "OK", "application/json",
                    render_diagnostics_json(fetch(SnapshotFields::meta | SnapshotFields::listeners | SnapshotFields::connections))));
            if (method == "GET" && path == "/v1/events") {
                std::string_view cursor = "0";
                if (query.starts_with("cursor=")) {
                    auto v = query.substr(7);
                    auto amp = v.find('&');
                    cursor = amp == std::string_view::npos ? v : v.substr(0, amp);
                }
                std::array<std::string_view, 2> args{"events", cursor};
                auto res = command(args);
                if (!res) return with_cors(json_error(400, "Bad Request", res.error(), res.error()));
                return with_cors(build_http_response(200, "OK", "application/json", render_events_json(*res)));
            }
            if (method == "GET" && path == "/metrics") {
                if (!metrics_enabled || !metrics::available())
                    return with_cors(json_error(404, "Not Found", "metrics-disabled", "OpenMetrics endpoint is disabled"));
                return with_cors(build_http_response(200, "OK",
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    metrics::render_openmetrics(fetch(SnapshotFields::meta | SnapshotFields::listeners | SnapshotFields::groups))));
            }
            if (method == "PUT" && path == "/v1/mode") {
                auto mode = extract_json_string(body, "mode");
                auto outbound = extract_json_string(body, "outbound");
                if (!mode || mode->empty())
                    return with_cors(json_error(400, "Bad Request", "invalid-body", "expected {\"mode\":\"...\"}"));
                std::expected<std::string, std::string> res;
                if (outbound && !outbound->empty()) {
                    std::array<std::string_view, 3> args{"mode", *mode, *outbound};
                    res = command(args);
                } else {
                    std::array<std::string_view, 2> args{"mode", *mode};
                    res = command(args);
                }
                if (!res) {
                    int code = res.error() == "invalid-mode" ? 400 : (res.error() == "unknown-outbound" ? 404 : 409);
                    return with_cors(json_error(code, code == 400 ? "Bad Request" : (code == 404 ? "Not Found" : "Conflict"),
                        res.error(), res.error()));
                }
                return with_cors(build_http_response(200, "OK", "application/json", render_mode_json(fetch(SnapshotFields::meta))));
            }
            if (auto raw_tag = parse_group_select_tag(method, path))
                return with_cors(handle_group_select(*raw_tag, body, fetch, command));
            if (method == "POST" && path == "/v1/log-level") {
                auto level = extract_json_string(body, "level");
                auto domain = extract_json_string(body, "domain").value_or("global");
                if (!level || level->empty() || domain.empty())
                    return with_cors(json_error(400, "Bad Request", "invalid-body", "expected {\"level\":\"...\"}"));
                std::array<std::string_view, 3> args{"log-level", domain, *level};
                auto res = command(args);
                if (!res) return with_cors(json_error(400, "Bad Request", "invalid-log-level", res.error()));
                return with_cors(build_http_response(200, "OK", "application/json",
                    std::format("{{\"domain\":{},\"level\":{}}}\n", json_escape(domain), json_escape(*level))));
            }
            if (method == "POST" && path == "/v1/reload") {
                std::array<std::string_view, 1> args{"reload"};
                auto res = command(args);
                if (!res) return with_cors(json_error(409, "Conflict", res.error(), res.error()));
                return with_cors(build_http_response(202, "Accepted", "application/json",
                    std::format("{{\"state\":\"pending\",\"detail\":{}}}\n", json_escape(*res))));
            }
            if (method == "POST" && path == "/v1/cache/fakeip/flush")
                return with_cors(handle_fakeip_flush(command));
            if (method == "POST" && path == "/v1/state/clear-cache")
                return with_cors(handle_clear_cache(query, body, command));
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
                if (!res) return with_cors(json_error(409, "Conflict", res.error(), res.error()));
                return with_cors(build_http_response(200, "OK", "application/json",
                    std::format("{{\"accepted\":true,\"detail\":{}}}\n", json_escape(*res))));
            }
            if (is_outbound_probe_route(method, path))
                return with_cors(handle_direct_outbound_probe(path, body, command));
            if (method == "POST" && path.size() > 17 && path.starts_with("/v1/groups/") && path.ends_with("/probe")) {
                auto raw_tag = path.substr(11, path.size() - 17);
                auto tag = url_decode_once(raw_tag);
                if (!tag || tag->empty())
                    return with_cors(json_error(400, "Bad Request", "invalid-group", "expected group name"));
                std::array<std::string_view, 2> args{"probe", *tag};
                auto res = command(args);
                if (!res) {
                    int code = res.error() == "unknown-group" ? 404 : 409;
                    return with_cors(json_error(code, code == 404 ? "Not Found" : "Conflict", res.error(), res.error()));
                }
                return with_cors(build_http_response(202, "Accepted", "application/json",
                    std::format("{{\"group\":{},\"probe\":\"triggered\"}}\n", json_escape(*tag))));
            }
            if (method == "DELETE" && path == "/v1/connections") {
                std::array<std::string_view, 1> args{"close-all"};
                auto res = command(args);
                if (!res) return with_cors(json_error(409, "Conflict", res.error(), res.error()));
                std::string_view count = "0";
                if (res->starts_with("closed=")) {
                    count = std::string_view(*res).substr(7);
                    while (!count.empty() && (count.back() == '\n' || count.back() == '\r')) count.remove_suffix(1);
                }
                return with_cors(build_http_response(200, "OK", "application/json",
                    std::format("{{\"closed\":{}}}\n", count.empty() ? "0" : count)));
            }
            if (method == "DELETE" && path.starts_with("/v1/connections/")) {
                auto id = path.substr(16);
                if (id.empty() || id.contains('/'))
                    return with_cors(json_error(400, "Bad Request", "invalid-id", "expected numeric connection id"));
                std::array<std::string_view, 2> args{"close-any", id};
                auto res = command(args);
                if (!res) {
                    int code = res.error() == "unknown-connection" ? 404 : (res.error() == "invalid-id" ? 400 : 409);
                    return with_cors(json_error(code, code == 404 ? "Not Found" : (code == 400 ? "Bad Request" : "Conflict"),
                        res.error(), res.error()));
                }
                return with_cors(build_http_response(200, "OK", "application/json",
                    std::format("{{\"id\":{},\"closed\":true}}\n", json_escape(id))));
            }
            return with_cors(json_error(404, "Not Found", "not-found", "unknown control endpoint"));
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
        impl->cors_allow_origins = cfg.cors_allow_origins;
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

    auto HttpControlServer::configure_ssmapi(this HttpControlServer& self, bool enabled,
        std::string prefix) -> std::expected<void, std::string> {
        if (!enabled) {
            if (self.impl_) self.impl_->ssmapi_enabled = false;
            return {};
        }
        if (!ssmapi_available()) return std::unexpected("ssmapi feature is not enabled in this build");
        if (!self.impl_) self.impl_ = std::make_unique<Impl>();
        self.impl_->ssmapi_enabled = true;
        self.impl_->ssmapi_prefix = prefix.empty() ? std::string("/ssmapi") : std::move(prefix);
        return {};
    }

    auto HttpControlServer::handle_direct_http_for_test(this HttpControlServer& self, std::string_view raw,
        SnapshotBuilder snapshot, CommandHandler command) -> std::string {
        return self.handle_direct_http_for_test(raw,
            [&](SnapshotFields, std::optional<std::uint64_t>) { return snapshot(); }, command);
    }

    auto HttpControlServer::handle_direct_http_for_test(this HttpControlServer& self, std::string_view raw,
        ScopedSnapshotBuilder snapshot, CommandHandler command) -> std::string {
        if (!self.impl_) self.impl_ = std::make_unique<Impl>();
        return self.impl_->handle_request(raw, snapshot, command);
    }

    auto HttpControlServer::poll(this HttpControlServer& self, SnapshotBuilder snapshot, CommandHandler command) -> void {
        self.poll([&](SnapshotFields, std::optional<std::uint64_t>) { return snapshot(); }, command);
    }

    auto HttpControlServer::poll(this HttpControlServer& self, ScopedSnapshotBuilder snapshot, CommandHandler command) -> void {
        if (!self.impl_ || !self.impl_->listen_fd.valid()) return;
        auto& impl = *self.impl_;
        auto now = Impl::Clock::now();
        auto fetch = [&](SnapshotFields f, std::optional<std::uint64_t> cid) -> ControlSnapshot {
            return impl.fetch_snapshot(snapshot, f, cid);
        };

        while (impl.peers.size() < kMaxPeers) {
            auto c = accept_nonblocking(impl.listen_fd);
            if (!c.valid()) break;
            Peer peer{};
            peer.fd = std::move(c);
            peer.deadline = now + kPeerTimeout;
            impl.peers.push_back(std::move(peer));
        }

        for (auto it = impl.peers.begin(); it != impl.peers.end();) {
            if (now >= it->deadline) { ++impl.expired; it = impl.peers.erase(it); continue; }
            bool done = false;
            if (!it->writing && !it->has_pending_probe() && !it->has_pending_dns_query()) {
                char buf[2048];
                std::size_t n = 0;
                auto status = recv_nonblocking(it->fd, buf, n);
                if (status == SocketIoStatus::ok) {
                    if (it->in.size() + n > kMaxRequestBytes) {
                        it->out = json_error(413, "Payload Too Large", "request-too-large", "request exceeds 8 KiB");
                        it->writing = true;
                    } else {
                        it->in.append(buf, n);
                        if (auto hdr_end = it->in.find("\r\n\r\n"); hdr_end != std::string::npos) {
                            auto content_len = parse_content_length(std::string_view(it->in).substr(0, hdr_end));
                            if (!content_len) { it->out = json_error(400, "Bad Request", "invalid-content-length", "malformed Content-Length"); it->writing = true; }
                            else if (*content_len > 4096) { it->out = json_error(413, "Payload Too Large", "body-too-large", "body exceeds 4 KiB"); it->writing = true; }
                            else if (it->in.size() >= hdr_end + 4 + *content_len) {
                                auto raw_req = std::string_view(it->in).substr(0, hdr_end + 4 + *content_len);
                                auto req = parse_http_request_head(raw_req, hdr_end);
                                if (req.valid) {
                                    if (auto mc = match_cors_origin(impl.cors_allow_origins, extract_header_value(req.headers, "origin")))
                                        it->cors_origin = std::string(*mc);
                                }
                                if (req.valid && req.path == "/v1/ws") {
                                    done = try_upgrade_ws_peer(*it, req, hdr_end, *content_len, impl.ws_peers,
                                        impl.token, impl.cors_allow_origins, now, impl.authorized, impl.unauthorized);
                                } else {
                                auto skind = req.valid ? detect_stream_kind(req.method, req.path, req.query) : StreamKind::none;
                                if (skind != StreamKind::none) {
                                    if (!impl.check_auth(req.headers, req.query)) {
                                        it->out = inject_cors_headers(json_error(401, "Unauthorized", "unauthorized", "missing or invalid bearer token"), it->cors_origin);
                                        it->writing = true;
                                    } else if (skind == StreamKind::logs && !build_log_command_args(req.query)) {
                                        it->out = inject_cors_headers(json_error(400, "Bad Request", "invalid-query", "malformed query parameter"), it->cors_origin);
                                        it->writing = true;
                                    } else setup_sse_peer(*it, skind, req.query, now, fetch);
                                } else if (req.valid && is_outbound_probe_route(req.method, req.path)) {
                                    if (!impl.check_auth(req.headers, req.query)) {
                                        it->out = inject_cors_headers(json_error(401, "Unauthorized", "unauthorized", "missing or invalid bearer token"), it->cors_origin);
                                        it->writing = true;
                                    } else start_deferred_probe(*it, req.path, req.body, now, command);
                                } else if (req.valid && req.method == "GET" && req.path == "/v1/dns/query") {
                                    if (!impl.check_auth(req.headers, req.query)) {
                                        it->out = inject_cors_headers(json_error(401, "Unauthorized", "unauthorized", "missing or invalid bearer token"), it->cors_origin);
                                        it->writing = true;
                                    } else start_deferred_dns_query(*it, req.query, now, command);
                                } else {
                                    it->out = impl.handle_request(raw_req, snapshot, command);
                                    if (it->out.size() > kMaxWriteBytes)
                                        it->out = json_error(500, "Internal Server Error", "reply-too-large", "reply cap");
                                    it->writing = true;
                                }
                                }
                            }
                        }
                    }
                } else if (status == SocketIoStatus::closed) {
                    done = true;
                }
            }
            if (!done && it->has_pending_probe() && now >= it->next_stream_poll)
                poll_deferred_probe(*it, now, command);
            if (!done && it->has_pending_dns_query() && now >= it->next_stream_poll)
                poll_deferred_dns_query(*it, now, command);
            if (!done && it->is_streaming() && it->out_offset >= it->out.size() && now >= it->next_stream_poll)
                tick_sse_peer(*it, now, fetch, command);
            if (!done && it->writing)
                done = flush_peer_writes(*it, now);
            if (done) it = impl.peers.erase(it); else ++it;
        }
        poll_ws_peers(impl.ws_peers, impl.token, now, fetch, command, impl.authorized, impl.unauthorized, impl.expired);
    }

    auto HttpControlServer::listen_native_fd(this HttpControlServer const& self) noexcept -> int {
#if defined(_WIN32)
        (void)self; return -1;
#else
        return (self.impl_ && self.impl_->listen_fd.valid()) ? static_cast<int>(self.impl_->listen_fd.native()) : -1;
#endif
    }
    auto HttpControlServer::next_poll_delay(this HttpControlServer const& self) noexcept
        -> std::optional<std::chrono::milliseconds> {
        if (!self.impl_ || !self.impl_->listen_fd.valid()) return std::nullopt;
        auto now = Impl::Clock::now();
        auto d1 = compute_peers_poll_delay(self.impl_->peers, now);
        auto d2 = compute_ws_peers_poll_delay(self.impl_->ws_peers, now);
        if (d1 && d2) return std::min(*d1, *d2);
        return d1 ? d1 : d2;
    }

    auto HttpControlServer::attach_ssmapi_users(this HttpControlServer& self,
        std::shared_ptr<relay::ShadowsocksUserDirectory> users) noexcept -> void {
        if (self.impl_) self.impl_->ssmapi.attach_users(std::move(users));
    }

    auto HttpControlServer::stop(this HttpControlServer& self) noexcept -> void { self.impl_.reset(); }
}
