// Hysteria 2 HTTP/3 server masquerade responder (string, file, proxy).
export module relay.hysteria2_masquerade;
import std;
import config;
import http.connect;
import http.header;
import platform.ip_address;
import tls.profiles;
import tls.corosio_client;
import tls.corosio_application;
import tls.application_io;
import capy;
import corosio;

export namespace relay::hysteria2_masquerade {
    inline constexpr std::size_t max_file_bytes = 16u * 1024u * 1024u;
    inline constexpr std::size_t max_proxy_body_bytes = 4u * 1024u * 1024u;

    struct Request {
        std::string method{"GET"};
        std::string path{"/"};
        std::string authority;
        std::vector<std::pair<std::string, std::string>> headers;
    };

    struct Response {
        std::uint16_t status = 404;
        std::vector<std::pair<std::string, std::string>> headers;
        std::vector<std::uint8_t> body;
        bool omit_body = false;
    };

    namespace detail {
        inline auto ascii_lower(std::string_view in) -> std::string {
            std::string out;
            out.reserve(in.size());
            for (unsigned char c : in)
                out.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c));
            return out;
        }

        inline auto trim_ows(std::string_view v) noexcept -> std::string_view {
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
            return v;
        }

        inline auto forbidden_header(std::string_view lower_name) noexcept -> bool {
            if (lower_name.empty() || lower_name.front() == ':' || lower_name.starts_with("hysteria-")) return true;
            constexpr std::array<std::string_view, 9> hop{
                "connection", "keep-alive", "proxy-connection", "transfer-encoding",
                "upgrade", "te", "host", "content-length", "proxy-authenticate"
            };
            return std::ranges::contains(hop, lower_name);
        }

        inline auto valid_token(std::string_view s) noexcept -> bool {
            if (s.empty() || s.size() > 64) return false;
            return std::ranges::all_of(s, [](unsigned char c) {
                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
                    c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
                    c == '`' || c == '|' || c == '~';
            });
        }

        inline auto valid_header_value(std::string_view v) noexcept -> bool {
            return v.size() <= 4096 && std::ranges::all_of(v, [](unsigned char c) {
                return c == '\t' || (c >= 0x20 && c != 0x7f);
            });
        }

        inline auto hex_nibble(char c) noexcept -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        inline auto decode_url_path(std::string_view raw) -> std::optional<std::string> {
            auto cut = raw.find_first_of("?#");
            if (cut != std::string_view::npos) raw = raw.substr(0, cut);
            if (raw.empty() || raw.front() != '/' || raw.size() > 2048) return std::nullopt;
            std::string out;
            out.reserve(raw.size());
            for (std::size_t i = 0; i < raw.size(); ++i) {
                unsigned char c = static_cast<unsigned char>(raw[i]);
                if (c == '%') {
                    if (i + 2 >= raw.size()) return std::nullopt;
                    int hi = hex_nibble(raw[i + 1]), lo = hex_nibble(raw[i + 2]);
                    if (hi < 0 || lo < 0) return std::nullopt;
                    c = static_cast<unsigned char>((hi << 4) | lo);
                    i += 2;
                }
                if (c < 0x20 || c == 0x7f || c == '\\') return std::nullopt;
                out.push_back(static_cast<char>(c));
            }
            return out;
        }

        inline auto mime_type(std::filesystem::path const& file) -> std::string {
            auto ext = ascii_lower(file.extension().string());
            if (ext == ".html" || ext == ".htm") return "text/html; charset=utf-8";
            if (ext == ".css") return "text/css; charset=utf-8";
            if (ext == ".js" || ext == ".mjs") return "application/javascript; charset=utf-8";
            if (ext == ".json") return "application/json";
            if (ext == ".xml") return "application/xml";
            if (ext == ".txt") return "text/plain; charset=utf-8";
            if (ext == ".svg") return "image/svg+xml";
            if (ext == ".png") return "image/png";
            if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
            if (ext == ".gif") return "image/gif";
            if (ext == ".webp") return "image/webp";
            if (ext == ".ico") return "image/x-icon";
            if (ext == ".woff2") return "font/woff2";
            if (ext == ".pdf") return "application/pdf";
            return "application/octet-stream";
        }

        inline auto path_within_root(std::filesystem::path const& root, std::filesystem::path const& target) -> bool {
            auto rit = root.begin(), tit = target.begin();
            for (; rit != root.end(); ++rit, ++tit) {
                if (tit == target.end() || *rit != *tit) return false;
            }
            return tit != target.end();
        }

        struct ProxyUrl {
            bool https = false;
            std::string host;
            std::uint16_t port = 80;
            std::string base_path;
        };

        inline auto parse_proxy_url(std::string_view url) -> std::optional<ProxyUrl> {
            ProxyUrl out{};
            std::string_view rest = url;
            if (rest.starts_with("http://")) { out.https = false; out.port = 80; rest.remove_prefix(7); }
            else if (rest.starts_with("https://")) { out.https = true; out.port = 443; rest.remove_prefix(8); }
            else return std::nullopt;
            auto slash = rest.find('/');
            auto authority = rest.substr(0, slash);
            if (slash != std::string_view::npos) {
                out.base_path = std::string(rest.substr(slash));
                while (out.base_path.size() > 1 && out.base_path.back() == '/') out.base_path.pop_back();
                if (out.base_path == "/") out.base_path.clear();
            }
            if (authority.empty()) return std::nullopt;
            std::string_view host = authority, port_s;
            if (authority.front() == '[') {
                auto close = authority.find(']');
                if (close == std::string_view::npos || close <= 1) return std::nullopt;
                host = authority.substr(1, close - 1);
                if (close + 1 < authority.size()) {
                    if (authority[close + 1] != ':') return std::nullopt;
                    port_s = authority.substr(close + 2);
                }
            } else {
                auto colon = authority.rfind(':');
                if (colon != std::string_view::npos) {
                    host = authority.substr(0, colon);
                    port_s = authority.substr(colon + 1);
                }
            }
            if (host.empty()) return std::nullopt;
            out.host = std::string(host);
            if (!port_s.empty()) {
                std::uint16_t p = 0;
                auto [end, ec] = std::from_chars(port_s.data(), port_s.data() + port_s.size(), p);
                if (ec != std::errc{} || end != port_s.data() + port_s.size() || !p) return std::nullopt;
                out.port = p;
            }
            return out;
        }

        inline auto build_proxy_request(ProxyUrl const& target, config::Hysteria2Masquerade const& cfg, Request const& req) -> std::string {
            std::string method = valid_token(req.method) ? req.method : "GET";
            std::string path = (!req.path.empty() && req.path.front() == '/' &&
                std::ranges::all_of(req.path, [](unsigned char c) { return c > 0x20 && c < 0x7f; }))
                ? req.path : "/";
            std::string combined = target.base_path + path;
            std::string host_header;
            if (cfg.rewrite_host || req.authority.empty() || !valid_header_value(req.authority)) {
                bool ipv6 = target.host.contains(':');
                host_header = ipv6 ? ("[" + target.host + "]") : target.host;
                std::uint16_t def_port = target.https ? 443 : 80;
                if (target.port != def_port) host_header += ":" + std::to_string(target.port);
            } else {
                host_header = req.authority;
            }
            std::string wire;
            wire.reserve(256 + combined.size());
            wire += method; wire += ' '; wire += combined; wire += " HTTP/1.1\r\n";
            wire += "Host: "; wire += host_header; wire += "\r\n";
            for (auto const& [k, v] : req.headers) {
                auto low = ascii_lower(k);
                if (forbidden_header(low) || low == "accept-encoding" || !valid_token(low) || !valid_header_value(v)) continue;
                wire += low; wire += ": "; wire += v; wire += "\r\n";
            }
            wire += "Accept-Encoding: identity\r\nConnection: close\r\n\r\n";
            return wire;
        }

        inline auto parse_response_headers(std::string_view wire, Response& out) -> bool {
            auto line_end = wire.find("\r\n");
            if (line_end == std::string_view::npos) return false;
            auto status_line = wire.substr(0, line_end);
            auto sp1 = status_line.find(' ');
            if (sp1 == std::string_view::npos || sp1 + 4 > status_line.size()) return false;
            std::uint16_t code = 0;
            auto code_sv = status_line.substr(sp1 + 1, 3);
            auto [end, ec] = std::from_chars(code_sv.data(), code_sv.data() + code_sv.size(), code);
            if (ec != std::errc{} || end != code_sv.data() + 3 || code < 200 || code > 599) return false;
            out.status = code;
            out.headers.clear();
            auto rest = wire.substr(line_end + 2);
            while (!rest.empty()) {
                auto nl = rest.find("\r\n");
                auto line = nl == std::string_view::npos ? rest : rest.substr(0, nl);
                if (nl == std::string_view::npos) rest = {};
                else rest.remove_prefix(nl + 2);
                if (line.empty()) break;
                auto colon = line.find(':');
                if (colon == std::string_view::npos) continue;
                auto name = ascii_lower(trim_ows(line.substr(0, colon)));
                auto val = trim_ows(line.substr(colon + 1));
                if (forbidden_header(name) || !valid_token(name) || !valid_header_value(val)) continue;
                if (out.headers.size() < 64) out.headers.emplace_back(std::move(name), std::string(val));
            }
            return true;
        }

        inline auto consume_response_chunk(http::ResponseDecoder& decoder, std::string_view data,
            Response& resp, bool& got_header, bool& complete) -> bool {
            while (!data.empty()) {
                auto step = decoder.feed(data);
                if (step.event == http::ResponseEvent::malformed || step.event == http::ResponseEvent::truncated || !step.consumed)
                    return false;
                data.remove_prefix(step.consumed);
                if (step.event == http::ResponseEvent::header && !step.informational) {
                    if (!parse_response_headers(step.wire, resp)) return false;
                    got_header = true;
                } else if ((step.event == http::ResponseEvent::data || step.event == http::ResponseEvent::complete) && !step.wire.empty()) {
                    if (!got_header && !step.informational && step.wire.starts_with("HTTP/")) {
                        if (!parse_response_headers(step.wire, resp)) return false;
                        got_header = true;
                    } else {
                        if (step.wire.size() > max_proxy_body_bytes - resp.body.size()) return false;
                        auto ptr = reinterpret_cast<std::uint8_t const*>(step.wire.data());
                        resp.body.insert(resp.body.end(), ptr, ptr + step.wire.size());
                    }
                }
                if (step.event == http::ResponseEvent::complete) { complete = true; return true; }
            }
            if (!complete && decoder.feed({}).event == http::ResponseEvent::complete) complete = true;
            return true;
        }

        inline auto exchange_http(corosio::io_context& ctx, corosio::endpoint ep, std::string const& wire_req,
            bool is_head, std::chrono::steady_clock::time_point deadline, std::stop_token stop)
            -> capy::task<std::optional<Response>> {
            corosio::tcp_socket sock(ctx);
            if (auto ec = sock.open(ep.address().family())) co_return std::nullopt;
            std::stop_callback on_stop(stop, [&]() noexcept { sock.cancel(); });
            if (stop.stop_requested()) co_return std::nullopt;
            auto [cec] = co_await corosio::timeout(sock.connect(ep), deadline);
            if (cec) co_return std::nullopt;
            std::size_t off = 0;
            while (off < wire_req.size()) {
                auto [wec, n] = co_await corosio::timeout(
                    sock.write_some(capy::const_buffer(wire_req.data() + off, wire_req.size() - off)), deadline);
                if (wec || !n) co_return std::nullopt;
                off += n;
            }
            http::ResponseDecoder decoder(is_head, false, http::ChunkOutput::payload);
            Response resp; resp.omit_body = is_head;
            bool got_header = false, complete = false;
            std::array<char, 4096> buf{};
            while (!complete) {
                auto [rec, n] = co_await corosio::timeout(
                    sock.read_some(capy::mutable_buffer(buf.data(), buf.size())), deadline);
                if (n > 0) {
                    if (!consume_response_chunk(decoder, {buf.data(), n}, resp, got_header, complete)) co_return std::nullopt;
                }
                if (rec) {
                    if (!complete) {
                        auto fin = decoder.finish();
                        if (fin.event != http::ResponseEvent::complete) co_return std::nullopt;
                        complete = true;
                    }
                    break;
                }
            }
            co_return got_header ? std::optional(std::move(resp)) : std::nullopt;
        }

        inline auto exchange_https(corosio::io_context& ctx, ProxyUrl const& target, corosio::endpoint ep,
            std::string const& wire_req, bool is_head, std::chrono::steady_clock::time_point deadline, std::stop_token stop)
            -> capy::task<std::optional<Response>> {
            constexpr std::array<std::string_view, 1> alpn{"http/1.1"};
            auto profile = tls::ClientProfile::load(target.host, "", 0x001d, false, alpn);
            if (!profile) co_return std::nullopt;
            auto now_ms = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
            auto end_ms = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count());
            auto wall = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            auto hs = profile->handshake(now_ms, end_ms, wall);
            if (!hs) co_return std::nullopt;
            tls::detail::OwnedClient owned(ctx, std::move(*hs));
            std::stop_callback on_stop(stop, [&]() noexcept { owned.cancel(); });
            if (stop.stop_requested()) co_return std::nullopt;
            if (!co_await owned.start(ep)) co_return std::nullopt;
            auto* client = owned.client();
            auto* app = client ? client->application() : nullptr;
            if (!app) co_return std::nullopt;
            tls::detail::ApplicationDeadline app_dl{deadline};
            auto req_bytes = std::span(reinterpret_cast<std::uint8_t const*>(wire_req.data()), wire_req.size());
            if (!co_await app->send_all(req_bytes, app_dl)) { app->cancel(); co_return std::nullopt; }
            tls::detail::ApplicationStreamReader reader(*app);
            http::ResponseDecoder decoder(is_head, false, http::ChunkOutput::payload);
            Response resp; resp.omit_body = is_head;
            bool got_header = false, complete = false;
            std::array<std::uint8_t, 4096> buf{};
            while (!complete) {
                auto rd = co_await reader.read_some(buf, app_dl);
                if (!rd) co_return std::nullopt;
                if (rd->kind == tls::detail::AsyncStreamReadKind::backpressure) {
                    if (!co_await app->flush(app_dl)) co_return std::nullopt;
                    continue;
                }
                if (rd->kind == tls::detail::AsyncStreamReadKind::eof) {
                    if (decoder.finish().event != http::ResponseEvent::complete) co_return std::nullopt;
                    complete = true; break;
                }
                if (rd->kind == tls::detail::AsyncStreamReadKind::event) {
                    auto k = rd->event->kind;
                    if (k == tls::ApplicationEventKind::close_notify) {
                        if (decoder.finish().event != http::ResponseEvent::complete) co_return std::nullopt;
                        complete = true; break;
                    }
                    if (k == tls::ApplicationEventKind::key_update_requested) {
                        if (!co_await app->flush(app_dl)) co_return std::nullopt;
                    }
                    continue;
                }
                std::string_view data(reinterpret_cast<char const*>(buf.data()), rd->size);
                if (!consume_response_chunk(decoder, data, resp, got_header, complete)) { app->cancel(); co_return std::nullopt; }
            }
            (void)co_await app->close_notify(app_dl);
            co_return got_header ? std::optional(std::move(resp)) : std::nullopt;
        }
    }

    inline auto parse_request(std::span<http::HeaderField const> fields) -> Request {
        Request out{};
        for (auto const& f : fields) {
            if (f.name == ":method") out.method = std::string(f.value);
            else if (f.name == ":path") out.path = std::string(f.value);
            else if (f.name == ":authority") out.authority = std::string(f.value);
            else if (!f.name.empty() && f.name.front() != ':') {
                auto low = detail::ascii_lower(f.name);
                if (!detail::forbidden_header(low) && out.headers.size() < 64)
                    out.headers.emplace_back(std::move(low), std::string(f.value));
            }
        }
        return out;
    }

    inline auto serve_string(config::Hysteria2Masquerade const& cfg, Request const& req) -> Response {
        Response resp{};
        resp.status = (cfg.status_code >= 200 && cfg.status_code <= 599) ? cfg.status_code : std::uint16_t{200};
        bool has_ct = false;
        for (auto const& [k, v] : cfg.headers) {
            auto low = detail::ascii_lower(k);
            if (detail::forbidden_header(low)) continue;
            if (low == "content-type") has_ct = true;
            resp.headers.emplace_back(std::move(low), v);
        }
        bool const no_body = (resp.status == 204 || resp.status == 304);
        if (!has_ct && !no_body) resp.headers.emplace_back("content-type", "text/plain; charset=utf-8");
        if (!no_body) resp.body.assign(cfg.target.begin(), cfg.target.end());
        resp.omit_body = (req.method == "HEAD") || no_body;
        return resp;
    }

    inline auto serve_file(config::Hysteria2Masquerade const& cfg, Request const& req) -> Response {
        Response resp{};
        resp.omit_body = (req.method == "HEAD");
        if (req.method != "GET" && req.method != "HEAD") {
            resp.status = 405;
            resp.headers.emplace_back("allow", "GET, HEAD");
            return resp;
        }
        auto decoded = detail::decode_url_path(req.path);
        if (!decoded) { resp.status = 404; return resp; }
        std::error_code ec;
        auto root = std::filesystem::canonical(cfg.target, ec);
        if (ec || !std::filesystem::is_directory(root, ec)) { resp.status = 404; return resp; }
        std::filesystem::path rel;
        std::string_view sv(*decoded);
        while (!sv.empty()) {
            while (!sv.empty() && sv.front() == '/') sv.remove_prefix(1);
            if (sv.empty()) break;
            auto next = sv.find('/');
            auto seg = sv.substr(0, next);
            if (seg == "." || seg == "..") { resp.status = 404; return resp; }
            rel /= seg;
            if (next == std::string_view::npos) break;
            sv.remove_prefix(next + 1);
        }
        auto candidate = rel.empty() ? (root / "index.html") : (root / rel);
        if (std::filesystem::is_directory(candidate, ec)) candidate /= "index.html";
        auto resolved = std::filesystem::canonical(candidate, ec);
        if (ec || !detail::path_within_root(root, resolved) || !std::filesystem::is_regular_file(resolved, ec)) {
            resp.status = 404; return resp;
        }
        auto sz = std::filesystem::file_size(resolved, ec);
        if (ec) { resp.status = 404; return resp; }
        if (sz > max_file_bytes) { resp.status = 413; return resp; }
        std::ifstream in(resolved, std::ios::binary);
        if (!in) { resp.status = 404; return resp; }
        resp.body.resize(static_cast<std::size_t>(sz));
        if (sz > 0 && !in.read(reinterpret_cast<char*>(resp.body.data()), static_cast<std::streamsize>(sz))) {
            resp.body.clear(); resp.status = 404; return resp;
        }
        resp.status = 200;
        resp.headers.emplace_back("content-type", detail::mime_type(resolved));
        return resp;
    }

    inline auto serve_proxy(corosio::io_context& ctx, config::Hysteria2Masquerade const& cfg,
        Request const& req, std::stop_token stop = {}) -> capy::task<Response> {
        Response bad_gw{}; bad_gw.status = 502; bad_gw.omit_body = (req.method == "HEAD");
        auto parsed = detail::parse_proxy_url(cfg.target);
        if (!parsed) co_return bad_gw;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        corosio::endpoint ep{};
        if (auto ip = platform::parse_ip_address(parsed->host)) {
            if (ip->size == 4) {
                corosio::ipv4_address::bytes_type b{};
                std::copy_n(ip->bytes.begin(), 4, b.begin());
                ep = {corosio::ipv4_address(b), parsed->port};
            } else {
                ep = {corosio::ipv6_address(ip->bytes), parsed->port};
            }
        } else {
            corosio::resolver res(ctx);
            std::stop_callback on_stop(stop, [&]() noexcept { res.cancel(); });
            if (stop.stop_requested()) co_return bad_gw;
            auto [ec, list] = co_await corosio::timeout(res.resolve(parsed->host, std::to_string(parsed->port)), deadline);
            if (ec || list.empty()) co_return bad_gw;
            ep = list.front();
        }
        auto wire = detail::build_proxy_request(*parsed, cfg, req);
        bool is_head = (req.method == "HEAD");
        auto result = parsed->https
            ? co_await detail::exchange_https(ctx, *parsed, ep, wire, is_head, deadline, stop)
            : co_await detail::exchange_http(ctx, ep, wire, is_head, deadline, stop);
        if (result && (result->status == 204 || result->status == 304)) {
            result->body.clear();
            result->omit_body = true;
        }
        co_return result ? std::move(*result) : bad_gw;
    }

    inline auto serve(corosio::io_context& ctx, config::Hysteria2Masquerade const& cfg,
        Request const& req, std::stop_token stop = {}) -> capy::task<Response> {
        if (cfg.type == "string") co_return serve_string(cfg, req);
        if (cfg.type == "file") co_return serve_file(cfg, req);
        if (cfg.type == "proxy") co_return co_await serve_proxy(ctx, cfg, req, stop);
        co_return Response{404, {}, {}, req.method == "HEAD"};
    }
}
