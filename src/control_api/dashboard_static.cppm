module;
#include "embedded_dashboard_assets.inc"

// Read-only sandboxed static file server & built-in embedded dashboard for control-http.
export module control_api.dashboard_static;
import std;
import control_api.http_format;

export namespace control_api::http_detail {
    inline constexpr std::size_t kMaxDashboardFileBytes = 4 * 1024 * 1024;

    struct EmbeddedDashboardAsset {
        std::string_view route;
        std::string_view mime;
        std::span<unsigned char const> bytes;
        bool gzipped = false;
        bool immutable = false;
    };

    inline auto init_dashboard_root(std::string const& configured)
        -> std::expected<std::filesystem::path, std::string> {
        if (configured.empty() || configured == "embedded") return std::filesystem::path{};
        std::error_code ec;
        auto canonical = std::filesystem::canonical(configured, ec);
        if (ec || !std::filesystem::is_directory(canonical, ec) || ec)
            return std::unexpected("control dashboard-root is not an accessible directory");
        return canonical;
    }

    inline auto dashboard_mime_type(std::filesystem::path const& file) noexcept -> std::optional<std::string_view> {
        auto ext = file.extension().string();
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext == ".html") return "text/html; charset=utf-8";
        if (ext == ".js" || ext == ".mjs") return "text/javascript; charset=utf-8";
        if (ext == ".css") return "text/css; charset=utf-8";
        if (ext == ".svg") return "image/svg+xml";
        if (ext == ".png") return "image/png";
        if (ext == ".ico") return "image/x-icon";
        if (ext == ".json" || ext == ".webmanifest") return "application/json; charset=utf-8";
        if (ext == ".woff2") return "font/woff2";
        if (ext == ".txt") return "text/plain; charset=utf-8";
        return std::nullopt;
    }

    inline auto decode_dashboard_path(std::string_view raw) -> std::optional<std::string> {
        if (raw.empty() || raw.front() != '/' || raw.size() > 512) return std::nullopt;
        if (raw.contains("..") || raw.contains('\\')) return std::nullopt;
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        std::string decoded;
        decoded.reserve(raw.size());
        for (std::size_t i = 0; i < raw.size(); ++i) {
            unsigned char ch = static_cast<unsigned char>(raw[i]);
            if (ch == '%') {
                if (i + 2 >= raw.size()) return std::nullopt;
                int hi = hex(raw[i + 1]), lo = hex(raw[i + 2]);
                if (hi < 0 || lo < 0) return std::nullopt;
                ch = static_cast<unsigned char>((hi << 4) | lo);
                if (ch == '/' || ch == '\\' || ch == '\0' || ch == '.') return std::nullopt;
                i += 2;
            }
            if (ch < 0x20 || ch == 0x7f || ch == '\\') return std::nullopt;
            decoded.push_back(static_cast<char>(ch));
        }
        std::size_t pos = 1;
        while (pos < decoded.size()) {
            auto slash = decoded.find('/', pos);
            auto seg = slash == std::string::npos
                ? std::string_view(decoded).substr(pos)
                : std::string_view(decoded).substr(pos, slash - pos);
            if (seg == "." || seg == ".." || (!seg.empty() && seg.front() == '.')) return std::nullopt;
            if (slash == std::string::npos) break;
            pos = slash + 1;
        }
        return decoded;
    }

    inline auto path_strictly_within(std::filesystem::path const& root, std::filesystem::path const& target) -> bool {
        auto r = root.begin();
        auto t = target.begin();
        for (; r != root.end(); ++r, ++t) {
            if (t == target.end() || *r != *t) return false;
        }
        return t != target.end();
    }

    inline auto build_dashboard_http_response(std::string_view mime, std::string_view body,
        std::size_t content_length, bool immutable, bool gzipped = false) -> std::string {
        auto cache = immutable ? "public, max-age=31536000, immutable" : "no-cache";
        std::string_view encoding = gzipped ? "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n" : "";
        return std::format(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\n{}Content-Length: {}\r\nCache-Control: {}\r\n"
            "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n"
            "Content-Security-Policy: default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; script-src 'self'; object-src 'none'; frame-ancestors 'none'\r\n"
            "Connection: close\r\n\r\n{}",
            mime, encoding, content_length, cache, body);
    }

    inline auto dashboard_method_not_allowed() -> std::string {
        constexpr std::string_view body =
            "{\"error\":{\"code\":\"method-not-allowed\",\"message\":\"dashboard is read-only\"}}\n";
        return std::format(
            "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Type: application/json\r\n"
            "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
            body.size(), body);
    }

    inline auto has_embedded_dashboard() noexcept -> bool {
        return control_api::embedded_dashboard_raw::kEntryCount > 0;
    }

    inline auto embedded_dashboard_asset_count() noexcept -> std::size_t {
        return control_api::embedded_dashboard_raw::kEntryCount;
    }

    inline auto embedded_dashboard_asset_at(std::size_t index) noexcept -> std::optional<EmbeddedDashboardAsset> {
        if (index >= control_api::embedded_dashboard_raw::kEntryCount) return std::nullopt;
        auto const& e = control_api::embedded_dashboard_raw::kEntries[index];
        return EmbeddedDashboardAsset{
            .route = e.route,
            .mime = e.mime,
            .bytes = std::span<unsigned char const>(e.data, e.size),
            .gzipped = e.gzipped,
            .immutable = e.immutable,
        };
    }

    inline auto find_embedded_dashboard_asset(std::string_view route) noexcept -> std::optional<EmbeddedDashboardAsset> {
        for (std::size_t i = 0; i < control_api::embedded_dashboard_raw::kEntryCount; ++i) {
            auto const& e = control_api::embedded_dashboard_raw::kEntries[i];
            if (route == e.route) {
                return EmbeddedDashboardAsset{
                    .route = e.route,
                    .mime = e.mime,
                    .bytes = std::span<unsigned char const>(e.data, e.size),
                    .gzipped = e.gzipped,
                    .immutable = e.immutable,
                };
            }
        }
        return std::nullopt;
    }

    inline auto accept_encoding_allows_gzip(std::string_view headers) noexcept -> bool {
        auto trim = [](std::string_view s) noexcept {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
            return s;
        };
        auto iequals = [](std::string_view a, std::string_view b) noexcept {
            return a.size() == b.size() && std::ranges::equal(a, b, [](char x, char y) {
                return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
            });
        };
        auto q_is_zero = [&](std::string_view params) noexcept -> bool {
            while (!params.empty()) {
                auto sc = params.find(';');
                auto item = trim(sc == std::string_view::npos ? params : params.substr(0, sc));
                if (auto eq = item.find('='); eq != std::string_view::npos) {
                    if (iequals(trim(item.substr(0, eq)), "q")) {
                        auto v = trim(item.substr(eq + 1));
                        if (v.empty()) return false;
                        bool saw_digit = false;
                        for (char c : v) {
                            if (c == '.') continue;
                            if (c < '0' || c > '9') return false;
                            saw_digit = true;
                            if (c != '0') return false;
                        }
                        return saw_digit;
                    }
                }
                if (sc == std::string_view::npos) break;
                params.remove_prefix(sc + 1);
            }
            return false;
        };

        bool header_present = false;
        bool gzip_seen = false, gzip_allowed = false;
        bool star_seen = false, star_allowed = false;
        auto rest = headers;
        while (!rest.empty()) {
            auto eol = rest.find("\r\n");
            auto line = rest.substr(0, eol);
            if (auto colon = line.find(':'); colon != std::string_view::npos &&
                iequals(trim(line.substr(0, colon)), "accept-encoding")) {
                auto val = trim(line.substr(colon + 1));
                if (!val.empty()) header_present = true;
                while (!val.empty()) {
                    auto comma = val.find(',');
                    auto tok = trim(comma == std::string_view::npos ? val : val.substr(0, comma));
                    if (!tok.empty()) {
                        auto sc = tok.find(';');
                        auto coding = trim(sc == std::string_view::npos ? tok : tok.substr(0, sc));
                        auto params = sc == std::string_view::npos ? std::string_view{} : tok.substr(sc + 1);
                        bool allowed = !q_is_zero(params);
                        if (iequals(coding, "gzip") || iequals(coding, "x-gzip")) {
                            gzip_seen = true;
                            gzip_allowed = allowed;
                        } else if (coding == "*") {
                            star_seen = true;
                            star_allowed = allowed;
                        }
                    }
                    if (comma == std::string_view::npos) break;
                    val.remove_prefix(comma + 1);
                }
            }
            if (eol == std::string_view::npos) break;
            rest.remove_prefix(eol + 2);
        }
        if (!header_present) return true;
        if (gzip_seen) return gzip_allowed;
        if (star_seen) return star_allowed;
        return false;
    }

    inline auto dashboard_not_acceptable() -> std::string {
        constexpr std::string_view body =
            "{\"error\":{\"code\":\"not-acceptable\",\"message\":\"embedded asset requires Accept-Encoding: gzip\"}}\n";
        return std::format(
            "HTTP/1.1 406 Not Acceptable\r\nContent-Type: application/json\r\nVary: Accept-Encoding\r\n"
            "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
            body.size(), body);
    }

    inline auto serve_embedded_dashboard_request(std::string_view method, std::string_view raw_path,
        std::string_view headers = {}) -> std::string {
        if (method != "GET" && method != "HEAD") return dashboard_method_not_allowed();
        auto decoded = decode_dashboard_path(raw_path);
        if (!decoded) return json_error(400, "Bad Request", "invalid-path", "invalid dashboard path");
        std::string_view route = (*decoded == "/") ? std::string_view("/index.html") : std::string_view(*decoded);
        auto asset = find_embedded_dashboard_asset(route);
        if (!asset) {
            std::string_view rel(*decoded);
            while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);
            bool has_ext = !rel.empty() && std::filesystem::path(rel).has_extension();
            if (has_ext) return json_error(404, "Not Found", "not-found", "dashboard asset not found");
            asset = find_embedded_dashboard_asset("/index.html");
            if (!asset) return json_error(404, "Not Found", "not-found", "dashboard index not found");
        }
        if (asset->gzipped && !accept_encoding_allows_gzip(headers)) return dashboard_not_acceptable();
        std::string_view body;
        if (method == "GET") {
            body = std::string_view(reinterpret_cast<char const*>(asset->bytes.data()), asset->bytes.size());
        }
        return build_dashboard_http_response(asset->mime, body, asset->bytes.size(), asset->immutable, asset->gzipped);
    }

    inline auto serve_dashboard_request(std::filesystem::path const& root, std::string_view method,
        std::string_view raw_path) -> std::string {
        if (method != "GET" && method != "HEAD") return dashboard_method_not_allowed();
        auto decoded = decode_dashboard_path(raw_path);
        if (!decoded) return json_error(400, "Bad Request", "invalid-path", "invalid dashboard path");
        std::string_view rel(*decoded);
        while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);
        std::filesystem::path candidate = rel.empty() ? (root / "index.html") : (root / rel);
        std::error_code ec;
        bool exists = std::filesystem::exists(candidate, ec);
        if (ec) return json_error(404, "Not Found", "not-found", "dashboard asset not found");
        if (!exists || std::filesystem::is_directory(candidate, ec)) {
            bool has_ext = !rel.empty() && std::filesystem::path(rel).has_extension();
            if (has_ext) return json_error(404, "Not Found", "not-found", "dashboard asset not found");
            candidate = root / "index.html";
            if (!std::filesystem::exists(candidate, ec) || ec)
                return json_error(404, "Not Found", "not-found", "dashboard index not found");
        }
        auto canonical = std::filesystem::canonical(candidate, ec);
        if (ec || !path_strictly_within(root, canonical))
            return json_error(403, "Forbidden", "path-outside-root", "access outside dashboard-root is denied");
        auto fname = canonical.filename().string();
        if (fname.empty() || fname.front() == '.')
            return json_error(403, "Forbidden", "hidden-file", "hidden files are denied");
        if (!std::filesystem::is_regular_file(canonical, ec) || ec)
            return json_error(404, "Not Found", "not-found", "not a regular file");
        auto mime = dashboard_mime_type(canonical);
        if (!mime) return json_error(403, "Forbidden", "unsupported-media", "disallowed static file extension");
        auto size = std::filesystem::file_size(canonical, ec);
        if (ec) return json_error(404, "Not Found", "not-found", "cannot stat file");
        if (size > kMaxDashboardFileBytes)
            return json_error(413, "Payload Too Large", "asset-too-large", "dashboard file exceeds 4 MiB");
        std::string body;
        if (method == "GET") {
            body.resize(static_cast<std::size_t>(size));
            std::ifstream in(canonical, std::ios::binary);
            if (!in || (size > 0 && !in.read(body.data(), static_cast<std::streamsize>(size))))
                return json_error(500, "Internal Server Error", "read-failed", "failed reading dashboard asset");
        }
        return build_dashboard_http_response(*mime, body, static_cast<std::size_t>(size), rel.starts_with("assets/"));
    }
}
