// Private read-only sandboxed static file server for control-http dashboard-root.
#pragma once

namespace {
    constexpr std::size_t kMaxDashboardFileBytes = 4 * 1024 * 1024;

    auto init_dashboard_root(std::string const& configured)
        -> std::expected<std::filesystem::path, std::string> {
        if (configured.empty()) return std::filesystem::path{};
        std::error_code ec;
        auto canonical = std::filesystem::canonical(configured, ec);
        if (ec || !std::filesystem::is_directory(canonical, ec) || ec)
            return std::unexpected("control dashboard-root is not an accessible directory");
        return canonical;
    }

    auto dashboard_mime_type(std::filesystem::path const& file) noexcept -> std::optional<std::string_view> {
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

    auto decode_dashboard_path(std::string_view raw) -> std::optional<std::string> {
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

    auto path_strictly_within(std::filesystem::path const& root, std::filesystem::path const& target) -> bool {
        auto r = root.begin();
        auto t = target.begin();
        for (; r != root.end(); ++r, ++t) {
            if (t == target.end() || *r != *t) return false;
        }
        return t != target.end();
    }

    auto serve_dashboard_request(std::filesystem::path const& root, std::string_view method,
        std::string_view raw_path) -> std::string {
        if (method != "GET" && method != "HEAD") {
            constexpr std::string_view body = "{\"error\":{\"code\":\"method-not-allowed\",\"message\":\"dashboard is read-only\"}}\n";
            return std::format(
                "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Type: application/json\r\n"
                "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
                body.size(), body);
        }
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
        auto cache = rel.starts_with("assets/") ? "public, max-age=31536000, immutable" : "no-cache";
        return std::format(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: {}\r\n"
            "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n"
            "Content-Security-Policy: default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; script-src 'self'; object-src 'none'; frame-ancestors 'none'\r\n"
            "Connection: close\r\n\r\n{}",
            *mime, size, cache, body);
    }
}
