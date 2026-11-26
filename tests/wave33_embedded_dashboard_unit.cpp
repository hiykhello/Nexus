// Wave 33 Track 33E-3 unit tests: embedded Web Dashboard & custom dashboard-root precedence.
#include <cassert>
#include <unistd.h>

import std;
import config;
import control_api;
import control_api.dashboard_static;
import control_api.types;

namespace {
    auto split_http(std::string_view resp) -> std::pair<std::string_view, std::string_view> {
        auto pos = resp.find("\r\n\r\n");
        assert(pos != std::string_view::npos);
        return {resp.substr(0, pos), resp.substr(pos + 4)};
    }

    auto make_snap(control_api::SnapshotFields, std::optional<std::uint64_t>) -> control_api::ControlSnapshot {
        control_api::ControlSnapshot s{};
        s.instance = "wave33-embedded-test";
        return s;
    }

    auto dummy_cmd(std::span<std::string_view const>) -> std::expected<std::string, std::string> {
        return std::unexpected("unused");
    }

    auto test_embedded_default_and_assets() -> void {
        assert(control_api::http_detail::has_embedded_dashboard());
        assert(control_api::http_detail::embedded_dashboard_asset_count() >= 2);

        control_api::HttpControlServer srv;
        auto req = [&](std::string_view raw) {
            return srv.handle_direct_http_for_test(raw, make_snap, dummy_cmd);
        };

        // 1. GET / serves embedded index.html with strict CSP and no-cache.
        auto r_root = req("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        auto [h_root, b_root] = split_http(r_root);
        assert(h_root.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(h_root.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert(h_root.contains("Cache-Control: no-cache\r\n"));
        assert(h_root.contains("X-Content-Type-Options: nosniff\r\n"));
        assert(h_root.contains("X-Frame-Options: DENY\r\n"));
        assert(h_root.contains("Referrer-Policy: no-referrer\r\n"));
        assert(h_root.contains("Content-Security-Policy: default-src 'self';"));
        assert(!h_root.contains("Content-Encoding: gzip"));
        assert(b_root.contains("<nexus-app></nexus-app>"));

        // 2. HEAD / returns headers with matching Content-Length and empty body.
        auto r_head = req("HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        auto [h_head, b_head] = split_http(r_head);
        assert(h_head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(h_head.contains(std::format("Content-Length: {}\r\n", b_root.size())));
        assert(b_head.empty());

        // 3. Static JS asset referenced by index.html serves with immutable cache & gzip header.
        std::string js_route;
        for (std::size_t i = 0; i < control_api::http_detail::embedded_dashboard_asset_count(); ++i) {
            auto asset = control_api::http_detail::embedded_dashboard_asset_at(i);
            assert(asset.has_value());
            if (asset->route.starts_with("/assets/") && asset->route.ends_with(".js")) {
                js_route = std::string(asset->route);
                break;
            }
        }
        assert(!js_route.empty());
        assert(b_root.contains(js_route));

        auto r_js = req(std::format("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", js_route));
        auto [h_js, b_js] = split_http(r_js);
        assert(h_js.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(h_js.contains("Content-Type: text/javascript; charset=utf-8\r\n"));
        assert(h_js.contains("Content-Encoding: gzip\r\n"));
        assert(h_js.contains("Vary: Accept-Encoding\r\n"));
        assert(h_js.contains("Cache-Control: public, max-age=31536000, immutable\r\n"));
        assert(h_js.contains("Content-Security-Policy: default-src 'self';"));
        assert(b_js.size() > 1000);
        assert(static_cast<unsigned char>(b_js[0]) == 0x1fu && static_cast<unsigned char>(b_js[1]) == 0x8bu);

        auto r_js_head = req(std::format("HEAD {} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", js_route));
        auto [h_js_head, b_js_head] = split_http(r_js_head);
        assert(h_js_head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(h_js_head.contains(std::format("Content-Length: {}\r\n", b_js.size())));
        assert(b_js_head.empty());

        // 3b. Accept-Encoding negotiation on gzipped JS vs raw index.html.
        auto r_js_gzip = req(std::format("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: br, gzip;q=0.8\r\n\r\n", js_route));
        assert(r_js_gzip.starts_with("HTTP/1.1 200 OK\r\n"));
        auto r_js_star = req(std::format("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: *\r\n\r\n", js_route));
        assert(r_js_star.starts_with("HTTP/1.1 200 OK\r\n"));
        for (std::string_view deny : {"identity", "gzip;q=0, identity", "br, deflate", "*;q=0"}) {
            auto r_406 = req(std::format("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: {}\r\n\r\n", js_route, deny));
            assert(r_406.starts_with("HTTP/1.1 406 Not Acceptable\r\n"));
            assert(r_406.contains("Vary: Accept-Encoding\r\n"));
        }
        auto r_html_id = req("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: identity\r\n\r\n");
        assert(r_html_id.starts_with("HTTP/1.1 200 OK\r\n"));

        // 4. SPA routes fall back to embedded index.html.
        for (std::string_view spa : {"/outbounds", "/connections", "/services", "/logs", "/diagnostics"}) {
            auto r_spa = req(std::format("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", spa));
            auto [h_spa, b_spa] = split_http(r_spa);
            assert(h_spa.starts_with("HTTP/1.1 200 OK\r\n"));
            assert(h_spa.contains("Cache-Control: no-cache\r\n"));
            assert(b_spa == b_root);
        }

        // 5. Missing static files with extensions return 404; traversal/hidden return 400; writes return 405.
        assert(req("GET /assets/missing.js HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert(req("GET /missing.css HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert(req("GET /../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert(req("GET /%2e%2e/etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert(req("GET /.env HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert(req("PUT /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert(req("POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n").starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

        // 6. Control API /v1/* routes still dispatch normally.
        auto r_health = req("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert(r_health.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(r_health.contains("\"status\":\"ok\""));
    }

    auto test_explicit_embedded_and_custom_root_precedence() -> void {
        // Explicit dashboard_root = "embedded" succeeds and serves embedded dashboard.
        {
            config::ControlHttpConfig cfg{};
            cfg.host = "127.0.0.1";
            cfg.port = 0;
            cfg.dashboard_root = "embedded";
            control_api::HttpControlServer srv;
            assert(srv.start(cfg).has_value());
            auto r = srv.handle_direct_http_for_test("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", make_snap, dummy_cmd);
            auto [h, b] = split_http(r);
            assert(h.starts_with("HTTP/1.1 200 OK\r\n"));
            assert(b.contains("<nexus-app></nexus-app>"));
            srv.stop();
        }

        // Nonexistent custom dashboard_root is rejected at startup.
        {
            config::ControlHttpConfig bad{};
            bad.host = "127.0.0.1";
            bad.port = 0;
            bad.dashboard_root = "/nonexistent/nexus-wave33-missing-dashboard";
            control_api::HttpControlServer srv;
            assert(!srv.start(bad).has_value());
        }

        // Custom dashboard_root directory takes precedence over embedded assets.
        auto tmp = std::filesystem::temp_directory_path() / ("nexus-w33-dash-" + std::to_string(::getpid()));
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
        std::filesystem::create_directories(tmp / "assets");
        struct Cleanup {
            std::filesystem::path dir;
            ~Cleanup() { std::error_code e; std::filesystem::remove_all(dir, e); }
        } cleanup{tmp};

        {
            std::ofstream ofs(tmp / "index.html", std::ios::binary);
            ofs << "<!doctype html><html><body><custom-dashboard-override/></body></html>\n";
        }
        {
            std::ofstream ofs(tmp / "assets" / "custom.css", std::ios::binary);
            ofs << "body { color: #123456; }\n";
        }

        config::ControlHttpConfig cfg{};
        cfg.host = "127.0.0.1";
        cfg.port = 0;
        cfg.dashboard_root = tmp.string();
        control_api::HttpControlServer srv;
        assert(srv.start(cfg).has_value());

        auto req = [&](std::string_view raw) {
            return srv.handle_direct_http_for_test(raw, make_snap, dummy_cmd);
        };

        auto r_root = req("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        auto [h_root, b_root] = split_http(r_root);
        assert(h_root.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(b_root.contains("<custom-dashboard-override/>"));
        assert(!b_root.contains("<nexus-app>"));

        auto r_spa = req("GET /outbounds HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert(split_http(r_spa).second == b_root);

        auto r_css = req("GET /assets/custom.css HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        auto [h_css, b_css] = split_http(r_css);
        assert(h_css.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(h_css.contains("Content-Type: text/css; charset=utf-8\r\n"));
        assert(h_css.contains("Cache-Control: public, max-age=31536000, immutable\r\n"));
        assert(b_css.contains("#123456"));

        assert(req("GET /assets/missing.js HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").starts_with("HTTP/1.1 404 Not Found\r\n"));
        srv.stop();
    }
}

int main() {
    test_embedded_default_and_assets();
    test_explicit_embedded_and_custom_root_precedence();
    std::cout << "wave33_embedded_dashboard_unit: all tests passed\n";
    return 0;
}
