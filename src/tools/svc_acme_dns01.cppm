module;
#include <boost/capy/ex/run_async.hpp>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

export module cli.svc_acme_dns01;
import std;
import capy;
import corosio;
import config;
import crypto;
import acme.types;
import acme.jws;
import acme.dns01_providers;
import http.header;
import platform.ip_address;
import rulefile;
import tls.profiles;
import tls.corosio_client;
import tls.corosio_application;

export namespace cli::acme_detail {
    using Clock = std::chrono::steady_clock;

    inline auto now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now().time_since_epoch()).count());
    }
    inline auto now_epoch() noexcept -> std::int64_t {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    inline auto lower_ascii(std::string_view s) -> std::string {
        std::string out(s);
        for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        return out;
    }
    inline auto parse_ip_ep(std::string_view host, std::uint16_t port) -> std::expected<corosio::endpoint, std::string> {
        auto ip = platform::parse_ip_address(host);
        if (!ip) return std::unexpected("acme: invalid listen IP: " + std::string(host));
        if (ip->size == 4) {
            corosio::ipv4_address::bytes_type b{};
            std::copy_n(ip->bytes.begin(), 4, b.begin());
            return corosio::endpoint(corosio::ipv4_address(b), port);
        }
        return corosio::endpoint(corosio::ipv6_address(ip->bytes), port);
    }

    struct ParsedUrl { bool tls = false; std::string host; std::uint16_t port = 80; std::string path = "/"; };

    inline auto parse_port(std::string_view ps) -> std::expected<std::uint16_t, std::string> {
        unsigned p = 0;
        auto [e, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), p);
        if (ec != std::errc{} || e != ps.data() + ps.size() || !p || p > 65535)
            return std::unexpected("acme: invalid URL port");
        return static_cast<std::uint16_t>(p);
    }

    inline auto parse_acme_url(std::string_view url) -> std::expected<ParsedUrl, std::string> {
        if (std::ranges::any_of(url, [](unsigned char c) { return c <= 0x20 || c >= 0x7f; }))
            return std::unexpected("acme: invalid URL character");
        ParsedUrl out;
        if (url.starts_with("https://")) { out.tls = true; out.port = 443; url.remove_prefix(8); }
        else if (url.starts_with("http://")) { out.tls = false; out.port = 80; url.remove_prefix(7); }
        else return std::unexpected("acme: unsupported URL scheme");
        auto slash = url.find('/');
        auto auth = slash == std::string_view::npos ? url : url.substr(0, slash);
        out.path = slash == std::string_view::npos ? std::string("/") : std::string(url.substr(slash));
        if (auth.empty() || auth.contains('@')) return std::unexpected("acme: empty or invalid URL host");
        if (auth.starts_with('[')) {
            auto rb = auth.find(']');
            if (rb == std::string_view::npos) return std::unexpected("acme: malformed IPv6 URL");
            out.host = std::string(auth.substr(1, rb - 1));
            if (rb + 1 < auth.size()) {
                if (auth[rb + 1] != ':') return std::unexpected("acme: malformed IPv6 URL");
                auto p = parse_port(auth.substr(rb + 2)); if (!p) return std::unexpected(p.error()); out.port = *p;
            }
        } else if (auto col = auth.rfind(':'); col != std::string_view::npos) {
            out.host = std::string(auth.substr(0, col));
            auto p = parse_port(auth.substr(col + 1)); if (!p) return std::unexpected(p.error()); out.port = *p;
        } else out.host = std::string(auth);
        if (out.host.empty()) return std::unexpected("acme: empty URL host");
        return out;
    }

    inline auto decode_chunked(std::string_view raw) -> std::string {
        std::string out;
        std::size_t pos = 0;
        while (pos < raw.size()) {
            auto crlf = raw.find("\r\n", pos);
            if (crlf == std::string_view::npos) break;
            std::size_t sz = 0;
            auto hex = raw.substr(pos, crlf - pos);
            if (auto sc = hex.find(';'); sc != std::string_view::npos) hex = hex.substr(0, sc);
            while (!hex.empty() && (hex.front() == ' ' || hex.front() == '\t')) hex.remove_prefix(1);
            while (!hex.empty() && (hex.back() == ' ' || hex.back() == '\t')) hex.remove_suffix(1);
            auto [e, ec] = std::from_chars(hex.data(), hex.data() + hex.size(), sz, 16);
            if (ec != std::errc{} || e != hex.data() + hex.size() || sz == 0) break;
            pos = crlf + 2;
            if (sz > raw.size() - pos || raw.size() - pos - sz < 2 ||
                raw[pos + sz] != '\r' || raw[pos + sz + 1] != '\n') break;
            out.append(raw.substr(pos, sz));
            pos += sz + 2;
        }
        return out;
    }

    inline auto parse_http_resp(std::string_view raw, bool head_method) -> std::expected<acme::HttpResponse, std::string> {
        auto hdr = http::inspect_header(raw);
        if (hdr.status != http::HeaderStatus::complete) return std::unexpected("acme: incomplete HTTP response");
        auto sp1 = hdr.first.find(' ');
        if (sp1 == std::string_view::npos || sp1 + 4 > hdr.first.size())
            return std::unexpected("acme: malformed HTTP status line");
        unsigned code = 0;
        auto [e, ec] = std::from_chars(hdr.first.data() + sp1 + 1, hdr.first.data() + sp1 + 4, code);
        if (ec != std::errc{}) return std::unexpected("acme: invalid HTTP status");
        acme::HttpResponse resp{.status = code};
        bool chunked = false;
        std::optional<std::size_t> content_len;
        http::HeaderFieldCursor cur(hdr.field_lines);
        for (;;) {
            auto it = cur.next();
            if (it.status != http::HeaderFieldStatus::field) break;
            auto k = lower_ascii(it.field.name);
            if (k == "replay-nonce") resp.replay_nonce = std::string(it.field.value);
            else if (k == "location") resp.location = std::string(it.field.value);
            else if (k == "transfer-encoding" && lower_ascii(it.field.value).contains("chunked")) chunked = true;
            else if (k == "content-length") {
                std::size_t cl = 0;
                if (std::from_chars(it.field.value.data(), it.field.value.data() + it.field.value.size(), cl).ec == std::errc{})
                    content_len = cl;
            }
        }
        if (!head_method) {
            auto body = raw.substr(hdr.consumed);
            if (chunked) resp.body = decode_chunked(body);
            else if (content_len && body.size() >= *content_len) resp.body = std::string(body.substr(0, *content_len));
            else resp.body = std::string(body);
        }
        return resp;
    }

    inline auto resolve_acme_ep(std::string const& host, std::uint16_t port) -> std::expected<corosio::endpoint, std::string> {
        if (auto ip = parse_ip_ep(host, port); ip) return *ip;
        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_UNSPEC;
        auto ps = std::to_string(port);
        addrinfo* res = nullptr;
        if (::getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) == 0 && res) {
            struct Free { addrinfo* p; ~Free() { ::freeaddrinfo(p); } } fg{res};
            for (auto* rp = res; rp; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET) {
                    auto* sin = reinterpret_cast<sockaddr_in const*>(rp->ai_addr);
                    corosio::ipv4_address::bytes_type b{};
                    std::memcpy(b.data(), &sin->sin_addr, 4);
                    return corosio::endpoint(corosio::ipv4_address(b), port);
                }
                if (rp->ai_family == AF_INET6) {
                    auto* sin6 = reinterpret_cast<sockaddr_in6 const*>(rp->ai_addr);
                    corosio::ipv6_address::bytes_type b{};
                    std::memcpy(b.data(), &sin6->sin6_addr, 16);
                    return corosio::endpoint(corosio::ipv6_address(b), port);
                }
            }
        }
        return std::unexpected("acme: cannot resolve host: " + host);
    }

    inline auto http_exchange_coro(corosio::io_context& io, acme::HttpRequest const& req, std::string_view ca_file)
        -> capy::task<std::expected<acme::HttpResponse, std::string>> {
        using namespace std::chrono_literals;
        auto u = parse_acme_url(req.url);
        if (!u) co_return std::unexpected(std::move(u.error()));
        auto ep = resolve_acme_ep(u->host, u->port);
        if (!ep) co_return std::unexpected(std::move(ep.error()));

        corosio::tcp_socket sock(io);
        if (sock.open()) co_return std::unexpected("acme: socket open failed");
        auto dl = Clock::now() + 5s;
        auto [ce] = co_await corosio::timeout(sock.connect(*ep), dl);
        if (ce) co_return std::unexpected("acme: connect failed: " + ce.message());

        if (req.method.empty() || std::ranges::any_of(req.method, [](unsigned char c) { return c <= 0x20 || c >= 0x7f; }) ||
            std::ranges::any_of(req.content_type, [](unsigned char c) { return c < 0x20 || c == 0x7f; }))
            co_return std::unexpected("acme: invalid HTTP request header field");
        auto host_hdr = u->host.contains(':') ? std::format("[{}]:{}", u->host, u->port) : std::format("{}:{}", u->host, u->port);
        std::string wire = std::format("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n", req.method, u->path, host_hdr);
        for (auto const& [hk, hv] : req.headers) {
            if (hk.empty() || !std::ranges::all_of(hk, http::header_token) || !http::valid_header_field_value(hv))
                co_return std::unexpected("acme: invalid extra HTTP header");
            wire += std::format("{}: {}\r\n", hk, hv);
        }
        if (!req.content_type.empty()) wire += std::format("Content-Type: {}\r\n", req.content_type);
        if (!req.body.empty()) wire += std::format("Content-Length: {}\r\n", req.body.size());
        wire += "\r\n"; wire += req.body;
        struct WipeWire {
            std::string& w;
            ~WipeWire() { if (!w.empty()) crypto::cleanse({reinterpret_cast<std::uint8_t*>(w.data()), w.size()}); }
        } wipe_wire{wire};

        std::string raw;
        if (!u->tls) {
            std::span<char const> rem(wire);
            while (!rem.empty()) {
                auto [we, n] = co_await corosio::timeout(sock.write_some(capy::const_buffer(rem.data(), rem.size())), dl);
                if (we || !n) co_return std::unexpected("acme: HTTP write failed");
                rem = rem.subspan(n);
            }
            std::array<char, 4096> buf{};
            while (raw.size() < 262144) {
                auto [re, n] = co_await corosio::timeout(sock.read_some(capy::mutable_buffer(buf.data(), buf.size())), dl);
                if (n > 0) raw.append(buf.data(), n);
                if (re || n == 0) break;
            }
        } else {
            std::array<std::string_view, 1> alpn{"http/1.1"};
            auto prof = tls::ClientProfile::load(u->host, ca_file, 0x001d, false, alpn);
            if (!prof) co_return std::unexpected("acme TLS profile: " + prof.error());
            auto hs = prof->handshake(now_ms(), now_ms() + 5000, now_epoch());
            if (!hs) co_return std::unexpected("acme TLS handshake init: " + hs.error());
            tls::detail::ClientConnection<corosio::tcp_socket> cli(sock, std::move(*hs));
            auto started = co_await cli.start();
            if (!started || !cli.application()) co_return std::unexpected("acme TLS handshake failed");
            auto* app = cli.application();
            auto adl = tls::detail::ApplicationDeadline{dl};
            if (!co_await app->send_all({reinterpret_cast<std::uint8_t const*>(wire.data()), wire.size()}, adl))
                co_return std::unexpected("acme HTTPS write failed");
            tls::detail::ApplicationStreamReader reader(*app);
            std::array<std::uint8_t, 16640> buf{};
            while (raw.size() < 262144) {
                auto r = co_await reader.read_some(buf, adl);
                if (!r || r->kind == tls::detail::AsyncStreamReadKind::eof) break;
                if (r->kind == tls::detail::AsyncStreamReadKind::backpressure) {
                    if (!co_await app->flush(adl)) break;
                    continue;
                }
                if (r->kind == tls::detail::AsyncStreamReadKind::event) {
                    if (r->event->kind == tls::ApplicationEventKind::close_notify) break;
                    continue;
                }
                raw.append(reinterpret_cast<char const*>(buf.data()), r->size);
            }
        }
        co_return parse_http_resp(raw, req.method == "HEAD");
    }

    inline auto read_secret_line(std::string_view path, std::string_view label) -> std::expected<std::string, std::string> {
        auto priv = rulefile::read_private_file(path);
        if (!priv) return std::unexpected(std::format("acme {}: {}", label, priv.error()));
        std::string_view sv(priv->bytes().data(), priv->bytes().size());
        while (!sv.empty() && (sv.back() == '\n' || sv.back() == '\r' || sv.back() == ' ' || sv.back() == '\t')) sv.remove_suffix(1);
        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) sv.remove_prefix(1);
        if (sv.empty()) return std::unexpected(std::format("acme {}: secret file is empty", label));
        return std::string(sv);
    }

    inline auto load_acme_eab(config::AcmeServiceConfig const& cfg) -> std::expected<std::optional<acme::EabCredentials>, std::string> {
        if (cfg.eab_kid.empty()) return std::optional<acme::EabCredentials>{};
        auto raw = read_secret_line(cfg.eab_hmac_file, "eab-hmac-file");
        if (!raw) return std::unexpected(raw.error());
        struct Wipe { std::string& s; ~Wipe() { if (!s.empty()) crypto::cleanse({reinterpret_cast<std::uint8_t*>(s.data()), s.size()}); } } w{*raw};
        auto decoded = acme::base64url_decode(*raw);
        if (!decoded) return std::unexpected("acme eab-hmac-file: " + decoded.error());
        return std::optional<acme::EabCredentials>{acme::EabCredentials{cfg.eab_kid, std::move(*decoded)}};
    }

    struct Dns01ProviderRuntime {
        std::optional<acme::CloudflareDns01Provider> cloudflare;
        std::optional<acme::AliDns01Provider> alidns;

        static auto load(config::AcmeServiceConfig const& cfg) -> std::expected<Dns01ProviderRuntime, std::string> {
            Dns01ProviderRuntime rt;
            if (cfg.dns01_provider == "cloudflare") {
                auto tok = read_secret_line(cfg.dns01_api_token_file, "dns01-api-token-file");
                if (!tok) return std::unexpected(tok.error());
                rt.cloudflare.emplace(std::move(*tok));
            } else if (cfg.dns01_provider == "alidns") {
                auto kid = read_secret_line(cfg.dns01_access_key_id_file, "dns01-access-key-id-file");
                if (!kid) return std::unexpected(kid.error());
                auto sec = read_secret_line(cfg.dns01_access_key_secret_file, "dns01-access-key-secret-file");
                if (!sec) {
                    crypto::cleanse({reinterpret_cast<std::uint8_t*>(kid->data()), kid->size()});
                    return std::unexpected(sec.error());
                }
                rt.alidns.emplace(std::move(*kid), std::move(*sec));
            }
            return rt;
        }

        [[nodiscard]] auto has_remote() const noexcept -> bool { return cloudflare.has_value() || alidns.has_value(); }

        [[nodiscard]] auto publish(std::string_view domain, std::string_view txt, acme::HttpExchangeFn http) const
            -> std::expected<acme::Dns01RecordHandle, std::string> {
            if (cloudflare) return cloudflare->publish(domain, txt, http);
            if (alidns) return alidns->publish(domain, txt, http);
            return std::unexpected("no remote DNS-01 provider configured");
        }

        auto cleanup(std::span<acme::Dns01RecordHandle const> handles, acme::HttpExchangeFn http) const -> void {
            for (auto const& h : handles) {
                if (cloudflare) (void)cloudflare->cleanup(h, http);
                else if (alidns) (void)alidns->cleanup(h, http);
            }
        }
    };
}
