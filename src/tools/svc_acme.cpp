module;
#include <boost/capy/ex/run_async.hpp>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

module cli.proxy_services;
import std;
import capy;
import corosio;
import config;
import logging;
import logging.cli;
import acme.types;
import acme.jws;
import acme.store;
import acme.client;
import http.header;
import platform.ip_address;
import rulefile;
import tls.profiles;
import tls.server_credential;
import tls.corosio_server_handshake;
import tls.corosio_client;
import tls.corosio_application;

namespace cli {
    namespace {
        using Clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;

        auto now_ms() noexcept -> std::uint64_t {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now().time_since_epoch()).count());
        }
        auto now_epoch() noexcept -> std::int64_t {
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
        auto lower_ascii(std::string_view s) -> std::string {
            std::string out(s);
            for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            return out;
        }
        auto parse_ip_ep(std::string_view host, std::uint16_t port) -> std::expected<corosio::endpoint, std::string> {
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

        auto parse_port(std::string_view ps) -> std::expected<std::uint16_t, std::string> {
            unsigned p = 0;
            auto [e, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), p);
            if (ec != std::errc{} || e != ps.data() + ps.size() || !p || p > 65535)
                return std::unexpected("acme: invalid URL port");
            return static_cast<std::uint16_t>(p);
        }

        auto parse_acme_url(std::string_view url) -> std::expected<ParsedUrl, std::string> {
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

        auto decode_chunked(std::string_view raw) -> std::string {
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

        auto parse_http_resp(std::string_view raw, bool head_method) -> std::expected<acme::HttpResponse, std::string> {
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
                if (it.status == http::HeaderFieldStatus::end) break;
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

        auto resolve_acme_ep(std::string const& host, std::uint16_t port) -> std::expected<corosio::endpoint, std::string> {
            if (auto ip = parse_ip_ep(host, port); ip) return *ip;
#ifndef _WIN32
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
#endif
            return std::unexpected("acme: cannot resolve host: " + host);
        }

        auto http_exchange_coro(corosio::io_context& io, acme::HttpRequest const& req, std::string_view ca_file)
            -> capy::task<std::expected<acme::HttpResponse, std::string>> {
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
            if (!req.content_type.empty()) wire += std::format("Content-Type: {}\r\n", req.content_type);
            if (!req.body.empty()) wire += std::format("Content-Length: {}\r\n", req.body.size());
            wire += "\r\n"; wire += req.body;

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

        struct AcmeRuntimeState {
            acme::AcmeConfig cfg;
            std::string ca_file;
            std::uint32_t check_interval_ms = 3600000;
            acme::EcAccountKey account_key;
            acme::CertificateStore store;
            tls::AtomicServerCredential live_credential;
            AcmeHooks hooks;
            logging::Runtime* logs = nullptr;

            // Live challenge state (must outlive io_context coroutine frames).
            std::uint16_t http01_port = 0;
            std::uint16_t alpn01_port = 0;
            std::mutex ch_mu;
            std::unordered_map<std::string, std::string> http01_tokens;
            std::unordered_map<std::string, std::string> dns01_records;
            tls::AtomicServerCredential alpn01_cred;

            std::atomic_bool stopping{false};
            std::mutex cv_mu;
            std::condition_variable_any cv;
            corosio::io_context io;
            corosio::tcp_acceptor http01_acc{io};
            corosio::tcp_acceptor alpn01_acc{io};
            std::jthread io_thread;
            std::jthread renew_thread;

            AcmeRuntimeState(acme::AcmeConfig c, std::string ca, std::uint32_t interval,
                acme::EcAccountKey k, AcmeHooks h, logging::Runtime* l)
                : cfg(std::move(c)), ca_file(std::move(ca)), check_interval_ms(interval),
                  account_key(std::move(k)), hooks(std::move(h)), logs(l) {}

            ~AcmeRuntimeState() { stop(); }

            auto stop() noexcept -> void {
                if (stopping.exchange(true, std::memory_order_acq_rel)) return;
                renew_thread.request_stop();
                cv.notify_all();
                if (renew_thread.joinable()) renew_thread.join();
                http01_acc.close();
                alpn01_acc.close();
                io.stop();
                if (io_thread.joinable()) io_thread.join();
            }

            auto serve_http01(corosio::tcp_socket sock) -> capy::task<> {
                std::array<char, 2048> buf{};
                auto dl = Clock::now() + 3s;
                auto [ec, n] = co_await corosio::timeout(sock.read_some(capy::mutable_buffer(buf.data(), buf.size())), dl);
                if (ec || n == 0) co_return;
                std::string_view req(buf.data(), n);
                auto hdr = http::inspect_header(req);
                std::string reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                constexpr std::string_view kPrefix = "GET /.well-known/acme-challenge/";
                if (hdr.status == http::HeaderStatus::complete && hdr.first.starts_with(kPrefix)) {
                    auto rest = hdr.first.substr(kPrefix.size());
                    auto sp = rest.find(' ');
                    if (sp != std::string_view::npos) {
                        auto token = std::string(rest.substr(0, sp));
                        std::lock_guard lk(ch_mu);
                        if (auto it = http01_tokens.find(token); it != http01_tokens.end()) {
                            reply = std::format(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                it->second.size(), it->second);
                        }
                    }
                }
                (void)co_await corosio::timeout(sock.write_some(capy::const_buffer(reply.data(), reply.size())), dl);
            }

            auto serve_alpn01(corosio::tcp_socket sock) -> capy::task<> {
                auto cred = alpn01_cred.clone_current();
                if (!cred) co_return;
                auto hs = tls::make_server_handshake(*cred, now_ms(), now_ms() + 3000, {}, "acme-tls/1");
                if (!hs) co_return;
                (void)co_await tls::detail::server_handshake(sock, *hs);
            }

            auto accept_loop(corosio::tcp_acceptor& acc, bool is_http01) -> capy::task<> {
                while (!stopping.load(std::memory_order_acquire)) {
                    auto [ec, s] = co_await acc.accept();
                    if (ec) break;
                    if (is_http01) capy::run_async(io.get_executor())(serve_http01(std::move(s)));
                    else capy::run_async(io.get_executor())(serve_alpn01(std::move(s)));
                }
            }

            auto publish_live_credential(acme::CertificateBundle const& bundle) -> void {
                if (auto gen = live_credential.update_pem(bundle.cert_pem, bundle.key_pem); gen) {
                    if (hooks.on_credential_updated) hooks.on_credential_updated(bundle.cert_pem, bundle.key_pem);
                    if (logs) logs->emit(logging::Level::info, logging::Domain::core, 102, {},
                        "acme hot-swapped TLS ServerCredential (generation={})", *gen);
                }
            }

            auto run_renewal_once() -> void {
                auto http_fn = [this](acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
                    corosio::io_context cctx;
                    std::expected<acme::HttpResponse, std::string> out = std::unexpected("acme HTTP did not complete");
                    capy::run_async(cctx.get_executor(),
                        [&](auto res) noexcept { out = std::move(res); },
                        [&](std::exception_ptr) noexcept {})(http_exchange_coro(cctx, req, ca_file));
                    cctx.run_for(6s);
                    return out;
                };
                auto pub_http = [this](std::string_view tok, std::string_view ka) -> bool {
                    std::lock_guard lk(ch_mu);
                    http01_tokens[std::string(tok)] = std::string(ka);
                    return true;
                };
                auto pub_alpn = [this](std::string_view, std::string_view cp, std::string_view kp) -> bool {
                    return alpn01_cred.update_pem(cp, kp).has_value();
                };
                auto pub_dns = [this](std::string_view dom, std::string_view txt) -> bool {
                    std::string body;
                    {
                        std::lock_guard lk(ch_mu);
                        dns01_records[std::string(dom)] = std::string(txt);
                        for (auto const& [k, v] : dns01_records) body += std::format("_acme-challenge.{} TXT {}\n", k, v);
                    }
                    if (!cfg.state_dir.empty()) (void)rulefile::replace_file((cfg.state_dir / "dns01_challenges.txt").string(), body);
                    return true;
                };
                auto clean = [this]() {
                    std::lock_guard lk(ch_mu);
                    http01_tokens.clear();
                    // Keep dns01_records observable until next renewal; remove transient HTTP tokens immediately.
                };
                acme::ChallengeHooks ch_hooks{
                    .publish_http01 = pub_http,
                    .publish_alpn01 = pub_alpn,
                    .publish_dns01 = pub_dns,
                    .cleanup = clean,
                };
                auto res = acme::ensure_certificate(cfg, store, account_key, http_fn, ch_hooks, now_epoch());
                if (res && *res) {
                    if (auto cur = store.current()) publish_live_credential(*cur);
                } else if (!res && logs) {
                    logs->emit(logging::Level::warn, logging::Domain::core, 108, {}, "acme renewal attempt: {}", res.error());
                }
            }

            auto renew_loop(std::stop_token st) -> void {
                while (!st.stop_requested() && !stopping.load(std::memory_order_acquire)) {
                    if (store.needs_renewal(now_epoch(), cfg.renew_before_seconds)) run_renewal_once();
                    std::unique_lock lk(cv_mu);
                    cv.wait_for(lk, st, std::chrono::milliseconds(std::max<std::uint32_t>(check_interval_ms, 50u)),
                        [this] { return stopping.load(std::memory_order_acquire); });
                }
            }
        };
    }

    auto init_acme_service(config::AcmeServiceConfig const& cfg, logging::Runtime& logs, AcmeHooks hooks)
        -> std::expected<ServiceHandle, std::string> {
        if (cfg.directory_url.empty() || cfg.domains.empty() || cfg.state_dir.empty())
            return std::unexpected("acme: directory_url, domains, and state_dir are required");
        std::error_code fs_ec;
        std::filesystem::create_directories(cfg.state_dir, fs_ec);
        if (fs_ec) return std::unexpected("acme: cannot create state_dir: " + fs_ec.message());

        auto key_path = (std::filesystem::path(cfg.state_dir) / "account.key").string();
        std::optional<acme::EcAccountKey> acct_key;
        if (auto existing = rulefile::read_private_file(key_path); existing) {
            auto parsed = acme::EcAccountKey::from_pem({existing->bytes().data(), existing->bytes().size()});
            if (parsed) acct_key.emplace(std::move(*parsed));
        }
        if (!acct_key) {
            auto gen = acme::EcAccountKey::generate_p256();
            if (!gen) return std::unexpected("acme: account key generation failed: " + gen.error());
            if (auto saved = rulefile::replace_file(key_path, gen->to_pem()); !saved)
                return std::unexpected("acme: cannot persist account key: " + saved.error());
            acct_key.emplace(std::move(*gen));
        }

        acme::ChallengeType ct = acme::ChallengeType::http01;
        if (cfg.challenge == "tls-alpn-01") ct = acme::ChallengeType::tls_alpn01;
        else if (cfg.challenge == "dns-01") ct = acme::ChallengeType::dns01;

        acme::AcmeConfig ac{
            .directory_url = cfg.directory_url,
            .domains = cfg.domains,
            .email = cfg.email,
            .challenge = ct,
            .state_dir = cfg.state_dir,
            .renew_before_seconds = cfg.renew_before_seconds,
        };
        auto st = std::make_unique<AcmeRuntimeState>(std::move(ac), cfg.ca_file, cfg.check_interval_ms,
            std::move(*acct_key), std::move(hooks), &logs);

        if (auto loaded = acme::CertificateStore::load_from_dir(cfg.state_dir); loaded) {
            st->store.install(*loaded);
            st->publish_live_credential(*loaded);
        }

        auto bind_acc = [](corosio::tcp_acceptor& acc, std::string_view host, std::uint16_t port, std::string_view tag)
            -> std::expected<std::uint16_t, std::string> {
            auto ep = parse_ip_ep(host, port);
            if (!ep) return std::unexpected(ep.error());
            if (auto ec = acc.open(); ec) return std::unexpected(std::format("acme {} open: {}", tag, ec.message()));
            if (auto ec = acc.bind(*ep); ec) return std::unexpected(std::format("acme {} bind: {}", tag, ec.message()));
            if (auto ec = acc.listen(); ec) return std::unexpected(std::format("acme {} listen: {}", tag, ec.message()));
            return acc.local_endpoint().port();
        };
        bool need_io = false;
        if (ct == acme::ChallengeType::http01) {
            auto bp = bind_acc(st->http01_acc, cfg.http_listen_host, cfg.http_listen_port, "http-01");
            if (!bp) return std::unexpected(bp.error());
            st->http01_port = *bp;
            capy::run_async(st->io.get_executor())(st->accept_loop(st->http01_acc, true));
            need_io = true;
        } else if (ct == acme::ChallengeType::tls_alpn01) {
            auto bp = bind_acc(st->alpn01_acc, cfg.tls_alpn_listen_host, cfg.tls_alpn_listen_port, "alpn-01");
            if (!bp) return std::unexpected(bp.error());
            st->alpn01_port = *bp;
            capy::run_async(st->io.get_executor())(st->accept_loop(st->alpn01_acc, false));
            need_io = true;
        }
        if (need_io) st->io_thread = std::jthread([ptr = st.get()] { ptr->io.run(); });
        st->renew_thread = std::jthread([ptr = st.get()](std::stop_token tok) { ptr->renew_loop(tok); });

        logs.emit(logging::Level::info, logging::Domain::core, 101, {},
            "acme service started (challenge={}, http01_port={}, alpn01_port={})",
            cfg.challenge, st->http01_port, st->alpn01_port);
        return ServiceHandle::create(std::move(st));
    }

    auto acme_http01_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        return h.state ? static_cast<AcmeRuntimeState const*>(h.state.get())->http01_port : 0;
    }
    auto acme_alpn01_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        return h.state ? static_cast<AcmeRuntimeState const*>(h.state.get())->alpn01_port : 0;
    }
    auto acme_credential_generation(ServiceHandle const& h) noexcept -> std::uint64_t {
        return h.state ? static_cast<AcmeRuntimeState const*>(h.state.get())->live_credential.generation() : 0;
    }
    auto acme_has_valid_credential(ServiceHandle const& h) noexcept -> bool {
        return h.state && !static_cast<AcmeRuntimeState const*>(h.state.get())->live_credential.empty();
    }
    auto acme_dns01_record(ServiceHandle const& h, std::string_view domain) -> std::optional<std::string> {
        if (!h.state) return std::nullopt;
        auto* st = static_cast<AcmeRuntimeState*>(h.state.get());
        std::lock_guard lk(st->ch_mu);
        auto it = st->dns01_records.find(std::string(domain));
        return it == st->dns01_records.end() ? std::nullopt : std::optional<std::string>(it->second);
    }
}
