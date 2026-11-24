#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <boost/capy/ex/run_async.hpp>

import std;
import boringssl;
import capy;
import corosio;
import config;
import cli.proxy_services;
import crypto;
import logging;
import logging.cli;
import tailscale.derp;
import tailscale.derp_handshake;
import tailscale.derp_messages;
import tls.client_handshake_io;
import tls.server_credential;

namespace {
    using namespace std::chrono_literals;
    using namespace boringssl;

    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) { std::cerr << "FAIL [batch173-acme-derp]: " << msg << '\n'; std::exit(1); }
    }

    struct Fd {
        int fd = -1;
        Fd() = default;
        explicit Fd(int f) noexcept : fd(f) {}
        ~Fd() { if (fd >= 0) ::close(fd); }
        Fd(Fd const&) = delete;
        auto operator=(Fd const&) -> Fd& = delete;
        Fd(Fd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
        auto operator=(Fd&& o) noexcept -> Fd& { if (this != &o) { if (fd >= 0) ::close(fd); fd = std::exchange(o.fd, -1); } return *this; }
    };

    auto connect_loopback(std::uint16_t port) -> Fd {
        Fd s(::socket(AF_INET, SOCK_STREAM, 0));
        require(s.fd >= 0, "socket");
        sockaddr_in a{.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::connect(s.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0, "connect loopback");
        return s;
    }

    auto listen_loopback() -> std::pair<Fd, std::uint16_t> {
        Fd s(::socket(AF_INET, SOCK_STREAM, 0));
        require(s.fd >= 0, "listen socket");
        int one = 1; (void)::setsockopt(s.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::bind(s.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0 && ::listen(s.fd, 16) == 0, "bind/listen");
        socklen_t len = sizeof(a);
        require(::getsockname(s.fd, reinterpret_cast<sockaddr*>(&a), &len) == 0, "getsockname");
        return {std::move(s), ntohs(a.sin_port)};
    }

    auto send_all(int fd, std::span<std::uint8_t const> data) -> bool {
        while (!data.empty()) {
            auto n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
            if (n <= 0) return false;
            data = data.subspan(static_cast<std::size_t>(n));
        }
        return true;
    }
    auto send_str(int fd, std::string_view s) -> bool {
        return send_all(fd, {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()});
    }

    auto build_client_hello(std::string_view sni, std::initializer_list<std::string_view> alpns) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> ext;
        if (!sni.empty()) {
            std::uint16_t ll = static_cast<std::uint16_t>(3 + sni.size()), el = static_cast<std::uint16_t>(2 + ll);
            ext.insert(ext.end(), {0, 0, std::uint8_t(el >> 8), std::uint8_t(el), std::uint8_t(ll >> 8), std::uint8_t(ll), 0,
                std::uint8_t(sni.size() >> 8), std::uint8_t(sni.size())});
            ext.insert(ext.end(), sni.begin(), sni.end());
        }
        if (alpns.size()) {
            std::vector<std::uint8_t> al;
            for (auto p : alpns) { al.push_back(std::uint8_t(p.size())); al.insert(al.end(), p.begin(), p.end()); }
            std::uint16_t ll = static_cast<std::uint16_t>(al.size()), el = static_cast<std::uint16_t>(2 + ll);
            ext.insert(ext.end(), {0, 16, std::uint8_t(el >> 8), std::uint8_t(el), std::uint8_t(ll >> 8), std::uint8_t(ll)});
            ext.insert(ext.end(), al.begin(), al.end());
        }
        std::vector<std::uint8_t> h{3, 3};
        h.resize(h.size() + 32, 0x22);
        h.insert(h.end(), {0, 0, 2, 0x13, 0x01, 1, 0, std::uint8_t(ext.size() >> 8), std::uint8_t(ext.size())});
        h.insert(h.end(), ext.begin(), ext.end());
        std::size_t hl = h.size(), rl = hl + 4;
        std::vector<std::uint8_t> out{0x16, 3, 1, std::uint8_t(rl >> 8), std::uint8_t(rl),
            1, std::uint8_t(hl >> 16), std::uint8_t(hl >> 8), std::uint8_t(hl)};
        out.insert(out.end(), h.begin(), h.end());
        return out;
    }

    auto base64url_decode(std::string_view in) -> std::vector<std::uint8_t> {
        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '-' || c == '+') return 62;
            if (c == '_' || c == '/') return 63;
            return -1;
        };
        std::vector<std::uint8_t> out;
        std::uint32_t acc = 0; int bits = 0;
        for (char c : in) {
            int v = val(c);
            if (v < 0) continue;
            acc = (acc << 6) | static_cast<std::uint32_t>(v);
            bits += 6;
            if (bits >= 8) { bits -= 8; out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xff)); }
        }
        return out;
    }

    auto sign_cert_from_csr_der(std::span<std::uint8_t const> csr_der) -> std::string {
        auto const* p = csr_der.data();
        std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req(d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size())), X509_REQ_free);
        require(req != nullptr, "d2i_X509_REQ");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pub(X509_REQ_get_pubkey(req.get()), EVP_PKEY_free);
        require(pub != nullptr, "X509_REQ_get_pubkey");
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx(EVP_PKEY_CTX_new_id(evp_pkey_ed25519, nullptr), EVP_PKEY_CTX_free);
        EVP_PKEY* ca_raw = nullptr;
        require(kctx && EVP_PKEY_keygen_init(kctx.get()) == 1 && EVP_PKEY_keygen(kctx.get(), &ca_raw) == 1, "ca keygen");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ca_key(ca_raw, EVP_PKEY_free);
        std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
        require(cert && X509_set_version(cert.get(), 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 42) == 1, "x509 init");
        require(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) && X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400 * 90), "x509 time");
        require(X509_set_pubkey(cert.get(), pub.get()) == 1, "x509 pubkey");
        require(X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req.get())) == 1, "x509 subj");
        require(X509_set_issuer_name(cert.get(), X509_REQ_get_subject_name(req.get())) == 1, "x509 iss");
        require(X509_sign(cert.get(), ca_key.get(), nullptr) > 0, "x509 sign");
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        require(bio && PEM_write_bio_X509(bio.get(), cert.get()) == 1, "pem write");
        char* data = nullptr;
        auto len = BIO_get_mem_data(bio.get(), &data);
        return std::string(data, static_cast<std::size_t>(len));
    }

    // 173.B: ACME Real HTTP-01 / TLS-ALPN-01 / DNS-01 + Atomic Credential Swap
    auto run_acme_challenge_e2e(std::string const& challenge_type) -> void {
        auto [ca_fd, ca_port] = listen_loopback();
        std::atomic_bool stop{false};
        std::atomic_bool challenge_verified{false};
        std::atomic<std::uint16_t> live_http_port{0};
        std::atomic<std::uint16_t> live_alpn_port{0};
        std::string issued_cert;
        std::string order_status = "pending";
        std::string base = std::format("http://127.0.0.1:{}", ca_port);

        auto verify_alpn01_tls = [&](std::uint16_t port) -> bool {
            corosio::io_context io;
            corosio::tcp_socket s(io);
            if (s.open()) return false;
            bool ok = false;
            auto task = [&]() -> capy::task<> {
                auto [ce] = co_await corosio::timeout(s.connect({corosio::ipv4_address::loopback(), port}),
                    std::chrono::steady_clock::now() + 2s);
                if (ce) co_return;
                std::array<std::string_view, 1> alpns{"acme-tls/1"};
                std::array<std::uint16_t, 1> groups{0x001d};
                auto hello = tls::make_client_hello("edge.example.com", alpns, groups);
                if (!hello) co_return;
                auto dummy = tls::ServerCredential::generate_ed25519();
                if (!dummy) co_return;
                std::vector<crypto::Bytes> anchors{crypto::Bytes(dummy->certificate().begin(), dummy->certificate().end())};
                auto hs = tls::ClientHandshakeIo::create(std::move(*hello), groups, anchors, tls::PeerNameKind::dns,
                    {reinterpret_cast<std::uint8_t const*>("edge.example.com"), 16}, 0, 0, 5000);
                if (!hs) co_return;
                auto out = hs->pending_output();
                auto [we, wn] = co_await s.write_some(capy::const_buffer(out.data(), out.size()));
                if (we || wn != out.size()) co_return;
                std::array<std::uint8_t, 128> resp{};
                auto [re, rn] = co_await corosio::timeout(s.read_some(capy::mutable_buffer(resp.data(), resp.size())),
                    std::chrono::steady_clock::now() + 2s);
                // Server replies with real TLS 1.3 ServerHello handshake record (0x16 0x03 0x03 ...).
                ok = !re && rn >= 5 && resp[0] == 0x16 && resp[1] == 0x03 && resp[2] == 0x03;
            };
            capy::run_async(io.get_executor())(task());
            io.run_for(3s);
            return ok;
        };

        std::jthread ca_thr([&] {
            while (!stop) {
                pollfd p{ca_fd.fd, POLLIN, 0};
                if (::poll(&p, 1, 10) <= 0) continue;
                Fd c(::accept(ca_fd.fd, nullptr, nullptr));
                if (c.fd < 0) continue;
                std::string raw;
                std::array<char, 4096> b{};
                std::size_t body_off = 0, need = 0;
                for (int i = 0; i < 100; ++i) {
                    pollfd cp{c.fd, POLLIN, 0};
                    if (::poll(&cp, 1, 200) <= 0) break;
                    auto n = ::recv(c.fd, b.data(), b.size(), 0);
                    if (n <= 0) break;
                    raw.append(b.data(), static_cast<std::size_t>(n));
                    if (!body_off) {
                        if (auto sep = raw.find("\r\n\r\n"); sep != std::string::npos) {
                            body_off = sep + 4;
                            if (auto cl = raw.find("Content-Length:"); cl != std::string::npos && cl < sep) {
                                std::size_t v = 0; auto pos = cl + 15;
                                while (pos < sep && raw[pos] == ' ') ++pos;
                                (void)std::from_chars(raw.data() + pos, raw.data() + sep, v);
                                need = v;
                            }
                        }
                    }
                    if (body_off && raw.size() >= body_off + need) break;
                }
                auto eol = raw.find("\r\n");
                if (eol == std::string::npos) continue;
                auto line = std::string_view(raw).substr(0, eol);
                auto body = body_off <= raw.size() ? std::string_view(raw).substr(body_off) : std::string_view{};
                auto send_http = [&](int code, std::string_view bdy, std::string_view loc = {}) {
                    std::string r = std::format("HTTP/1.1 {} OK\r\nReplay-Nonce: nonce173\r\nContent-Length: {}\r\n", code, bdy.size());
                    if (!loc.empty()) r += std::format("Location: {}\r\n", loc);
                    r += "Connection: close\r\n\r\n";
                    r += bdy;
                    (void)send_str(c.fd, r);
                };
                if (line.starts_with("GET /dir ")) {
                    send_http(200, std::format(R"({{"newNonce":"{0}/nonce","newAccount":"{0}/acc","newOrder":"{0}/order"}})", base));
                } else if (line.starts_with("HEAD /nonce ")) {
                    send_http(200, {});
                } else if (line.starts_with("POST /acc ")) {
                    send_http(201, R"({"status":"valid"})", base + "/acct/1");
                } else if (line.starts_with("POST /order ")) {
                    send_http(201, std::format(R"({{"status":"pending","authorizations":["{0}/authz/1"],"finalize":"{0}/fin/1"}})", base), base + "/order/1");
                } else if (line.starts_with("POST /authz/1 ")) {
                    send_http(200, std::format(R"({{"identifier":{{"type":"dns","value":"edge.example.com"}},"status":"pending","challenges":[{{"type":"http-01","url":"{0}/ch/http","token":"tok173http","status":"pending"}},{{"type":"tls-alpn-01","url":"{0}/ch/alpn","token":"tok173alpn","status":"pending"}},{{"type":"dns-01","url":"{0}/ch/dns","token":"tok173dns","status":"pending"}}]}})", base));
                } else if (line.starts_with("POST /ch/")) {
                    if (challenge_type == "http-01") {
                        auto hc = connect_loopback(live_http_port.load());
                        (void)send_str(hc.fd, "GET /.well-known/acme-challenge/tok173http HTTP/1.1\r\nHost: localhost\r\n\r\n");
                        std::array<char, 512> hb{};
                        pollfd hp{hc.fd, POLLIN, 0};
                        if (::poll(&hp, 1, 1000) > 0) {
                            auto hn = ::recv(hc.fd, hb.data(), hb.size(), 0);
                            std::string_view hs(hb.data(), hn > 0 ? static_cast<std::size_t>(hn) : 0);
                            challenge_verified = hs.contains("200 OK") && hs.contains("tok173http.");
                        }
                    } else if (challenge_type == "tls-alpn-01") {
                        challenge_verified = verify_alpn01_tls(live_alpn_port.load());
                    } else {
                        challenge_verified = true;
                    }
                    order_status = "ready";
                    send_http(200, R"({"status":"valid"})");
                } else if (line.starts_with("POST /fin/1 ")) {
                    auto ppos = body.find("\"payload\":\"");
                    require(ppos != std::string_view::npos, "jws payload");
                    auto pend = body.find('"', ppos + 11);
                    auto pbytes = base64url_decode(body.substr(ppos + 11, pend - (ppos + 11)));
                    std::string pjson(pbytes.begin(), pbytes.end());
                    auto cpos = pjson.find("\"csr\":\"");
                    require(cpos != std::string::npos, "csr field");
                    auto cend = pjson.find('"', cpos + 7);
                    issued_cert = sign_cert_from_csr_der(base64url_decode(pjson.substr(cpos + 7, cend - (cpos + 7))));
                    order_status = "valid";
                    send_http(200, std::format(R"({{"status":"valid","finalize":"{0}/fin/1","certificate":"{0}/cert/1"}})", base));
                } else if (line.starts_with("POST /order/1 ")) {
                    send_http(200, std::format(R"({{"status":"{1}","finalize":"{0}/fin/1","certificate":"{0}/cert/1"}})", base, order_status));
                } else if (line.starts_with("POST /cert/1 ")) {
                    send_http(200, issued_cert);
                }
            }
        });

        auto tmp = std::filesystem::temp_directory_path() / ("nexus_b173_acme_" + challenge_type);
        std::filesystem::remove_all(tmp);
        logging::Runtime logs;
        std::atomic_bool hook_fired{false};
        config::AcmeServiceConfig cfg{
            .directory_url = base + "/dir", .domains = {"edge.example.com"},
            .email = "ops@example.com", .challenge = challenge_type,
            .state_dir = tmp.string(), .renew_before_seconds = 3600, .check_interval_ms = 50,
        };
        auto handle = cli::init_acme_service(cfg, logs, {.on_credential_updated = [&](std::string_view cp, std::string_view kp) noexcept {
            if (cp.contains("BEGIN CERTIFICATE") && kp.contains("PRIVATE KEY")) hook_fired.store(true, std::memory_order_release);
        }});
        require(handle.has_value(), handle ? "" : handle.error());
        live_http_port.store(cli::acme_http01_port(*handle));
        live_alpn_port.store(cli::acme_alpn01_port(*handle));
        if (challenge_type == "http-01") require(live_http_port.load() != 0, "http-01 bound");
        if (challenge_type == "tls-alpn-01") require(live_alpn_port.load() != 0, "alpn-01 bound");

        auto dl = std::chrono::steady_clock::now() + 5s;
        while (std::chrono::steady_clock::now() < dl && cli::acme_credential_generation(*handle) == 0)
            std::this_thread::sleep_for(20ms);

        require(challenge_verified.load(), "acme challenge verified: " + challenge_type);
        require(cli::acme_credential_generation(*handle) >= 1 && cli::acme_has_valid_credential(*handle), "acme atomic ServerCredential updated");
        require(hook_fired.load(), "acme hot-update hook fired");
        if (challenge_type == "dns-01") {
            auto txt = cli::acme_dns01_record(*handle, "edge.example.com");
            require(txt && !txt->empty() && std::filesystem::exists(tmp / "dns01_challenges.txt"), "dns-01 TXT published");
        }
        handle->state.reset();
        stop = true;
        std::filesystem::remove_all(tmp);
    }

    // 173.D: DERP Server Real HTTP Upgrade + WebSocket Upgrade + Two-Peer Relay
    auto test_173d_derp_server_e2e() -> void {
        logging::Runtime logs;
        config::DerpServerServiceConfig dcfg{.max_peers = 32, .listen_host = "127.0.0.1", .listen_port = 0};
        auto h = cli::init_derp_server_service(dcfg, logs);
        require(h.has_value(), h ? "" : h.error());
        auto port = cli::derp_bound_port(*h);
        auto srv_pub = cli::derp_public_key(*h);
        require(port != 0, "derp bound port");

        {
            auto c = connect_loopback(port);
            require(send_str(c.fd, "GET /generate_204 HTTP/1.1\r\nHost: localhost\r\n\r\n"), "204 req");
            std::array<char, 64> b{};
            pollfd p{c.fd, POLLIN, 0};
            require(::poll(&p, 1, 1000) > 0, "204 poll");
            auto n = ::recv(c.fd, b.data(), b.size(), 0);
            require(n > 0 && std::string_view(b.data(), static_cast<std::size_t>(n)).contains("204 No Content"), "204 resp");
        }

        auto read_http_upgrade = [](int fd, std::vector<std::uint8_t>& rem) {
            std::string raw; std::array<char, 512> b{};
            for (;;) {
                pollfd p{fd, POLLIN, 0};
                require(::poll(&p, 1, 2000) > 0, "upgrade poll");
                auto n = ::recv(fd, b.data(), b.size(), 0);
                require(n > 0, "upgrade recv");
                raw.append(b.data(), static_cast<std::size_t>(n));
                if (auto pos = raw.find("\r\n\r\n"); pos != std::string::npos) {
                    require(raw.starts_with("HTTP/1.1 101"), "101 Switching Protocols");
                    rem.assign(reinterpret_cast<std::uint8_t const*>(raw.data() + pos + 4),
                        reinterpret_cast<std::uint8_t const*>(raw.data() + raw.size()));
                    return;
                }
            }
        };
        auto read_exact_buf = [&](int fd, std::vector<std::uint8_t>& rem, std::size_t n) -> std::vector<std::uint8_t> {
            while (rem.size() < n) {
                std::array<std::uint8_t, 512> tmp{};
                pollfd p{fd, POLLIN, 0};
                require(::poll(&p, 1, 2000) > 0, "derp frame poll");
                auto r = ::recv(fd, tmp.data(), tmp.size(), 0);
                require(r > 0, "derp frame recv");
                rem.insert(rem.end(), tmp.begin(), tmp.begin() + r);
            }
            std::vector<std::uint8_t> out(rem.begin(), rem.begin() + static_cast<std::ptrdiff_t>(n));
            rem.erase(rem.begin(), rem.begin() + static_cast<std::ptrdiff_t>(n));
            return out;
        };
        auto read_derp_frame = [&](int fd, std::vector<std::uint8_t>& rem, bool ws) -> std::pair<tailscale::derp::Type, std::vector<std::uint8_t>> {
            std::vector<std::uint8_t> raw;
            if (ws) {
                auto wh = read_exact_buf(fd, rem, 2);
                std::size_t plen = wh[1] & 0x7f;
                if (plen == 126) { auto ex = read_exact_buf(fd, rem, 2); plen = (std::size_t(ex[0]) << 8) | ex[1]; }
                raw = read_exact_buf(fd, rem, plen);
            } else {
                auto dh = read_exact_buf(fd, rem, 5);
                auto hdr = tailscale::derp::parse_header(dh);
                require(hdr.has_value(), "derp hdr");
                auto pl = read_exact_buf(fd, rem, hdr->length);
                return {hdr->type, std::move(pl)};
            }
            auto hdr = tailscale::derp::parse_header(raw);
            require(hdr.has_value() && raw.size() == 5 + hdr->length, "ws derp hdr");
            return {hdr->type, std::vector<std::uint8_t>(raw.begin() + 5, raw.end())};
        };
        auto send_ws_masked = [](int fd, std::span<std::uint8_t const> pl) {
            std::vector<std::uint8_t> out{0x82};
            if (pl.size() < 126) out.push_back(static_cast<std::uint8_t>(0x80 | pl.size()));
            else { out.push_back(0x80 | 126); out.push_back(std::uint8_t(pl.size() >> 8)); out.push_back(std::uint8_t(pl.size())); }
            std::array<std::uint8_t, 4> mask{0x12, 0x34, 0x56, 0x78};
            out.insert(out.end(), mask.begin(), mask.end());
            for (std::size_t i = 0; i < pl.size(); ++i) out.push_back(pl[i] ^ mask[i & 3]);
            require(send_all(fd, out), "send ws masked");
        };

        auto key_a = *crypto::X25519Private::generate(), key_b = *crypto::X25519Private::generate();
        auto pub_a = *key_a.public_key(), pub_b = *key_b.public_key();
        auto sock_a = connect_loopback(port);
        require(send_str(sock_a.fd, "GET /derp HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"), "peer A upgrade");
        std::vector<std::uint8_t> rem_a; read_http_upgrade(sock_a.fd, rem_a);
        auto sock_b = connect_loopback(port);
        require(send_str(sock_b.fd, "GET /derp HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"), "peer B ws upgrade");
        std::vector<std::uint8_t> rem_b; read_http_upgrade(sock_b.fd, rem_b);

        auto do_handshake = [&](int fd, std::vector<std::uint8_t>& rem, crypto::X25519Private const& key, bool ws) {
            auto now = std::chrono::steady_clock::now();
            tailscale::derp::PinnedClientHandshake hs(key, srv_pub, now, now + 5s);
            auto [t1, p1] = read_derp_frame(fd, rem, ws);
            tailscale::derp::Nonce n{}; require(crypto::random_bytes(n).has_value(), "nonce");
            auto ci = hs.start({t1, p1}, n, std::chrono::steady_clock::now());
            require(ci.has_value(), "hs start");
            if (ws) send_ws_masked(fd, *ci); else require(send_all(fd, *ci), "send ci");
            auto [t2, p2] = read_derp_frame(fd, rem, ws);
            require(hs.finish({t2, p2}, std::chrono::steady_clock::now()).has_value(), "hs finish");
        };
        do_handshake(sock_a.fd, rem_a, key_a, false);
        do_handshake(sock_b.fd, rem_b, key_b, true);

        std::string_view payload = "hello-via-derp-ws-relay";
        auto spkt = *tailscale::derp::encode_packet(tailscale::derp::Type::send_packet, pub_b,
            {reinterpret_cast<std::uint8_t const*>(payload.data()), payload.size()});
        require(send_all(sock_a.fd, spkt), "send_packet");
        auto [rt, rp] = read_derp_frame(sock_b.fd, rem_b, true);
        auto parsed = tailscale::derp::parse_packet({rt, rp}, tailscale::derp::Type::recv_packet);
        require(parsed.has_value() && parsed->peer == pub_a &&
            std::string_view(reinterpret_cast<char const*>(parsed->bytes.data()), parsed->bytes.size()) == payload, "DERP A->B relay");

        std::array<std::uint8_t, 8> ptok{1,2,3,4,5,6,7,8};
        send_ws_masked(sock_b.fd, *tailscale::derp::encode_ping(tailscale::derp::Type::ping, ptok));
        auto [pt, pp] = read_derp_frame(sock_b.fd, rem_b, true);
        auto pong = tailscale::derp::parse_ping({pt, pp}, tailscale::derp::Type::pong);
        require(pong.has_value() && *pong == ptok, "DERP ping/pong");
    }
}

int main() {
    run_acme_challenge_e2e("http-01");
    run_acme_challenge_e2e("tls-alpn-01");
    run_acme_challenge_e2e("dns-01");
    test_173d_derp_server_e2e();
    std::cout << "BATCH 173 ACME & DERP SERVER REAL I/O E2E TESTS PASSED\n";
    return 0;
}
