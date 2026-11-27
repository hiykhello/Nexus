#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

import std;
import capy;
import corosio;
import config;
import crypto;
import dns.message;
import dns.message_program;
import dns.reverse;
import memory.budget;
import quic.ech_config;
import relay;
import tls.application_io;
import tls.client_handshake_io;
import tls.corosio_application;
import tls.corosio_client;
import tls.corosio_server_handshake;
import tls.ech_server;
import tls.hello;
import tls.hello_config;
import tls.outbound_fragment;
import tls.profiles;
import tls.server_handshake_io;

namespace {
    template<class T, auto Free>
    struct SslPtr {
        T* p = nullptr;
        explicit SslPtr(T* ptr = nullptr) : p(ptr) {}
        ~SslPtr() { if (p) Free(p); }
        SslPtr(SslPtr const&) = delete;
        auto operator=(SslPtr const&) -> SslPtr& = delete;
        auto get() const noexcept -> T* { return p; }
    };

    auto encode_b64(std::span<std::uint8_t const> data) -> std::string {
        static constexpr char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((data.size() + 2) / 3) * 4);
        for (std::size_t i = 0; i < data.size(); i += 3) {
            std::uint32_t v = std::uint32_t(data[i]) << 16;
            if (i + 1 < data.size()) v |= std::uint32_t(data[i + 1]) << 8;
            if (i + 2 < data.size()) v |= std::uint32_t(data[i + 2]);
            out.push_back(tbl[(v >> 18) & 63]);
            out.push_back(tbl[(v >> 12) & 63]);
            out.push_back(i + 1 < data.size() ? tbl[(v >> 6) & 63] : '=');
            out.push_back(i + 2 < data.size() ? tbl[v & 63] : '=');
        }
        return out;
    }

    auto put16(crypto::Bytes& out, std::size_t v) -> void {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v & 0xff));
    }

    auto to_bytes(std::string_view s) noexcept -> std::span<std::uint8_t const> {
        return {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()};
    }

    auto to_sv(std::span<std::uint8_t const> b) noexcept -> std::string_view {
        return {reinterpret_cast<char const*>(b.data()), b.size()};
    }

    struct TestCert {
        std::string cert_pem, key_pem;
        crypto::Bytes cert_der;
        std::int64_t valid_time = 0;
    };

    auto make_test_cert(std::string_view san_ext) -> TestCert {
        SslPtr<EC_KEY, EC_KEY_free> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        EC_KEY_generate_key(ec.get());
        SslPtr<EVP_PKEY, EVP_PKEY_free> pkey(EVP_PKEY_new());
        EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get());
        SslPtr<X509, X509_free> x(X509_new());
        X509_set_version(x.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 42);
        X509_gmtime_adj(X509_getm_notBefore(x.get()), -3600);
        X509_gmtime_adj(X509_getm_notAfter(x.get()), 86400 * 30);
        X509_set_pubkey(x.get(), pkey.get());
        X509_NAME* sub = X509_get_subject_name(x.get());
        X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC,
            reinterpret_cast<unsigned char const*>("inner.secret.example"), -1, -1, 0);
        X509_set_issuer_name(x.get(), sub);
        auto add_ext = [&](int nid, std::string val) {
            SslPtr<X509_EXTENSION, X509_EXTENSION_free> ext(X509V3_EXT_nconf_nid(nullptr, nullptr, nid, val.data()));
            X509_add_ext(x.get(), ext.get(), -1);
        };
        add_ext(NID_basic_constraints, "critical,CA:TRUE");
        add_ext(NID_key_usage, "critical,digitalSignature,keyCertSign");
        add_ext(NID_ext_key_usage, "serverAuth");
        add_ext(NID_subject_alt_name, std::string(san_ext));
        X509_sign(x.get(), pkey.get(), EVP_sha256());
        auto bio_str = [](BIO* b) -> std::string {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(b, &mem);
            return (mem && mem->data && mem->length) ? std::string(mem->data, mem->length) : std::string{};
        };
        SslPtr<BIO, BIO_free> cb(BIO_new(BIO_s_mem())), kb(BIO_new(BIO_s_mem()));
        PEM_write_bio_X509(cb.get(), x.get());
        PEM_write_bio_PrivateKey(kb.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
        int dlen = i2d_X509(x.get(), nullptr);
        crypto::Bytes der(static_cast<std::size_t>(dlen));
        unsigned char* p = der.data();
        i2d_X509(x.get(), &p);
        auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return {bio_str(cb.get()), bio_str(kb.get()), std::move(der), now_sec};
    }

    struct TestEchMaterial {
        std::array<std::uint8_t, 32> priv{};
        crypto::Bytes config_list_wire;
        quic::EchConfig parsed;
    };

    auto make_ech_material(std::uint8_t id, std::uint16_t aead_id, std::string_view pub_name) -> TestEchMaterial {
        TestEchMaterial out;
        (void)crypto::random_bytes(out.priv);
        EVP_HPKE_KEY key;
        EVP_HPKE_KEY_zero(&key);
        EVP_HPKE_KEY_init(&key, EVP_hpke_x25519_hkdf_sha256(), out.priv.data(), out.priv.size());
        std::array<std::uint8_t, 32> pub{};
        std::size_t pub_len = 0;
        EVP_HPKE_KEY_public_key(&key, pub.data(), &pub_len, pub.size());
        EVP_HPKE_KEY_cleanup(&key);
        crypto::Bytes contents{id};
        put16(contents, 0x0020); put16(contents, 32);
        contents.insert(contents.end(), pub.begin(), pub.end());
        put16(contents, 4); put16(contents, 0x0001); put16(contents, aead_id);
        contents.push_back(64);
        contents.push_back(static_cast<std::uint8_t>(pub_name.size()));
        contents.insert(contents.end(), pub_name.begin(), pub_name.end());
        put16(contents, 0);
        crypto::Bytes cfg;
        put16(cfg, 0xfe0d); put16(cfg, contents.size());
        cfg.insert(cfg.end(), contents.begin(), contents.end());
        put16(out.config_list_wire, cfg.size());
        out.config_list_wire.insert(out.config_list_wire.end(), cfg.begin(), cfg.end());
        out.parsed = *quic::select_ech_config(out.config_list_wire);
        return out;
    }

    auto drive_handshake(tls::ClientHandshakeIo& client, tls::ServerHandshakeIo& server) -> bool {
        std::uint64_t now = 100;
        for (int step = 0; step < 64 && (!client.complete() || !server.complete()); ++step, ++now) {
            bool progress = false;
            while (!client.pending_output().empty()) {
                auto out = client.pending_output();
                crypto::Bytes wire(out.begin(), out.end());
                if (!client.written(wire.size(), now)) return false;
                for (std::size_t pos = 0; pos < wire.size();) {
                    auto f = server.feed(std::span<std::uint8_t const>(wire).subspan(pos), now);
                    if (!f || !f->consumed) return false;
                    pos += f->consumed;
                }
                progress = true;
            }
            while (!server.pending_output().empty()) {
                auto out = server.pending_output();
                crypto::Bytes wire(out.begin(), out.end());
                if (!server.written(wire.size(), now)) return false;
                for (std::size_t pos = 0; pos < wire.size();) {
                    auto f = client.feed(std::span<std::uint8_t const>(wire).subspan(pos), now);
                    if (!f || !f->consumed) return false;
                    pos += f->consumed;
                }
                progress = true;
            }
            if (!progress) break;
        }
        return client.complete() && server.complete();
    }

    auto check_app_exchange(tls::ClientHandshakeIo& client, tls::ServerHandshakeIo& server) -> bool {
        auto capp = client.take_application_records();
        auto sapp = server.take_application_records();
        if (!capp || !sapp) return false;
        auto c2s = capp->seal(to_bytes("ech-client-to-server-ok"));
        if (!c2s) return false;
        auto sopen = sapp->open(*c2s);
        if (!sopen || to_sv(*sopen) != "ech-client-to-server-ok") return false;
        auto s2c = sapp->seal(to_bytes("ech-server-to-client-ok"));
        if (!s2c) return false;
        auto copen = capp->open(*s2c);
        return copen && to_sv(*copen) == "ech-server-to-client-ok";
    }

    auto make_https_ech_dns_response(std::uint16_t id, std::string_view qname,
                                     std::span<std::uint8_t const> ech_config_list) -> crypto::Bytes {
        auto write_qname = [](crypto::Bytes& out, std::string_view name) {
            for (std::size_t start = 0; start < name.size();) {
                auto dot = name.find('.', start);
                if (dot == std::string_view::npos) dot = name.size();
                out.push_back(static_cast<std::uint8_t>(dot - start));
                out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                           name.begin() + static_cast<std::ptrdiff_t>(dot));
                start = dot + 1;
            }
            out.push_back(0);
        };
        crypto::Bytes rdata;
        put16(rdata, 1); rdata.push_back(0);
        put16(rdata, 4); put16(rdata, 4); rdata.insert(rdata.end(), {198, 51, 100, 42});
        put16(rdata, 5); put16(rdata, ech_config_list.size());
        rdata.insert(rdata.end(), ech_config_list.begin(), ech_config_list.end());
        put16(rdata, 6); put16(rdata, 16);
        rdata.insert(rdata.end(), {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42});
        crypto::Bytes wire;
        put16(wire, id); put16(wire, 0x8180);
        put16(wire, 1); put16(wire, 1); put16(wire, 0); put16(wire, 0);
        write_qname(wire, qname); put16(wire, 65); put16(wire, 1);
        write_qname(wire, qname); put16(wire, 65); put16(wire, 1);
        wire.insert(wire.end(), {0, 0, 0, 60});
        put16(wire, rdata.size());
        wire.insert(wire.end(), rdata.begin(), rdata.end());
        return wire;
    }

    auto run_async_fragment_roundtrip(TestCert const& cert, tls::OutboundFragmentOptions frag_opts,
                                      std::string_view alpn_proto) -> bool {
        corosio::io_context ctx;
        corosio::tcp_acceptor acceptor(ctx);
        if (acceptor.open() || acceptor.bind(corosio::endpoint(corosio::ipv4_address::loopback(), 0)) || acceptor.listen())
            return false;
        auto ep = acceptor.local_endpoint();
        auto cred = tls::ServerCredential::create_file_contents(to_bytes(cert.cert_pem), to_bytes(cert.key_pem));
        if (!cred) return false;
        tls::ClientProfile cp{"inner.secret.example", {cert.cert_der}, 0x001d, false, {std::string(alpn_proto)}};
        cp.tls_fragment = frag_opts;
        bool server_ok = false, client_ok = false;
        auto now_ms = [] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()); };

        auto server_task = [&]() -> capy::task<void> {
            corosio::tcp_socket sock(ctx);
            if (auto [ec] = co_await acceptor.accept(sock); ec) co_return;
            auto hs = tls::make_server_handshake(*cred, now_ms(), now_ms() + 5000, {}, alpn_proto);
            if (!hs) co_return;
            auto res = co_await tls::detail::server_handshake(sock, *hs);
            if (!res) co_return;
            tls::detail::ApplicationConnection<corosio::tcp_socket> app(sock, std::move(res->records), std::move(res->unread));
            std::array<std::uint8_t, 64> buf{};
            auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            auto r = co_await app.read_into(buf, dl);
            if (!r || to_sv(std::span<std::uint8_t const>(buf).first(r->data_size)) != "ping-frag") co_return;
            if (!co_await app.send_all(to_bytes("pong-frag"), dl)) co_return;
            server_ok = true;
        };
        auto client_task = [&]() -> capy::task<void> {
            corosio::tcp_socket sock(ctx);
            if (auto [ec] = co_await sock.connect(ep); ec) co_return;
            auto hs = cp.handshake(now_ms(), now_ms() + 5000, cert.valid_time);
            if (!hs) co_return;
            tls::detail::ClientConnection<corosio::tcp_socket> conn(sock, std::move(*hs));
            if (!co_await conn.start() || !conn.application()) co_return;
            auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            if (!co_await conn.application()->send_all(to_bytes("ping-frag"), dl)) co_return;
            std::array<std::uint8_t, 64> buf{};
            auto r = co_await conn.application()->read_into(buf, dl);
            if (!r || to_sv(std::span<std::uint8_t const>(buf).first(r->data_size)) != "pong-frag") co_return;
            client_ok = true;
        };
        capy::run_async(ctx.get_executor())(server_task());
        capy::run_async(ctx.get_executor())(client_task());
        ctx.run();
        return server_ok && client_ok;
    }
}

int main() {
    unsigned failures = 0;
    auto check = [&](bool cond, std::string_view label) {
        if (!cond) { ++failures; std::cerr << "FAIL: " << label << '\n'; }
    };
    auto cert = make_test_cert("DNS:inner.secret.example,DNS:public.cover.example");
    auto cred = tls::ServerCredential::create_file_contents(to_bytes(cert.cert_pem), to_bytes(cert.key_pem));
    check(cred.has_value(), "create test server credential");

    // 1. Outbound TLS Fragmentation (SNI-label-aware TCP splits + TLS record splits + live loopback TLS 1.3).
    {
        std::array<std::uint16_t, 1> groups{0x001d};
        std::array<std::string_view, 1> alpn{"h2"};
        auto ch = tls::make_client_hello("secret.sub.example.com", alpn, groups);
        auto ch_io = tls::ClientHandshakeIo::create(std::move(*ch), groups, std::span(&cert.cert_der, 1),
            tls::PeerNameKind::dns, to_bytes("secret.sub.example.com"), cert.valid_time, 100, 5000);
        check(ch_io.has_value(), "create ClientHandshakeIo for fragment tests");
        auto wire = ch_io->pending_output();
        auto sni = tls::locate_client_hello_sni(wire);
        check(sni && to_sv(wire.subspan(sni->host_offset, sni->host_len)) == "secret.sub.example.com", "locate SNI in ClientHello");
        if (sni) {
            tls::OutboundFragmentOptions tcp_opts{.enabled = true, .record_fragment = false, .min_bytes = 12, .max_bytes = 40};
            for (std::uint64_t seed = 1; seed <= 20; ++seed) {
                auto splits = tls::plan_client_hello_splits(wire, tcp_opts, seed);
                std::size_t sum = 0; bool cut_inside = false;
                for (auto sz : splits) { sum += sz; if (sum > sni->host_offset && sum < sni->host_offset + sni->host_len) cut_inside = true; }
                check(sum == wire.size() && splits.size() > 1 && cut_inside, "SNI-label-aware TCP split invariant");
            }
            tls::OutboundFragmentOptions rec_opts{.enabled = true, .record_fragment = true, .min_bytes = 8, .max_bytes = 24};
            auto frag = tls::fragment_client_hello_records(wire, rec_opts, 0xabcdef1234ULL);
            crypto::Bytes reassembled; std::size_t pos = 0, rec_count = 0; bool intact = false;
            while (pos + 5 <= frag.size()) {
                check(frag[pos] == 0x16 && frag[pos + 1] == wire[1] && frag[pos + 2] == wire[2], "TLS record header");
                auto rlen = (std::size_t{frag[pos + 3]} << 8) | frag[pos + 4];
                auto pay = std::span<std::uint8_t const>(frag).subspan(pos + 5, rlen);
                if (to_sv(pay).find("secret.sub.example.com") != std::string_view::npos) intact = true;
                reassembled.insert(reassembled.end(), pay.begin(), pay.end());
                pos += 5 + rlen; ++rec_count;
            }
            check(pos == frag.size() && rec_count >= 3 && !intact && std::ranges::equal(reassembled, wire.subspan(5)),
                  "TLS record fragmentation splits SNI and reassembles identically");
        }
        std::array<std::uint8_t, 8> non_ch{'G', 'E', 'T', ' ', '/', ' ', '\r', '\n'};
        check(tls::plan_client_hello_splits(non_ch, {.enabled = true}, 7) == std::vector<std::size_t>{8} &&
              std::ranges::equal(tls::fragment_client_hello_records(non_ch, {.record_fragment = true}, 7), non_ch),
              "non-ClientHello passthrough");
        check(run_async_fragment_roundtrip(cert, {.enabled = true, .record_fragment = false, .min_bytes = 7, .max_bytes = 17, .fallback_delay_ms = 10}, "h2"),
              "live loopback TLS 1.3 with TCP SNI fragmentation");
        check(run_async_fragment_roundtrip(cert, {.enabled = true, .record_fragment = true, .min_bytes = 9, .max_bytes = 23, .fallback_delay_ms = 10}, "http/1.1"),
              "live loopback TLS 1.3 with TLS record fragmentation");
    }

    // 2. Server-Side ECH key formats + full Client ECH <-> Server ECH round-trip + HRR + retry_configs.
    {
        auto ech_aes = make_ech_material(7, 0x0001, "public.cover.example");
        auto ech_chacha = make_ech_material(9, 0x0003, "public.cover.example");
        std::string cli_text = "PrivateKey: " + encode_b64(ech_aes.priv) + "\nEchConfigList: " + encode_b64(ech_aes.config_list_wire) + "\n";
        auto keys_cli = tls::parse_ech_server_keys(to_bytes(cli_text));
        check(keys_cli && (*keys_cli)->entries().size() == 1, "parse generate ech-keypair text format");
        crypto::Bytes pem_bin;
        put16(pem_bin, 32); pem_bin.insert(pem_bin.end(), ech_chacha.priv.begin(), ech_chacha.priv.end());
        put16(pem_bin, ech_chacha.config_list_wire.size());
        pem_bin.insert(pem_bin.end(), ech_chacha.config_list_wire.begin(), ech_chacha.config_list_wire.end());
        std::string pem_ech_keys = "-----BEGIN ECH KEYS-----\n" + encode_b64(pem_bin) + "\n-----END ECH KEYS-----\n";
        auto keys_pem = tls::parse_ech_server_keys(to_bytes(pem_ech_keys));
        check(keys_pem && (*keys_pem)->entries().size() == 1 && (*keys_pem)->entries()[0].config_id == 9, "parse PEM ECH KEYS");
        std::string pem_pair = "-----BEGIN ECH PRIVATE KEY-----\n" + encode_b64(ech_aes.priv) + "\n-----END ECH PRIVATE KEY-----\n"
                               "-----BEGIN ECH CONFIG-----\n" + encode_b64(ech_aes.config_list_wire) + "\n-----END ECH CONFIG-----\n";
        check(tls::parse_ech_server_keys(to_bytes(pem_pair)).has_value(), "parse PEM ECH PRIVATE KEY + ECH CONFIG");
        crypto::Bytes raw_bin(ech_aes.priv.begin(), ech_aes.priv.end());
        raw_bin.insert(raw_bin.end(), ech_aes.config_list_wire.begin(), ech_aes.config_list_wire.end());
        check(tls::parse_ech_server_keys(raw_bin).has_value(), "parse raw binary ECH key");
        std::string bad_text = "PrivateKey: " + encode_b64(ech_chacha.priv) + "\nEchConfigList: " + encode_b64(ech_aes.config_list_wire) + "\n";
        check(!tls::parse_ech_server_keys(to_bytes(bad_text)), "reject mismatched ECH private/public key");

        // 2a. Full Client ECH <-> Server ECH AES-128-GCM with memory budget.
        tls::ClientProfile cp{"inner.secret.example", {cert.cert_der}, 0x001d, false, {"h2"}};
        auto client = cp.handshake(100, 5000, cert.valid_time, {}, &ech_aes.parsed);
        check(client.has_value(), "create client ECH handshake");
        auto ch_sv = to_sv(client->pending_output());
        check(ch_sv.find("public.cover.example") != std::string_view::npos &&
              ch_sv.find("inner.secret.example") == std::string_view::npos,
              "ECH outer ClientHello conceals inner SNI");
        auto budget = std::make_shared<memory::Budget>(4 * 1024 * 1024);
        std::array<std::string_view, 2> alpn_prefs{"h2", "http/1.1"};
        auto server = tls::make_server_handshake(*cred, 100, 5000, budget, alpn_prefs, false, *keys_cli);
        check(server && drive_handshake(*client, *server), "Client ECH <-> Server ECH AES-128-GCM handshake");
        check(server->ech_accepted() && server->negotiated_sni() == "inner.secret.example" &&
              to_sv(server->negotiated_alpn()) == "h2" && check_app_exchange(*client, *server),
              "server decrypts inner SNI + ALPN and exchanges app data under ECH");

        // 2b. ChaCha20-Poly1305 ECH + HelloRetryRequest (empty initial key_share).
        std::array<std::uint16_t, 1> x25519{0x001d};
        auto hrr_hello = tls::make_client_hello("inner.secret.example", std::span<std::string_view const>{}, x25519);
        auto hrr_client = tls::ClientHandshakeIo::create(std::move(*hrr_hello), std::span<std::uint16_t const>{},
            std::span(&cert.cert_der, 1), tls::PeerNameKind::dns, to_bytes("inner.secret.example"),
            cert.valid_time, 100, 5000, {}, {}, &ech_chacha.parsed);
        auto hrr_server = tls::make_server_handshake(*cred, 100, 5000, {}, {}, *keys_pem);
        check(hrr_client && hrr_server && drive_handshake(*hrr_client, *hrr_server) &&
              hrr_server->ech_accepted() && hrr_server->negotiated_sni() == "inner.secret.example" &&
              check_app_exchange(*hrr_client, *hrr_server),
              "Client ECH <-> Server ECH ChaCha20-Poly1305 + HRR round-trip");

        // 2c. Key mismatch / GREASE outer ECH -> outer fallback + retry_configs in EncryptedExtensions.
        auto grease_hello = tls::make_client_hello("public.cover.example", std::span<std::string_view const>{}, x25519);
        crypto::Bytes grease_ext{0, 0, 1, 0, 1, 99, 0, 32};
        grease_ext.resize(grease_ext.size() + 32, 0x42);
        put16(grease_ext, 48); grease_ext.resize(grease_ext.size() + 48, 0x24);
        grease_hello->extensions.push_back({0xfe0d, std::move(grease_ext)});
        auto mm_client = tls::ClientHandshakeIo::create(std::move(*grease_hello), x25519,
            std::span(&cert.cert_der, 1), tls::PeerNameKind::dns, to_bytes("public.cover.example"),
            cert.valid_time, 100, 5000);
        auto mm_server = tls::make_server_handshake(*cred, 100, 5000, {}, {}, *keys_cli);
        check(mm_client && mm_server && drive_handshake(*mm_client, *mm_server),
              "ECH key mismatch falls back to outer ClientHello");
        auto const* neg = mm_client->negotiated();
        auto retry_cfg = neg ? quic::select_ech_config(neg->ech_retry_configs) : std::unexpected(quic::EchConfigError::malformed);
        check(!mm_server->ech_accepted() && mm_server->negotiated_sni() == "public.cover.example" &&
              neg && std::ranges::equal(neg->ech_retry_configs, (*keys_cli)->retry_configs_wire()) &&
              retry_cfg && retry_cfg->id == 7 && retry_cfg->public_name == "public.cover.example",
              "ECH key mismatch sends valid retry_configs in EncryptedExtensions");
    }

    // 3. KDL config parsing (tls-fragment boolean/block + alpn) & ECH query-server-name validation.
    {
        std::string_view kdl_ok = R"kdl(
schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none" } }
outbounds {
    outbound "direct" type="direct"
    outbound "v" type="vless" {
        server host="127.0.0.1" port=443; authentication { uuid-file "/tmp/u" }
        tls { server-name "example.com"; ca-file "/tmp/ca.pem"; verify #true; tls-fragment { record-fragment #true; min 12; max 64; fallback-delay-ms 250 }; alpn "h2" "http/1.1" }
    }
    outbound "p" type="http-connect" {
        server host="127.0.0.1" port=443
        tls { server-name "proxy.example"; ca-file "/tmp/ca.pem"; verify #true; tls-fragment #true; alpn "http/1.1" }
    }
    outbound "grp" type="selector" { member "v"; member "p"; member "direct"; selected "v" }
}
routing { final "grp" }
)kdl";
        auto cfg = config::parse_kdl(kdl_ok);
        check(cfg && cfg->vless_outbounds.size() == 1 && cfg->vless_outbounds[0].config.tls_fragment.enabled &&
              cfg->vless_outbounds[0].config.tls_fragment.record_fragment &&
              cfg->vless_outbounds[0].config.tls_fragment.min_bytes == 12 &&
              cfg->vless_outbounds[0].config.tls_fragment.max_bytes == 64 &&
              cfg->vless_outbounds[0].config.tls_fragment.fallback_delay_ms == 250 &&
              cfg->vless_outbounds[0].config.alpn == std::vector<std::string>{"h2", "http/1.1"} &&
              cfg->tcp_proxy_outbounds.size() == 1 && cfg->tcp_proxy_outbounds[0].config.tls &&
              cfg->tcp_proxy_outbounds[0].config.tls->tls_fragment.enabled &&
              !cfg->tcp_proxy_outbounds[0].config.tls->tls_fragment.record_fragment &&
              cfg->tcp_proxy_outbounds[0].config.tls->alpn == std::vector<std::string>{"http/1.1"},
              "parse KDL tls-fragment boolean/block and alpn");
        std::string_view kdl_bad = R"kdl(
schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none" } }
outbounds {
    outbound "direct" type="direct"
    outbound "v" type="vless" {
        server host="127.0.0.1" port=443; authentication { uuid-file "/tmp/u" }
        tls { server-name "example.com"; ca-file "/tmp/ca.pem"; verify #true; tls-fragment { min 100; max 10 } }
    }
}
routing { final "v" }
)kdl";
        check(!config::parse_kdl(kdl_bad), "reject tls-fragment min > max");

        auto tmp_ca = std::filesystem::temp_directory_path() / "nexus_wave31_31a_ca.pem";
        { std::ofstream f(tmp_ca, std::ios::binary); f << cert.cert_pem; }
        corosio::io_context rctx;
        relay::Server srv(rctx);
        config::TcpProxyOutbound tp{};
        tp.protocol = config::TcpProxyProtocol::http_connect;
        tp.host = "127.0.0.1"; tp.port = 443;
        tp.tls = config::TcpProxyTls{.server_name = "inner.secret.example", .ca_file = tmp_ca.string()};
        tp.tls->ech.dns = false; tp.tls->ech.query_server_name = "ech.cdn.example";
        check(!srv.add_tcp_proxy(tp), "reject query-server-name without ech-dns");
        tp.tls->ech.dns = true; tp.tls->ech.query_server_name = "192.0.2.1";
        check(!srv.add_tcp_proxy(tp), "reject IP-literal query-server-name");
        std::error_code rm_ec; std::filesystem::remove(tmp_ca, rm_ec);
    }

    // 4. DNS HTTPS (Type 65) RR ECHPublicName reverse-mapping.
    {
        auto ech_mat = make_ech_material(3, 0x0001, "public.cover.example");
        auto pub = dns::MessageProgram::extract_https_ech_public_name(ech_mat.config_list_wire);
        check(pub && *pub == "public.cover.example", "extract ECHPublicName from ECHConfigList");
        std::array<std::uint8_t, 6> bad_ech{0, 4, 0xfe, 0x0d, 0, 99};
        check(!dns::MessageProgram::extract_https_ech_public_name(bad_ech), "reject truncated ECHConfigList");
        auto dns_wire = make_https_ech_dns_response(0x4242, "app.hidden.example", ech_mat.config_list_wire);
        dns::QueryMessage q{0x4242, 0x0100, {"app.hidden.example", 65, 1}, {}};
        dns::ReverseCache cache(32, 7, {0x1111, 0x2222});
        auto count = dns::MessageProgram::record_https_ech_reverse(cache, 5, q, dns_wire, 10000);
        auto by_dom = cache.lookup_ech_public_name(5, "APP.HIDDEN.EXAMPLE.", 10500);
        dns::Address v4{{198, 51, 100, 42}, 4};
        dns::Address v6{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42}, 16};
        auto by_v4 = cache.lookup_ech_public_name(5, v4, 10500);
        auto by_v6 = cache.lookup_ech_public_name(5, v6, 10500);
        check(count == 3 && by_dom && by_dom->view() == "public.cover.example" &&
              by_v4 && by_v4->view() == "public.cover.example" && by_v6 && by_v6->view() == "public.cover.example" &&
              !cache.lookup_ech_public_name(6, "app.hidden.example", 10500) &&
              !cache.lookup_ech_public_name(5, "app.hidden.example", 70000) &&
              cache.clear() && !cache.lookup_ech_public_name(5, v4, 10500),
              "DNS HTTPS RR ECHPublicName domain + ipv4hint + ipv6hint reverse-mapping, TTL, view isolation, clear");
    }

    if (!failures) std::cout << "Wave 31 Track 31A (TLS fragmentation, Server ECH, query-server-name, DNS HTTPS ECH reverse) passed\n";
    return failures ? 1 : 0;
}
