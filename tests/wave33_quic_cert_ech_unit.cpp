#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

import std;
import capy;
import corosio;
import config;
import crypto;
import dns.local_config;
import hysteria2.auth;
import hysteria2.listener;
import hysteria2.transport_options;
import masque.bearer;
import masque.config;
import masque.listener;
import ngtcp2;
import quic.cid_registry;
import quic.connection;
import quic.ech_config;
import quic.server_early_data;
import quic.tls_client;
import quic.tls_server;
import tls.certificate_trust;
import tls.ech_server;
import tls.fingerprint;
import tls.hello;
import tls.server_credential;
import tuic.application;
import tuic.client;
import tuic.server;
import tuic.transport_options;
import tuic.wire;

namespace q = quic;
namespace n = ::ngtcp2;
namespace t = tls;
namespace io = ::corosio;
using Clock = std::chrono::steady_clock;

namespace {
    void require(bool cond, std::string_view msg) {
        if (!cond) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }
    template<class T, auto Free> struct SslPtr {
        T* p = nullptr;
        explicit SslPtr(T* ptr = nullptr) : p(ptr) {}
        ~SslPtr() { if (p) Free(p); }
        SslPtr(SslPtr const&) = delete; auto operator=(SslPtr const&) -> SslPtr& = delete;
        auto get() const noexcept -> T* { return p; }
    };
    auto to_bytes(std::string_view s) noexcept -> std::span<std::uint8_t const> { return {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()}; }
    auto put16(crypto::Bytes& out, std::size_t v) -> void { out.push_back(static_cast<std::uint8_t>(v >> 8)); out.push_back(static_cast<std::uint8_t>(v & 0xff)); }
    auto encode_b64(std::span<std::uint8_t const> d) -> std::string {
        static constexpr char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out; out.reserve(((d.size() + 2) / 3) * 4);
        for (std::size_t i = 0; i < d.size(); i += 3) {
            std::uint32_t v = std::uint32_t(d[i]) << 16 | (i + 1 < d.size() ? std::uint32_t(d[i + 1]) << 8 : 0) | (i + 2 < d.size() ? d[i + 2] : 0);
            out.push_back(tbl[(v >> 18) & 63]); out.push_back(tbl[(v >> 12) & 63]);
            out.push_back(i + 1 < d.size() ? tbl[(v >> 6) & 63] : '='); out.push_back(i + 2 < d.size() ? tbl[v & 63] : '=');
        }
        return out;
    }

    struct TestCert {
        std::string cert_pem, key_pem; crypto::Bytes cert_der; std::int64_t valid_time = 0;
        auto to_credential() const -> t::ServerCredential {
            auto cred = t::ServerCredential::create_file_contents(to_bytes(cert_pem), to_bytes(key_pem));
            require(cred.has_value(), "create ServerCredential"); return std::move(*cred);
        }
    };

    auto make_test_cert(std::string_view cn, std::string_view san_ext, long serial) -> TestCert {
        SslPtr<EC_KEY, EC_KEY_free> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        EC_KEY_generate_key(ec.get());
        SslPtr<EVP_PKEY, EVP_PKEY_free> pkey(EVP_PKEY_new());
        EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get());
        SslPtr<X509, X509_free> x(X509_new());
        X509_set_version(x.get(), 2); ASN1_INTEGER_set(X509_get_serialNumber(x.get()), serial);
        X509_gmtime_adj(X509_getm_notBefore(x.get()), -3600); X509_gmtime_adj(X509_getm_notAfter(x.get()), 86400 * 30);
        X509_set_pubkey(x.get(), pkey.get());
        X509_NAME* sub = X509_get_subject_name(x.get());
        X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC, reinterpret_cast<unsigned char const*>(cn.data()), static_cast<int>(cn.size()), -1, 0);
        X509_set_issuer_name(x.get(), sub);
        auto add_ext = [&](int nid, std::string val) {
            SslPtr<X509_EXTENSION, X509_EXTENSION_free> ext(X509V3_EXT_nconf_nid(nullptr, nullptr, nid, val.data()));
            X509_add_ext(x.get(), ext.get(), -1);
        };
        add_ext(NID_basic_constraints, "critical,CA:TRUE"); add_ext(NID_key_usage, "critical,digitalSignature,keyCertSign");
        add_ext(NID_ext_key_usage, "serverAuth"); add_ext(NID_subject_alt_name, std::string(san_ext));
        X509_sign(x.get(), pkey.get(), EVP_sha256());
        auto bio_str = [](BIO* b) -> std::string {
            BUF_MEM* m = nullptr; BIO_get_mem_ptr(b, &m);
            return (m && m->data && m->length) ? std::string(m->data, m->length) : std::string{};
        };
        SslPtr<BIO, BIO_free> cb(BIO_new(BIO_s_mem())), kb(BIO_new(BIO_s_mem()));
        PEM_write_bio_X509(cb.get(), x.get()); PEM_write_bio_PrivateKey(kb.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
        int dlen = i2d_X509(x.get(), nullptr);
        crypto::Bytes der(static_cast<std::size_t>(dlen));
        unsigned char* p = der.data(); i2d_X509(x.get(), &p);
        auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        return {bio_str(cb.get()), bio_str(kb.get()), std::move(der), now};
    }

    struct TestEchMaterial {
        std::array<std::uint8_t, 32> priv{};
        crypto::Bytes config_list_wire;
        q::EchConfig parsed;
        std::string key_file_text;
        std::shared_ptr<t::EchServerKeys const> server_keys;
    };

    auto make_ech_material(std::uint8_t id, std::uint16_t aead_id, std::string_view pub_name) -> TestEchMaterial {
        TestEchMaterial out; (void)crypto::random_bytes(out.priv);
        EVP_HPKE_KEY key; EVP_HPKE_KEY_zero(&key);
        EVP_HPKE_KEY_init(&key, EVP_hpke_x25519_hkdf_sha256(), out.priv.data(), out.priv.size());
        std::array<std::uint8_t, 32> pub{}; std::size_t pub_len = 0;
        EVP_HPKE_KEY_public_key(&key, pub.data(), &pub_len, pub.size());
        EVP_HPKE_KEY_cleanup(&key);
        crypto::Bytes contents{id};
        put16(contents, 0x0020); put16(contents, 32); contents.insert(contents.end(), pub.begin(), pub.end());
        put16(contents, 4); put16(contents, 0x0001); put16(contents, aead_id);
        contents.push_back(64); contents.push_back(static_cast<std::uint8_t>(pub_name.size()));
        contents.insert(contents.end(), pub_name.begin(), pub_name.end()); put16(contents, 0);
        crypto::Bytes cfg; put16(cfg, 0xfe0d); put16(cfg, contents.size());
        cfg.insert(cfg.end(), contents.begin(), contents.end());
        put16(out.config_list_wire, cfg.size()); out.config_list_wire.insert(out.config_list_wire.end(), cfg.begin(), cfg.end());
        auto parsed = q::select_ech_config(out.config_list_wire); require(parsed.has_value(), "parse ECHConfigList");
        out.parsed = std::move(*parsed);
        out.key_file_text = "PrivateKey: " + encode_b64(out.priv) + "\nEchConfigList: " + encode_b64(out.config_list_wire) + "\n";
        auto keys = t::parse_ech_server_keys(to_bytes(out.key_file_text)); require(keys.has_value(), "parse EchServerKeys");
        out.server_keys = std::move(*keys);
        return out;
    }

    struct QuicMem {
        static auto alloc(std::size_t sz, void*) noexcept -> void* { return std::malloc(std::max<std::size_t>(sz, 1)); }
        static auto free_fn(void* p, void*) noexcept -> void { std::free(p); }
        static auto zero(std::size_t c, std::size_t sz, void*) noexcept -> void* { return std::calloc(std::max<std::size_t>(c, 1), std::max<std::size_t>(sz, 1)); }
        static auto realloc_fn(void* p, std::size_t sz, void*) noexcept -> void* { return std::realloc(p, std::max<std::size_t>(sz, 1)); }
        auto callbacks() noexcept -> n::ngtcp2_mem { return {this, alloc, free_fn, zero, realloc_fn}; }
    };

    struct QuicPath {
        n::ngtcp2_sockaddr_in local{}, remote{};
        n::ngtcp2_path value{};
        explicit QuicPath(bool server) {
            local.sin_family = remote.sin_family = n::af_inet;
            auto port = [](unsigned v) { return std::bit_cast<std::uint16_t>(std::array<std::uint8_t, 2>{static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)}); };
            local.sin_port = port(server ? 443 : 12345); remote.sin_port = port(server ? 12345 : 443);
            local.sin_addr.s_addr = remote.sin_addr.s_addr = std::bit_cast<std::uint32_t>(std::array<std::uint8_t, 4>{127, 0, 0, 1});
            value = {{reinterpret_cast<n::ngtcp2_sockaddr*>(&local), sizeof(local)}, {reinterpret_cast<n::ngtcp2_sockaddr*>(&remote), sizeof(remote)}, nullptr};
        }
    };

    auto make_cid(std::array<std::uint8_t, 8> b) -> n::ngtcp2_cid { n::ngtcp2_cid out{}; n::ngtcp2_cid_init(&out, b.data(), b.size()); return out; }

    struct PkiVerify {
        std::span<std::uint8_t const> anchor; std::string_view name; std::int64_t time;
        auto operator()(std::span<std::span<std::uint8_t const> const> chain) const -> bool {
            std::array<std::span<std::uint8_t const>, 1> anchors{anchor};
            return t::verify_server_certificate_chain(chain, anchors, t::PeerNameKind::dns, to_bytes(name), time).has_value();
        }
    };

    template<class Tls> struct MiniApp {
        Tls& tls; unsigned completed = 0; crypto::Bytes rx;
        explicit MiniApp(Tls& v) : tls(v) {}
        template<class C> auto connection_closed(C&, int) noexcept -> void { tls.cancel(); }
        template<class C> auto handshake_complete(C&) -> int { if (!tls.complete()) return n::err_callback_failure; ++completed; return 0; }
        template<class C> auto handshake_confirmed(C&) -> int { return tls.complete() ? 0 : n::err_callback_failure; }
        template<class C> auto stream_data(C& c, std::uint32_t, std::int64_t id, std::uint64_t, std::span<std::uint8_t const> in, void*) -> int {
            rx.insert(rx.end(), in.begin(), in.end());
            (void)n::ngtcp2_conn_extend_max_stream_offset(c.native(), id, in.size());
            (void)n::ngtcp2_conn_extend_max_offset(c.native(), in.size()); return 0;
        }
        template<class... A> auto stream_acked(A&&...) -> int { return 0; } template<class... A> auto stream_close(A&&...) -> int { return 0; }
        template<class... A> auto stream_reset(A&&...) -> int { return 0; } template<class... A> auto stop_sending(A&&...) -> int { return 0; }
        template<class... A> auto stream_limit(A&&...) -> int { return 0; } template<class... A> auto datagram(A&&...) -> int { return 0; }
        template<class... A> auto add_connection_id(A&&...) -> int { return 0; } template<class... A> auto remove_connection_id(A&&...) -> int { return 0; }
    };

    auto make_client_hello(std::string_view sni, std::uint16_t suite, bool grease_ech = false, std::uint8_t grease_id = 99) -> t::ClientHello {
        t::ClientHello ch; (void)crypto::random_bytes(ch.random); ch.cipher_suites = {suite}; ch.compression_methods = {0};
        crypto::Bytes sni_ext; put16(sni_ext, sni.size() + 3); sni_ext.push_back(0); put16(sni_ext, sni.size());
        sni_ext.insert(sni_ext.end(), sni.begin(), sni.end());
        ch.extensions = {{0, std::move(sni_ext)}, {43, {2, 3, 4}}, {10, {0, 2, 0, 29}}, {13, {0, 2, 0x04, 0x03}}, {51, {0, 0}}, {16, {0, 3, 2, 'h', '3'}}};
        if (grease_ech) {
            crypto::Bytes ext{0, 0, 1, 0, 1, grease_id, 0, 32}; std::array<std::uint8_t, 32> enc{}; (void)crypto::random_bytes(enc);
            ext.insert(ext.end(), enc.begin(), enc.end()); put16(ext, 48); ext.resize(ext.size() + 48, 0x5a);
            ch.extensions.push_back({0xfe0d, std::move(ext)});
        }
        return ch;
    }

    struct HandshakeResult { int rc = 0; bool ech_accepted = false, ech_rejected = false; std::string sni; crypto::Bytes retry_configs; };
    template<class ClientTls, class ServerTls>
    auto run_quic_handshake(ClientTls& client_tls, ServerTls& server_tls, std::string_view stream_payload = {}) -> HandshakeResult {
        auto finish = [&](int code) -> HandshakeResult {
            auto rv = client_tls.ech_retry_configs();
            return {code, server_tls.ech_accepted(), server_tls.ech_rejected(), std::string(server_tls.negotiated_sni()), {rv.begin(), rv.end()}};
        };
        QuicMem cm, sm; QuicPath cp(false), sp(true);
        MiniApp<ClientTls> capp(client_tls); MiniApp<ServerTls> sapp(server_tls);
        q::Connection client(client_tls, capp); q::Connection server(server_tls, sapp);
        n::ngtcp2_settings st{}; n::ngtcp2_settings_default_versioned(n::settings_version, &st);
        st.initial_ts = 1; st.handshake_timeout = 10 * n::seconds;
        auto mk_tp = [](bool srv) {
            n::ngtcp2_transport_params p{}; n::ngtcp2_transport_params_default_versioned(n::transport_params_version, &p);
            p.initial_max_data = 65536; p.initial_max_stream_data_bidi_local = p.initial_max_stream_data_bidi_remote = p.initial_max_stream_data_uni = 4096;
            p.initial_max_streams_bidi = 16; p.initial_max_streams_uni = 3; p.disable_active_migration = 1;
            if (srv) { p.original_dcid = make_cid({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}); p.original_dcid_present = 1; }
            return p;
        };
        auto id0 = make_cid({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});
        auto cid = make_cid({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        auto sid = make_cid({0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5});
        if (client.start(false, id0, cid, cp.value, st, mk_tp(false), cm.callbacks())) return finish(-1);
        if (server.start(true, cid, sid, sp.value, st, mk_tp(true), sm.callbacks())) return finish(-2);
        std::uint64_t now = 2;
        auto step = [&](auto& tx, auto& rx, QuicPath& dst) -> int {
            std::array<std::uint8_t, 1500> buf{};
            auto w = tx.write_packet(buf, nullptr, nullptr, now += 1000000);
            if (!w) return w.error();
            return *w ? rx.read(dst.value, nullptr, std::span(buf).first(*w), now += 1000000) : 0;
        };
        auto tick_expiry = [&]() -> int {
            for (auto* c : {client.native(), server.native()})
                if (n::ngtcp2_conn_get_expiry2(c) <= now) if (int e = n::ngtcp2_conn_handle_expiry(c, now)) return e;
            return 0;
        };
        for (unsigned r = 0; r < 600 && (!client_tls.complete() || !server_tls.complete() || !capp.completed || !sapp.completed); ++r) {
            if (int e = step(client, server, sp)) return finish(e);
            if (int e = step(server, client, cp)) return finish(e);
            if (int e = tick_expiry()) return finish(e);
        }
        if (!client_tls.complete() || !server_tls.complete()) return finish(-3);
        if (!stream_payload.empty()) {
            std::int64_t strm = -1;
            if (n::ngtcp2_conn_open_bidi_stream(client.native(), &strm, nullptr)) return finish(-4);
            std::size_t off = 0; bool fin = false;
            for (unsigned r = 0; r < 100 && sapp.rx.size() < stream_payload.size(); ++r) {
                if (!fin) {
                    std::array<std::uint8_t, 1500> out{};
                    n::ngtcp2_vec v{const_cast<std::uint8_t*>(reinterpret_cast<std::uint8_t const*>(stream_payload.data() + off)), stream_payload.size() - off};
                    auto wr = client.write_stream(out, nullptr, nullptr, strm, std::span(&v, 1), true, now += 1000000);
                    if (!wr) return finish(-5);
                    if (wr->stream_bytes >= 0) { off += static_cast<std::size_t>(wr->stream_bytes); fin = (off == stream_payload.size()); }
                    if (wr->packet_bytes) if (int e = server.read(sp.value, nullptr, std::span(out).first(wr->packet_bytes), now += 1000000)) return finish(e);
                }
                if (int e = step(client, server, sp)) return finish(e);
                if (int e = step(server, client, cp)) return finish(e);
                if (int e = tick_expiry()) return finish(e);
            }
            if (std::string_view(reinterpret_cast<char const*>(sapp.rx.data()), sapp.rx.size()) != stream_payload) return finish(-6);
        }
        return finish(0);
    }

    void test_quic_kdl_validation() {
        auto parsed = config::parse_kdl(R"kdl(schema-version 1; role "server"
services { acme directory-url="https://acme.example/dir" email="a@b.c" state-dir="/tmp/acme" { domain "hy2.example" } }
inbounds {
    inbound "h-acme" type="hysteria2" { listen host="127.0.0.1" port=8443; authentication { user "u" password-file="/tmp/p" }; tls { certificate-provider "acme"; ech-key-file "/tmp/ech.key" } }
    inbound "h-reload" type="hysteria2" { listen host="127.0.0.1" port=8444; authentication { user "u" password-file="/tmp/p" }; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; cert-hot-reload #true; ech-key-file "/tmp/ech.key" } }
    inbound "t-acme" type="tuic" { listen host="127.0.0.1" port=8445; authentication { user "u" uuid-file="/tmp/u" password-file="/tmp/p" }; tls { certificate-provider "acme"; ech-key-file "/tmp/ech.key" } }
    inbound "t-reload" type="tuic" { listen host="127.0.0.1" port=8446; authentication { user "u" uuid-file="/tmp/u" password-file="/tmp/p" }; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; cert-hot-reload #true } }
}
outbounds { outbound "direct" type="direct" }; routing { final "direct" })kdl");
        if (!parsed) std::cerr << "hy2/tuic KDL err: " << parsed.error() << '\n';
        require(parsed.has_value() && parsed->inbounds.size() == 4, "parse KDL with Hy2/TUIC acme/reload/ech");
        require(parsed->inbounds[0].hysteria2->certificate_provider == "acme" && parsed->inbounds[0].hysteria2->ech_key_file == "/tmp/ech.key", "hy2 acme+ech");
        require(parsed->inbounds[1].hysteria2->cert_hot_reload && parsed->inbounds[2].tuic->certificate_provider == "acme", "hy2 reload & tuic acme");
        require(parsed->inbounds[2].tuic->ech_key_file == "/tmp/ech.key" && parsed->inbounds[3].tuic->cert_hot_reload, "tuic ech & reload");

        auto m_acme = config::parse_kdl(R"kdl(schema-version 1; role "server"
services { acme directory-url="https://acme.example/dir" email="a@b.c" state-dir="/tmp/acme" { domain "m.example" } }
inbounds { inbound "m-acme" type="masque" { listen host="127.0.0.1" port=8447; authority "m.example"; authentication { bearer-file "/tmp/b" }; allow cidr="192.0.2.0/24" first-port=1 last-port=65535; tls { certificate-provider "acme"; ech-key-file "/tmp/ech.key" } } }
outbounds { outbound "direct" type="direct" }; routing { final "direct" })kdl");
        if (!m_acme) std::cerr << "masque acme err: " << m_acme.error() << '\n';
        require(m_acme.has_value() && m_acme->inbounds[0].masque->certificate_provider == "acme" && m_acme->inbounds[0].masque->ech_key_file == "/tmp/ech.key", "masque acme+ech");

        auto m_reload = config::parse_kdl(R"kdl(schema-version 1; role "server"
inbounds { inbound "m-reload" type="masque" { listen host="127.0.0.1" port=8448; authority "m2.example"; authentication { bearer-file "/tmp/b" }; allow cidr="192.0.2.0/24" first-port=1 last-port=65535; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; cert-hot-reload #true } } }
outbounds { outbound "direct" type="direct" }; routing { final "direct" })kdl");
        if (!m_reload) std::cerr << "masque reload err: " << m_reload.error() << '\n';
        require(m_reload.has_value() && m_reload->inbounds[0].masque->cert_hot_reload, "masque reload");

        constexpr std::array<std::string_view, 4> invalid_kdl{{
            R"kdl(schema-version 1; role "server"; inbounds { inbound "h" type="hysteria2" { listen host="127.0.0.1" port=8443; authentication { user "u" password-file="/tmp/p" }; tls { certificate-provider "acme" } } }; outbounds { outbound "direct" type="direct" }; routing { final "direct" })kdl",
            R"kdl(schema-version 1; role "server"; inbounds { inbound "t" type="tuic" { listen host="127.0.0.1" port=8444; authentication { user "u" uuid-file="/tmp/u" password-file="/tmp/p" }; tls { certificate-provider "acme" } } }; outbounds { outbound "direct" type="direct" }; routing { final "direct" })kdl",
            R"kdl(schema-version 1; role "server"; inbounds { inbound "m" type="masque" { listen host="127.0.0.1" port=8445; authority "m.test"; authentication { bearer-file "/tmp/b" }; allow cidr="192.0.2.0/24" first-port=1 last-port=65535; tls { certificate-provider "acme" } } }; outbounds { outbound "direct" type="direct" }; routing { final "direct" })kdl",
            R"kdl(schema-version 1; role "server"; inbounds { inbound "t" type="tuic" { listen host="127.0.0.1" port=8444; authentication { user "u" uuid-file="/tmp/u" password-file="/tmp/p" }; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; alpn "h3" } } }; outbounds { outbound "direct" type="direct" }; routing { final "direct" })kdl",
        }};
        for (auto doc : invalid_kdl) require(!config::parse_kdl(doc).has_value(), "reject invalid QUIC TLS KDL");
    }

    struct TuicLiveHooks {
        capy::async_event ev; std::size_t auth_count = 0;
        void authenticated(quic::SessionHandle, std::size_t) { ++auth_count; ev.set(); }
        void connect_stream(quic::SessionHandle, tuic::StreamHandle, tuic::TargetAddress const&) {}
        void udp_packet(quic::SessionHandle, tuic::IncomingUdpPacket) {}
        void udp_dissociate(quic::SessionHandle, std::uint16_t) {}
        void transport_closed(quic::SessionHandle) noexcept { ev.set(); }
        bool session_drained(quic::SessionHandle) const noexcept { return true; }
        void session_destroyed(quic::SessionHandle) noexcept {}
    };

    struct Hy2StubHooks {
        auto authenticate(hysteria2::ClientAuthView) noexcept -> std::optional<std::size_t> { return 0; }
        auto datagram(quic::SessionHandle, std::span<std::uint8_t const>) noexcept -> int { return 0; }
        auto serve(auto&) -> capy::task<> { co_return; }
    };

    void test_quic_live_cert_hot_reload() {
        auto cert_a = make_test_cert("first.quic.test", "DNS:first.quic.test", 101);
        auto cert_b = make_test_cert("second.quic.test", "DNS:second.quic.test", 202);
        auto atomic = std::make_shared<t::AtomicServerCredential>();
        require(atomic->update(cert_a.to_credential()) == 1, "gen 1");
        {
            q::TlsClient<PkiVerify> c(make_client_hello("first.quic.test", 0x1301), 29, PkiVerify{cert_a.cert_der, "first.quic.test", cert_a.valid_time}, "h3");
            q::TlsServer s(atomic, "h3");
            require(run_quic_handshake(c, s, "hello-a").rc == 0, "TlsServer Cert A");
        }
        require(atomic->update(cert_b.to_credential()) == 2, "gen 2");
        {
            q::TlsClient<PkiVerify> c_old(make_client_hello("first.quic.test", 0x1301), 29, PkiVerify{cert_a.cert_der, "first.quic.test", cert_a.valid_time}, "h3");
            q::TlsServer s(atomic, "h3");
            require(run_quic_handshake(c_old, s).rc != 0 && c_old.alert() == 42, "old Cert A trust rejected after swap");
        }
        {
            q::TlsClient<PkiVerify> c_b(make_client_hello("second.quic.test", 0x1301), 29, PkiVerify{cert_b.cert_der, "second.quic.test", cert_b.valid_time}, "h3");
            q::TlsServer s(atomic, "h3");
            require(run_quic_handshake(c_b, s, "hello-b").rc == 0, "TlsServer Cert B");
        }
        {
            q::EarlyDataTicketStore<8> store;
            auto ed_b = q::EarlyDataTlsServer<q::EarlyDataTicketStore<8>>::create(atomic, "h3", store, true);
            require(ed_b.has_value(), "EarlyDataTlsServer Cert B");
            q::TlsClient<PkiVerify> c_b(make_client_hello("second.quic.test", 0x1301), 29, PkiVerify{cert_b.cert_der, "second.quic.test", cert_b.valid_time}, "h3");
            require(run_quic_handshake(c_b, **ed_b, "ed-b").rc == 0, "EarlyDataTlsServer handshake Cert B");
            require(atomic->update(cert_a.to_credential()) == 3, "gen 3");
            auto ed_a = q::EarlyDataTlsServer<q::EarlyDataTicketStore<8>>::create(atomic, "h3", store, true);
            require(ed_a.has_value(), "EarlyDataTlsServer Cert A");
            q::TlsClient<PkiVerify> c_a(make_client_hello("first.quic.test", 0x1301), 29, PkiVerify{cert_a.cert_der, "first.quic.test", cert_a.valid_time}, "h3");
            require(run_quic_handshake(c_a, **ed_a, "ed-a").rc == 0, "EarlyDataTlsServer handshake Cert A");
        }
        {
            auto ech = make_ech_material(5, 1, "outer.public.example");
            io::io_context ctx; Hy2StubHooks hy2_hooks;
            hysteria2::Listener<Hy2StubHooks, 4, 4> hy2_l(ctx, hy2_hooks, atomic, hysteria2::TransportOptions{}, ech.server_keys);
            require(hy2_l.prepare({io::ipv4_address::loopback(), 0}).has_value(), "hysteria2::Listener prepare(atomic, ech)");
            hy2_l.stop();
            auto bearer = masque::BearerCredential::create(to_bytes("test-bearer-token")); require(bearer.has_value(), "MASQUE bearer");
            masque::DestinationRule rule{}; rule.network.family = 4; rule.network.address[0] = 192; rule.network.address[1] = 0; rule.network.address[2] = 2; rule.prefix = 24; rule.first_port = 1; rule.last_port = 65535;
            masque::HostConfig mcfg("m.test", std::move(*bearer), {rule});
            masque::Listener<4, 4> masque_l(ctx, mcfg, atomic, dns::system_local_snapshots(), nullptr, nullptr, ech.server_keys);
            require(masque_l.prepare({io::ipv4_address::loopback(), 0}).has_value(), "masque::Listener prepare(atomic, ech)");
            masque_l.stop();
            dns::stop_system_local_snapshots();
        }
        // Live loopback tuic::Listener serves Cert A then hot-swaps to Cert B WITHOUT restarting!
        auto tmp_dir = std::filesystem::temp_directory_path() / ("nexus-w33-quic-" + std::to_string(static_cast<unsigned long>(::getpid())));
        std::filesystem::create_directories(tmp_dir);
        struct Cleanup { std::filesystem::path p; ~Cleanup() { std::error_code ec; std::filesystem::remove_all(p, ec); } } clean{tmp_dir};
        auto write_f = [&](std::string const& name, std::string_view data, bool priv = false) -> std::string {
            auto p = (tmp_dir / name).string(); std::ofstream(p, std::ios::binary).write(data.data(), static_cast<std::streamsize>(data.size()));
            if (priv) std::filesystem::permissions(p, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace);
            return p;
        };
        auto ca_a = write_f("a.pem", cert_a.cert_pem), ca_b = write_f("b.pem", cert_b.cert_pem);
        auto uuid_f = write_f("uuid", "b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f\n", true), pass_f = write_f("pass", "w33-secret\n", true);
        auto uuid = tuic::parse_uuid("b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f"); require(uuid.has_value(), "TUIC UUID");
        std::array<tuic::UserCredential, 1> users{tuic::UserCredential{*uuid, "w33-secret", "u1"}};
        io::io_context ctx; TuicLiveHooks hooks;
        tuic::Listener<TuicLiveHooks> listener(ctx, atomic, users, tuic::ClientTransportOptions{}, hooks);
        auto bound = listener.prepare({io::ipv4_address::loopback(), 0}); require(bound.has_value(), "bind TUIC listener");
        listener.start();
        bool ok = false;
        auto run_live = [&]() -> capy::task<> {
            struct Guard { tuic::Listener<TuicLiveHooks>& l; ~Guard() { l.stop(); } } g{listener};
            auto connect_expect = [&](std::string_view host, std::string const& ca, std::size_t expect_auth) -> capy::task<bool> {
                auto prof = tuic::ClientProfile::load(host, ca, uuid_f, pass_f, 0x001d, false, tuic::ClientTransportOptions{}, t::Fingerprint::native);
                if (!prof) co_return false;
                tuic::Client<> cli(ctx, **prof);
                if (!cli.start(*bound)) co_return false;
                bool ready = false;
                auto ops = [&]() -> capy::task<capy::results<>> {
                    struct F { tuic::Client<>& c; ~F() { c.finish(); } } f{cli};
                    auto dl = Clock::now() + std::chrono::seconds(4);
                    ready = co_await cli.ready(dl);
                    while (ready && hooks.auth_count < expect_auth && Clock::now() < dl) {
                        hooks.ev.clear();
                        auto [ec] = co_await io::timeout(hooks.ev.wait(), dl);
                        if (ec) break;
                    }
                    co_return capy::results<>{};
                };
                (void)co_await capy::when_all(cli.run(), ops());
                co_return ready && hooks.auth_count >= expect_auth;
            };
            bool r1 = co_await connect_expect("first.quic.test", ca_a, 1);
            (void)atomic->update(cert_b.to_credential()); // Live hot-swap with ZERO listener restart!
            bool r2 = co_await connect_expect("second.quic.test", ca_b, 2);
            ok = r1 && r2 && hooks.auth_count == 2;
        };
        capy::run_async(ctx.get_executor())(listener.run());
        capy::run_async(ctx.get_executor())(run_live());
        ctx.run_for(std::chrono::seconds(10));
        listener.stop(); ctx.restart(); ctx.run_for(std::chrono::milliseconds(100));
        require(ok, "live TUIC listener hot-swapped Cert A -> Cert B without restart");
    }

    void test_quic_server_ech() {
        auto inner_cert = make_test_cert("inner.secret.example", "DNS:inner.secret.example", 303);
        auto outer_cert = make_test_cert("outer.public.example", "DNS:outer.public.example", 404);
        auto inner_cred = inner_cert.to_credential(), outer_cred = outer_cert.to_credential();
        auto ech_aes = make_ech_material(7, 1, "outer.public.example"), ech_chacha = make_ech_material(9, 3, "outer.public.example"), ech_stale = make_ech_material(99, 1, "outer.public.example");
        auto tmp_ech = std::filesystem::temp_directory_path() / ("nexus-w33-ech-" + std::to_string(static_cast<unsigned long>(::getpid())) + ".key");
        std::ofstream(tmp_ech, std::ios::binary).write(ech_aes.key_file_text.data(), static_cast<std::streamsize>(ech_aes.key_file_text.size()));
#if !defined(_WIN32)
        ::chmod(tmp_ech.c_str(), 0600);
#endif
        struct Rm { std::filesystem::path p; ~Rm() { std::error_code ec; std::filesystem::remove(p, ec); } } rm{tmp_ech};
        auto loaded_keys = t::load_ech_server_keys_file(tmp_ech.string()); require(loaded_keys.has_value(), "load_ech_server_keys_file(0600)");

        for (auto const* mat : {&ech_aes, &ech_chacha}) {
            q::TlsClient<PkiVerify> cli(make_client_hello("inner.secret.example", 0x1301), 29, PkiVerify{inner_cert.cert_der, "inner.secret.example", inner_cert.valid_time}, "h3");
            require(cli.enable_ech(mat->parsed), "enable QUIC ECH");
            q::TlsServer srv(inner_cred, "h3", mat->server_keys);
            auto r = run_quic_handshake(cli, srv, "ech-quic-1rtt");
            require(r.rc == 0 && r.ech_accepted && !r.ech_rejected && r.sni == "inner.secret.example", "QUIC 1-RTT ECH accepted + inner SNI");
        }
        {
            q::TlsClient<PkiVerify> cli(make_client_hello("inner.secret.example", 0x1303), 0, PkiVerify{inner_cert.cert_der, "inner.secret.example", inner_cert.valid_time}, "h3");
            require(cli.enable_ech(ech_aes.parsed), "enable QUIC ECH HRR");
            q::TlsServer srv(inner_cred, "h3", *loaded_keys);
            auto r = run_quic_handshake(cli, srv, "ech-quic-hrr");
            require(r.rc == 0 && r.ech_accepted && r.sni == "inner.secret.example", "QUIC HRR ECH accepted + inner SNI");
        }
        {
            q::TlsClient<PkiVerify> cli(make_client_hello("inner.secret.example", 0x1301), 29, PkiVerify{inner_cert.cert_der, "inner.secret.example", inner_cert.valid_time}, "h3");
            require(cli.enable_ech(ech_stale.parsed), "enable stale ECH");
            q::TlsServer srv(outer_cred, "h3", ech_aes.server_keys);
            auto r = run_quic_handshake(cli, srv);
            require(r.rc != 0 && cli.alert() == 121 && !r.ech_accepted, "strict stale ECH -> alert 121");
        }
        {
            q::TlsClient<PkiVerify> cli(make_client_hello("outer.public.example", 0x1301, true, 99), 29, PkiVerify{outer_cert.cert_der, "outer.public.example", outer_cert.valid_time}, "h3");
            q::TlsServer srv(outer_cred, "h3", ech_aes.server_keys);
            auto r = run_quic_handshake(cli, srv, "grease-retry-ok");
            require(r.rc == 0 && !r.ech_accepted && r.ech_rejected && r.sni == "outer.public.example", "outer SNI + rejected_offered");
            require(std::ranges::equal(r.retry_configs, ech_aes.server_keys->retry_configs_wire()), "exact retry_configs received");
        }
        {
            q::EarlyDataTicketStore<8> store;
            auto srv1 = q::EarlyDataTlsServer<q::EarlyDataTicketStore<8>>::create(inner_cred, "h3", store, true, {}, ech_aes.server_keys);
            require(srv1.has_value(), "EarlyDataTlsServer ECH create");
            q::TlsClient<PkiVerify> cli1(make_client_hello("inner.secret.example", 0x1301), 0, PkiVerify{inner_cert.cert_der, "inner.secret.example", inner_cert.valid_time}, "h3");
            require(cli1.enable_ech(ech_aes.parsed), "enable ECH for EarlyDataTlsServer HRR");
            auto r1 = run_quic_handshake(cli1, **srv1, "tuic-ech-hrr");
            require(r1.rc == 0 && r1.ech_accepted && r1.sni == "inner.secret.example", "EarlyDataTlsServer ECH + HRR");
            auto srv2 = q::EarlyDataTlsServer<q::EarlyDataTicketStore<8>>::create(outer_cred, "h3", store, true, {}, ech_aes.server_keys);
            require(srv2.has_value(), "EarlyDataTlsServer fallback create");
            q::TlsClient<PkiVerify> cli2(make_client_hello("outer.public.example", 0x1301, true, 99), 29, PkiVerify{outer_cert.cert_der, "outer.public.example", outer_cert.valid_time}, "h3");
            auto r2 = run_quic_handshake(cli2, **srv2, "tuic-ech-fallback");
            require(r2.rc == 0 && !r2.ech_accepted && r2.ech_rejected && std::ranges::equal(r2.retry_configs, ech_aes.server_keys->retry_configs_wire()), "EarlyDataTlsServer ECH fallback + retry_configs");
        }
    }
}

int main() {
    test_quic_kdl_validation();
    test_quic_live_cert_hot_reload();
    test_quic_server_ech();
    std::println("wave33_quic_cert_ech_unit: PASS");
    return 0;
}
