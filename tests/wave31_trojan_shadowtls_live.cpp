#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>
import std;
import capy;
import corosio;
import config;
import crypto;
import relay;
import shadowtls.v3;
import shadowtls.stream;
import tls.profiles;
import tls.fingerprint;
import tls.server_credential;
import tls.server_handshake_io;
import tls.corosio_server_handshake;
import tls.client_handshake_io;
import tls.corosio_client;
import tls.corosio_application;
import tls.byte_stream;
import trojan;
import trojan.auth;

namespace io = ::corosio;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {
    struct TempDir {
        fs::path path;
        ~TempDir() { if (!path.empty()) { std::error_code ec; fs::remove_all(path, ec); } }
    };

    auto make_temp_dir(std::string_view prefix) -> TempDir {
        auto dir = fs::temp_directory_path() /
            (std::string(prefix) + "-" + std::to_string(Clock::now().time_since_epoch().count()));
        fs::create_directories(dir);
        return TempDir{dir};
    }

    auto write_private(fs::path const& file, std::string_view content) -> bool {
        {
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            if (!out) return false;
            out.write(content.data(), static_cast<std::streamsize>(content.size()));
        }
        std::error_code ec;
        fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
        return !ec;
    }

    auto make_cert(fs::path const& cert, fs::path const& key, std::string_view cn, std::string_view san) -> bool {
        auto cmd = std::format(
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
            "-keyout '{}' -out '{}' -subj '/CN={}' -addext 'subjectAltName={}' -days 1 >/dev/null 2>&1",
            key.string(), cert.string(), cn, san);
        if (std::system(cmd.c_str()) != 0) return false;
        std::error_code ec;
        fs::permissions(key, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
        return !ec;
    }

    auto read_bytes(fs::path const& file) -> crypto::Bytes {
        std::ifstream f(file, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), {}};
    }

    auto now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
    }

    auto as_u8(std::string_view s) noexcept -> std::span<std::uint8_t const> {
        return {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()};
    }

    auto test_trojan_fallback() -> int {
        auto tmp = make_temp_dir("nexus-w31-trojan");
        auto cert_path = tmp.path / "cert.pem";
        auto key_path = tmp.path / "key.pem";
        auto pass_path = tmp.path / "alice.pass";
        if (!make_cert(cert_path, key_path, "localhost", "DNS:localhost,IP:127.0.0.1")) return 10;
        if (!write_private(pass_path, "trojan-secret-pass")) return 11;
        auto valid_key = trojan::PasswordKey::load(pass_path.string());
        if (!valid_key) return 12;

        auto shared = relay::make_shared_io_context();
        if (!shared) return 13;
        auto& ctx = **shared;

        io::tcp_acceptor decoy_def(ctx), decoy_h2(ctx), real_echo(ctx);
        if (decoy_def.open(io::family::v4) || decoy_def.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || decoy_def.listen(8))
            return 14;
        if (decoy_h2.open(io::family::v4) || decoy_h2.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || decoy_h2.listen(8))
            return 15;
        if (real_echo.open(io::family::v4) || real_echo.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || real_echo.listen(8))
            return 16;
        auto const def_port = decoy_def.local_endpoint().port();
        auto const h2_port = decoy_h2.local_endpoint().port();
        auto const echo_port = real_echo.local_endpoint().port();

        auto srv = relay::Server::create_shared(ctx);
        if (!srv) return 17;
        std::array<std::string, 1> pass_files{pass_path.string()};
        std::array<std::string, 1> names{"alice"};
        std::array<std::pair<std::string, config::FallbackTarget>, 1> alpn_fb{{{"h2", {"127.0.0.1", h2_port}}}};
        if (auto ok = (*srv)->prepare_trojan_inbound(
                cert_path.string(), key_path.string(), pass_files, names, {}, {}, {},
                config::FallbackTarget{"127.0.0.1", def_port}, alpn_fb); !ok) {
            std::println("prepare_trojan_inbound failed: {}", ok.error());
            return 18;
        }
        auto trojan_port = (*srv)->start(0, relay::Inbound::trojan, 1, false);
        if (!trojan_port) return 19;

        auto serve_prefix_echo = [](io::tcp_acceptor& acc, std::string prefix, int count) -> capy::task<> {
            for (int i = 0; i < count; ++i) {
                auto [ec, peer] = co_await acc.accept();
                if (ec) break;
                std::array<char, 2048> buf{};
                auto [re, n] = co_await peer.read_some(capy::mutable_buffer(buf.data(), buf.size()));
                if (!re && n) {
                    std::string reply = prefix;
                    reply.append(buf.data(), n);
                    (void)co_await peer.write_some(capy::const_buffer(reply.data(), reply.size()));
                }
                (void)peer.shutdown(io::shutdown_send);
                peer.close();
            }
            acc.close();
        };

        auto tls_exchange = [&](std::span<std::string_view const> alpn, std::span<std::uint8_t const> send_bytes,
                                std::string& got_out) -> capy::task<bool> {
            auto vtime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto prof = tls::ClientProfile::load("localhost", cert_path.string(), 0x001d, false, alpn);
            if (!prof) co_return false;
            io::tcp_socket cli(ctx);
            auto dl = Clock::now() + std::chrono::seconds(5);
            if (cli.open(io::family::v4)) co_return false;
            auto [ce] = co_await io::timeout(cli.connect(io::endpoint(io::ipv4_address::loopback(), *trojan_port)), dl);
            if (ce) co_return false;
            auto hs = prof->handshake(now_ms(), now_ms() + 5000, vtime);
            if (!hs) co_return false;
            auto res = co_await tls::detail::corosio_handshake(cli, *hs);
            if (!res) co_return false;
            tls::detail::ApplicationConnection<io::tcp_socket> app(cli, std::move(res->records), std::move(res->unread));
            tls::detail::ByteStream<io::tcp_socket> stream(app);
            if (!co_await stream.send(send_bytes, dl)) co_return false;
            std::array<std::uint8_t, 2048> rx{};
            got_out.clear();
            for (;;) {
                auto r = co_await stream.read(rx, dl);
                if (!r) co_return false;
                if (!*r) break;
                got_out.append(reinterpret_cast<char const*>(rx.data()), *r);
            }
            cli.close();
            co_return true;
        };

        int err = 0;
        auto run_clients = [&]() -> capy::task<> {
            // 1. Short HTTP/1.1 active probe (<58 bytes, no ALPN) -> default decoy, zero bytes lost.
            std::string reply;
            std::string_view http1 = "GET /probe?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
            if (!co_await tls_exchange({}, as_u8(http1), reply) || reply != std::string("DEFAULT-DECOY:") + std::string(http1)) {
                err = 20; co_return;
            }
            // 2. HTTP/2 active probe (negotiated ALPN "h2") -> fallback-for-alpn["h2"], zero bytes lost.
            std::array<std::string_view, 1> h2_alpn{"h2"};
            std::string_view h2_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            if (!co_await tls_exchange(h2_alpn, as_u8(h2_preface), reply) || reply != std::string("H2-DECOY:") + std::string(h2_preface)) {
                err = 21; co_return;
            }
            // 3. Wrong-password syntactically valid Trojan request -> default decoy with exact replay.
            trojan::Key wrong_key;
            std::ranges::fill(wrong_key, std::uint8_t{'f'});
            trojan::Address dest{trojan::Family::ipv4, {127, 0, 0, 1}, 4, echo_port};
            auto wrong_wire = trojan::encode_request(wrong_key, {trojan::Command::tcp, dest});
            if (!wrong_wire) { err = 22; co_return; }
            std::string_view tail = "WRONG-PASS-TAIL";
            wrong_wire->insert(wrong_wire->end(), tail.begin(), tail.end());
            std::string expected_wrong = "DEFAULT-DECOY:";
            expected_wrong.append(reinterpret_cast<char const*>(wrong_wire->data()), wrong_wire->size());
            if (!co_await tls_exchange({}, *wrong_wire, reply) || reply != expected_wrong) {
                err = 23; co_return;
            }
            // 4. Legitimate Trojan client with coalesced payload -> proxied to real_echo, zero bytes lost.
            auto good_wire = trojan::encode_request(valid_key->view(), {trojan::Command::tcp, dest});
            if (!good_wire) { err = 24; co_return; }
            std::string_view payload = "VALID-TROJAN-COALESCED-PAYLOAD";
            good_wire->insert(good_wire->end(), payload.begin(), payload.end());
            if (!co_await tls_exchange({}, *good_wire, reply) || reply != std::string("REAL-ECHO:") + std::string(payload)) {
                err = 25; co_return;
            }
        };

        bool done = false;
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(serve_prefix_echo(decoy_def, "DEFAULT-DECOY:", 2));
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(serve_prefix_echo(decoy_h2, "H2-DECOY:", 1));
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(serve_prefix_echo(real_echo, "REAL-ECHO:", 1));
        capy::run_async(ctx.get_executor(), [&] { done = true; }, [&](std::exception_ptr) noexcept { err = 26; done = true; })(run_clients());
        for (int i = 0; i < 400 && !done; ++i) (void)ctx.run_for(std::chrono::milliseconds(10));
        (*srv)->stop();
        if (!done) return 27;
        return err;
    }

    auto test_shadowtls_sni_routing() -> int {
        auto tmp = make_temp_dir("nexus-w31-stls");
        auto def_cert = tmp.path / "def.pem", def_key = tmp.path / "def.key";
        auto alt_cert = tmp.path / "alt.pem", alt_key = tmp.path / "alt.key";
        auto pass_path = tmp.path / "u1.pass";
        if (!make_cert(def_cert, def_key, "default.test", "DNS:default.test,DNS:evil.local")) return 30;
        if (!make_cert(alt_cert, alt_key, "alt.example", "DNS:alt.example")) return 31;
        if (!write_private(pass_path, "stls-sni-secret")) return 32;

        auto load_cred = [](fs::path const& c, fs::path const& k) {
            auto cb = read_bytes(c); auto kb = read_bytes(k);
            auto cred = tls::ServerCredential::create_file_contents(cb, kb);
            crypto::cleanse(kb);
            return cred;
        };
        auto cred_def = load_cred(def_cert, def_key);
        auto cred_alt = load_cred(alt_cert, alt_key);
        if (!cred_def || !cred_alt) return 33;

        auto shared = relay::make_shared_io_context();
        if (!shared) return 34;
        auto& ctx = **shared;

        io::tcp_acceptor cover_def(ctx), cover_alt(ctx), target_echo(ctx);
        if (cover_def.open(io::family::v4) || cover_def.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || cover_def.listen(8))
            return 35;
        if (cover_alt.open(io::family::v4) || cover_alt.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || cover_alt.listen(8))
            return 36;
        if (target_echo.open(io::family::v4) || target_echo.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || target_echo.listen(8))
            return 37;
        auto const def_port = cover_def.local_endpoint().port();
        auto const alt_port = cover_alt.local_endpoint().port();
        auto const tgt_port = target_echo.local_endpoint().port();

        auto srv = relay::Server::create_shared(ctx);
        if (!srv) return 38;
        std::array<std::string, 1> pass_files{pass_path.string()};
        std::array<std::string, 1> names{"u1"};
        std::array<std::pair<std::string, config::FallbackTarget>, 1> sni_map{{{"alt.example", {"127.0.0.1", alt_port}}}};
        if (auto ok = (*srv)->prepare_shadowtls_inbound(
                "127.0.0.1", def_port, "127.0.0.1", tgt_port, pass_files, names, true, sni_map, "all"); !ok) {
            std::println("prepare_shadowtls_inbound failed: {}", ok.error());
            return 39;
        }
        auto stls_port = (*srv)->start(0, relay::Inbound::shadowtls, 1, false);
        if (!stls_port) return 40;

        int def_hits = 0, alt_hits = 0;
        auto serve_cover = [](io::tcp_acceptor& acc, tls::ServerCredential const& cred, int count, int& hits) -> capy::task<> {
            for (int i = 0; i < count; ++i) {
                auto [ec, sock] = co_await acc.accept();
                if (ec) break;
                ++hits;
                auto copy = cred.clone();
                if (!copy) { sock.close(); break; }
                auto hs = tls::ServerHandshakeIo::create(std::move(*copy), now_ms(), now_ms() + 5000);
                if (hs) {
                    auto res = co_await tls::detail::server_handshake(sock, *hs);
                    if (res) {
                        std::array<std::uint8_t, 64> hold{};
                        (void)co_await io::timeout(sock.read_some(capy::mutable_buffer(hold.data(), hold.size())),
                            Clock::now() + std::chrono::milliseconds(50));
                    }
                }
                sock.close();
            }
            acc.close();
        };

        auto serve_echo = [&]() -> capy::task<> {
            auto [ec, peer] = co_await target_echo.accept();
            if (!ec) {
                std::array<char, 256> buf{};
                auto [re, n] = co_await peer.read_some(capy::mutable_buffer(buf.data(), buf.size()));
                if (!re && n) (void)co_await peer.write_some(capy::const_buffer(buf.data(), n));
                (void)peer.shutdown(io::shutdown_send);
                peer.close();
            }
            target_echo.close();
        };

        int err = 0;
        auto run_clients = [&]() -> capy::task<> {
            auto dl = Clock::now() + std::chrono::seconds(5);
            auto vtime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            // 1. Plain TLS client with SNI "alt.example" -> routed to cover_alt via handshake-for-server-name.
            {
                auto prof = tls::ClientProfile::load("alt.example", alt_cert.string());
                if (!prof) { err = 41; co_return; }
                io::tcp_socket cli(ctx);
                if (cli.open(io::family::v4)) { err = 42; co_return; }
                auto [ce] = co_await io::timeout(cli.connect(io::endpoint(io::ipv4_address::loopback(), *stls_port)), dl);
                if (ce) { err = 43; co_return; }
                auto hs = prof->handshake(now_ms(), now_ms() + 5000, vtime);
                if (!hs || !co_await tls::detail::corosio_handshake(cli, *hs)) { err = 44; co_return; }
                cli.close();
            }
            // 2. Authenticated ShadowTLS v3 client with SNI "alt.example" -> cover_alt handshake + target echo.
            {
                constexpr std::array<std::string_view, 1> alpn{"h2"};
                auto prof = tls::ClientProfile::load("alt.example", alt_cert.string(), 0x001d, false, alpn);
                if (!prof) { err = 45; co_return; }
                io::tcp_socket cli(ctx);
                if (cli.open(io::family::v4)) { err = 46; co_return; }
                auto [ce] = co_await io::timeout(cli.connect(io::endpoint(io::ipv4_address::loopback(), *stls_port)), dl);
                if (ce) { err = 47; co_return; }
                auto hs = co_await shadowtls::handshake_client(cli, *prof, tls::Fingerprint::chrome, "stls-sni-secret", dl, vtime, true);
                if (!hs) { err = 48; co_return; }
                shadowtls::VerifiedSocket<io::tcp_socket> vs(cli, std::move(hs->stream), std::move(hs->unread_wire));
                std::string_view msg = "shadowtls-sni-ok";
                if (!co_await vs.send(as_u8(msg), dl)) { err = 49; co_return; }
                std::array<std::uint8_t, 64> rx{};
                auto got = co_await vs.read(rx, dl);
                if (!got || std::string_view(reinterpret_cast<char const*>(rx.data()), *got) != msg) { err = 50; co_return; }
                (void)co_await vs.close_output(dl);
                cli.close();
            }
            // 3. Plain TLS client with SSRF SNI "evil.local" under wildcard-sni "all" -> rejected & routed to cover_def.
            {
                auto prof = tls::ClientProfile::load("evil.local", def_cert.string());
                if (!prof) { err = 51; co_return; }
                io::tcp_socket cli(ctx);
                if (cli.open(io::family::v4)) { err = 52; co_return; }
                auto [ce] = co_await io::timeout(cli.connect(io::endpoint(io::ipv4_address::loopback(), *stls_port)), dl);
                if (ce) { err = 53; co_return; }
                auto hs = prof->handshake(now_ms(), now_ms() + 5000, vtime);
                if (!hs || !co_await tls::detail::corosio_handshake(cli, *hs)) { err = 54; co_return; }
                cli.close();
            }
        };

        bool done = false;
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(serve_cover(cover_def, *cred_def, 1, def_hits));
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(serve_cover(cover_alt, *cred_alt, 2, alt_hits));
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(serve_echo());
        capy::run_async(ctx.get_executor(), [&] { done = true; }, [&](std::exception_ptr) noexcept { err = 55; done = true; })(run_clients());
        for (int i = 0; i < 400 && !done; ++i) (void)ctx.run_for(std::chrono::milliseconds(10));
        (*srv)->stop();
        if (!done) return 56;
        if (err) return err;
        if (alt_hits != 2 || def_hits != 1) return 57;
        return 0;
    }
}

auto main() -> int {
    if (int r = test_trojan_fallback(); r != 0) {
        std::println("test_trojan_fallback failed with {}", r);
        return r;
    }
    if (int r = test_shadowtls_sni_routing(); r != 0) {
        std::println("test_shadowtls_sni_routing failed with {}", r);
        return r;
    }
    std::println("Wave 31E live Trojan fallback/ALPN decoy relay + ShadowTLS SNI/wildcard SSRF routing passed");
}
