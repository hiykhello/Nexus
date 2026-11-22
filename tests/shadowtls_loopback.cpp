#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>
import std;
import crypto;
import shadowtls.v3;
import shadowtls.stream;
import tls.profiles;
import tls.fingerprint;
import tls.server_credential;
import tls.server_handshake_io;
import tls.corosio_server_handshake;
import tls.client_handshake_io;
import tls.corosio_client;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace io = nex::corosio;
namespace capy = nex::capy;
namespace stls = shadowtls;
using Clock = std::chrono::steady_clock;

namespace {
    struct TempCertDir {
        std::filesystem::path dir;
        std::string cert_file;
        std::string key_file;
        TempCertDir(std::filesystem::path d, std::string c, std::string k)
            : dir(std::move(d)), cert_file(std::move(c)), key_file(std::move(k)) {}
        TempCertDir(TempCertDir&& o) noexcept
            : dir(std::exchange(o.dir, {})), cert_file(std::move(o.cert_file)), key_file(std::move(o.key_file)) {}
        TempCertDir& operator=(TempCertDir&&) = delete;
        ~TempCertDir() { if (!dir.empty()) { std::error_code ec; std::filesystem::remove_all(dir, ec); } }
    };

    auto make_temp_cert() -> std::optional<TempCertDir> {
        auto dir = std::filesystem::temp_directory_path() /
                   ("nexus-stls-loopback-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
        TempCertDir out{dir, (dir / "cert.pem").string(), (dir / "key.pem").string()};
        auto cmd = std::format(
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
            "-keyout '{}' -out '{}' -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -days 1 >/dev/null 2>&1",
            out.key_file, out.cert_file);
        if (std::system(cmd.c_str()) != 0) return std::nullopt;
        return out;
    }

    auto as_u8(std::string_view s) noexcept -> std::span<std::uint8_t const> {
        return {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()};
    }

    auto read_bytes(std::string const& path) -> ::crypto::Bytes {
        std::ifstream f(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), {}};
    }

    auto now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
    }
}

auto main() -> int {
    auto tmp = make_temp_cert();
    if (!tmp) return 1;
    auto cert = read_bytes(tmp->cert_file);
    auto key = read_bytes(tmp->key_file);
    auto cred = tls::ServerCredential::create_file_contents(cert, key);
    ::crypto::cleanse(key);
    if (!cred) return 2;

    io::io_context ctx;
    io::tcp_acceptor cover_acc(ctx), stls_acc(ctx);
    if (cover_acc.open() || cover_acc.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || cover_acc.listen())
        return 3;
    if (stls_acc.open() || stls_acc.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || stls_acc.listen())
        return 4;
    auto cover_port = cover_acc.local_endpoint().port();
    auto stls_port = stls_acc.local_endpoint().port();

    auto serve_cover = [&]() -> capy::task<> {
        for (int i = 0; i < 2; ++i) {
            auto [ec, sock] = co_await cover_acc.accept();
            if (ec) co_return;
            auto copy = cred->clone();
            if (!copy) co_return;
            auto hs = tls::ServerHandshakeIo::create(std::move(*copy), now_ms(), now_ms() + 5000);
            if (!hs) co_return;
            auto res = co_await tls::detail::server_handshake(sock, *hs);
            if (res) {
                std::array<std::uint8_t, 64> hold{};
                (void)co_await io::timeout(sock.read_some(capy::mutable_buffer(hold.data(), hold.size())), Clock::now() + std::chrono::milliseconds(50));
            }
            sock.close();
        }
    };

    auto serve_stls = [&]() -> capy::task<> {
        std::array<std::string, 1> passwords{"shadowtls-secret"};
        std::array<std::string_view, 1> pass_views{passwords[0]};
        for (int i = 0; i < 2; ++i) {
            auto [ec, client] = co_await stls_acc.accept();
            if (ec) co_return;
            auto deadline = Clock::now() + std::chrono::seconds(5);
            stls::TlsRecordReader reader;
            std::array<std::uint8_t, 16640> rx{};
            std::vector<std::uint8_t> first_rec, leftover;
            while (first_rec.empty()) {
                auto [rec_ec, n] = co_await io::timeout(client.read_some(capy::mutable_buffer(rx.data(), rx.size())), deadline);
                if (rec_ec || !n) break;
                auto step = reader.feed(std::span(rx).first(n));
                if (step.status == stls::RecordStatus::complete) {
                    first_rec.assign(step.record.begin(), step.record.end());
                    leftover.assign(rx.begin() + static_cast<std::ptrdiff_t>(step.consumed), rx.begin() + static_cast<std::ptrdiff_t>(n));
                    reader.consume();
                } else if (step.status != stls::RecordStatus::incomplete) break;
            }
            io::tcp_socket hs_sock(ctx);
            bool connected = !first_rec.empty() && !hs_sock.open();
            if (connected) {
                auto [hs_ec] = co_await io::timeout(hs_sock.connect(io::endpoint(io::ipv4_address::loopback(), cover_port)), deadline);
                connected = !hs_ec;
            }
            if (!connected) {
                client.close();
                continue;
            }
            auto matched = stls::verify_client_hello(first_rec, pass_views);
            if (!matched) {
                co_await stls::relay_plain_tls(client, hs_sock, first_rec, leftover, deadline);
                hs_sock.close();
                client.close();
                continue;
            }
            auto session = co_await stls::handshake_server(client, hs_sock, passwords, first_rec, leftover, *matched, deadline, true);
            hs_sock.close();
            if (session) {
                stls::VerifiedSocket<io::tcp_socket> vs(client, std::move(session->stream),
                                                        std::move(session->unread_wire), std::move(session->initial_payload));
                std::array<std::uint8_t, 256> buf{};
                for (;;) {
                    auto got = co_await vs.read(buf, deadline);
                    if (!got || !*got) break;
                    if (!co_await vs.send(std::span(buf).first(*got), deadline)) break;
                }
                (void)co_await vs.close_output(deadline);
            }
            client.close();
        }
    };

    int result = 0;
    auto run_clients = [&]() -> capy::task<> {
        auto deadline = Clock::now() + std::chrono::seconds(5);
        auto vtime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        constexpr std::array<std::string_view, 1> alpn{"h2"};
        auto prof = tls::ClientProfile::load("localhost", tmp->cert_file, 0x001d, false, alpn);
        if (!prof) { result = 10; co_return; }

        // 1. Authenticated ShadowTLS v3 client with uTLS Chrome preset
        {
            io::tcp_socket cli(ctx);
            if (cli.open()) { result = 11; co_return; }
            auto [ec] = co_await io::timeout(cli.connect(io::endpoint(io::ipv4_address::loopback(), stls_port)), deadline);
            if (ec) { result = 12; co_return; }
            auto hs = co_await stls::handshake_client(cli, *prof, tls::Fingerprint::chrome, "shadowtls-secret", deadline, vtime, true);
            if (!hs) { std::println("stls client hs err: {}", hs.error()); result = 13; co_return; }
            stls::VerifiedSocket<io::tcp_socket> vs(cli, std::move(hs->stream), std::move(hs->unread_wire));
            std::string_view msg = "hello-shadowtls-v3";
            if (!co_await vs.send(as_u8(msg), deadline)) { result = 14; co_return; }
            std::array<std::uint8_t, 64> rx{};
            auto got = co_await vs.read(rx, deadline);
            if (!got || std::string_view(reinterpret_cast<char const*>(rx.data()), *got) != msg) {
                result = 15; co_return;
            }
            (void)co_await vs.close_output(deadline);
            auto eof = co_await vs.read(rx, deadline);
            if (!eof || *eof != 0) { result = 16; co_return; }
            cli.close();
        }

        // 2. Unauthenticated plain TLS 1.3 client fallback to handshake cover server
        {
            io::tcp_socket cli(ctx);
            if (cli.open()) { result = 17; co_return; }
            auto [ec] = co_await io::timeout(cli.connect(io::endpoint(io::ipv4_address::loopback(), stls_port)), deadline);
            if (ec) { result = 18; co_return; }
            auto hello = tls::make_fingerprint_hello(std::string_view("localhost"), alpn,
                tls::make_profile_fingerprint_config(tls::Fingerprint::firefox, 0x001d, false, tls::HandshakeTransport::tcp));
            if (!hello) { result = 19; co_return; }
            std::vector<std::span<std::uint8_t const>> anchors;
            for (auto const& a : prof->anchors) anchors.emplace_back(a);
            std::string_view host = "localhost";
            auto cs = tls::ClientSessionHandshake::create(
                std::move(hello->hello), hello->initial_groups(), anchors, tls::PeerNameKind::dns,
                as_u8(host), vtime);
            if (!cs) { result = 20; co_return; }
            auto cio = tls::ClientHandshakeIo::create(std::move(*cs), now_ms(), now_ms() + 5000);
            if (!cio) { result = 21; co_return; }
            auto res = co_await tls::detail::corosio_handshake(cli, *cio);
            if (!res) { result = 22; co_return; }
            cli.close();
        }
        cover_acc.close();
        stls_acc.close();
    };

    capy::run_async(ctx.get_executor())(serve_cover());
    capy::run_async(ctx.get_executor())(serve_stls());
    capy::run_async(ctx.get_executor())(run_clients());
    ctx.run_for(std::chrono::seconds(8));
    if (result != 0) return result;
    std::println("ShadowTLS v3 loopback (uTLS Chrome VerifiedSocket echo + plain TLS passthrough fallback) passed");
}
