#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/timeout.hpp>
import std;
import crypto;
import tuic.wire;
import tuic.application;
import tuic.client;
import tuic.server;
import quic.cid_registry;
import quic.datagram_port;
import tls.fingerprint;
import tls.server_credential;
import capy;
import corosio;

namespace io = ::corosio;
using Clock = std::chrono::steady_clock;

namespace {
    struct TempDir {
        std::filesystem::path dir;
        std::string cert_file, key_file, uuid_file, pass_file, bad_pass_file;
        TempDir(std::filesystem::path d, std::string c, std::string k, std::string u, std::string p, std::string b)
            : dir(std::move(d)), cert_file(std::move(c)), key_file(std::move(k)),
              uuid_file(std::move(u)), pass_file(std::move(p)), bad_pass_file(std::move(b)) {}
        TempDir(TempDir&& o) noexcept
            : dir(std::exchange(o.dir, {})), cert_file(std::move(o.cert_file)), key_file(std::move(o.key_file)),
              uuid_file(std::move(o.uuid_file)), pass_file(std::move(o.pass_file)), bad_pass_file(std::move(o.bad_pass_file)) {}
        TempDir& operator=(TempDir&&) = delete;
        ~TempDir() { if (!dir.empty()) { std::error_code ec; std::filesystem::remove_all(dir, ec); } }
    };

    auto make_temp_files() -> std::optional<TempDir> {
        auto dir = std::filesystem::temp_directory_path() /
                   ("nexus-tuic-loopback-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
        TempDir out{dir, (dir / "cert.pem").string(), (dir / "key.pem").string(),
                    (dir / "uuid.txt").string(), (dir / "pass.txt").string(), (dir / "bad.txt").string()};
        auto cmd = std::format(
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
            "-keyout '{}' -out '{}' -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -days 1 >/dev/null 2>&1",
            out.key_file, out.cert_file);
        if (std::system(cmd.c_str()) != 0) return std::nullopt;
        std::ofstream(out.uuid_file) << "b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f\n";
        std::ofstream(out.pass_file) << "tuic-pass\n";
        std::ofstream(out.bad_pass_file) << "wrong-pass\n";
        auto priv = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
        std::filesystem::permissions(out.uuid_file, priv, std::filesystem::perm_options::replace);
        std::filesystem::permissions(out.pass_file, priv, std::filesystem::perm_options::replace);
        std::filesystem::permissions(out.bad_pass_file, priv, std::filesystem::perm_options::replace);
        return out;
    }

    auto as_u8(std::string_view s) noexcept -> std::span<std::uint8_t const> {
        return {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()};
    }

    auto read_bytes(std::string const& path) -> ::crypto::Bytes {
        std::ifstream f(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), {}};
    }

    struct ServerHooks {
        capy::async_event ev;
        std::deque<std::pair<quic::SessionHandle, tuic::StreamHandle>> tcp_accepts;
        std::deque<std::pair<quic::SessionHandle, tuic::IncomingUdpPacket>> udp_rx;
        std::vector<std::uint16_t> dissociations;
        bool auth_seen = false;
        void authenticated(quic::SessionHandle, std::size_t) { auth_seen = true; ev.set(); }
        void connect_stream(quic::SessionHandle owner, tuic::StreamHandle stream, tuic::TargetAddress const&) {
            tcp_accepts.emplace_back(owner, stream);
            ev.set();
        }
        void udp_packet(quic::SessionHandle owner, tuic::IncomingUdpPacket pkt) {
            udp_rx.emplace_back(owner, std::move(pkt));
            ev.set();
        }
        void udp_dissociate(quic::SessionHandle, std::uint16_t assoc) {
            dissociations.push_back(assoc);
            ev.set();
        }
        void transport_closed(quic::SessionHandle) noexcept { ev.set(); }
        bool session_drained(quic::SessionHandle) const noexcept { return true; }
        void session_destroyed(quic::SessionHandle) noexcept {}
    };
}

auto main() -> int {
    auto tmp = make_temp_files();
    if (!tmp) return 1;
    auto cert = read_bytes(tmp->cert_file);
    auto key = read_bytes(tmp->key_file);
    auto cred = tls::ServerCredential::create_file_contents(cert, key);
    ::crypto::cleanse(key);
    if (!cred) return 2;

    auto uuid = tuic::parse_uuid("b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f");
    if (!uuid) return 3;
    std::array<tuic::UserCredential, 1> users{tuic::UserCredential{*uuid, "tuic-pass", "u1"}};
    tuic::ClientTransportOptions srv_opts{};
    io::io_context ctx;
    ServerHooks hooks;
    tuic::Listener<ServerHooks> listener(ctx, *cred, users, srv_opts, hooks);
    auto bound = listener.prepare(io::endpoint(io::ipv4_address::loopback(), 0));
    if (!bound) return 4;
    listener.start();

    bool stop_server = false;
    auto echo_stream = [&](quic::SessionHandle owner, tuic::StreamHandle s) -> capy::task<> {
        std::array<std::uint8_t, 512> buf{};
        for (;;) {
            auto* app = listener.app(owner);
            if (!app) co_return;
            auto n = app->read_stream(s, buf);
            if (!n) co_return;
            if (*n > 0) {
                (void)app->send_stream(s, std::span(buf).first(*n));
                listener.notify();
                continue;
            }
            if (app->stream_eof(s)) {
                (void)app->close_stream_write(s);
                listener.notify();
                co_return;
            }
            listener.changed().clear();
            auto [ec] = co_await io::timeout(listener.changed().wait(), Clock::now() + std::chrono::seconds(3));
            if (ec) co_return;
        }
    };

    auto dispatch_server = [&]() -> capy::task<> {
        while (!stop_server) {
            while (!hooks.tcp_accepts.empty()) {
                auto [owner, stream] = hooks.tcp_accepts.front();
                hooks.tcp_accepts.pop_front();
                capy::run_async(ctx.get_executor())(echo_stream(owner, stream));
            }
            while (!hooks.udp_rx.empty()) {
                auto [owner, pkt] = std::move(hooks.udp_rx.front());
                hooks.udp_rx.pop_front();
                if (auto* app = listener.app(owner)) {
                    (void)app->send_udp(pkt.assoc_id, pkt.destination, pkt.payload, false);
                    listener.notify();
                }
            }
            hooks.ev.clear();
            (void)co_await io::timeout(hooks.ev.wait(), Clock::now() + std::chrono::milliseconds(200));
        }
    };

    int result = 0;
    auto run_clients = [&]() -> capy::task<> {
        struct Shutdown { bool& s; ServerHooks& h; tuic::Listener<ServerHooks>& l;
            ~Shutdown() { s = true; h.ev.set(); l.stop(); } } shutdown{stop_server, hooks, listener};
        auto deadline = Clock::now() + std::chrono::seconds(6);

        // 1. Standard TUIC v5 + uTLS Chrome (TCP stream + QUIC Datagram UDP + dissociate)
        {
            auto prof = tuic::ClientProfile::load(
                "localhost", tmp->cert_file, tmp->uuid_file, tmp->pass_file, 0x001d, false,
                tuic::ClientTransportOptions{.cc = tuic::CongestionControl::bbr, .udp_over_stream = false},
                tls::Fingerprint::chrome);
            if (!prof) { result = 10; co_return; }
            tuic::Client<> client(ctx, **prof);
            if (!client.start(*bound)) { result = 11; co_return; }
            auto ops = [&]() -> capy::task<capy::results<>> {
                struct Fin { tuic::Client<>& c; ~Fin() { c.finish(); } } fin{client};
                if (!co_await client.ready(deadline)) { result = 12; co_return capy::results<>{}; }

                tuic::TargetAddress tgt{tuic::AddressType::domain, "echo.local", {}, 9000};
                auto ch = client.open_channel(tgt);
                if (!ch) { result = 13; co_return capy::results<>{}; }
                std::string_view tcp_msg = "hello-tuic-tcp";
                if (!co_await (*ch)->send(as_u8(tcp_msg))) { result = 14; co_return capy::results<>{}; }
                if (!co_await (*ch)->close_output()) { result = 15; co_return capy::results<>{}; }
                std::string tcp_rx;
                std::array<std::uint8_t, 64> tmp_buf{};
                for (;;) {
                    auto r = co_await (*ch)->read(tmp_buf);
                    if (!r) { result = 16; co_return capy::results<>{}; }
                    if (*r == 0) break;
                    tcp_rx.append(reinterpret_cast<char const*>(tmp_buf.data()), *r);
                }
                if (tcp_rx != tcp_msg) { result = 17; co_return capy::results<>{}; }

                std::string_view udp_msg = "hello-tuic-udp";
                if (!client.send_udp(7, tgt, as_u8(udp_msg))) { result = 18; co_return capy::results<>{}; }
                auto pkt = co_await client.wait_udp(deadline);
                if (!pkt || pkt->assoc_id != 7 ||
                    std::string_view(reinterpret_cast<char const*>(pkt->payload.data()), pkt->payload.size()) != udp_msg) {
                    result = 19; co_return capy::results<>{};
                }
                if (!client.dissociate(7)) { result = 20; co_return capy::results<>{}; }
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(client.run(), ops());
            if (result) co_return;
        }

        // 2. UDP-over-stream mode + uTLS Safari
        {
            auto prof = tuic::ClientProfile::load(
                "localhost", tmp->cert_file, tmp->uuid_file, tmp->pass_file, 0x001d, false,
                tuic::ClientTransportOptions{.udp_over_stream = true}, tls::Fingerprint::safari);
            if (!prof) { result = 21; co_return; }
            tuic::Client<> client(ctx, **prof);
            if (!client.start(*bound)) { result = 22; co_return; }
            auto ops = [&]() -> capy::task<capy::results<>> {
                struct Fin { tuic::Client<>& c; ~Fin() { c.finish(); } } fin{client};
                if (!co_await client.ready(deadline)) { result = 23; co_return capy::results<>{}; }
                tuic::TargetAddress tgt{tuic::AddressType::domain, "echo.local", {}, 9001};
                for (int round = 0; round < 70; ++round) {
                    std::string uos_msg = "hello-tuic-uos-" + std::to_string(round);
                    if (!client.send_udp(9, tgt, as_u8(uos_msg))) { result = 24; co_return capy::results<>{}; }
                    auto pkt = co_await client.wait_udp(deadline);
                    if (!pkt || pkt->assoc_id != 9 ||
                        std::string_view(reinterpret_cast<char const*>(pkt->payload.data()), pkt->payload.size()) != uos_msg) {
                        result = 25; co_return capy::results<>{};
                    }
                }
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(client.run(), ops());
            if (result) co_return;
        }

        stop_server = true;
        hooks.ev.set();
        listener.stop();
    };

    capy::run_async(ctx.get_executor())(listener.run());
    capy::run_async(ctx.get_executor())(dispatch_server());
    capy::run_async(ctx.get_executor())(run_clients());
    ctx.run_for(std::chrono::seconds(8));
    stop_server = true;
    hooks.ev.set();
    listener.stop();
    ctx.restart();
    ctx.run_for(std::chrono::milliseconds(200));
    if (result != 0) return result;
    if (!hooks.auth_seen) return 30;
    std::println("TUIC v5 loopback (uTLS Chrome/Safari, BBR TCP echo, QUIC Datagram UDP, UDP-over-stream, dissociate) passed");
}
