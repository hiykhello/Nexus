module;
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_all.hpp>

module cli.proxy_services;
import std;
import boringssl;
import capy;
import corosio;
import config;
import encoding.base64;
import http.header;
import logging;
import logging.cli;
import platform.ip_address;
import tailscale.derp;
import tailscale.derp_server;
import tls.profiles;
import tls.server_credential;
import tls.corosio_server_handshake;
import tls.corosio_application;

namespace cli {
    namespace {
        using Clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;

        auto now_ms() noexcept -> std::uint64_t {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now().time_since_epoch()).count());
        }
        auto lower_ascii(std::string_view s) -> std::string {
            std::string out(s);
            for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            return out;
        }
        auto ws_accept(std::string_view key) -> std::optional<std::string> {
            constexpr std::string_view guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            if (key.size() != 24) return std::nullopt;
            std::string in;
            in.reserve(24 + guid.size());
            in.append(key); in.append(guid);
            std::array<std::uint8_t, 20> sha{};
            unsigned len = 0;
            if (!boringssl::EVP_Digest(in.data(), in.size(), sha.data(), &len, boringssl::EVP_sha1(), nullptr) || len != 20)
                return std::nullopt;
            return encoding::encode_base64(sha);
        }
        auto encode_ws_binary(std::span<std::uint8_t const> payload) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> out;
            out.reserve(10 + payload.size());
            out.push_back(0x82); // FIN + binary opcode
            if (payload.size() < 126) {
                out.push_back(static_cast<std::uint8_t>(payload.size()));
            } else if (payload.size() <= 65535) {
                out.push_back(126);
                out.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xff));
                out.push_back(static_cast<std::uint8_t>(payload.size() & 0xff));
            } else {
                out.push_back(127);
                for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>((payload.size() >> (i * 8)) & 0xff));
            }
            out.insert(out.end(), payload.begin(), payload.end());
            return out;
        }

        // Unified plain TCP / TLS 1.3 byte stream for DERP HTTP/HTTPS connections.
        struct DerpTransport {
            corosio::tcp_socket& sock;
            std::optional<tls::detail::ApplicationConnection<corosio::tcp_socket>> tls_app;
            std::optional<tls::detail::ApplicationStreamReader<corosio::tcp_socket>> tls_reader;

            auto read_some(std::span<std::uint8_t> dst, std::optional<Clock::time_point> deadline = {}) -> capy::task<std::size_t> {
                if (tls_reader) {
                    for (;;) {
                        auto r = co_await tls_reader->read_some(dst, deadline);
                        if (!r || r->kind == tls::detail::AsyncStreamReadKind::eof) co_return 0;
                        if (r->kind == tls::detail::AsyncStreamReadKind::backpressure) {
                            if (!co_await tls_app->flush(deadline)) co_return 0;
                            continue;
                        }
                        if (r->kind == tls::detail::AsyncStreamReadKind::event) {
                            if (r->event->kind == tls::ApplicationEventKind::close_notify) co_return 0;
                            continue;
                        }
                        co_return r->size;
                    }
                }
                if (deadline && Clock::now() >= *deadline) co_return 0;
                auto [ec, n] = deadline
                    ? co_await corosio::timeout(sock.read_some(capy::mutable_buffer(dst.data(), dst.size())), *deadline)
                    : co_await sock.read_some(capy::mutable_buffer(dst.data(), dst.size()));
                co_return ec ? 0 : n;
            }

            auto write_all(std::span<std::uint8_t const> data, std::optional<Clock::time_point> deadline = {}) -> capy::task<bool> {
                if (tls_app) co_return (co_await tls_app->send_all(data, deadline)).has_value();
                while (!data.empty()) {
                    if (deadline && Clock::now() >= *deadline) co_return false;
                    auto [ec, n] = deadline
                        ? co_await corosio::timeout(sock.write_some(capy::const_buffer(data.data(), data.size())), *deadline)
                        : co_await sock.write_some(capy::const_buffer(data.data(), data.size()));
                    if (ec || !n || n > data.size()) co_return false;
                    data = data.subspan(n);
                }
                co_return true;
            }
        };

        struct DerpPeerConn {
            std::uint64_t id = 0;
            bool websocket = false;
            corosio::tcp_socket* sock = nullptr;
            bool closed = false;
            bool close_after_flush = false;
            std::deque<std::vector<std::uint8_t>> tx_queue;
            capy::async_event tx_wake;

            auto enqueue(std::vector<std::uint8_t> frame, bool close_after = false) -> void {
                if (closed) return;
                if (close_after) close_after_flush = true;
                if (!frame.empty() && tx_queue.size() < 256)
                    tx_queue.push_back(websocket ? encode_ws_binary(frame) : std::move(frame));
                tx_wake.set();
            }
            auto close() noexcept -> void {
                closed = true;
                tx_wake.set();
                if (sock) sock->cancel();
            }
        };

        struct DerpServiceState {
            tailscale::derp::DerpRelayServer relay;
            std::optional<tls::ServerCredential> tls_cred;
            std::uint16_t bound_port = 0;
            std::uint64_t next_cid = 1;
            std::size_t max_pre_upgrade = 64;
            std::size_t active_pre_upgrade = 0;
            std::unordered_set<corosio::tcp_socket*> pre_upgrade_socks;
            std::atomic_bool stopping{false};
            std::mutex conns_mu;
            std::unordered_map<std::uint64_t, std::shared_ptr<DerpPeerConn>> conns;
            // Declared after relay/conns so ~io_context() tears down frames before state.
            std::mutex shutdown_mu;
            std::condition_variable shutdown_cv;
            bool shutdown_done = false, worker_done = false;
            corosio::io_context io;
            corosio::tcp_acceptor acceptor{io};
            std::jthread worker;

            explicit DerpServiceState(tailscale::derp::DerpRelayServer r) : relay(std::move(r)) {}
            ~DerpServiceState() { stop(); }

            auto close_on_io() noexcept -> void {
                acceptor.close();
                for (auto* s : pre_upgrade_socks) if (s) s->cancel();
                std::lock_guard lk(conns_mu);
                for (auto& [_, c] : conns) c->close();
            }

            auto shutdown_task() -> capy::task<> {
                close_on_io();
                { std::lock_guard lk(shutdown_mu); shutdown_done = true; }
                shutdown_cv.notify_all();
                io.stop();
                co_return;
            }

            auto stop() noexcept -> void {
                if (stopping.exchange(true, std::memory_order_acq_rel)) return;
                if (!worker.joinable()) {
                    close_on_io();
                } else {
                    try {
                        capy::run_async(io.get_executor())(shutdown_task());
                        std::unique_lock lk(shutdown_mu);
                        shutdown_cv.wait_for(lk, std::chrono::seconds(2), [&] { return shutdown_done || worker_done; });
                    } catch (...) {}
                    io.stop();
                    worker.join();
                }
                std::lock_guard lk(conns_mu);
                conns.clear();
            }

            auto dispatch(std::vector<tailscale::derp::OutboundFrame> frames) -> void {
                std::lock_guard lk(conns_mu);
                for (auto& f : frames) {
                    if (auto it = conns.find(f.connection_id); it != conns.end())
                        it->second->enqueue(std::move(f.frame), f.close_after);
                }
            }

            auto feed_derp_bytes(std::uint64_t cid, tailscale::derp::Decoder& dec, std::span<std::uint8_t const> data) -> bool {
                while (!data.empty()) {
                    auto f = dec.feed(data);
                    if (f.error) return false;
                    data = data.subspan(f.consumed);
                    if (f.ready) {
                        auto fr = dec.frame();
                        if (!fr) return false;
                        auto out = relay.handle_frame(cid, *fr, now_ms());
                        (void)dec.consume();
                        if (!out) return false;
                        dispatch(std::move(*out));
                    }
                }
                return true;
            }

            auto writer_loop(DerpTransport& tr, std::shared_ptr<DerpPeerConn> conn) -> capy::task<capy::results<>> {
                while (!conn->closed && !stopping.load(std::memory_order_acquire)) {
                    if (conn->tx_queue.empty()) {
                        if (conn->close_after_flush) break;
                        conn->tx_wake.clear();
                        co_await conn->tx_wake.wait();
                        continue;
                    }
                    auto pkt = std::move(conn->tx_queue.front());
                    conn->tx_queue.pop_front();
                    if (!co_await tr.write_all(pkt)) break;
                }
                conn->close();
                co_return capy::results<>{};
            }

            auto reader_loop(DerpTransport& tr, std::shared_ptr<DerpPeerConn> conn, std::vector<std::uint8_t> initial)
                -> capy::task<capy::results<>> {
                tailscale::derp::Decoder dec;
                std::vector<std::uint8_t> ws_buf;
                auto process_ws = [&]() -> bool {
                    std::size_t off = 0;
                    while (ws_buf.size() - off >= 2) {
                        auto b0 = ws_buf[off], b1 = ws_buf[off + 1];
                        bool masked = (b1 & 0x80) != 0;
                        std::uint64_t plen = b1 & 0x7f;
                        std::size_t hdr = 2;
                        if (plen == 126) {
                            if (ws_buf.size() - off < 4) break;
                            plen = (std::uint64_t(ws_buf[off + 2]) << 8) | ws_buf[off + 3];
                            hdr = 4;
                        } else if (plen == 127) {
                            if (ws_buf.size() - off < 10) break;
                            plen = 0;
                            for (int i = 0; i < 8; ++i) plen = (plen << 8) | ws_buf[off + 2 + i];
                            hdr = 10;
                        }
                        if (plen > tailscale::derp::max_frame_size) return false;
                        std::size_t need = hdr + (masked ? 4 : 0) + static_cast<std::size_t>(plen);
                        if (ws_buf.size() - off < need) break;
                        auto opcode = b0 & 0x0f;
                        if (opcode == 0x8) return false; // close
                        std::vector<std::uint8_t> payload(ws_buf.begin() + static_cast<std::ptrdiff_t>(off + hdr + (masked ? 4 : 0)),
                            ws_buf.begin() + static_cast<std::ptrdiff_t>(off + need));
                        if (masked) {
                            for (std::size_t i = 0; i < payload.size(); ++i)
                                payload[i] ^= ws_buf[off + hdr + (i & 3)];
                        }
                        off += need;
                        if (opcode == 0x1 || opcode == 0x2 || opcode == 0x0) {
                            if (!feed_derp_bytes(conn->id, dec, payload)) return false;
                        }
                    }
                    if (off > 0) ws_buf.erase(ws_buf.begin(), ws_buf.begin() + static_cast<std::ptrdiff_t>(off));
                    return true;
                };

                if (!initial.empty()) {
                    if (conn->websocket) { ws_buf = std::move(initial); if (!process_ws()) { conn->close(); co_return capy::results<>{}; } }
                    else if (!feed_derp_bytes(conn->id, dec, initial)) { conn->close(); co_return capy::results<>{}; }
                }
                std::array<std::uint8_t, 16640> buf{};
                while (!conn->closed && !stopping.load(std::memory_order_acquire)) {
                    auto n = co_await tr.read_some(buf);
                    if (n == 0) break;
                    if (conn->websocket) {
                        ws_buf.insert(ws_buf.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
                        if (!process_ws()) break;
                    } else if (!feed_derp_bytes(conn->id, dec, std::span(buf).first(n))) {
                        break;
                    }
                }
                conn->close();
                co_return capy::results<>{};
            }

            auto handle_client(corosio::tcp_socket sock) -> capy::task<> {
                struct PreUpgradeGuard {
                    DerpServiceState& st;
                    corosio::tcp_socket* sock;
                    bool active = true;
                    PreUpgradeGuard(DerpServiceState& s, corosio::tcp_socket* sk) : st(s), sock(sk) {
                        st.pre_upgrade_socks.insert(sock);
                    }
                    auto release() noexcept -> void {
                        if (!active) return;
                        active = false;
                        st.pre_upgrade_socks.erase(sock);
                        if (st.active_pre_upgrade > 0) --st.active_pre_upgrade;
                    }
                    ~PreUpgradeGuard() { release(); }
                } pre_guard{*this, &sock};
                if (stopping.load(std::memory_order_acquire)) co_return;
                auto upgrade_deadline = Clock::now() + 5s;
                DerpTransport tr{sock};
                if (tls_cred) {
                    auto hs = tls::make_server_handshake(*tls_cred, now_ms(), now_ms() + 5000);
                    if (!hs) co_return;
                    auto res = co_await tls::detail::server_handshake(sock, *hs);
                    if (!res) co_return;
                    tr.tls_app.emplace(sock, std::move(res->records), std::move(res->unread));
                    tr.tls_reader.emplace(*tr.tls_app);
                }
                std::string hdr_buf;
                std::array<std::uint8_t, 4096> tmp{};
                decltype(http::inspect_header(hdr_buf)) hdr{};
                while (hdr_buf.size() < http::max_header_bytes && Clock::now() < upgrade_deadline) {
                    auto n = co_await tr.read_some(tmp, upgrade_deadline);
                    if (n == 0) co_return;
                    hdr_buf.append(reinterpret_cast<char const*>(tmp.data()), n);
                    hdr = http::inspect_header(hdr_buf);
                    if (hdr.status != http::HeaderStatus::incomplete) break;
                }
                if (hdr.status != http::HeaderStatus::complete) co_return;
                if (hdr.first.starts_with("GET /generate_204 ")) {
                    constexpr std::string_view k204 = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    (void)co_await tr.write_all({reinterpret_cast<std::uint8_t const*>(k204.data()), k204.size()}, upgrade_deadline);
                    co_return;
                }
                if (!hdr.first.starts_with("GET /derp ")) {
                    constexpr std::string_view k404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    (void)co_await tr.write_all({reinterpret_cast<std::uint8_t const*>(k404.data()), k404.size()}, upgrade_deadline);
                    co_return;
                }
                std::string upgrade_val, ws_key;
                http::HeaderFieldCursor cur(hdr.field_lines);
                for (;;) {
                    auto it = cur.next();
                    if (it.status != http::HeaderFieldStatus::field) break;
                    auto k = lower_ascii(it.field.name);
                    if (k == "upgrade") upgrade_val = lower_ascii(it.field.value);
                    else if (k == "sec-websocket-key") ws_key = std::string(it.field.value);
                }
                bool is_ws = (upgrade_val == "websocket");
                std::string resp;
                if (is_ws) {
                    auto acc = ws_accept(ws_key);
                    if (!acc) co_return;
                    resp = std::format("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", *acc);
                } else if (upgrade_val == "derp") {
                    resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
                } else {
                    co_return;
                }
                if (!co_await tr.write_all({reinterpret_cast<std::uint8_t const*>(resp.data()), resp.size()}, upgrade_deadline)) co_return;

                auto cid = next_cid++;
                auto conn = std::make_shared<DerpPeerConn>();
                conn->id = cid;
                conn->websocket = is_ws;
                {
                    std::lock_guard lk(conns_mu);
                    if (stopping.load(std::memory_order_acquire)) co_return;
                    conn->sock = &sock;
                    conns[cid] = conn;
                }
                pre_guard.release();
                struct Cleanup {
                    DerpServiceState& st;
                    std::uint64_t id;
                    std::shared_ptr<DerpPeerConn> conn;
                    ~Cleanup() {
                        {
                            std::lock_guard lk(st.conns_mu);
                            conn->close();
                            conn->sock = nullptr;
                            st.conns.erase(id);
                        }
                        st.dispatch(st.relay.disconnect(id));
                    }
                } cleanup{*this, cid, conn};

                auto sk = relay.accept_connection(cid);
                if (!sk) co_return;
                conn->enqueue(std::move(sk->frame));

                std::vector<std::uint8_t> trailing(
                    reinterpret_cast<std::uint8_t const*>(hdr_buf.data() + hdr.consumed),
                    reinterpret_cast<std::uint8_t const*>(hdr_buf.data() + hdr_buf.size()));
                (void)co_await capy::when_all(
                    writer_loop(tr, conn),
                    reader_loop(tr, conn, std::move(trailing)));
            }

            auto accept_loop() -> capy::task<> {
                while (!stopping.load(std::memory_order_acquire)) {
                    auto [ec, s] = co_await acceptor.accept();
                    if (ec) break;
                    if (active_pre_upgrade >= max_pre_upgrade) { s.close(); continue; }
                    ++active_pre_upgrade;
                    try {
                        capy::run_async(io.get_executor())(handle_client(std::move(s)));
                    } catch (...) {
                        if (active_pre_upgrade > 0) --active_pre_upgrade;
                    }
                }
            }
        };
    }

    auto init_derp_server_service(config::DerpServerServiceConfig const& cfg, logging::Runtime& logs)
        -> std::expected<ServiceHandle, std::string> {
        auto ip = platform::parse_ip_address(cfg.listen_host);
        if (!ip) return std::unexpected("derp-server: invalid listen_host: " + cfg.listen_host);
        corosio::endpoint ep = [&] {
            if (ip->size == 4) {
                corosio::ipv4_address::bytes_type b{};
                std::copy_n(ip->bytes.begin(), 4, b.begin());
                return corosio::endpoint(corosio::ipv4_address(b), cfg.listen_port);
            }
            return corosio::endpoint(corosio::ipv6_address(ip->bytes), cfg.listen_port);
        }();
        auto relay = tailscale::derp::DerpRelayServer::generate(cfg.max_peers);
        if (!relay) return std::unexpected(std::move(relay.error()));

        auto st = std::make_unique<DerpServiceState>(std::move(*relay));
        st->max_pre_upgrade = std::clamp<std::size_t>(cfg.max_peers, 16, 256);
        if (!cfg.cert_file.empty()) {
            auto cred = tls::load_server_credential(cfg.cert_file, cfg.key_file);
            if (!cred) return std::unexpected("derp-server TLS credential: " + cred.error());
            st->tls_cred.emplace(std::move(*cred));
        }
        if (auto ec = st->acceptor.open(); ec) return std::unexpected("derp-server open: " + ec.message());
        if (auto ec = st->acceptor.bind(ep); ec) return std::unexpected("derp-server bind: " + ec.message());
        if (auto ec = st->acceptor.listen(); ec) return std::unexpected("derp-server listen: " + ec.message());
        st->bound_port = st->acceptor.local_endpoint().port();

        capy::run_async(st->io.get_executor())(st->accept_loop());
        st->worker = std::jthread([ptr = st.get()] {
            ptr->io.run();
            { std::lock_guard lk(ptr->shutdown_mu); ptr->worker_done = true; }
            ptr->shutdown_cv.notify_all();
        });
        logs.emit(logging::Level::info, logging::Domain::core, 101, {},
            "derp-server listening on {}:{} (tls={}, max_peers={})",
            cfg.listen_host, st->bound_port, st->tls_cred.has_value(), cfg.max_peers);
        return ServiceHandle::create(std::move(st));
    }

    auto derp_bound_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        return h.state ? static_cast<DerpServiceState const*>(h.state.get())->bound_port : 0;
    }
    auto derp_public_key(ServiceHandle const& h) noexcept -> std::array<std::uint8_t, 32> {
        return h.state ? static_cast<DerpServiceState const*>(h.state.get())->relay.public_key() : std::array<std::uint8_t, 32>{};
    }
}
