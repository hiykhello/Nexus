module;
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_all.hpp>

module cli.proxy_services;
import std;
import capy;
import corosio;
import config;
import logging;
import logging.cli;
import platform.ip_address;
import relay.reverse_tunnel;

namespace cli {
    namespace {
        using Clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;
        namespace rt = relay::reverse_tunnel;

        auto now_ms() noexcept -> std::int64_t {
            return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        }
        auto parse_ip_ep(std::string_view host, std::uint16_t port) -> std::expected<corosio::endpoint, std::string> {
            auto ip = platform::parse_ip_address(host);
            if (!ip) return std::unexpected("reverse-tunnel: invalid IP: " + std::string(host));
            if (ip->size == 4) {
                corosio::ipv4_address::bytes_type b{};
                std::copy_n(ip->bytes.begin(), 4, b.begin());
                return corosio::endpoint(corosio::ipv4_address(b), port);
            }
            return corosio::endpoint(corosio::ipv6_address(ip->bytes), port);
        }

        auto write_all(corosio::tcp_socket& s, std::span<std::uint8_t const> data) -> capy::task<bool> {
            while (!data.empty()) {
                auto [ec, n] = co_await s.write_some(capy::const_buffer(data.data(), data.size()));
                if (ec || !n || n > data.size()) co_return false;
                data = data.subspan(n);
            }
            co_return true;
        }

        struct MuxStream {
            std::uint32_t id = 0;
            corosio::tcp_socket* sock = nullptr;
            std::deque<std::vector<std::uint8_t>> rx_queue;
            bool remote_fin = false;
            bool closed = false;
            capy::async_event rx_wake;

            auto push(std::vector<std::uint8_t> data) -> void {
                if (closed || rx_queue.size() >= 256) return;
                rx_queue.push_back(std::move(data));
                rx_wake.set();
            }
            auto finish_remote() -> void { remote_fin = true; rx_wake.set(); }
            auto cancel() noexcept -> void {
                closed = true;
                rx_wake.set();
                if (sock) sock->cancel();
            }
        };

        struct ControlChannel {
            corosio::tcp_socket sock;
            std::deque<std::vector<std::uint8_t>> tx_queue;
            capy::async_event tx_wake;
            bool closed = false;
            explicit ControlChannel(corosio::io_context& io) : sock(io) {}

            auto send_frame(rt::Frame const& f) -> bool {
                if (closed || tx_queue.size() >= 512) return false;
                auto enc = rt::encode_frame(f);
                if (!enc) return false;
                tx_queue.push_back(std::move(*enc));
                tx_wake.set();
                return true;
            }
            auto close() noexcept -> void {
                closed = true;
                tx_wake.set();
                sock.cancel();
            }
        };

        struct ReverseTunnelState {
            config::ReverseTunnelServiceConfig cfg;
            rt::TunnelSession session;
            corosio::endpoint target_ep;
            corosio::endpoint control_ep;
            std::uint16_t bound_control_port = 0;
            std::uint16_t bound_expose_port = 0;
            std::uint32_t next_sid = 1;
            std::atomic_bool stopping{false};
            std::mutex state_mu;
            std::shared_ptr<ControlChannel> active_ctrl;
            std::vector<std::shared_ptr<ControlChannel>> pending_ctrls;
            std::unordered_map<std::uint32_t, std::shared_ptr<MuxStream>> streams;
            // Declared after all coroutine-referenced state so ~io_context() destroys
            // suspended stream/control frames while state_mu/streams/session remain alive.
            std::mutex shutdown_mu;
            std::condition_variable shutdown_cv;
            bool shutdown_done = false, worker_done = false;
            corosio::io_context io;
            corosio::tcp_acceptor ctrl_acc{io};
            corosio::tcp_acceptor expose_acc{io};
            std::jthread worker;

            explicit ReverseTunnelState(config::ReverseTunnelServiceConfig c)
                : cfg(std::move(c)), session(cfg.token, cfg.max_streams) {}

            ~ReverseTunnelState() { stop(); }

            auto close_all_streams() noexcept -> void {
                std::lock_guard lk(state_mu);
                for (auto& [_, s] : streams) s->cancel();
                streams.clear();
            }

            auto close_on_io() noexcept -> void {
                ctrl_acc.close();
                expose_acc.close();
                std::lock_guard lk(state_mu);
                if (active_ctrl) active_ctrl->close();
                for (auto& p : pending_ctrls) p->close();
                for (auto& [_, s] : streams) s->cancel();
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
                if (!worker.joinable()) close_on_io();
                else {
                    try {
                        capy::run_async(io.get_executor())(shutdown_task());
                        std::unique_lock lk(shutdown_mu);
                        shutdown_cv.wait_for(lk, std::chrono::seconds(2), [&] { return shutdown_done || worker_done; });
                    } catch (...) {}
                    io.stop(); worker.join();
                }
                std::lock_guard lk(state_mu); active_ctrl.reset(); pending_ctrls.clear(); streams.clear();
            }

            auto ctrl_writer(std::shared_ptr<ControlChannel> ch) -> capy::task<capy::results<>> {
                while (!ch->closed && !stopping.load(std::memory_order_acquire)) {
                    if (ch->tx_queue.empty()) { ch->tx_wake.clear(); co_await ch->tx_wake.wait(); continue; }
                    auto wire = std::move(ch->tx_queue.front()); ch->tx_queue.pop_front();
                    if (!co_await write_all(ch->sock, wire)) break;
                }
                ch->close(); co_return capy::results<>{};
            }

            auto pump_stream_to_ctrl(std::shared_ptr<ControlChannel> ch, std::shared_ptr<MuxStream> st)
                -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 16384> buf{};
                while (!st->closed && !ch->closed && !stopping.load(std::memory_order_acquire)) {
                    auto [ec, n] = co_await st->sock->read_some(capy::mutable_buffer(buf.data(), buf.size()));
                    if (ec || n == 0) break;
                    rt::Frame f{.kind = rt::FrameKind::stream_data, .stream_id = st->id,
                        .payload = std::vector<std::uint8_t>(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n))};
                    (void)session.on_data(st->id, n);
                    if (!ch->send_frame(f)) break;
                }
                if (!ch->closed) {
                    if (auto fin = session.close_local(st->id)) (void)ch->send_frame(*fin);
                    else (void)ch->send_frame({rt::FrameKind::half_close, st->id, {}});
                }
                co_return capy::results<>{};
            }

            auto pump_ctrl_to_stream(std::shared_ptr<MuxStream> st) -> capy::task<capy::results<>> {
                while (!st->closed && !stopping.load(std::memory_order_acquire)) {
                    if (st->rx_queue.empty()) {
                        if (st->remote_fin) { (void)st->sock->shutdown(corosio::shutdown_send); break; }
                        st->rx_wake.clear(); co_await st->rx_wake.wait(); continue;
                    }
                    auto chunk = std::move(st->rx_queue.front()); st->rx_queue.pop_front();
                    if (!co_await write_all(*st->sock, chunk)) break;
                }
                co_return capy::results<>{};
            }

            auto erase_session_stream(std::uint32_t sid) noexcept -> void {
                (void)session.close_local(sid);
                (void)session.on_remote_half_close(sid);
            }

            auto run_stream(std::shared_ptr<ControlChannel> ch, std::shared_ptr<MuxStream> st, corosio::tcp_socket sock)
                -> capy::task<> {
                struct Guard {
                    ReverseTunnelState& owner; std::uint32_t sid; std::shared_ptr<MuxStream> s;
                    ~Guard() {
                        std::lock_guard lk(owner.state_mu);
                        s->cancel(); s->sock = nullptr;
                        if (auto it = owner.streams.find(sid); it != owner.streams.end() && it->second == s) {
                            owner.streams.erase(it);
                            owner.erase_session_stream(sid);
                        }
                    }
                } g{*this, st->id, st};
                {
                    std::lock_guard lk(state_mu);
                    if (st->closed || stopping.load(std::memory_order_acquire)) co_return;
                    st->sock = &sock;
                }
                (void)co_await capy::when_all(pump_stream_to_ctrl(ch, st), pump_ctrl_to_stream(st));
            }

            auto client_open_target(std::shared_ptr<ControlChannel> ch, std::shared_ptr<MuxStream> st) -> capy::task<> {
                auto const sid = st->id;
                struct OpenGuard {
                    ReverseTunnelState& owner; std::shared_ptr<MuxStream> s; bool handed_off = false;
                    ~OpenGuard() {
                        if (handed_off) return;
                        std::lock_guard lk(owner.state_mu);
                        s->cancel();
                        if (auto it = owner.streams.find(s->id); it != owner.streams.end() && it->second == s)
                            owner.streams.erase(it);
                    }
                } og{*this, st};
                corosio::tcp_socket target(io);
                if (target.open()) { (void)ch->send_frame({rt::FrameKind::reset_stream, sid, {}}); co_return; }
                auto [ce] = co_await corosio::timeout(target.connect(target_ep), Clock::now() + 5s);
                if (ce || ch->closed || stopping.load(std::memory_order_acquire)) {
                    (void)ch->send_frame({rt::FrameKind::reset_stream, sid, {}}); co_return;
                }
                {
                    std::lock_guard lk(state_mu);
                    auto it = streams.find(sid);
                    if (it == streams.end() || it->second != st || st->closed) co_return;
                }
                og.handed_off = true;
                co_await run_stream(ch, std::move(st), std::move(target));
            }

            auto handle_ctrl_frame(std::shared_ptr<ControlChannel> ch, rt::Frame const& f, bool is_server) -> bool {
                if (is_server && (!session.registered() || active_ctrl != ch)) return false;
                switch (f.kind) {
                case rt::FrameKind::register_req:
                    return false;
                case rt::FrameKind::register_ack:
                    return !is_server && !f.payload.empty() && f.payload[0] == 1;
                case rt::FrameKind::ping:
                    return ch->send_frame(session.on_heartbeat(now_ms()));
                case rt::FrameKind::pong:
                    (void)session.on_heartbeat(now_ms());
                    return true;
                case rt::FrameKind::open_stream: {
                    std::shared_ptr<MuxStream> st;
                    {
                        std::lock_guard lk(state_mu);
                        if (is_server || streams.size() >= cfg.max_streams || streams.contains(f.stream_id)) {
                            (void)ch->send_frame({rt::FrameKind::reset_stream, f.stream_id, {}}); return true;
                        }
                        st = std::make_shared<MuxStream>(); st->id = f.stream_id; streams[f.stream_id] = st;
                    }
                    capy::run_async(io.get_executor())(client_open_target(ch, std::move(st)));
                    return true;
                }
                case rt::FrameKind::stream_data: {
                    std::shared_ptr<MuxStream> st;
                    { std::lock_guard lk(state_mu); if (auto it = streams.find(f.stream_id); it != streams.end()) st = it->second; }
                    if (st) { (void)session.on_data(f.stream_id, f.payload.size()); st->push(f.payload); }
                    return true;
                }
                case rt::FrameKind::half_close: {
                    std::shared_ptr<MuxStream> st;
                    { std::lock_guard lk(state_mu); if (auto it = streams.find(f.stream_id); it != streams.end()) st = it->second; }
                    if (st) { (void)session.on_remote_half_close(f.stream_id); st->finish_remote(); }
                    return true;
                }
                case rt::FrameKind::reset_stream: {
                    std::lock_guard lk(state_mu);
                    if (auto it = streams.find(f.stream_id); it != streams.end()) it->second->cancel();
                    erase_session_stream(f.stream_id);
                    return true;
                }
                }
                return false;
            }

            auto ctrl_reader(std::shared_ptr<ControlChannel> ch, bool is_server, std::vector<std::uint8_t> buf = {})
                -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 16384> tmp{};
                auto hb = std::chrono::milliseconds(cfg.heartbeat_timeout_ms);
                auto process_buf = [&]() -> bool {
                    std::size_t off = 0;
                    while (off < buf.size()) {
                        auto dec = rt::decode_frame(std::span(buf).subspan(off));
                        if (!dec) { if (dec.error() == "incomplete") break; return false; }
                        off += dec->second;
                        if (!handle_ctrl_frame(ch, dec->first, is_server)) return false;
                    }
                    if (off > 0) buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(off));
                    return true;
                };
                if (!buf.empty() && !process_buf()) { ch->close(); co_return capy::results<>{}; }
                while (!ch->closed && !stopping.load(std::memory_order_acquire)) {
                    auto [ec, n] = co_await corosio::timeout(
                        ch->sock.read_some(capy::mutable_buffer(tmp.data(), tmp.size())), Clock::now() + hb);
                    if (ec || n == 0) break;
                    buf.insert(buf.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(n));
                    if (!process_buf()) break;
                }
                ch->close();
                co_return capy::results<>{};
            }

            auto serve_server_ctrl(std::shared_ptr<ControlChannel> ch) -> capy::task<> {
                struct PendingGuard {
                    ReverseTunnelState& owner; std::shared_ptr<ControlChannel> ch;
                    ~PendingGuard() { std::lock_guard lk(owner.state_mu); std::erase(owner.pending_ctrls, ch); }
                } pg{*this, ch};
                std::vector<std::uint8_t> buf;
                std::array<std::uint8_t, 4096> tmp{};
                auto dl = Clock::now() + std::min<std::chrono::milliseconds>(5s, std::chrono::milliseconds(cfg.heartbeat_timeout_ms));
                std::optional<rt::Frame> reg_frame;
                while (!ch->closed && !stopping.load(std::memory_order_acquire) && buf.size() < 4096) {
                    auto [ec, n] = co_await corosio::timeout(ch->sock.read_some(capy::mutable_buffer(tmp.data(), tmp.size())), dl);
                    if (ec || n == 0) co_return;
                    buf.insert(buf.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(n));
                    auto dec = rt::decode_frame(buf);
                    if (!dec) { if (dec.error() == "incomplete") continue; co_return; }
                    buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(dec->second));
                    reg_frame = std::move(dec->first);
                    break;
                }
                if (!reg_frame || reg_frame->kind != rt::FrameKind::register_req) co_return;
                std::string_view tok(reinterpret_cast<char const*>(reg_frame->payload.data()), reg_frame->payload.size());
                rt::TunnelSession verifier(cfg.token, 1);
                auto check = verifier.handle_register(tok, now_ms());
                if (check.payload.empty() || check.payload[0] != 1) {
                    if (auto enc = rt::encode_frame(check)) (void)co_await write_all(ch->sock, *enc);
                    co_return;
                }
                {
                    std::lock_guard lk(state_mu);
                    std::erase(pending_ctrls, ch);
                    if (active_ctrl) active_ctrl->close();
                    for (auto& [_, s] : streams) s->cancel();
                    streams.clear();
                    session.reset_all_for_reconnect();
                    auto ack = session.handle_register(tok, now_ms());
                    active_ctrl = ch;
                    (void)ch->send_frame(ack);
                }
                (void)co_await capy::when_all(ctrl_writer(ch), ctrl_reader(ch, true, std::move(buf)));
                std::lock_guard lk(state_mu);
                if (active_ctrl == ch) {
                    active_ctrl.reset();
                    for (auto& [_, s] : streams) s->cancel();
                    streams.clear();
                    session.reset_all_for_reconnect();
                }
            }

            auto server_ctrl_accept() -> capy::task<> {
                while (!stopping.load(std::memory_order_acquire)) {
                    auto [ec, s] = co_await ctrl_acc.accept();
                    if (ec) break;
                    auto ch = std::make_shared<ControlChannel>(io);
                    ch->sock = std::move(s);
                    {
                        std::lock_guard lk(state_mu);
                        if (pending_ctrls.size() >= 8) { ch->sock.close(); continue; }
                        pending_ctrls.push_back(ch);
                    }
                    capy::run_async(io.get_executor())(serve_server_ctrl(std::move(ch)));
                }
            }

            auto server_expose_accept() -> capy::task<> {
                while (!stopping.load(std::memory_order_acquire)) {
                    auto [ec, s] = co_await expose_acc.accept();
                    if (ec) break;
                    std::shared_ptr<ControlChannel> ch;
                    { std::lock_guard lk(state_mu); ch = active_ctrl; }
                    if (!ch || ch->closed || !session.registered()) { s.close(); continue; }
                    auto sid = next_sid++;
                    if (sid == 0) sid = next_sid++;
                    auto opened = session.open_stream(sid);
                    if (!opened || !ch->send_frame(*opened)) { erase_session_stream(sid); s.close(); continue; }
                    auto st = std::make_shared<MuxStream>();
                    st->id = sid;
                    {
                        std::lock_guard lk(state_mu);
                        streams[sid] = st;
                    }
                    capy::run_async(io.get_executor())(run_stream(ch, st, std::move(s)));
                }
            }

            auto client_heartbeat(std::shared_ptr<ControlChannel> ch) -> capy::task<capy::results<>> {
                corosio::steady_timer t(io);
                auto period = std::chrono::milliseconds(std::max<std::uint32_t>(cfg.heartbeat_timeout_ms / 3, 50));
                while (!ch->closed && !stopping.load(std::memory_order_acquire)) {
                    t.expires_after(period);
                    auto [ec] = co_await t.wait();
                    if (ec || ch->closed) break;
                    if (!ch->send_frame({rt::FrameKind::ping, 0, {}})) break;
                }
                co_return capy::results<>{};
            }

            auto client_loop() -> capy::task<> {
                corosio::steady_timer backoff(io);
                while (!stopping.load(std::memory_order_acquire)) {
                    auto ch = std::make_shared<ControlChannel>(io);
                    if (!ch->sock.open()) {
                        auto [ce] = co_await corosio::timeout(ch->sock.connect(control_ep), Clock::now() + 5s);
                        if (!ce && !stopping.load(std::memory_order_acquire)) {
                            {
                                std::lock_guard lk(state_mu);
                                active_ctrl = ch;
                            }
                            rt::Frame reg{.kind = rt::FrameKind::register_req, .stream_id = 0,
                                .payload = std::vector<std::uint8_t>(cfg.token.begin(), cfg.token.end())};
                            (void)ch->send_frame(reg);
                            (void)co_await capy::when_all(
                                ctrl_writer(ch), ctrl_reader(ch, false), client_heartbeat(ch));
                            {
                                std::lock_guard lk(state_mu);
                                if (active_ctrl == ch) active_ctrl.reset();
                            }
                            close_all_streams();
                        }
                    }
                    if (stopping.load(std::memory_order_acquire)) break;
                    backoff.expires_after(100ms);
                    (void)co_await backoff.wait();
                }
            }
        };
    }

    auto init_reverse_tunnel_service(config::ReverseTunnelServiceConfig const& cfg, logging::Runtime& logs)
        -> std::expected<ServiceHandle, std::string> {
        if (cfg.token.empty()) return std::unexpected("reverse-tunnel: token is required");
        auto ctrl_ep = parse_ip_ep(cfg.control_host, cfg.control_port);
        if (!ctrl_ep) return std::unexpected(ctrl_ep.error());

        auto st = std::make_unique<ReverseTunnelState>(cfg);
        st->control_ep = *ctrl_ep;
        if (cfg.mode == "server") {
            auto exp_ep = parse_ip_ep(cfg.expose_host, cfg.expose_port);
            if (!exp_ep) return std::unexpected(exp_ep.error());
            if (auto ec = st->ctrl_acc.open(); ec) return std::unexpected("reverse-tunnel ctrl open: " + ec.message());
            if (auto ec = st->ctrl_acc.bind(*ctrl_ep); ec) return std::unexpected("reverse-tunnel ctrl bind: " + ec.message());
            if (auto ec = st->ctrl_acc.listen(); ec) return std::unexpected("reverse-tunnel ctrl listen: " + ec.message());
            if (auto ec = st->expose_acc.open(); ec) return std::unexpected("reverse-tunnel expose open: " + ec.message());
            if (auto ec = st->expose_acc.bind(*exp_ep); ec) return std::unexpected("reverse-tunnel expose bind: " + ec.message());
            if (auto ec = st->expose_acc.listen(); ec) return std::unexpected("reverse-tunnel expose listen: " + ec.message());
            st->bound_control_port = st->ctrl_acc.local_endpoint().port();
            st->bound_expose_port = st->expose_acc.local_endpoint().port();
            capy::run_async(st->io.get_executor())(st->server_ctrl_accept());
            capy::run_async(st->io.get_executor())(st->server_expose_accept());
        } else if (cfg.mode == "client") {
            if (cfg.control_port == 0 || cfg.target_port == 0)
                return std::unexpected("reverse-tunnel client requires control_port and target_port");
            auto tep = parse_ip_ep(cfg.target_host, cfg.target_port);
            if (!tep) return std::unexpected(tep.error());
            st->target_ep = *tep;
            capy::run_async(st->io.get_executor())(st->client_loop());
        } else {
            return std::unexpected("reverse-tunnel: invalid mode: " + cfg.mode);
        }

        st->worker = std::jthread([ptr = st.get()] {
            ptr->io.run();
            { std::lock_guard lk(ptr->shutdown_mu); ptr->worker_done = true; }
            ptr->shutdown_cv.notify_all();
        });
        logs.emit(logging::Level::info, logging::Domain::core, 101, {},
            "reverse-tunnel started (mode={}, control_port={}, expose_port={})",
            cfg.mode, st->bound_control_port, st->bound_expose_port);
        return ServiceHandle::create(std::move(st));
    }

    auto reverse_tunnel_control_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        return h.state ? static_cast<ReverseTunnelState const*>(h.state.get())->bound_control_port : 0;
    }
    auto reverse_tunnel_expose_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        return h.state ? static_cast<ReverseTunnelState const*>(h.state.get())->bound_expose_port : 0;
    }
}
