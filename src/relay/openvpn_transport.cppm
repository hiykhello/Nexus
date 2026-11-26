module;
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>

export module relay:openvpn_transport;
import std;
import containers.ring_queue;
import config;
import platform.socket_options;
import net.udp_socket;
import tls.profiles;
import tls.client_handshake_io;
import tls.application_io;
import openvpn.types;
import openvpn.wire;
import openvpn.control;
import openvpn.session;
import capy;
import corosio;
import relay.l3_mux;
import :types;
import :tunnel_facade;
import :session_interface;

export namespace relay::ovpn_detail {
    namespace io = ::corosio;

    inline auto now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
    }

    struct SocketBinder {
        platform::SocketBinding const& binding;
        Clock::time_point deadline;
        auto operator()(int fd) const noexcept -> std::error_code {
            return binding.configured() ? platform::apply_socket_binding(fd, binding, true, deadline) : std::error_code{};
        }
    };

    struct HostState : std::enable_shared_from_this<HostState> {
        io::io_context& context;
        config::OpenVpnOutbound const& cfg;
        tls::ShapedClientProfile const& tls;
        std::string const& password;
        platform::SocketBinding binding;
        TunnelFactory const* via;
        net::UdpSocket udp;
        net::UdpEndpoint udp_target{};
        std::optional<io::tcp_socket> tcp;
        pro::proxy<TunnelFacade> detour_tunnel;
        std::unique_ptr<Session> detour_session;
        std::vector<std::uint8_t> tcp_rx_buf;
        std::size_t tcp_rx_head = 0;
        auto consume_tcp_rx(std::size_t n) -> void {
            tcp_rx_head += n;
            if (tcp_rx_head == tcp_rx_buf.size()) { tcp_rx_buf.clear(); tcp_rx_head = 0; }
            else if (tcp_rx_head >= 4096 && tcp_rx_head * 2 >= tcp_rx_buf.size()) {
                tcp_rx_buf.erase(tcp_rx_buf.begin(), tcp_rx_buf.begin() + static_cast<std::ptrdiff_t>(tcp_rx_head));
                tcp_rx_head = 0;
            }
        }
        openvpn::DataChannel data;
        openvpn::Cipher active_cipher;
        std::uint64_t local_sid = 0;
        std::uint32_t peer_id = 0;
        std::uint16_t ping_s = 10, ping_restart_s = 60;
        static constexpr std::size_t kTxQueueCap = 256;
        L3Mux mux;
        containers::RingQueue<kTxQueueCap> tx_ring;
        std::array<std::vector<std::uint8_t>, kTxQueueCap> tx_slots;
        auto tx_push(std::vector<std::uint8_t> pkt) noexcept -> bool {
            if (tx_ring.full()) return false;
            tx_slots[tx_ring.tail()] = std::move(pkt);
            tx_ring.commit();
            return true;
        }
        capy::async_event ready_event, tx_event;
        std::stop_source stop_src;
        std::uint64_t last_tx_ms = 0, last_rx_ms = 0;
        bool started = false, connecting = false, stopped = false, loop_active = false, use_tcp = false;

        HostState(io::io_context& ctx, config::OpenVpnOutbound const& c, tls::ShapedClientProfile const& t,
                  std::string const& pw, platform::SocketBinding b, TunnelFactory const* d)
            : context(ctx), cfg(c), tls(t), password(pw), binding(std::move(b)), via(d),
              active_cipher(c.cipher == config::OpenVpnCipher::chacha20_poly1305
                  ? openvpn::Cipher::chacha20_poly1305 : openvpn::Cipher::aes_256_gcm),
              ping_s(c.keepalive_s),
              mux(L3Endpoint{c.has_v4, c.local_v4, c.has_v6, c.local_v6, c.mtu}, &HostState::send_ip, this),
              use_tcp(c.transport == config::OpenVpnTransport::tcp || d != nullptr) {}

        static auto send_ip(void* ctx, std::span<std::uint8_t const> pkt) -> bool {
            auto* h = static_cast<HostState*>(ctx);
            if (h->stopped || !h->data.ready()) return false;
            auto sealed = h->data.seal_data_v2(pkt);
            if (!sealed) return false;
            h->last_tx_ms = now_ms();
            if (!h->use_tcp) {
                if (h->udp.send(h->udp_target, *sealed).has_value()) return true;
                return h->tx_push(std::move(*sealed));
            }
            auto framed = openvpn::encode_tcp_frame(*sealed);
            if (!framed || !h->tx_push(std::move(*framed))) return false;
            h->tx_event.set();
            return true;
        }

        auto send_wire(std::span<std::uint8_t const> pkt) -> capy::task<bool> {
            if (stopped) co_return false;
            if (!use_tcp) co_return udp.send(udp_target, pkt).has_value();
            auto framed = openvpn::encode_tcp_frame(pkt);
            if (!framed) co_return false;
            if (detour_tunnel) co_return co_await detour_tunnel->send(*framed);
            if (!tcp || !tcp->is_open()) co_return false;
            std::span<std::uint8_t const> rest = *framed;
            while (!rest.empty()) {
                auto [ec, n] = co_await tcp->write_some(capy::const_buffer(rest.data(), rest.size()));
                if (ec || n == 0 || n > rest.size()) co_return false;
                rest = rest.subspan(n);
            }
            co_return true;
        }

        auto recv_wire(Clock::time_point deadline) -> capy::task<std::optional<std::vector<std::uint8_t>>> {
            if (!use_tcp) {
                std::array<std::uint8_t, 4096> buf{};
                while (!stopped && Clock::now() < deadline) {
                    auto r = udp.receive(buf);
                    if (!r) co_return std::nullopt;
                    if (*r) {
                        if ((*r)->valid && (*r)->source == udp_target)
                            co_return std::vector<std::uint8_t>(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>((*r)->size));
                        continue;
                    }
                    auto [ec] = co_await io::timeout(io::delay(std::chrono::milliseconds(2)), deadline);
                    if (ec && ec != capy::cond::timeout) co_return std::nullopt;
                }
                co_return std::nullopt;
            }
            for (;;) {
                auto dec = openvpn::decode_tcp_frame(std::span(tcp_rx_buf).subspan(tcp_rx_head));
                if (!dec) co_return std::nullopt;
                if (*dec) {
                    auto pkt = std::move((*dec)->first);
                    consume_tcp_rx((*dec)->second);
                    co_return pkt;
                }
                if (tcp_rx_buf.size() - tcp_rx_head > 65536 || stopped || Clock::now() >= deadline) co_return std::nullopt;
                std::array<std::uint8_t, 4096> tmp{};
                if (detour_tunnel) {
                    auto r = co_await detour_tunnel->read(tmp);
                    if (!r || *r == 0) co_return std::nullopt;
                    tcp_rx_buf.insert(tcp_rx_buf.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(*r));
                } else if (tcp && tcp->is_open()) {
                    auto [ec, n] = co_await io::timeout(tcp->read_some(capy::mutable_buffer(tmp.data(), tmp.size())), deadline);
                    if (ec || n == 0) co_return std::nullopt;
                    tcp_rx_buf.insert(tcp_rx_buf.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(n));
                } else co_return std::nullopt;
            }
        }

        auto send_ctrl_packets(std::vector<openvpn::ControlPacket> const& pkts) -> capy::task<bool> {
            for (auto const& p : pkts) {
                auto w = openvpn::encode_control_packet(p);
                if (!w || !co_await send_wire(*w)) co_return false;
            }
            co_return true;
        }

        auto pump_app_send(tls::ApplicationIo& app, openvpn::ControlChannel& ctrl, std::span<std::uint8_t const> msg) -> capy::task<bool> {
            if (!app.send(msg)) co_return false;
            while (!app.pending_output().empty()) {
                auto out = app.pending_output();
                std::size_t n = out.size();
                auto pkts = ctrl.enqueue_tls_bytes(out, now_ms());
                if (pkts.empty() || !co_await send_ctrl_packets(pkts) || !app.written(n)) co_return false;
            }
            co_return true;
        }

        auto pump_app_recv(tls::ApplicationIo& app, openvpn::ControlChannel& ctrl, std::vector<std::uint8_t>& tls_rx,
                           std::vector<std::uint8_t>& plain_out, Clock::time_point dl) -> capy::task<bool> {
            for (;;) {
                while (!tls_rx.empty()) {
                    auto fed = app.feed(tls_rx);
                    if (!fed) co_return false;
                    tls_rx.erase(tls_rx.begin(), tls_rx.begin() + static_cast<std::ptrdiff_t>(fed->consumed));
                    while (!app.pending_output().empty()) {
                        auto out = app.pending_output();
                        std::size_t n = out.size();
                        auto pkts = ctrl.enqueue_tls_bytes(out, now_ms());
                        if (pkts.empty() || !co_await send_ctrl_packets(pkts) || !app.written(n)) co_return false;
                    }
                    if (fed->event && fed->event->kind == tls::ApplicationEventKind::data)
                        plain_out.insert(plain_out.end(), fed->event->data.begin(), fed->event->data.end());
                    else if (fed->event && (fed->event->kind == tls::ApplicationEventKind::close_notify ||
                                            fed->event->kind == tls::ApplicationEventKind::fatal_alert))
                        co_return false;
                    if (!fed->consumed) break;
                }
                if (!plain_out.empty()) co_return true;
                auto pkt = co_await recv_wire(dl);
                if (!pkt) co_return false;
                auto cp = openvpn::decode_control_packet(*pkt);
                if (!cp) continue;
                auto tls_chunk = ctrl.on_packet(*cp, now_ms());
                if (!tls_chunk) co_return false;
                if (auto ack = ctrl.take_ack()) {
                    auto aw = openvpn::encode_control_packet(*ack);
                    if (!aw || !co_await send_wire(*aw)) co_return false;
                }
                tls_rx.insert(tls_rx.end(), tls_chunk->begin(), tls_chunk->end());
            }
        }

        auto handle_wire_data(std::span<std::uint8_t const> wire, std::uint64_t ms) -> void {
            if (wire.empty()) return;
            auto op = static_cast<std::uint8_t>((wire[0] >> 3) & 0x1f);
            if (op == static_cast<std::uint8_t>(openvpn::Opcode::data_v2)) {
                auto plain = data.open_data_v2(wire);
                if (!plain) return;
                constexpr std::array<std::uint8_t, 16> occ_magic{
                    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
                    0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c};
                if (plain->size() >= occ_magic.size() &&
                    std::ranges::equal(std::span(*plain).first<16>(), occ_magic)) {
                    if (plain->size() >= 17 && (*plain)[16] == 5) { stop(); return; }
                    last_rx_ms = ms;
                    return;
                }
                last_rx_ms = ms;
                if (plain->size() == openvpn::ping_magic.size() && std::ranges::equal(*plain, openvpn::ping_magic)) return;
                mux.on_ip_packet(*plain, ms);
            } else if (auto cp = openvpn::decode_control_packet(wire); cp && cp->packet_id && cp->session_id != 0) {
                openvpn::ControlPacket ack{.opcode = openvpn::Opcode::ack_v1, .key_id = cp->key_id,
                    .session_id = local_sid, .acks = {*cp->packet_id}, .remote_session_id = cp->session_id};
                if (auto w = openvpn::encode_control_packet(ack)) {
                    if (!use_tcp) (void)udp.send(udp_target, *w);
                    else if (auto f = openvpn::encode_tcp_frame(*w); f && tx_push(std::move(*f))) {
                        tx_event.set();
                    }
                }
            }
        }

        static auto udp_loop(HostState* h) -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 4096> buf{};
            while (!h->stopped && !h->stop_src.stop_requested()) {
                bool moved = false;
                while (auto r = h->udp.receive(buf)) {
                    if (!*r) break;
                    if ((*r)->valid && (*r)->source == h->udp_target) {
                        h->handle_wire_data(std::span(buf).first((*r)->size), now_ms());
                        if (h->stopped) co_return capy::results<>{};
                    }
                    moved = true;
                }
                while (!h->tx_ring.empty()) {
                    auto const idx = h->tx_ring.front();
                    if (!h->udp.send(h->udp_target, h->tx_slots[idx])) break;
                    h->tx_slots[idx].clear();
                    h->tx_ring.consume();
                    moved = true;
                }
                auto ms = now_ms();
                h->mux.tick(ms);
                if (h->ping_s > 0 && ms - h->last_tx_ms >= static_cast<std::uint64_t>(h->ping_s) * 1000) {
                    if (auto ping = h->data.seal_data_v2(openvpn::ping_magic)) {
                        h->last_tx_ms = ms;
                        (void)h->udp.send(h->udp_target, *ping);
                    }
                }
                if (h->ping_restart_s > 0 && h->last_rx_ms > 0 &&
                    ms - h->last_rx_ms >= static_cast<std::uint64_t>(h->ping_restart_s) * 1000) { h->stop(); break; }
                auto [ec] = co_await io::delay(moved ? std::chrono::milliseconds(1)
                    : (h->mux.active() ? std::chrono::milliseconds(2) : std::chrono::milliseconds(10)));
                if (ec) break;
            }
            h->stop();
            co_return capy::results<>{};
        }

        static auto tcp_rx_loop(HostState* h) -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 4096> tmp{};
            while (!h->stopped && !h->stop_src.stop_requested()) {
                for (;;) {
                    auto dec = openvpn::decode_tcp_frame(std::span(h->tcp_rx_buf).subspan(h->tcp_rx_head));
                    if (!dec) { h->stop(); co_return capy::results<>{}; }
                    if (!*dec) break;
                    auto pkt = std::move((*dec)->first);
                    h->consume_tcp_rx((*dec)->second);
                    h->handle_wire_data(pkt, now_ms());
                    if (h->stopped) co_return capy::results<>{};
                }
                if (h->detour_tunnel) {
                    auto r = co_await h->detour_tunnel->read(tmp);
                    if (!r || *r == 0) break;
                    h->tcp_rx_buf.insert(h->tcp_rx_buf.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(*r));
                } else if (h->tcp && h->tcp->is_open()) {
                    auto [ec, n] = co_await h->tcp->read_some(capy::mutable_buffer(tmp.data(), tmp.size()));
                    if (ec || n == 0) break;
                    h->tcp_rx_buf.insert(h->tcp_rx_buf.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(n));
                } else break;
            }
            h->stop();
            co_return capy::results<>{};
        }

        static auto tcp_tx_loop(HostState* h) -> capy::task<capy::results<>> {
            while (!h->stopped && !h->stop_src.stop_requested()) {
                h->tx_event.clear();
                if (h->tx_ring.empty()) {
                    auto [ec] = co_await h->tx_event.wait();
                    if (ec) break;
                    continue;
                }
                auto const idx = h->tx_ring.front();
                auto pkt = std::move(h->tx_slots[idx]);
                h->tx_ring.consume();
                bool ok = true;
                if (h->detour_tunnel) ok = co_await h->detour_tunnel->send(pkt);
                else if (h->tcp && h->tcp->is_open()) {
                    std::span<std::uint8_t const> rest = pkt;
                    while (!rest.empty()) {
                        auto [ec, n] = co_await h->tcp->write_some(capy::const_buffer(rest.data(), rest.size()));
                        if (ec || n == 0 || n > rest.size()) { ok = false; break; }
                        rest = rest.subspan(n);
                    }
                } else ok = false;
                if (!ok) break;
            }
            h->stop();
            co_return capy::results<>{};
        }

        static auto tcp_timer_loop(HostState* h) -> capy::task<capy::results<>> {
            while (!h->stopped && !h->stop_src.stop_requested()) {
                auto ms = now_ms();
                h->mux.tick(ms);
                if (h->ping_s > 0 && ms - h->last_tx_ms >= static_cast<std::uint64_t>(h->ping_s) * 1000) {
                    if (auto ping = h->data.seal_data_v2(openvpn::ping_magic)) {
                        if (auto f = openvpn::encode_tcp_frame(*ping); f && h->tx_push(std::move(*f))) {
                            h->last_tx_ms = ms;
                            h->tx_event.set();
                        }
                    }
                }
                if (h->ping_restart_s > 0 && h->last_rx_ms > 0 &&
                    ms - h->last_rx_ms >= static_cast<std::uint64_t>(h->ping_restart_s) * 1000) { h->stop(); break; }
                auto [ec] = co_await io::delay(h->mux.active() ? std::chrono::milliseconds(2) : std::chrono::milliseconds(10));
                if (ec) break;
            }
            co_return capy::results<>{};
        }

        auto stop() noexcept -> void {
            if (stopped) return;
            stopped = true;
            stop_src.request_stop();
            ready_event.set();
            tx_event.set();
            mux.reset_flows();
            if (detour_tunnel) detour_tunnel->cancel();
            if (detour_session) detour_session->close();
            if (tcp) tcp->cancel();
            udp.close();
        }
    };
}
