// Shared user-space L3 IP <-> active TCP / UDP-NAT multiplexer for WireGuard & CONNECT-IP outbounds.
module;
#include <boost/capy/ex/async_event.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>

export module relay.l3_mux;
import std;
import containers.ring_queue;
import packet;
import tcp.send;
import tcp.receive;
import capy;
import corosio;

export namespace relay {
    struct L3Endpoint {
        bool has_v4 = true;
        std::array<std::uint8_t, 4> local_v4{10, 0, 0, 2};
        bool has_v6 = false;
        std::array<std::uint8_t, 16> local_v6{};
        std::uint16_t mtu = 1420;
    };

    class L3Mux {
    public:
        using SendPacketFn = bool (*)(void* ctx, std::span<std::uint8_t const> packet);

        struct TcpFlow {
            enum class State { syn_sent, established, closed };
            bool is_v6 = false;
            std::array<std::uint8_t, 16> remote{};
            std::uint16_t remote_port = 0, local_port = 0, peer_mss = 1360;
            std::uint32_t peer_window = 65535;
            std::uint16_t last_rx_win = 65535;
            State state = State::syn_sent;
            std::uint32_t iss = 0;
            std::uint64_t syn_deadline = 0;
            unsigned syn_retries = 0;
            std::optional<tcp::TimedSend> send;
            std::optional<tcp::ReceiveBuffer> recv;
            bool fin_requested = false, fin_sent = false, fin_acked = false;
            std::uint32_t fin_seq = 0;
            std::uint64_t fin_deadline = 0;
            unsigned fin_retries = 0;
            std::uint64_t persist_deadline = 0;
            unsigned persist_retries = 0;
            capy::async_event changed;
        };

        struct UdpDatagram {
            bool is_v6 = false;
            std::array<std::uint8_t, 16> source{};
            std::uint16_t source_port = 0;
            std::vector<std::uint8_t> payload;
        };

        struct UdpFlow {
            std::uint16_t local_port = 0;
            bool closed = false;
            containers::BoundedRing<UdpDatagram, 128> rx_queue;
            capy::async_event rx_event;
        };

    private:
        // Contiguous active vector + open-addressed local_port index (backward-shift delete).
        template<class Flow>
        class PortTable {
            static constexpr std::uint32_t kNull = std::numeric_limits<std::uint32_t>::max();
            std::vector<std::shared_ptr<Flow>> items_;
            std::vector<std::uint32_t> buckets_;
            std::size_t mask_ = 0;

            static constexpr auto hash_port(std::uint16_t port) noexcept -> std::size_t {
                return static_cast<std::size_t>((static_cast<std::uint32_t>(port) * 2654435761u) >> 16);
            }
            auto insert_bucket(std::uint16_t port, std::uint32_t idx) noexcept -> void {
                for (std::size_t pos = hash_port(port) & mask_; ; pos = (pos + 1) & mask_) {
                    if (buckets_[pos] == kNull) { buckets_[pos] = idx; return; }
                }
            }
            auto ensure_capacity(std::size_t target) -> void {
                if (!buckets_.empty() && target * 2 <= buckets_.size()) return;
                std::size_t bsz = buckets_.empty() ? 32 : buckets_.size() * 2;
                while (bsz < target * 2) bsz <<= 1;
                buckets_.assign(bsz, kNull);
                mask_ = bsz - 1;
                for (std::uint32_t i = 0; i < items_.size(); ++i) insert_bucket(items_[i]->local_port, i);
            }
            [[nodiscard]] auto find_bucket(std::uint16_t port) const noexcept -> std::size_t {
                if (buckets_.empty() || items_.empty()) return buckets_.size();
                for (std::size_t pos = hash_port(port) & mask_; ; pos = (pos + 1) & mask_) {
                    auto cur = buckets_[pos];
                    if (cur == kNull) return buckets_.size();
                    if (items_[cur]->local_port == port) return pos;
                }
            }
        public:
            [[nodiscard]] auto empty() const noexcept -> bool { return items_.empty(); }
            [[nodiscard]] auto items() noexcept -> std::vector<std::shared_ptr<Flow>>& { return items_; }
            [[nodiscard]] auto items() const noexcept -> std::vector<std::shared_ptr<Flow>> const& { return items_; }
            [[nodiscard]] auto contains(std::uint16_t port) const noexcept -> bool { return find_bucket(port) < buckets_.size(); }
            [[nodiscard]] auto find(std::uint16_t port) const noexcept -> Flow* {
                auto pos = find_bucket(port);
                return pos < buckets_.size() ? items_[buckets_[pos]].get() : nullptr;
            }
            auto insert(std::shared_ptr<Flow> flow) -> void {
                ensure_capacity(items_.size() + 1);
                auto idx = static_cast<std::uint32_t>(items_.size());
                auto port = flow->local_port;
                items_.push_back(std::move(flow));
                insert_bucket(port, idx);
            }
            auto erase(std::uint16_t port, Flow const* expected) noexcept -> bool {
                auto pos = find_bucket(port);
                if (pos >= buckets_.size()) return false;
                auto idx = buckets_[pos];
                if (items_[idx].get() != expected) return false;
                std::size_t hole = pos;
                for (std::size_t scan = (hole + 1) & mask_; buckets_[scan] != kNull; scan = (scan + 1) & mask_) {
                    auto cur = buckets_[scan];
                    auto ideal = hash_port(items_[cur]->local_port) & mask_;
                    if (((scan - ideal) & mask_) >= ((scan - hole) & mask_)) {
                        buckets_[hole] = cur;
                        hole = scan;
                    }
                }
                buckets_[hole] = kNull;
                auto const last = static_cast<std::uint32_t>(items_.size() - 1);
                if (idx != last) {
                    auto moved_port = items_[last]->local_port;
                    items_[idx] = std::move(items_[last]);
                    for (std::size_t p = hash_port(moved_port) & mask_; ; p = (p + 1) & mask_) {
                        if (buckets_[p] == last) { buckets_[p] = idx; break; }
                    }
                }
                items_.pop_back();
                return true;
            }
            auto clear() noexcept -> void {
                items_.clear();
                std::ranges::fill(buckets_, kNull);
            }
        };

        L3Endpoint cfg_;
        SendPacketFn send_fn_;
        void* send_ctx_;
        std::uint16_t port_begin_ = 32768, port_end_ = 60999;
        std::uint16_t next_port_ = 32768;
        PortTable<TcpFlow> tcp_;
        PortTable<UdpFlow> udp_;

        auto alloc_tcp_port() -> std::optional<std::uint16_t> {
            std::uint32_t span = static_cast<std::uint32_t>(port_end_) - port_begin_ + 1u;
            for (std::uint32_t n = 0; n < span; ++n) {
                std::uint16_t p = next_port_;
                next_port_ = next_port_ >= port_end_ ? port_begin_ : static_cast<std::uint16_t>(next_port_ + 1);
                if (!tcp_.contains(p)) return p;
            }
            return std::nullopt;
        }

        auto alloc_udp_port() -> std::optional<std::uint16_t> {
            std::uint32_t span = static_cast<std::uint32_t>(port_end_) - port_begin_ + 1u;
            for (std::uint32_t n = 0; n < span; ++n) {
                std::uint16_t p = next_port_;
                next_port_ = next_port_ >= port_end_ ? port_begin_ : static_cast<std::uint16_t>(next_port_ + 1);
                if (!udp_.contains(p)) return p;
            }
            return std::nullopt;
        }

        auto local_mss(bool is_v6) const noexcept -> std::uint16_t {
            std::uint16_t hdr = is_v6 ? 60 : 40;
            return cfg_.mtu > hdr + 128 ? static_cast<std::uint16_t>(cfg_.mtu - hdr) : 536;
        }

        auto emit_tcp(TcpFlow const& f, std::uint32_t seq, std::uint32_t ack, std::uint16_t flags,
                      std::uint16_t win, std::span<std::uint8_t const> opts, std::span<std::uint8_t const> payload,
                      std::span<std::uint8_t const> payload_tail = {}) -> bool {
            if (!f.is_v6) {
                packet::Address4 dst{};
                std::copy_n(f.remote.begin(), 4, dst.begin());
                packet::Tcp4View v{cfg_.local_v4, dst, f.local_port, f.remote_port, seq, ack, flags, win, 0, opts, payload};
                auto pkt = packet::make_tcp4(v, payload_tail, cfg_.mtu);
                return pkt && send_fn_(send_ctx_, *pkt);
            }
            packet::Address6 dst{};
            std::copy_n(f.remote.begin(), 16, dst.begin());
            packet::Tcp6View v{cfg_.local_v6, dst, f.local_port, f.remote_port, seq, ack, flags, win, 0, opts, payload};
            auto pkt = packet::make_tcp6(v, payload_tail, cfg_.mtu);
            return pkt && send_fn_(send_ctx_, *pkt);
        }

        auto emit_syn(TcpFlow const& f) -> bool {
            auto mss = local_mss(f.is_v6);
            std::array<std::uint8_t, 4> opt{2, 4, static_cast<std::uint8_t>(mss >> 8), static_cast<std::uint8_t>(mss)};
            return emit_tcp(f, f.iss, 0, 0x02, 65535, opt, {});
        }

        static auto same_remote(bool is_v6, std::array<std::uint8_t, 16> const& a, std::span<std::uint8_t const> b) noexcept -> bool {
            std::size_t n = is_v6 ? 16 : 4;
            return b.size() >= n && std::equal(a.begin(), a.begin() + static_cast<std::ptrdiff_t>(n), b.begin());
        }

        static auto parse_peer_mss(std::span<std::uint8_t const> opts, std::uint16_t limit) noexcept -> std::uint16_t {
            if (auto parsed = packet::parse_tcp_options(opts)) {
                for (std::size_t i = 0; i < parsed->count; ++i) {
                    auto const& item = parsed->items[i];
                    if (item.kind == 2 && item.data.size() == 2) {
                        auto m = static_cast<std::uint16_t>((std::uint16_t(item.data[0]) << 8) | item.data[1]);
                        return std::min<std::uint16_t>(std::max<std::uint16_t>(m, 536), limit);
                    }
                }
            }
            return std::min<std::uint16_t>(536, limit);
        }

        static auto win16(tcp::ReceiveBuffer const& r) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>(std::min<std::size_t>(r.window(), 65535));
        }

        auto handle_tcp_seg(bool is_v6, std::span<std::uint8_t const> src_ip, std::uint16_t sport, std::uint16_t dport,
                            std::uint32_t seq, std::uint32_t ack, std::uint16_t flags, std::uint16_t peer_win,
                            std::span<std::uint8_t const> opts, std::span<std::uint8_t const> payload, std::uint64_t now) -> void {
            auto* fp = tcp_.find(dport);
            if (!fp) return;
            auto& f = *fp;
            if (f.is_v6 != is_v6 || f.remote_port != sport || !same_remote(is_v6, f.remote, src_ip) || f.state == TcpFlow::State::closed)
                return;
            if (flags & 0x04) {
                f.state = TcpFlow::State::closed;
                f.changed.set();
                return;
            }
            if (f.state == TcpFlow::State::syn_sent) {
                if ((flags & 0x12) != 0x12 || ack != f.iss + 1) return;
                auto sb = tcp::TimedSend::create(f.iss + 1, 65536);
                auto rb = tcp::ReceiveBuffer::create(seq + 1, 65536);
                if (!sb || !rb) { f.state = TcpFlow::State::closed; f.changed.set(); return; }
                f.send.emplace(std::move(*sb));
                f.recv.emplace(std::move(*rb));
                f.peer_mss = parse_peer_mss(opts, local_mss(is_v6));
                f.peer_window = peer_win;
                f.state = TcpFlow::State::established;
                auto const rw = win16(*f.recv);
                if (emit_tcp(f, f.iss + 1, f.recv->next(), 0x10, rw, {}, {})) f.last_rx_win = rw;
                f.changed.set();
                return;
            }
            bool need_ack = false;
            if (flags & 0x10) {
                f.peer_window = peer_win;
                if (f.peer_window > 0) { f.persist_deadline = 0; f.persist_retries = 0; }
                std::uint32_t data_ack = ack;
                if (f.fin_sent && ack == f.fin_seq + 1) {
                    f.fin_acked = true;
                    data_ack = f.send->next();
                }
                (void)f.send->acknowledge(data_ack, now);
                flush_tx(f, now);
                f.changed.set();
            }
            if (!payload.empty()) {
                auto ins = f.recv->insert(seq, payload);
                if (ins.accepted > 0 || ins.duplicate > 0) need_ack = true;
            }
            if (flags & 0x01) {
                auto fr = f.recv->insert_fin(seq + static_cast<std::uint32_t>(payload.size()));
                if (fr == tcp::FinResult::accepted || fr == tcp::FinResult::duplicate) need_ack = true;
            }
            if (need_ack) {
                auto s = f.fin_sent ? f.fin_seq + 1 : f.send->next();
                auto const rw = win16(*f.recv);
                if (emit_tcp(f, s, f.recv->next(), 0x10, rw, {}, {})) f.last_rx_win = rw;
                f.changed.set();
            }
        }

    public:
        L3Mux(L3Endpoint cfg, SendPacketFn send_fn, void* send_ctx) noexcept
            : cfg_(cfg), send_fn_(send_fn), send_ctx_(send_ctx) {}

        [[nodiscard]] auto endpoint() const noexcept -> L3Endpoint const& { return cfg_; }
        auto set_endpoint(L3Endpoint cfg) noexcept -> void { cfg_ = cfg; }
        auto set_port_range(std::uint16_t begin, std::uint16_t end) noexcept -> void {
            if (begin >= 1024 && begin <= end) { port_begin_ = begin; port_end_ = end; next_port_ = begin; }
        }
        auto reset_flows() -> void {
            for (auto& f : tcp_.items()) { f->state = TcpFlow::State::closed; f->changed.set(); }
            tcp_.clear();
            for (auto& f : udp_.items()) { f->closed = true; f->rx_event.set(); }
            udp_.clear();
        }
        [[nodiscard]] auto active() const noexcept -> bool { return !tcp_.empty() || !udp_.empty(); }

        auto open_tcp(corosio::endpoint const& dst, std::uint32_t iss, std::uint64_t now) -> std::shared_ptr<TcpFlow> {
            bool is_v6 = dst.address().is_v6();
            if ((is_v6 && !cfg_.has_v6) || (!is_v6 && !cfg_.has_v4)) return nullptr;
            auto port = alloc_tcp_port();
            if (!port) return nullptr;
            auto flow = std::make_shared<TcpFlow>();
            flow->is_v6 = is_v6;
            flow->local_port = *port;
            flow->remote_port = dst.port();
            flow->iss = iss;
            flow->syn_deadline = now + 1000;
            if (is_v6) {
                auto b = dst.address().to_v6().to_bytes();
                std::ranges::copy(b, flow->remote.begin());
            } else {
                auto b = dst.address().to_v4().to_bytes();
                std::ranges::copy(b, flow->remote.begin());
            }
            tcp_.insert(flow);
            (void)emit_syn(*flow);
            return flow;
        }

        auto close_tcp(TcpFlow& f) -> void {
            auto* found = tcp_.find(f.local_port);
            if (!found || found != &f) return;
            if (f.state == TcpFlow::State::established) {
                auto s = f.fin_sent ? f.fin_seq + 1 : f.send->next();
                (void)emit_tcp(f, s, f.recv->next(), 0x04, 0, {}, {});
            }
            f.state = TcpFlow::State::closed;
            f.changed.set();
            (void)tcp_.erase(f.local_port, &f);
        }

        auto request_fin(TcpFlow& f, std::uint64_t now) -> void {
            if (f.state != TcpFlow::State::established || f.fin_requested) return;
            f.fin_requested = true;
            flush_tx(f, now);
        }

        auto on_rx_read(TcpFlow& f) -> void {
            if (f.state != TcpFlow::State::established || !f.recv || f.recv->finished()) return;
            auto const rw = win16(*f.recv);
            if (rw > f.last_rx_win && (f.last_rx_win < f.peer_mss || rw - f.last_rx_win >= 16384 || rw == 65535)) {
                auto s = f.fin_sent ? f.fin_seq + 1 : f.send->next();
                if (emit_tcp(f, s, f.recv->next(), 0x10, rw, {}, {})) f.last_rx_win = rw;
            }
        }

        auto flush_tx(TcpFlow& f, std::uint64_t now) -> void {
            if (f.state != TcpFlow::State::established) return;
            auto const cap = std::min<std::size_t>(32768, f.peer_window);
            while (f.send->in_flight() < cap) {
                auto const budget = std::min<std::size_t>(f.peer_mss, cap - f.send->in_flight());
                auto slice = f.send->unsent_view(budget);
                if (slice.empty()) break;
                auto const rw = win16(*f.recv);
                if (!emit_tcp(f, slice.sequence, f.recv->next(), 0x18, rw, {}, slice.head, slice.tail)) break;
                f.last_rx_win = rw;
                if (!f.send->sent(slice.size(), now)) break;
            }
            if (f.peer_window == 0 && f.send->in_flight() == 0 && f.send->queued() > 0 && f.persist_deadline == 0)
                f.persist_deadline = now + 500;
            if (f.fin_requested && !f.fin_sent && f.send->queued() == 0) {
                f.fin_seq = f.send->next();
                f.fin_sent = true;
                f.fin_retries = 0;
                f.fin_deadline = now + 1000;
                auto const rw = win16(*f.recv);
                if (emit_tcp(f, f.fin_seq, f.recv->next(), 0x11, rw, {}, {})) f.last_rx_win = rw;
            }
        }

        auto open_udp() -> std::shared_ptr<UdpFlow> {
            auto port = alloc_udp_port();
            if (!port) return nullptr;
            auto flow = std::make_shared<UdpFlow>();
            flow->local_port = *port;
            udp_.insert(flow);
            return flow;
        }

        auto close_udp(UdpFlow& f) -> void {
            auto* found = udp_.find(f.local_port);
            if (!found || found != &f) return;
            f.closed = true;
            f.rx_event.set();
            (void)udp_.erase(f.local_port, &f);
        }

        auto send_udp(UdpFlow const& f, bool is_v6, std::span<std::uint8_t const> dst,
                      std::uint16_t dport, std::span<std::uint8_t const> payload) -> bool {
            if (f.closed) return false;
            if (!is_v6) {
                if (!cfg_.has_v4 || dst.size() < 4) return false;
                packet::Address4 d4{};
                std::copy_n(dst.begin(), 4, d4.begin());
                auto pkt = packet::make_udp4(cfg_.local_v4, d4, f.local_port, dport, payload, cfg_.mtu);
                return pkt && send_fn_(send_ctx_, *pkt);
            }
            if (!cfg_.has_v6 || dst.size() < 16) return false;
            packet::Address6 d6{};
            std::copy_n(dst.begin(), 16, d6.begin());
            auto pkt = packet::make_udp6(cfg_.local_v6, d6, f.local_port, dport, payload, cfg_.mtu);
            return pkt && send_fn_(send_ctx_, *pkt);
        }

        auto on_ip_packet(std::span<std::uint8_t const> pkt, std::uint64_t now) -> void {
            if (pkt.empty()) return;
            auto ver = pkt[0] >> 4;
            if (ver == 4) {
                if (auto u = packet::parse_udp4(pkt)) {
                    if (auto* flow = udp_.find(u->destination_port); flow && !flow->rx_queue.full()) {
                        UdpDatagram dg{false, {}, u->source_port, {u->payload.begin(), u->payload.end()}};
                        std::ranges::copy(u->source, dg.source.begin());
                        flow->rx_queue.push_back(std::move(dg));
                        flow->rx_event.set();
                    }
                    return;
                }
                if (auto t = packet::parse_tcp4(pkt)) {
                    handle_tcp_seg(false, t->source, t->source_port, t->destination_port,
                                   t->sequence, t->acknowledgement, t->flags, t->window, t->options, t->payload, now);
                }
            } else if (ver == 6) {
                if (auto u = packet::parse_udp6(pkt)) {
                    if (auto* flow = udp_.find(u->destination_port); flow && !flow->rx_queue.full()) {
                        UdpDatagram dg{true, u->source, u->source_port, {u->payload.begin(), u->payload.end()}};
                        flow->rx_queue.push_back(std::move(dg));
                        flow->rx_event.set();
                    }
                    return;
                }
                if (auto t = packet::parse_tcp6(pkt)) {
                    handle_tcp_seg(true, t->source, t->source_port, t->destination_port,
                                   t->sequence, t->acknowledgement, t->flags, t->window, t->options, t->payload, now);
                }
            }
        }

        auto tick(std::uint64_t now) -> void {
            for (auto& f : tcp_.items()) {
                if (f->state == TcpFlow::State::syn_sent && now >= f->syn_deadline) {
                    if (f->syn_retries >= 4) { f->state = TcpFlow::State::closed; f->changed.set(); continue; }
                    ++f->syn_retries;
                    f->syn_deadline = now + (1000ull << std::min(f->syn_retries, 3u));
                    (void)emit_syn(*f);
                } else if (f->state == TcpFlow::State::established) {
                    if (f->send->expired(now)) { f->state = TcpFlow::State::closed; f->changed.set(); continue; }
                    auto const rtx_max = f->peer_window ? std::min<std::size_t>(f->peer_mss, f->peer_window) : std::size_t{f->peer_mss};
                    if (auto d = f->send->due_view(now, rtx_max); d && *d) {
                        auto const rw = win16(*f->recv);
                        if (emit_tcp(*f, (*d)->sequence, f->recv->next(), 0x18, rw, {}, (*d)->head, (*d)->tail)) {
                            f->last_rx_win = rw;
                            (void)f->send->retransmitted(now);
                        }
                    } else if (f->peer_window == 0 && f->send->in_flight() == 0 && f->send->queued() > 0 &&
                               f->persist_deadline && now >= f->persist_deadline) {
                        if (f->persist_retries >= 8) { f->state = TcpFlow::State::closed; f->changed.set(); continue; }
                        ++f->persist_retries;
                        f->persist_deadline = now + (500ull << std::min(f->persist_retries, 4u));
                        auto const rw = win16(*f->recv);
                        if (emit_tcp(*f, f->send->una() - 1, f->recv->next(), 0x10, rw, {}, {})) f->last_rx_win = rw;
                    } else if (f->fin_sent && !f->fin_acked && now >= f->fin_deadline) {
                        if (f->fin_retries >= 8) { f->state = TcpFlow::State::closed; f->changed.set(); continue; }
                        ++f->fin_retries;
                        f->fin_deadline = now + (1000ull << std::min(f->fin_retries, 3u));
                        auto const rw = win16(*f->recv);
                        if (emit_tcp(*f, f->fin_seq, f->recv->next(), 0x11, rw, {}, {})) f->last_rx_win = rw;
                    }
                }
            }
        }
        [[nodiscard]] auto next_tick_ms(std::uint64_t now) const noexcept -> std::optional<std::uint64_t> {
            std::optional<std::uint64_t> next;
            auto clamp = [&](std::uint64_t t) noexcept { if (!next || t < *next) next = t; };
            for (auto const& f : tcp_.items()) {
                if (f->state == TcpFlow::State::syn_sent) clamp(f->syn_deadline);
                else if (f->state == TcpFlow::State::established) {
                    if (f->send && f->send->in_flight() > 0) clamp(now + 25);
                    if (f->persist_deadline) clamp(f->persist_deadline);
                    if (f->fin_sent && !f->fin_acked) clamp(f->fin_deadline);
                }
            }
            return next;
        }
    };
}
