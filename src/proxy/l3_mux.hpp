// Shared user-space L3 IP <-> active TCP / UDP-NAT multiplexer for WireGuard & CONNECT-IP outbounds.
// Included inside a translation unit after module imports (std, packet, tcp.*, boost.*).
#pragma once

namespace proxy { namespace {
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
            State state = State::syn_sent;
            std::uint32_t iss = 0;
            std::uint64_t syn_deadline = 0;
            unsigned syn_retries = 0;
            std::optional<tcp::TimedSend> send;
            std::optional<tcp::ReceiveBuffer> recv;
            bool fin_requested = false, fin_sent = false, fin_acked = false;
            std::uint32_t fin_seq = 0;
            std::uint64_t fin_deadline = 0;
            nex::capy::async_event changed;
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
            std::deque<UdpDatagram> rx_queue;
            nex::capy::async_event rx_event;
        };

    private:
        L3Endpoint cfg_;
        SendPacketFn send_fn_;
        void* send_ctx_;
        std::uint16_t next_port_ = 32768;
        std::unordered_map<std::uint16_t, std::shared_ptr<TcpFlow>> tcp_;
        std::unordered_map<std::uint16_t, std::shared_ptr<UdpFlow>> udp_;

        auto alloc_tcp_port() -> std::optional<std::uint16_t> {
            for (std::uint32_t n = 0; n < 28232; ++n) {
                std::uint16_t p = next_port_;
                next_port_ = next_port_ >= 60999 ? 32768 : static_cast<std::uint16_t>(next_port_ + 1);
                if (!tcp_.contains(p)) return p;
            }
            return std::nullopt;
        }

        auto alloc_udp_port() -> std::optional<std::uint16_t> {
            for (std::uint32_t n = 0; n < 28232; ++n) {
                std::uint16_t p = next_port_;
                next_port_ = next_port_ >= 60999 ? 32768 : static_cast<std::uint16_t>(next_port_ + 1);
                if (!udp_.contains(p)) return p;
            }
            return std::nullopt;
        }

        auto local_mss(bool is_v6) const noexcept -> std::uint16_t {
            std::uint16_t hdr = is_v6 ? 60 : 40;
            return cfg_.mtu > hdr + 128 ? static_cast<std::uint16_t>(cfg_.mtu - hdr) : 536;
        }

        auto emit_tcp(TcpFlow const& f, std::uint32_t seq, std::uint32_t ack, std::uint16_t flags,
                      std::uint16_t win, std::span<std::uint8_t const> opts, std::span<std::uint8_t const> payload) -> bool {
            if (!f.is_v6) {
                packet::Address4 dst{};
                std::copy_n(f.remote.begin(), 4, dst.begin());
                packet::Tcp4View v{cfg_.local_v4, dst, f.local_port, f.remote_port, seq, ack, flags, win, 0, opts, payload};
                auto pkt = packet::make_tcp4(v, cfg_.mtu);
                return pkt && send_fn_(send_ctx_, *pkt);
            }
            packet::Address6 dst{};
            std::copy_n(f.remote.begin(), 16, dst.begin());
            packet::Tcp6View v{cfg_.local_v6, dst, f.local_port, f.remote_port, seq, ack, flags, win, 0, opts, payload};
            auto pkt = packet::make_tcp6(v, cfg_.mtu);
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
                            std::uint32_t seq, std::uint32_t ack, std::uint16_t flags,
                            std::span<std::uint8_t const> opts, std::span<std::uint8_t const> payload, std::uint64_t now) -> void {
            auto it = tcp_.find(dport);
            if (it == tcp_.end()) return;
            auto& f = *it->second;
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
                f.state = TcpFlow::State::established;
                (void)emit_tcp(f, f.iss + 1, f.recv->next(), 0x10, win16(*f.recv), {}, {});
                f.changed.set();
                return;
            }
            bool need_ack = false;
            if (flags & 0x10) {
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
                (void)emit_tcp(f, s, f.recv->next(), 0x10, win16(*f.recv), {}, {});
                f.changed.set();
            }
        }

    public:
        L3Mux(L3Endpoint cfg, SendPacketFn send_fn, void* send_ctx) noexcept
            : cfg_(cfg), send_fn_(send_fn), send_ctx_(send_ctx) {}

        [[nodiscard]] auto endpoint() const noexcept -> L3Endpoint const& { return cfg_; }
        auto set_endpoint(L3Endpoint cfg) noexcept -> void { cfg_ = cfg; }
        auto reset_flows() -> void {
            for (auto& [p, f] : tcp_) { (void)p; f->state = TcpFlow::State::closed; f->changed.set(); }
            tcp_.clear();
            for (auto& [p, f] : udp_) { (void)p; f->closed = true; f->rx_event.set(); }
            udp_.clear();
        }
        [[nodiscard]] auto active() const noexcept -> bool { return !tcp_.empty() || !udp_.empty(); }

        auto open_tcp(nex::corosio::endpoint const& dst, std::uint32_t iss, std::uint64_t now) -> std::shared_ptr<TcpFlow> {
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
            tcp_.emplace(*port, flow);
            (void)emit_syn(*flow);
            return flow;
        }

        auto close_tcp(TcpFlow& f) -> void {
            auto it = tcp_.find(f.local_port);
            if (it == tcp_.end() || it->second.get() != &f) return;
            if (f.state == TcpFlow::State::established) {
                auto s = f.fin_sent ? f.fin_seq + 1 : f.send->next();
                (void)emit_tcp(f, s, f.recv->next(), 0x04, 0, {}, {});
            }
            f.state = TcpFlow::State::closed;
            f.changed.set();
            tcp_.erase(it);
        }

        auto request_fin(TcpFlow& f, std::uint64_t now) -> void {
            if (f.state != TcpFlow::State::established || f.fin_requested) return;
            f.fin_requested = true;
            flush_tx(f, now);
        }

        auto flush_tx(TcpFlow& f, std::uint64_t now) -> void {
            if (f.state != TcpFlow::State::established) return;
            while (f.send->in_flight() < 32768) {
                auto slice = f.send->unsent(f.peer_mss);
                if (slice.bytes.empty()) break;
                if (!emit_tcp(f, slice.sequence, f.recv->next(), 0x18, win16(*f.recv), {}, slice.bytes)) break;
                if (!f.send->sent(slice.bytes.size(), now)) break;
            }
            if (f.fin_requested && !f.fin_sent && f.send->queued() == 0) {
                f.fin_seq = f.send->next();
                f.fin_sent = true;
                f.fin_deadline = now + 1000;
                (void)emit_tcp(f, f.fin_seq, f.recv->next(), 0x11, win16(*f.recv), {}, {});
            }
        }

        auto open_udp() -> std::shared_ptr<UdpFlow> {
            auto port = alloc_udp_port();
            if (!port) return nullptr;
            auto flow = std::make_shared<UdpFlow>();
            flow->local_port = *port;
            udp_.emplace(*port, flow);
            return flow;
        }

        auto close_udp(UdpFlow& f) -> void {
            auto it = udp_.find(f.local_port);
            if (it == udp_.end() || it->second.get() != &f) return;
            f.closed = true;
            f.rx_event.set();
            udp_.erase(it);
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
                    if (auto it = udp_.find(u->destination_port); it != udp_.end() && it->second->rx_queue.size() < 128) {
                        UdpDatagram dg{false, {}, u->source_port, {u->payload.begin(), u->payload.end()}};
                        std::ranges::copy(u->source, dg.source.begin());
                        it->second->rx_queue.push_back(std::move(dg));
                        it->second->rx_event.set();
                    }
                    return;
                }
                if (auto t = packet::parse_tcp4(pkt)) {
                    handle_tcp_seg(false, t->source, t->source_port, t->destination_port,
                                   t->sequence, t->acknowledgement, t->flags, t->options, t->payload, now);
                }
            } else if (ver == 6) {
                if (auto u = packet::parse_udp6(pkt)) {
                    if (auto it = udp_.find(u->destination_port); it != udp_.end() && it->second->rx_queue.size() < 128) {
                        UdpDatagram dg{true, u->source, u->source_port, {u->payload.begin(), u->payload.end()}};
                        it->second->rx_queue.push_back(std::move(dg));
                        it->second->rx_event.set();
                    }
                    return;
                }
                if (auto t = packet::parse_tcp6(pkt)) {
                    handle_tcp_seg(true, t->source, t->source_port, t->destination_port,
                                   t->sequence, t->acknowledgement, t->flags, t->options, t->payload, now);
                }
            }
        }

        auto tick(std::uint64_t now) -> void {
            for (auto& [port, f] : tcp_) {
                if (f->state == TcpFlow::State::syn_sent && now >= f->syn_deadline) {
                    if (f->syn_retries >= 4) { f->state = TcpFlow::State::closed; f->changed.set(); continue; }
                    ++f->syn_retries;
                    f->syn_deadline = now + (1000ull << std::min(f->syn_retries, 3u));
                    (void)emit_syn(*f);
                } else if (f->state == TcpFlow::State::established) {
                    if (auto d = f->send->due(now, f->peer_mss); d && *d) {
                        if (emit_tcp(*f, (*d)->sequence, f->recv->next(), 0x18, win16(*f->recv), {}, (*d)->bytes))
                            (void)f->send->retransmitted(now);
                    } else if (f->fin_sent && !f->fin_acked && now >= f->fin_deadline) {
                        f->fin_deadline = now + 1000;
                        (void)emit_tcp(*f, f->fin_seq, f->recv->next(), 0x11, win16(*f->recv), {}, {});
                    }
                }
            }
        }
    };
}}
