// Included inside the module implementation namespace after the L3 multiplexer.
#pragma once

        template<class Host> class L3Tunnel {
            Session& session_;
            std::shared_ptr<Host> host_;
            std::uint32_t timeout_ms_;
            DnsSlot dns_;
            std::shared_ptr<L3Mux::TcpFlow> tcp_;
            std::shared_ptr<L3Mux::UdpFlow> udp_;
            std::vector<std::uint8_t> rx_buf_;
            std::size_t rx_off_ = 0;
            bool relay_local_ = true;
            bool canceled_ = false;

        public:
            L3Tunnel(Session& session, std::shared_ptr<Host> host, std::uint32_t timeout_ms, bool relay_local)
                : session_(session), host_(std::move(host)), timeout_ms_(timeout_ms), relay_local_(relay_local) {}

            ~L3Tunnel() { cancel(); }

            auto cancel() noexcept -> void {
                canceled_ = true;
                dns_.cancel();
                if (tcp_) { host_->mux.close_tcp(*tcp_); tcp_.reset(); }
                if (udp_) { host_->mux.close_udp(*udp_); udp_.reset(); }
            }

            auto connect(io::endpoint dst) -> capy::task<TunnelConnectResult> {
                return connect_until(dst, Clock::now() + std::chrono::milliseconds(timeout_ms_));
            }

            auto connect_until(io::endpoint dst, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!co_await host_->ensure_started(session_, dns_, deadline))
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                std::uint32_t iss = 0;
                if (!platform::secure_random(std::as_writable_bytes(std::span(&iss, 1)))) co_return TunnelConnectResult::failed;
                auto flow = host_->mux.open_tcp(dst, iss, now_ms());
                if (!flow) co_return TunnelConnectResult::failed;
                tcp_ = flow;
                while (flow->state == L3Mux::TcpFlow::State::syn_sent) {
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                    flow->changed.clear();
                    auto [ec] = co_await io::timeout(flow->changed.wait(), deadline);
                    if (ec == capy::cond::timeout || Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                    if (ec) co_return TunnelConnectResult::failed;
                }
                if (flow->state != L3Mux::TcpFlow::State::established) co_return TunnelConnectResult::failed;
                co_return TunnelConnectResult::connected;
            }

            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (canceled_ || session_.closed) co_return false;
                if (udp_) {
                    auto f = net::parse_datagram({}, {}, bytes);
                    if (f.status != net::DatagramStatus::accepted || f.consumed != bytes.size()) co_return false;
                    if (f.destination.family != net::ProxyAddressFamily::ipv4 &&
                        f.destination.family != net::ProxyAddressFamily::ipv6) co_return false;
                    bool ok = host_->mux.send_udp(*udp_, f.destination.family == net::ProxyAddressFamily::ipv6,
                                                  f.destination.bytes, f.destination.port, f.payload);
                    if (ok) session_.touched = Clock::now();
                    co_return ok;
                }
                auto flow = tcp_;
                if (!flow || flow->state != L3Mux::TcpFlow::State::established) co_return false;
                while (!bytes.empty()) {
                    if (canceled_ || session_.closed || flow->state != L3Mux::TcpFlow::State::established) co_return false;
                    auto avail = flow->send->available();
                    if (avail > 0) {
                        auto chunk = bytes.first(std::min(bytes.size(), avail));
                        if (!flow->send->enqueue(chunk)) co_return false;
                        host_->mux.flush_tx(*flow, now_ms());
                        bytes = bytes.subspan(chunk.size());
                        session_.touched = Clock::now();
                        continue;
                    }
                    flow->changed.clear();
                    auto [ec] = co_await flow->changed.wait();
                    if (ec) co_return false;
                }
                co_return true;
            }

            auto read(std::span<std::uint8_t> out) -> capy::task<std::expected<std::size_t, std::string>> {
                if (canceled_ || session_.closed) co_return std::unexpected("IP tunnel closed");
                if (auto flow = udp_) {
                    for (;;) {
                        if (canceled_ || session_.closed || flow->closed || host_->stopped)
                            co_return std::unexpected("IP tunnel UDP closed");
                        if (rx_off_ < rx_buf_.size()) {
                            auto n = std::min(out.size(), rx_buf_.size() - rx_off_);
                            std::copy_n(rx_buf_.begin() + static_cast<std::ptrdiff_t>(rx_off_), n, out.begin());
                            rx_off_ += n;
                            if (rx_off_ == rx_buf_.size()) { rx_buf_.clear(); rx_off_ = 0; }
                            session_.touched = Clock::now();
                            co_return n;
                        }
                        if (!flow->rx_queue.empty()) {
                            auto dg = std::move(flow->rx_queue.front());
                            flow->rx_queue.pop_front();
                            net::ProxyAddress pa{};
                            pa.family = dg.is_v6 ? net::ProxyAddressFamily::ipv6 : net::ProxyAddressFamily::ipv4;
                            pa.length = dg.is_v6 ? 16 : 4;
                            pa.port = dg.source_port;
                            std::copy_n(dg.source.begin(), pa.length, pa.bytes.begin());
                            if (auto enc = net::encode_datagram({}, pa, dg.payload)) {
                                rx_buf_ = std::move(*enc); rx_off_ = 0;
                            }
                            continue;
                        }
                        flow->rx_event.clear();
                        auto [ec] = co_await flow->rx_event.wait();
                        if (ec) co_return std::unexpected("IP tunnel UDP interrupted");
                    }
                }
                auto flow = tcp_;
                if (!flow) co_return std::unexpected("IP tunnel TCP closed");
                for (;;) {
                    if (canceled_ || session_.closed) co_return std::unexpected("IP tunnel closed");
                    if (flow->recv) {
                        if (auto n = flow->recv->read(out); n > 0) {
                            session_.touched = Clock::now();
                            co_return n;
                        }
                        if (flow->recv->finished()) co_return std::size_t{0};
                    }
                    if (flow->state == L3Mux::TcpFlow::State::closed || host_->stopped)
                        co_return std::unexpected("IP tunnel TCP reset");
                    flow->changed.clear();
                    auto [ec] = co_await flow->changed.wait();
                    if (ec) co_return std::unexpected("IP tunnel TCP interrupted");
                }
            }

            auto close_output() -> capy::task<bool> {
                if (tcp_) host_->mux.request_fin(*tcp_, now_ms());
                co_return true;
            }
            auto upload() -> capy::task<bool> {
                if (!tcp_ || canceled_ || session_.closed) co_return false;
                co_return co_await net::stream_relay::upload(
                    net::ByteRelayAdapter{session_.client, *this, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
            auto download() -> capy::task<bool> {
                if (!tcp_ || canceled_ || session_.closed) co_return false;
                co_return co_await net::stream_relay::download(
                    net::ByteRelayAdapter{session_.client, *this, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
            auto packet_transport() const noexcept -> net::PacketTransport {
                return {net::PacketTransportKind::framed, {}, false};
            }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!co_await host_->ensure_started(session_, dns_, deadline))
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                udp_ = host_->mux.open_udp();
                co_return udp_ ? TunnelConnectResult::connected : TunnelConnectResult::failed;
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        };
