// Private MASQUE CONNECT-IP outbound L3 adapter included inside masque_outbound.cpp.
#pragma once

template<bool Layered>
struct MasqueIpHost : std::enable_shared_from_this<MasqueIpHost<Layered>> {
    using Connection = MasqueConnection<Layered>;
    io::io_context& context;
    MasqueOutProfile const& profile;
    platform::SocketBinding binding;
    TunnelFactory const* lower;
    std::shared_ptr<Connection> connection;

    auto client() noexcept -> typename Connection::Client* {
        return connection ? &connection->client : nullptr;
    }
    L3Mux mux;
    std::uint64_t addr_epoch = 0, route_epoch = 0;
    bool started = false, connecting = false, stopped = false, loop_active = false;
    Clock::time_point retry_at{};
    std::chrono::milliseconds retry_delay{100};
    nex::capy::async_event ready_event;

    static auto now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
    }

    auto scope() const noexcept -> masque::IpRequestScope {
        if (profile.scope.kind == masque::IpTargetKind::any) return {{}, true, profile.scope.protocol};
        return {std::span(&profile.scope.prefix, 1), false, profile.scope.protocol};
    }

    static auto send_ip(void* ctx, std::span<std::uint8_t const> pkt) -> bool {
        auto* h = static_cast<MasqueIpHost*>(ctx);
        if (!h->connection || h->stopped || pkt.size() > h->profile.ip.mtu ||
            h->client()->address_epoch() != h->addr_epoch || h->client()->route_epoch() != h->route_epoch) return false;
        auto ip = masque::inspect_ip_packet(pkt);
        if (!ip || ip->routed || ip->source_override || ip->noninitial_fragment) return false;
        if (!masque::ip_matches_scope(*ip, h->scope(), masque::IpScopeSide::destination)) return false;
        if (h->route_epoch && !masque::ip_destination_advertised(*ip, h->client()->advertised_routes()))
            return false;
        return h->client()->send(pkt);
    }

    static auto initial_l3(MasqueIpOptions const& ip) noexcept -> L3Endpoint {
        L3Endpoint l3{};
        l3.mtu = ip.mtu;
        l3.has_v4 = ip.local_v4.has_value();
        if (ip.local_v4) l3.local_v4 = *ip.local_v4;
        l3.has_v6 = ip.local_v6.has_value();
        if (ip.local_v6) l3.local_v6 = *ip.local_v6;
        return l3;
    }

    MasqueIpHost(io::io_context& ctx, MasqueOutProfile const& p, platform::SocketBinding const& selected_binding,
                 TunnelFactory const* via)
        : context(ctx), profile(p), binding(selected_binding), lower(via), mux(initial_l3(p.ip), &MasqueIpHost::send_ip, this) {}

    auto apply_ip_control() -> void {
        if (!connection) return;
        auto address_update = client()->address_epoch();
        auto route_update = client()->route_epoch();
        if (address_update == addr_epoch && route_update == route_epoch) return;
        // A skipped snapshot may have withdrawn an address and restored it
        // before the pump ran. Existing flows cannot cross that gap.
        bool skipped = address_update - addr_epoch > 1;
        bool routes_changed = route_epoch != route_update;
        bool changed = profile.ip.protocol=="connect-ip" && address_update!=addr_epoch &&
            apply_masque_assigned_addresses(mux, client()->assigned_addresses());
        addr_epoch = address_update;
        route_epoch = route_update;
        if ((skipped || routes_changed) && !changed) mux.reset_flows();
        if (skipped || changed || routes_changed)
            client()->discard_ip_datagrams();
    }

    static auto pump_loop(std::shared_ptr<MasqueIpHost> h) -> capy::task<> {
        struct Guard { std::shared_ptr<MasqueIpHost> h; ~Guard() { h->loop_active = false; } } g{h};
        while (!h->stopped && h->connection && h->client()->ready()) {
            h->apply_ip_control();
            auto ms = now_ms();
            bool moved = false;
            while (auto pkt = h->client()->try_receive()) {
                auto ip = masque::inspect_ip_packet(*pkt);
                if (!ip || ip->noninitial_fragment || pkt->size() > h->profile.ip.mtu ||
                    !masque::ip_matches_scope(*ip, h->scope(), masque::IpScopeSide::source)) continue;
                auto const& endpoint = h->mux.endpoint();
                bool assigned = ip->version == 4
                    ? endpoint.has_v4 && std::ranges::equal(std::span(ip->destination).first(4), endpoint.local_v4)
                    : endpoint.has_v6 && ip->destination == endpoint.local_v6;
                if (!assigned) continue;
                h->mux.on_ip_packet(ip->packet, ms);
                moved = true;
            }
            h->mux.tick(ms);
            auto [ec] = co_await io::delay(moved ? std::chrono::milliseconds(1)
                                                 : (h->mux.active() ? std::chrono::milliseconds(2) : std::chrono::milliseconds(10)));
            if (ec) break;
        }
        h->disconnect();
    }

    auto disconnect() noexcept -> void {
        mux.reset_flows();
        mux.set_endpoint(initial_l3(profile.ip));
        addr_epoch = route_epoch = 0;
        started = false;
        if (auto active = std::exchange(connection, {})) active->stop();
        retry_at = Clock::now() + retry_delay;
        retry_delay = std::min(retry_delay * 2, std::chrono::milliseconds(2000));
        ready_event.set();
    }

    auto ensure_started(Session& s, DnsSlot& dns, Clock::time_point deadline) -> capy::task<bool> {
        if (stopped || s.closed || Clock::now() >= deadline) co_return false;
        if (started) co_return client()->ready();
        while (connecting) {
            ready_event.clear();
            auto [ec] = co_await io::timeout(ready_event.wait(), deadline);
            if (ec || stopped || s.closed || Clock::now() >= deadline) co_return false;
            if (started) co_return client()->ready();
        }
        if (stopped) co_return false;
        connecting = true;
        struct Fin { MasqueIpHost& h; ~Fin() { h.connecting = false; h.ready_event.set(); } } fin{*this};
        auto now = Clock::now();
        if (retry_at > now) {
            if (retry_at >= deadline) co_return false;
            auto [ec] = co_await io::delay(retry_at - now);
            if (ec || stopped || s.closed || Clock::now() >= deadline) co_return false;
        }
        auto eps = profile.bootstrap
            ? co_await resolve_bootstrap_owned(s, context, dns, *profile.bootstrap, profile.host, profile.port, deadline)
            : co_await resolve_local_owned(s, context, dns, profile.host, profile.port, deadline);
        if (stopped || s.closed || !eps || eps->empty()) co_return false;
        auto ech = co_await profile.ech.resolve(s, context, dns, profile.bootstrap, profile.port, deadline);
        if (stopped || s.closed || !ech || Clock::now() >= deadline) co_return false;
        auto start=co_await start_masque_connection(s,context,profile,binding,lower,eps->front(),
            *ech ? &**ech : nullptr,deadline,stopped,connection);
        if (start!=TunnelConnectResult::connected) {disconnect();co_return false;}
        auto active=connection;
        auto& client=active->client;
        std::stop_callback canceled(s.stop.get_token(),[active]() noexcept {active->stop();});
        auto connected = co_await client.connect_ip(profile.ip.path,deadline,static_cast<std::size_t>(profile.ip.mtu)+16,profile.ip.protocol,profile.ip.headers);
        while (connected && client.ready() && !profile.ip.local_v4 && !profile.ip.local_v6 && !client.address_epoch()) {
            auto& changed = client.rx_event();
            changed.clear();
            auto [ec] = co_await io::timeout(changed.wait(), deadline);
            if (ec) connected = false;
        }
        if (!connected || !client.ready() || stopped || s.closed || Clock::now() >= deadline) {
            if (connection) disconnect();
            co_return false;
        }
        addr_epoch = route_epoch = 0;
        apply_ip_control();
        loop_active = true;
        try {
            auto keep = this->shared_from_this();
            capy::run_async(context.get_executor(), []() noexcept {},
                [keep](std::exception_ptr) noexcept { keep->disconnect(); })(pump_loop(keep));
        } catch (...) {
            loop_active = false;
            disconnect();
            co_return false;
        }
        started = !stopped && connection && client.ready();
        if (started) retry_delay = std::chrono::milliseconds(100);
        co_return started;
    }

    auto stop() noexcept -> void {
        if (stopped) return;
        stopped = true;
        disconnect();
    }
};

template<bool Layered>
class MasqueIpTunnel {
    using Host = MasqueIpHost<Layered>;
    Session& session_;
    std::shared_ptr<MasqueOutProfile> profile_;
    std::shared_ptr<Host> host_;
    DnsSlot dns_;
    std::shared_ptr<L3Mux::TcpFlow> tcp_;
    std::shared_ptr<L3Mux::UdpFlow> udp_;
    std::vector<std::uint8_t> rx_buf_;
    std::size_t rx_off_ = 0;
    bool relay_local_ = true;
    bool canceled_ = false;

public:
    MasqueIpTunnel(Session& s, std::shared_ptr<MasqueOutProfile> p, std::shared_ptr<Host> h, bool relay_local)
        : session_(s), profile_(std::move(p)), host_(std::move(h)), relay_local_(relay_local) {}

    ~MasqueIpTunnel() { cancel(); }

    auto cancel() noexcept -> void {
        canceled_ = true;
        dns_.cancel();
        if (tcp_) { host_->mux.close_tcp(*tcp_); tcp_.reset(); }
        if (udp_) { host_->mux.close_udp(*udp_); udp_.reset(); }
    }

    auto connect(io::endpoint dst) -> capy::task<TunnelConnectResult> {
        return connect_until(dst, Clock::now() + std::chrono::milliseconds(profile_->timeout));
    }

    auto connect_until(io::endpoint dst, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
        if (!co_await host_->ensure_started(session_, dns_, deadline))
            co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
        host_->apply_ip_control();
        std::uint32_t iss = 0;
        if (!platform::secure_random(std::as_writable_bytes(std::span(&iss, 1)))) co_return TunnelConnectResult::failed;
        auto flow = host_->mux.open_tcp(dst, iss, Host::now_ms());
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
        co_return flow->state == L3Mux::TcpFlow::State::established ? TunnelConnectResult::connected : TunnelConnectResult::failed;
    }

    auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        if (canceled_ || session_.closed) co_return false;
        host_->apply_ip_control();
        if (udp_) {
            if (udp_->closed) co_return false;
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
            if (auto avail = flow->send->available(); avail > 0) {
                auto chunk = bytes.first(std::min(bytes.size(), avail));
                if (!flow->send->enqueue(chunk)) co_return false;
                host_->mux.flush_tx(*flow, Host::now_ms());
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
        if (canceled_ || session_.closed) co_return std::unexpected("MASQUE CONNECT-IP closed");
        if (auto flow = udp_) {
            for (;;) {
                if (canceled_ || session_.closed || flow->closed || host_->stopped)
                    co_return std::unexpected("MASQUE CONNECT-IP UDP closed");
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
                    if (auto enc = net::encode_datagram({}, pa, dg.payload)) { rx_buf_ = std::move(*enc); rx_off_ = 0; }
                    continue;
                }
                flow->rx_event.clear();
                auto [ec] = co_await flow->rx_event.wait();
                if (ec) co_return std::unexpected("MASQUE CONNECT-IP UDP interrupted");
            }
        }
        auto flow = tcp_;
        if (!flow) co_return std::unexpected("MASQUE CONNECT-IP TCP closed");
        for (;;) {
            if (canceled_ || session_.closed) co_return std::unexpected("MASQUE CONNECT-IP closed");
            if (flow->state == L3Mux::TcpFlow::State::closed || host_->stopped)
                co_return std::unexpected("MASQUE CONNECT-IP TCP reset");
            if (flow->recv) {
                if (auto n = flow->recv->read(out); n > 0) { session_.touched = Clock::now(); co_return n; }
                if (flow->recv->finished()) co_return std::size_t{0};
            }
            flow->changed.clear();
            auto [ec] = co_await flow->changed.wait();
            if (ec) co_return std::unexpected("MASQUE CONNECT-IP TCP interrupted");
        }
    }

    auto close_output() -> capy::task<bool> {
        if (tcp_) host_->mux.request_fin(*tcp_, Host::now_ms());
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
        host_->apply_ip_control();
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
