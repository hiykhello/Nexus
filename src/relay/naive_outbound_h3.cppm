module;
#include <boost/capy/ex/run_async.hpp>

module relay:naive_outbound_h3;
import std;
import proxy.v4;
import crypto;
import naive.h3_connect;
import naive.h3_client;
import masque.client_profile;
import net.connection_pool;
import net.packet_stream_socket;
import net.unified_datagram;
import net.stream_relay;
import net.datagram_frame;
import platform.ip_address;
import platform.socket_options;
import capy;
import corosio;
import :types;
import :server_interface;
import :tunnel_facade;
import :route_interface;
import :session_interface;
import :internal_decls;

namespace relay::naive_out_detail {
    template<class Op>
    class LocalOpToken {
        struct Cancel {
            std::stop_source* source;
            auto operator()() const noexcept -> void { source->request_stop(); }
        };
        std::stop_source& source_;
        std::optional<capy::await_context> env_;
        std::optional<std::stop_callback<Cancel>> parent_;
        Op op_;

    public:
        LocalOpToken(Op&& op, std::stop_source& source)
            : source_(source), op_(std::move(op)) {}
        LocalOpToken(LocalOpToken const&) = delete;
        LocalOpToken(LocalOpToken&& other) noexcept(std::is_nothrow_move_constructible_v<Op>)
            : source_(other.source_), op_(std::move(other.op_)) {
            if (other.env_) std::terminate();
        }
        auto await_ready() noexcept(noexcept(op_.await_ready())) -> bool { return op_.await_ready(); }
        auto await_suspend(std::coroutine_handle<> cont, capy::await_context const* parent) {
            env_.emplace(*parent);
            env_->stop_token = source_.get_token();
            parent_.emplace(parent->stop_token, Cancel{&source_});
            return op_.await_suspend(cont, &*env_);
        }
        auto await_resume() {
            parent_.reset();
            return op_.await_resume();
        }
    };

    template<class Op>
    LocalOpToken(Op&&, std::stop_source&) -> LocalOpToken<std::remove_cvref_t<Op>>;

    struct NaiveQuicDetour {
        Session session;
        pro::proxy<TunnelFacade> tunnel;

        NaiveQuicDetour(Session const& parent, corosio::io_context& context) : session(context) {
            session.dns = parent.dns;
            session.local_dns = parent.local_dns;
            session.route_snapshot = parent.route_snapshot;
            session.tunnel_factories = parent.tunnel_factories;
            session.direct_tcp_options = parent.direct_tcp_options;
            session.started = parent.started;
            session.handshake_deadline = parent.handshake_deadline;
        }
        auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
        auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
        auto cancel() noexcept -> void {
            if (tunnel) tunnel->cancel();
            session.close();
        }
        auto connect(TunnelFactory const& factory, corosio::io_context& context, net::UnifiedDatagramSocket& socket,
                     corosio::endpoint peer, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (session.closed || tunnel) co_return TunnelConnectResult::failed;
            if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
            auto stop = co_await capy::this_coro::stop_token;
            std::stop_callback canceled(stop, [this]() noexcept { cancel(); });
            if (session.closed) co_return TunnelConnectResult::failed;
            tunnel = factory(session, context, false);
            if (!tunnel) co_return TunnelConnectResult::failed;
            auto transport = tunnel->packet_transport();
            if (transport.kind == net::PacketTransportKind::none) co_return TunnelConnectResult::failed;
            auto connected = co_await tunnel->connect_packets(net::packet_peer_address(peer), deadline);
            if (connected != TunnelConnectResult::connected) co_return connected;
            if (session.closed || !socket.attach_detour(*this, transport, peer)) co_return TunnelConnectResult::failed;
            auto prepared = co_await socket.prepare_detour(deadline);
            if (prepared && !session.closed) co_return TunnelConnectResult::connected;
            co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
        }
    };

    struct UnifiedH3Connector {
        using Socket = net::UnifiedDatagramSocket;
        Session state;
        corosio::io_context& context;
        std::string host;
        std::uint16_t port;
        std::optional<std::size_t> bootstrap;
        TcpSocketOptions const& options;
        TunnelFactory const* factory = nullptr;
        std::optional<NaiveQuicDetour> detour;
        DnsSlot dns;
        bool canceled = false;

        UnifiedH3Connector(corosio::io_context& ctx, OutboundContext const& env,
                           std::string h, std::uint16_t p, std::optional<std::size_t> bs,
                           TcpSocketOptions const& opts, TunnelFactory const* lower)
            : state(ctx), context(ctx), host(std::move(h)), port(p), bootstrap(bs),
              options(opts), factory(lower) {
            state.dns = env.dns;
            state.local_dns = env.local_dns;
            if (env.owner) state.route_snapshot = env.owner->current_route_snapshot();
            state.tunnel_factories = env.factories;
            state.direct_tcp_options = env.direct_options;
            if (factory) detour.emplace(state, ctx);
        }
        ~UnifiedH3Connector() { cancel(); }

        auto cancel() noexcept -> void {
            canceled = true;
            dns.cancel();
            if (detour) detour->cancel();
            state.close();
        }

        auto prepare(Socket& socket, Clock::time_point deadline)
            -> capy::task<std::optional<corosio::endpoint>> {
            auto& resolver_session = detour ? detour->session : state;
            auto eps = bootstrap
                ? co_await resolve_bootstrap_owned(resolver_session, context, dns, *bootstrap, host, port, deadline)
                : co_await resolve_local_owned(resolver_session, context, dns, host, port, deadline);
            if (canceled || !eps || eps->empty()) co_return std::nullopt;
            for (auto const& peer : *eps) {
                if (canceled) co_return std::nullopt;
                if (!valid_destination(peer)) continue;
                if (factory) {
                    if (co_await detour->connect(*factory, context, socket, peer, deadline) == TunnelConnectResult::connected)
                        co_return peer;
                    detour->cancel();
                    break;
                }
                if (!socket.prepare_physical(peer, &options.binding, deadline))
                    co_return peer;
            }
            co_return std::nullopt;
        }
    };

    struct H3Worker {
        using Conn = naive::OwnedH3ConnectClient<UnifiedH3Connector>;
        using Pool = net::ConnectionPool<Conn, true>;

        OutboundContext environment;
        std::string host;
        std::uint16_t port;
        std::optional<std::size_t> bootstrap;
        masque::ClientProfile const& client_profile;
        TcpSocketOptions options;
        TunnelFactory const* detour;
        bool enable_datagrams;
        Pool pool;
        capy::async_mutex starting;
        capy::async_event stop_ev_;
        Conn* starting_conn = nullptr;
        bool stopped = false, reaper_active_ = false;

        H3Worker(OutboundContext const& env, std::string h, std::uint16_t p,
                 std::optional<std::size_t> bs, masque::ClientProfile const& mp,
                 TcpSocketOptions opts, TunnelFactory const* lower, std::size_t max_sessions, bool dgram)
            : environment(env), host(std::move(h)), port(p), bootstrap(bs),
              client_profile(mp), options(std::move(opts)), detour(lower), enable_datagrams(dgram),
              pool(net::PoolOptions{.max_sessions = max_sessions, .min_idle = 0,
                                    .idle_timeout = std::chrono::seconds(120)}) {}

        auto reap_loop() -> capy::task<> {
            struct Done { bool& flag; ~Done() { flag = false; } } done{reaper_active_};
            while (!stopped) {
                stop_ev_.clear();
                if (stopped) break;
                auto [ec] = co_await corosio::timeout(stop_ev_.wait(), Clock::now() + std::chrono::seconds(10));
                if (stopped || ec != capy::cond::timeout) break;
                pool.reap(Clock::now());
            }
        }

        auto start_reaper() -> void {
            if (stopped || reaper_active_) return;
            reaper_active_ = true;
            capy::run_async(environment.context.get_executor(), [] {}, [this](std::exception_ptr) noexcept {
                reaper_active_ = false;
            })(reap_loop());
        }

        auto stop() noexcept -> void {
            stopped = true;
            stop_ev_.set();
            if (auto* active = starting_conn) active->stop();
            pool.stop();
        }
        auto drained() const noexcept -> bool { return !reaper_active_ && !starting_conn && pool.drained(); }
        ~H3Worker() { stop(); if (!drained()) std::terminate(); }

        struct AcquireResult {
            std::optional<typename Pool::Lease> lease;
            bool reused = false;
            TunnelConnectResult error = TunnelConnectResult::failed;
        };

        auto acquire(std::stop_source& caller_stop, Clock::time_point deadline, bool allow_reuse = true)
            -> capy::task<AcquireResult> {
            if (stopped || caller_stop.stop_requested()) co_return AcquireResult{.error = TunnelConnectResult::failed};
            if (Clock::now() >= deadline) co_return AcquireResult{.error = TunnelConnectResult::timeout};
            pool.reap(Clock::now());
            if (allow_reuse) {
                if (auto reused = pool.acquire()) co_return AcquireResult{.lease = std::move(*reused), .reused = true};
            }
            auto wait = corosio::timeout(starting.scoped_lock(), deadline);
            auto [lock_ec, lock] = co_await LocalOpToken(std::move(wait), caller_stop);
            if (lock_ec || caller_stop.stop_requested() || stopped || Clock::now() >= deadline)
                co_return AcquireResult{.error = Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed};
            if (allow_reuse) {
                if (auto reused = pool.acquire()) co_return AcquireResult{.lease = std::move(*reused), .reused = true};
            }
            pool.reap(Clock::now());
            auto slot = pool.reserve();
            if (!slot) co_return AcquireResult{.error = TunnelConnectResult::failed};
            auto conn = std::make_unique<Conn>(client_profile, enable_datagrams, environment.context,
                environment, host, port, bootstrap, options, detour);
            struct Reg {
                H3Worker& w;
                Reg(H3Worker& owner, Conn* c) noexcept : w(owner) { w.starting_conn = c; }
                ~Reg() { w.starting_conn = nullptr; }
            } reg(*this, conn.get());
            typename Conn::StartResult started;
            {
                std::stop_callback cb(caller_stop.get_token(), [p = conn.get()]() noexcept { p->stop(); });
                started = co_await conn->start(environment.context, deadline);
            }
            if (started != Conn::StartResult::connected || caller_stop.stop_requested() || stopped)
                co_return AcquireResult{.error = started == Conn::StartResult::timeout || Clock::now() >= deadline
                    ? TunnelConnectResult::timeout : TunnelConnectResult::failed};
            auto lease = slot->commit(std::move(conn));
            if (!lease) co_return AcquireResult{.error = TunnelConnectResult::failed};
            co_return AcquireResult{.lease = std::move(*lease), .reused = false};
        }
    };

    struct H3Profile {
        std::string host;
        std::uint16_t port = 0;
        std::string auth_header;
        std::vector<std::pair<std::string, std::string>> extra_headers;
        bool padding = false;
        std::optional<std::size_t> bootstrap;
        std::uint32_t timeout_ms = 10000;
        std::size_t max_sessions = 8;
        TcpSocketOptions options;
        std::unique_ptr<masque::ClientProfile> client_profile;
        std::mutex mutex;
        std::array<std::unique_ptr<H3Worker>, 17> physical;
        std::array<std::unique_ptr<H3Worker>, 17> layered;

        H3Profile(std::string h, std::uint16_t p, std::string auth,
                  std::vector<std::pair<std::string, std::string>> eh,
                  bool pad, std::optional<std::size_t> bs, std::uint32_t tms,
                  std::size_t ms, TcpSocketOptions opts,
                  std::unique_ptr<masque::ClientProfile> cp)
            : host(std::move(h)), port(p), auth_header(std::move(auth)),
              extra_headers(std::move(eh)), padding(pad), bootstrap(bs),
              timeout_ms(tms), max_sessions(ms), options(std::move(opts)),
              client_profile(std::move(cp)) {}

        ~H3Profile() {
            if (!auth_header.empty())
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(auth_header.data()), auth_header.size()));
        }
    };

    inline auto format_authority(corosio::endpoint const& ep) -> std::string {
        return ep.is_v6()
            ? "[" + ep.address().to_v6().to_string() + "]:" + std::to_string(ep.port())
            : ep.address().to_v4().to_string() + ":" + std::to_string(ep.port());
    }

    inline auto format_domain_authority(std::string_view host, std::uint16_t port) -> std::string {
        auto ip = platform::parse_ip_address(host);
        if (ip && ip->size == 16 && !host.starts_with('['))
            return "[" + std::string(host) + "]:" + std::to_string(port);
        return std::string(host) + ":" + std::to_string(port);
    }

    class H3Tunnel {
        using Worker = H3Worker;
        using Conn = typename Worker::Conn;
        using Lease = typename Worker::Pool::Lease;
        using StreamHandle = typename Conn::StreamHandle;

        Session& session_;
        Worker& worker_;
        H3Profile const& profile_;
        bool relay_local_;
        std::stop_source stop_;
        std::optional<Lease> lease_;
        std::unique_ptr<StreamHandle> stream_;
        net::ProxyAddress remote_addr_{};
        std::string remote_host_;
        std::vector<std::uint8_t> dgram_rx_;
        std::size_t dgram_off_ = 0;
        bool ready_ = false, udp_opened_ = false, canceled_ = false;
        bool up_done_ = false, down_done_ = false;

        auto connect_auth(std::string authority, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (ready_ || canceled_ || session_.closed) co_return TunnelConnectResult::failed;
            for (int attempt = 0; attempt < 2; ++attempt) {
                auto res = co_await worker_.acquire(stop_, deadline, attempt == 0);
                if (!res.lease) co_return res.error;
                lease_.emplace(std::move(*res.lease));
                auto open_op = lease_->connection().open_connect(
                    authority, profile_.auth_header, profile_.extra_headers, profile_.padding, deadline);
                auto st = co_await LocalOpToken(std::move(open_op), stop_);
                if (st && !canceled_ && !session_.closed) {
                    stream_ = std::move(*st);
                    ready_ = true;
                    co_return TunnelConnectResult::connected;
                }
                if (st) (*st)->release();
                bool const retry = !st && attempt == 0 && res.reused && !lease_->connection().usable() &&
                    !canceled_ && !session_.closed && Clock::now() < deadline;
                lease_.reset();
                if (retry) continue;
                co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            }
            co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
        }

    public:
        H3Tunnel(Session& session, Worker& worker, H3Profile const& profile, bool relay_local)
            : session_(session), worker_(worker), profile_(profile), relay_local_(relay_local) {}
        ~H3Tunnel() { cancel(); stream_.reset(); lease_.reset(); }

        auto cancel() noexcept -> void {
            if (std::exchange(canceled_, true)) return;
            stop_.request_stop();
            if (stream_) stream_->release();
            if (ready_ && relay_local_) session_.client.cancel();
        }
        auto connect(corosio::endpoint dst) -> capy::task<TunnelConnectResult> {
            return connect_until(dst, session_.started + std::chrono::milliseconds(profile_.timeout_ms));
        }
        auto connect_until(corosio::endpoint dst, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            return connect_auth(format_authority(dst), deadline);
        }
        auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            return connect_auth(format_domain_authority(domain, port), deadline);
        }
        auto has_uot() const noexcept -> bool { return false; }
        auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto has_xudp() const noexcept -> bool { return false; }
        auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }

        auto packet_transport() const noexcept -> net::PacketTransport {
            return worker_.enable_datagrams ? net::PacketTransport{net::PacketTransportKind::framed, {}, false} : net::PacketTransport{};
        }

        auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            return connect_packets(net::ProxyAddress{}, deadline);
        }

        auto connect_packets(net::ProxyAddress const&, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (!worker_.enable_datagrams || ready_ || canceled_ || session_.closed) co_return TunnelConnectResult::failed;
            auto res = co_await worker_.acquire(stop_, deadline);
            if (!res.lease) co_return res.error;
            lease_.emplace(std::move(*res.lease));
            ready_ = true;
            co_return TunnelConnectResult::connected;
        }

        auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            if (!ready_ || canceled_) co_return false;
            if (worker_.enable_datagrams) {
                if (!udp_opened_) {
                    if (!lease_) co_return false;
                    auto frame = net::parse_datagram({}, {}, bytes);
                    if (frame.status != net::DatagramStatus::accepted || frame.consumed != bytes.size()) co_return false;
                    remote_addr_ = frame.destination;
                    if (remote_addr_.family == net::ProxyAddressFamily::ipv4) {
                        corosio::ipv4_address::bytes_type b{};
                        std::copy_n(remote_addr_.bytes.begin(), 4, b.begin());
                        remote_host_ = corosio::ipv4_address(b).to_string();
                    } else if (remote_addr_.family == net::ProxyAddressFamily::ipv6) {
                        corosio::ipv6_address::bytes_type b{};
                        std::copy_n(remote_addr_.bytes.begin(), 16, b.begin());
                        remote_host_ = corosio::ipv6_address(b).to_string();
                    } else {
                        remote_host_.assign(reinterpret_cast<char const*>(remote_addr_.bytes.data()), remote_addr_.length);
                    }
                    auto open_deadline = Clock::now() + std::chrono::milliseconds(profile_.timeout_ms);
                    auto open_op = lease_->connection().open_connect_udp(
                        profile_.client_profile->authority(), remote_host_, remote_addr_.port,
                        profile_.auth_header, open_deadline);
                    auto st = co_await LocalOpToken(std::move(open_op), stop_);
                    if (!st && !canceled_ && !session_.closed && !lease_->connection().usable() && Clock::now() < open_deadline) {
                        lease_.reset();
                        auto fresh = co_await worker_.acquire(stop_, open_deadline, false);
                        if (fresh.lease && !canceled_ && !session_.closed) {
                            lease_.emplace(std::move(*fresh.lease));
                            auto retry_op = lease_->connection().open_connect_udp(
                                profile_.client_profile->authority(), remote_host_, remote_addr_.port,
                                profile_.auth_header, open_deadline);
                            st = co_await LocalOpToken(std::move(retry_op), stop_);
                        }
                    }
                    if (!st || canceled_ || session_.closed) {
                        if (st) (*st)->release();
                        lease_.reset();
                        co_return false;
                    }
                    stream_ = std::move(*st);
                    udp_opened_ = true;
                }
                auto frame = net::parse_datagram({}, {}, bytes);
                if (frame.status != net::DatagramStatus::accepted || frame.consumed != bytes.size() ||
                    frame.destination != remote_addr_)
                    co_return false;
                bool ok = stream_->send_datagram(frame.payload);
                if (ok) session_.touched = Clock::now();
                co_return ok;
            }
            if (!stream_) co_return false;
            bool ok = co_await stream_->send(bytes, Clock::now() + std::chrono::seconds(300));
            if (ok) session_.touched = Clock::now();
            co_return ok;
        }

        auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
            if (!ready_ || canceled_) co_return std::unexpected("HTTP/3 tunnel closed");
            if (worker_.enable_datagrams) {
                while (!udp_opened_) {
                    if (canceled_ || session_.closed) co_return std::unexpected("HTTP/3 UDP closed");
                    auto [ec] = co_await corosio::delay(std::chrono::milliseconds(5));
                    if (ec) co_return std::unexpected("HTTP/3 UDP interrupted");
                }
                for (;;) {
                    if (dgram_off_ < dgram_rx_.size()) {
                        auto n = std::min(bytes.size(), dgram_rx_.size() - dgram_off_);
                        std::copy_n(dgram_rx_.begin() + static_cast<std::ptrdiff_t>(dgram_off_), n, bytes.begin());
                        dgram_off_ += n;
                        if (dgram_off_ == dgram_rx_.size()) { dgram_rx_.clear(); dgram_off_ = 0; }
                        session_.touched = Clock::now();
                        co_return n;
                    }
                    auto pkt = co_await stream_->recv_datagram(Clock::now() + std::chrono::seconds(300));
                    if (!pkt) co_return std::unexpected("HTTP/3 datagram stream closed");
                    auto framed = net::encode_datagram({}, remote_addr_, *pkt);
                    if (framed) { dgram_rx_ = std::move(*framed); dgram_off_ = 0; }
                }
            }
            if (!stream_) co_return std::unexpected("HTTP/3 stream closed");
            auto r = co_await stream_->read(bytes, Clock::now() + std::chrono::seconds(300));
            if (r) session_.touched = Clock::now();
            co_return r;
        }

        auto close_output() -> capy::task<bool> {
            if (worker_.enable_datagrams) co_return true;
            co_return stream_ && !canceled_ ? co_await stream_->close_output(Clock::now() + std::chrono::seconds(30)) : false;
        }
        auto upload() -> capy::task<bool> {
            if (!ready_ || !stream_ || up_done_) co_return false;
            up_done_ = true;
            co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{
                session_.client, *stream_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
        auto download() -> capy::task<bool> {
            if (!ready_ || !stream_ || down_done_) co_return false;
            down_done_ = true;
            co_return co_await net::stream_relay::download(net::ByteRelayAdapter{
                session_.client, *stream_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
    };
}
