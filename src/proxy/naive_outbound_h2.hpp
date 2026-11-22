#pragma once

namespace proxy::naive_out_detail {
    struct H2Resolver {
        Session& session;
        nex::corosio::io_context& context;
        std::string const& host;
        std::uint16_t port;
        std::optional<std::size_t> bootstrap;
        DnsSlot slot;

        auto operator()(Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
            if (bootstrap) co_return co_await resolve_bootstrap_owned(session, context, slot, *bootstrap, host, port, deadline);
            co_return co_await resolve_local_owned(session, context, slot, host, port, deadline);
        }
        auto cancel() noexcept -> void { slot.cancel(); }
    };

    struct H2Lower {
        using Candidates = LowerConnector::Candidates;
        Session& session;
        LowerConnector connector;
        H2Lower(Session& s, OutboundContext const& env, TunnelFactory const& detour,
                std::string const& host, std::uint16_t port, std::optional<std::size_t> bs)
            : session(s), connector{{}, &env.context, &detour, host, port, bs} {}
        auto connect(Clock::time_point dl, Candidates& c) -> nex::capy::task<tls::detail::ConnectResult> {
            switch (co_await connector.connect(session, dl, c)) {
            case TunnelConnectResult::connected: co_return tls::detail::ConnectResult::connected;
            case TunnelConnectResult::retryable: co_return tls::detail::ConnectResult::retryable;
            case TunnelConnectResult::timeout: co_return tls::detail::ConnectResult::timeout;
            default: co_return tls::detail::ConnectResult::failed;
            }
        }
        auto retry() noexcept -> bool { return connector.retry(); }
        auto read(std::span<std::uint8_t> bytes) { return connector.tunnel->read(bytes); }
        auto send(std::span<std::uint8_t const> bytes) { return connector.tunnel->send(bytes); }
        auto close_output() { return connector.tunnel->close_output(); }
        auto cancel() noexcept -> void { connector.cancel(); }
    };

    template<int Mode>
    class H2TlsConnector {
        using Physical = tls::detail::PhysicalConnector<H2Resolver, tls::ShapedClientProfile>;
        using Layer = tls::detail::LayerConnector<H2Lower, tls::ShapedClientProfile>;
        using Fast = tls::detail::FastOpenPhysicalConnector<H2Resolver, tls::ShapedClientProfile>;
        using Inner = std::conditional_t<Mode == 1, Layer, std::conditional_t<Mode == 2, Fast, Physical>>;

        Session state_;
        std::optional<Inner> inner_;

    public:
        using Socket = typename Inner::Socket;

        H2TlsConnector(OutboundContext const& env, std::string const& host, std::uint16_t port,
                       std::optional<std::size_t> bootstrap, tls::ShapedClientProfile const& tls_profile,
                       TunnelFactory const* detour, TcpSocketOptions const& options)
            : state_(env.context) {
            state_.dns = env.dns;
            state_.local_dns = env.local_dns;
            state_.tunnel_factories = env.factories;
            state_.direct_tcp_options = env.direct_options;
            if constexpr (Mode == 1) inner_.emplace(tls_profile, state_, env, *detour, host, port, bootstrap);
            else inner_.emplace(env.context, H2Resolver{state_, env.context, host, port, bootstrap, {}}, tls_profile, options);
        }
        ~H2TlsConnector() { cancel(); }
        auto connect(Clock::time_point dl) -> nex::capy::task<bool> {
            co_return co_await inner_->start(dl) == tls::detail::ConnectResult::connected;
        }
        auto application() noexcept -> tls::detail::ApplicationConnection<Socket>* { return inner_->application(); }
        auto negotiated_alpn() const noexcept -> std::string_view {
            auto const* neg = inner_->negotiated();
            if (!neg || !neg->alpn || neg->alpn->empty()) return {};
            return std::string_view(reinterpret_cast<char const*>(neg->alpn->data()), neg->alpn->size());
        }
        auto cancel() noexcept -> void {
            if (inner_) inner_->cancel();
            state_.close();
        }
    };

    struct H2Profile;

    template<int Mode>
    struct H2Worker {
        using Connector = H2TlsConnector<Mode>;
        using Conn = naive::OwnedH2Connection<Connector>;
        using Pool = net::ConnectionPool<Conn, true>;

        OutboundContext environment;
        H2Profile const& profile;
        TunnelFactory const* detour;
        TcpSocketOptions options;
        Pool pool;
        nex::capy::async_mutex starting;
        Conn* starting_conn = nullptr;
        bool stopped = false;

        H2Worker(OutboundContext const& env, H2Profile const& p, TunnelFactory const* lower,
                 TcpSocketOptions opts, std::size_t max_sessions)
            : environment(env), profile(p), detour(lower), options(std::move(opts)),
              pool(net::PoolOptions{.max_sessions = max_sessions, .min_idle = 0,
                                    .idle_timeout = std::chrono::seconds(120)}) {}

        auto stop() noexcept -> void {
            stopped = true;
            if (auto* active = starting_conn) active->stop();
            pool.stop();
        }
        auto drained() const noexcept -> bool { return !starting_conn && pool.drained(); }
        ~H2Worker() { stop(); if (!drained()) std::terminate(); }

        struct AcquireResult {
            std::optional<typename Pool::Lease> lease;
            std::unique_ptr<Connector> h1_fallback;
            TunnelConnectResult error = TunnelConnectResult::failed;
        };

        auto acquire(std::stop_source& caller_stop, Clock::time_point deadline) -> nex::capy::task<AcquireResult>;
    };

    struct H2Profile {
        std::string host;
        std::uint16_t port = 443;
        std::string auth_header;
        std::vector<std::pair<std::string, std::string>> extra_headers;
        bool padding = false;
        bool allow_h1_fallback = false;
        bool fast_open = false;
        std::optional<std::size_t> bootstrap;
        std::uint32_t timeout_ms = 10000;
        std::size_t max_sessions = 8;
        TcpSocketOptions options;
        tls::ShapedClientProfile tls;
        std::mutex mutex;
        std::array<std::unique_ptr<H2Worker<0>>, 17> physical;
        std::array<std::unique_ptr<H2Worker<1>>, 17> layered;
        std::array<std::unique_ptr<H2Worker<2>>, 17> fast;

        H2Profile(std::string h, std::uint16_t p, std::string auth,
                  std::vector<std::pair<std::string, std::string>> eh,
                  bool pad, bool h1fb, bool fo, std::optional<std::size_t> bs,
                  std::uint32_t tms, std::size_t ms, TcpSocketOptions opts,
                  tls::ShapedClientProfile tls_in)
            : host(std::move(h)), port(p), auth_header(std::move(auth)),
              extra_headers(std::move(eh)), padding(pad), allow_h1_fallback(h1fb),
              fast_open(fo), bootstrap(bs), timeout_ms(tms), max_sessions(ms),
              options(std::move(opts)), tls(std::move(tls_in)) {}

        ~H2Profile() {
            if (!auth_header.empty())
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(auth_header.data()), auth_header.size()));
        }
    };

    template<int Mode>
    auto H2Worker<Mode>::acquire(std::stop_source& caller_stop, Clock::time_point deadline)
        -> nex::capy::task<AcquireResult> {
        if (stopped || caller_stop.stop_requested()) co_return AcquireResult{.error = TunnelConnectResult::failed};
        if (Clock::now() >= deadline) co_return AcquireResult{.error = TunnelConnectResult::timeout};
        pool.reap(Clock::now());
        if (auto reused = pool.acquire()) co_return AcquireResult{.lease = std::move(*reused)};
        auto wait = nex::corosio::timeout(starting.scoped_lock(), deadline);
        auto [lock_ec, lock] = co_await LocalOpToken(std::move(wait), caller_stop);
        if (lock_ec || caller_stop.stop_requested() || stopped || Clock::now() >= deadline)
            co_return AcquireResult{.error = Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed};
        if (auto reused = pool.acquire()) co_return AcquireResult{.lease = std::move(*reused)};
        auto slot = pool.reserve();
        if (!slot) co_return AcquireResult{.error = TunnelConnectResult::failed};
        auto conn = std::make_unique<Conn>(environment, profile.host, profile.port,
                                           profile.bootstrap, profile.tls, detour, options);
        struct Reg {
            H2Worker& w;
            Reg(H2Worker& owner, Conn* c) noexcept : w(owner) { w.starting_conn = c; }
            ~Reg() { w.starting_conn = nullptr; }
        } reg(*this, conn.get());
        typename Conn::StartResult started;
        {
            std::stop_callback cb(caller_stop.get_token(), [p = conn.get()]() noexcept { p->stop(); });
            started = co_await conn->start(deadline);
        }
        if (caller_stop.stop_requested() || stopped) co_return AcquireResult{.error = TunnelConnectResult::failed};
        if (started == Conn::StartResult::non_h2_tls && profile.allow_h1_fallback) {
            auto fallback = conn->take_non_h2_connector();
            if (fallback) co_return AcquireResult{.h1_fallback = std::move(fallback)};
            co_return AcquireResult{.error = TunnelConnectResult::failed};
        }
        if (started != Conn::StartResult::connected)
            co_return AcquireResult{.error = started == Conn::StartResult::timeout || Clock::now() >= deadline
                ? TunnelConnectResult::timeout : TunnelConnectResult::failed};
        auto lease = slot->commit(std::move(conn));
        if (!lease) co_return AcquireResult{.error = TunnelConnectResult::failed};
        if (!lease->connection().run(environment.context))
            co_return AcquireResult{.error = TunnelConnectResult::failed};
        co_return AcquireResult{.lease = std::move(*lease)};
    }

    template<int Mode>
    class H2Tunnel {
        using Worker = H2Worker<Mode>;
        using Connector = typename Worker::Connector;
        using TlsByteStream = tls::detail::ByteStream<typename Connector::Socket>;
        using H2Stream = naive::H2ClientStream<typename Worker::Conn::Stream>;

        Session& session_;
        Worker& worker_;
        H2Profile const& profile_;
        bool relay_local_;
        std::stop_source stop_;
        std::optional<typename Worker::Pool::Lease> lease_;
        std::unique_ptr<H2Stream> stream_;
        std::unique_ptr<Connector> h1_conn_;
        std::unique_ptr<TlsByteStream> h1_stream_;
        std::string h1_tail_;
        std::size_t h1_tail_off_ = 0;
        bool ready_ = false, canceled_ = false, up_done_ = false, down_done_ = false;

        auto handshake_h1(std::string_view authority, Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
            auto* app = h1_conn_->application();
            if (!app) co_return TunnelConnectResult::failed;
            h1_stream_ = std::make_unique<TlsByteStream>(*app);
            std::string req = "CONNECT ";
            req.append(authority).append(" HTTP/1.1\r\nHost: ").append(authority).append("\r\n");
            if (!profile_.auth_header.empty()) req.append("Proxy-Authorization: ").append(profile_.auth_header).append("\r\n");
            for (auto const& [k, v] : profile_.extra_headers) req.append(k).append(": ").append(v).append("\r\n");
            req += "Proxy-Connection: keep-alive\r\n\r\n";
            if (!co_await h1_stream_->send({reinterpret_cast<std::uint8_t const*>(req.data()), req.size()}, deadline))
                co_return TunnelConnectResult::failed;
            std::string buf;
            std::array<std::uint8_t, 1024> chunk{};
            while (buf.size() < 8192) {
                auto got = co_await h1_stream_->read(chunk, deadline);
                if (!got || !*got) co_return TunnelConnectResult::failed;
                buf.append(reinterpret_cast<char const*>(chunk.data()), *got);
                auto pos = buf.find("\r\n\r\n");
                if (pos != std::string::npos) {
                    auto sl = std::string_view(buf).substr(0, buf.find("\r\n"));
                    if (!sl.starts_with("HTTP/1.") || sl.size() < 12 || sl.substr(9, 3) != "200")
                        co_return TunnelConnectResult::failed;
                    if (pos + 4 < buf.size()) h1_tail_ = buf.substr(pos + 4);
                    ready_ = true;
                    co_return TunnelConnectResult::connected;
                }
            }
            co_return TunnelConnectResult::failed;
        }

        auto connect_auth(std::string authority, Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
            if (ready_ || canceled_ || session_.closed) co_return TunnelConnectResult::failed;
            auto res = co_await worker_.acquire(stop_, deadline);
            if (res.h1_fallback) { h1_conn_ = std::move(res.h1_fallback); co_return co_await handshake_h1(authority, deadline); }
            if (!res.lease) co_return res.error;
            lease_.emplace(std::move(*res.lease));
            auto st = co_await lease_->connection().open_connect(
                authority, profile_.auth_header, profile_.extra_headers, profile_.padding, deadline);
            if (!st || canceled_ || session_.closed) {
                if (st) (*st)->release();
                lease_.reset();
                co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            }
            stream_ = std::move(*st);
            ready_ = true;
            co_return TunnelConnectResult::connected;
        }

    public:
        H2Tunnel(Session& session, Worker& worker, H2Profile const& profile, bool relay_local)
            : session_(session), worker_(worker), profile_(profile), relay_local_(relay_local) {}
        ~H2Tunnel() { cancel(); stream_.reset(); lease_.reset(); h1_stream_.reset(); h1_conn_.reset(); }

        auto cancel() noexcept -> void {
            if (std::exchange(canceled_, true)) return;
            stop_.request_stop();
            if (stream_) stream_->release();
            if (h1_stream_) h1_stream_->cancel();
            if (h1_conn_) h1_conn_->cancel();
            if (ready_ && relay_local_) session_.client.cancel();
        }
        auto connect(nex::corosio::endpoint dst) -> nex::capy::task<TunnelConnectResult> {
            return connect_until(dst, session_.started + std::chrono::milliseconds(profile_.timeout_ms));
        }
        auto connect_until(nex::corosio::endpoint dst, Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
            return connect_auth(format_authority(dst), deadline);
        }
        auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
            return connect_auth(format_domain_authority(domain, port), deadline);
        }
        auto packet_transport() const noexcept -> net::PacketTransport { return {}; }
        auto connect_packets(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto has_uot() const noexcept -> bool { return false; }
        auto connect_uot() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_uot_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto has_xudp() const noexcept -> bool { return false; }
        auto connect_xudp() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_xudp_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }

        auto send(std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
            if (!ready_ || canceled_) co_return false;
            auto dl = Clock::now() + std::chrono::seconds(300);
            bool ok = stream_ ? co_await stream_->send(bytes, dl) : co_await h1_stream_->send(bytes, dl);
            if (ok) session_.touched = Clock::now();
            co_return ok;
        }
        auto read(std::span<std::uint8_t> bytes) -> nex::capy::task<std::expected<std::size_t, std::string>> {
            if (!ready_ || canceled_) co_return std::unexpected("HTTP/2 tunnel closed");
            if (h1_tail_off_ < h1_tail_.size()) {
                auto n = std::min(bytes.size(), h1_tail_.size() - h1_tail_off_);
                std::copy_n(h1_tail_.data() + h1_tail_off_, n, reinterpret_cast<char*>(bytes.data()));
                h1_tail_off_ += n;
                if (h1_tail_off_ == h1_tail_.size()) { std::string{}.swap(h1_tail_); h1_tail_off_ = 0; }
                session_.touched = Clock::now();
                co_return n;
            }
            auto dl = Clock::now() + std::chrono::seconds(300);
            if (stream_) {
                auto r = co_await stream_->read(bytes, dl);
                if (r) session_.touched = Clock::now();
                co_return r;
            }
            auto r = co_await h1_stream_->read(bytes, dl);
            if (!r) co_return std::unexpected("HTTP/1.1 TLS read failed");
            session_.touched = Clock::now();
            co_return *r;
        }
        auto close_output() -> nex::capy::task<bool> {
            if (!ready_ || canceled_) co_return false;
            auto dl = Clock::now() + std::chrono::seconds(30);
            if (stream_) co_return co_await stream_->close_output(dl);
            co_return co_await h1_stream_->close_output(dl);
        }
        auto upload() -> nex::capy::task<bool> {
            if (!ready_ || up_done_) co_return false;
            up_done_ = true;
            co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{
                session_.client, *this, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
        auto download() -> nex::capy::task<bool> {
            if (!ready_ || down_done_) co_return false;
            down_done_ = true;
            co_return co_await net::stream_relay::download(net::ByteRelayAdapter{
                session_.client, *this, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
    };
}
