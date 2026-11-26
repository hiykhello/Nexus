module;
#include <string.h>
#include <boost/capy/ex/run_async.hpp>

module relay;
import std;
import proxy.v4;
import crypto;
import rulefile;
import ssh.wire;
import ssh.crypto;
import ssh.session;
import ssh.connection;
import net.connection_pool;
import net.operation_token;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import platform.ip_address;
import capy;
import corosio;

namespace relay {
    namespace {
        template<int> struct SshWorker;

        struct SshProfile {
            std::string host;
            std::uint16_t port = 22;
            ssh::ClientAuth auth;
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout_ms = 10000;
            std::size_t max_sessions = 16;
            TcpSocketOptions options;
            bool fast_open = false;
            std::mutex mutex;
            std::vector<std::unique_ptr<SshWorker<0>>> physical;
            std::vector<std::unique_ptr<SshWorker<1>>> layered;
            std::vector<std::unique_ptr<SshWorker<2>>> fast;
            ~SshProfile();
        };

        struct SshLower {
            using Candidates = LowerConnector::Candidates;
            Session& session;
            LowerConnector connector;
            SshLower(Session& s, OutboundContext const& env, TunnelFactory const& detour, SshProfile const& p)
                : session(s), connector{{}, &env.context, &detour, p.host, p.port, p.bootstrap} {}
            auto connect(Clock::time_point dl, Candidates& candidates) { return connector.connect(session, dl, candidates); }
            auto read(std::span<std::uint8_t> bytes) { return connector.tunnel->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return connector.tunnel->send(bytes); }
            auto close_output() { return connector.tunnel->close_output(); }
            auto cancel() noexcept -> void { connector.cancel(); }
        };

        template<int Mode>
        class SshNode {
        public:
            using Socket = std::conditional_t<Mode == 1, SshLower,
                std::conditional_t<Mode == 2, net::FastOpenStream, corosio::tcp_socket>>;
        private:
            Session state_;
            OutboundContext const& environment_;
            SshProfile const& profile_;
            TcpSocketOptions const& options_;
            DnsSlot dns_;
            std::optional<Socket> socket_;
            bool canceled_ = false;
        public:
            SshNode(OutboundContext const& env, SshProfile const& p, TunnelFactory const* detour, TcpSocketOptions const& opts)
                : state_(env.context), environment_(env), profile_(p), options_(opts) {
                state_.dns = env.dns;
                state_.local_dns = env.local_dns;
                if (env.owner) state_.route_snapshot = env.owner->current_route_snapshot();
                state_.tunnel_factories = env.factories;
                state_.direct_tcp_options = env.direct_options;
                if constexpr (Mode == 1) socket_.emplace(state_, env, *detour, p);
            }
            ~SshNode() { state_.close(); }
            auto connect(Clock::time_point dl) -> capy::task<bool> {
                if (canceled_ || Clock::now() >= dl) co_return false;
                if constexpr (Mode == 1) {
                    typename SshLower::Candidates candidates;
                    co_return co_await socket_->connect(dl, candidates) == TunnelConnectResult::connected && !canceled_;
                } else {
                    auto endpoints = profile_.bootstrap
                        ? co_await resolve_bootstrap_owned(state_, environment_.context, dns_, *profile_.bootstrap, profile_.host, profile_.port, dl)
                        : co_await resolve_local_owned(state_, environment_.context, dns_, profile_.host, profile_.port, dl);
                    if (canceled_ || Clock::now() >= dl || !endpoints || endpoints->empty()) co_return false;
                    if constexpr (Mode == 2) {
                        socket_.emplace(environment_.context, std::move(*endpoints), dl, options_);
                        co_return !canceled_;
                    } else {
                        socket_.emplace(environment_.context);
                        bool preparation_failed = false;
                        auto op = net::connect_tcp_candidates(*socket_, std::span(*endpoints),
                            [](auto const&, auto const& ep) { return valid_destination(ep); },
                            options_, preparation_failed, dl);
                        auto [error, selected] = co_await corosio::timeout(std::move(op), dl);
                        if (error || canceled_) co_return false;
                        state_.record_physical_peer(selected);
                        co_return true;
                    }
                }
            }
            auto socket() noexcept -> Socket& { return *socket_; }
            auto cancel() noexcept -> void {
                canceled_ = true;
                dns_.cancel();
                if (socket_) socket_->cancel();
                state_.close();
            }
        };

        template<int Mode>
        struct SshWorker {
            using Conn = ssh::OwnedConnection<SshNode<Mode>>;
            using Pool = net::ConnectionPool<Conn, true>;
            OutboundContext environment;
            SshProfile const& profile;
            TunnelFactory const* detour;
            TcpSocketOptions options;
            Pool pool;
            capy::async_mutex starting;
            capy::async_event stop_ev_;
            Conn* starting_connection = nullptr;
            bool stopped = false, reaper_active_ = false;

            SshWorker(OutboundContext const& env, SshProfile const& value, TunnelFactory const* lower, TcpSocketOptions opts)
                : environment(env), profile(value), detour(lower), options(opts),
                  pool(net::PoolOptions{.max_sessions = value.max_sessions, .min_idle = 0, .idle_timeout = std::chrono::seconds(120)}) {}

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
                if (auto* active = starting_connection) active->stop();
                pool.stop();
            }
            auto drained() const noexcept -> bool { return !reaper_active_ && !starting_connection && pool.drained(); }
            ~SshWorker() { stop(); if (!drained()) std::terminate(); }

            auto acquire(std::stop_source& caller_stop, Clock::time_point deadline)
                -> capy::task<std::expected<typename Pool::Lease, TunnelConnectResult>> {
                if (stopped || caller_stop.stop_requested()) co_return std::unexpected(TunnelConnectResult::failed);
                if (Clock::now() >= deadline) co_return std::unexpected(TunnelConnectResult::timeout);
                pool.reap(Clock::now());
                if (auto reused = pool.acquire()) co_return std::move(*reused);
                auto wait = corosio::timeout(starting.scoped_lock(), deadline);
                auto [lock_error, lock] = co_await net::OperationToken(std::move(wait), caller_stop);
                if (lock_error || caller_stop.stop_requested() || stopped || Clock::now() >= deadline)
                    co_return std::unexpected(Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
                if (auto reused = pool.acquire()) co_return std::move(*reused);
                auto creation = pool.reserve();
                if (!creation) co_return std::unexpected(TunnelConnectResult::failed);
                auto connection = std::make_unique<Conn>(environment, profile, detour, options);
                struct Starting {
                    SshWorker& worker;
                    Starting(SshWorker& owner, Conn* c) noexcept : worker(owner) { worker.starting_connection = c; }
                    ~Starting() { worker.starting_connection = nullptr; }
                } registration(*this, connection.get());
                typename Conn::StartResult started;
                {
                    std::stop_callback starting_cb(caller_stop.get_token(), [p = connection.get()]() noexcept { p->stop(); });
                    started = co_await connection->start(profile.auth, deadline);
                }
                if (started != Conn::StartResult::connected || caller_stop.stop_requested() || stopped)
                    co_return std::unexpected(started == Conn::StartResult::timeout || Clock::now() >= deadline
                        ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
                auto accepted = creation->commit(std::move(connection));
                if (!accepted) co_return std::unexpected(TunnelConnectResult::failed);
                accepted->connection().run(environment.context);
                co_return std::move(*accepted);
            }
        };

        SshProfile::~SshProfile() {
            if (auth.password)
                crypto::cleanse(std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t*>(auth.password->data()), auth.password->size()));
        }

        template<int Mode>
        auto ssh_slots(SshProfile& profile) noexcept -> auto& {
            if constexpr (Mode == 1) return profile.layered;
            else if constexpr (Mode == 2) return profile.fast;
            else return profile.physical;
        }
        template<int Mode>
        auto ssh_find(SshProfile& profile, corosio::io_context& context) noexcept -> SshWorker<Mode>* {
            for (auto const& w : ssh_slots<Mode>(profile))
                if (w && &w->environment.context == &context) return w.get();
            return nullptr;
        }
        template<int Mode>
        auto ssh_initialize(SshProfile& profile, OutboundContext const& env, TunnelFactory const* detour, bool direct) -> bool {
            std::lock_guard lock(profile.mutex);
            if (ssh_find<Mode>(profile, env.context)) return false;
            auto& entries = ssh_slots<Mode>(profile);
            auto slot = std::ranges::find_if(entries, [](auto const& w) { return !w; });
            if (direct && !env.direct_options) return false;
            bool append = slot == entries.end();
            if (append) entries.reserve(entries.size() + 1);
            auto worker = std::make_unique<SshWorker<Mode>>(env, profile, detour, direct ? *env.direct_options : profile.options);
            worker->start_reaper();
            if (!append) *slot = std::move(worker); else entries.push_back(std::move(worker));
            return true;
        }
        template<int Mode>
        auto ssh_stop(SshProfile& profile, corosio::io_context& context) noexcept -> void {
            SshWorker<Mode>* worker = nullptr;
            { std::lock_guard lock(profile.mutex); worker = ssh_find<Mode>(profile, context); }
            if (worker) worker->stop();
        }
        template<int Mode>
        auto ssh_drained(SshProfile& profile, corosio::io_context& context) noexcept -> bool {
            std::lock_guard lock(profile.mutex);
            for (auto const& worker : ssh_slots<Mode>(profile))
                if (worker && &worker->environment.context == &context && !worker->drained()) return false;
            return true;
        }
        template<int Mode>
        auto ssh_finish(SshProfile& profile, corosio::io_context& context) noexcept -> void {
            std::lock_guard lock(profile.mutex);
            for (auto& worker : ssh_slots<Mode>(profile)) {
                if (worker && &worker->environment.context == &context) {
                    if (!worker->drained()) std::terminate();
                    worker.reset();
                    return;
                }
            }
        }

        template<int Mode>
        class SshTunnel {
            using Worker = SshWorker<Mode>;
            using Pool = typename Worker::Pool;
            using Conn = typename Worker::Conn;
            Session& session_;
            Worker& worker_;
            std::uint32_t timeout_ms_;
            bool relay_local_, ready_ = false;
            std::stop_source stop_;
            std::optional<typename Pool::Lease> lease_;
            std::optional<ssh::Channel<typename Conn::Stream>> channel_;

            auto open_target(std::string_view host, std::uint16_t port, Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                if (ready_ || lease_ || stop_.stop_requested() || session_.closed || host.empty() || !port)
                    co_return TunnelConnectResult::failed;
                struct Guard {
                    SshTunnel& owner;
                    bool done = false;
                    ~Guard() {
                        if (!done) {
                            owner.cancel();
                            owner.channel_.reset();
                            owner.lease_.reset();
                        }
                    }
                } guard{*this};
                auto lease = co_await worker_.acquire(stop_, deadline);
                if (!lease) co_return lease.error();
                lease_.emplace(std::move(*lease));
                auto* protocol = lease_->connection().protocol();
                if (!protocol || !protocol->usable()) {
                    lease_->connection().cancel();
                    co_return TunnelConnectResult::failed;
                }
                auto id = co_await protocol->open_direct_tcpip(host, port, deadline, stop_.get_token());
                if (!id || stop_.stop_requested() || session_.closed) {
                    if (!protocol->usable()) lease_->connection().cancel();
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                }
                channel_.emplace(*protocol, *id);
                ready_ = true;
                guard.done = true;
                co_return TunnelConnectResult::connected;
            }
        public:
            SshTunnel(Session& s, Worker& w, std::uint32_t timeout_ms, bool relay_local)
                : session_(s), worker_(w), timeout_ms_(timeout_ms), relay_local_(relay_local) {}
            auto cancel() noexcept -> void {
                stop_.request_stop();
                if (channel_) channel_->cancel();
                if (ready_ && relay_local_) session_.client.cancel();
            }
            auto connect(corosio::endpoint ep) -> capy::task<TunnelConnectResult> {
                return connect_until(ep, session_.started + std::chrono::milliseconds(timeout_ms_));
            }
            auto connect_until(corosio::endpoint ep, Clock::time_point dl) -> capy::task<TunnelConnectResult> {
                if (!valid_destination(ep)) co_return TunnelConnectResult::failed;
                co_return co_await open_target(ep.address().to_string(), ep.port(), dl);
            }
            auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point dl)
                -> capy::task<TunnelConnectResult> {
                co_return co_await open_target(domain, port, dl);
            }
            auto packet_transport() const noexcept -> net::PacketTransport { return {}; }
            auto has_uot() const noexcept -> bool { return false; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_packets(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                auto ok = co_await channel_->send(bytes);
                if (ok) session_.touched = Clock::now();
                else cancel();
                co_return ok;
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if (!ready_ || stop_.stop_requested()) co_return std::unexpected("SSH channel closed");
                auto n = co_await channel_->read(bytes);
                if (!n) { cancel(); co_return std::unexpected(n.error()); }
                if (*n) session_.touched = Clock::now();
                co_return *n;
            }
            auto close_output() -> capy::task<bool> { co_return ready_ && co_await channel_->close_output(); }
            auto upload() -> capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::upload(
                    net::ByteRelayAdapter{session_.client, *channel_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
            auto download() -> capy::task<bool> {
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await net::stream_relay::download(
                    net::ByteRelayAdapter{session_.client, *channel_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
        };
    }

    auto make_ssh_factory(std::string_view host, std::uint16_t port, std::string_view user,
        std::optional<std::string_view> password_file, std::optional<std::string_view> private_key_file,
        std::span<std::array<std::uint8_t, 32> const> host_key_sha256, std::string_view cipher,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, std::uint32_t keepalive_ms,
        std::size_t max_sessions, TcpSocketOptions options, bool fast_open) -> std::expected<TunnelFactory, std::string> {
        auto bad_text = [](std::string_view v, std::size_t max_len) noexcept {
            return v.empty() || v.size() > max_len || std::ranges::any_of(v, [](unsigned char c) { return c < 33 || c > 126; });
        };
        if (bad_text(host, 253) || !port || bad_text(user, 128) || host_key_sha256.empty() ||
            !timeout_ms || timeout_ms > 3600000 || !max_sessions || max_sessions > 256 || !options.valid())
            return std::unexpected("invalid SSH outbound options");
        if (!password_file && !private_key_file)
            return std::unexpected("SSH outbound requires password-file or private-key-file");
        if (!cipher.empty() && !ssh::parse_cipher_kind(cipher))
            return std::unexpected("unsupported SSH cipher");

        ssh::ClientAuth auth;
        auth.user = std::string(user);
        auth.host_key_sha256.assign(host_key_sha256.begin(), host_key_sha256.end());
        auth.preferred_cipher = std::string(cipher);
        auth.keepalive_interval_ms = keepalive_ms;
        if (password_file) {
            auto pf = rulefile::read_private_file(*password_file);
            if (!pf) return std::unexpected("SSH password file: " + pf.error());
            auto b = pf->bytes();
            while (!b.empty() && (b.back() == '\n' || b.back() == '\r')) b = b.first(b.size() - 1);
            if (b.empty() || b.size() > 4096) return std::unexpected("invalid SSH password length");
            auth.password.emplace(b.data(), b.size());
        }
        if (private_key_file) {
            auto kf = rulefile::read_private_file(*private_key_file);
            if (!kf) return std::unexpected("SSH private key file: " + kf.error());
            auto pk = ssh::PrivateKey::parse(std::string_view(kf->bytes().data(), kf->bytes().size()));
            if (!pk) return std::unexpected("SSH private key: " + pk.error());
            auth.private_key.emplace(std::move(*pk));
        }

        auto profile = std::make_unique<SshProfile>(std::string(host), port, std::move(auth),
            bootstrap, timeout_ms, max_sessions, options, fast_open);
        auto* borrowed = profile.get();
        TunnelFactory factory{
            [profile = std::move(profile)](Session& session, corosio::io_context& context, bool local, TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
                SshWorker<2>* fast = nullptr;
                { std::lock_guard lock(profile->mutex); fast = ssh_find<2>(*profile, context); }
                if (fast) return pro::make_proxy<TunnelFacade, SshTunnel<2>>(session, *fast, profile->timeout_ms, local);
                SshWorker<0>* worker = nullptr;
                { std::lock_guard lock(profile->mutex); worker = ssh_find<0>(*profile, context); }
                return worker ? pro::make_proxy<TunnelFacade, SshTunnel<0>>(session, *worker, profile->timeout_ms, local) : pro::proxy<TunnelFacade>{};
            },
            timeout_ms,
            [borrowed](Session& session, corosio::io_context& context, TunnelFactory const&, bool local) -> pro::proxy<TunnelFacade> {
                SshWorker<1>* worker = nullptr;
                { std::lock_guard lock(borrowed->mutex); worker = ssh_find<1>(*borrowed, context); }
                return worker ? pro::make_proxy<TunnelFacade, SshTunnel<1>>(session, *worker, borrowed->timeout_ms, local) : pro::proxy<TunnelFacade>{};
            },
            std::nullopt,
            options.configured() || fast_open
        };
        factory.start_context = [borrowed](OutboundContext const& env, TunnelFactory const* detour, bool direct) {
            auto fast = direct && env.direct_options ? env.direct_options->tcp_fast_open.value_or(false) : borrowed->fast_open;
            return detour ? ssh_initialize<1>(*borrowed, env, detour, direct)
                          : (fast ? ssh_initialize<2>(*borrowed, env, nullptr, direct)
                                  : ssh_initialize<0>(*borrowed, env, nullptr, direct));
        };
        factory.stop_context = [borrowed](corosio::io_context& context) noexcept {
            ssh_stop<0>(*borrowed, context);
            ssh_stop<1>(*borrowed, context);
            ssh_stop<2>(*borrowed, context);
        };
        factory.reap_context = [borrowed](corosio::io_context& context) noexcept {
            std::lock_guard lock(borrowed->mutex);
            if (auto* w = ssh_find<0>(*borrowed, context)) w->pool.reap(Clock::time_point::max());
            if (auto* w = ssh_find<1>(*borrowed, context)) w->pool.reap(Clock::time_point::max());
            if (auto* w = ssh_find<2>(*borrowed, context)) w->pool.reap(Clock::time_point::max());
        };
        factory.quiesced_context = [borrowed](corosio::io_context& context) noexcept {
            return ssh_drained<0>(*borrowed, context) && ssh_drained<1>(*borrowed, context) && ssh_drained<2>(*borrowed, context);
        };
        factory.finish_context = [borrowed](corosio::io_context& context) noexcept {
            ssh_finish<0>(*borrowed, context);
            ssh_finish<1>(*borrowed, context);
            ssh_finish<2>(*borrowed, context);
        };
        return factory;
    }
}
