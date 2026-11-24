// Borrowed-lease HTTP/2 gRPC multiplexed connection pool for proxy outbounds.
module;
#include <boost/capy/ex/run_async.hpp>

module relay:grpc_pool;
import std;
import grpc.headers;
import grpc.session;
import grpc.connection;
import tls.profiles;
import tls.connector;
import net.connection_pool;
import net.operation_token;
import capy;
import corosio;
import :types;
import :server_interface;
import :tunnel_facade;
import :route_interface;
import :session_interface;
import :internal_decls;

namespace relay::grpc_pool {
    namespace g = grpc;
    using Connected = tls::detail::ConnectResult;
    using Mode = tls::detail::TransportMode;

    struct EndpointSpec {
        std::string_view host;
        std::uint16_t port;
        std::optional<std::size_t> bootstrap;
        tls::ShapedClientProfile const& tls;
        g::RequestProfile const& request;
        g::ResponsePolicy response;
        g::Limits limits;
        std::size_t max_sessions;
    };

    struct Resolver {
        Session& session;
        corosio::io_context& context;
        std::string_view host;
        std::uint16_t port;
        std::optional<std::size_t> bootstrap;
        DnsSlot slot;
        inline auto operator()(Clock::time_point deadline) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
            if (bootstrap)
                return resolve_bootstrap_owned(session, context, slot, *bootstrap, std::string(host), port, deadline);
            return resolve_local_owned(session, context, slot, std::string(host), port, deadline);
        }
        inline auto connected(corosio::endpoint const& endpoint) noexcept -> void { session.record_physical_peer(endpoint); }
        inline auto cancel() noexcept -> void { slot.cancel(); }
    };

    struct Lower {
        using Candidates = LowerConnector::Candidates;
        Session& session;
        LowerConnector connector;
        inline Lower(Session& state, OutboundContext const& environment, TunnelFactory const& detour,
              std::string_view host, std::uint16_t port, std::optional<std::size_t> bootstrap)
            : session(state), connector{{}, &environment.context, &detour, host, port, bootstrap} {}
        inline auto connect(Clock::time_point deadline, Candidates& candidates) -> capy::task<Connected> {
            switch (co_await connector.connect(session, deadline, candidates)) {
            case TunnelConnectResult::connected: co_return Connected::connected;
            case TunnelConnectResult::retryable: co_return Connected::retryable;
            case TunnelConnectResult::timeout: co_return Connected::timeout;
            default: co_return Connected::failed;
            }
        }
        inline auto retry() noexcept -> bool { return connector.retry(); }
        inline auto read(std::span<std::uint8_t> bytes) { return connector.tunnel->read(bytes); }
        inline auto send(std::span<std::uint8_t const> bytes) { return connector.tunnel->send(bytes); }
        inline auto close_output() { return connector.tunnel->close_output(); }
        inline auto cancel() noexcept -> void { connector.cancel(); }
    };

    class Node {
        using Connector = tls::detail::UnifiedConnector<Resolver, Lower, tls::ShapedClientProfile>;
        Session state_;
        std::optional<Connector> connector_;
    public:
        using Socket = typename Connector::Socket;
        inline Node(OutboundContext const& environment, EndpointSpec const& spec, TunnelFactory const* detour,
             TcpSocketOptions const& options, Mode mode)
            : state_(environment.context) {
            state_.dns = environment.dns;
            state_.local_dns = environment.local_dns;
            if (environment.owner) state_.route_snapshot = environment.owner->current_route_snapshot();
            state_.tunnel_factories = environment.factories;
            state_.direct_tcp_options = environment.direct_options;
            if (mode == Mode::layered)
                connector_.emplace(environment.context, spec.tls, std::in_place, state_, environment, *detour,
                                   spec.host, spec.port, spec.bootstrap);
            else
                connector_.emplace(mode, environment.context,
                                   Resolver{state_, environment.context, spec.host, spec.port, spec.bootstrap, {}},
                                   spec.tls, options);
        }
        inline ~Node() { state_.close(); }
        inline auto start(Clock::time_point deadline) { return connector_->start(deadline); }
        inline auto application() noexcept { return connector_->application(); }
        inline auto accepts_alpn() const noexcept -> bool {
            auto* selected = connector_->negotiated();
            return selected && selected->alpn && std::ranges::equal(*selected->alpn, std::string_view("h2"));
        }
        inline auto cancel() noexcept -> void { connector_->cancel(); state_.close(); }
    };

    using Connection = g::OwnedConnection<Node, g::detail::ByteStreamReadPolicy, 16>;

    struct PoolWorker {
        using Conn = grpc_pool::Connection;
        using Pool = net::ConnectionPool<Conn, true>;
        OutboundContext environment_;
        EndpointSpec spec;
        TunnelFactory const* detour;
        TcpSocketOptions options;
        Mode mode;
        Pool pool;
        capy::async_mutex starting;
        capy::async_event stop_ev_;
        Conn* starting_connection = nullptr;
        bool stopped = false, reaper_active_ = false;

        inline PoolWorker(OutboundContext const& env, EndpointSpec value, TunnelFactory const* lower,
                   TcpSocketOptions selected, Mode m)
            : environment_(env), spec(value), detour(lower), options(selected), mode(m),
              pool(net::PoolOptions{.max_sessions = value.max_sessions}) {}

        inline auto reap_loop() -> capy::task<> {
            struct Done { bool& flag; ~Done() { flag = false; } } done{reaper_active_};
            while (!stopped) {
                stop_ev_.clear();
                if (stopped) break;
                auto [ec] = co_await corosio::timeout(stop_ev_.wait(), Clock::now() + std::chrono::seconds(10));
                if (stopped || ec != capy::cond::timeout) break;
                pool.reap(Clock::now());
            }
        }

        inline auto start_reaper() -> void {
            if (stopped || reaper_active_) return;
            reaper_active_ = true;
            capy::run_async(environment_.context.get_executor(), [] {}, [this](std::exception_ptr) noexcept {
                reaper_active_ = false;
            })(reap_loop());
        }

        inline auto environment() const noexcept -> OutboundContext const& { return environment_; }
        inline auto stop() noexcept -> void {
            stopped = true;
            stop_ev_.set();
            if (auto* active = starting_connection) active->stop();
            pool.stop();
        }
        inline auto drained() const noexcept -> bool { return !reaper_active_ && !starting_connection && pool.drained(); }
        inline ~PoolWorker() { stop(); if (!drained()) std::terminate(); }

        inline auto acquire(std::stop_source& caller_stop, Clock::time_point deadline)
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
            auto connection = std::make_unique<Conn>(environment_, spec, detour, options, mode);
            struct Starting {
                PoolWorker& worker;
                inline Starting(PoolWorker& owner, Conn* c) noexcept : worker(owner) { worker.starting_connection = c; }
                inline ~Starting() { worker.starting_connection = nullptr; }
            } registration(*this, connection.get());
            Connected connected;
            {
                std::stop_callback starting_cb(caller_stop.get_token(), [p = connection.get()]() noexcept { p->stop(); });
                connected = co_await connection->start(spec.request, spec.limits, spec.response, deadline);
            }
            if (connected != Connected::connected || caller_stop.stop_requested() || stopped)
                co_return std::unexpected(connected == Connected::timeout || Clock::now() >= deadline
                    ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
            auto accepted = creation->commit(std::move(connection));
            if (!accepted) co_return std::unexpected(TunnelConnectResult::failed);
            accepted->connection().run(environment_.context);
            co_return std::move(*accepted);
        }
    };

    template<class Profile>
    auto slots(Profile& profile, Mode mode) noexcept -> auto& {
        if (mode == Mode::layered) return profile.layered;
        if (mode == Mode::fast_open) return profile.fast;
        return profile.physical;
    }

    template<class Profile>
    auto find(Profile& profile, Mode mode, corosio::io_context& context) noexcept {
        for (auto const& slot : slots(profile, mode))
            if (slot && &slot->environment().context == &context) return slot.get();
        return static_cast<typename std::remove_reference_t<decltype(slots(profile, mode))>::value_type::element_type*>(nullptr);
    }

    template<class Profile>
    auto stop(Profile& profile, corosio::io_context& context) noexcept -> void {
        for (auto mode : {Mode::physical, Mode::layered, Mode::fast_open}) {
            typename std::remove_reference_t<decltype(slots(profile, mode))>::value_type::element_type* worker = nullptr;
            { std::lock_guard lock(profile.mutex); worker = find(profile, mode, context); }
            if (worker) worker->stop();
        }
    }

    template<class Profile>
    auto reap(Profile& profile, corosio::io_context& context) noexcept -> void {
        for (auto mode : {Mode::physical, Mode::layered, Mode::fast_open}) {
            typename std::remove_reference_t<decltype(slots(profile, mode))>::value_type::element_type* worker = nullptr;
            { std::lock_guard lock(profile.mutex); worker = find(profile, mode, context); }
            if (worker) {
                if constexpr (requires { worker->reap(); }) worker->reap();
                else if constexpr (requires { worker->grpc; }) worker->grpc.pool.reap(Clock::time_point::max());
                else worker->pool.reap(Clock::time_point::max());
            }
        }
    }

    template<class Profile>
    auto drained(Profile& profile, corosio::io_context& context) noexcept -> bool {
        std::lock_guard lock(profile.mutex);
        for (auto mode : {Mode::physical, Mode::layered, Mode::fast_open})
            for (auto const& worker : slots(profile, mode))
                if (worker && &worker->environment().context == &context && !worker->drained()) return false;
        return true;
    }

    template<class Profile>
    auto finish(Profile& profile, corosio::io_context& context) noexcept -> void {
        std::lock_guard lock(profile.mutex);
        for (auto mode : {Mode::physical, Mode::layered, Mode::fast_open})
            for (auto& worker : slots(profile, mode))
                if (worker && &worker->environment().context == &context) {
                    if (!worker->drained()) std::terminate();
                    worker.reset();
                    break;
                }
    }
}
