// Borrowed-lease HTTP/2 gRPC multiplexed connection pool for proxy outbounds.
#pragma once

namespace proxy::grpc_pool {
    namespace g = grpc;
    using Connected = tls::detail::ConnectResult;

    template<class Profile>
    struct Resolver {
        Session& session;
        nex::corosio::io_context& context;
        Profile const& profile;
        DnsSlot slot;
        auto operator()(Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
            if (profile.bootstrap)
                return resolve_bootstrap_owned(session, context, slot, *profile.bootstrap, profile.host, profile.port, deadline);
            return resolve_local_owned(session, context, slot, profile.host, profile.port, deadline);
        }
        auto connected(nex::corosio::endpoint const& endpoint) noexcept -> void { session.record_physical_peer(endpoint); }
        auto cancel() noexcept -> void { slot.cancel(); }
    };

    template<class Profile>
    struct Lower {
        using Candidates = LowerConnector::Candidates;
        Session& session;
        LowerConnector connector;
        Lower(Session& state, OutboundContext const& environment, TunnelFactory const& detour, Profile const& profile)
            : session(state), connector{{}, &environment.context, &detour, profile.host, profile.port, profile.bootstrap} {}
        auto connect(Clock::time_point deadline, Candidates& candidates) -> nex::capy::task<Connected> {
            switch (co_await connector.connect(session, deadline, candidates)) {
            case TunnelConnectResult::connected: co_return Connected::connected;
            case TunnelConnectResult::retryable: co_return Connected::retryable;
            case TunnelConnectResult::timeout: co_return Connected::timeout;
            default: co_return Connected::failed;
            }
        }
        auto retry() noexcept -> bool { return connector.retry(); }
        auto read(std::span<std::uint8_t> bytes) { return connector.tunnel->read(bytes); }
        auto send(std::span<std::uint8_t const> bytes) { return connector.tunnel->send(bytes); }
        auto close_output() { return connector.tunnel->close_output(); }
        auto cancel() noexcept -> void { connector.cancel(); }
    };

    template<class Profile, int Mode>
    class Node {
        using Connector = std::conditional_t<Mode == 1,
            tls::detail::LayerConnector<Lower<Profile>, tls::ShapedClientProfile>,
            std::conditional_t<Mode == 2,
                tls::detail::FastOpenPhysicalConnector<Resolver<Profile>, tls::ShapedClientProfile>,
                tls::detail::PhysicalConnector<Resolver<Profile>, tls::ShapedClientProfile>>>;
        Session state_;
        std::optional<Connector> connector_;
    public:
        using Socket = typename Connector::Socket;
        Node(OutboundContext const& environment, Profile const& profile, TunnelFactory const* detour, TcpSocketOptions const& options)
            : state_(environment.context) {
            state_.dns = environment.dns;
            state_.local_dns = environment.local_dns;
            state_.tunnel_factories = environment.factories;
            state_.direct_tcp_options = environment.direct_options;
            if constexpr (Mode == 1) connector_.emplace(profile.tls, state_, environment, *detour, profile);
            else connector_.emplace(environment.context, Resolver<Profile>{state_, environment.context, profile}, profile.tls, options);
        }
        ~Node() { state_.close(); }
        auto start(Clock::time_point deadline) { return connector_->start(deadline); }
        auto application() noexcept { return connector_->application(); }
        auto accepts_alpn() const noexcept -> bool {
            auto* selected = connector_->negotiated();
            return selected && selected->alpn && std::ranges::equal(*selected->alpn, std::string_view("h2"));
        }
        auto cancel() noexcept -> void { connector_->cancel(); state_.close(); }
    };

    template<class Profile, int Mode>
    using Connection = g::OwnedConnection<Node<Profile, Mode>, g::detail::ByteStreamReadPolicy, 16>;

    template<class Profile, int Mode>
    struct PoolWorker {
        using Conn = Connection<Profile, Mode>;
        using Pool = net::ConnectionPool<Conn, true>;
        OutboundContext environment;
        Profile const& profile;
        TunnelFactory const* detour;
        TcpSocketOptions options;
        Pool pool;
        nex::capy::async_mutex starting;
        Conn* starting_connection = nullptr;
        bool stopped = false;

        PoolWorker(OutboundContext const& env, Profile const& value, TunnelFactory const* lower, TcpSocketOptions selected)
            : environment(env), profile(value), detour(lower), options(selected),
              pool(net::PoolOptions{.max_sessions = value.max_sessions}) {}

        auto stop() noexcept -> void {
            stopped = true;
            if (auto* active = starting_connection) active->stop();
            pool.stop();
        }
        auto drained() const noexcept -> bool { return !starting_connection && pool.drained(); }
        ~PoolWorker() { stop(); if (!drained()) std::terminate(); }

        auto acquire(std::stop_source& caller_stop, Clock::time_point deadline)
            -> nex::capy::task<std::expected<typename Pool::Lease, TunnelConnectResult>> {
            if (stopped || caller_stop.stop_requested()) co_return std::unexpected(TunnelConnectResult::failed);
            if (Clock::now() >= deadline) co_return std::unexpected(TunnelConnectResult::timeout);
            pool.reap(Clock::now());
            if (auto reused = pool.acquire()) co_return std::move(*reused);
            auto wait = nex::corosio::timeout(starting.scoped_lock(), deadline);
            auto [lock_error, lock] = co_await net::OperationToken(std::move(wait), caller_stop);
            if (lock_error || caller_stop.stop_requested() || stopped || Clock::now() >= deadline)
                co_return std::unexpected(Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
            if (auto reused = pool.acquire()) co_return std::move(*reused);
            auto creation = pool.reserve();
            if (!creation) co_return std::unexpected(TunnelConnectResult::failed);
            auto connection = std::make_unique<Conn>(environment, profile, detour, options);
            struct Starting {
                PoolWorker& worker;
                Starting(PoolWorker& owner, Conn* c) noexcept : worker(owner) { worker.starting_connection = c; }
                ~Starting() { worker.starting_connection = nullptr; }
            } registration(*this, connection.get());
            Connected connected;
            {
                std::stop_callback starting_cb(caller_stop.get_token(), [p = connection.get()]() noexcept { p->stop(); });
                connected = co_await connection->start(profile.request, profile.limits, profile.response, deadline);
            }
            if (connected != Connected::connected || caller_stop.stop_requested() || stopped)
                co_return std::unexpected(connected == Connected::timeout || Clock::now() >= deadline
                    ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
            auto accepted = creation->commit(std::move(connection));
            if (!accepted) co_return std::unexpected(TunnelConnectResult::failed);
            accepted->connection().run(environment.context);
            co_return std::move(*accepted);
        }
    };

    template<int Mode, class Profile>
    auto slots(Profile& profile) noexcept -> auto& {
        if constexpr (Mode == 1) return profile.layered;
        else if constexpr (Mode == 2) return profile.fast;
        else return profile.physical;
    }

    template<int Mode, class Profile>
    auto find(Profile& profile, nex::corosio::io_context& context) noexcept {
        for (auto const& slot : slots<Mode>(profile))
            if (slot && &slot->environment().context == &context) return slot.get();
        return static_cast<typename std::remove_reference_t<decltype(slots<Mode>(profile))>::value_type::element_type*>(nullptr);
    }

    template<int Mode, class Profile>
    auto stop(Profile& profile, nex::corosio::io_context& context) noexcept -> void {
        typename std::remove_reference_t<decltype(slots<Mode>(profile))>::value_type::element_type* worker = nullptr;
        { std::lock_guard lock(profile.mutex); worker = find<Mode>(profile, context); }
        if (worker) worker->stop();
    }

    template<int Mode, class Profile>
    auto finish(Profile& profile, nex::corosio::io_context& context) noexcept -> void {
        std::lock_guard lock(profile.mutex);
        for (auto& worker : slots<Mode>(profile))
            if (worker && &worker->environment().context == &context) {
                if (!worker->drained()) std::terminate();
                worker.reset();
                return;
            }
    }
}
