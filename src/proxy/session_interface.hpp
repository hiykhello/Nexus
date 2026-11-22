// Declarations included inside the proxy module.
#pragma once

    export struct Session {
        // Destroyed last, after sockets and all owners of this session.
        std::optional<SessionQuota::Lease> quota;
        std::optional<SessionQuota::Lease> principal_lease;
        PrincipalPolicy const* principal_policy=nullptr;
        PrincipalBudget const* principal=nullptr;
        [[nodiscard]] auto admit_principal(std::string_view user,PrincipalResource resource=PrincipalResource::connection) noexcept -> bool;
        [[nodiscard]] auto admit_principal_child(Session const& parent) noexcept -> bool;
        [[nodiscard]] auto meters_principal_bytes() const noexcept -> bool {
            return principal && principal->bytes().metered();
        }
        auto reserve_principal_stream(bool upstream,std::size_t size) -> capy::task<std::optional<PrincipalBytes::Reservation>>;
        [[nodiscard]] auto reserve_principal_datagram(bool upstream,std::size_t size) -> std::optional<PrincipalBytes::Reservation>;
        std::optional<std::uint32_t> source_uid;
        std::string process_path;
        std::optional<std::string_view> source_interface;
        platform::network::Monitor const* network_monitor=nullptr;
        rules::IngressMetadata ingress;
        // Set by packet hosts that must protect the physical endpoint from
        // their own routes. The caller owns this slot until the session ends.
        net::UdpEndpoint* physical_peer=nullptr;
        auto record_physical_peer(io::endpoint const& endpoint) noexcept -> void;
        auto process_metadata() const noexcept -> std::optional<std::string_view> {
            if (process_path.empty()) return {};
            return process_path;
        }
        SessionQuota* splice_pipes=nullptr;
        DirectBufferPool* direct_buffers=nullptr;
        SplicePipePool* splice_pipe_pool=nullptr;
        auto inspect_source_owner(rules::RouteMatcher const&,std::optional<io::endpoint> original={}) -> void;
        io::tcp_socket client;
        io::tcp_socket target;
        // The parent server holds the registry until all workers drain.
        TrafficRegistration traffic;
        auto begin_traffic(TrafficProtocol,std::uint16_t destination_port,std::optional<TransparentDatagram> = {}) -> void;
        auto end_traffic() noexcept -> void;
        auto register_child_traffic() -> void;
        [[nodiscard]] auto track_child_traffic(TrafficProtocol,ConnectPath,std::uint16_t destination_port,bool can_close=false) -> TrafficRegistration;
        auto traffic_delivery() noexcept -> net::stream_relay::Delivery {
            if (!traffic.slot_) return {};
            return {this,[](void* owner,bool upstream,std::size_t size) noexcept {
                static_cast<Session*>(owner)->count_traffic(upstream,size);
            }};
        }
        auto select_traffic_path(ConnectPath path) noexcept -> void {
            traffic.select_path(path);
        }
        auto record_traffic_route(TrafficRoute,ConnectPath) noexcept -> void;
        auto record_datagram_route(bool ordered,net::UdpSelection const&) noexcept -> void;
        auto count_traffic(bool upstream,std::size_t bytes) noexcept -> void {
            traffic.count(upstream,bytes);
        }
        // Multiplexed children borrow the physical owner through their join.
        Session* transport_owner=nullptr;
        // Borrowed from immutable credentials or the VLESS inbound profile.
        std::optional<std::string_view> auth_user;
        io::endpoint udp_advertise;
        // The policy referenced by inbound and ordered_tcp stays alive through the session.
        std::shared_ptr<RouteSnapshot const> route_snapshot;
        std::shared_ptr<dns::detail::TransportSnapshot const> dns_transport_override;
        [[nodiscard]] auto dns_transports() const noexcept -> dns::detail::TransportSnapshot const* {
            if (dns_transport_override) return dns_transport_override.get();
            return route_snapshot ? route_snapshot->dns_transports.get() : nullptr;
        }
        [[nodiscard]] auto dns_rules() const noexcept -> std::span<policy::DnsRule const>;
        [[nodiscard]] auto dns_requirements() const noexcept -> policy::DnsContextRequirements;
        std::optional<std::string_view> inbound;
        // Transport peer when there is no client stream.
        std::optional<net::UdpEndpoint> datagram_source;
        OrderedTcpPolicy const* ordered_tcp=nullptr;
        DnsState* dns = nullptr;
        LocalDnsState* local_dns = nullptr;
        dns::ReverseCache* reverse_cache = nullptr;
        std::uint64_t reverse_view = 0;
#ifdef NEXUS_ENABLE_FAKEIP
        // Borrowed from the server, which outlives its suspended sessions.
        dns::FakeIpShared* fakeip = nullptr;
        std::unique_ptr<dns::FakeIpShared::Target> fakeip_target;
        std::uint64_t fakeip_view=0;
#endif
        // Borrowed from the active DNS query on this session's executor.
        void* dns_operation = nullptr;
        void (*cancel_dns)(void*) noexcept = nullptr;
        // The server retains this snapshot until the context destroys its tasks.
        std::vector<TunnelFactory> const* tunnel_factories = nullptr;
        pro::proxy<TunnelFacade> tunnel;
        Clock::time_point started = Clock::now();
        Clock::time_point touched = started;
        Clock::time_point handshake_deadline = started + std::chrono::seconds(10);
        Clock::time_point lifetime_deadline = Clock::time_point::max();
        std::uint32_t direct_connect_timeout_ms = 10000;
        TcpSocketOptions const* direct_tcp_options=nullptr;
        struct DirectWireShaping {
            bool tls_record_fragment=false;
            std::uint16_t tls_fragment_min=0, tls_fragment_max=0;
            std::array<std::uint8_t,64> tcp_prefix{};
            std::uint8_t tcp_prefix_len=0;
            bool applied=false;
            [[nodiscard]] auto pending() const noexcept -> bool {
                return !applied && (tls_record_fragment || tcp_prefix_len>0);
            }
        } direct_shaping;
        std::stop_source stop;
        // The server registry only borrows this session and outlives its task.
        std::vector<Session*>* registry = nullptr;
        std::size_t registry_index=0;
        bool relaying = false;
        bool half_closed = false;
        bool closed = false;
        bool done = false;
        bool http_draining = false;
        Clock::time_point half_close_started{};
        std::chrono::milliseconds half_close_timeout{15000};
        Clock::time_point http_drain_started{};
        auto mark_half_closed() noexcept -> void {
            if (!half_closed) {
                half_closed = true;
                half_close_started = Clock::now();
            }
        }
        explicit Session(io::io_context& ctx);
        Session(Session const&)=delete;
        auto operator=(Session const&) -> Session& = delete;
        Session(Session&&)=delete;
        auto operator=(Session&&) -> Session& = delete;
        ~Session();
        auto close() noexcept -> void;
    };
    struct OutboundContext {
        io::io_context& context;
        DnsState* dns;
        LocalDnsState* local_dns;
        std::vector<TunnelFactory> const* factories;
        TcpSocketOptions const* direct_options;
        Server const* owner=nullptr;
        std::size_t factory_index=0;
        [[nodiscard]] auto prewarm_allowed() const noexcept -> bool;
    };
    struct TunnelChainStep { TunnelLayerFactory const* factory; io::endpoint endpoint; };
    enum class TunnelChainMode { tcp, uot, xudp, packets };
    // Endpoints are resolved before entry. Factories and steps outlive this
    // operation and every resulting layer; the session owns the active chain.
    auto connect_tunnel_chain(Session& session,io::io_context& context,TunnelFactory const& first,
        std::span<TunnelChainStep const> steps,io::endpoint destination,TunnelChainMode mode,Clock::time_point deadline)
        -> capy::task<TunnelConnectResult>;

    [[nodiscard]] auto accepted_local(io::tcp_socket const&) noexcept -> io::endpoint;
    [[nodiscard]] auto accepted_peer(io::tcp_socket const&) noexcept -> io::endpoint;
    inline auto traffic_endpoint(io::endpoint const& endpoint) noexcept -> net::UdpEndpoint {
        auto address=endpoint.address();
        net::UdpEndpoint result{address.is_v4() ? std::uint8_t{4} : std::uint8_t{6},{},endpoint.port()};
        if (address.is_v4()) std::ranges::copy(address.to_v4().to_bytes(),result.address.begin());
        else std::ranges::copy(address.to_v6().to_bytes(),result.address.begin());
        return result;
    }
    inline auto Session::record_physical_peer(io::endpoint const& endpoint) noexcept -> void {
        if (physical_peer && endpoint.port() && !endpoint.address().is_unspecified())
            *physical_peer=traffic_endpoint(endpoint);
    }
    // The immediate stream peer is the source for TCP and stream-carried UDP.
    inline auto source_endpoint(Session& session,bool required) -> std::optional<net::UdpEndpoint> {
        if (!required) return {};
        if (session.datagram_source) return session.datagram_source;
        auto& owner=session.transport_owner ? *session.transport_owner : session;
        auto remote=accepted_peer(owner.client);
        auto address=remote.address();
        if (!remote.port() || address.is_unspecified()) return {};
        return traffic_endpoint(remote);
    }
    auto ingress_metadata(platform::network::Monitor const*,net::UdpEndpoint const&,
        std::optional<std::uint8_t> dscp={},std::uint32_t index=0) noexcept -> rules::IngressMetadata;

    inline auto source_endpoint(Session& session,rules::RouteMatcher const& policy) -> std::optional<net::UdpEndpoint> {
        return source_endpoint(session,policy.needs_source() || (session.dns && session.dns->context.source));
    }

    // The root task owns the session. Capy's trampoline invokes this handler
    // before destroying that task's frame; abandonment invokes no handler.
    inline auto session_error(Session& session) {
        return [&session](std::exception_ptr) noexcept {
            session.close(); session.done=true;
        };
    }
