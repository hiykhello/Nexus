// Session state, tunnel chaining, and ingress endpoint helper declarations.
export module relay:session_interface;
import std;
import containers.inplace_vector;
import capy;
import corosio;
import proxy.v4;
import relay.request_backend;
import relay.session_quota;
import relay.principal_limits;
import relay.dns_state;
import net.principal_bytes;
import net.stream_relay;
import net.udp_route;
import net.datagram_frame;
import net.udp_socket;
import dns.corosio_query;
import dns.policy;
import dns.reverse;
import dns.tls_query;
import rules;
import platform.network_state;
import :types;
import :tunnel_facade;
import :route_interface;
import :traffic_interface;
import :relay_pool;
import :shadowsocks_users;

namespace relay {
    export struct DirectWireShaping {
        bool tls_record_fragment = false;
        std::uint16_t tls_fragment_min = 0, tls_fragment_max = 0;
        std::uint32_t tls_fragment_fallback_delay_ms = 0;
        std::array<std::uint8_t, 64> tcp_prefix{};
        std::uint8_t tcp_prefix_len = 0;
        bool applied = false;
        [[nodiscard]] auto pending() const noexcept -> bool {
            return !applied && (tls_record_fragment || tcp_prefix_len > 0);
        }
        [[nodiscard]] auto configured() const noexcept -> bool {
            return applied || tls_record_fragment || tcp_prefix_len > 0;
        }
    };

    export struct NetworkMetadataSnapshot {
        std::optional<rules::NetworkType> network_type;
        std::optional<bool> network_is_expensive;
        std::optional<bool> network_is_constrained;
        std::string wifi_ssid;
        std::optional<rules::MacAddress> wifi_bssid;
        std::vector<rules::ProgramAddress> default_interface_addresses;
    };

    // Cold per-session metadata allocated on demand and copy-on-write shared
    // across multiplexed child streams.
    export struct SessionExtras {
        std::string process_path;
        std::string source_user;
        std::string package_name;
        containers::inplace_vector<std::string, 8> process_paths;
        DirectWireShaping direct_shaping;
        std::optional<std::string> route_override_address;
        std::uint16_t route_override_port = 0;
    };

    export struct Session {
        using DirectWireShaping = relay::DirectWireShaping;
        // Destroyed last, after sockets and all owners of this session.
        std::optional<SessionQuota::Lease> quota;
        std::optional<SessionQuota::Lease> principal_lease;
        PrincipalPolicy const* principal_policy = nullptr;
        PrincipalBudget const* principal = nullptr;
        [[nodiscard]] auto admit_principal(std::string_view user, PrincipalResource resource = PrincipalResource::connection) noexcept -> bool;
        [[nodiscard]] auto admit_principal_child(Session const& parent) noexcept -> bool;
        [[nodiscard]] auto meters_principal_bytes() const noexcept -> bool {
            return principal && principal->bytes().metered();
        }
        auto reserve_principal_stream(bool upstream, std::size_t size) -> capy::task<std::optional<PrincipalBytes::Reservation>>;
        [[nodiscard]] auto reserve_principal_datagram(bool upstream, std::size_t size) -> std::optional<PrincipalBytes::Reservation>;
        std::optional<std::uint32_t> source_uid;
        std::optional<std::uint32_t> source_gid;
        std::optional<std::string_view> source_interface;
        platform::network::Monitor const* network_monitor = nullptr;
        std::shared_ptr<SessionExtras> extras;
        std::shared_ptr<NetworkMetadataSnapshot const> network_metadata;
        rules::IngressMetadata ingress;
        [[nodiscard]] auto ensure_mutable_extras() -> SessionExtras& {
            if (!extras) extras = std::make_shared<SessionExtras>();
            else if (extras.use_count() > 1) extras = std::make_shared<SessionExtras>(*extras);
            return *extras;
        }
        [[nodiscard]] auto process_path_view() const noexcept -> std::string_view {
            return extras ? std::string_view(extras->process_path) : std::string_view{};
        }
        [[nodiscard]] auto source_user_view() const noexcept -> std::string_view {
            return extras ? std::string_view(extras->source_user) : std::string_view{};
        }
        [[nodiscard]] auto package_name_view() const noexcept -> std::string_view {
            return extras ? std::string_view(extras->package_name) : std::string_view{};
        }
        [[nodiscard]] auto process_paths_span() const noexcept -> std::span<std::string const> {
            return extras ? std::span<std::string const>(extras->process_paths) : std::span<std::string const>{};
        }
        [[nodiscard]] auto direct_shaping_pending() const noexcept -> bool {
            return extras && extras->direct_shaping.pending();
        }
        [[nodiscard]] auto direct_shaping_ptr() const noexcept -> DirectWireShaping const* {
            return extras ? &extras->direct_shaping : nullptr;
        }
        [[nodiscard]] auto route_override_addr() const noexcept -> std::optional<std::string_view> {
            if (extras && extras->route_override_address) return *extras->route_override_address;
            return {};
        }
        [[nodiscard]] auto route_override_port_val() const noexcept -> std::uint16_t {
            return extras ? extras->route_override_port : std::uint16_t{0};
        }
        auto populate_network_metadata() noexcept -> void;
        auto fill_match_input(rules::MatchInput& m) const noexcept -> rules::MatchInput& {
            if (!m.inbound) m.inbound = inbound;
            if (!m.auth_user) m.auth_user = auth_user;
            if (!m.source_uid) m.source_uid = source_uid;
            if (!m.source_gid) m.source_gid = source_gid;
            if (!m.source_interface) m.source_interface = source_interface;
            if (!m.route_mode) m.route_mode = active_route_mode();
            if (auto const* ex = extras.get()) {
                if (!m.process_path && !ex->process_path.empty()) m.process_path = ex->process_path;
                if (!m.process_paths && !ex->process_paths.empty())
                    m.process_paths = std::span<std::string const>(ex->process_paths);
                if (!m.source_user && !ex->source_user.empty()) m.source_user = ex->source_user;
                if (!m.package_name && !ex->package_name.empty()) m.package_name = ex->package_name;
            }
            if (auto const* net = network_metadata.get()) {
                if (!m.network_type) m.network_type = net->network_type;
                if (!m.network_is_expensive) m.network_is_expensive = net->network_is_expensive;
                if (!m.network_is_constrained) m.network_is_constrained = net->network_is_constrained;
                if (!m.wifi_ssid && !net->wifi_ssid.empty()) m.wifi_ssid = net->wifi_ssid;
                if (!m.wifi_bssid) m.wifi_bssid = net->wifi_bssid;
                if (!m.default_interface_addresses && !net->default_interface_addresses.empty())
                    m.default_interface_addresses = std::span<rules::ProgramAddress const>(net->default_interface_addresses);
            }
            return m;
        }
        auto fill_program_input(rules::ProgramInput& p) const noexcept -> rules::ProgramInput& {
            if (!p.inbound) p.inbound = inbound;
            if (!p.auth_user) p.auth_user = auth_user;
            if (!p.source_uid) p.source_uid = source_uid;
            if (!p.source_gid) p.source_gid = source_gid;
            if (!p.source_interface) p.source_interface = source_interface;
            if (!p.route_mode) p.route_mode = active_route_mode();
            if (auto const* ex = extras.get()) {
                if (!p.process_path && !ex->process_path.empty()) p.process_path = ex->process_path;
                if (!p.process_paths && !ex->process_paths.empty())
                    p.process_paths = std::span<std::string const>(ex->process_paths);
                if (!p.source_user && !ex->source_user.empty()) p.source_user = ex->source_user;
                if (!p.package_name && !ex->package_name.empty()) p.package_name = ex->package_name;
            }
            if (auto const* net = network_metadata.get()) {
                if (!p.network_type) p.network_type = net->network_type;
                if (!p.network_is_expensive) p.network_is_expensive = net->network_is_expensive;
                if (!p.network_is_constrained) p.network_is_constrained = net->network_is_constrained;
                if (!p.wifi_ssid && !net->wifi_ssid.empty()) p.wifi_ssid = net->wifi_ssid;
                if (!p.wifi_bssid) p.wifi_bssid = net->wifi_bssid;
                if (!p.default_interface_addresses && !net->default_interface_addresses.empty())
                    p.default_interface_addresses = std::span<rules::ProgramAddress const>(net->default_interface_addresses);
            }
            return p;
        }
        auto fill_dns_context(policy::DnsContext& d) const noexcept -> policy::DnsContext& {
            if (!d.inbound) d.inbound = inbound;
            if (!d.auth_user) d.auth_user = auth_user;
            if (!d.source_interface) d.source_interface = source_interface;
            if (!d.source_uid) d.source_uid = source_uid;
            if (!d.source_gid) d.source_gid = source_gid;
            if (auto const* ex = extras.get()) {
                if (!d.source_user && !ex->source_user.empty()) d.source_user = ex->source_user;
                if (!d.process_path && !ex->process_path.empty()) d.process_path = ex->process_path;
                if (!d.process_paths && !ex->process_paths.empty())
                    d.process_paths = std::span<std::string const>(ex->process_paths);
                if (!d.package_name && !ex->package_name.empty()) d.package_name = ex->package_name;
            }
            if (auto const* net = network_metadata.get()) {
                if (!d.network_type) d.network_type = net->network_type;
                if (!d.network_is_expensive) d.network_is_expensive = net->network_is_expensive;
                if (!d.network_is_constrained) d.network_is_constrained = net->network_is_constrained;
                if (!d.wifi_ssid && !net->wifi_ssid.empty()) d.wifi_ssid = net->wifi_ssid;
                if (!d.wifi_bssid) d.wifi_bssid = net->wifi_bssid;
                if (d.default_interface_addresses.empty() && !net->default_interface_addresses.empty())
                    d.default_interface_addresses = std::span<rules::ProgramAddress const>(net->default_interface_addresses);
            }
            if (!d.route_mode) d.route_mode = active_route_mode();
            return d;
        }
        // Set by packet hosts that must protect the physical endpoint from
        // their own routes. The caller owns this slot until the session ends.
        net::UdpEndpoint* physical_peer = nullptr;
        auto record_physical_peer(io::endpoint const& endpoint) noexcept -> void;
        auto process_metadata() const noexcept -> std::optional<std::string_view> {
            auto path = process_path_view();
            if (path.empty()) return {};
            return path;
        }
        SessionQuota* splice_pipes = nullptr;
        DirectBufferPool* direct_buffers = nullptr;
        SplicePipePool* splice_pipe_pool = nullptr;
        std::size_t splice_max_idle_pipes = SplicePipePool::kMaxIdlePipes;
        std::array<bool, 2> splice_wait_busy{};
        auto inspect_source_owner(rules::RouteProgram const&, std::optional<io::endpoint> original = {}) -> void;
        io::tcp_socket client;
        io::tcp_socket target;
        // The parent server holds the registry until all workers drain.
        TrafficRegistration traffic;
        std::shared_ptr<ShadowsocksUserDirectory> ss_dynamic_users;
        std::shared_ptr<ShadowsocksDynamicUser> user_accounting;
        auto begin_traffic(TrafficProtocol, std::uint16_t destination_port, std::optional<TransparentDatagram> = {}) -> void;
        auto end_traffic() noexcept -> void;
        auto register_child_traffic() -> void;
        [[nodiscard]] auto track_child_traffic(TrafficProtocol, ConnectPath, std::uint16_t destination_port, bool can_close = false) -> TrafficRegistration;
        auto traffic_delivery() noexcept -> net::stream_relay::Delivery {
            if (!traffic.slot_ && !user_accounting) return {};
            return {this, [](void* owner, bool upstream, std::size_t size) noexcept {
                static_cast<Session*>(owner)->count_traffic(upstream, size);
            }};
        }
        auto select_traffic_path(ConnectPath path) noexcept -> void {
            traffic.select_path(path);
        }
        auto set_traffic_group(std::string_view tag) noexcept -> void;
        auto record_traffic_route(TrafficRoute, ConnectPath) noexcept -> void;
        auto record_datagram_route(bool ordered, net::UdpSelection const&) noexcept -> void;
        auto record_dial_failure(TrafficRoute const&) noexcept -> void;
        auto record_dial_failure(std::size_t outbound) noexcept -> void;
        std::string_view group_tag;
        GroupRuntimeHooks* group_hooks = nullptr;
        bool find_process = false;
        auto count_traffic(bool upstream, std::size_t bytes) noexcept -> void {
            traffic.count(upstream, bytes);
            if (user_accounting) {
                user_accounting->record_bytes(upstream, bytes);
                if (!user_accounting->admits()) close();
            }
        }
        // Multiplexed children borrow the physical owner through their join.
        Session* transport_owner = nullptr;
        // Borrowed from immutable credentials or the VLESS inbound profile.
        std::optional<std::string_view> auth_user;
        io::endpoint udp_advertise;
        // The policy referenced by inbound and ordered_tcp stays alive through the session.
        std::shared_ptr<RouteSnapshot const> route_snapshot;
        rules::RuntimeRouteMode const* runtime_mode = nullptr;
        [[nodiscard]] auto active_route_mode() const noexcept -> rules::RouteMode {
            return runtime_mode ? runtime_mode->mode.load(std::memory_order_acquire) : rules::RouteMode::rule;
        }
        [[nodiscard]] auto mode_override_outbound(std::string_view host) const noexcept -> std::optional<std::size_t> {
            if (!runtime_mode) return {};
            auto mode = runtime_mode->mode.load(std::memory_order_acquire);
            if (mode == rules::RouteMode::direct) return std::size_t{0};
            if (mode == rules::RouteMode::global) {
                auto target = runtime_mode->global_outbound.load(std::memory_order_acquire);
                return route_snapshot ? route_snapshot->matcher.choose_outbound(target, host) : target;
            }
            return {};
        }
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
        OrderedTcpPolicy const* ordered_tcp = nullptr;
        DnsState* dns = nullptr;
        LocalDnsState* local_dns = nullptr;
        dns::ReverseCache* reverse_cache = nullptr;
        std::uint64_t reverse_view = 0;
#ifdef NEXUS_ENABLE_FAKEIP
        // Borrowed from the server, which outlives its suspended sessions.
        dns::FakeIpShared* fakeip = nullptr;
        std::unique_ptr<dns::FakeIpShared::Target> fakeip_target;
        std::uint64_t fakeip_view = 0;
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
        TcpSocketOptions const* direct_tcp_options = nullptr;
        std::stop_source stop;
        // The server registry only borrows this session and outlives its task.
        std::vector<Session*>* registry = nullptr;
        std::size_t registry_index = 0;
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
        Session(Session const&) = delete;
        auto operator=(Session const&) -> Session& = delete;
        Session(Session&&) = delete;
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
        Server const* owner = nullptr;
        std::size_t factory_index = 0;
        [[nodiscard]] auto prewarm_allowed() const noexcept -> bool;
    };
    struct TunnelChainStep { TunnelLayerFactory const* factory; io::endpoint endpoint; };
    enum class TunnelChainMode { tcp, uot, xudp, packets };
    // Endpoints are resolved before entry. Factories and steps outlive this
    // operation and every resulting layer; the session owns the active chain.
    auto connect_tunnel_chain(Session& session, io::io_context& context, TunnelFactory const& first,
        std::span<TunnelChainStep const> steps, io::endpoint destination, TunnelChainMode mode, Clock::time_point deadline)
        -> capy::task<TunnelConnectResult>;

    [[nodiscard]] auto accepted_local(io::tcp_socket const&) noexcept -> io::endpoint;
    [[nodiscard]] auto accepted_peer(io::tcp_socket const&) noexcept -> io::endpoint;
    inline auto traffic_endpoint(io::endpoint const& endpoint) noexcept -> net::UdpEndpoint {
        auto address = endpoint.address();
        net::UdpEndpoint result{address.is_v4() ? std::uint8_t{4} : std::uint8_t{6}, {}, endpoint.port()};
        if (address.is_v4()) std::ranges::copy(address.to_v4().to_bytes(), result.address.begin());
        else std::ranges::copy(address.to_v6().to_bytes(), result.address.begin());
        return result;
    }
    inline auto Session::record_physical_peer(io::endpoint const& endpoint) noexcept -> void {
        if (physical_peer && endpoint.port() && !endpoint.address().is_unspecified())
            *physical_peer = traffic_endpoint(endpoint);
    }
    // The immediate stream peer is the source for TCP and stream-carried UDP.
    inline auto source_endpoint(Session& session, bool required) -> std::optional<net::UdpEndpoint> {
        if (!required) return {};
        if (session.datagram_source) return session.datagram_source;
        auto& owner = session.transport_owner ? *session.transport_owner : session;
        auto remote = accepted_peer(owner.client);
        auto address = remote.address();
        if (!remote.port() || address.is_unspecified()) return {};
        return traffic_endpoint(remote);
    }
    auto ingress_metadata(platform::network::Monitor const*, net::UdpEndpoint const&,
        std::optional<std::uint8_t> dscp = {}, std::uint32_t index = 0) noexcept -> rules::IngressMetadata;

    inline auto source_endpoint(Session& session, rules::RouteProgram const& policy) -> std::optional<net::UdpEndpoint> {
        return source_endpoint(session, policy.needs_source() || session.dns_requirements().source);
    }

    // The root task owns the session. Capy's trampoline invokes this handler
    // before destroying that task's frame; abandonment invokes no handler.
    inline auto session_error(Session& session) {
        return [&session](std::exception_ptr) noexcept {
            session.close(); session.done = true;
        };
    }

    export inline auto init_multiplexed_child(Session& child, Session& parent, Clock::time_point deadline) -> void {
        child.transport_owner = &parent;
        child.user_accounting = parent.user_accounting;
        child.register_child_traffic();
        if (!child.auth_user) child.auth_user = parent.auth_user;
        child.datagram_source = parent.datagram_source;
        child.ingress = parent.ingress;
        child.route_snapshot = parent.route_snapshot;
        child.runtime_mode = parent.runtime_mode;
        child.dns_transport_override = parent.dns_transport_override;
        child.ordered_tcp = parent.ordered_tcp;
        child.principal_policy = parent.principal_policy;
        child.inbound = parent.inbound;
        child.dns = parent.dns;
        child.local_dns = parent.local_dns;
        child.reverse_cache = parent.reverse_cache;
        child.reverse_view = parent.reverse_view;
        child.direct_buffers = parent.direct_buffers;
        child.splice_pipes = parent.splice_pipes;
        child.splice_pipe_pool = parent.splice_pipe_pool;
        child.network_monitor = parent.network_monitor;
        child.group_hooks = parent.group_hooks;
        child.group_tag = parent.group_tag;
        child.find_process = parent.find_process;
        child.source_uid = parent.source_uid;
        child.source_gid = parent.source_gid;
        child.source_interface = parent.source_interface;
        child.network_metadata = parent.network_metadata;
        if (parent.extras) {
            if (!parent.extras->direct_shaping.configured() &&
                !parent.extras->route_override_address &&
                parent.extras->route_override_port == 0) {
                child.extras = parent.extras;
            } else if (!parent.extras->process_path.empty() || !parent.extras->process_paths.empty() ||
                       !parent.extras->source_user.empty() || !parent.extras->package_name.empty()) {
                auto& ce = child.ensure_mutable_extras();
                ce.process_path = parent.extras->process_path;
                ce.process_paths = parent.extras->process_paths;
                ce.source_user = parent.extras->source_user;
                ce.package_name = parent.extras->package_name;
            }
        }
#ifdef NEXUS_ENABLE_FAKEIP
        child.fakeip = parent.fakeip;
        child.fakeip_view = parent.fakeip_view;
#endif
        child.tunnel_factories = parent.tunnel_factories;
        child.direct_connect_timeout_ms = parent.direct_connect_timeout_ms;
        child.direct_tcp_options = parent.direct_tcp_options;
        child.started = child.touched = Clock::now();
        child.handshake_deadline = deadline;
    }
}
