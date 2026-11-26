// Exported Server class and TcpAdmission declarations for proxy runtime.
module;
#include <boost/corosio/backend.hpp>

export module relay:server_interface;
import std;
import capy;
import corosio;
import functional;
import utility;
import config;
import xhttp.config;
import rules;
import socks5;
import relay.dns_routing;
import relay.dns_state;
import relay.dns_backend;
import relay.request_backend;
import relay.session_quota;
import relay.principal_limits;
import dns.corosio_query;
import dns.address_sequence;
import dns.response_cache;
import dns.local_config;
import dns.reverse;
import dns.tls_query;
import net.datagram_frame;
import net.udp_socket;
import platform.network_state;
import :types;
import :tunnel_facade;
import :route_interface;
import :traffic_interface;
import :relay_pool;
import :session_interface;

export namespace relay {
    // One publication point for every ordinary TCP listener in a host.
    // Publication quiesces previous-generation acceptors before advancing generation.
    class TcpAdmission {
        friend class Server;
        struct Entry { std::uint64_t generation = 0; Server* server = nullptr; bool threaded = false; };
        std::mutex mutex;
        std::atomic<std::uint64_t> generation{0};
        std::vector<Entry> entries;
        auto attach(std::uint64_t gen, Server* srv, bool threaded) -> void;
        auto detach(Server* srv) noexcept -> void;
    public:
        [[nodiscard]] auto publish(std::uint64_t next, functional::function_ref<void() noexcept> prepare) -> bool;
        [[nodiscard]] auto publish(std::uint64_t next) -> bool { return publish(next, []() noexcept {}); }
    };

    // TCP proxy server; one worker runs in the caller, multiple workers use threads.
    // Public methods must be called from one controlling thread.
    class Server {
        friend class TcpAdmission;
        // The registry outlives context shutdown, which can destroy task frames.
        std::vector<Session*> sessions;
        std::shared_ptr<platform::network::Monitor const> network_monitor;
        std::shared_ptr<TrafficRegistry> traffic;
        std::size_t traffic_slot_limit = 0;
#ifdef NEXUS_DNS_SHARED
        // A standalone server owns its generation; CLI listeners may borrow one.
        std::unique_ptr<SharedDnsGeneration> owned_dns_generation;
#endif
        // Pending DNS tasks borrow this worker-local state until context shutdown.
        std::unique_ptr<DnsState> dns;
        std::unique_ptr<LocalDnsState> local_dns;
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_GROUP)
        // The generation owner outlives all servers and their tasks.
        dns_hp_experiment::GroupSnapshot* dns_group = nullptr;
        std::size_t dns_group_index = 0, dns_reader_base = 0;
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        dns_hp_experiment::Coordinator* dns_coordinator = nullptr;
#ifdef NEXUS_DNS_SHARED
#ifdef NEXUS_DNS_RESPONSE
        dns::ResponseCache* dns_response_cache = nullptr;
#endif
#endif
        dns_hp_experiment::ViewRegistry* dns_view_registry = nullptr;
#ifdef NEXUS_DNS_SHARED
        dns_hp_experiment::LocalViewRegistry* dns_local_registry = nullptr;
#endif
        std::vector<dns_hp_experiment::ViewRegistry::Profile> dns_profiles;
        bool dns_optimistic = false;
#endif
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        dns::detail::RefreshBudget* dns_refresh_budget = nullptr;
#endif
#endif
        // Session coroutines also borrow the policy and credentials.
        rules::RouteMatcher policy;
        std::shared_ptr<OrderedTcpPolicy const> ordered_tcp;
        std::shared_ptr<RouteSnapshots> route_snapshots;
        std::size_t route_snapshot_index = 0;
        mutable std::uint64_t cached_route_version = 0;
        mutable std::shared_ptr<RouteSnapshot const> cached_route_snapshot;
        std::shared_ptr<rules::RuntimeRouteMode const> runtime_mode;
        std::optional<Credentials> credentials;
#ifdef NEXUS_ENABLE_FAKEIP
        // Sessions borrow the shared owner through context shutdown.
        std::shared_ptr<dns::FakeIpShared> fakeip;
        std::uint64_t fakeip_view = 0;
#endif
        std::shared_ptr<dns::ReverseCache> reverse_cache;
        // Factories outlive context shutdown and suspended sessions. Workers borrow
        // their parent's factories; reconfiguration is forbidden until they stop.
        std::uint32_t direct_connect_timeout_ms = 10000;
        TcpSocketOptions direct_tcp_options;
        std::vector<TunnelFactory> outbounds;
        std::vector<TunnelFactory> const* borrowed_outbounds = nullptr;
#ifdef NEXUS_ENABLE_SS2022
        InboundFactory shadowsocks_inbound;
        InboundFactory const* borrowed_shadowsocks_inbound = nullptr;
#endif
#ifdef NEXUS_ENABLE_VLESS
        InboundFactory vless_inbound;
        bool vless_xhttp_inbound = false;
        InboundFactory const* borrowed_vless_inbound = nullptr;
#endif
#ifdef NEXUS_ENABLE_TROJAN
        InboundFactory trojan_inbound;
        InboundFactory const* borrowed_trojan_inbound = nullptr;
#endif
#ifdef NEXUS_ENABLE_SNELL
        InboundFactory snell_inbound;
        InboundFactory const* borrowed_snell_inbound = nullptr;
#endif
#ifdef NEXUS_ENABLE_ANYTLS
        InboundFactory anytls_inbound;
        InboundFactory const* borrowed_anytls_inbound = nullptr;
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
        InboundFactory shadowtls_inbound;
        InboundFactory const* borrowed_shadowtls_inbound = nullptr;
#endif
#ifdef NEXUS_ENABLE_NAIVE
        InboundFactory naive_inbound;
        InboundFactory const* borrowed_naive_inbound = nullptr;
        InboundFactory http_modern_inbound;
        InboundFactory const* borrowed_http_modern_inbound = nullptr;
        bool naive_tcp_enabled = false;
        bool naive_h3_enabled = false;
        bool http_modern_tcp_enabled = false;
        bool http_modern_h3_enabled = false;
        auto prepare_modern_h3_naive(config::NaiveInbound const&) -> std::expected<void, std::string>;
        auto prepare_modern_h3_http(config::HttpInbound const&, std::optional<Credentials> const&) -> std::expected<void, std::string>;
        auto start_modern_h3(io::endpoint) -> std::expected<std::uint16_t, std::error_code>;
        auto drain_modern_h3() noexcept -> void;
        auto stop_modern_h3() noexcept -> void;
        auto modern_h3_drained() const noexcept -> bool;
#endif
        DirectBufferPool direct_buffers;
        SplicePipePool splice_pipe_pool;
        std::size_t splice_max_idle_pipes = SplicePipePool::kMaxIdlePipes;
#if BOOST_COROSIO_HAVE_LIBURING
        std::optional<io::io_context> owned_context{std::in_place, io::uring};
#else
        std::optional<io::io_context> owned_context{std::in_place};
#endif
        io::io_context& context;
        bool shared_context = false;
        bool accept_task_active = false;
        bool context_registered = false;
        std::optional<io::tcp_acceptor> listener;
        std::optional<io::posix_stream_descriptor> listener_readiness;
        struct RetainedListener {
            int fd = -1;
            RetainedListener() noexcept = default;
            explicit RetainedListener(int v) noexcept : fd(v) {}
            RetainedListener(RetainedListener const&) = delete;
            auto operator=(RetainedListener const&) -> RetainedListener& = delete;
            RetainedListener(RetainedListener&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
            auto operator=(RetainedListener&& o) noexcept -> RetainedListener& { if (this != &o) { close(); fd = std::exchange(o.fd, -1); } return *this; }
            ~RetainedListener() { close(); }
            auto close() noexcept -> void;
        };
        RetainedListener staged_listener;
        std::vector<RetainedListener> retained_listeners;
        std::shared_ptr<TcpAdmission> admission;
        std::uint64_t listener_generation = 0;
#ifdef NEXUS_TPROXY_UDP
        std::shared_ptr<TransparentUdp> transparent_udp;
        bool transparent_datagrams = false;
        auto start_transparent_udp(io::endpoint, bool reuse) -> std::error_code;
        auto poll_transparent_udp() -> void;
        auto stop_transparent_udp() noexcept -> void;
#endif
        std::shared_ptr<FixedUdpInbound> fixed_udp_inbound;
        auto start_fixed_udp(io::endpoint) -> std::expected<std::uint16_t, std::error_code>;
        auto poll_fixed_udp(Clock::time_point) -> void;
        auto drain_fixed_udp() noexcept -> void;
        auto stop_fixed_udp() noexcept -> void;
        SessionQuota quota{64};
        std::shared_ptr<PrincipalPolicy const> principals;
        std::optional<SessionQuota> splice_pipes;
        std::optional<DnsRouting> dns_routing;
        std::optional<std::size_t> max_bootstrap_index;
        bool running = false;
        bool accepting = false;
        io::endpoint bound_listener;
        bool tun_redirect_dual_stack = false, redirect_tcp_dns = false;
        std::optional<std::uint32_t> redirect_socket_mark;
        struct DetourHandle { std::mutex mu; Server* server = nullptr; io::io_context* io = nullptr; io::endpoint ep{}; bool active = false; };
        config::ListenOptions listen_options{};
        std::shared_ptr<DetourHandle> self_detour; std::weak_ptr<DetourHandle> detour_target; bool detour_enabled = false;
        std::optional<socks5::Request> fixed_tcp_target;
        io::endpoint udp_advertise;
        std::string fixed_unix_target;
        functional::move_only_function<void() noexcept> unix_listener_cleanup;
        std::atomic_bool drain_requested{false}, drain_complete{false};
        std::shared_ptr<std::atomic_bool const> memory_shed;
        std::atomic<std::uint8_t> memory_reclaim_requested{0};
        std::shared_ptr<ShadowsocksUserDirectory> ss_dynamic_users;
        std::shared_ptr<GroupRuntimeHooks> group_hooks;
        bool find_process_enabled = false;
        Inbound inbound_type = Inbound::socks5;
        std::vector<std::unique_ptr<Server>> workers;
        std::vector<std::thread> threads;
        std::atomic_bool stopping{false}, failed{false};
        bool outbound_contexts_started = false;
        std::array<std::uint16_t, 256> outbound_context_order{};
        std::uint16_t outbound_context_count = 0;
        auto start_outbound_contexts() -> bool; auto stop_outbound_contexts() noexcept -> void;
        auto finish_outbound_contexts() noexcept -> void; auto reap_outbound_contexts() noexcept -> void;
        [[nodiscard]] auto outbound_contexts_quiesced() const noexcept -> bool;
        auto apply_memory_reclaim(std::uint8_t level) noexcept -> void;
        mutable std::mutex failure_mutex;
        std::optional<RuntimeFailure> failure_state;
        auto record_failure(RuntimeFailure value) -> void;
        auto get_failure() const -> std::optional<RuntimeFailure>;
        static constexpr std::size_t kMaxConcurrentProbes = 16;
        std::mutex probe_mutex;
        std::deque<std::shared_ptr<OutboundProbe>> pending_probes;
        std::atomic<std::size_t> active_probes{0};
        dns::TlsQueryMaintenance dns_tls_maintenance;
        auto close_listener() noexcept -> void; auto retire_acceptor() noexcept -> void;
        auto probe_http(Session&, OutboundProbe&) -> capy::task<bool>;
        auto probe_https(Session&, OutboundProbe&) -> capy::task<bool>;
        auto probe_h2_ping(Session&, OutboundProbe&) -> capy::task<std::optional<std::uint32_t>>;
        auto run_probe(std::shared_ptr<OutboundProbe>) -> capy::task<>;
        auto accept_loop() -> capy::task<>; auto accept_unix() -> capy::task<>;
        auto ensure_detour_handle() -> std::shared_ptr<DetourHandle>; auto publish_detour(bool active) noexcept -> void;
        auto dispatch_accepted(io::tcp_socket&& accepted) -> void;
        auto serve_session(std::unique_ptr<Session> session) -> capy::task<>;
        auto start_one(io::endpoint endpoint, Inbound inbound, bool reuse, int shared_fd = -1, bool threaded = false) -> std::expected<std::uint16_t, std::error_code>;
        auto run_worker_thread(Server* ptr) -> void;
        auto start_listeners(io::endpoint endpoint, Inbound inbound, unsigned count, Server const* previous)
            -> std::expected<std::uint16_t, std::error_code>;
#ifdef NEXUS_ENABLE_XHTTP_VLESS
        std::shared_ptr<class Xhttp3Inbound> xhttp3_inbound;
        auto prepare_xhttp3(std::string_view, std::string_view, std::span<std::string const>,
            std::span<std::string const>, xhttp::Profile) -> std::expected<void, std::string>;
        auto start_xhttp3(io::endpoint) -> std::expected<std::uint16_t, std::error_code>;
        auto drain_xhttp3() noexcept -> void;
        auto stop_xhttp3() noexcept -> void;
#endif
#ifdef NEXUS_ENABLE_NAIVE
        std::unique_ptr<struct ModernHttp3Inbound, void(*)(ModernHttp3Inbound*)> modern_h3_inbound{
            nullptr, +[](ModernHttp3Inbound*) {}
        };
#endif
    public:
        Server();
        explicit Server(RoutingOnly);
        explicit Server(io::io_context& external_context);
        [[nodiscard]] auto start_tun_redirect(bool ipv4, bool ipv6, bool dns) -> std::expected<std::uint16_t, std::error_code>;
        auto set_network_monitor(std::shared_ptr<platform::network::Monitor const>) noexcept -> void;
        [[nodiscard]] auto transparent_metadata(net::UdpEndpoint const&, std::optional<std::uint8_t> dscp = {},
            std::uint32_t index = 0) const noexcept -> rules::IngressMetadata;
        // Some hosts always create separate worker Servers, even for one worker.
        // Their parent must not claim the sole reader needed by that child.
        auto prepare_routing(unsigned workers, bool child_workers = false) -> std::expected<void, std::error_code>;
        auto activate_context() -> std::expected<void, std::error_code>;
        auto inherit_routing(Server const& parent, std::size_t index, std::size_t count,
            std::optional<std::uint32_t> direct_mark = {}) -> void;
        [[nodiscard]] auto current_route_snapshot() const noexcept -> std::shared_ptr<RouteSnapshot const>;
        auto attach_session(Session&, SessionQuota::Lease&&, std::shared_ptr<RouteSnapshot const> snapshot = {}) -> void;
        // Enable before start. Worker servers share this listener's snapshot.
        auto enable_traffic_stats(std::size_t packet_slots = 0) -> bool;
        [[nodiscard]] auto track_traffic(TrafficProtocol, ConnectPath, std::optional<net::UdpEndpoint> source,
            std::uint16_t destination_port, bool can_close = false) const -> TrafficRegistration;
        [[nodiscard]] auto traffic_snapshot() const -> TrafficSnapshot;
        [[nodiscard]] auto request_traffic_close(std::uint64_t id) -> TrafficCloseRequest;
        [[nodiscard]] auto close_group_sessions(std::string_view group_tag, std::optional<std::size_t> outbound = {}) -> std::size_t;
        auto set_find_process(bool enabled) noexcept -> void;
        auto set_group_hooks(std::shared_ptr<GroupRuntimeHooks> hooks) noexcept -> void;
        auto process_traffic_closes() -> void;
        auto begin_drain() noexcept -> void;
        [[nodiscard]] auto drained() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::shared_ptr<OutboundProbe>) -> bool;
        auto start_pending_probe() -> void;
        auto maintain_dns_transports() noexcept -> void { dns_tls_maintenance.poll(context); }
        auto set_memory_shed(std::shared_ptr<std::atomic_bool const> flag) noexcept -> void;
        [[nodiscard]] auto shedding_memory() const noexcept -> bool {
            return memory_shed && memory_shed->load(std::memory_order_acquire);
        }
        auto request_memory_reclaim(std::uint8_t level) noexcept -> void;
        auto set_shadowsocks_dynamic_users(std::shared_ptr<ShadowsocksUserDirectory> users) noexcept -> void;
        [[nodiscard]] auto set_session_limit(std::size_t maximum) -> bool;
        [[nodiscard]] auto set_principal_policy(std::shared_ptr<PrincipalPolicy const> snapshot) noexcept -> bool;
        [[nodiscard]] auto principal_policy() const noexcept -> PrincipalPolicy const* { return principals.get(); }
        auto publish_principal_bytes(std::chrono::steady_clock::time_point now) const noexcept -> void {
            if (principals)
                for (auto const& budget : principals->entries()) budget.publish_bytes(now);
        }
        // The host must ignore SIGPIPE before enabling splice on bare TCP sockets.
        [[nodiscard]] auto set_tcp_splice_pipes(std::size_t maximum) -> bool;
        auto acquire_session() noexcept -> std::optional<SessionQuota::Lease> { return quota.try_acquire(); }
        auto executor_context() noexcept -> io::io_context& { return context; }
        [[nodiscard]] static auto from_context(io::io_context&) noexcept -> Server*;
        [[nodiscard]] auto enable_transparent_udp() noexcept -> bool;
        // Session must have been attached to this active routing context and
        // remain alive until the returned transport and its tasks are drained.
        auto open_stream(Session&, std::size_t outbound, io::endpoint, Clock::time_point) -> capy::task<PacketConnectResult>;
        [[nodiscard]] auto open_packet_tunnel(Session&, std::size_t outbound) -> std::unique_ptr<PacketTunnel>;
        [[nodiscard]] auto has_packet_outbound(std::size_t outbound) const noexcept -> bool;
        [[nodiscard]] auto ordered_routing_policy() const noexcept -> OrderedTcpPolicy const* { return ordered_tcp.get(); }
        auto routing_policy() const noexcept -> rules::RouteMatcher const& { return policy; }
        // Converts context initialization system failures into an error result.
        [[nodiscard]] static auto create() -> std::expected<std::unique_ptr<Server>, std::error_code>;
        [[nodiscard]] static auto create_shared(io::io_context& external_context) -> std::expected<std::unique_ptr<Server>, std::error_code>;
        [[nodiscard]] auto uses_shared_context() const noexcept -> bool { return shared_context; }
        auto prepare_poll() -> std::chrono::milliseconds;
        auto finish_poll(Clock::time_point now, bool maintain_dns = true) -> void;
        ~Server();
#ifdef NEXUS_DNS_SHARED
        // Set after DNS routing and before the generation is sealed or started.
        [[nodiscard]] auto bind_shared_dns(SharedDnsGeneration&, std::size_t group, std::size_t reader_base)
            -> std::expected<void, std::error_code>;
#endif
        Server(Server const&) = delete;
        auto operator=(Server const&) -> Server& = delete;

#ifdef NEXUS_TEST_DNS_GROUP
        [[nodiscard]] auto set_dns_group_for_test(dns_hp_experiment::GroupSnapshot& owner, std::size_t group, std::size_t reader_base
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
            , dns::detail::RefreshBudget* refresh_budget = nullptr
#endif
            )
            -> std::expected<void, std::error_code>;
#ifdef NEXUS_TEST_DNS_COORDINATOR
        // Fixture generation owns both objects until every worker has drained.
        [[nodiscard]] auto set_dns_coordinator_for_test(dns_hp_experiment::Coordinator&,
            dns_hp_experiment::ViewRegistry&, bool optimistic = false) -> std::expected<void, std::error_code>;
#endif
#endif

        [[nodiscard]] auto set_block_rules(std::string_view data, RuleFormat format) -> std::expected<void, std::string>;
        [[nodiscard]] auto set_route(std::optional<std::string_view> data, RuleFormat format, RouteAction action, RouteAction fallback) -> std::expected<void, std::string>;
        [[nodiscard]] auto set_routes(std::span<RouteRule const> rules, RouteAction fallback) -> std::expected<void, std::string>;
        // Outbound 0 is direct, 1 is block, and prepared tunnel instances start at 2.
        [[nodiscard]] auto set_indexed_routes(std::span<IndexedRouteRule const> rules, std::size_t fallback,
            std::optional<std::string_view> inbound = {})
            -> std::expected<void, std::string>;
        // The CLI compiles every listener before publishing one generation.
        [[nodiscard]] auto compile_route_snapshot(std::span<IndexedRouteRule const>, std::size_t fallback,
            std::optional<std::string_view> inbound, std::optional<OrderedRuleInput>, std::shared_ptr<rules::OutboundDistribution const> distribution = {})
            const
            -> std::expected<RouteSnapshot, std::string>;
        [[nodiscard]] auto set_route_snapshots(std::shared_ptr<RouteSnapshots>, std::size_t index) -> bool;
        auto set_runtime_mode(std::shared_ptr<rules::RuntimeRouteMode const>) noexcept -> void;
        [[nodiscard]] auto get_runtime_mode() const noexcept -> std::shared_ptr<rules::RuntimeRouteMode const> const& { return runtime_mode; }
#ifdef NEXUS_TEST_SOURCE_ROUTE
        [[nodiscard]] auto set_source_policy_for_test(rules::RouteMatcher policy) -> bool;
#endif
        // Opt-in ordered TCP path, limited to SOCKS/Mixed CONNECT. Unknown
        // predicates may be skipped only when explicitly selected by caller.
        [[nodiscard]] auto set_ordered_tcp(std::span<rules::ProgramRule const>, std::size_t fallback,
            std::uint32_t sniff_timeout_ms, bool skip_unknown, bool udp = false) -> std::expected<void, std::string>;
        // Authentication can be changed only while stopped. Mixed authentication
        // is rejected until both protocols can enforce the same credentials.
        [[nodiscard]] auto set_socks5_credentials(std::string_view username, std::string_view password)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto clear_socks5_credentials() -> std::expected<void, std::string>;
        // Configure an explicit unscoped IP DNS server while stopped; absent by default.
        [[nodiscard]] auto set_dns_upstream(std::array<std::uint8_t, 4> address, std::uint16_t port)
            -> std::expected<void, std::error_code>;
        [[nodiscard]] auto set_dns_upstream(std::array<std::uint8_t, 16> address, std::uint16_t port)
            -> std::expected<void, std::error_code>;
        // A zero port selects the system resolver. Rules are ordered, first match wins.
        [[nodiscard]] auto set_dns_routing(DnsRouting routing) -> std::expected<void, std::error_code>;
#ifdef NEXUS_ENABLE_FAKEIP
        [[nodiscard]] auto protects_fakeip(std::span<std::uint8_t const> address) const -> bool;
        [[nodiscard]] auto set_fakeip(std::shared_ptr<dns::FakeIpShared> owner, std::uint64_t view)
            -> std::expected<void, std::error_code>;
#endif
        [[nodiscard]] auto set_reverse_cache(std::shared_ptr<dns::ReverseCache> owner)
            -> std::expected<void, std::error_code>;
        [[nodiscard]] auto reverse_cache_ptr() const noexcept -> dns::ReverseCache* { return reverse_cache.get(); }
        [[nodiscard]] auto set_direct_connect_timeout(std::uint32_t timeout_ms) -> std::expected<void, std::string>;
        [[nodiscard]] auto set_direct_tcp_options(TcpSocketOptions options) -> std::expected<void, std::string>;
        [[nodiscard]] auto set_listen_options(config::ListenOptions options) -> std::expected<void, std::string>;
        auto set_detour_target(Server* target) noexcept -> void;
        [[nodiscard]] auto listening_endpoint() const noexcept -> io::endpoint { return bound_listener; }
        // Replace the complete dependency set while stopped. Index 0 means
        // direct; tunnel indexes start at 2. Cycles and block are rejected.
        [[nodiscard]] auto set_outbound_detours(std::span<OutboundDetour const>) -> std::expected<void, std::string>;
        // Bootstrap indexes refer to DNS servers; prepare the authenticated outbound before starting.
        [[nodiscard]] auto prepare_vless(std::string_view host, std::uint16_t port,
            std::string_view uuid_file, std::string_view server_name, std::string_view ca_file,
            TlsKeyExchange key_exchange = TlsKeyExchange::x25519, std::optional<std::size_t> bootstrap = {}, std::optional<Reality> reality = {}, bool vision = false, std::uint32_t timeout_ms = 10000, TcpSocketOptions tcp_options = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, bool fast_open = false, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}, bool packetaddr = false, bool fixed_udp = false)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto add_vless(std::string_view host, std::uint16_t port,
            std::string_view uuid_file, std::string_view server_name, std::string_view ca_file,
            TlsKeyExchange key_exchange = TlsKeyExchange::x25519, std::optional<std::size_t> bootstrap = {}, std::optional<Reality> reality = {}, bool vision = false, std::uint32_t timeout_ms = 10000, TcpSocketOptions tcp_options = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, bool fast_open = false, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}, bool packetaddr = false, bool fixed_udp = false, std::optional<xhttp::Profile> xhttp = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}, QuicEchOptions const& ech = {})
            -> std::expected<std::size_t, std::string>;
        // The caller retains responsibility for securely handling the input PSK.
        [[nodiscard]] auto add_shadowsocks(std::string_view host, std::uint16_t port, std::span<std::uint8_t const> key,
            std::optional<std::size_t> bootstrap = {}, bool udp_over_tcp = false, std::uint32_t timeout_ms = 10000, TcpSocketOptions tcp_options = {}, bool fast_open = false,
            std::span<std::array<std::uint8_t, 32> const> identity_keys = {}, ShadowsocksCipher cipher = ShadowsocksCipher::aes, bool udp_native = false)
            -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto prepare_vless_inbound(std::string_view certificate, std::string_view key,
            std::span<std::string const> users, bool vision = false, std::optional<RealityInbound> reality = {},
            std::span<std::string const> names = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, std::optional<xhttp::Profile> xhttp = {}, std::optional<config::InboundMultiplexConfig> multiplex = {}) -> std::expected<void, std::string>;
        // Configure once; matching keys share a process-lifetime replay table.
        [[nodiscard]] auto prepare_shadowsocks_inbound(std::span<std::uint8_t const> key,
            std::span<ShadowsocksUserKey const> users = {}, ShadowsocksCipher cipher = ShadowsocksCipher::aes, std::optional<config::InboundMultiplexConfig> multiplex = {}) -> std::expected<void, std::string>;
        [[nodiscard]] auto wrap_outbound_multiplex(std::size_t outbound_index, config::MultiplexConfig const& cfg) -> std::expected<void, std::string>;
        [[nodiscard]] auto add_trojan(std::string_view host, std::uint16_t port, std::string_view password_file,
            std::string_view server_name, std::string_view ca_file, TlsKeyExchange exchange = TlsKeyExchange::x25519,
            std::optional<std::size_t> bootstrap = {}, std::uint32_t timeout_ms = 10000, TcpSocketOptions options = {}, bool fast_open = false, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, QuicEchOptions const& ech = {})
            -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_anytls(std::string_view host, std::uint16_t port, std::string_view password_file,
            std::string_view server_name, std::string_view ca_file, TlsKeyExchange exchange = TlsKeyExchange::x25519,
            std::optional<std::size_t> bootstrap = {}, std::uint32_t timeout_ms = 10000, TcpSocketOptions options = {}, AnyTlsOptions pool = {}, bool fast_open = false, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, QuicEchOptions const& ech = {})
            -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_snell(std::string_view host, std::uint16_t port, std::string_view psk_file, std::optional<std::string_view> user_file, std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, TcpSocketOptions options, bool fast_open = false, bool http_obfs = false, std::string_view obfs_host = {}, std::string_view obfs_uri = {}, bool reuse = false) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_hysteria2(std::string_view host, std::uint16_t port, std::string_view password_file, std::string_view server_name,
            std::string_view ca_file, TlsKeyExchange exchange, std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms,
            TcpSocketOptions options, std::uint32_t handshake_ms, std::uint32_t idle_ms, std::size_t native_bytes, bool udp,
            std::optional<std::string_view> salamander_file = {}, std::optional<std::size_t> max_udp_payload_size = {}, bool disable_path_mtu_discovery = false, std::uint64_t send_bps = 0, std::uint64_t receive_bps = 0, bool disable_compensation = false, TlsFingerprint fingerprint = TlsFingerprint::native, bool lazy_tcp_response = false, QuicEchOptions const& ech = {}, quic::ReceiveWindows windows = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}, std::span<config::PortRange const> port_ranges = {}, std::uint32_t hop_interval_ms = 0) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto prepare_trojan_inbound(std::string_view certificate, std::string_view key,
            std::span<std::string const> password_files, std::span<std::string const> names = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, std::optional<config::InboundMultiplexConfig> multiplex = {}) -> std::expected<void, std::string>;
        [[nodiscard]] auto prepare_snell_inbound(std::string_view psk, std::optional<std::string_view> user, std::uint32_t replay_window_seconds, std::shared_ptr<SnellReplayRegistry> registry, bool http_obfs = false) -> std::expected<void, std::string>;
        [[nodiscard]] auto prepare_anytls_inbound(std::string_view certificate, std::string_view key,
            std::span<std::string const> password_files, std::span<std::string const> names = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}) -> std::expected<void, std::string>;
        [[nodiscard]] auto add_tcp_proxy(config::TcpProxyOutbound const&) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_shadowtls(std::string_view host, std::uint16_t port, std::string_view password_file,
            std::string_view server_name, std::string_view ca_file, TlsKeyExchange exchange = TlsKeyExchange::x25519,
            std::optional<std::size_t> bootstrap = {}, std::uint32_t timeout_ms = 10000, TcpSocketOptions options = {},
            TlsFingerprint fingerprint = TlsFingerprint::native, bool strict_tls13 = true, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto prepare_shadowtls_inbound(std::string_view handshake_host, std::uint16_t handshake_port,
            std::string_view target_host, std::uint16_t target_port, std::span<std::string const> password_files,
            std::span<std::string const> names = {}, bool strict_tls13 = true) -> std::expected<void, std::string>;
        [[nodiscard]] auto add_tuic(std::string_view host, std::uint16_t port, std::string_view uuid_file, std::string_view password_file,
            std::string_view server_name, std::string_view ca_file, TlsKeyExchange exchange = TlsKeyExchange::x25519,
            TlsFingerprint fingerprint = TlsFingerprint::native, std::string_view cc = "cubic", bool udp_over_stream = false,
            std::uint32_t heartbeat_ms = 10000, std::uint32_t handshake_ms = 10000, std::uint32_t idle_ms = 60000,
            std::size_t native_bytes = 8 * 1024 * 1024, std::optional<std::size_t> bootstrap = {},
            std::uint32_t timeout_ms = 10000, TcpSocketOptions options = {}, QuicEchOptions const& ech = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_masque(std::string_view host, std::uint16_t port, std::string_view authority, std::string_view bearer_file,
            std::string_view server_name, std::string_view ca_file, TlsKeyExchange exchange = TlsKeyExchange::x25519,
            TlsFingerprint fingerprint = TlsFingerprint::native, std::uint32_t handshake_ms = 10000, std::uint32_t idle_ms = 300000,
            std::size_t native_bytes = 8 * 1024 * 1024, std::optional<std::size_t> bootstrap = {},
            std::uint32_t timeout_ms = 10000, TcpSocketOptions options = {}, MasqueIpOptions ip = {}, QuicEchOptions const& ech = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_wireguard(std::string_view host, std::uint16_t port, std::string_view private_key_file,
            std::string_view peer_public_key_file, std::optional<std::string_view> preshared_key_file,
            bool has_v4, std::array<std::uint8_t, 4> local_v4, bool has_v6, std::array<std::uint8_t, 16> local_v6,
            bool warp, std::array<std::uint8_t, 3> reserved, std::uint16_t mtu = 1420, std::uint16_t keepalive_s = 0,
            std::optional<std::size_t> bootstrap = {}, std::uint32_t timeout_ms = 10000, TcpSocketOptions options = {}) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_ssh(std::string_view host, std::uint16_t port, std::string_view user,
            std::optional<std::string_view> password_file, std::optional<std::string_view> private_key_file,
            std::span<std::array<std::uint8_t, 32> const> host_key_sha256, std::string_view cipher = {},
            std::optional<std::size_t> bootstrap = {}, std::uint32_t timeout_ms = 10000, std::uint32_t keepalive_ms = 30000,
            std::size_t max_sessions = 16, TcpSocketOptions options = {}, bool fast_open = false) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_naive(config::NaiveOutbound const&) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_openvpn(config::OpenVpnOutbound const&) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_openconnect(config::OpenConnectOutbound const&) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto add_tor(config::TorServiceConfig const&, std::uint32_t timeout_ms = 15000) -> std::expected<std::size_t, std::string>;
        [[nodiscard]] auto prepare_naive_inbound(config::NaiveInbound const&) -> std::expected<void, std::string>;
        [[nodiscard]] auto prepare_http_modern_inbound(config::HttpInbound const&) -> std::expected<void, std::string>;
        [[nodiscard]] auto add_mesh(MeshLink, std::uint16_t mtu) -> std::expected<std::size_t, std::string>;
        // Workers: 1..16.
        auto set_udp_advertise(io::endpoint address) noexcept -> void { udp_advertise = address; }
        auto set_fixed_unix_target(std::string_view path) -> bool;
        auto start_unix(std::string_view path, unsigned workers) -> std::expected<void, std::error_code>;
        [[nodiscard]] auto set_fixed_tcp_target(std::string_view host, std::uint16_t port) -> bool;
        [[nodiscard]] auto set_fixed_udp_target(std::string_view host, std::uint16_t port, std::uint32_t idle_ms = 60000) -> bool;
        [[nodiscard]] auto start(std::uint16_t port, Inbound inbound = Inbound::socks5, unsigned workers = 1, bool ipv6 = false, std::optional<std::array<std::uint8_t, 16>> address = {}) -> std::expected<std::uint16_t, std::error_code>;
        // Staged listener queues connections until generation is published; previous reuses listen fds on unchanged bind.
        [[nodiscard]] auto stage_tcp(std::shared_ptr<TcpAdmission> admission, std::uint64_t generation,
            std::uint16_t port, Inbound inbound, unsigned workers, bool ipv6,
            std::optional<std::array<std::uint8_t, 16>> address, Server const* previous = nullptr)
            -> std::expected<std::uint16_t, std::error_code>;
        [[nodiscard]] auto healthy() const noexcept -> bool;
        // First unexpected runtime failure, retained through stop and cleared on the next start.
        [[nodiscard]] auto failure() const -> std::optional<RuntimeFailure>;
        auto poll(std::chrono::milliseconds maximum_wait) -> void;
        auto stop() noexcept -> void;
    };

    [[nodiscard]] auto make_shared_io_context() -> std::expected<std::unique_ptr<io::io_context>, std::error_code>;
    auto register_context_server(io::io_context& io, Server* srv, bool has_proxy_dns) -> void;
    auto unregister_context_server(io::io_context& io, Server* srv) noexcept -> std::size_t;
}
