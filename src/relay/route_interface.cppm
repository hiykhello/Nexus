// Packet tunnel, route snapshots, DNS snapshot, and reject storm guard.
export module relay:route_interface;
import std;
import capy;
import corosio;
import functional;
import utility;
import proxy.v4;
import rules;
import dns.corosio_query;
import dns.policy;
import dns.local_config;
import dns.tls_query;
import net.datagram_frame;
import relay.dns_backend;
import relay.dns_routing;
import sniff.tcp;
import sniff.route_tcp;
import :types;
import :tunnel_facade;

namespace relay {
    export class PacketTunnel {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        explicit PacketTunnel(std::unique_ptr<Impl>);
        friend class Server;
    public:
        ~PacketTunnel();
        PacketTunnel(PacketTunnel const&) = delete;
        auto operator=(PacketTunnel const&) -> PacketTunnel& = delete;
        [[nodiscard]] auto transport() const noexcept -> net::PacketTransport;
        [[nodiscard]] auto fixed_peer() const noexcept -> bool;
        [[nodiscard]] auto connect_until(Clock::time_point deadline) -> capy::task<PacketConnectResult>;
        [[nodiscard]] auto connect_until(net::ProxyAddress peer, Clock::time_point deadline) -> capy::task<PacketConnectResult>;
        [[nodiscard]] auto connection_deadline(Clock::time_point limit) const noexcept -> Clock::time_point;
        auto connect(Clock::time_point deadline) -> capy::task<PacketConnectResult>;
        auto connect(net::ProxyAddress peer, Clock::time_point deadline) -> capy::task<PacketConnectResult>;
        auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool>;
        auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>>;
        auto cancel() noexcept -> void;
    };
    // The immutable factory and its profile must outlive every layer it creates.
    using TunnelLayerFactory = functional::move_only_function<pro::proxy<TunnelFacade>(Session&, pro::proxy<TunnelFacade>&&) const>;
    using InboundFactory = functional::move_only_function<capy::task<>(Session&, io::io_context&, rules::RouteProgram const&) const>;
    // The snapshot source is process-wide; rotation remains worker-local.
    export struct LocalDnsState {
        dns::LocalSnapshotSource& source = dns::system_local_snapshots();
        std::size_t rotation = 0;
    };
    export struct DnsSlot {
        void* operation = nullptr;
        void (*cancel_operation)(void*) noexcept = nullptr;
        bool canceled = false;
        auto cancel() noexcept -> void { canceled = true; if (cancel_operation) cancel_operation(operation); }
    };
    // Only layered transports carry this state. A supplied stream is already
    // connected; a detour resolves the node and owns each lower attempt.
    struct LowerConnector {
        pro::proxy<TunnelFacade> tunnel;
        io::io_context* context = nullptr;
        TunnelFactory const* factory = nullptr;
        std::string_view host;
        std::uint16_t port = 0;
        std::optional<std::size_t> bootstrap;
        DnsSlot dns;
        // Kept in the startup coroutine, then released before data transfer.
        struct Candidates { std::vector<io::endpoint> endpoints; std::size_t next = 0; bool resolved = false; };
        auto connect(Session&, Clock::time_point, Candidates&) -> capy::task<TunnelConnectResult>;
        // The upper handshake has drained before replacing its lower stream.
        auto retry() noexcept -> bool {
            if (!factory) return false;
            if (tunnel) tunnel->cancel();
            tunnel = {};
            return true;
        }
        auto cancel() noexcept -> void { dns.cancel(); if (tunnel) tunnel->cancel(); }
    };
    struct OrderedTcpPolicy {
        rules::RouteProgram program;
        std::size_t fallback;
        std::chrono::milliseconds sniff_timeout;
        sniff::UnknownRoutePolicy unknown_policy;
        bool udp = false;
    };
    export struct DnsRuleSnapshot {
        std::vector<policy::DnsRule> rules;
        policy::DnsContextRequirements context = policy::dns_context_requirements(rules);
#ifdef NEXUS_DNS_RESPONSE
        bool has_response_program = policy::dns_has_response_program(rules);
#endif
        std::optional<std::uint64_t> view;

        explicit DnsRuleSnapshot(std::vector<policy::DnsRule> values, std::optional<std::uint64_t> policy_view = {})
            : rules(std::move(values)), view(policy_view) {}
    };
    export struct DnsRuntimeSnapshot {
        DnsRouting routing;
        std::uint64_t generation = 1;
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        std::shared_ptr<dns_hp_experiment::ViewRegistry> view_registry;
        std::vector<dns_hp_experiment::ViewRegistry::Profile> profiles;
#endif
        [[nodiscard]] auto endpoint(std::size_t index) const -> corosio::endpoint {
            auto const& server = routing.servers[index];
            if (server.ipv6) return corosio::endpoint(corosio::ipv6_address(server.address), server.port);
            corosio::ipv4_address::bytes_type bytes{};
            std::copy_n(server.address.begin(), 4, bytes.begin());
            return corosio::endpoint(corosio::ipv4_address(bytes), server.port);
        }
    };
    export [[nodiscard]] inline auto compile_dns_runtime_snapshot(DnsRouting routing, std::uint64_t generation)
        -> std::expected<std::shared_ptr<DnsRuntimeSnapshot const>, std::string> {
        if (routing.servers.empty() || routing.final >= routing.servers.size())
            return std::unexpected("invalid DNS routing configuration");
        if (generation == 0 || generation >= dns::detail::TransportSnapshot::generation_limit)
            return std::unexpected("DNS runtime generation exhausted");
        auto snapshot = std::make_shared<DnsRuntimeSnapshot>(DnsRuntimeSnapshot{std::move(routing), generation});
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        try {
            snapshot->view_registry = std::make_shared<dns_hp_experiment::ViewRegistry>(64, 1024 * 1024, 4096);
            snapshot->profiles.reserve(snapshot->routing.servers.size());
            for (std::size_t i = 0; i < snapshot->routing.servers.size(); ++i) {
                auto profile = snapshot->view_registry->register_profile(snapshot->routing, i);
                if (!profile) return std::unexpected("cannot register reloaded DNS server profile");
                snapshot->profiles.push_back(*profile);
            }
            snapshot->view_registry->seal();
        } catch (std::bad_alloc const&) {
            return std::unexpected("DNS reload: out of memory");
        }
#endif
        return snapshot;
    }
    export struct GroupTagMap {
        std::vector<std::string> selector_names;
        std::vector<std::optional<std::size_t>> indexed_rule_groups;
        std::vector<std::optional<std::size_t>> ordered_rule_groups;
        std::optional<std::size_t> default_group;
        std::vector<std::optional<std::size_t>> unique_outbound_group;

        [[nodiscard]] auto resolve(bool ordered, std::optional<std::size_t> rule, std::size_t outbound) const noexcept
            -> std::optional<std::size_t> {
            if (rule) {
                auto const& vec = ordered ? ordered_rule_groups : indexed_rule_groups;
                if (*rule < vec.size() && vec[*rule]) return vec[*rule];
            } else if (default_group) {
                return default_group;
            }
            if (outbound < unique_outbound_group.size()) return unique_outbound_group[outbound];
            return {};
        }
        [[nodiscard]] auto name(std::size_t idx) const noexcept -> std::string_view {
            return idx < selector_names.size() ? std::string_view(selector_names[idx]) : std::string_view{};
        }
    };
    export struct TunnelRefBits {
        std::vector<std::uint64_t> words;
        std::size_t bit_count = 0;
        explicit TunnelRefBits(std::size_t bits = 0) : words((bits + 63u) / 64u, 0u), bit_count(bits) {}
        [[nodiscard]] auto size() const noexcept -> std::size_t { return bit_count; }
        auto set(std::size_t idx) noexcept -> void {
            if (idx < bit_count) words[idx >> 6] |= (std::uint64_t{1} << (idx & 63u));
        }
        [[nodiscard]] auto test(std::size_t idx) const noexcept -> bool {
            return idx < bit_count && ((words[idx >> 6] >> (idx & 63u)) & 1u) != 0u;
        }
    };
    export struct RouteSnapshot {
        rules::RouteProgram matcher;
        std::optional<OrderedTcpPolicy> ordered;
        std::shared_ptr<DnsRuleSnapshot const> dns{};
        std::uint64_t generation = 1;
        std::optional<TunnelRefBits> tunnel_references{};
        std::shared_ptr<dns::detail::TransportSnapshot const> dns_transports;
        std::shared_ptr<DnsRuntimeSnapshot const> dns_runtime{};
        std::shared_ptr<GroupTagMap const> group_tags{};
        bool dns_disabled = false;
    };
    export using RouteSnapshots = utility::atomic_shared_ptr<std::vector<RouteSnapshot> const>;
    export struct OrderedRuleInput {
        std::span<rules::ProgramRule const> rules;
        std::uint32_t sniff_timeout_ms;
        bool skip_unknown, udp;
    };
    export [[nodiscard]] auto compile_routes(std::span<IndexedRouteRule const>, std::size_t fallback,
        std::size_t physical_count, std::optional<std::string_view> inbound, std::optional<OrderedRuleInput>,
        std::shared_ptr<rules::OutboundDistribution const> distribution = {},
        std::span<std::size_t const> extra_outbounds = {}) -> std::expected<RouteSnapshot, std::string>;
    // Sliding 30-second window (50 triggers) that upgrades default reject
    // replies to silent drop under flood unless no-drop is configured.
    export class RejectStormGuard {
        static constexpr std::size_t kThreshold = 50;
        static constexpr auto kWindow = std::chrono::seconds(30);
        mutable std::mutex mutex_;
        std::array<Clock::time_point, kThreshold> ring_{};
        std::size_t head_ = 0, count_ = 0;
    public:
        [[nodiscard]] auto should_drop(rules::RejectMethod method, bool no_drop,
            Clock::time_point now = Clock::now()) noexcept -> bool {
            if (method == rules::RejectMethod::drop) return true;
            if (no_drop) return false;
            std::lock_guard lock(mutex_);
            while (count_ > 0 && now - ring_[head_] > kWindow) {
                head_ = (head_ + 1) % kThreshold;
                --count_;
            }
            if (count_ >= kThreshold) return true;
            ring_[(head_ + count_) % kThreshold] = now;
            ++count_;
            return false;
        }
        auto reset() noexcept -> void {
            std::lock_guard lock(mutex_);
            head_ = 0; count_ = 0;
        }
    };
    export inline auto global_reject_storm_guard() noexcept -> RejectStormGuard& {
        static RejectStormGuard guard;
        return guard;
    }
}
