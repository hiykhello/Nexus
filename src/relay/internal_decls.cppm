// Internal outbound factories, ordered routing, DNS, and dial declarations.
export module relay:internal_decls;
import std;
import capy;
import corosio;
import config;
import xhttp.config;
import rules;
import socks5;
import dns.corosio_query;
import dns.corosio_resolver;
import dns.local_config;
import dns.local_response;
import dns.policy;
import dns.response_race_walk;
import dns.reverse;
import net.datagram_frame;
import net.ordered_datagram;
import net.udp_socket;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import :types;
import :tunnel_facade;
import :route_interface;
import :traffic_interface;
import :relay_pool;
import :session_interface;

namespace relay {
#ifdef NEXUS_ENABLE_VLESS
    auto make_vless_inbound_factory(std::string_view certificate, std::string_view key, std::span<std::string const> users, bool vision, std::optional<RealityInbound> reality, std::span<std::string const> names, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, std::optional<config::InboundMultiplexConfig> multiplex = {})
        -> std::expected<InboundFactory, std::string>;
    auto make_vless_factory(std::string_view host, std::uint16_t port, std::string_view uuid_file,
        std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap, std::optional<Reality> reality, bool vision, std::uint32_t timeout_ms, TcpSocketOptions tcp_options = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, bool fast_open = false, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}, bool packetaddr = false, bool fixed_udp = false, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<TunnelFactory, std::string>;
    auto make_vless_layer_factory(std::string_view uuid_file,
        std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<Reality> reality,
        bool vision, std::uint32_t timeout_ms, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}) -> std::expected<TunnelLayerFactory, std::string>;
    auto make_vless_grpc_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view, TlsKeyExchange, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, GrpcTransport, TlsFingerprint, std::optional<std::uint16_t>, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<TunnelFactory, std::string>;
    auto make_vless_grpc_inbound_factory(std::string_view, std::string_view, std::span<std::string const>, std::span<std::string const>, GrpcTransport) -> std::expected<InboundFactory, std::string>;
#ifdef NEXUS_ENABLE_XHTTP_VLESS
    auto make_vless_xhttp_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view, TlsKeyExchange,
        std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, xhttp::Profile, TlsFingerprint, std::optional<std::uint16_t>, std::optional<Reality>, std::span<std::array<std::uint8_t, 32> const> pins = {})
        -> std::expected<TunnelFactory, std::string>;
    auto make_vless_xhttp_inbound_factory(std::string_view, std::string_view, std::span<std::string const>,
        std::span<std::string const>, xhttp::Profile, std::optional<RealityInbound>) -> std::expected<InboundFactory, std::string>;
#endif
#endif

#ifdef NEXUS_ENABLE_SS2022
    auto make_shadowsocks_inbound_factory(std::span<std::uint8_t const> key,
        std::span<ShadowsocksUserKey const> users, ShadowsocksCipher cipher, std::optional<config::InboundMultiplexConfig> multiplex = {}) -> std::expected<InboundFactory, std::string>;
    auto make_shadowsocks_factory(std::string_view host, std::uint16_t port, std::span<std::uint8_t const> key,
        std::optional<std::size_t> bootstrap, bool udp_over_tcp, std::uint32_t timeout_ms, TcpSocketOptions tcp_options, bool fast_open,
        std::span<std::array<std::uint8_t, 32> const> identities, ShadowsocksCipher cipher, bool udp_native)
        -> std::expected<TunnelFactory, std::string>;
    auto make_shadowsocks_layer_factory(std::span<std::uint8_t const> key, bool udp_over_tcp, std::uint32_t timeout_ms)
        -> std::expected<TunnelLayerFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_TROJAN
    auto make_trojan_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view,
        TlsKeyExchange, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, bool fast_open = false, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}) -> std::expected<TunnelFactory, std::string>;
    auto make_trojan_inbound_factory(std::string_view, std::string_view, std::span<std::string const>, std::span<std::string const>, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}, std::optional<config::InboundMultiplexConfig> multiplex = {})
        -> std::expected<InboundFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_ANYTLS
    auto make_anytls_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view,
        TlsKeyExchange, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, AnyTlsOptions, bool fast_open = false, TlsFingerprint fingerprint = TlsFingerprint::native, std::optional<std::uint16_t> record_size_limit = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {}) -> std::expected<TunnelFactory, std::string>;
    auto make_anytls_inbound_factory(std::string_view, std::string_view, std::span<std::string const>, std::span<std::string const>, std::optional<HttpUpgradeTransport> transport = {}, std::optional<GrpcTransport> grpc = {})
        -> std::expected<InboundFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_SNELL
    auto make_snell_inbound_factory(std::string_view, std::optional<std::string_view>, std::uint32_t, std::shared_ptr<SnellReplayRegistry>, bool) -> std::expected<InboundFactory, std::string>;
    auto make_snell_factory(std::string_view, std::uint16_t, std::string_view, std::optional<std::string_view>, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, bool fast_open = false, bool http_obfs = false, std::string_view obfs_host = {}, std::string_view obfs_uri = {}, bool reuse = false) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_HY2_CLIENT
    auto make_hysteria2_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view, TlsKeyExchange, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, std::uint32_t, std::uint32_t, std::size_t, bool, std::optional<std::string_view>, std::optional<std::size_t>, bool, std::uint64_t, std::uint64_t, bool, TlsFingerprint = TlsFingerprint::native, bool lazy_tcp_response = false, QuicEchOptions const& ech = {}, bool dns_available = false, quic::ReceiveWindows windows = {}, std::span<std::array<std::uint8_t, 32> const> pins = {}, std::span<config::PortRange const> port_ranges = {}, std::uint32_t hop_interval_ms = 0) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
    auto make_shadowtls_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view,
        TlsKeyExchange, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, TlsFingerprint = TlsFingerprint::native, bool strict_tls13 = true, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<TunnelFactory, std::string>;
    auto make_shadowtls_inbound_factory(std::string_view, std::uint16_t, std::string_view, std::uint16_t,
        std::span<std::string const>, std::span<std::string const>, bool strict_tls13 = true) -> std::expected<InboundFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_TUIC
    auto make_tuic_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view, std::string_view,
        TlsKeyExchange, TlsFingerprint, std::string_view, bool, std::uint32_t, std::uint32_t, std::uint32_t, std::size_t,
        std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, QuicEchOptions const&, bool, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_MASQUE_OUTBOUND
    auto make_masque_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::string_view, std::string_view,
        TlsKeyExchange, TlsFingerprint, std::uint32_t, std::uint32_t, std::size_t, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions, MasqueIpOptions, QuicEchOptions const&, bool, std::span<std::array<std::uint8_t, 32> const> pins = {}) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_WIREGUARD
    auto make_wireguard_factory(std::string_view, std::uint16_t, std::string_view, std::string_view, std::optional<std::string_view>,
        bool, std::array<std::uint8_t, 4>, bool, std::array<std::uint8_t, 16>, bool, std::array<std::uint8_t, 3>,
        std::uint16_t, std::uint16_t, std::optional<std::size_t>, std::uint32_t, TcpSocketOptions) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_SSH
    auto make_ssh_factory(std::string_view, std::uint16_t, std::string_view, std::optional<std::string_view>,
        std::optional<std::string_view>, std::span<std::array<std::uint8_t, 32> const>, std::string_view,
        std::optional<std::size_t>, std::uint32_t, std::uint32_t, std::size_t, TcpSocketOptions, bool) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_NAIVE
    auto make_naive_factory(config::NaiveOutbound const&) -> std::expected<TunnelFactory, std::string>;
    auto make_http_modern_factory(config::TcpProxyOutbound const&) -> std::expected<TunnelFactory, std::string>;
    auto make_naive_h2_inbound_factory(config::NaiveInbound const&) -> std::expected<InboundFactory, std::string>;
    auto make_http_modern_inbound_factory(config::HttpInbound const&, std::optional<Credentials> const&) -> std::expected<InboundFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_OPENVPN
    auto make_openvpn_factory(config::OpenVpnOutbound const&) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_OPENCONNECT
    auto make_openconnect_factory(config::OpenConnectOutbound const&) -> std::expected<TunnelFactory, std::string>;
#endif
#ifdef NEXUS_ENABLE_TOR
    auto make_tor_factory(config::TorServiceConfig const&, std::uint32_t timeout_ms) -> std::expected<TunnelFactory, std::string>;
#endif

    struct ResolveOverride {
        std::optional<rules::DnsRuleStrategy> strategy{};
        std::optional<std::size_t> server{};
        std::optional<bool> disable_cache{};
        std::optional<std::uint32_t> rewrite_ttl{};
        std::optional<dns::ClientSubnet> client_subnet{};
    };
    auto resolve_destination(Session&, io::io_context&, std::string, std::uint16_t, Clock::time_point,
        policy::DnsContext = {.network = rules::Network::tcp}, ResolveOverride = {})
        -> capy::task<std::expected<std::vector<io::endpoint>, dns::detail::ResolveError>>;
    struct RouteResolveFailure {
        sniff::RouteResolveError action;
        std::optional<dns::detail::ResolveError> dns;
    };
    auto resolve_route_action(Session&, io::io_context&, rules::ProgramCursor&, rules::ProgramStep,
        rules::ProgramInput&, sniff::RouteCandidates&, std::vector<io::endpoint>&, Clock::time_point)
        -> capy::task<std::expected<void, RouteResolveFailure>>;
    // Request metadata and borrowed views remain stable for the entire route
    // and dial operation. An owner must not be moved while views are in use.
    struct OrderedTcpRequest {
        std::string target;
        std::optional<dns::ReverseName> reverse_name;
        std::optional<net::UdpEndpoint> source;
        rules::ProgramInput input;
        sniff::RouteCandidates candidates;
        std::vector<io::endpoint> endpoints;
        OrderedTcpRequest() = default;
        OrderedTcpRequest(OrderedTcpRequest const&) = delete;
        auto operator=(OrderedTcpRequest const&) -> OrderedTcpRequest& = delete;
        [[nodiscard]] auto prepare(Session&, socks5::Request const&) -> bool;
    };
    export auto hijack_dns_query(Session&, io::io_context&, std::span<std::uint8_t const>, net::UdpEndpoint, Clock::time_point,
        rules::Network network = rules::Network::udp)
        -> capy::task<std::optional<std::vector<std::uint8_t>>>;
    export auto ordered_datagram_router(Session&, io::io_context&, std::optional<net::UdpEndpoint>, std::optional<bool> fakeip_alias = {})
        -> net::stream_datagrams::OrderedRouter;
    struct OrderedTcpResult {
        sniff::RouteTcpStop stop;
        std::uint8_t code = 1;
        std::optional<dns::detail::ResolveError> dns;
        std::optional<rules::Error> rule_error;
        std::error_code system{};
        bool first_sent = false;
        Clock::time_point deadline{};
        bool dns_hijacked = false;
        bool reject_drop = false;
    };
    auto shape_direct_first_payload(Session&, std::span<std::uint8_t const>) -> std::optional<std::vector<std::uint8_t>>;
    auto replay_shaped_direct(Session&, std::span<std::uint8_t const> head, std::span<std::uint8_t const> tail, Clock::time_point deadline) -> capy::task<bool>;
    // All borrowed state, including prefetched bytes held by the sniffer,
    // remains owned by the caller. On success it must replay those bytes.
    auto execute_ordered_tcp(Session&, io::io_context&, rules::RouteProgram const&, rules::ProgramCursor&,
        rules::ProgramInput&, sniff::TcpSniffer&, sniff::RouteCandidates&, std::vector<io::endpoint>&,
        std::size_t fallback, Clock::time_point sniff_deadline, Clock::time_point deadline,
        sniff::UnknownRoutePolicy unknown_policy = sniff::UnknownRoutePolicy::pause,
        void* reader_context = nullptr,
        capy::task<sniff::TcpReadResult> (*reader)(void*, sniff::TcpSniffer&, Clock::time_point) = nullptr,
        std::optional<std::span<std::uint8_t const>> first_override = {})
        -> capy::task<OrderedTcpResult>;
    export auto route_ordered_stream_tcp(Session&, io::io_context&, socks5::Request const&, void*,
        capy::task<sniff::TcpReadResult> (*)(void*, sniff::TcpSniffer&, Clock::time_point))
        -> capy::task<bool>;
    export enum class OrderedStreamResult { rejected, rejected_drop, connected, dns_handled };
    export using TcpDnsHandler = capy::task<bool> (*)(void*, std::span<std::uint8_t const>, Clock::time_point);
    export auto route_ordered_stream_tcp(Session&, io::io_context&, socks5::Request const&, void*,
        capy::task<sniff::TcpReadResult> (*)(void*, sniff::TcpSniffer&, Clock::time_point), TcpDnsHandler)
        -> capy::task<OrderedStreamResult>;
    // Replay is single-use even if a tunnel write fails after a partial send.
    auto write_principal_payload(Session&, bool upstream, std::span<std::uint8_t const>) -> capy::task<bool>;
    auto replay_ordered_tcp(Session&, sniff::TcpReplay&, Clock::time_point) -> capy::task<bool>;
    auto resolve_bootstrap(Session& session, io::io_context& context, std::size_t selected,
        std::string name, std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
    auto resolve_bootstrap_owned(Session& session, io::io_context& context, DnsSlot& slot, std::size_t selected,
        std::string name, std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
#ifdef NEXUS_DNS_RESPONSE
    // The slot and borrowed rotation must outlive the query and its drain.
    export auto resolve_response_owned(Session&, io::io_context&, DnsSlot&, std::size_t selected, std::string name,
        std::uint16_t type, Clock::time_point deadline, std::shared_ptr<dns::LocalSnapshot const> snapshot,
        bool disable_cache, std::size_t* rotation = nullptr, std::optional<std::string> candidate = {},
        std::optional<dns::ClientSubnet> subnet = {}) -> capy::task<std::expected<dns::detail::LocalResponseSelection, dns::detail::ResolveError>>;
    export auto resolve_destination_race(Session&, io::io_context&, std::string name, std::uint16_t port, Clock::time_point deadline,
        policy::DnsContext input, std::span<dns::ResponseRaceMode const> modes)
        -> capy::task<std::expected<std::vector<io::endpoint>, dns::detail::ResolveError>>;
#endif
    auto resolve_local(Session& session, io::io_context& context, std::string name, std::uint16_t port,
        Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
    auto resolve_local_owned(Session& session, io::io_context& context, DnsSlot& slot, std::string name,
        std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
    auto watch_client_error(Session& session) -> capy::task<capy::results<>>;
#ifdef NEXUS_ENABLE_SOCKS_UDP
    export auto resolve_udp_domain(Session& session, io::io_context& context, std::string name,
        std::uint16_t port, Clock::time_point deadline, net::UdpEndpoint const* source = nullptr) -> capy::task<std::optional<std::vector<io::endpoint>>>;
#endif
    // Endpoints and session must outlive the operation; action uses RouteAction's
    // direct/block values or the existing tunnel factory index encoding.
    auto dial_route_candidates(Session&, io::io_context&, std::span<io::endpoint const>, std::size_t, Clock::time_point,
        std::span<std::uint8_t const> first, bool* first_sent, std::optional<std::size_t> rule,
        std::optional<std::string_view> tunnel_domain) -> capy::task<std::uint8_t>;
    auto dial(Session& session, io::io_context& context,
        rules::RouteMatcher const& policy, socks5::Request const& request, Clock::time_point limit = Clock::time_point::max(),
        std::span<std::uint8_t const> first = {}, bool* first_sent = nullptr) -> capy::task<std::uint8_t>;
    export auto dial_destination(Session&, io::io_context&, rules::RouteMatcher const&, socks5::Request const&, Clock::time_point limit = Clock::time_point::max()) -> capy::task<std::uint8_t>;
    export auto dial_destination(Session&, io::io_context&, rules::RouteMatcher const&, socks5::Request const&, net::UdpEndpoint const&, Clock::time_point limit = Clock::time_point::max()) -> capy::task<std::uint8_t>;
    auto forward_http(Session& session, io::io_context& context,
        rules::RouteMatcher const& policy, std::string_view input) -> capy::task<>;
    auto serve_fixed_unix(Session&, io::io_context&, std::string_view) -> capy::task<>;
    auto serve_fixed_tcp(Session&, io::io_context&, rules::RouteMatcher const&,
        socks5::Request const&) -> capy::task<>;
    auto serve_redirect_dns(Session&, io::io_context&, std::span<std::uint8_t const>, Clock::time_point) -> capy::task<>;
    auto serve_transparent_tcp(Session&, io::io_context&, rules::RouteMatcher const&, io::endpoint listener, bool tproxy, bool dns)
        -> capy::task<>;
    enum class ProxyHandshake { socks5, mixed, http };

    auto handshake(Session& session, io::io_context& context,
        rules::RouteMatcher const& policy, ProxyHandshake mode, std::optional<Credentials> const& credentials) -> capy::task<>;
    auto relay_splice(Session&, bool, bool = false) -> capy::task<std::optional<bool>>;
}
