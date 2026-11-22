module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/continuation.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
export module proxy;
import std;
import proxy.v4;
import proxy.request_backend;
import rules;
import config;
import xhttp.config;
export import proxy.dns_routing;
import proxy.dns_state;
import dns.corosio_query;
import dns.address_sequence;
import dns.response_cache;
import http.connect;
import proxy.session_quota;
import proxy.principal_limits;
import net.principal_bytes;
export import proxy.dns_backend;
import dns.local_config;
export import dns.reverse;
import dns.tls_query;
import dns.local_response;
import dns.response_race_walk;
import net.udp_socket;
import net.udp_route;
import net.datagram_frame;
import net.ordered_datagram;
import net.stream_relay;
import platform.socket_options;
import platform.network_state;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
export import anytls.pool;
export namespace proxy { using TcpSocketOptions=platform::TcpSocketOptions; using AnyTlsOptions=anytls::PoolOptions; using HttpUpgradeTransport=config::HttpUpgradeTransport; using GrpcTransport=config::GrpcTransport; using TlsFingerprint=config::TlsFingerprint; using QuicEchOptions=config::QuicEchOptions; }
export namespace proxy { enum class TlsKeyExchange { x25519, x25519_mlkem768, x25519_mlkem768_only }; struct Reality { std::array<std::uint8_t,32> public_key{}; std::array<std::uint8_t,8> short_id{}; };
    struct RealityInbound { std::string private_key_file,certificate_file,signing_key_file,fallback_host;
        std::uint16_t fallback_port=0; std::vector<std::string> server_names;
        std::vector<std::array<std::uint8_t,8>> short_ids; std::uint64_t max_time_difference_seconds=60;
        std::optional<std::size_t> fallback_resolver; };
    struct MasqueIpOptions {
        bool enabled=false;
        std::string path="/.well-known/masque/ip/*/*/";
        std::uint16_t mtu=1280;
        std::optional<std::array<std::uint8_t,4>> local_v4;
        std::optional<std::array<std::uint8_t,16>> local_v6;
        std::string protocol="connect-ip";
        std::vector<std::pair<std::string,std::string>> headers;
    }; }
export namespace proxy {struct Session; struct SnellReplayRegistry; auto create_snell_replay_registry() -> std::shared_ptr<SnellReplayRegistry>;}
namespace proxy {
    namespace capy = boost::capy;
    namespace io = boost::corosio;
    using Clock = std::chrono::steady_clock;
    auto valid_destination(io::endpoint const& endpoint) noexcept -> bool {
        auto address=endpoint.address();
        if (!endpoint.port() || address.is_unspecified()) return false;
        if (!address.is_v6()) return true;
        auto bytes=address.to_v6().to_bytes();
        bool mapped=std::ranges::all_of(std::span(bytes).first<10>(),[](auto b) { return b==0; }) &&
                    bytes[10]==255 && bytes[11]==255;
        return !mapped || std::ranges::any_of(std::span(bytes).last<4>(),[](auto b) { return b!=0; });
    }
    struct Session; struct OutboundContext;
    export class Server;
#include "tunnel_facade.hpp"

#include "route_interface.hpp"

#include "traffic_interface.hpp"

#include "relay_pool.hpp"

#include "session_interface.hpp"

    struct Credentials {
        std::array<std::uint8_t, 255> username{}, password{};
        std::uint8_t username_size = 0, password_size = 0;
    };
#ifdef NEXUS_ENABLE_VLESS
    auto make_vless_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> users, bool vision, std::optional<RealityInbound> reality,std::span<std::string const> names,std::optional<HttpUpgradeTransport> transport={},std::optional<GrpcTransport> grpc={})
        -> std::expected<InboundFactory,std::string>;
    auto make_vless_factory(std::string_view host, std::uint16_t port, std::string_view uuid_file,
        std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap, std::optional<Reality> reality, bool vision, std::uint32_t timeout_ms,TcpSocketOptions tcp_options={},std::optional<HttpUpgradeTransport> transport={},std::optional<GrpcTransport> grpc={},bool fast_open=false,TlsFingerprint fingerprint=TlsFingerprint::native,std::optional<std::uint16_t> record_size_limit={},bool packetaddr=false,bool fixed_udp=false,std::span<std::array<std::uint8_t,32> const> pins={}) -> std::expected<TunnelFactory,std::string>;
    auto make_vless_layer_factory(std::string_view uuid_file,
        std::string_view server_name,std::string_view ca_file,TlsKeyExchange key_exchange,std::optional<Reality> reality,
        bool vision,std::uint32_t timeout_ms,std::optional<HttpUpgradeTransport> transport={},std::optional<GrpcTransport> grpc={},TlsFingerprint fingerprint=TlsFingerprint::native,std::optional<std::uint16_t> record_size_limit={}) -> std::expected<TunnelLayerFactory,std::string>;
    auto make_vless_grpc_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,TlsKeyExchange,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,GrpcTransport,TlsFingerprint,std::optional<std::uint16_t>,std::span<std::array<std::uint8_t,32> const> pins={}) -> std::expected<TunnelFactory,std::string>;
    auto make_vless_grpc_inbound_factory(std::string_view,std::string_view,std::span<std::string const>,std::span<std::string const>,GrpcTransport) -> std::expected<InboundFactory,std::string>;
#ifdef NEXUS_ENABLE_XHTTP_VLESS
    auto make_vless_xhttp_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,TlsKeyExchange,
        std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,xhttp::Profile,TlsFingerprint,std::optional<std::uint16_t>,std::optional<Reality>,std::span<std::array<std::uint8_t,32> const> pins={})
        -> std::expected<TunnelFactory,std::string>;
    auto make_vless_xhttp_inbound_factory(std::string_view,std::string_view,std::span<std::string const>,
        std::span<std::string const>,xhttp::Profile,std::optional<RealityInbound>) -> std::expected<InboundFactory,std::string>;
#endif
#endif

    export struct ShadowsocksUserKey {
        std::string_view name;
        std::span<std::uint8_t const> key;
    };
    export enum class ShadowsocksCipher { aes, chacha20 };
#ifdef NEXUS_ENABLE_SS2022
    auto make_shadowsocks_inbound_factory(std::span<std::uint8_t const> key,
        std::span<ShadowsocksUserKey const> users,ShadowsocksCipher cipher) -> std::expected<InboundFactory,std::string>;
    auto make_shadowsocks_factory(std::string_view host,std::uint16_t port,std::span<std::uint8_t const> key,
        std::optional<std::size_t> bootstrap, bool udp_over_tcp, std::uint32_t timeout_ms,TcpSocketOptions tcp_options,bool fast_open,
        std::span<std::array<std::uint8_t,32> const> identities,ShadowsocksCipher cipher,bool udp_native)
        -> std::expected<TunnelFactory,std::string>;
    auto make_shadowsocks_layer_factory(std::span<std::uint8_t const> key,bool udp_over_tcp,std::uint32_t timeout_ms)
        -> std::expected<TunnelLayerFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_TROJAN
    auto make_trojan_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,
        TlsKeyExchange,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,bool fast_open=false,TlsFingerprint fingerprint=TlsFingerprint::native,std::optional<std::uint16_t> record_size_limit={},std::span<std::array<std::uint8_t,32> const> pins={},std::optional<HttpUpgradeTransport> transport={},std::optional<GrpcTransport> grpc={}) -> std::expected<TunnelFactory,std::string>;
    auto make_trojan_inbound_factory(std::string_view,std::string_view,std::span<std::string const>,std::span<std::string const>,std::optional<HttpUpgradeTransport> transport={},std::optional<GrpcTransport> grpc={})
        -> std::expected<InboundFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_ANYTLS
    auto make_anytls_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,
        TlsKeyExchange,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,AnyTlsOptions,bool fast_open=false,TlsFingerprint fingerprint=TlsFingerprint::native,std::optional<std::uint16_t> record_size_limit={},std::span<std::array<std::uint8_t,32> const> pins={},std::optional<HttpUpgradeTransport> transport={},std::optional<GrpcTransport> grpc={}) -> std::expected<TunnelFactory,std::string>;
    auto make_anytls_inbound_factory(std::string_view,std::string_view,std::span<std::string const>,std::span<std::string const>,std::optional<HttpUpgradeTransport> transport={},std::optional<GrpcTransport> grpc={})
        -> std::expected<InboundFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_SNELL
    auto make_snell_inbound_factory(std::string_view,std::optional<std::string_view>,std::uint32_t,std::shared_ptr<SnellReplayRegistry>,bool) -> std::expected<InboundFactory,std::string>;
    auto make_snell_factory(std::string_view,std::uint16_t,std::string_view,std::optional<std::string_view>,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,bool fast_open=false,bool http_obfs=false,std::string_view obfs_host={},std::string_view obfs_uri={},bool reuse=false) -> std::expected<TunnelFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_HY2_CLIENT
    auto make_hysteria2_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,TlsKeyExchange,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,std::uint32_t,std::uint32_t,std::size_t,bool,std::optional<std::string_view>,std::optional<std::size_t>,bool,std::uint64_t,std::uint64_t,bool,TlsFingerprint=TlsFingerprint::native,bool lazy_tcp_response=false,QuicEchOptions const& ech={},bool dns_available=false,quic::ReceiveWindows windows={},std::span<std::array<std::uint8_t,32> const> pins={},std::span<config::PortRange const> port_ranges={},std::uint32_t hop_interval_ms=0) -> std::expected<TunnelFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
    auto make_shadowtls_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,
        TlsKeyExchange,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,TlsFingerprint=TlsFingerprint::native,bool strict_tls13=true,std::span<std::array<std::uint8_t,32> const> pins={}) -> std::expected<TunnelFactory,std::string>;
    auto make_shadowtls_inbound_factory(std::string_view,std::uint16_t,std::string_view,std::uint16_t,
        std::span<std::string const>,std::span<std::string const>,bool strict_tls13=true) -> std::expected<InboundFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_TUIC
    auto make_tuic_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,std::string_view,
        TlsKeyExchange,TlsFingerprint,std::string_view,bool,std::uint32_t,std::uint32_t,std::uint32_t,std::size_t,
        std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,QuicEchOptions const&,bool,std::span<std::array<std::uint8_t,32> const> pins={}) -> std::expected<TunnelFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_MASQUE_OUTBOUND
    auto make_masque_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::string_view,std::string_view,
        TlsKeyExchange,TlsFingerprint,std::uint32_t,std::uint32_t,std::size_t,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions,MasqueIpOptions,QuicEchOptions const&,bool,std::span<std::array<std::uint8_t,32> const> pins={}) -> std::expected<TunnelFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_WIREGUARD
    auto make_wireguard_factory(std::string_view,std::uint16_t,std::string_view,std::string_view,std::optional<std::string_view>,
        bool,std::array<std::uint8_t,4>,bool,std::array<std::uint8_t,16>,bool,std::array<std::uint8_t,3>,
        std::uint16_t,std::uint16_t,std::optional<std::size_t>,std::uint32_t,TcpSocketOptions) -> std::expected<TunnelFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_SSH
    auto make_ssh_factory(std::string_view,std::uint16_t,std::string_view,std::optional<std::string_view>,
        std::optional<std::string_view>,std::span<std::array<std::uint8_t,32> const>,std::string_view,
        std::optional<std::size_t>,std::uint32_t,std::uint32_t,std::size_t,TcpSocketOptions,bool) -> std::expected<TunnelFactory,std::string>;
#endif
#ifdef NEXUS_ENABLE_NAIVE
    auto make_naive_factory(config::NaiveOutbound const&) -> std::expected<TunnelFactory,std::string>;
    auto make_http_modern_factory(config::TcpProxyOutbound const&) -> std::expected<TunnelFactory,std::string>;
    auto make_naive_h2_inbound_factory(config::NaiveInbound const&) -> std::expected<InboundFactory,std::string>;
    auto make_http_modern_inbound_factory(config::HttpInbound const&,std::optional<Credentials> const&) -> std::expected<InboundFactory,std::string>;
#endif

    auto resolve_destination(Session&,io::io_context&,std::string,std::uint16_t,Clock::time_point,
        policy::DnsContext={.network=rules::Network::tcp})
        -> capy::task<std::expected<std::vector<io::endpoint>,dns::detail::ResolveError>>;
    struct RouteResolveFailure {
        sniff::RouteResolveError action;
        std::optional<dns::detail::ResolveError> dns;
    };
    auto resolve_route_action(Session&,io::io_context&,rules::ProgramCursor&,rules::ProgramStep,
        rules::ProgramInput&,sniff::RouteCandidates&,std::vector<io::endpoint>&,Clock::time_point)
        -> capy::task<std::expected<void,RouteResolveFailure>>;
    // Request metadata and borrowed views remain stable for the entire route
    // and dial operation. An owner must not be moved while views are in use.
    struct OrderedTcpRequest {
        std::string target;
        std::optional<dns::ReverseName> reverse_name;
        std::optional<net::UdpEndpoint> source;
        rules::ProgramInput input;
        sniff::RouteCandidates candidates;
        std::vector<io::endpoint> endpoints;
        OrderedTcpRequest()=default;
        OrderedTcpRequest(OrderedTcpRequest const&)=delete;
        auto operator=(OrderedTcpRequest const&) -> OrderedTcpRequest& = delete;
        [[nodiscard]] auto prepare(Session&,socks5::Request const&) -> bool;
    };
    export auto hijack_dns_query(Session&,io::io_context&,std::span<std::uint8_t const>,net::UdpEndpoint,Clock::time_point,
        rules::Network network=rules::Network::udp)
        -> capy::task<std::optional<std::vector<std::uint8_t>>>;
    export auto ordered_datagram_router(Session&,io::io_context&,std::optional<net::UdpEndpoint>,std::optional<bool> fakeip_alias={})
        -> net::stream_datagrams::OrderedRouter;
    struct OrderedTcpResult {
        sniff::RouteTcpStop stop;
        std::uint8_t code=1;
        std::optional<dns::detail::ResolveError> dns;
        std::optional<rules::Error> rule_error;
        std::error_code system{};
        bool first_sent=false;
        Clock::time_point deadline{};
        bool dns_hijacked=false;
        bool reject_drop=false;
    };
    auto shape_direct_first_payload(Session&,std::span<std::uint8_t const>) -> std::optional<std::vector<std::uint8_t>>;
    auto replay_shaped_direct(Session&,std::span<std::uint8_t const> head,std::span<std::uint8_t const> tail,Clock::time_point deadline) -> capy::task<bool>;
    // All borrowed state, including prefetched bytes held by the sniffer,
    // remains owned by the caller. On success it must replay those bytes.
    auto execute_ordered_tcp(Session&,io::io_context&,rules::RouteProgram const&,rules::ProgramCursor&,
        rules::ProgramInput&,sniff::TcpSniffer&,sniff::RouteCandidates&,std::vector<io::endpoint>&,
        std::size_t fallback,Clock::time_point sniff_deadline,Clock::time_point deadline,
        sniff::UnknownRoutePolicy unknown_policy=sniff::UnknownRoutePolicy::pause,
        void* reader_context=nullptr,
        capy::task<sniff::TcpReadResult> (*reader)(void*,sniff::TcpSniffer&,Clock::time_point)=nullptr,
        std::optional<std::span<std::uint8_t const>> first_override={})
        -> capy::task<OrderedTcpResult>;
    export auto route_ordered_stream_tcp(Session&,io::io_context&,socks5::Request const&,void*,
        capy::task<sniff::TcpReadResult> (*)(void*,sniff::TcpSniffer&,Clock::time_point))
        -> capy::task<bool>;
    export enum class OrderedStreamResult { rejected,rejected_drop,connected,dns_handled };
    export using TcpDnsHandler=capy::task<bool> (*)(void*,std::span<std::uint8_t const>,Clock::time_point);
    export auto route_ordered_stream_tcp(Session&,io::io_context&,socks5::Request const&,void*,
        capy::task<sniff::TcpReadResult> (*)(void*,sniff::TcpSniffer&,Clock::time_point),TcpDnsHandler)
        -> capy::task<OrderedStreamResult>;
    // Replay is single-use even if a tunnel write fails after a partial send.
    auto write_principal_payload(Session&,bool upstream,std::span<std::uint8_t const>) -> capy::task<bool>;
    auto replay_ordered_tcp(Session&,sniff::TcpReplay&,Clock::time_point) -> capy::task<bool>;
    auto resolve_bootstrap(Session& session, io::io_context& context, std::size_t selected,
                           std::string name, std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
    auto resolve_bootstrap_owned(Session& session, io::io_context& context, DnsSlot& slot, std::size_t selected,
                                 std::string name, std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
#ifdef NEXUS_DNS_RESPONSE
    // The slot and borrowed rotation must outlive the query and its drain.
    export auto resolve_response_owned(Session&,io::io_context&,DnsSlot&,std::size_t selected,std::string name,
        std::uint16_t type,Clock::time_point deadline,std::shared_ptr<dns::LocalSnapshot const> snapshot,
        bool disable_cache,std::size_t* rotation=nullptr,std::optional<std::string> candidate={},
        std::optional<dns::ClientSubnet> subnet={}) -> capy::task<std::expected<dns::detail::LocalResponseSelection,dns::detail::ResolveError>>;
    export auto resolve_destination_race(Session&,io::io_context&,std::string name,std::uint16_t port,Clock::time_point deadline,
        policy::DnsContext input,std::span<dns::ResponseRaceMode const> modes)
        -> capy::task<std::expected<std::vector<io::endpoint>,dns::detail::ResolveError>>;
#endif
    auto resolve_local(Session& session, io::io_context& context, std::string name, std::uint16_t port,
                       Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
    auto resolve_local_owned(Session& session, io::io_context& context, DnsSlot& slot, std::string name,
                             std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
    auto watch_client_error(Session& session) -> capy::task<capy::results<>>;
#ifdef NEXUS_ENABLE_SOCKS_UDP
    export auto resolve_udp_domain(Session& session, io::io_context& context, std::string name,
                            std::uint16_t port, Clock::time_point deadline,net::UdpEndpoint const* source=nullptr) -> capy::task<std::optional<std::vector<io::endpoint>>>;
#endif
    // Endpoints and session must outlive the operation; action uses RouteAction's
    // direct/block values or the existing tunnel factory index encoding.
    auto dial_route_candidates(Session&,io::io_context&,std::span<io::endpoint const>,std::size_t,Clock::time_point,
        std::span<std::uint8_t const> first,bool* first_sent,std::optional<std::size_t> rule,
        std::optional<std::string_view> tunnel_domain) -> capy::task<std::uint8_t>;
    auto dial(Session& session, io::io_context& context,
              rules::RouteMatcher const& policy, socks5::Request const& request,Clock::time_point limit=Clock::time_point::max(),
              std::span<std::uint8_t const> first={},bool* first_sent=nullptr) -> capy::task<std::uint8_t>;
    export auto dial_destination(Session&,io::io_context&,rules::RouteMatcher const&,socks5::Request const&,Clock::time_point limit=Clock::time_point::max()) -> capy::task<std::uint8_t>;
    export auto dial_destination(Session&,io::io_context&,rules::RouteMatcher const&,socks5::Request const&,net::UdpEndpoint const&,Clock::time_point limit=Clock::time_point::max()) -> capy::task<std::uint8_t>;
    auto forward_http(Session& session, io::io_context& context,
                      rules::RouteMatcher const& policy, std::string_view input) -> capy::task<>;
    auto serve_fixed_unix(Session&,io::io_context&,std::string_view) -> capy::task<>;
    auto serve_fixed_tcp(Session&,io::io_context&,rules::RouteMatcher const&,
                         socks5::Request const&) -> capy::task<>;
    auto serve_redirect_dns(Session&,io::io_context&,std::span<std::uint8_t const>,Clock::time_point) -> capy::task<>;
    auto serve_transparent_tcp(Session&,io::io_context&,rules::RouteMatcher const&,io::endpoint listener,bool tproxy,bool dns)
        -> capy::task<>;
    enum class ProxyHandshake { socks5, mixed, http };

    auto handshake(Session& session, io::io_context& context,
                   rules::RouteMatcher const& policy, ProxyHandshake mode, std::optional<Credentials> const& credentials) -> capy::task<>;
}

export namespace proxy {
    enum class OutboundProbeMode { http, h2_ping };
    struct OutboundProbeStatusRange {
        std::uint16_t low = 200;
        std::uint16_t high = 299;
    };
    struct OutboundProbe {
        rules::RouteMatcher route;
        socks5::Request target;
        std::string request;
        OutboundProbeMode mode = OutboundProbeMode::http;
        std::vector<OutboundProbeStatusRange> expected_status;
        bool use_tls = false;
        std::string tls_server_name;
        std::string tls_ca_file;
        std::chrono::steady_clock::time_point deadline;
        // Zero is pending, one is failure, and success stores latency + 2 ms.
        std::atomic<std::uint32_t> result{0};
        std::atomic<std::uint16_t> status_code{0};
    };
    class MeshLink {
    public:
        struct Network {
            std::optional<std::array<std::uint8_t,4>> ipv4;
            std::optional<std::array<std::uint8_t,16>> ipv6;
            std::uint64_t revision;
        };
        virtual ~MeshLink() = default;
        virtual auto network() const -> std::optional<Network> = 0;
        virtual auto failed() const noexcept -> bool = 0;
        virtual auto send(std::uint64_t, std::span<std::uint8_t const>) -> bool = 0;
        virtual auto receive(std::uint64_t) -> std::optional<std::vector<std::uint8_t>> = 0;
    };
    struct NaiveUserFile { std::string name, username, password_file; };
    enum class Inbound { socks5, mixed, vless, shadowsocks, trojan, anytls, snell, shadowtls, redirect, tproxy, http, fixed_tcp, fixed_udp, naive };
    struct RoutingOnly {};
    enum class RuleFormat { kdl, beve, srs };
    enum class RouteAction { direct, block, vless };
    struct RouteRule { std::string_view data; RuleFormat format; RouteAction action; };
    struct IndexedRouteRule { std::string_view data; RuleFormat format; std::size_t outbound; bool ip_cidr_match_source=false; };
    [[nodiscard]] auto compile_routes(std::span<IndexedRouteRule const>,std::size_t fallback,
        std::size_t physical_count,std::optional<std::string_view> inbound,std::optional<OrderedRuleInput>,
        std::shared_ptr<rules::OutboundDistribution const> distribution={}) -> std::expected<RouteSnapshot,std::string>;
    struct OutboundDetour { std::size_t outbound, detour; };
    enum class FailureKind { accept, accept_task, worker, transparent_udp };
    struct RuntimeFailure {
        FailureKind kind;
        std::error_code system_error;
    };
    [[nodiscard]] auto describe(FailureKind kind) noexcept -> std::string_view;

    class TransparentUdp;
    class FixedUdpInbound;
    // One publication point for every ordinary TCP listener in a host.
    // The mutex serializes publication with the nonblocking kernel accept.
    class TcpAdmission {
        friend class Server;
        std::mutex mutex;
        std::atomic<std::uint64_t> generation{0};
    public:
        [[nodiscard]] auto publish(std::uint64_t next,std::function_ref<void() noexcept> prepare) -> bool;
        [[nodiscard]] auto publish(std::uint64_t next) -> bool {return publish(next,[]() noexcept {});}
    };

#include "server_interface.hpp"


}
