// Core exported types and module-private foundation helpers for proxy runtime.
module;
#include <proxy/proxy_macros.h>

export module relay:types;
import std;
import proxy.v4;
import capy;
import corosio;
import functional;
import utility;
import config;
import rules;
import socks5;
import anytls.pool;
import platform.socket_options;

export namespace relay {
    inline constexpr std::uint32_t max_tunnel_outbounds = 65535u;
    using TcpSocketOptions = platform::TcpSocketOptions;
    using AnyTlsOptions = anytls::PoolOptions;
    using HttpUpgradeTransport = config::HttpUpgradeTransport;
    using GrpcTransport = config::GrpcTransport;
    using TlsFingerprint = config::TlsFingerprint;
    using QuicEchOptions = config::QuicEchOptions;

    enum class TlsKeyExchange { x25519, x25519_mlkem768, x25519_mlkem768_only };
    struct Reality { std::array<std::uint8_t, 32> public_key{}; std::array<std::uint8_t, 8> short_id{}; };
    struct RealityInbound {
        std::string private_key_file, certificate_file, signing_key_file, fallback_host;
        std::uint16_t fallback_port = 0;
        std::vector<std::string> server_names;
        std::vector<std::array<std::uint8_t, 8>> short_ids;
        std::uint64_t max_time_difference_seconds = 60;
        std::optional<std::size_t> fallback_resolver;
    };
    struct InboundTlsRuntime {
        std::shared_ptr<void> atomic_credential{};
        std::vector<std::string> alpn{};
        std::string ech_key_file{};
    };
    struct MasqueIpOptions {
        bool enabled = false;
        std::string path = "/.well-known/masque/ip/*/*/";
        std::uint16_t mtu = 1280;
        std::optional<std::array<std::uint8_t, 4>> local_v4;
        std::optional<std::array<std::uint8_t, 16>> local_v6;
        std::string protocol = "connect-ip";
        std::vector<std::pair<std::string, std::string>> headers;
    };

    class Server;
    struct Session;
    struct SnellReplayRegistry;
    auto create_snell_replay_registry() -> std::shared_ptr<SnellReplayRegistry>;

    struct ShadowsocksUserKey {
        std::string_view name;
        std::span<std::uint8_t const> key;
    };
    enum class ShadowsocksCipher { aes, chacha20 };

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
    struct MeshNetwork {
        std::optional<std::array<std::uint8_t, 4>> ipv4;
        std::optional<std::array<std::uint8_t, 16>> ipv6;
        std::uint64_t revision;
    };
    struct MeshWorkerBinding {
        std::size_t worker_id = 0;
        std::uint16_t port_begin = 32768;
        std::uint16_t port_end = 60999;
    };
    PRO_DEF_MEM_DISPATCH(MeshLinkNetwork, network);
    PRO_DEF_MEM_DISPATCH(MeshLinkFailed, failed);
    PRO_DEF_MEM_DISPATCH(MeshLinkBindWorker, bind_worker);
    PRO_DEF_MEM_DISPATCH(MeshLinkUnbindWorker, unbind_worker);
    PRO_DEF_MEM_DISPATCH(MeshLinkSend, send);
    PRO_DEF_MEM_DISPATCH(MeshLinkReceive, receive);
    struct MeshLinkFacade : pro::facade_builder
        ::add_convention<MeshLinkNetwork, std::optional<MeshNetwork>() const>
        ::add_convention<MeshLinkFailed, bool() const noexcept>
        ::add_convention<MeshLinkBindWorker, std::optional<MeshWorkerBinding>()>
        ::add_convention<MeshLinkUnbindWorker, void(std::size_t) noexcept>
        ::add_convention<MeshLinkSend, bool(std::size_t, std::uint64_t, std::span<std::uint8_t const>)>
        ::add_convention<MeshLinkReceive, std::optional<std::vector<std::uint8_t>>(std::size_t, std::uint64_t)>
        ::support_copy<pro::constraint_level::nothrow>
        ::build {};
    using MeshLink = pro::proxy<MeshLinkFacade>;
    struct NaiveUserFile { std::string name, username, password_file; };
    enum class Inbound { socks5, mixed, vless, shadowsocks, trojan, anytls, snell, shadowtls, redirect, tproxy, http, fixed_tcp, fixed_udp, naive };
    struct RoutingOnly {};
    enum class RuleFormat { kdl, beve, srs, nxmm, json, domain_list, ipcidr_list, classical, adguard };
    enum class RouteAction { direct, block, vless };
    struct RouteRule { std::string_view data; RuleFormat format; RouteAction action; };
    struct IndexedRouteRule {
        std::string_view data; RuleFormat format; std::size_t outbound; bool ip_cidr_match_source = false;
        std::shared_ptr<rules::MmapMatcher const> mmap{};
    };
    struct OutboundDetour { std::size_t outbound, detour; };
    enum class FailureKind { accept, accept_task, worker, transparent_udp };
    struct RuntimeFailure {
        FailureKind kind;
        std::error_code system_error;
    };
    [[nodiscard]] auto describe(FailureKind kind) noexcept -> std::string_view;

    class TransparentUdp;
    class FixedUdpInbound;
    class TcpAdmission;
}

namespace relay {
    namespace capy = ::capy;
    namespace io = ::corosio;
    using Clock = std::chrono::steady_clock;

    inline auto valid_destination(io::endpoint const& endpoint) noexcept -> bool {
        auto address = endpoint.address();
        if (!endpoint.port() || address.is_unspecified()) return false;
        if (!address.is_v6()) return true;
        auto bytes = address.to_v6().to_bytes();
        bool mapped = std::ranges::all_of(std::span(bytes).first<10>(), [](auto b) { return b == 0; }) &&
                      bytes[10] == 255 && bytes[11] == 255;
        return !mapped || std::ranges::any_of(std::span(bytes).last<4>(), [](auto b) { return b != 0; });
    }

    struct OutboundContext;
    struct Credentials {
        std::array<std::uint8_t, 255> username{}, password{};
        std::uint8_t username_size = 0, password_size = 0;
    };
}
