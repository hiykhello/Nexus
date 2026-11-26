// Inbound listener socket options and inbound configuration types for config module.
export module config.listen_types;
import std;
import platform.ip_address;
import quic.receive_windows;
import xhttp.config;
import config.extra_types;
import config.tun_types;

export namespace config {
    struct ListenOptions {
        std::string bind_interface;
        std::optional<std::uint32_t> routing_mark;
        std::string netns;
        std::optional<bool> tcp_fast_open;
        std::optional<bool> multipath_tcp;
        std::optional<bool> tcp_keepalive;
        std::optional<std::uint32_t> tcp_keepalive_idle_s;
        std::optional<std::uint32_t> tcp_keepalive_interval_s;
        std::optional<std::uint32_t> tcp_keepalive_count;
        std::optional<bool> reuse_addr;
        std::optional<bool> udp_fragment;
        std::optional<std::uint32_t> udp_timeout_ms;
        std::optional<std::string> detour;
        [[nodiscard]] auto configured() const noexcept -> bool {
            return !bind_interface.empty() || routing_mark.has_value() || !netns.empty() ||
                tcp_fast_open.has_value() || multipath_tcp.has_value() || tcp_keepalive.has_value() ||
                tcp_keepalive_idle_s.has_value() || tcp_keepalive_interval_s.has_value() ||
                tcp_keepalive_count.has_value() || reuse_addr.has_value() || udp_fragment.has_value() ||
                udp_timeout_ms.has_value() || detour.has_value();
        }
        [[nodiscard]] auto valid() const noexcept -> bool {
            if (!bind_interface.empty()) {
                if (bind_interface.size() >= 16 || bind_interface == "." || bind_interface == ".." ||
                    std::ranges::any_of(bind_interface, [](unsigned char c) {
                        return c == '/' || c == ':' || c <= 32 || c == 127;
                    }))
                    return false;
            }
            if (!netns.empty() && (netns.front() != '/' || netns.size() >= 4096 || netns.contains('\0')))
                return false;
            auto secs = [](auto v) { return !v || (*v >= 1 && *v <= 32767); };
            if (!secs(tcp_keepalive_idle_s) || !secs(tcp_keepalive_interval_s) ||
                (tcp_keepalive_count && (*tcp_keepalive_count < 1 || *tcp_keepalive_count > 127)))
                return false;
            if (tcp_keepalive == false && (tcp_keepalive_idle_s || tcp_keepalive_interval_s || tcp_keepalive_count))
                return false;
            if (udp_timeout_ms && (*udp_timeout_ms < 1000 || *udp_timeout_ms > 3600000))
                return false;
            return true;
        }
        auto operator==(ListenOptions const&) const -> bool = default;
    };

    enum class Inbound { socks5, mixed, vless, shadowsocks, trojan, anytls, hysteria2, snell, masque, shadowtls, tuic, tun, redirect, tproxy, http, naive, fixed_tcp, fixed_udp };

    struct FallbackTarget {
        std::string host;
        std::uint16_t port = 0;
        auto operator==(FallbackTarget const&) const -> bool = default;
    };
    struct Hysteria2Masquerade {
        std::string type;
        std::string target;
        std::uint16_t status_code = 200;
        std::vector<std::pair<std::string, std::string>> headers;
        bool rewrite_host = true;
        auto operator==(Hysteria2Masquerade const&) const -> bool = default;
    };
    struct PasswordAuth {
        std::string username;
        std::string password_file;
    };
    struct VlessUser { std::string name; std::string uuid_file; };
    struct HttpUpgradeTransport {
        struct Header { std::string name, value; };
        std::string host, path = "/";
        std::vector<Header> headers;
        bool websocket = false;
        std::uint32_t max_early_data = 0;
        std::string early_data_header_name;
    };
    struct GrpcTransport {
        enum class ResponsePolicy { standard, sing_box_lite };
        std::string service_name, authority;
        ResponsePolicy response_policy = ResponsePolicy::standard;
        std::size_t input_window = 2 * 1024 * 1024, message_bytes = 1024 * 1024 + 64, hunk_bytes = 1024 * 1024;
        std::size_t output_bytes = 2 * 1024 * 1024, output_messages = 64, library_bytes = 4 * 1024 * 1024, max_sessions = 64;
        bool tcp_fast_open = false;
        std::uint32_t idle_timeout_ms = 0, ping_timeout_ms = 0;
        bool permit_without_stream = false;
    };
    struct VlessInbound {
        struct Reality {
            std::string private_key_file, certificate_file, signing_key_file, fallback_host;
            std::uint16_t fallback_port = 0;
            std::vector<std::string> server_names;
            std::vector<std::array<std::uint8_t, 8>> short_ids;
            std::uint64_t max_time_difference_seconds = 60;
            std::optional<std::string> fallback_resolver;
            std::optional<std::size_t> fallback_resolver_index;
        };
        std::vector<VlessUser> users;
        std::string certificate_file, private_key_file;
        bool vision = false;
        std::optional<Reality> reality;
        std::optional<HttpUpgradeTransport> transport;
        std::optional<GrpcTransport> grpc;
        std::optional<xhttp::Profile> xhttp;
        std::optional<InboundMultiplexConfig> multiplex;
        ListenOptions listen{};
        std::string certificate_provider, ech_key_file;
        std::vector<std::string> alpn;
        bool cert_hot_reload = false;
    };
    struct ShadowsocksUser { std::string name, key_file; };
    struct ShadowsocksInbound {
        std::string method, key_file;
        std::vector<ShadowsocksUser> users;
        std::optional<InboundMultiplexConfig> multiplex;
        ListenOptions listen{};
    };
    struct PasswordTlsUser { std::string name, password_file; };
    struct PasswordTlsInbound {
        std::vector<PasswordTlsUser> users;
        std::string certificate_file, private_key_file;
        std::optional<HttpUpgradeTransport> transport;
        std::optional<GrpcTransport> grpc;
        std::optional<InboundMultiplexConfig> multiplex;
        ListenOptions listen{};
        std::string certificate_provider, ech_key_file;
        std::vector<std::string> alpn;
        bool cert_hot_reload = false;
        std::optional<FallbackTarget> fallback;
        std::vector<std::pair<std::string, FallbackTarget>> fallback_for_alpn;
    };
    using TrojanUser = PasswordTlsUser;
    using TrojanInbound = PasswordTlsInbound;
    using AnyTlsInbound = PasswordTlsInbound;
    struct SnellInbound {
        std::string psk_file;
        bool http_obfs = false;
        std::optional<std::string> user_file;
        std::uint32_t replay_window_seconds = 0;
        std::string listen_host;
        std::array<std::uint8_t, 16> listen_address{};
        ListenOptions listen{};
    };
    struct Hysteria2Transport {
        std::uint32_t handshake_timeout_ms = 10000, idle_timeout_ms = 300000;
        std::size_t native_bytes = 8 * 1024 * 1024;
        bool udp = true;
        std::optional<std::string> salamander_password_file;
        std::optional<std::size_t> max_udp_payload_size;
        bool disable_path_mtu_discovery = false;
        std::uint64_t send_bps = 0, receive_bps = 0;
        bool ignore_client_bandwidth = false, disable_compensation = false, lazy_tcp_response = false;
        quic::ReceiveWindows receive_windows;
        std::vector<PortRange> port_ranges;
        std::uint32_t hop_interval_ms = 0, hop_interval_max_ms = 0;
    };
    struct Hysteria2Inbound {
        PasswordTlsInbound connection;
        Hysteria2Transport transport;
        std::string listen_host;
        std::array<std::uint8_t, 16> listen_address{};
        ListenOptions listen{};
        std::string certificate_provider, ech_key_file;
        std::vector<std::string> alpn;
        bool cert_hot_reload = false;
        Hysteria2Masquerade masquerade{};
    };
    struct MasqueDestination {
        std::array<std::uint8_t, 16> network{};
        std::uint8_t family = 0, prefix = 0;
        std::uint16_t first_port = 0, last_port = 0;
    };
    struct MasqueIpInbound {
        std::string interface;
        std::vector<std::string> local_addresses, client_addresses, allowed_routes;
    };
    struct MasqueInbound {
        std::string listen_host, authority, certificate_file, private_key_file, bearer_file;
        std::array<std::uint8_t, 16> listen_address{};
        std::vector<MasqueDestination> destinations;
        std::uint32_t dns_timeout_ms = 5000;
        std::size_t native_bytes = 8 * 1024 * 1024;
        std::optional<MasqueIpInbound> ip;
        ListenOptions listen{};
        std::string certificate_provider, ech_key_file;
        std::vector<std::string> alpn;
        bool cert_hot_reload = false;
    };
    struct ShadowTlsInbound {
        std::string handshake_host;
        std::uint16_t handshake_port = 0;
        std::string target_host;
        std::uint16_t target_port = 0;
        std::vector<PasswordAuth> users;
        bool strict_tls13 = true;
        std::array<std::uint8_t, 16> listen_address{};
        ListenOptions listen{};
        std::vector<std::pair<std::string, FallbackTarget>> handshake_for_server_name;
        std::string wildcard_sni;
    };
    struct TuicUser { std::string name, uuid_file, password_file; };
    struct TuicInbound {
        std::string listen_host, certificate_file, private_key_file;
        std::array<std::uint8_t, 16> listen_address{};
        std::vector<TuicUser> users;
        std::string congestion_control = "cubic";
        std::uint32_t handshake_timeout_ms = 10000, idle_timeout_ms = 60000;
        std::size_t native_bytes = 8 * 1024 * 1024;
        bool udp = true;
        ListenOptions listen{};
        std::string certificate_provider, ech_key_file;
        std::vector<std::string> alpn;
        bool cert_hot_reload = false;
        bool zero_rtt_handshake = false;
    };
    struct FixedUdpInbound {
        std::string listen_host, target_host;
        std::array<std::uint8_t, 16> listen_address{};
        std::uint16_t target_port = 0;
        std::uint32_t idle_timeout_ms = 60000;
        ListenOptions listen{};
    };
    struct HttpInbound {
        bool has_tls = false, http2 = true, http3 = false, connect_udp = false;
        std::string listen_host, certificate_file, private_key_file;
        std::array<std::uint8_t, 16> listen_address{};
        std::uint32_t handshake_timeout_ms = 10000, idle_timeout_ms = 60000;
        std::size_t native_bytes = 8 * 1024 * 1024;
        ListenOptions listen{};
        std::string certificate_provider, ech_key_file;
        std::vector<std::string> alpn;
        bool cert_hot_reload = false;
    };
    struct NaiveInbound {
        std::string listen_host, certificate_file, private_key_file;
        std::array<std::uint8_t, 16> listen_address{};
        std::vector<NaiveUser> users;
        NaiveProtocol protocol = NaiveProtocol::h2;
        bool padding = true;
        std::uint16_t fallback_status = 404;
        std::uint32_t handshake_timeout_ms = 10000, idle_timeout_ms = 60000;
        std::size_t native_bytes = 8 * 1024 * 1024;
        ListenOptions listen{};
        std::string certificate_provider, ech_key_file;
        std::vector<std::string> alpn;
        bool cert_hot_reload = false;
    };
    struct UserLimits {
        std::string name;
        std::optional<std::size_t> connections, streams;
        std::optional<std::uint64_t> byte_quota;
        std::optional<std::uint32_t> bytes_per_second, burst_bytes;
    };
    struct FixedTcpTarget { std::string host; std::uint16_t port; std::string unix_path; };
    struct InboundConfig {
        std::string name;
        std::uint16_t port;
        Inbound type;
        std::optional<PasswordAuth> password_auth;
        std::optional<VlessInbound> vless;
        std::optional<ShadowsocksInbound> shadowsocks;
        bool listen_ipv6 = false;
        std::optional<TrojanInbound> trojan;
        std::optional<AnyTlsInbound> anytls;
        std::optional<Hysteria2Inbound> hysteria2;
        std::optional<SnellInbound> snell;
        std::optional<MasqueInbound> masque;
        std::optional<ShadowTlsInbound> shadowtls;
        std::optional<TuicInbound> tuic;
        std::optional<TunInbound> tun;
        std::optional<std::array<std::uint8_t, 16>> redirect_address{}, listen_address{};
        std::string redirect_host{}, listen_host{};
        bool transparent_udp = false;
        std::vector<UserLimits> user_limits;
        std::optional<FixedTcpTarget> fixed_tcp;
        std::optional<FixedUdpInbound> fixed_udp;
        std::string unix_path;
        std::optional<platform::IpAddress> udp_advertise_ip;
        std::optional<NaiveInbound> naive;
        std::optional<HttpInbound> http;
        ListenOptions listen{};
        std::optional<std::size_t> detour_index;
    };
}
