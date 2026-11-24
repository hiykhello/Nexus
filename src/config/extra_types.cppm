// Extra inbound/outbound/TLS configuration types for config module.
export module config.extra_types;
import std;
import platform.socket_options;
import rules;
export import config.service_types;
export import config.provider_types;

export namespace config {
    struct CertificateConfig {
        std::string ca_file;
        bool system_store = false;
    };

    struct NtpConfig {
        std::string host;
        std::uint16_t port = 123;
        std::uint32_t interval_ms = 1800000;
        std::uint32_t timeout_ms = 5000;
    };

    struct FixedUdpInbound {
        std::string listen_host, target_host;
        std::array<std::uint8_t, 16> listen_address{};
        std::uint16_t target_port = 0;
        std::uint32_t idle_timeout_ms = 60000;
    };

    struct PortRange {
        std::uint16_t first = 0, last = 0;
        auto operator==(PortRange const&) const -> bool = default;
    };

    enum class TlsKeyExchange { x25519, x25519_mlkem768, x25519_mlkem768_only };
    enum class TlsFingerprint : std::uint8_t {
        native, tls13_grease, tls13_randomized,
        chrome, firefox, safari, ios, android, edge, random, tls12
    };
    namespace detail {
        struct FingerprintEntry { std::string_view name; TlsFingerprint value; };
        inline constexpr auto fingerprint_table = std::to_array<FingerprintEntry>({
            {"native", TlsFingerprint::native},
            {"tls13-grease", TlsFingerprint::tls13_grease},
            {"tls13-randomized", TlsFingerprint::tls13_randomized},
            {"chrome", TlsFingerprint::chrome},
            {"chrome-133", TlsFingerprint::chrome},
            {"firefox", TlsFingerprint::firefox},
            {"firefox-135", TlsFingerprint::firefox},
            {"safari", TlsFingerprint::safari},
            {"safari-18", TlsFingerprint::safari},
            {"ios", TlsFingerprint::ios},
            {"android", TlsFingerprint::android},
            {"edge", TlsFingerprint::edge},
            {"random", TlsFingerprint::random},
            {"tls12", TlsFingerprint::tls12},
        });
    }
    [[nodiscard]] inline auto parse_tls_fingerprint(std::string_view value) noexcept -> std::optional<TlsFingerprint> {
        for (auto const& entry : detail::fingerprint_table) if (entry.name == value) return entry.value;
        return std::nullopt;
    }
    [[nodiscard]] inline auto tls_fingerprint_name(TlsFingerprint value) noexcept -> std::string_view {
        for (auto const& entry : detail::fingerprint_table) if (entry.value == value) return entry.name;
        return {};
    }

    enum class NaiveProtocol : std::uint8_t { h2, h3, both };
    enum class HttpProxyVersion : std::uint8_t { h1, auto_h2, h2, h3 };

    struct HttpInbound {
        bool has_tls = false, http2 = true, http3 = false, connect_udp = false;
        std::string listen_host, certificate_file, private_key_file;
        std::array<std::uint8_t, 16> listen_address{};
        std::uint32_t handshake_timeout_ms = 10000, idle_timeout_ms = 60000;
        std::size_t native_bytes = 8 * 1024 * 1024;
    };

    struct NaiveUser {
        std::string name, username, password_file;
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
    };

    struct NaiveOutbound {
        NaiveProtocol protocol = NaiveProtocol::h2;
        std::string host;
        std::uint16_t port = 443;
        std::string username, password_file;
        std::string server_name, ca_file;
        std::vector<std::array<std::uint8_t, 32>> certificate_sha256;
        TlsKeyExchange key_exchange = TlsKeyExchange::x25519;
        TlsFingerprint fingerprint = TlsFingerprint::native;
        bool padding = true;
        std::vector<std::pair<std::string, std::string>> extra_headers;
        std::size_t max_sessions = 8;
        std::uint32_t connect_timeout_ms = 10000, handshake_timeout_ms = 10000, idle_timeout_ms = 60000;
        std::size_t native_bytes = 8 * 1024 * 1024;
        std::optional<std::string> bootstrap_resolver, detour;
        std::optional<std::size_t> bootstrap_index, detour_index;
        platform::TcpSocketOptions tcp_options;
        std::optional<bool> tcp_fast_open;
    };
    struct NamedNaiveOutbound { std::string name; NaiveOutbound config; };

    struct SshOutbound {
        std::string host;
        std::uint16_t port = 22;
        std::string user;
        std::optional<std::string> password_file, private_key_file;
        std::vector<std::array<std::uint8_t, 32>> host_key_sha256;
        std::string cipher;
        std::optional<std::string> bootstrap_resolver, detour;
        std::optional<std::size_t> bootstrap_index, detour_index;
        std::uint32_t connect_timeout_ms = 10000, keepalive_interval_ms = 30000;
        std::size_t max_sessions = 16;
        platform::TcpSocketOptions tcp_options;
        std::optional<bool> tcp_fast_open;
    };
    struct NamedSshOutbound { std::string name; SshOutbound config; };

    enum class MultiplexProtocol : std::uint8_t { smux, smux_v1, smux_v2 };
    struct MultiplexConfig {
        bool enabled = false;
        MultiplexProtocol protocol = MultiplexProtocol::smux_v2;
        std::uint32_t max_connections = 4;
        std::uint32_t min_streams = 4;
        std::uint32_t max_streams = 16;
        bool padding = false;
        bool only_tcp = false;
        auto operator==(MultiplexConfig const&) const -> bool = default;
    };
    struct InboundMultiplexConfig {
        bool enabled = false;
        bool padding = false;
        std::uint32_t max_streams = 64;
        auto operator==(InboundMultiplexConfig const&) const -> bool = default;
    };

    enum class OpenVpnTransport : std::uint8_t { udp, tcp };
    enum class OpenVpnCipher : std::uint8_t { aes_256_gcm, chacha20_poly1305 };

    struct OpenVpnOutbound {
        OpenVpnTransport transport = OpenVpnTransport::udp;
        OpenVpnCipher cipher = OpenVpnCipher::aes_256_gcm;
        std::string host;
        std::uint16_t port = 1194;
        std::string server_name, ca_file;
        std::vector<std::array<std::uint8_t, 32>> certificate_sha256;
        TlsKeyExchange key_exchange = TlsKeyExchange::x25519;
        TlsFingerprint fingerprint = TlsFingerprint::native;
        std::string username;
        std::optional<std::string> password_file, static_key_file;
        bool has_v4 = true;
        std::array<std::uint8_t, 4> local_v4{10, 8, 0, 2};
        bool has_v6 = false;
        std::array<std::uint8_t, 16> local_v6{};
        std::uint16_t mtu = 1400, keepalive_s = 10;
        std::optional<std::string> bootstrap_resolver, detour;
        std::optional<std::size_t> bootstrap_index, detour_index;
        std::uint32_t connect_timeout_ms = 10000;
        platform::TcpSocketOptions tcp_options;
    };
    struct NamedOpenVpnOutbound { std::string name; OpenVpnOutbound config; };

    struct OpenConnectOutbound {
        std::string host;
        std::uint16_t port = 443;
        std::string server_name, ca_file;
        std::vector<std::array<std::uint8_t, 32>> certificate_sha256;
        TlsKeyExchange key_exchange = TlsKeyExchange::x25519;
        TlsFingerprint fingerprint = TlsFingerprint::native;
        std::string username, group, user_agent{"AnyConnect Linux_64 5.0"};
        std::optional<std::string> password_file, cookie_file;
        bool has_v4 = true;
        std::array<std::uint8_t, 4> local_v4{10, 99, 0, 2};
        bool has_v6 = false;
        std::array<std::uint8_t, 16> local_v6{};
        std::uint16_t mtu = 1400, dpd_s = 30, keepalive_s = 20;
        std::optional<std::string> bootstrap_resolver, detour;
        std::optional<std::size_t> bootstrap_index, detour_index;
        std::uint32_t connect_timeout_ms = 10000;
        platform::TcpSocketOptions tcp_options;
    };
    struct NamedOpenConnectOutbound { std::string name; OpenConnectOutbound config; };

    struct TunUidRange {
        std::uint32_t min = 0, max = 0;
        auto operator==(TunUidRange const&) const -> bool = default;
    };

    struct TunInboundExtra {
        std::optional<std::uint32_t> auto_redirect_input_mark, auto_redirect_output_mark, auto_redirect_reset_mark;
        std::vector<TunUidRange> include_uids, exclude_uids;
        std::vector<std::uint32_t> include_android_users;
        std::vector<std::string> include_interfaces, exclude_interfaces;
        bool device_fd_skip_ioctl = false, bridge_mode = false;
    };

    struct OrderedTcpActionExtra {
        std::optional<rules::DnsRuleStrategy> resolve_strategy{};
        std::optional<std::string> resolve_server_name{};
        std::optional<std::size_t> resolve_server{};
        std::optional<bool> resolve_disable_cache{};
        std::optional<std::uint32_t> resolve_rewrite_ttl{};
        std::optional<rules::SubnetPrefix> resolve_client_subnet{};
        std::uint32_t sniff_protocols = 0;
        bool sniff_override_destination = false;
        std::uint32_t sniff_timeout_ms = 0;
        bool udp_disable_domain_unmapping = false;
    };
}
