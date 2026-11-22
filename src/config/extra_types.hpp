// Private extra configuration types included inside export namespace config.
#pragma once

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
    [[nodiscard]] auto parse_tls_fingerprint(std::string_view) noexcept -> std::optional<TlsFingerprint>;
    [[nodiscard]] auto tls_fingerprint_name(TlsFingerprint) noexcept -> std::string_view;

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
        TcpSocketOptions tcp_options;
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
        TcpSocketOptions tcp_options;
        std::optional<bool> tcp_fast_open;
    };
    struct NamedSshOutbound { std::string name; SshOutbound config; };
