// Optional service configuration types for config module.
export module config.service_types;
import std;

export namespace config {
    struct MemoryWatchdogConfig {
        std::uint64_t soft_mb = 64;
        std::uint64_t hard_mb = 88;
        std::uint64_t emergency_mb = 104;
        std::uint32_t cooldown_ms = 5000;
        auto operator==(MemoryWatchdogConfig const&) const -> bool = default;
    };

    struct SsmApiConfig {
        bool enabled = false;
        std::string prefix = "/ssmapi";
        auto operator==(SsmApiConfig const&) const -> bool = default;
    };

    struct SniDemuxRuleConfig {
        std::string host_pattern;
        std::string required_alpn;
        std::string role = "proxy";
        std::string target_upstream;
        auto operator==(SniDemuxRuleConfig const&) const -> bool = default;
    };

    struct SniDemuxConfig {
        std::string listen_host = "127.0.0.1";
        std::uint16_t listen_port = 443;
        std::string fallback_upstream = "127.0.0.1:8443";
        std::vector<SniDemuxRuleConfig> rules;
        auto operator==(SniDemuxConfig const&) const -> bool = default;
    };

    struct AcmeServiceConfig {
        std::string directory_url;
        std::vector<std::string> domains;
        std::string email;
        std::string challenge = "http-01";
        std::string state_dir;
        std::int64_t renew_before_seconds = 30 * 24 * 3600;
        std::string http_listen_host = "127.0.0.1";
        std::uint16_t http_listen_port = 0;
        std::string tls_alpn_listen_host = "127.0.0.1";
        std::uint16_t tls_alpn_listen_port = 0;
        std::string ca_file;
        std::uint32_t check_interval_ms = 3600000;
        auto operator==(AcmeServiceConfig const&) const -> bool = default;
    };

    struct ReverseTunnelServiceConfig {
        std::string token;
        std::size_t max_streams = 256;
        std::uint32_t heartbeat_timeout_ms = 30000;
        std::string mode = "server";
        std::string control_host = "127.0.0.1";
        std::uint16_t control_port = 0;
        std::string expose_host = "127.0.0.1";
        std::uint16_t expose_port = 0;
        std::string target_host = "127.0.0.1";
        std::uint16_t target_port = 0;
        auto operator==(ReverseTunnelServiceConfig const&) const -> bool = default;
    };

    struct BridgeServiceConfig {
        std::string tun_interface = "nexus-tun0";
        std::string physical_interface = "eth0";
        std::uint16_t mtu = 1500;
        bool allow_ipv4 = true;
        bool allow_ipv6 = true;
        bool drop_link_local = true;
        auto operator==(BridgeServiceConfig const&) const -> bool = default;
    };

    struct TorServiceConfig {
        std::string socks_host = "127.0.0.1";
        std::uint16_t socks_port = 9050;
        std::string control_host = "127.0.0.1";
        std::uint16_t control_port = 9051;
        std::string control_password;
        std::string cookie_hex;
        bool isolate_streams = true;
        bool allow_remote_socks = false;
        auto operator==(TorServiceConfig const&) const -> bool = default;
    };

    struct DerpServerServiceConfig {
        std::size_t max_peers = 1024;
        std::string listen_host = "127.0.0.1";
        std::uint16_t listen_port = 0;
        std::string cert_file;
        std::string key_file;
        auto operator==(DerpServerServiceConfig const&) const -> bool = default;
    };

    struct ServicesConfig {
        std::optional<MemoryWatchdogConfig> memory_watchdog;
        std::optional<SsmApiConfig> ssmapi;
        std::optional<SniDemuxConfig> sni_demux;
        std::optional<AcmeServiceConfig> acme;
        std::optional<ReverseTunnelServiceConfig> reverse_tunnel;
        std::optional<BridgeServiceConfig> bridge;
        std::optional<TorServiceConfig> tor;
        std::optional<DerpServerServiceConfig> derp_server;
        auto operator==(ServicesConfig const&) const -> bool = default;

        [[nodiscard]] auto any_configured() const noexcept -> bool {
            return memory_watchdog || (ssmapi && ssmapi->enabled) || sni_demux ||
                   acme || reverse_tunnel || bridge || tor || derp_server;
        }
    };
}
