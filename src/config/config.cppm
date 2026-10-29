export module nexus.config;
import std;

export namespace nexus::config {
    enum class Inbound { socks5, mixed, vless, shadowsocks };
    enum class RuleFormat { kdl, beve };
    enum class RouteAction { direct, block, vless };
    struct BlockRules {
        std::string path;
        RuleFormat format;
    };
    struct RouteRule { BlockRules file; RouteAction action; std::size_t outbound = 0; };
    struct PasswordAuth {
        std::string username;
        std::string password_file;
    };
    struct VlessUser { std::string name; std::string uuid_file; };
    struct VlessInbound { std::vector<VlessUser> users; std::string certificate_file, private_key_file; };
    struct ShadowsocksInbound { std::string method, key_file; };
    struct InboundConfig {
        std::string name;
        std::uint16_t port;
        Inbound type;
        std::optional<PasswordAuth> password_auth;
        std::optional<VlessInbound> vless;
        std::optional<ShadowsocksInbound> shadowsocks;
        bool listen_ipv6 = false;
    };
    enum class TlsKeyExchange { x25519, x25519_mlkem768, x25519_mlkem768_only };
    struct VlessOutbound {
        std::string host;
        std::uint16_t port = 0;
        std::string uuid_file;
        std::string server_name;
        std::string ca_file;
        TlsKeyExchange key_exchange = TlsKeyExchange::x25519;
        std::optional<std::string> bootstrap_resolver;
        std::optional<std::size_t> bootstrap_index;
    };
    struct NamedVlessOutbound { std::string name; VlessOutbound config; };
    struct ShadowsocksOutbound {
        std::string host; std::uint16_t port = 0; std::string method, key_file;
        std::optional<std::string> bootstrap_resolver;
        std::optional<std::size_t> bootstrap_index;
    };
    struct NamedShadowsocksOutbound { std::string name; ShadowsocksOutbound config; };
    struct DnsUpstream {
        std::array<std::uint8_t,16> address{};
        bool ipv6 = false;
        std::uint16_t port = 0;
        bool tcp = false;
        std::string host;
        std::optional<std::size_t> resolver;
    };
    struct DnsServer { std::string name; std::optional<DnsUpstream> upstream; };
    struct DnsRule { std::string domain; bool suffix; std::size_t server; };
    enum class DnsStrategy { automatic, prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only };
    struct DnsRouting {
        std::vector<DnsServer> servers;
        std::vector<DnsRule> rules;
        std::size_t final;
        DnsStrategy strategy = DnsStrategy::automatic;
        bool disable_cache = false;
        bool edns = false;
    };
    struct Config {
        std::uint16_t port = 0;
        bool listen_ipv6 = false;
        std::vector<InboundConfig> inbounds;
        unsigned workers = 1;
        Inbound inbound = Inbound::socks5;
        std::optional<BlockRules> block_rules;
        std::vector<RouteRule> routes;
        RouteAction rule_action = RouteAction::block;
        RouteAction default_action = RouteAction::direct;
        std::size_t default_outbound = 0;
        std::optional<PasswordAuth> password_auth;
        std::optional<VlessInbound> vless_inbound;
        std::optional<ShadowsocksInbound> shadowsocks_inbound;
        std::optional<VlessOutbound> vless;
        std::vector<NamedVlessOutbound> vless_outbounds;
        std::vector<NamedShadowsocksOutbound> shadowsocks_outbounds;
        std::optional<DnsUpstream> dns_upstream;
        std::optional<DnsRouting> dns;
    };
    inline constexpr std::size_t max_config_bytes = 1048576;
    [[nodiscard]] auto parse_kdl(std::string_view input) -> std::expected<Config, std::string>;
}
