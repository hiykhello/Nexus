export module provider.types;
import std;

export namespace provider {
    struct SubscriptionUserinfo {
        std::optional<std::uint64_t> upload;
        std::optional<std::uint64_t> download;
        std::optional<std::uint64_t> total;
        std::optional<std::uint64_t> expire;
        auto operator==(SubscriptionUserinfo const&) const -> bool = default;
    };

    enum class ProxyProtocol {
        vless, trojan, shadowsocks, hysteria2, tuic, anytls,
        snell, naive, ssh, socks5, http_connect, wireguard
    };

    enum class ProviderFormat {
        auto_detect, uri_list, base64_uri, clash_yaml, singbox_json, sip008_json
    };

    struct ParsedProxy {
        std::string tag;
        ProxyProtocol protocol = ProxyProtocol::vless;
        std::string host;
        std::uint16_t port = 0;
        std::string username, secret, method;
        std::string sni, ca_file, certificate_sha256, fingerprint;
        std::vector<std::string> alpn;
        bool tls_enabled = true;
        bool skip_cert_verify = false;
        std::string transport, path, host_header, service_name, xhttp_mode, flow;
        std::string reality_public_key, reality_short_id;
        bool udp = true, uot = false;
        std::string obfs, obfs_password;
        std::string hy2_ports;
        std::uint32_t hy2_hop_interval_ms = 0, hy2_up_mbps = 0, hy2_down_mbps = 0;
        std::string congestion_control, udp_relay_mode;
        int snell_version = 5;
        std::string naive_protocol = "h2";
        bool padding = true;
        bool mux_enabled = false;
        std::string mux_protocol = "h2mux";
        std::string detour;
        std::string wg_private_key, wg_peer_public_key, wg_preshared_key;
        std::string wg_local_ipv4, wg_local_ipv6;
        std::uint16_t wg_mtu = 1420;
        std::array<std::uint8_t, 3> wg_reserved{};
    };

    struct ProviderFilter {
        std::string include_regex, exclude_regex, tag_prefix, detour, ca_file;
    };

    struct ParsedGroup {
        std::string name;
        std::string type = "selector";
        std::vector<std::string> members, use_providers;
        std::string probe_url = "https://www.gstatic.com/generate_204";
        std::uint32_t interval_ms = 300000;
        std::uint32_t tolerance_ms = 50;
    };

    struct ParsedRule {
        std::string kind, value, target;
        bool invert = false;
    };

    struct ParsedDocument {
        ProviderFormat detected_format = ProviderFormat::auto_detect;
        std::vector<ParsedProxy> proxies;
        std::vector<ParsedGroup> groups;
        std::vector<ParsedRule> rules;
        std::vector<std::string> dns_servers;
        std::string default_outbound = "direct";
        std::uint16_t inbound_port = 7890;
        std::string inbound_type = "mixed";
        std::vector<std::string> warnings;
    };

    struct ConvertOptions {
        ProviderFormat format = ProviderFormat::auto_detect;
        std::string secrets_dir;
        bool inline_placeholders = false;
        std::string inbound_listen = "127.0.0.1:7890";
        std::string inbound_type = "mixed";
        std::string default_group;
        std::string ca_file;
        ProviderFilter filter;
    };
}
