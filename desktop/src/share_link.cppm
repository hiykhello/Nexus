export module desktop.share_link;

import std;

export namespace desktop {
    enum class OutboundScheme { vless, trojan, anytls, hysteria2, tuic, snell, shadowsocks, ssh, naive, http_connect };

    struct ParsedOutbound {
        OutboundScheme scheme = OutboundScheme::vless;
        std::string tag;
        std::string host;
        std::uint16_t port = 0;
        std::string secret;
        std::string username;
        std::string method;
        std::string sni;
        std::string fingerprint;
        std::string certificate_sha256;
        std::string flow;
        std::string reality_public_key;
        std::string reality_short_id;
        std::string transport;
        std::string path;
        std::string host_header;
        std::string xhttp_mode;
        int snell_version = 0;
        std::string obfs;
        std::string obfs_host;
        std::string congestion_control;
        std::string udp_relay_mode;
        std::string private_key_file;
        std::string protocol;
        std::string http_version;
        bool padding = true;
        bool udp = false;
    };

    [[nodiscard]] auto parse_share_link(std::string_view uri)
        -> std::expected<ParsedOutbound, std::string>;

    // Renders a Nexus KDL 2.0 outbound block referencing a private 0600 secret file
    // (never embedding plaintext credentials inline in config.kdl).
    [[nodiscard]] auto render_kdl_outbound(ParsedOutbound const& node, std::string_view secret_file_path)
        -> std::string;
}
