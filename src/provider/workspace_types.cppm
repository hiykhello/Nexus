// Layer 1 portable workspace & Layer 3 host adapter canonical v1 schema types.
export module provider.workspace_types;
import std;

export namespace provider {
    struct WorkspaceTls {
        bool enabled = true;
        std::string sni;
        std::string fingerprint;
        std::string key_exchange;
        std::string ca_pem;
        std::vector<std::string> cert_sha256;
        std::string reality_public_key;
        std::string reality_short_id;
        std::string ech_mode;
        std::string ech_config;
    };

    struct WorkspaceTransport {
        std::string type;
        std::string host;
        std::string path;
        std::string service_name;
        std::string authority;
        std::string xhttp_mode;
        std::string xhttp_protocol;
        std::map<std::string, std::string> headers;
    };

    struct WorkspaceMultiplex {
        bool enabled = false;
        std::string protocol = "smux-v2";
        std::uint32_t max_connections = 0;
        bool padding = false;
    };

    struct WorkspaceNodeExtra {
        std::string hy2_ports;
        std::uint32_t hy2_hop_interval_ms = 0;
        std::uint32_t hy2_up_mbps = 0;
        std::uint32_t hy2_down_mbps = 0;
        std::string hy2_salamander_password;
        std::string tuic_congestion_control;
        bool tuic_udp_over_stream = false;
        std::string wg_peer_public_key;
        std::string wg_preshared_key;
        std::vector<std::string> wg_local_addresses;
        std::string wg_reserved;
        std::uint16_t wg_mtu = 1420;
        std::string masque_mode;
        std::string masque_path;
        std::vector<std::string> masque_local_addresses;
        std::string naive_protocol;
        int snell_version = 5;
        std::string snell_obfs;
        std::string snell_obfs_host;
        std::vector<std::string> ssh_host_key_sha256;
    };

    struct WorkspaceNode {
        std::string protocol;
        std::string server;
        std::uint16_t port = 0;
        std::string username;
        std::string password;
        std::string method;
        std::string flow;
        std::string packet_encoding;
        WorkspaceTls tls{};
        WorkspaceTransport transport{};
        WorkspaceMultiplex multiplex{};
        WorkspaceNodeExtra extra{};
    };

    struct WorkspacePolicyGroup {
        std::string strategy = "selector";
        std::vector<std::string> member_ids;
        std::string dynamic_sub_id;
        std::string include_regex;
        std::string exclude_regex;
        std::string probe_url = "https://www.gstatic.com/generate_204";
        std::uint32_t probe_interval_ms = 300000;
        std::uint32_t tolerance_ms = 50;
    };

    struct WorkspaceProxyChain {
        std::vector<std::string> hop_ids;
    };

    struct WorkspaceProfile {
        std::string id;
        std::string remarks;
        std::string subscription_id;
        bool is_from_sub = false;
        std::string kind = "node";
        WorkspaceNode node{};
        std::string custom_outbound_kdl;
        WorkspacePolicyGroup policy_group{};
        WorkspaceProxyChain proxy_chain{};
        std::string full_custom_kdl;
    };

    struct WorkspaceSubUsage {
        std::int64_t upload_bytes = 0;
        std::int64_t download_bytes = 0;
        std::int64_t total_bytes = 0;
        std::int64_t expire_unix_sec = 0;
        std::string profile_title;
        std::string web_page_url;
        std::string support_url;
    };

    struct WorkspaceSubscription {
        std::string id;
        std::string remarks;
        std::string url;
        std::vector<std::string> more_urls;
        bool enabled = true;
        std::uint32_t auto_update_minutes = 0;
        std::string user_agent;
        std::map<std::string, std::string> request_headers;
        std::string include_regex;
        std::string exclude_regex;
        std::string prev_profile_id;
        std::string next_profile_id;
        std::int64_t updated_at_ms = 0;
        WorkspaceSubUsage usage{};
    };

    struct WorkspaceRoutingRule {
        std::string id;
        bool enabled = true;
        bool locked = false;
        std::string scope = "both";
        std::string target_type = "proxy";
        std::string target_profile_id;
        std::vector<std::string> domains;
        std::vector<std::string> ips;
        std::vector<std::string> rule_sets;
        std::vector<std::string> ports;
        std::vector<std::string> networks;
        std::vector<std::string> protocols;
        std::vector<std::string> desktop_process;
        std::vector<std::string> android_packages;
        bool tls_fragment = false;
    };

    struct WorkspaceRoutingProfile {
        std::string id;
        std::string name;
        bool is_active = false;
        std::string domain_strategy = "as-is";
        std::string default_outbound = "proxy";
        std::vector<WorkspaceRoutingRule> rules;
    };

    struct WorkspaceSimpleDns {
        std::string bootstrap_dns;
        std::vector<std::string> direct_dns;
        std::vector<std::string> remote_dns;
        bool parallel_query = false;
        std::vector<std::string> direct_expected_rule_sets;
        bool fake_ip_enabled = false;
        std::string fake_ip_v4_pool = "198.18.0.0/16";
        std::string fake_ip_v6_pool = "fc00::/18";
        bool fake_ip_global = false;
        bool block_aaaa = false;
        bool block_svcb_https = false;
        std::uint32_t serve_stale_seconds = 0;
        bool use_system_hosts = false;
        std::map<std::string, std::variant<std::string, std::vector<std::string>>> hosts;
        std::string strategy = "prefer_ipv4";
    };

    struct WorkspaceDns {
        std::string mode = "simple";
        WorkspaceSimpleDns simple{};
        std::string raw_kdl;
    };

    struct WorkspaceRuleSetAsset {
        std::string tag;
        std::string source_type = "local";
        std::string format = "nxmm";
        std::string path;
        std::string url;
        std::string sha256;
        std::uint32_t update_interval_ms = 3600000;
    };

    struct WorkspaceFullTemplate {
        bool enabled = false;
        std::string template_kdl;
        bool append_proxies_only = false;
        std::string proxy_detour;
    };

    struct Workspace {
        int schema_version = 1;
        std::int64_t revision = 0;
        std::int64_t updated_at_ms = 0;
        std::vector<WorkspaceProfile> profiles;
        std::vector<WorkspaceSubscription> subscriptions;
        std::vector<WorkspaceRoutingProfile> routing_profiles;
        WorkspaceDns dns{};
        std::vector<WorkspaceRuleSetAsset> rule_set_assets;
        WorkspaceFullTemplate full_template{};
    };

    struct DesktopHostConfig {
        bool enable_mixed = true;
        std::string mixed_listen = "127.0.0.1:7890";
        std::string second_local_listen;
        std::string lan_listen;
        std::string lan_username;
        std::string lan_password;
        bool enable_tun = false;
        std::string tun_interface_name = "nexus-tun";
        std::uint16_t tun_mtu = 1500;
        std::string tun_inet4 = "198.18.0.1/30";
        std::string tun_inet6;
        bool tun_auto_route = true;
        bool tun_strict_route = false;
        std::vector<std::string> tun_route_exclude;
        bool tun_route_exclude_private = true;
        std::string bind_interface;
        std::string inet4_bind_address;
        std::string inet6_bind_address;
    };

    struct AndroidHostConfig {
        std::string run_mode = "vpn";
        bool enable_local_proxy = false;
        std::string local_listen = "127.0.0.1:7890";
        bool dynamic_local_port = false;
        std::uint16_t tun_mtu = 1500;
        bool tun_fd_from_env = true;
        std::string protect_socket_path;
        std::string dns_bridge_socket_path;
        std::string dns_listen;
    };

    struct HostConfig {
        int schema_version = 1;
        std::string platform = "desktop-linux";
        std::string log_level = "info";
        std::string log_file;
        unsigned workers = 1;
        std::string workers_spec;
        unsigned workers_max = 0;
        std::string state_dir;
        std::string cache_dir;
        std::string control_socket;
        std::string control_http_listen;
        std::string control_bearer_file;
        std::string ca_file;
        bool include_sibling_nodes_in_selector = true;
        std::uint32_t max_selector_members = 128;
        DesktopHostConfig desktop{};
        AndroidHostConfig android{};
    };

    struct WorkspaceComposeOptions {
        std::string secrets_dir;
        std::string active_profile_id;
    };

    struct WorkspaceComposeResult {
        bool ok = false;
        std::string active_tag;
        std::string selector_tag;
        std::vector<std::string> selector_members;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::vector<std::string> secret_files;
        std::string kdl;
    };

    struct WorkspaceShareExportResult {
        bool ok = false;
        std::string uri;
        std::size_t exported_count = 0;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };

    struct WorkspaceShareImportResult {
        bool ok = false;
        std::vector<std::string> imported_ids;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::string workspace_json;
    };

    struct WorkspaceSyncSealResult {
        bool ok = false;
        std::int64_t revision = 0;
        std::int64_t updated_at_ms = 0;
        std::string envelope_sha256;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::string envelope_json;
    };

    struct WorkspaceSyncOpenResult {
        bool ok = false;
        std::int64_t revision = 0;
        std::int64_t updated_at_ms = 0;
        std::string device_label;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::string workspace_json;
    };
}
