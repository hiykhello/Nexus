export module desktop.workspace_models;

import std;

export namespace desktop {
    struct TlsConfig {
        bool enabled = false;
        std::string sni;
        std::string fingerprint;
        std::string key_exchange;
        std::string ca_pem;
        std::vector<std::string> cert_sha256;
        std::string reality_public_key;
        std::string reality_short_id;
        std::string ech_mode;
        std::string ech_config;
        std::string ech_query_server_name;
        bool fragment = false;
        bool record_fragment = false;
    };

    struct TransportConfig {
        std::string type;
        std::string host;
        std::string path;
        std::string service_name;
        std::string authority;
        std::string xhttp_mode;
        std::string xhttp_protocol;
        std::vector<std::pair<std::string, std::string>> headers;
        std::int64_t max_early_data = 0;
        std::string early_data_header_name;
        std::int64_t grpc_idle_timeout_ms = 0;
        std::int64_t grpc_ping_timeout_ms = 0;
        bool grpc_permit_without_stream = false;
    };

    struct MultiplexConfig {
        bool enabled = false;
        std::string protocol;
        std::int64_t max_connections = 0;
        std::int64_t min_streams = 0;
        bool padding = false;
    };

    struct NodeExtraConfig {
        std::string hy2_ports;
        std::int64_t hy2_hop_interval_ms = 0;
        std::int64_t hy2_up_mbps = 0;
        std::int64_t hy2_down_mbps = 0;
        std::string hy2_salamander_password;
        std::string tuic_congestion_control;
        bool tuic_udp_over_stream = false;
        std::string wg_peer_public_key;
        std::string wg_preshared_key;
        std::vector<std::string> wg_local_addresses;
        std::string wg_reserved;
        std::int64_t wg_mtu = 0;
        std::string masque_mode;
        std::string masque_path;
        std::vector<std::string> masque_local_addresses;
        std::string naive_protocol;
        std::int64_t snell_version = 0;
        std::string snell_obfs;
        std::string snell_obfs_host;
        std::vector<std::string> ssh_host_key_sha256;
    };

    struct NodeConfig {
        std::string protocol;
        std::string server;
        std::int64_t port = 443;
        std::string username;
        std::string password;
        std::string method;
        std::string flow;
        std::string packet_encoding;
        TlsConfig tls;
        TransportConfig transport;
        MultiplexConfig multiplex;
        NodeExtraConfig extra;
    };

    struct PolicyGroupConfig {
        std::string strategy = "selector"; // "selector" | "url-test" | "fallback" | "load-balance"
        std::vector<std::string> member_ids;
        std::string dynamic_sub_id;
        std::string include_regex;
        std::string exclude_regex;
        std::string probe_url = "https://www.gstatic.com/generate_204";
        std::int64_t probe_interval_ms = 300000;
        std::int64_t tolerance_ms = 100;
        bool interrupt_exist_connections = false;
    };

    struct ProxyChainConfig {
        std::vector<std::string> hop_ids;
    };

    // Polymorphic 5-kind ProfileItem: "node" | "custom_outbound" | "policy_group" | "proxy_chain" | "full_custom_kdl"
    struct WorkspaceProfileItem {
        std::string id;
        std::string remarks;
        std::string subscription_id;
        bool is_from_sub = false;
        std::string kind = "node";
        NodeConfig node;
        std::string custom_outbound_kdl;
        PolicyGroupConfig policy_group;
        ProxyChainConfig proxy_chain;
        std::string full_custom_kdl;
    };

    struct SubscriptionUsage {
        std::int64_t upload_bytes = 0;
        std::int64_t download_bytes = 0;
        std::int64_t total_bytes = 0;
        std::int64_t expire_unix_sec = 0;
        std::string profile_title;
        std::string web_page_url;
        std::string support_url;
    };

    struct SubscriptionItem {
        std::string id;
        std::string remarks;
        std::string url;
        std::vector<std::string> more_urls;
        bool enabled = true;
        std::int64_t auto_update_minutes = 0;
        std::string user_agent;
        std::vector<std::pair<std::string, std::string>> request_headers;
        std::string include_regex;
        std::string exclude_regex;
        std::string prev_profile_id;
        std::string next_profile_id;
        std::int64_t updated_at_ms = 0;
        SubscriptionUsage usage;
    };

    struct RoutingRule {
        std::string id;
        bool enabled = true;
        bool locked = false;
        std::string scope = "both"; // "both" | "routing_only" | "dns_only"
        std::string target_type = "proxy"; // "proxy" | "direct" | "block" | "profile_id"
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

    struct RoutingProfile {
        std::string id;
        std::string name;
        bool is_active = false;
        std::string domain_strategy = "as-is"; // "as-is" | "ip-if-non-match" | "ip-on-demand"
        std::string default_outbound = "proxy"; // "proxy" | "direct" | "block"
        bool auto_detect_interface = false;
        bool find_process = false;
        std::vector<RoutingRule> rules;
    };

    struct SimpleDnsConfig {
        std::string bootstrap_dns = "223.5.5.5";
        std::vector<std::string> direct_dns{"https://223.5.5.5/dns-query"};
        std::vector<std::string> remote_dns{"https://1.1.1.1/dns-query"};
        bool parallel_query = false;
        std::vector<std::string> direct_expected_rule_sets;
        bool fake_ip_enabled = false;
        std::string fake_ip_v4_pool = "198.18.0.0/16";
        std::string fake_ip_v6_pool = "fc00::/18";
        bool fake_ip_global = false;
        bool block_aaaa = false;
        bool block_svcb_https = false;
        std::int64_t serve_stale_seconds = 0;
        bool use_system_hosts = true;
        std::vector<std::pair<std::string, std::string>> hosts;
        std::string strategy = "prefer_ipv4";
    };

    struct DnsConfig {
        std::string mode = "simple"; // "simple" | "raw_kdl"
        SimpleDnsConfig simple;
        std::string raw_kdl;
    };

    struct RuleSetAsset {
        std::string tag;
        std::string source_type = "local"; // "local" | "remote"
        std::string format = "srs"; // "nxmm" | "srs" | "beve" | "kdl" | "domain-list" | "ipcidr-list"
        std::string path;
        std::string url;
        std::string sha256;
        std::int64_t update_interval_ms = 0;
    };

    struct FullTemplateConfig {
        bool enabled = false;
        std::string template_kdl;
        bool append_proxies_only = false;
        std::string proxy_detour;
    };

    struct WorkspaceDocument {
        std::int64_t schema_version = 1;
        std::int64_t revision = 1;
        std::int64_t updated_at_ms = 0;
        std::vector<WorkspaceProfileItem> profiles;
        std::vector<SubscriptionItem> subscriptions;
        std::vector<RoutingProfile> routing_profiles;
        DnsConfig dns;
        std::vector<RuleSetAsset> rule_set_assets;
        FullTemplateConfig full_template;
    };
}
