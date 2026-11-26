export module desktop.http_control;

import std;

export namespace desktop {
    struct HttpReply {
        bool ok = false;
        int status_code = 0;
        std::string body;
    };

    struct OutboundMemberSnapshot {
        std::string name;
        std::string state;
        std::int64_t latency_ms = -1;
        bool selected = false;
        bool overridden = false;
    };

    struct OutboundGroupSnapshot {
        std::string tag;
        std::string mode;
        std::string active;
        bool manual_override = false;
        std::vector<OutboundMemberSnapshot> members;
    };

    struct ActiveConnectionSnapshot {
        std::uint64_t id = 0;
        std::uint32_t listener = 0;
        std::string inbound;
        std::string protocol;
        std::string path;
        std::string source;
        std::string target;
        std::string outbound;
        std::string route_mode;
        std::string route_rule;
        std::string process_path;
        std::int64_t source_uid = -1;
        std::uint16_t destination_port = 0;
        std::uint64_t duration_ms = 0;
        std::uint64_t upload_bytes = 0;
        std::uint64_t download_bytes = 0;
        bool can_close = false;
    };

    struct LogEntrySnapshot {
        std::uint64_t seq = 0;
        std::string level;
        std::string domain;
        std::uint32_t event_code = 0;
        std::string message;
    };

    struct LogsSnapshot {
        std::uint64_t latest_seq = 0;
        std::uint64_t evicted = 0;
        std::vector<LogEntrySnapshot> entries;
    };

    struct MetricsSnapshot {
        std::uint64_t control_generation = 0;
        std::uint64_t active_sessions = 0;
        std::uint64_t upload_bytes = 0;
        std::uint64_t download_bytes = 0;
    };

    struct OutboundProbeResult {
        bool ok = false;
        std::string outbound;
        std::string resolved_outbound;
        std::string state;
        std::int64_t latency_ms = -1;
        int status_code = 0;
        std::string url;
        std::string error;
    };

    // Parses OpenMetrics /metrics output emitted by Nexus (Batch 95C).
    [[nodiscard]] auto parse_openmetrics_summary(std::string_view text) -> MetricsSnapshot;

    // Parses JSON emitted by POST /v1/outbounds/{tag}/probe (Wave 25).
    [[nodiscard]] auto parse_outbound_probe_json(std::string_view json) -> OutboundProbeResult;

    // Parses JSON emitted by GET /v1/outbounds.
    [[nodiscard]] auto parse_outbounds_json(std::string_view json) -> std::vector<OutboundGroupSnapshot>;

    // Parses JSON emitted by GET /v1/connections.
    [[nodiscard]] auto parse_connections_json(std::string_view json) -> std::vector<ActiveConnectionSnapshot>;

    // Parses JSON emitted by GET /v1/connections/{id}.
    [[nodiscard]] auto parse_connection_detail_json(std::string_view json) -> std::optional<ActiveConnectionSnapshot>;

    // Parses JSON emitted by GET /v1/logs.
    [[nodiscard]] auto parse_logs_json(std::string_view json) -> LogsSnapshot;

    [[nodiscard]] inline auto url_encode(std::string_view input) -> std::string {
        std::string out;
        out.reserve(input.size());
        for (unsigned char c : input) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                out.push_back(static_cast<char>(c));
            } else {
                out += std::format("%{:02X}", c);
            }
        }
        return out;
    }

    [[nodiscard]] inline auto json_escape(std::string_view input) -> std::string {
        std::string out;
        out.reserve(input.size());
        for (unsigned char c : input) {
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) out += std::format("\\u{:04x}", c);
                else out.push_back(static_cast<char>(c));
                break;
            }
        }
        return out;
    }

    // Minimal zero-dependency HTTP/1.1 client for Nexus /v1/* and /metrics endpoints.
    class HttpControlClient {
        mutable std::mutex mu_;
        std::string host_;
        std::uint16_t port_;
        std::string bearer_token_;
        std::chrono::milliseconds timeout_{2000};

    public:
        HttpControlClient(std::string host, std::uint16_t port, std::string bearer_token = {})
            : host_(std::move(host)), port_(port), bearer_token_(std::move(bearer_token)) {}

        [[nodiscard]] auto host(this HttpControlClient const& self) -> std::string {
            std::scoped_lock lk(self.mu_);
            return self.host_;
        }
        [[nodiscard]] auto port(this HttpControlClient const& self) noexcept -> std::uint16_t {
            std::scoped_lock lk(self.mu_);
            return self.port_;
        }
        auto set_endpoint(this HttpControlClient& self, std::string host, std::uint16_t port) -> void {
            std::scoped_lock lk(self.mu_);
            self.host_ = std::move(host);
            self.port_ = port;
        }
        auto set_bearer_token(this HttpControlClient& self, std::string token) -> void {
            std::scoped_lock lk(self.mu_);
            self.bearer_token_ = std::move(token);
        }

        [[nodiscard]] auto request(this HttpControlClient const& self,
                                   std::string_view method,
                                   std::string_view path,
                                   std::string_view body = {},
                                   std::optional<std::chrono::milliseconds> timeout_override = std::nullopt) -> HttpReply;

        [[nodiscard]] auto health(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/v1/health");
        }
        [[nodiscard]] auto status(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/v1/status");
        }
        [[nodiscard]] auto outbounds(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/v1/outbounds");
        }
        [[nodiscard]] auto select_group(this HttpControlClient const& self,
                                        std::string_view tag,
                                        std::string_view member) -> HttpReply {
            return self.request("PUT", std::format("/v1/groups/{}", url_encode(tag)),
                                std::format("{{\"member\":\"{}\"}}", json_escape(member)));
        }
        [[nodiscard]] auto reset_group_auto(this HttpControlClient const& self,
                                            std::string_view tag) -> HttpReply {
            return self.request("PUT", std::format("/v1/groups/{}", url_encode(tag)), "{\"member\":\"--auto\"}");
        }
        [[nodiscard]] auto probe_group(this HttpControlClient const& self, std::string_view tag) -> HttpReply {
            return self.request("POST", std::format("/v1/groups/{}/probe", url_encode(tag)), "{}");
        }
        [[nodiscard]] auto probe_outbound(this HttpControlClient const& self,
                                          std::string_view tag,
                                          std::string_view url = "https://www.gstatic.com/generate_204",
                                          std::uint32_t timeout_ms = 4000,
                                          std::string_view mode = "http") -> HttpReply {
            auto payload = std::format("{{\"url\":\"{}\",\"timeout_ms\":{},\"mode\":\"{}\"}}",
                json_escape(url), timeout_ms, json_escape(mode));
            auto wait = std::chrono::milliseconds(std::clamp<std::uint64_t>(timeout_ms, 500u, 30000u) + 2500u);
            return self.request("POST", std::format("/v1/outbounds/{}/probe", url_encode(tag)), payload, wait);
        }
        [[nodiscard]] auto reload(this HttpControlClient const& self) -> HttpReply {
            return self.request("POST", "/v1/reload");
        }
        [[nodiscard]] auto set_log_level(this HttpControlClient const& self,
                                         std::string_view level) -> HttpReply {
            return self.request("POST", "/v1/log-level", std::format("{{\"level\":\"{}\"}}", json_escape(level)));
        }
        [[nodiscard]] auto connections(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/v1/connections");
        }
        [[nodiscard]] auto connection_detail(this HttpControlClient const& self, std::uint64_t id) -> HttpReply {
            return self.request("GET", std::format("/v1/connections/{}", id));
        }
        [[nodiscard]] auto logs(this HttpControlClient const& self,
                                std::string_view level = {},
                                std::string_view domain = {},
                                std::string_view search = {},
                                std::uint64_t since = 0,
                                std::size_t limit = 128) -> HttpReply {
            std::string path = std::format("/v1/logs?limit={}", limit);
            if (since > 0) path += std::format("&since={}", since);
            if (!level.empty() && level != "all") path += std::format("&level={}", url_encode(level));
            if (!domain.empty() && domain != "all") path += std::format("&domain={}", url_encode(domain));
            if (!search.empty()) path += std::format("&search={}", url_encode(search));
            return self.request("GET", path);
        }
        [[nodiscard]] auto close_all_connections(this HttpControlClient const& self) -> HttpReply {
            return self.request("DELETE", "/v1/connections");
        }
        [[nodiscard]] auto close_connection(this HttpControlClient const& self, std::uint64_t id) -> HttpReply {
            return self.request("DELETE", std::format("/v1/connections/{}", id));
        }
        [[nodiscard]] auto diagnostics(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/v1/diagnostics");
        }
        [[nodiscard]] auto events(this HttpControlClient const& self, std::uint64_t cursor = 0) -> HttpReply {
            return self.request("GET", std::format("/v1/events?cursor={}", cursor));
        }
        [[nodiscard]] auto notify_network_change(this HttpControlClient const& self,
                                                 std::uint64_t generation = 0) -> HttpReply {
            if (generation > 0) {
                return self.request("POST", "/v1/network-change",
                                    std::format("{{\"generation\":\"{}\"}}", generation));
            }
            return self.request("POST", "/v1/network-change", "{}");
        }
        [[nodiscard]] auto clear_cache(this HttpControlClient const& self,
                                       std::string_view target = "all") -> HttpReply {
            return self.request("POST", "/v1/state/clear-cache",
                                std::format("{{\"target\":\"{}\"}}", json_escape(target)));
        }
        [[nodiscard]] auto metrics(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/metrics");
        }
        [[nodiscard]] auto mode(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/v1/mode");
        }
        [[nodiscard]] auto set_mode(this HttpControlClient const& self,
                                    std::string_view m,
                                    std::string_view outbound = {}) -> HttpReply {
            std::string payload = outbound.empty()
                ? std::format("{{\"mode\":\"{}\"}}", json_escape(m))
                : std::format("{{\"mode\":\"{}\",\"outbound\":\"{}\"}}", json_escape(m), json_escape(outbound));
            return self.request("PUT", "/v1/mode", payload);
        }
    };
}
