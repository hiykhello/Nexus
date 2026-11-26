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
        std::int64_t ewma_ms = -1;
        int last_status = 0;
        bool breaker_open = false;
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

    struct RuleEntrySnapshot {
        std::uint32_t index = 0;
        std::string type;
        std::string action;
        std::string target;
        std::string summary;
    };

    struct DnsAnswerSnapshot {
        std::string name;
        std::string type;
        std::uint32_t ttl = 0;
        std::string data;
    };

    struct DnsQueryResult {
        bool ok = false;
        std::string name;
        std::string type;
        int rcode = -1;
        std::string rcode_name;
        std::uint32_t ttl = 0;
        std::uint64_t elapsed_ms = 0;
        std::vector<DnsAnswerSnapshot> answers;
        std::string error;
    };

    struct FakeIpFlushResult {
        bool ok = false;
        std::uint64_t flushed = 0;
        bool fakeip = false;
        std::string error;
    };

    struct SseEvent {
        std::string event;
        std::string data;
    };

    struct WsEvent {
        std::string type;
        std::string data_json;
    };

    // RFC 6455 §1.3 Sec-WebSocket-Accept computation using standard GUID 258EAFA5-E914-47DA-95CA-C5AB0DC85B11.
    [[nodiscard]] auto compute_ws_accept_key(std::string_view sec_ws_key) -> std::string;

    // Parses a multiplexed /v1/ws JSON envelope {"type":"...","data":...}.
    [[nodiscard]] auto parse_ws_envelope_json(std::string_view json) -> std::optional<WsEvent>;

    // Parses /v1/status or /v1/ws metrics JSON payload into MetricsSnapshot.
    [[nodiscard]] auto parse_status_metrics_json(std::string_view json) -> std::optional<MetricsSnapshot>;

    // Incremental text/event-stream (SSE) frame decoder supporting CRLF/LF, comments, and multi-line data.
    class SseFrameParser {
        std::string line_buf_;
        std::string cur_event_;
        std::string cur_data_;
        bool has_data_ = false;
        bool line_overflow_ = false;
        bool frame_overflow_ = false;

    public:
        static constexpr std::size_t kMaxFrameBytes = 256u * 1024u;
        auto feed(this SseFrameParser& self, std::string_view chunk,
                  std::function<bool(SseEvent const&)> const& on_event) -> bool;
        auto finish(this SseFrameParser& self,
                    std::function<bool(SseEvent const&)> const& on_event) -> bool;
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

    // Parses a single log entry JSON object (emitted by SSE GET /v1/logs?stream=1).
    [[nodiscard]] auto parse_log_entry_json(std::string_view json) -> std::optional<LogEntrySnapshot>;

    // Parses JSON emitted by GET /v1/rules (Wave 30-31).
    [[nodiscard]] auto parse_rules_json(std::string_view json) -> std::vector<RuleEntrySnapshot>;

    // Parses JSON emitted by GET /v1/dns/query (Wave 30-31).
    [[nodiscard]] auto parse_dns_query_json(std::string_view json) -> DnsQueryResult;

    // Parses JSON emitted by POST /v1/cache/fakeip/flush (Wave 30-31).
    [[nodiscard]] auto parse_fakeip_flush_json(std::string_view json) -> FakeIpFlushResult;

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
        std::uint64_t endpoint_gen_{0};
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
        [[nodiscard]] auto endpoint_generation(this HttpControlClient const& self) noexcept -> std::uint64_t {
            std::scoped_lock lk(self.mu_);
            return self.endpoint_gen_;
        }
        auto set_endpoint(this HttpControlClient& self, std::string host, std::uint16_t port) -> void {
            std::scoped_lock lk(self.mu_);
            if (self.host_ != host || self.port_ != port) {
                self.host_ = std::move(host);
                self.port_ = port;
                ++self.endpoint_gen_;
            }
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
                                         std::string_view level,
                                         std::string_view domain = "global") -> HttpReply {
            std::string payload = (domain.empty() || domain == "global")
                ? std::format("{{\"level\":\"{}\"}}", json_escape(level))
                : std::format("{{\"level\":\"{}\",\"domain\":\"{}\"}}", json_escape(level), json_escape(domain));
            return self.request("POST", "/v1/log-level", payload);
        }
        [[nodiscard]] auto rules(this HttpControlClient const& self) -> HttpReply {
            return self.request("GET", "/v1/rules");
        }
        [[nodiscard]] auto dns_query(this HttpControlClient const& self,
                                     std::string_view name,
                                     std::string_view qtype = "A",
                                     std::string_view server = {},
                                     std::chrono::milliseconds timeout_override = std::chrono::milliseconds{15000}) -> HttpReply {
            std::string path = std::format("/v1/dns/query?name={}&type={}",
                url_encode(name), url_encode(qtype.empty() ? "A" : qtype));
            if (!server.empty()) path += std::format("&server={}", url_encode(server));
            return self.request("GET", path, {}, timeout_override);
        }
        [[nodiscard]] auto flush_fakeip(this HttpControlClient const& self) -> HttpReply {
            return self.request("POST", "/v1/cache/fakeip/flush", "{}");
        }
        // Opens a persistent text/event-stream SSE connection until on_event returns false, EOF, error, or stop is requested.
        [[nodiscard]] auto stream_sse(this HttpControlClient const& self,
                                      std::string_view path,
                                      std::function<bool(SseEvent const&)> on_event,
                                      std::stop_token stop = {},
                                      std::chrono::milliseconds connect_timeout = std::chrono::milliseconds{3000},
                                      std::chrono::milliseconds poll_interval = std::chrono::milliseconds{100},
                                      std::function<void()> on_connected = {})
            -> std::expected<void, std::string>;
        [[nodiscard]] auto stream_logs_sse(this HttpControlClient const& self,
                                           std::function<bool(SseEvent const&)> on_event,
                                           std::stop_token stop = {},
                                           std::string_view level = {},
                                           std::string_view domain = {},
                                           std::string_view search = {},
                                           std::uint64_t since = 0,
                                           std::function<void()> on_connected = {}) -> std::expected<void, std::string> {
            std::string path = "/v1/logs?stream=1";
            if (since > 0) path += std::format("&since={}", since);
            if (!level.empty() && level != "all") path += std::format("&level={}", url_encode(level));
            if (!domain.empty() && domain != "all") path += std::format("&domain={}", url_encode(domain));
            if (!search.empty()) path += std::format("&search={}", url_encode(search));
            return self.stream_sse(path, std::move(on_event), std::move(stop),
                                   std::chrono::milliseconds{3000}, std::chrono::milliseconds{100},
                                   std::move(on_connected));
        }
        [[nodiscard]] auto stream_connections_sse(this HttpControlClient const& self,
                                                  std::function<bool(SseEvent const&)> on_event,
                                                  std::stop_token stop = {},
                                                  std::uint32_t interval_ms = 1000,
                                                  std::function<void()> on_connected = {}) -> std::expected<void, std::string> {
            auto clamped = std::clamp<std::uint32_t>(interval_ms, 250u, 10000u);
            return self.stream_sse(std::format("/v1/connections?stream=1&interval_ms={}", clamped),
                                   std::move(on_event), std::move(stop),
                                   std::chrono::milliseconds{3000}, std::chrono::milliseconds{100},
                                   std::move(on_connected));
        }
        // Opens a loopback-only RFC 6455 multiplexed WebSocket stream to GET /v1/ws (Authorization: Bearer header only).
        [[nodiscard]] auto stream_ws(this HttpControlClient const& self,
                                     std::vector<std::string> const& channels,
                                     std::function<bool(WsEvent const&)> on_event,
                                     std::stop_token stop = {},
                                     std::uint64_t since = 0,
                                     std::uint32_t interval_ms = 1000,
                                     std::chrono::milliseconds connect_timeout = std::chrono::milliseconds{3000},
                                     std::chrono::milliseconds poll_interval = std::chrono::milliseconds{100},
                                     std::function<void()> on_connected = {})
            -> std::expected<void, std::string>;
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
