export module proxy.sni_demux;
import std;
import nexus.compat;

export namespace proxy {
    enum class SniPeekStatus : std::uint8_t { incomplete, matched, non_tls, malformed };
    enum class DemuxRole : std::uint8_t { proxy_inbound, https_site, web_console, custom };

    struct SniPeekResult {
        SniPeekStatus status = SniPeekStatus::incomplete;
        std::string server_name;
        nexus::inplace_vector<std::string, 8> alpn_protocols;
        std::size_t record_length = 0;
    };

    struct DemuxRule {
        std::string host_pattern; // exact host or "*.domain.tld"
        std::string required_alpn; // empty matches any ALPN
        DemuxRole role = DemuxRole::proxy_inbound;
        std::string target_upstream;
    };

    struct DemuxDecision {
        bool matched_rule = false;
        DemuxRole role = DemuxRole::https_site;
        std::string target_upstream;
        std::string server_name;
        std::string selected_alpn;
        std::span<std::uint8_t const> passthrough_bytes;
    };

    [[nodiscard]] auto inspect_client_hello(std::span<std::uint8_t const> bytes) noexcept -> SniPeekResult;

    class SniDemuxRouter {
        std::vector<DemuxRule> rules_;
        DemuxRole fallback_role_ = DemuxRole::https_site;
        std::string fallback_upstream_ = "127.0.0.1:8443";
    public:
        auto add_rule(DemuxRule rule) -> void;
        auto set_fallback(DemuxRole role, std::string upstream) -> void;
        [[nodiscard]] auto route(std::span<std::uint8_t const> peek_bytes) const -> DemuxDecision;
    };
}
