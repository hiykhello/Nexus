// Private outbound group configuration types included inside export namespace config.
#pragma once

    enum class OutboundGroupMode { select, fallback, url_test, load_balance };
    enum class OutboundProbeMode { http, h2_ping };
    struct OutboundStatusRange {
        std::uint16_t low = 200;
        std::uint16_t high = 299;
        auto operator==(OutboundStatusRange const&) const -> bool = default;
    };
    struct OutboundProbeSettings {
        std::string url;
        OutboundProbeMode mode = OutboundProbeMode::http;
        std::uint32_t interval_ms = 300000, timeout_ms = 5000, tolerance_ms = 0;
        std::vector<OutboundStatusRange> expected_status;
        std::string ca_file;
        std::string server_name;
        auto operator==(OutboundProbeSettings const&) const -> bool = default;
    };
    struct OutboundSelector {
        OutboundGroupMode mode = OutboundGroupMode::select;
        OutboundProbeSettings probe;
        bool uses_probe = false, uses_balance = false;
        std::string name;
        std::vector<std::string> members;
        std::string selected;
        std::string selected_leaf;
    };
    struct ControlHttpConfig {
        std::string host;
        std::uint16_t port = 0;
        std::string bearer_token_file;
        bool metrics = false;
        bool ipv6 = false;
        std::string dashboard_root;
        auto operator==(ControlHttpConfig const&) const -> bool = default;
    };
