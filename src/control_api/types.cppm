export module control_api.types;

import std;

export namespace control_api {
    enum class SnapshotFields : std::uint32_t {
        none = 0,
        meta = 1u << 0,
        listeners = 1u << 1,
        connections = 1u << 2,
        groups = 1u << 3,
        rules = 1u << 4,
        all = (1u << 5) - 1,
    };

    [[nodiscard]] constexpr auto operator|(SnapshotFields a, SnapshotFields b) noexcept -> SnapshotFields {
        return static_cast<SnapshotFields>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
    }

    [[nodiscard]] constexpr auto has_field(SnapshotFields mask, SnapshotFields bit) noexcept -> bool {
        return (static_cast<std::uint32_t>(mask) & static_cast<std::uint32_t>(bit)) != 0;
    }

    struct ListenerMetric {
        std::size_t index = 0;
        std::uint16_t port = 0;
        std::size_t active_sessions = 0;
        std::uint64_t upload_bytes = 0;
        std::uint64_t download_bytes = 0;
    };

    struct GroupMemberMetric {
        std::string name;
        std::string state;
        std::optional<std::uint32_t> latency_ms;
        std::optional<std::uint32_t> ewma_ms;
        std::optional<std::uint16_t> last_status;
        bool breaker_open = false;
    };

    struct GroupMetric {
        std::string name;
        std::string mode;
        std::string selected;
        bool manual_override = false;
        std::vector<GroupMemberMetric> members;
    };

    struct ConnectionMetric {
        std::uint64_t id = 0;
        std::size_t listener = 0;
        std::string protocol;
        std::string path;
        std::uint16_t destination_port = 0;
        std::uint64_t upload_bytes = 0;
        std::uint64_t download_bytes = 0;
        std::string inbound;
        std::string source;
        std::string target;
        std::string outbound;
        std::string route_mode;
        std::string route_rule;
        std::string process_path;
        std::optional<std::uint32_t> source_uid;
        std::uint64_t duration_ms = 0;
        bool can_close = false;
    };

    struct RuleMetric {
        std::size_t index = 0;
        std::string type;
        std::string action;
        std::string target;
        std::string summary;
    };

    struct ControlSnapshot {
        std::string instance;
        unsigned workers = 1;
        std::uint64_t control_generation = 1;
        std::uint64_t authorized_requests = 0;
        std::uint64_t unauthorized_requests = 0;
        std::uint64_t expired_requests = 0;
        std::uint64_t reply_failed = 0;
        std::vector<ListenerMetric> listeners;
        std::vector<GroupMetric> groups;
        std::vector<ConnectionMetric> connections;
        std::vector<RuleMetric> rules;
        std::string route_mode = "rule";
        std::string global_outbound;
    };
}
