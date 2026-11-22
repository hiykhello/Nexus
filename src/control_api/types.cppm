export module control_api.types;

import std;

export namespace control_api {
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
    };
}
