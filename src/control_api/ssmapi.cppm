export module control_api.ssmapi;
import std;

export namespace control_api::ssmapi {
    inline constexpr std::size_t max_users = 1024;

    struct UserRecord {
        std::string username;
        std::string u_psk;
        bool enabled = true;
        std::uint64_t uplink_bytes = 0;
        std::uint64_t downlink_bytes = 0;
        std::uint64_t uplink_packets = 0;
        std::uint64_t downlink_packets = 0;
        std::uint64_t byte_quota = 0; // 0 = unlimited
        std::uint32_t tcp_sessions = 0;
        std::uint32_t udp_sessions = 0;
    };

    struct HttpResponse {
        int status = 200;
        std::string json;
    };

    class UserStore {
        mutable std::mutex mutex_;
        std::vector<UserRecord> users_;
        auto find_mut(std::string_view name) noexcept -> UserRecord*;
    public:
        ~UserStore();
        [[nodiscard]] auto upsert_user(UserRecord user) -> std::expected<void, std::string>;
        [[nodiscard]] auto remove_user(std::string_view username) -> bool;
        [[nodiscard]] auto get_user(std::string_view username) const -> std::optional<UserRecord>;
        [[nodiscard]] auto list_users() const -> std::vector<UserRecord>;
        auto record_traffic(std::string_view username, std::uint64_t up_bytes, std::uint64_t down_bytes,
                            std::uint64_t up_packets = 0, std::uint64_t down_packets = 0) -> bool;
        auto set_sessions(std::string_view username, std::uint32_t tcp_sessions, std::uint32_t udp_sessions) -> bool;
        [[nodiscard]] auto within_quota(std::string_view username) const noexcept -> bool;
        [[nodiscard]] auto render_users_json() const -> std::string;
        [[nodiscard]] auto render_user_json(std::string_view username) const -> std::optional<std::string>;
        [[nodiscard]] auto render_stats_json() const -> std::string;
    };

    [[nodiscard]] auto handle_http_request(UserStore& store, std::string_view method,
                                           std::string_view target, std::string_view body) -> HttpResponse;
}
