module control_api.ssmapi;
import std;
import crypto;
import encoding.json;
import glaze;

namespace control_api::ssmapi {
    namespace {
        auto cleanse_string(std::string& s) noexcept -> void {
            if (!s.empty()) {
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size()));
                s.clear();
            }
        }
    }

    namespace detail {
        struct UserWire {
            std::string username;
            std::string uPSK;
            bool enabled = true;
            std::uint64_t byteQuota = 0;
            ~UserWire() { cleanse_string(uPSK); }
        };
    }

    namespace {
        using detail::UserWire;

        auto valid_username(std::string_view name) noexcept -> bool {
            return !name.empty() && name.size() <= 64 &&
                std::ranges::all_of(name, [](unsigned char c) { return c >= 0x21 && c <= 0x7e && c != '/'; });
        }

        auto format_user(UserRecord const& u) -> std::string {
            return std::format(
                "{{\"username\":{},\"enabled\":{},\"uplinkBytes\":{},\"downlinkBytes\":{},\"uplinkPackets\":{},\"downlinkPackets\":{},\"byteQuota\":{},\"tcpSessions\":{},\"udpSessions\":{}}}",
                encoding::json_quote(u.username), u.enabled ? "true" : "false", u.uplink_bytes, u.downlink_bytes,
                u.uplink_packets, u.downlink_packets, u.byte_quota, u.tcp_sessions, u.udp_sessions);
        }
    }

    UserStore::~UserStore() {
        std::lock_guard lock(mutex_);
        for (auto& u : users_) cleanse_string(u.u_psk);
    }

    auto UserStore::find_mut(std::string_view name) noexcept -> UserRecord* {
        for (auto& u : users_) {
            if (u.username == name) return &u;
        }
        return nullptr;
    }

    auto UserStore::upsert_user(UserRecord user) -> std::expected<void, std::string> {
        if (!valid_username(user.username) || user.u_psk.empty()) {
            cleanse_string(user.u_psk);
            return std::unexpected("invalid ssmapi username or uPSK");
        }
        std::lock_guard lock(mutex_);
        if (auto* existing = find_mut(user.username)) {
            cleanse_string(existing->u_psk);
            existing->u_psk = std::move(user.u_psk);
            existing->enabled = user.enabled;
            existing->byte_quota = user.byte_quota;
            return {};
        }
        if (users_.size() >= max_users) {
            cleanse_string(user.u_psk);
            return std::unexpected("ssmapi user capacity reached");
        }
        users_.push_back(std::move(user));
        return {};
    }

    auto UserStore::remove_user(std::string_view username) -> bool {
        std::lock_guard lock(mutex_);
        auto it = std::ranges::find(users_, username, &UserRecord::username);
        if (it == users_.end()) return false;
        cleanse_string(it->u_psk);
        users_.erase(it);
        return true;
    }

    auto UserStore::get_user(std::string_view username) const -> std::optional<UserRecord> {
        std::lock_guard lock(mutex_);
        auto it = std::ranges::find(users_, username, &UserRecord::username);
        if (it == users_.end()) return std::nullopt;
        return *it;
    }

    auto UserStore::list_users() const -> std::vector<UserRecord> {
        std::lock_guard lock(mutex_);
        return users_;
    }

    auto UserStore::record_traffic(std::string_view username, std::uint64_t up_bytes, std::uint64_t down_bytes,
                                   std::uint64_t up_packets, std::uint64_t down_packets) -> bool {
        std::lock_guard lock(mutex_);
        auto* u = find_mut(username);
        if (!u) return false;
        u->uplink_bytes += up_bytes;
        u->downlink_bytes += down_bytes;
        u->uplink_packets += up_packets;
        u->downlink_packets += down_packets;
        return true;
    }

    auto UserStore::set_sessions(std::string_view username, std::uint32_t tcp_sessions, std::uint32_t udp_sessions) -> bool {
        std::lock_guard lock(mutex_);
        auto* u = find_mut(username);
        if (!u) return false;
        u->tcp_sessions = tcp_sessions;
        u->udp_sessions = udp_sessions;
        return true;
    }

    auto UserStore::within_quota(std::string_view username) const noexcept -> bool {
        std::lock_guard lock(mutex_);
        auto it = std::ranges::find(users_, username, &UserRecord::username);
        if (it == users_.end() || !it->enabled) return false;
        if (it->byte_quota == 0) return true;
        return (it->uplink_bytes + it->downlink_bytes) < it->byte_quota;
    }

    auto UserStore::render_users_json() const -> std::string {
        std::lock_guard lock(mutex_);
        std::string out = "{\"users\":[";
        for (std::size_t i = 0; i < users_.size(); ++i) {
            if (i > 0) out.push_back(',');
            out += format_user(users_[i]);
        }
        out += "]}";
        return out;
    }

    auto UserStore::render_user_json(std::string_view username) const -> std::optional<std::string> {
        std::lock_guard lock(mutex_);
        auto it = std::ranges::find(users_, username, &UserRecord::username);
        if (it == users_.end()) return std::nullopt;
        return format_user(*it);
    }

    auto UserStore::render_stats_json() const -> std::string {
        std::lock_guard lock(mutex_);
        std::uint64_t up = 0, down = 0, up_pkts = 0, down_pkts = 0;
        std::uint64_t tcp = 0, udp = 0;
        for (auto const& u : users_) {
            up += u.uplink_bytes; down += u.downlink_bytes;
            up_pkts += u.uplink_packets; down_pkts += u.downlink_packets;
            tcp += u.tcp_sessions; udp += u.udp_sessions;
        }
        return std::format(
            "{{\"userCount\":{},\"uplinkBytes\":{},\"downlinkBytes\":{},\"uplinkPackets\":{},\"downlinkPackets\":{},\"tcpSessions\":{},\"udpSessions\":{}}}",
            users_.size(), up, down, up_pkts, down_pkts, tcp, udp);
    }

    auto handle_http_request(UserStore& store, std::string_view method,
                             std::string_view target, std::string_view body) -> HttpResponse {
        auto q = target.find('?');
        auto path = (q == std::string_view::npos) ? target : target.substr(0, q);
        if (method == "GET" && path == "/v1/ssmapi/stats") return {200, store.render_stats_json()};
        if (method == "GET" && path == "/v1/ssmapi/users") return {200, store.render_users_json()};

        constexpr std::string_view prefix = "/v1/ssmapi/users/";
        auto parse_wire = [&](std::string_view forced_name) -> std::expected<UserRecord, std::string> {
            UserWire wire{};
            if (glaze::read<glaze::opts{.error_on_unknown_keys = false}>(wire, body))
                return std::unexpected("invalid JSON body");
            if (!forced_name.empty()) wire.username = std::string(forced_name);
            return UserRecord{.username = std::move(wire.username), .u_psk = std::move(wire.uPSK),
                              .enabled = wire.enabled, .byte_quota = wire.byteQuota};
        };

        if (method == "POST" && path == "/v1/ssmapi/users") {
            auto rec = parse_wire({});
            if (!rec) return {400, std::format("{{\"error\":{}}}", encoding::json_quote(rec.error()))};
            auto username = rec->username;
            if (auto r = store.upsert_user(std::move(*rec)); !r)
                return {400, std::format("{{\"error\":{}}}", encoding::json_quote(r.error()))};
            return {201, store.render_user_json(username).value_or("{}")};
        }
        if (path.starts_with(prefix) && path.size() > prefix.size()) {
            auto name = path.substr(prefix.size());
            if (method == "GET") {
                if (auto u = store.render_user_json(name)) return {200, *u};
                return {404, "{\"error\":\"user not found\"}"};
            }
            if (method == "PUT") {
                auto rec = parse_wire(name);
                if (!rec) return {400, std::format("{{\"error\":{}}}", encoding::json_quote(rec.error()))};
                if (auto r = store.upsert_user(std::move(*rec)); !r)
                    return {400, std::format("{{\"error\":{}}}", encoding::json_quote(r.error()))};
                return {200, store.render_user_json(name).value_or("{}")};
            }
            if (method == "DELETE") {
                if (!store.remove_user(name)) return {404, "{\"error\":\"user not found\"}"};
                return {204, {}};
            }
        }
        return {404, "{\"error\":\"not found\"}"};
    }
}
