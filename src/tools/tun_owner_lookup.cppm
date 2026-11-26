// Shared TUN clock & socket-owner metadata lookup helpers.
export module cli.tun_owner_lookup;
import std;
import containers.inplace_vector;
import platform.process_owner;
import rules;

export namespace cli::tun_enabled {
    inline auto now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    struct TunOwnerInfo {
        std::optional<std::uint32_t> uid{};
        std::optional<std::uint32_t> gid{};
        std::string process_path{};
        std::string user{};
        std::string package_name{};
        containers::inplace_vector<std::string, 8> process_paths{};
    };

    inline auto lookup_tun_owner(bool is_udp, std::span<std::uint8_t const> local_ip, std::uint16_t local_port,
        std::span<std::uint8_t const> remote_ip, std::uint16_t remote_port,
        rules::RouteMatcher const& policy, auto const* ordered) -> std::optional<TunOwnerInfo> {
        bool need_uid = policy.uses_source_uid() || (ordered && ordered->program.uses_source_uid());
        bool need_process = policy.uses_process() || (ordered && ordered->program.uses_process());
        if (!need_uid && !need_process)
            return {};
        auto lip = platform::normalize_socket_ip(local_ip);
        auto rip = platform::normalize_socket_ip(remote_ip);
        if (!lip || !rip) return {};
        if (auto owner = platform::lookup_socket_owner({is_udp, *lip, local_port, *rip, remote_port, need_process})) {
            TunOwnerInfo info;
#if !defined(_WIN32)
            info.uid = owner->uid;
            info.gid = owner->gid;
#endif
            if (!owner->executables.empty()) {
                info.process_path = owner->executables.front();
                info.process_paths = std::move(owner->executables);
            } else if (!owner->executable.empty()) {
                info.process_path = std::move(owner->executable);
            }
            if (!owner->user.empty()) info.user = std::move(owner->user);
            if (!owner->package_name.empty()) info.package_name = std::move(owner->package_name);
            return info;
        }
        return {};
    }

    // Bounded (1024 entries, 5s TTL) UDP source owner cache to avoid per-datagram netlink/proc scans.
    class TunUdpOwnerCache {
        struct Key {
            std::uint8_t ip_size = 0;
            std::array<std::uint8_t, 16> ip{};
            std::uint16_t port = 0;
            auto operator==(Key const&) const -> bool = default;
        };
        struct KeyHash {
            auto operator()(Key const& k) const noexcept -> std::size_t {
                std::size_t h = 14695981039346656037ull ^ k.ip_size;
                for (std::size_t i = 0; i < k.ip_size; ++i) { h ^= k.ip[i]; h *= 1099511628211ull; }
                h ^= k.port; h *= 1099511628211ull;
                return h;
            }
        };
        struct Entry {
            std::optional<TunOwnerInfo> info;
            std::uint64_t expires_ms = 0;
            bool has_process = false;
        };
        static constexpr std::size_t max_entries = 1024;
        static constexpr std::uint64_t ttl_ms = 5000;
        std::unordered_map<Key, Entry, KeyHash> map_;
        std::deque<Key> order_;
    public:
        [[nodiscard]] auto size() const noexcept -> std::size_t { return map_.size(); }
        auto lookup_or_query(std::uint64_t now_ms_val, std::span<std::uint8_t const> local_ip, std::uint16_t local_port,
            std::span<std::uint8_t const> remote_ip, std::uint16_t remote_port,
            rules::RouteMatcher const& policy, auto const* ordered) -> std::optional<TunOwnerInfo> {
            bool need_uid = policy.uses_source_uid() || (ordered && ordered->program.uses_source_uid());
            bool need_process = policy.uses_process() || (ordered && ordered->program.uses_process());
            if (!need_uid && !need_process) return {};
            auto lip = platform::normalize_socket_ip(local_ip);
            if (!lip || local_port == 0) return {};
            Key key{lip->size, lip->bytes, local_port};
            if (auto it = map_.find(key); it != map_.end() && now_ms_val < it->second.expires_ms) {
                if (!need_process || it->second.has_process) return it->second.info;
            }
            auto info = lookup_tun_owner(true, local_ip, local_port, remote_ip, remote_port, policy, ordered);
            auto [it, inserted] = map_.insert_or_assign(key, Entry{info, now_ms_val + ttl_ms, need_process});
            if (inserted) {
                order_.push_back(key);
                while (map_.size() > max_entries && !order_.empty()) {
                    map_.erase(order_.front());
                    order_.pop_front();
                }
            }
            return info;
        }
    };

    inline auto lookup_tun_owner_cached(TunUdpOwnerCache& cache, std::uint64_t now,
        std::span<std::uint8_t const> local_ip, std::uint16_t local_port,
        std::span<std::uint8_t const> remote_ip, std::uint16_t remote_port,
        rules::RouteMatcher const& policy, auto const* ordered) -> std::optional<TunOwnerInfo> {
        return cache.lookup_or_query(now, local_ip, local_port, remote_ip, remote_port, policy, ordered);
    }

    inline auto populate_tun_owner(bool is_udp, std::span<std::uint8_t const> local_ip, std::uint16_t local_port,
        std::span<std::uint8_t const> remote_ip, std::uint16_t remote_port,
        rules::RouteMatcher const& policy, auto const* ordered,
        std::optional<std::uint32_t>& uid_out, std::string& proc_out) -> void {
        if (auto info = lookup_tun_owner(is_udp, local_ip, local_port, remote_ip, remote_port, policy, ordered)) {
            if (info->uid) uid_out = info->uid;
            if (!info->process_path.empty()) proc_out = std::move(info->process_path);
        }
    }
}
