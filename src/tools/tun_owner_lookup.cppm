// Shared TUN clock & socket-owner metadata lookup helpers.
export module cli.tun_owner_lookup;
import std;
import containers.cache_index;
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
        rules::RouteProgram const& policy, auto const* ordered) -> std::optional<TunOwnerInfo> {
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
            Key key{};
            std::optional<TunOwnerInfo> info;
            std::uint64_t expires_ms = 0;
            bool has_process = false;
        };
        static constexpr std::size_t max_entries = 1024;
        static constexpr std::uint64_t ttl_ms = 5000;
        containers::ClockTable<Entry> table_;
    public:
        explicit TunUdpOwnerCache(std::size_t capacity = max_entries) : table_(capacity) {}
        [[nodiscard]] auto size() const noexcept -> std::size_t { return table_.size(); }
        auto lookup_or_query(std::uint64_t now_ms_val, std::span<std::uint8_t const> local_ip, std::uint16_t local_port,
            std::span<std::uint8_t const> remote_ip, std::uint16_t remote_port,
            rules::RouteProgram const& policy, auto const* ordered) -> std::optional<TunOwnerInfo> {
            bool need_uid = policy.uses_source_uid() || (ordered && ordered->program.uses_source_uid());
            bool need_process = policy.uses_process() || (ordered && ordered->program.uses_process());
            if (!need_uid && !need_process) return {};
            auto lip = platform::normalize_socket_ip(local_ip);
            if (!lip || local_port == 0) return {};
            if (table_.capacity() == 0)
                return lookup_tun_owner(true, local_ip, local_port, remote_ip, remote_port, policy, ordered);
            Key key{lip->size, lip->bytes, local_port};
            auto const hash = KeyHash{}(key);
            auto matches = [&](Entry const& e) noexcept { return e.key == key; };
            if (auto idx = table_.find(hash, matches)) {
                auto const& entry = table_.at(*idx);
                if (now_ms_val < entry.expires_ms && (!need_process || entry.has_process)) {
                    table_.touch(*idx);
                    return entry.info;
                }
            }
            auto info = lookup_tun_owner(true, local_ip, local_port, remote_ip, remote_port, policy, ordered);
            if (table_.capacity() != 0)
                table_.upsert(hash, matches, Entry{key, info, now_ms_val + ttl_ms, need_process},
                    [&](Entry const& e) noexcept { return now_ms_val >= e.expires_ms; });
            return info;
        }
    };

    inline auto lookup_tun_owner_cached(TunUdpOwnerCache& cache, std::uint64_t now,
        std::span<std::uint8_t const> local_ip, std::uint16_t local_port,
        std::span<std::uint8_t const> remote_ip, std::uint16_t remote_port,
        rules::RouteProgram const& policy, auto const* ordered) -> std::optional<TunOwnerInfo> {
        return cache.lookup_or_query(now, local_ip, local_port, remote_ip, remote_port, policy, ordered);
    }

    inline auto populate_tun_owner(bool is_udp, std::span<std::uint8_t const> local_ip, std::uint16_t local_port,
        std::span<std::uint8_t const> remote_ip, std::uint16_t remote_port,
        rules::RouteProgram const& policy, auto const* ordered,
        std::optional<std::uint32_t>& uid_out, std::string& proc_out) -> void {
        if (auto info = lookup_tun_owner(is_udp, local_ip, local_port, remote_ip, remote_port, policy, ordered)) {
            if (info->uid) uid_out = info->uid;
            if (!info->process_path.empty()) proc_out = std::move(info->process_path);
        }
    }
}
