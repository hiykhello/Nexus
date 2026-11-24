export module relay:shadowsocks_users;
import std;
import utility;

export namespace relay {
    struct ShadowsocksDynamicUser {
        struct StatDelta {
            std::uint64_t up_bytes = 0;
            std::uint64_t down_bytes = 0;
            std::uint64_t up_packets = 0;
            std::uint64_t down_packets = 0;
            std::uint32_t tcp_sessions = 0;
            std::uint32_t udp_sessions = 0;
        };

        std::string username;
        std::array<std::uint8_t, 32> key{};
        std::uint8_t key_len = 0;
        std::array<std::uint8_t, 16> identity_hash{};
        std::atomic<bool> enabled{true};
        std::atomic<bool> removed{false};
        std::atomic<std::uint64_t> byte_quota{0};
        std::atomic<std::uint64_t> total_up_bytes{0};
        std::atomic<std::uint64_t> total_down_bytes{0};
        std::atomic<std::uint64_t> delta_up_bytes{0};
        std::atomic<std::uint64_t> delta_down_bytes{0};
        std::atomic<std::uint64_t> delta_up_packets{0};
        std::atomic<std::uint64_t> delta_down_packets{0};
        std::atomic<std::uint32_t> tcp_sessions{0};
        std::atomic<std::uint32_t> udp_sessions{0};

        ~ShadowsocksDynamicUser() { utility::secure_zero(std::span{key}); }

        [[nodiscard]] auto key_span() const noexcept -> std::span<std::uint8_t const> {
            return std::span<std::uint8_t const>(key.data(), key_len);
        }

        [[nodiscard]] auto admits() const noexcept -> bool {
            if (removed.load(std::memory_order_acquire) || !enabled.load(std::memory_order_acquire))
                return false;
            auto q = byte_quota.load(std::memory_order_acquire);
            if (!q) return true;
            auto used = total_up_bytes.load(std::memory_order_relaxed) +
                total_down_bytes.load(std::memory_order_relaxed);
            return used < q;
        }

        auto record_bytes(bool upstream, std::uint64_t bytes) noexcept -> void {
            if (!bytes) return;
            if (upstream) {
                total_up_bytes.fetch_add(bytes, std::memory_order_relaxed);
                delta_up_bytes.fetch_add(bytes, std::memory_order_relaxed);
            } else {
                total_down_bytes.fetch_add(bytes, std::memory_order_relaxed);
                delta_down_bytes.fetch_add(bytes, std::memory_order_relaxed);
            }
        }

        auto record_datagram(bool upstream, std::uint64_t bytes) noexcept -> void {
            record_bytes(upstream, bytes);
            if (upstream) delta_up_packets.fetch_add(1, std::memory_order_relaxed);
            else delta_down_packets.fetch_add(1, std::memory_order_relaxed);
        }

        [[nodiscard]] auto consume_deltas() noexcept -> StatDelta {
            return {
                delta_up_bytes.exchange(0, std::memory_order_relaxed),
                delta_down_bytes.exchange(0, std::memory_order_relaxed),
                delta_up_packets.exchange(0, std::memory_order_relaxed),
                delta_down_packets.exchange(0, std::memory_order_relaxed),
                tcp_sessions.load(std::memory_order_relaxed),
                udp_sessions.load(std::memory_order_relaxed),
            };
        }
    };

    class ShadowsocksUserDirectory {
        using List = std::vector<std::shared_ptr<ShadowsocksDynamicUser>>;
        mutable std::mutex mu_;
        List entries_;
        std::shared_ptr<List const> snap_{std::make_shared<List const>()};
        std::atomic<std::uint64_t> revision_{0};

        auto publish_locked() -> void {
            snap_ = std::make_shared<List const>(entries_);
            revision_.fetch_add(1, std::memory_order_release);
        }

    public:
        auto upsert(std::string username, std::span<std::uint8_t const> raw_key,
            std::array<std::uint8_t, 16> hash, bool enabled, std::uint64_t byte_quota,
            std::uint64_t used_up = 0, std::uint64_t used_down = 0) -> void {
            if (raw_key.size() != 16 && raw_key.size() != 32) return;
            std::lock_guard lock(mu_);
            for (auto it = entries_.begin(); it != entries_.end(); ++it) {
                if ((*it)->username != username) continue;
                bool same_key = (*it)->key_len == raw_key.size() &&
                    std::ranges::equal((*it)->key_span(), raw_key);
                if (same_key) {
                    (*it)->enabled.store(enabled, std::memory_order_release);
                    (*it)->byte_quota.store(byte_quota, std::memory_order_release);
                    (*it)->removed.store(false, std::memory_order_release);
                    revision_.fetch_add(1, std::memory_order_release);
                    return;
                }
                (*it)->removed.store(true, std::memory_order_release);
                used_up = (*it)->total_up_bytes.load(std::memory_order_relaxed);
                used_down = (*it)->total_down_bytes.load(std::memory_order_relaxed);
                entries_.erase(it);
                break;
            }
            auto entry = std::make_shared<ShadowsocksDynamicUser>();
            entry->username = std::move(username);
            entry->key_len = static_cast<std::uint8_t>(raw_key.size());
            std::ranges::copy(raw_key, entry->key.begin());
            entry->identity_hash = hash;
            entry->enabled.store(enabled, std::memory_order_release);
            entry->byte_quota.store(byte_quota, std::memory_order_release);
            entry->total_up_bytes.store(used_up, std::memory_order_relaxed);
            entry->total_down_bytes.store(used_down, std::memory_order_relaxed);
            entries_.push_back(std::move(entry));
            publish_locked();
        }

        auto remove(std::string_view username) -> bool {
            std::lock_guard lock(mu_);
            auto it = std::ranges::find_if(entries_, [&](auto const& e) { return e->username == username; });
            if (it == entries_.end()) return false;
            (*it)->removed.store(true, std::memory_order_release);
            entries_.erase(it);
            publish_locked();
            return true;
        }

        [[nodiscard]] auto snapshot() const noexcept -> std::shared_ptr<List const> {
            std::lock_guard lock(mu_);
            return snap_;
        }

        [[nodiscard]] auto revision() const noexcept -> std::uint64_t {
            return revision_.load(std::memory_order_acquire);
        }

        template<class Fn>
        auto drain_stats(Fn&& fn) const -> void {
            auto current = snapshot();
            for (auto const& e : *current) fn(e->username, e->consume_deltas());
        }
    };
}
