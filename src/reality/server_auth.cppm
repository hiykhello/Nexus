export module reality.server_auth;
import std;
import reality.auth;
import tls.hello;
import tls.key_share;

export namespace reality {
    class ReplayCache {
        struct Entry { std::array<std::uint8_t, 32> id; std::uint64_t expires_at; };
        std::mutex mutex_;
        std::deque<Entry> queue_;
        std::set<std::array<std::uint8_t, 32>> index_;
        std::size_t capacity_;
    public:
        explicit ReplayCache(std::size_t capacity = 65536) noexcept : capacity_(capacity) {}
        [[nodiscard]] auto admit(std::span<std::uint8_t const> session_id, std::uint64_t now, std::uint64_t window_seconds) -> bool {
            if (session_id.size() != 32 || !capacity_) return session_id.size() == 32;
            std::array<std::uint8_t, 32> key{};
            std::ranges::copy(session_id, key.begin());
            std::lock_guard lock(mutex_);
            while (!queue_.empty() && queue_.front().expires_at <= now) {
                index_.erase(queue_.front().id);
                queue_.pop_front();
            }
            if (index_.contains(key)) return false;
            if (queue_.size() >= capacity_) {
                index_.erase(queue_.front().id);
                queue_.pop_front();
            }
            auto exp = now > std::numeric_limits<std::uint64_t>::max() - window_seconds
                ? std::numeric_limits<std::uint64_t>::max() : now + window_seconds;
            auto [it, inserted] = index_.insert(key);
            try { queue_.push_back({key, exp}); }
            catch (...) { if (inserted) index_.erase(it); throw; }
            return true;
        }
    };

    struct ServerPolicy {
        std::span<std::string const> server_names;
        std::span<std::array<std::uint8_t,8> const> short_ids;
        std::optional<std::array<std::uint8_t,3>> min_version,max_version;
        // Zero disables the clock-skew check, as in the pinned Xray server.
        std::uint64_t max_time_difference_seconds=0;
        ReplayCache* replay_cache = nullptr;
    };
    // The caller owns all policy storage and private key. Authentication failure
    // means fallback; it does not itself send data or prove a TLS handshake.
    [[nodiscard]] auto authenticate_server_hello(std::span<std::uint8_t const> wire,
        crypto::X25519Private const& private_key,ServerPolicy const& policy,std::uint64_t now)
        -> std::optional<OpenedHello>;
}

namespace reality {
    namespace {
        auto name(tls::Extension const* extension) noexcept -> std::optional<std::string_view> {
            if (!extension) return {};
            auto const& d=extension->data;
            if (d.size()<5 || (std::size_t(d[0])<<8 | d[1])!=d.size()-2 || d[2]!=0) return {};
            auto length=(std::size_t(d[3])<<8)|d[4];
            if (!length || length!=d.size()-5) return {};
            return std::string_view(reinterpret_cast<char const*>(d.data()+5),length);
        }
    }
    auto authenticate_server_hello(std::span<std::uint8_t const> wire,
        crypto::X25519Private const& private_key,ServerPolicy const& policy,std::uint64_t now)
        -> std::optional<OpenedHello> {
        if (wire.size()<4 || wire[0]!=1 || ((std::size_t(wire[1])<<16)|(std::size_t(wire[2])<<8)|wire[3])!=wire.size()-4) return {};
        auto hello=tls::ClientHello::parse(wire.subspan(4),65535);
        if (!hello || !hello->validate_tls13() || hello->session_id.size()!=32) return {};
        auto sni=name(hello->extension(0));
        if (!sni || !std::ranges::contains(policy.server_names,*sni)) return {};
        auto ext=hello->extension(51); if (!ext) return {};
        auto shares=tls::KeyShare::view_client(ext->data); if (!shares) return {};
        std::optional<std::span<std::uint8_t const>> x,hybrid; std::size_t cursor=0;
        while (auto share=shares->next(cursor)) {
            if (share->group==0x001d) {
                if (share->key_exchange.size()!=32) return {};
                x=share->key_exchange;
            }
            if (share->group==0x11ec) {
                if (share->key_exchange.size()!=1216) return {};
                hybrid=share->key_exchange.last(32);
            }
        }
        if (!x) x=hybrid;
        if (!x) return {};
        auto opened=open_client_hello(wire,private_key,*x); if (!opened) return {};
        auto const& id=opened->identity;
        if ((policy.min_version && id.version<*policy.min_version) || (policy.max_version && id.version>*policy.max_version)) return {};
        auto time=std::uint64_t(id.timestamp); auto delta=now>=time ? now-time : time-now;
        if (policy.max_time_difference_seconds && delta>policy.max_time_difference_seconds) return {};
        bool match=false;
        for (auto const& candidate:policy.short_ids) match |= crypto::constant_time_equal(id.short_id,candidate);
        if (!match) return {};
        if (policy.replay_cache) {
            auto const window = policy.max_time_difference_seconds
                ? std::max<std::uint64_t>(policy.max_time_difference_seconds * 2, 120)
                : std::uint64_t{120};
            if (!policy.replay_cache->admit(hello->session_id, now, window)) return {};
        }
        return std::move(*opened);
    }
}
