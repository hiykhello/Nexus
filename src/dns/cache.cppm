export module dns.cache;
import std;
import containers.cache_index;
import dns.message;
export import dns.cache_types;
export import dns.cache_snapshot;
export import dns.refresh_budget;

export namespace dns {
    // Calls are synchronized; times are monotonic milliseconds. Shared mode
    // tolerates timestamps sampled by different threads before lock acquisition.
    // The owner must assign distinct view IDs to distinct resolution policies,
    // never reuse one while its old entries or queries remain, and clear on change.
    class AddressCache {
        struct Entry {
            CacheKey key;
            AddressAnswer answer;
            std::optional<NegativeKind> negative;
            std::uint64_t expires;
            std::uint64_t revision;
        };
        struct Pending { CacheKey key; std::uint64_t query; std::optional<std::uint64_t> refresh_revision; };
        containers::ClockTable<Entry> entries_;
        std::vector<Pending> pending_;
        std::size_t capacity_;
        std::uint64_t stale_window_ms_;
        std::uint64_t generation_ = 1, now_ = 0, next_query_ = 0, min_evict_at_ = std::numeric_limits<std::uint64_t>::max();
        bool initialized_ = false;
        mutable std::shared_mutex mutex_;
        bool shared_;
        std::unique_ptr<detail::BasicSnapshotState<true>> snapshot_;
        auto ordered(std::uint64_t now) const noexcept -> std::uint64_t { return shared_ && initialized_ ? std::max(now, now_) : now; }
        auto advance(std::uint64_t now) -> std::expected<void, CacheError>;
        auto refresh_current(Pending const& pending) const -> bool;
        auto recompute_min_evict() noexcept -> void;
    public:
        class Reader {
            std::optional<detail::BasicSnapshotState<true>::Reader> state_;
            friend class AddressCache;
            explicit Reader(detail::BasicSnapshotState<true>& state, std::size_t index) : state_(state.reader(index)) {}
        public:
            Reader(Reader const&) = delete;
            auto operator=(Reader const&) -> Reader& = delete;
            Reader(Reader&&) = default;
            auto operator=(Reader&&) -> Reader& = delete;
        };
        // Zero disables insertion; at most 4096 entries, each separately bounded.
        // A nonzero reader count selects the immutable snapshot implementation
        // for shared reads. Readers are synchronous and must not cross co_await.
        explicit AddressCache(std::size_t capacity, std::uint64_t stale_window_ms = 0, bool shared = false,
                              std::size_t readers = 0)
            : entries_(readers ? 0 : std::min<std::size_t>(capacity, 4096)),
              capacity_(std::min<std::size_t>(capacity, 4096)), stale_window_ms_(stale_window_ms), shared_(shared) {
            if (readers && (!shared_ || capacity_ > 256)) throw std::invalid_argument("invalid snapshot cache configuration");
            if (readers) snapshot_ = std::make_unique<detail::BasicSnapshotState<true>>(capacity_, stale_window_ms_, readers);
        }
        // Register before each external query; at most 4096 outstanding.
        // Tokens belong to this instance and must be canceled on failure.
        [[nodiscard]] auto begin_query(CacheKey key) -> std::expected<CacheToken, CacheError>;
        // Reserve a publication token for an eligible stale entry. Empty means
        // ineligible, a same-key token exists, or the registered-token limit is
        // full. Superseding a token does not stop its work: the asynchronous
        // owner must independently bound and drain actual in-flight tasks.
        [[nodiscard]] auto begin_refresh(CacheKey key, std::uint64_t now, std::size_t max_registered_refreshes)
            -> std::expected<std::optional<CacheToken>, CacheError>;
        [[nodiscard]] auto cancel_query(CacheToken token) -> std::expected<void, CacheError>;
        [[nodiscard]] auto reader(std::size_t index) -> Reader {
            if (!snapshot_) throw std::logic_error("cache has no immutable readers");
            return Reader(*snapshot_, index);
        }
        [[nodiscard]] auto size() const -> std::size_t {
            return snapshot_ ? snapshot_->size() : ([&] { std::shared_lock lock(mutex_); return entries_.size(); })();
        }
        [[nodiscard]] auto lookup(CacheKey key, std::uint64_t now)
            -> std::expected<std::optional<AddressAnswer>, CacheError>;
        [[nodiscard]] auto lookup(CacheKey key, std::uint64_t now, Reader& reader)
            -> std::expected<std::optional<AddressAnswer>, CacheError>;
        // Positive entries only. A stale hit has TTL 1 and is unavailable when
        // less than one second remains in the configured window. It does not
        // extend the original deadlines; the caller owns refresh scheduling.
        [[nodiscard]] auto lookup_stale(CacheKey key, std::uint64_t now)
            -> std::expected<std::optional<StaleAddressAnswer>, CacheError>;
        [[nodiscard]] auto lookup_stale(CacheKey key, std::uint64_t now, Reader& reader)
            -> std::expected<std::optional<StaleAddressAnswer>, CacheError>;
        [[nodiscard]] auto lookup_negative(CacheKey key, std::uint64_t now)
            -> std::expected<std::optional<NegativeKind>, CacheError>;
        [[nodiscard]] auto lookup_negative(CacheKey key, std::uint64_t now, Reader& reader)
            -> std::expected<std::optional<NegativeKind>, CacheError>;
        [[nodiscard]] auto publish_negative(CacheKey key, NegativeKind kind, std::uint32_t ttl,
                                             std::uint64_t now, CacheToken token) -> std::expected<void, CacheError>;
        // Token must be captured before the external query starts and used once,
        // only with this instance and the registered key. A successful publication
        // invalidates earlier pending queries for the same key. Caller supplies
        // the remaining positive TTL and a verified, policy-approved answer.
        [[nodiscard]] auto publish(CacheKey key, AddressAnswer answer, std::uint64_t now, CacheToken token)
            -> std::expected<void, CacheError>;
        // A definitive negative answer removes the same-key positive value and
        // prevents older in-flight queries from restoring it; no negative is cached.
        [[nodiscard]] auto invalidate(CacheKey key, std::uint64_t now, CacheToken token)
            -> std::expected<void, CacheError>;
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<void, CacheError>;
    };
}
