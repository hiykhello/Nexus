export module nexus.dns.cache;
import std;
import nexus.dns.message;

export namespace nexus::dns {
    enum class CacheError { invalid_key, invalid_answer, time_reversed, stale_generation, stale_query, generation_exhausted, query_limit, disabled };
    enum class NegativeKind { name_not_found, no_data };
    struct CacheKey {
        std::uint64_t view;
        std::string name;
        std::uint16_t type;
    };
    struct CacheToken { std::uint64_t generation; std::uint64_t query; };
    // Single owner, no concurrent calls; times are monotonic milliseconds.
    // The owner must assign distinct view IDs to distinct resolution policies,
    // never reuse one while its old entries or queries remain, and clear on change.
    class AddressCache {
        struct Entry {
            CacheKey key;
            AddressAnswer answer;
            std::optional<NegativeKind> negative;
            std::uint64_t expires;
        };
        struct Pending { CacheKey key; std::uint64_t query; };
        std::vector<Entry> entries_;
        std::vector<Pending> pending_;
        std::size_t capacity_;
        std::uint64_t generation_=1, now_=0, next_query_=0;
        bool initialized_=false;
        auto advance(std::uint64_t now) -> std::expected<void,CacheError>;
    public:
        // Zero disables insertion; at most 4096 entries, each separately bounded.
        explicit AddressCache(std::size_t capacity) : capacity_(std::min<std::size_t>(capacity,4096)) {}
        // Register before each external query; at most 4096 outstanding.
        // Tokens belong to this instance and must be canceled on failure.
        [[nodiscard]] auto begin_query(CacheKey key) -> std::expected<CacheToken,CacheError>;
        [[nodiscard]] auto cancel_query(CacheToken token) -> std::expected<void,CacheError>;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        [[nodiscard]] auto lookup(CacheKey key, std::uint64_t now)
            -> std::expected<std::optional<AddressAnswer>,CacheError>;
        [[nodiscard]] auto lookup_negative(CacheKey key, std::uint64_t now)
            -> std::expected<std::optional<NegativeKind>,CacheError>;
        [[nodiscard]] auto publish_negative(CacheKey key, NegativeKind kind, std::uint32_t ttl,
                                             std::uint64_t now, CacheToken token) -> std::expected<void,CacheError>;
        // Token must be captured before the external query starts and used once,
        // only with this instance and the registered key. A successful publication
        // invalidates earlier pending queries for the same key. Caller supplies
        // the remaining positive TTL and a verified, policy-approved answer.
        [[nodiscard]] auto publish(CacheKey key, AddressAnswer answer, std::uint64_t now, CacheToken token)
            -> std::expected<void,CacheError>;
        // A definitive negative answer removes the same-key positive value and
        // prevents older in-flight queries from restoring it; no negative is cached.
        [[nodiscard]] auto invalidate(CacheKey key, std::uint64_t now, CacheToken token)
            -> std::expected<void,CacheError>;
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<void,CacheError>;
    };
}
