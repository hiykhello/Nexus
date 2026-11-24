// Executor-local GroupSnapshot membership adapter module.
export module dns.group_cache_binding;
import std;
export import dns.cache;
export import dns.group_snapshot;
import dns.message;

export namespace dns_hp_experiment {
    class GroupBinding {
        GroupSnapshot& cache_;
        std::size_t group_;
    public:
        using Reader = GroupSnapshot::Reader;
        class Token {
            friend class GroupBinding;
            GroupSnapshot const* owner_;
            std::size_t group_;
            dns::CacheToken value_;
            Token(GroupSnapshot const& owner, std::size_t group, dns::CacheToken value) noexcept
                : owner_(&owner), group_(group), value_(value) {}
        };
    private:
        [[nodiscard]] auto owns(Token const& token) const noexcept -> bool {
            return token.owner_ == &cache_ && token.group_ == group_;
        }
        // Only the bounded snapshot invalidates a matching generation when its
        // foreground registration/publication allocation fails. It is then safe
        // for the resolver to proceed without caching a successful network result.
        template<class F> auto foreground(F&& operation) {
            try { return operation(); }
            catch (std::bad_alloc const&) {
                if (!cache_.fails_closed_on_allocation()) throw;
                using Result = decltype(operation());
                return Result(std::unexpected(dns::CacheError::disabled));
            }
        }
    public:
        GroupBinding(GroupSnapshot& cache, std::size_t group) : cache_(cache), group_(group) {}
        auto begin_query(dns::CacheKey const& key) -> std::expected<Token, dns::CacheError> {
            auto result = foreground([&] { return cache_.begin_query(group_, key.view, key.name, key.type); });
            if (!result) return std::unexpected(result.error());
            return Token(cache_, group_, *result);
        }
        auto begin_refresh(dns::CacheKey key, std::uint64_t now, std::size_t maximum)
            -> std::expected<std::optional<Token>, dns::CacheError> {
            auto result = cache_.begin_refresh(group_, std::move(key), now, maximum);
            if (!result) return std::unexpected(result.error());
            if (!*result) return std::optional<Token>{};
            return std::optional<Token>(Token(cache_, group_, **result));
        }
        auto cancel_query(Token token) -> std::expected<void, dns::CacheError> {
            if (!owns(token)) return std::unexpected(dns::CacheError::stale_query);
            return cache_.cancel_query(token.value_);
        }
        auto publish(dns::CacheKey const& key, dns::AddressAnswer&& answer, std::uint64_t now, Token token)
            -> std::expected<void, dns::CacheError> {
            if (!owns(token)) return std::unexpected(dns::CacheError::stale_query);
            return foreground([&] { return cache_.publish_view(group_, key.view, key.name, key.type, std::move(answer), now, token.value_); });
        }
        auto publish(dns::CacheKey const& key, dns::AddressAnswer const& answer, std::uint64_t now, Token token)
            -> std::expected<void, dns::CacheError> {
            if (!owns(token)) return std::unexpected(dns::CacheError::stale_query);
            return foreground([&] { return cache_.publish_copy_view(group_, key.view, key.name, key.type, answer, now, token.value_); });
        }
        auto publish_from(dns::CacheKey const& key, dns::AddressAnswer const& answer,
                          std::uint64_t acquired, std::uint64_t now, Token token) -> std::expected<void, dns::CacheError> {
            if (!owns(token)) return std::unexpected(dns::CacheError::stale_query);
            return foreground([&] { return cache_.publish_copy_view_from(group_, key.view, key.name, key.type, answer, acquired, now, token.value_); });
        }
        auto publish_negative(dns::CacheKey const& key, dns::NegativeKind kind, std::uint32_t ttl,
                              std::uint64_t now, Token token) -> std::expected<void, dns::CacheError> {
            if (!owns(token)) return std::unexpected(dns::CacheError::stale_query);
            return foreground([&] { return cache_.publish_negative_view(group_, key.view, key.name, key.type, kind, ttl, now, token.value_); });
        }
        auto publish_negative_from(dns::CacheKey const& key, dns::NegativeKind kind, std::uint32_t ttl,
                                   std::uint64_t acquired, std::uint64_t now, Token token) -> std::expected<void, dns::CacheError> {
            if (!owns(token)) return std::unexpected(dns::CacheError::stale_query);
            return foreground([&] { return cache_.publish_negative_view_from(group_, key.view, key.name, key.type, kind, ttl, acquired, now, token.value_); });
        }
        auto invalidate(dns::CacheKey const& key, std::uint64_t now, Token token) -> std::expected<void, dns::CacheError> {
            if (!owns(token)) return std::unexpected(dns::CacheError::stale_query);
            return foreground([&] { return cache_.invalidate_view(group_, key.view, key.name, key.type, now, token.value_); });
        }
        auto lookup(dns::CacheKey key, std::uint64_t now, Reader& reader) {
            return cache_.lookup(group_, std::move(key), now, reader);
        }
        auto lookup_fresh(dns::CacheKey key, std::uint64_t now, Reader& reader) {
            return cache_.lookup_fresh(group_, std::move(key), now, reader);
        }
        auto lookup_negative(dns::CacheKey key, std::uint64_t now, Reader& reader) {
            return cache_.lookup_negative(group_, std::move(key), now, reader);
        }
        auto lookup_stale(dns::CacheKey key, std::uint64_t now, Reader& reader) {
            return cache_.lookup_stale(group_, std::move(key), now, reader);
        }
        // Shared snapshots require a reader on the normal resolution path.
        auto lookup(dns::CacheKey, std::uint64_t) -> std::expected<std::optional<dns::AddressAnswer>, dns::CacheError> {
            return std::unexpected(dns::CacheError::reader_required);
        }
        auto lookup_fresh(dns::CacheKey, std::uint64_t) -> std::expected<std::optional<GroupSnapshot::Fresh>, dns::CacheError> {
            return std::unexpected(dns::CacheError::reader_required);
        }
        auto lookup_negative(dns::CacheKey, std::uint64_t) -> std::expected<std::optional<dns::NegativeKind>, dns::CacheError> {
            return std::unexpected(dns::CacheError::reader_required);
        }
        auto lookup_stale(dns::CacheKey, std::uint64_t) -> std::expected<std::optional<dns::StaleAddressAnswer>, dns::CacheError> {
            return std::unexpected(dns::CacheError::reader_required);
        }
    };
}
