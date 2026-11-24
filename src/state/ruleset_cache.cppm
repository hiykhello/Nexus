export module state.ruleset_cache;
import std;
export import state.core;

export namespace state {
    enum class RuleFormat : std::uint8_t { kdl = 1, beve, srs, nxmm, json, domain_list, ipcidr_list, classical, adguard };

    struct RulesetKey {
        std::string canonical_url;
        RuleFormat format;
        std::uint32_t parser_version;
        Fingerprint scope{};
        auto operator==(RulesetKey const&) const -> bool = default;
    };

    struct RulesetMetadata {
        std::string etag, last_modified, response_target;
        Fingerprint content_blake3{}, content_sha256{};
        std::uint64_t fetched_at = 0, expires_at = 0;
        std::uint32_t size_bytes = 0;
    };

    struct CachedRuleset {
        RulesetMetadata metadata;
        std::string body;
    };

    struct RulesetLookup {
        std::uint64_t clear_epoch;
        std::optional<CachedRuleset> hit;
    };

    struct RulesetCacheLimits {
        std::uint64_t max_bytes = 128ull * 1024 * 1024;
        std::size_t max_entries = 64;
    };

    // Each operation takes the private rulesets directory lock. The caller
    // captures the lookup epoch before network I/O and supplies it to store.
    class RulesetCache {
        std::filesystem::path root_;
        RulesetCacheLimits limits_;

    public:
        explicit RulesetCache(std::filesystem::path root, RulesetCacheLimits limits = {})
            : root_(std::move(root)), limits_(limits) {}

        [[nodiscard]] auto lookup(this RulesetCache const& self, RulesetKey const& key)
            -> std::expected<RulesetLookup, StateError>;
        [[nodiscard]] auto store(this RulesetCache const& self, RulesetKey const& key,
                                 std::uint64_t epoch, RulesetMetadata metadata, std::string_view body)
            -> std::expected<void, StateError>;
        [[nodiscard]] auto discard(this RulesetCache const& self, RulesetKey const& key, std::uint64_t epoch,
                                   Fingerprint const& content)
            -> std::expected<void, StateError>;
        [[nodiscard]] auto clear(this RulesetCache const& self) -> std::expected<void, StateError>;
    };
}
