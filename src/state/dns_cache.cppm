export module state.dns_cache;
import std;
export import state.core;

export namespace state {
    struct DnsCacheShard {
        std::uint64_t epoch;
        std::optional<Bytes> payload;
    };
    inline constexpr Magic dns_cache_magic{'N','X','D','N','0','3'};
    inline constexpr std::size_t dns_shard_payload=1024*1024;

    class DnsCache {
        std::filesystem::path root_;
        std::size_t budget_;
    public:
        explicit DnsCache(std::filesystem::path root,std::size_t budget=4*1024*1024)
            :root_(std::move(root)),budget_(budget) {}
        [[nodiscard]] auto epoch() const -> std::expected<std::uint64_t,StateError>;
        [[nodiscard]] auto lookup(Fingerprint const& view) const -> std::expected<DnsCacheShard,StateError>;
        [[nodiscard]] auto store(Fingerprint const& view,std::uint64_t captured,std::span<std::byte const> payload) const
            -> std::expected<void,StateError>;
        [[nodiscard]] auto clear() const -> std::expected<void,StateError>;
    };

    // Names are parsed without trusting the file or disclosing the fingerprint.
    auto dns_shard_fingerprint(std::string_view name) noexcept -> std::optional<Fingerprint>;
}
