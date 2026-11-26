export module dns.fakeip_registry;
import std;
import dns.fakeip;
import dns.fakeip_target;
import dns.fakeip_response;
export namespace dns {
    enum class FakeIpRegistryError { invalid, overlap, full, missing, inactive, unknown, wrong_view, clock, capacity, stale, quarantine, unsealed, sealed };
    // Single-executor registry owns each pool for its entire lifetime. Retired
    // ranges stay reserved. The registry must outlive all responses and
    // target handles. No operation provides restart safety.
    class FakeIpRegistry {
        using Clock=std::chrono::steady_clock;
        struct Range { std::uint32_t first,last; std::unique_ptr<FakeIpPool> pool; bool active;
            std::optional<Clock::time_point> quarantine_start, quarantine_end; };
        std::vector<Range> ranges_;
        std::size_t limit_;
    public:
        explicit FakeIpRegistry(std::size_t limit) : limit_(limit) {}
        FakeIpRegistry(FakeIpRegistry const&)=delete;
        auto operator=(FakeIpRegistry const&) -> FakeIpRegistry& = delete;
        // Range includes reserved and allocatable addresses. A null pool is
        // a permanently reserved range. The caller must not retain aliases to
        // the transferred pool or bypass the registry to publish.
        [[nodiscard]] auto add(std::uint32_t first,std::uint32_t last,std::unique_ptr<FakeIpPool> pool)
            -> std::expected<void,FakeIpRegistryError>;
        // Creates an empty pool and blocks publication and lookup for the
        // entire caller-chosen interval, at least the current TTL plus grace.
        // The caller must establish exclusivity and cover any longer historical
        // protection period and in-flight transit.
        [[nodiscard]] auto add_quarantined(std::uint32_t first,std::uint32_t last,
            std::uint32_t alloc_first,std::uint32_t alloc_last,std::chrono::seconds ttl,
            std::chrono::seconds grace,Clock::time_point start,Clock::duration interval)
            -> std::expected<void,FakeIpRegistryError>;
        [[nodiscard]] auto retire(std::uint32_t first) -> std::expected<void,FakeIpRegistryError>;
        // Includes reserved, quarantined and retired ranges. Serialized with
        // all registry mutations; does not inspect or pin any mapping.
        [[nodiscard]] auto contains(std::uint32_t address) const noexcept -> bool;
        // A pending response can still finish after its range is retired.
        [[nodiscard]] auto respond(std::uint32_t first,std::span<std::uint8_t const> query,
            std::uint64_t view,std::chrono::steady_clock::time_point now,std::optional<FakeIpIpv6Range> ipv6={})
            -> std::expected<std::unique_ptr<FakeIpResponse>,std::variant<FakeIpRegistryError,FakeIpDnsError>>;
        // Null success denotes an address outside every registered range.
        [[nodiscard]] auto acquire(std::uint32_t address,std::uint64_t view,std::chrono::steady_clock::time_point now)
            -> std::expected<std::unique_ptr<FakeIpTarget>,FakeIpRegistryError>;
        // Evicts all unpinned entries across active pools while preserving pinned leases.
        auto flush_unpinned() noexcept -> std::size_t;
    };
}
