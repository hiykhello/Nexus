export module nexus.dns.fakeip;
import std;

export namespace nexus::dns {
    enum class FakeIpError { invalid_config, invalid_name, full, time_reversed, time_overflow, stale, pinned, exhausted };
    class FakeIpPool;
    struct FakeIpLease {
        std::uint32_t address;
        std::uint64_t generation;
        FakeIpPool const* owner;
        auto operator==(FakeIpLease const&) const -> bool = default;
    };
    struct FakeIpMapping { FakeIpLease lease; std::string domain; std::uint64_t view; };
    // IPv4 numeric addresses are in network byte order as integers. One
    // serialized owner; callers choose a non-overlapping allocatable range.
    // This in-memory object provides no restart or persistence guarantee.
    class FakeIpPool {
        using Clock=std::chrono::steady_clock;
        struct Entry {
            std::string domain;
            std::uint64_t view=0, generation=0;
            Clock::time_point reusable{};
            std::size_t pins=0;
        };
        std::uint32_t first_;
        std::vector<Entry> entries_;
        std::size_t cursor_=0;
        std::uint64_t next_generation_=1;
        bool generation_exhausted_=false;
        std::optional<Clock::time_point> last_;
        std::chrono::seconds ttl_, grace_;
        FakeIpPool(std::uint32_t first,std::size_t count,std::chrono::seconds ttl,std::chrono::seconds grace);
        [[nodiscard]] auto advance(Clock::time_point now) noexcept -> bool;
    public:
        [[nodiscard]] static auto create(std::uint32_t first,std::uint32_t last,
            std::chrono::seconds ttl,std::chrono::seconds grace) -> std::expected<std::unique_ptr<FakeIpPool>,FakeIpError>;
        FakeIpPool(FakeIpPool const&)=delete;
        auto operator=(FakeIpPool const&) -> FakeIpPool& = delete;
        [[nodiscard]] auto ttl() const noexcept -> std::chrono::seconds { return ttl_; }
        [[nodiscard]] auto first_address() const noexcept -> std::uint32_t { return first_; }
        [[nodiscard]] auto last_address() const noexcept -> std::uint32_t {
            return static_cast<std::uint32_t>(first_+entries_.size()-1);
        }
        [[nodiscard]] auto contains(std::uint32_t address) const noexcept -> bool {
            return address>=first_ && static_cast<std::uint64_t>(address)-first_<entries_.size();
        }
        // Call only when the answer will be published; repeat publications
        // extend the protection interval. A failed send may conservatively pin
        // the address until the interval ends.
        [[nodiscard]] auto publish(std::string_view domain,std::uint64_t view,Clock::time_point now)
            -> std::expected<FakeIpLease,FakeIpError>;
        [[nodiscard]] auto lookup(std::uint32_t address,Clock::time_point now)
            -> std::expected<std::optional<FakeIpMapping>,FakeIpError>;
        // Leases are valid only during the originating pool's lifetime.
        [[nodiscard]] auto pin(FakeIpLease lease,Clock::time_point now) -> std::expected<void,FakeIpError>;
        [[nodiscard]] auto unpin(FakeIpLease lease,Clock::time_point now) -> std::expected<void,FakeIpError>;
        // After a send may have reached the network, extend protection from
        // completion before releasing one publication pin. Failure keeps it.
        [[nodiscard]] auto finish_publication(FakeIpLease lease,Clock::time_point now) -> std::expected<void,FakeIpError>;
    };
}
