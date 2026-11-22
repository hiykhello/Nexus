export module dns.fakeip;
import std;

export namespace dns {
    // IPv6 aliases embed the complete lease key in the last 32 bits.
    // The rest of the configured IPv6 range stays reserved.
    struct FakeIpIpv6Range {
        std::array<std::uint8_t,12> network;
        std::uint8_t length;
        [[nodiscard]] auto contains(this FakeIpIpv6Range const& self,
            std::span<std::uint8_t const,16> address) noexcept -> bool {
            if (self.length>96) return false;
            auto whole=self.length/8, partial=self.length%8;
            if (!std::ranges::equal(address.first(whole), std::span(self.network).first(whole))) return false;
            return !partial || ((address[whole]^self.network[whole])>>(8-partial))==0;
        }
    };
    auto fakeip_ipv4_key(std::span<std::uint8_t const> address) noexcept -> std::optional<std::uint32_t> {
        if (address.size()==16) {
            if (!std::ranges::all_of(address.first(10),[](auto octet){return octet==0;}) ||
                address[10]!=0xff || address[11]!=0xff) return std::nullopt;
            address=address.last(4);
        }
        if (address.size()!=4) return std::nullopt;
        std::uint32_t key=0;
        for (auto octet : address) key=(key<<8)|octet;
        return key;
    }

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
        void* durable_store_=nullptr;
        std::optional<std::uint32_t> (*durable_assign_)(void*,std::string_view,std::uint64_t)=nullptr;
        std::chrono::seconds ttl_, grace_;
        FakeIpPool(std::uint32_t first,std::size_t count,std::chrono::seconds ttl,std::chrono::seconds grace);
        [[nodiscard]] auto advance(Clock::time_point now) noexcept -> bool;
    public:
        [[nodiscard]] static auto create(std::uint32_t first,std::uint32_t last,
            std::chrono::seconds ttl,std::chrono::seconds grace) -> std::expected<std::unique_ptr<FakeIpPool>,FakeIpError>;
        using Assign=std::optional<std::uint32_t> (*)(void*,std::string_view,std::uint64_t);
        auto attach(void* owner,Assign assign) noexcept -> void {durable_store_=owner;durable_assign_=assign;}
        [[nodiscard]] auto restore(std::uint32_t address,std::uint64_t view,std::string_view domain) -> bool;
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
