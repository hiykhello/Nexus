export module dns.fakeip_target;
import std;
import dns.fakeip;
export namespace dns {
    enum class FakeIpTargetError { unknown, wrong_view, clock, capacity, stale };
    class FakeIpTarget {
        FakeIpPool* pool_;
        FakeIpMapping mapping_;
        bool active_=false;
        FakeIpTarget(FakeIpPool& pool,FakeIpMapping mapping) : pool_(&pool),mapping_(std::move(mapping)) {}
        friend auto acquire_fakeip_target(FakeIpPool&,std::uint32_t,std::uint64_t,
            std::chrono::steady_clock::time_point) -> std::expected<std::unique_ptr<FakeIpTarget>,FakeIpTargetError>;
    public:
        FakeIpTarget(FakeIpTarget const&)=delete;
        auto operator=(FakeIpTarget const&) -> FakeIpTarget& = delete;
        // The pool must outlive this handle. Forgetting release intentionally
        // leaves the pin held, preventing reuse at the cost of capacity.
        [[nodiscard]] auto mapping() const noexcept -> FakeIpMapping const& { return mapping_; }
        [[nodiscard]] auto release(std::chrono::steady_clock::time_point now) -> std::expected<void,FakeIpTargetError>;
    };
    // A null success means an ordinary address outside the pool. An unknown
    // in-pool address and a mapping from another view are explicit errors.
    // All calls and connection release must be serialized with the pool.
    [[nodiscard]] auto acquire_fakeip_target(FakeIpPool& pool,std::uint32_t address,std::uint64_t view,
        std::chrono::steady_clock::time_point now) -> std::expected<std::unique_ptr<FakeIpTarget>,FakeIpTargetError>;
}
