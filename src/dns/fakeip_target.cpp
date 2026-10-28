module nexus.dns.fakeip_target;
import std;
import nexus.dns.fakeip;
namespace nexus::dns {
    auto acquire_fakeip_target(FakeIpPool& pool,std::uint32_t address,std::uint64_t view,
        std::chrono::steady_clock::time_point now) -> std::expected<std::unique_ptr<FakeIpTarget>,FakeIpTargetError> {
        auto mapping=pool.lookup(address,now);
        if (!mapping) return std::unexpected(FakeIpTargetError::clock);
        if (!pool.contains(address)) return std::unique_ptr<FakeIpTarget>{};
        if (!*mapping) return std::unexpected(FakeIpTargetError::unknown);
        if ((*mapping)->view!=view) return std::unexpected(FakeIpTargetError::wrong_view);
        auto target=std::unique_ptr<FakeIpTarget>(new FakeIpTarget(pool,std::move(**mapping)));
        auto pin=pool.pin(target->mapping_.lease,now);
        if (!pin) return std::unexpected(pin.error()==FakeIpError::exhausted ? FakeIpTargetError::capacity : FakeIpTargetError::stale);
        target->active_=true;
        return target;
    }
    auto FakeIpTarget::release(std::chrono::steady_clock::time_point now) -> std::expected<void,FakeIpTargetError> {
        if (!active_) return std::unexpected(FakeIpTargetError::stale);
        auto result=pool_->unpin(mapping_.lease,now);
        if (!result) return std::unexpected(result.error()==FakeIpError::time_reversed ? FakeIpTargetError::clock : FakeIpTargetError::stale);
        active_=false;
        return {};
    }
}
