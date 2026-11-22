export module hysteria2.sessions;
import std;

export namespace hysteria2 {
    using UdpClock=std::chrono::steady_clock;
    struct UdpSessionHandle {
        std::uint16_t slot=0;
        std::uint64_t generation=0;
        auto operator==(UdpSessionHandle const&) const noexcept -> bool = default;
    };
    struct UdpAdmission { UdpSessionHandle handle; bool created=false; };
    enum class UdpSessionError { full,expired,exhausted,clock };
    // One QUIC connection owns a separate table. An expired ID is admitted as
    // a new generation only after expire() reports the old binding to its
    // owner. Callbacks release external UDP ports; they must not reenter this
    // table. Wire Session ID 0 is valid.
    template<std::size_t Capacity=64>
    class UdpSessions {
        static_assert(Capacity>0 && Capacity<=65536);
        struct Entry {
            std::uint32_t id=0;
            std::uint64_t generation=0;
            UdpClock::time_point touched{};
            bool active=false;
        };
        std::array<Entry,Capacity> entries_{};
        std::chrono::milliseconds idle_;
        std::uint64_t next_=1;
        std::size_t size_=0;
        std::optional<UdpClock::time_point> observed_;
        auto observe(UdpClock::time_point now) noexcept -> bool {
            if (observed_ && now<*observed_) return false;
            observed_=now; return true;
        }
    public:
        explicit UdpSessions(std::chrono::milliseconds idle=std::chrono::minutes(5)) : idle_(idle) {
            if (idle.count()<1 || idle>std::chrono::hours(24)) throw std::invalid_argument("invalid Hy2 UDP session timeout");
        }
        UdpSessions(UdpSessions const&)=delete;
        auto operator=(UdpSessions const&) -> UdpSessions& = delete;
        auto valid(UdpSessionHandle handle) const noexcept -> bool {
            return handle.slot<entries_.size() && handle.generation && entries_[handle.slot].active &&
                entries_[handle.slot].generation==handle.generation;
        }
        auto live(UdpSessionHandle handle,UdpClock::time_point now) const noexcept -> bool {
            return valid(handle) && now>=entries_[handle.slot].touched && now-entries_[handle.slot].touched<idle_;
        }
        auto id(UdpSessionHandle handle) const noexcept -> std::optional<std::uint32_t> {
            return valid(handle) ? std::optional(entries_[handle.slot].id) : std::nullopt;
        }
        auto acquire(std::uint32_t id,UdpClock::time_point now) noexcept -> std::expected<UdpAdmission,UdpSessionError> {
            if (!observe(now)) return std::unexpected(UdpSessionError::clock);
            for (std::size_t i=0;i<entries_.size();++i) {
                auto& entry=entries_[i];
                if (!entry.active || entry.id!=id) continue;
                UdpSessionHandle handle{static_cast<std::uint16_t>(i),entry.generation};
                if (!live(handle,now)) return std::unexpected(UdpSessionError::expired);
                entry.touched=now; return UdpAdmission{handle,false};
            }
            if (size_==entries_.size()) return std::unexpected(UdpSessionError::full);
            if (!next_) return std::unexpected(UdpSessionError::exhausted);
            for (std::size_t i=0;i<entries_.size();++i) if (!entries_[i].active) {
                auto generation=next_++;
                entries_[i]={id,generation,now,true}; ++size_;
                return UdpAdmission{{static_cast<std::uint16_t>(i),generation},true};
            }
            return std::unexpected(UdpSessionError::full);
        }
        auto touch(UdpSessionHandle handle,UdpClock::time_point now) noexcept -> bool {
            if (!observe(now) || !live(handle,now)) return false;
            entries_[handle.slot].touched=now; return true;
        }
        auto release(UdpSessionHandle handle) noexcept -> bool {
            if (!valid(handle)) return false;
            entries_[handle.slot].active=false; --size_; return true;
        }
        template<class Expired>
        auto expire(UdpClock::time_point now,Expired&& expired) -> std::size_t {
            if (!observe(now)) return 0;
            std::size_t removed=0;
            for (std::size_t i=0;i<entries_.size();++i) {
                auto& entry=entries_[i];
                if (!entry.active || now<entry.touched || now-entry.touched<idle_) continue;
                auto handle=UdpSessionHandle{static_cast<std::uint16_t>(i),entry.generation}; auto id=entry.id;
                entry.active=false; --size_; ++removed; expired(handle,id);
            }
            return removed;
        }
        template<class Closed>
        auto close(Closed&& closed) -> void {
            for (std::size_t i=0;i<entries_.size();++i) if (entries_[i].active) {
                auto handle=UdpSessionHandle{static_cast<std::uint16_t>(i),entries_[i].generation}; auto id=entries_[i].id;
                entries_[i].active=false; --size_; closed(handle,id);
            }
        }
        auto size() const noexcept -> std::size_t { return size_; }
        auto find(std::uint32_t id,UdpClock::time_point now) const noexcept -> std::optional<UdpSessionHandle> {
            if (observed_ && now<*observed_) return {};
            for (std::size_t i=0;i<Capacity;++i) if (entries_[i].active && entries_[i].id==id) {
                UdpSessionHandle handle{static_cast<std::uint16_t>(i),entries_[i].generation};if(live(handle,now))return handle;
            }return {};
        }
        auto expiry() const noexcept -> std::optional<UdpClock::time_point> {
            std::optional<UdpClock::time_point> result;
            for(auto const& entry:entries_)if(entry.active){
                auto value=entry.touched>UdpClock::time_point::max()-idle_ ? UdpClock::time_point::max() : entry.touched+idle_;
                if(!result || value<*result)result=value;
            }return result;
        }
    };
}

