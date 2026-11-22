export module quic.cid_registry;
import std;

export namespace quic {
    struct SessionHandle {
        std::uint16_t slot=0;
        std::uint64_t generation=0;
        auto operator==(SessionHandle const&) const noexcept -> bool = default;
    };
    enum class CidError { invalid_owner,invalid_cid,collision,capacity,exhausted };
    // One executor owns this bounded shared-port routing table. Native CID
    // callbacks copy public identifiers here; no connection or TLS object is
    // erased into this registry. Reused slots always get a fresh generation.
    template<std::size_t Sessions=64,std::size_t IdsPerSession=8>
    class CidRegistry {
        static_assert(Sessions && Sessions<=65536 && IdsPerSession>=2 && IdsPerSession<=32);
        struct Slot { std::uint64_t generation=0;bool active=false; };
        struct Entry { std::array<std::uint8_t,20> bytes{};SessionHandle owner;std::uint8_t size=0; };
        std::array<Slot,Sessions> slots_{};
        std::array<Entry,Sessions*IdsPerSession> ids_{};
        std::uint64_t next_=1;
        std::size_t size_=0;
        static auto same(Entry const& entry,std::span<std::uint8_t const> id) noexcept -> bool {
            return entry.size==id.size() && std::ranges::equal(std::span(entry.bytes).first(entry.size),id);
        }
    public:
        auto live(SessionHandle owner) const noexcept -> bool {
            return owner.slot<Sessions && owner.generation && slots_[owner.slot].active && slots_[owner.slot].generation==owner.generation;
        }
        auto reserve() noexcept -> std::expected<SessionHandle,CidError> {
            if(!next_)return std::unexpected(CidError::exhausted);
            for(std::size_t i=0;i<Sessions;++i)if(!slots_[i].active){slots_[i]={next_++,true};++size_;return SessionHandle{static_cast<std::uint16_t>(i),slots_[i].generation};}
            return std::unexpected(CidError::capacity);
        }
        auto insert(SessionHandle owner,std::span<std::uint8_t const> id) noexcept -> std::expected<void,CidError> {
            if(!live(owner))return std::unexpected(CidError::invalid_owner);
            if(id.empty() || id.size()>20)return std::unexpected(CidError::invalid_cid);
            std::size_t count=0;Entry* free=nullptr;
            for(auto& entry:ids_){
                if(!entry.size){if(!free)free=&entry;continue;}
                if(same(entry,id))return entry.owner==owner?std::expected<void,CidError>{}:std::unexpected(CidError::collision);
                if(entry.owner==owner)++count;
            }
            if(!free || count==IdsPerSession)return std::unexpected(CidError::capacity);
            std::ranges::copy(id,free->bytes.begin());free->size=static_cast<std::uint8_t>(id.size());free->owner=owner;return {};
        }
        auto find(std::span<std::uint8_t const> id) const noexcept -> std::optional<SessionHandle> {
            if(id.empty() || id.size()>20)return {};
            for(auto const& entry:ids_)if(entry.size && same(entry,id) && live(entry.owner))return entry.owner;
            return {};
        }
        auto remove(SessionHandle owner,std::span<std::uint8_t const> id) noexcept -> bool {
            if(!live(owner) || id.empty() || id.size()>20)return false;
            for(auto& entry:ids_)if(entry.owner==owner && same(entry,id)){entry={};return true;}
            return false;
        }
        auto release(SessionHandle owner) noexcept -> bool {
            if(!live(owner))return false;
            for(auto& entry:ids_)if(entry.owner==owner)entry={};slots_[owner.slot].active=false;--size_;return true;
        }
        auto clear() noexcept -> void {for(auto& entry:ids_)entry={};for(auto& slot:slots_)slot.active=false;size_=0;}
        auto size() const noexcept -> std::size_t {return size_;}
    };
}
