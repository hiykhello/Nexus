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
        static constexpr std::size_t MaxIds = Sessions * IdsPerSession;
        using Index = std::conditional_t<(MaxIds < 65535), std::uint16_t, std::uint32_t>;
        static constexpr Index kEmpty = std::numeric_limits<Index>::max();
        static constexpr std::size_t BucketCount = std::bit_ceil(MaxIds * 2);
        static constexpr std::size_t BucketMask = BucketCount - 1;

        struct Slot { std::uint64_t generation=0; Index head=kEmpty; std::uint8_t cid_count=0; bool active=false; };
        struct Entry { std::array<std::uint8_t,20> bytes{}; SessionHandle owner{}; Index next_owner=kEmpty; Index next_free=kEmpty; std::uint8_t size=0; };

        std::array<Slot,Sessions> slots_{};
        std::array<Entry,MaxIds> ids_{};
        std::array<Index,BucketCount> buckets_{};
        std::uint64_t next_=1;
        std::size_t size_=0;
        std::size_t next_alloc_=0;
        Index free_head_=kEmpty;

        static auto hash_cid(std::span<std::uint8_t const> id) noexcept -> std::size_t {
            std::uint64_t h=14695981039346656037ULL^id.size();
            for (auto b:id) { h^=b; h*=1099511628211ULL; }
            h^=h>>33; h*=0xff51afd7ed558ccdULL; h^=h>>33;
            return static_cast<std::size_t>(h);
        }
        static auto same(Entry const& entry,std::span<std::uint8_t const> id) noexcept -> bool {
            return entry.size==id.size() && std::ranges::equal(std::span(entry.bytes).first(entry.size),id);
        }
        auto find_bucket(std::span<std::uint8_t const> id) const noexcept -> std::optional<std::size_t> {
            auto pos=hash_cid(id)&BucketMask;
            for (;;) {
                auto idx=buckets_[pos];
                if (idx==kEmpty) return std::nullopt;
                if (same(ids_[idx],id)) return pos;
                pos=(pos+1)&BucketMask;
            }
        }
        auto erase_bucket(std::size_t hole) noexcept -> void {
            for (;;) {
                auto cur=(hole+1)&BucketMask;
                for (;;) {
                    auto idx=buckets_[cur];
                    if (idx==kEmpty) { buckets_[hole]=kEmpty; return; }
                    auto const& e=ids_[idx];
                    auto ideal=hash_cid(std::span(e.bytes).first(e.size))&BucketMask;
                    if (((hole-ideal)&BucketMask)<((cur-ideal)&BucketMask)) {
                        buckets_[hole]=idx;
                        hole=cur;
                        break;
                    }
                    cur=(cur+1)&BucketMask;
                }
            }
        }
    public:
        CidRegistry() noexcept { buckets_.fill(kEmpty); }

        auto live(SessionHandle owner) const noexcept -> bool {
            return owner.slot<Sessions && owner.generation && slots_[owner.slot].active && slots_[owner.slot].generation==owner.generation;
        }
        auto reserve() noexcept -> std::expected<SessionHandle,CidError> {
            if (!next_) return std::unexpected(CidError::exhausted);
            for (std::size_t i=0;i<Sessions;++i) if (!slots_[i].active) {
                slots_[i]={next_++,kEmpty,0,true};
                ++size_;
                return SessionHandle{static_cast<std::uint16_t>(i),slots_[i].generation};
            }
            return std::unexpected(CidError::capacity);
        }
        auto insert(SessionHandle owner,std::span<std::uint8_t const> id) noexcept -> std::expected<void,CidError> {
            if (!live(owner)) return std::unexpected(CidError::invalid_owner);
            if (id.empty() || id.size()>20) return std::unexpected(CidError::invalid_cid);
            auto pos=hash_cid(id)&BucketMask;
            for (;;) {
                auto idx=buckets_[pos];
                if (idx==kEmpty) break;
                if (same(ids_[idx],id)) return ids_[idx].owner==owner ? std::expected<void,CidError>{} : std::unexpected(CidError::collision);
                pos=(pos+1)&BucketMask;
            }
            auto& slot=slots_[owner.slot];
            if (slot.cid_count>=IdsPerSession) return std::unexpected(CidError::capacity);
            Index idx=kEmpty;
            if (free_head_!=kEmpty) {
                idx=free_head_;
                free_head_=ids_[idx].next_free;
            } else if (next_alloc_<MaxIds) {
                idx=static_cast<Index>(next_alloc_++);
            } else {
                return std::unexpected(CidError::capacity);
            }
            auto& entry=ids_[idx];
            std::ranges::copy(id,entry.bytes.begin());
            entry.owner=owner;
            entry.next_owner=slot.head;
            entry.next_free=kEmpty;
            entry.size=static_cast<std::uint8_t>(id.size());
            slot.head=idx;
            ++slot.cid_count;
            buckets_[pos]=idx;
            return {};
        }
        auto find(std::span<std::uint8_t const> id) const noexcept -> std::optional<SessionHandle> {
            if (id.empty() || id.size()>20) return {};
            auto pos=find_bucket(id);
            if (!pos) return {};
            auto const& entry=ids_[buckets_[*pos]];
            return live(entry.owner) ? std::optional(entry.owner) : std::nullopt;
        }
        auto remove(SessionHandle owner,std::span<std::uint8_t const> id) noexcept -> bool {
            if (!live(owner) || id.empty() || id.size()>20) return false;
            auto pos=find_bucket(id);
            if (!pos) return false;
            auto idx=buckets_[*pos];
            if (ids_[idx].owner!=owner) return false;
            auto& slot=slots_[owner.slot];
            Index* link=&slot.head;
            while (*link!=kEmpty && *link!=idx) link=&ids_[*link].next_owner;
            if (*link==idx) *link=ids_[idx].next_owner;
            --slot.cid_count;
            erase_bucket(*pos);
            ids_[idx]={};
            ids_[idx].next_free=free_head_;
            free_head_=idx;
            return true;
        }
        auto release(SessionHandle owner) noexcept -> bool {
            if (!live(owner)) return false;
            auto& slot=slots_[owner.slot];
            for (Index idx=slot.head;idx!=kEmpty;) {
                auto next=ids_[idx].next_owner;
                if (auto pos=find_bucket(std::span(ids_[idx].bytes).first(ids_[idx].size))) erase_bucket(*pos);
                ids_[idx]={};
                ids_[idx].next_free=free_head_;
                free_head_=idx;
                idx=next;
            }
            slot.head=kEmpty;
            slot.cid_count=0;
            slot.active=false;
            --size_;
            return true;
        }
        auto clear() noexcept -> void {
            buckets_.fill(kEmpty);
            for (std::size_t i=0;i<next_alloc_;++i) ids_[i]={};
            for (auto& slot:slots_) { slot.active=false; slot.head=kEmpty; slot.cid_count=0; }
            next_alloc_=0;
            free_head_=kEmpty;
            size_=0;
        }
        auto size() const noexcept -> std::size_t { return size_; }
    };
}
