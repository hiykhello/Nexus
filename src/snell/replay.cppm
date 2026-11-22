export module snell.replay;
import std;
export namespace snell {
    // One fixed table per immutable credential epoch. Only authenticated salts
    // may be published; no unexpired entry is evicted to admit another salt.
    // Hash probing is bounded; a time heap reclaims expired slots without
    // scanning live entries. The lock covers both structures and the claim.
    template<std::size_t Capacity> class ReplayCache {
        static_assert(Capacity>0 && Capacity<std::numeric_limits<std::uint32_t>::max()/2);
        using Clock=std::chrono::steady_clock;using Index=std::uint32_t;
        static constexpr Index none=std::numeric_limits<Index>::max();
        static constexpr std::size_t buckets=std::bit_ceil(Capacity*2);
        struct Entry {std::array<std::uint8_t,16> salt{};Clock::time_point expires{};Index next=none,previous=none,bucket=none;};
        std::array<Entry,Capacity> entries_{};std::array<Index,buckets> heads_{};std::array<Index,Capacity> heap_{};
        std::size_t used_=0;Index free_=none;std::mutex lock_;
        static auto hash(std::span<std::uint8_t const,16> salt) noexcept ->std::size_t {
            std::uint64_t h=14695981039346656037ULL;for(auto b:salt){h^=b;h*=1099511628211ULL;}
            h^=h>>33;h*=0xff51afd7ed558ccdULL;h^=h>>33;return static_cast<std::size_t>(h)&(buckets-1);
        }
        auto less(Index a,Index b) const noexcept ->bool {return entries_[a].expires<entries_[b].expires;}
        auto push(Index index) noexcept ->void {
            auto pos=used_++;while(pos){auto parent=(pos-1)/2;if(!less(index,heap_[parent]))break;heap_[pos]=heap_[parent];pos=parent;}heap_[pos]=index;
        }
        auto pop() noexcept ->Index {
            auto first=heap_[0],last=heap_[--used_];if(!used_)return first;std::size_t pos=0;
            while(pos*2+1<used_){auto child=pos*2+1;if(child+1<used_&&less(heap_[child+1],heap_[child]))++child;if(!less(heap_[child],last))break;heap_[pos]=heap_[child];pos=child;}heap_[pos]=last;return first;
        }
        auto release(Index index) noexcept ->void {
            auto& entry=entries_[index];if(entry.previous==none)heads_[entry.bucket]=entry.next;else entries_[entry.previous].next=entry.next;
            if(entry.next!=none)entries_[entry.next].previous=entry.previous;entry.bucket=none;entry.previous=none;entry.next=free_;free_=index;
        }
    public:
        enum class Result { accepted,replay,full,invalid_lifetime };
        ReplayCache(){heads_.fill(none);for(std::size_t i=Capacity;i>0;--i){entries_[i-1].next=free_;free_=static_cast<Index>(i-1);}}
        ReplayCache(ReplayCache const&)=delete;auto operator=(ReplayCache const&) -> ReplayCache& =delete;
        [[nodiscard]] auto publish(std::span<std::uint8_t const,16> salt,Clock::time_point now,Clock::duration lifetime)->Result {
            if(lifetime<=Clock::duration::zero() || now>Clock::time_point::max()-lifetime)return Result::invalid_lifetime;
            std::lock_guard guard(lock_);while(used_&&entries_[heap_[0]].expires<=now)release(pop());
            auto bucket=static_cast<Index>(hash(salt));for(auto i=heads_[bucket];i!=none;i=entries_[i].next)if(std::ranges::equal(entries_[i].salt,salt))return Result::replay;
            if(free_==none)return Result::full;auto index=free_;auto& entry=entries_[index];free_=entry.next;
            std::ranges::copy(salt,entry.salt.begin());entry.expires=now+lifetime;entry.bucket=bucket;entry.previous=none;entry.next=heads_[bucket];
            if(entry.next!=none)entries_[entry.next].previous=index;heads_[bucket]=index;push(index);return Result::accepted;
        }
    };
}
