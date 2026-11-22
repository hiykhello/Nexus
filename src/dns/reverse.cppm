export module dns.reverse;
import std;
import dns.message;

export namespace dns {
    struct ReverseToken { std::uint64_t generation, epoch; };
    struct ReverseName {
        std::array<char,253> bytes{};
        std::uint8_t size=0;
        [[nodiscard]] auto view() const noexcept -> std::string_view { return {bytes.data(),size}; }
    };
    enum class ReverseRecord { stored, ignored, invalid, stale, unavailable };

    // Optional passive index, owned by one DNS generation. Validated positive
    // answers only: callers establish authenticity, view and remaining TTL.
    // All storage is reserved at construction; lookup and publication allocate
    // nothing. A lost observation suspends all lookups until it expires.
    class ReverseCache {
        friend class ReverseTransaction;
        enum class State : std::uint8_t { empty, occupied, deleted };
        struct Key { std::uint64_t view; std::array<std::uint8_t,16> bytes; std::uint8_t size; };
        static constexpr std::uint16_t no_name=std::numeric_limits<std::uint16_t>::max();
        struct Slot { Key key{}; std::uint64_t expires=0; std::uint16_t name=no_name; State state=State::empty; };
        struct NameEntry { ReverseName name{}; std::uint16_t next=no_name; };
        mutable std::mutex mutex_;
        std::vector<Slot> slots_, scratch_;
        std::vector<NameEntry> names_;
        std::uint16_t free_name_=no_name;
        std::size_t capacity_, count_=0, deleted_=0, storage_bytes_=0;
        std::uint64_t generation_, epoch_=1, watermark_=0, suspended_until_=0;
        // Conservative lower bound on every occupied expiry. It may lag after
        // removals, but must never exceed any live expiry.
        std::uint64_t earliest_expiry_=std::numeric_limits<std::uint64_t>::max();
        std::array<std::uint64_t,2> hash_key_;
        bool disabled_=false;

        static auto name_valid(std::string_view name) noexcept -> bool {
            if (name.empty() || name.size()>253) return false;
            std::size_t start=0;
            for (std::size_t i=0;i<=name.size();++i) {
                if (i==name.size() || name[i]=='.') {
                    if (i==start || i-start>63 || name[start]=='-' || name[i-1]=='-') return false;
                    start=i+1;
                } else {
                    char c=name[i];
                    if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return false;
                }
            }
            return true;
        }
        static auto lower(char c) noexcept -> char { return c>='A' && c<='Z' ? static_cast<char>(c+('a'-'A')) : c; }
        static auto canonical(Address address) noexcept -> std::optional<Address> {
            if (address.size==4) {
                if (std::any_of(address.bytes.begin()+4,address.bytes.end(),[](auto b) { return b!=0; })) return {};
            } else if (address.size==16) {
                if (std::all_of(address.bytes.begin(),address.bytes.begin()+10,[](auto b) { return b==0; }) &&
                    address.bytes[10]==0xff && address.bytes[11]==0xff) {
                    std::copy(address.bytes.begin()+12,address.bytes.end(),address.bytes.begin());
                    std::fill(address.bytes.begin()+4,address.bytes.end(),0);
                    address.size=4;
                }
            } else return {};
            return address;
        }
        auto hash(Key const& key) const noexcept -> std::size_t {
            // SipHash-2-4 over view, canonical address and its family. The
            // generation owner supplies an unpredictable per-instance key.
            auto v0=hash_key_[0]^0x736f6d6570736575ULL, v1=hash_key_[1]^0x646f72616e646f6dULL;
            auto v2=hash_key_[0]^0x6c7967656e657261ULL, v3=hash_key_[1]^0x7465646279746573ULL;
            auto round=[&] {
                v0+=v1; v1=std::rotl(v1,13); v1^=v0; v0=std::rotl(v0,32);
                v2+=v3; v3=std::rotl(v3,16); v3^=v2;
                v0+=v3; v3=std::rotl(v3,21); v3^=v0;
                v2+=v1; v1=std::rotl(v1,17); v1^=v2; v2=std::rotl(v2,32);
            };
            auto block=[&](std::uint64_t word) { v3^=word; round(); round(); v0^=word; };
            block(key.view);
            for (std::size_t offset=0;offset<16;offset+=8) {
                std::uint64_t word=0;
                for (unsigned i=0;i<8;++i) word|=std::uint64_t(key.bytes[offset+i])<<(8*i);
                block(word);
            }
            block((std::uint64_t{25}<<56)|key.size);
            v2^=0xff; round(); round(); round(); round();
            return static_cast<std::size_t>(v0^v1^v2^v3);
        }
        static auto same(Key const& a,Key const& b) noexcept -> bool {
            return a.view==b.view && a.size==b.size && a.bytes==b.bytes;
        }
        auto release_name(std::uint16_t index) noexcept -> void {
            if (index==no_name) return;
            names_[index].next=free_name_; free_name_=index;
        }
        auto reset_names() noexcept -> void {
            for (std::size_t i=0;i<names_.size();++i)
                names_[i].next=i+1<names_.size() ? static_cast<std::uint16_t>(i+1) : no_name;
            free_name_=names_.empty() ? no_name : 0;
        }
        auto erase(Slot& slot) noexcept -> void {
            release_name(slot.name); slot.name=no_name;
            slot.state=State::deleted; --count_; ++deleted_;
        }
        auto advance(std::uint64_t now) noexcept -> void { watermark_=std::max(watermark_,now); }
        // Returns a matching slot and an insertion position; expired entries
        // become tombstones so later keys in a probe chain remain visible.
        auto find(Key const& key) noexcept -> std::pair<std::optional<std::size_t>,std::optional<std::size_t>> {
            auto start=hash(key)%slots_.size();
            std::optional<std::size_t> free;
            for (std::size_t i=0;i<slots_.size();++i) {
                auto index=(start+i)%slots_.size(); auto& slot=slots_[index];
                if (slot.state==State::occupied && slot.expires<=watermark_) erase(slot);
                if (slot.state==State::empty) return {{},free ? free : std::optional<std::size_t>(index)};
                if (slot.state==State::deleted) { if (!free) free=index; continue; }
                if (same(slot.key,key)) return {index,free};
            }
            return {{},free};
        }
        auto sweep() noexcept -> void {
            earliest_expiry_=std::numeric_limits<std::uint64_t>::max();
            for (auto& slot:slots_) {
                if (slot.state!=State::occupied) continue;
                if (slot.expires<=watermark_) erase(slot);
                else earliest_expiry_=std::min(earliest_expiry_,slot.expires);
            }
        }
        // Rebuild into reserved storage, so churn cannot leave an unbounded
        // chain of tombstones or allocate during publication and lookup.
        auto compact() noexcept -> void {
            std::fill(scratch_.begin(),scratch_.end(),Slot{});
            earliest_expiry_=std::numeric_limits<std::uint64_t>::max();
            for (auto const& slot:slots_) {
                if (slot.state!=State::occupied) continue;
                if (slot.expires<=watermark_) { release_name(slot.name); --count_; continue; }
                earliest_expiry_=std::min(earliest_expiry_,slot.expires);
                auto index=hash(slot.key)%scratch_.size();
                while (scratch_[index].state==State::occupied) index=(index+1)%scratch_.size();
                scratch_[index]=slot;
            }
            slots_.swap(scratch_); deleted_=0;
        }
        auto compact_if_needed() noexcept -> void { if (deleted_>capacity_/2) compact(); }
    public:
        static constexpr std::size_t max_capacity=4096;
        static_assert(max_capacity<no_name);
        explicit ReverseCache(std::size_t capacity,std::uint64_t generation,std::array<std::uint64_t,2> hash_key)
            : capacity_(capacity),generation_(generation),hash_key_(hash_key) {
            if (!capacity || capacity>max_capacity || !generation) throw std::invalid_argument("invalid reverse cache capacity or generation");
            slots_.resize(capacity*2+1);
            scratch_.resize(capacity*2+1);
            names_.resize(capacity);
            reset_names();
            storage_bytes_=(slots_.capacity()+scratch_.capacity())*sizeof(Slot)+names_.capacity()*sizeof(NameEntry);
        }
        ReverseCache(ReverseCache const&)=delete;
        auto operator=(ReverseCache const&) -> ReverseCache& = delete;
        [[nodiscard]] auto storage_bytes() const noexcept -> std::size_t {
            return storage_bytes_;
        }
        [[nodiscard]] auto token() const -> ReverseToken { std::lock_guard lock(mutex_); return {generation_,epoch_}; }
        // A clear invalidates outstanding tokens; overflow disables the cache.
        auto clear() -> bool {
            std::lock_guard lock(mutex_);
            if (epoch_==std::numeric_limits<std::uint64_t>::max()) { disabled_=true; return false; }
            ++epoch_; count_=0; deleted_=0; suspended_until_=0;
            earliest_expiry_=std::numeric_limits<std::uint64_t>::max();
            for (auto& slot:slots_) slot=Slot{};
            reset_names();
            return true;
        }
        [[nodiscard]] auto record(std::uint64_t view,std::string_view name,std::span<Address const> addresses,
                                  std::uint32_t ttl,std::uint64_t now,ReverseToken token) -> ReverseRecord {
            if (!name_valid(name) || addresses.empty() || addresses.size()>128) return ReverseRecord::invalid;
            for (auto address:addresses) if (!canonical(address)) return ReverseRecord::invalid;
            std::lock_guard lock(mutex_);
            if (disabled_) return ReverseRecord::unavailable;
            if (token.generation!=generation_ || token.epoch!=epoch_) return ReverseRecord::stale;
            advance(now);
            auto duration=std::uint64_t(ttl)*1000;
            auto expires=now>std::numeric_limits<std::uint64_t>::max()-duration ? std::numeric_limits<std::uint64_t>::max() : now+duration;
            if (!ttl || expires<=watermark_) return ReverseRecord::ignored;
            compact_if_needed();
            bool lost=false, swept=false;
            for (auto address:addresses) {
                auto normalized=*canonical(address);
                Key key{view,normalized.bytes,normalized.size};
                auto [found,free]=find(key);
                if (!found && count_>=capacity_ && !swept && watermark_>=earliest_expiry_) {
                    sweep(); compact_if_needed(); swept=true; std::tie(found,free)=find(key);
                }
                if (!found) {
                    if (count_>=capacity_ || !free) { suspended_until_=std::max(suspended_until_,expires); lost=true; continue; }
                    auto& slot=slots_[*free];
                    if (slot.state==State::deleted) --deleted_;
                    // At most one name per occupied slot; ambiguous entries
                    // release their name but remain occupied until expiry.
                    auto name_index=free_name_;
                    free_name_=names_[name_index].next;
                    slot=Slot{key,expires,name_index,State::occupied}; ++count_;
                    earliest_expiry_=std::min(earliest_expiry_,expires);
                    auto& stored=names_[name_index].name;
                    stored=ReverseName{};
                    stored.size=static_cast<std::uint8_t>(name.size());
                    std::transform(name.begin(),name.end(),stored.bytes.begin(),lower);
                    continue;
                }
                auto& slot=slots_[*found];
                if (slot.name!=no_name) {
                    auto const& stored=names_[slot.name].name;
                    if (stored.size!=name.size() ||
                        !std::equal(name.begin(),name.end(),stored.bytes.begin(),[](char a,char b) { return lower(a)==b; })) {
                        release_name(slot.name); slot.name=no_name; // Ambiguous until expiry.
                    }
                }
                slot.expires=std::max(slot.expires,expires);
            }
            return lost ? ReverseRecord::unavailable : ReverseRecord::stored;
        }
        // Scoped IPv6 has no trustworthy scope in a DNS address answer; callers
        // must pass its nonzero scope to avoid using an unscoped mapping.
        [[nodiscard]] auto lookup(std::uint64_t view,Address address,std::uint64_t now,std::uint32_t scope=0)
            -> std::optional<ReverseName> {
            auto normalized=canonical(address);
            if (!normalized || scope) return {};
            std::lock_guard lock(mutex_);
            advance(now);
            if (disabled_ || suspended_until_>watermark_) return {};
            compact_if_needed();
            Key key{view,normalized->bytes,normalized->size};
            auto [found,free]=find(key); (void)free;
            if (!found || slots_[*found].name==no_name) return {};
            return names_[slots_[*found].name].name;
        }
    };

    // Stages both families until the resolver has accepted the entire result.
    // `started_ms` must be captured no later than the beginning of the query
    // that produces the answer. This conservatively avoids extending an RR's
    // lifetime while a network query or coalesced waiter is suspended.
    enum class ReverseCommit { published, empty, invalid, stale, unavailable };
    class ReverseTransaction {
        struct Batch { std::array<Address,64> addresses{}; std::size_t count=0; std::uint64_t started=0,expires=0; };
        ReverseCache& cache_;
        ReverseToken token_;
        std::uint64_t view_;
        ReverseName query_{},canonical_{};
        std::array<Batch,2> batches_{};
        std::size_t stages_=0,total_=0;
        bool valid_=true,finished_=false,canonical_set_=false;
        static auto equal_name(std::string_view a,std::string_view b) noexcept -> bool {
            return a.size()==b.size() && std::equal(a.begin(),a.end(),b.begin(),[](char x,char y) {
                return ReverseCache::lower(x)==ReverseCache::lower(y);
            });
        }
        static auto assign(ReverseName& output,std::string_view name) noexcept -> bool {
            if (!ReverseCache::name_valid(name)) return false;
            output.size=static_cast<std::uint8_t>(name.size());
            std::transform(name.begin(),name.end(),output.bytes.begin(),ReverseCache::lower);
            return true;
        }
    public:
        ReverseTransaction(ReverseCache& cache,std::uint64_t view,std::string_view query)
            : ReverseTransaction(cache,cache.token(),view,query) {}
        ReverseTransaction(ReverseCache& cache,ReverseToken token,std::uint64_t view,std::string_view query)
            : cache_(cache),token_(token),view_(view) { valid_=assign(query_,query); }
        ReverseTransaction(ReverseTransaction const&)=delete;
        auto operator=(ReverseTransaction const&) -> ReverseTransaction& = delete;
        // Answers must already be authenticated and parsed by the resolver.
        // `fresh` is false for optimistic stale cache responses: they can
        // participate in consistency checks but never create a mapping.
        auto stage(AddressAnswer const& answer,bool fresh,std::uint64_t started_ms) noexcept -> bool {
            if (!valid_ || finished_ || stages_==batches_.size()) { valid_=false; return false; }
            auto& batch=batches_[stages_++];
            if (answer.chain.empty() || !equal_name(answer.chain.front(),query_.view()) ||
                !equal_name(answer.chain.back(),answer.canonical_name) ||
                !ReverseCache::name_valid(answer.canonical_name) || answer.addresses.size()>64-total_) {
                valid_=false; return false;
            }
            if (canonical_set_ && !equal_name(canonical_.view(),answer.canonical_name)) { valid_=false; return false; }
            if (!canonical_set_) { (void)assign(canonical_,answer.canonical_name); canonical_set_=true; }
            for (auto address:answer.addresses)
                if (!ReverseCache::canonical(address)) { valid_=false; return false; }
            total_+=answer.addresses.size();
            if (!fresh || !answer.ttl || !*answer.ttl || answer.addresses.empty()) return true;
            auto duration=std::uint64_t(*answer.ttl)*1000;
            batch.started=started_ms;
            batch.expires=started_ms>std::numeric_limits<std::uint64_t>::max()-duration ?
                std::numeric_limits<std::uint64_t>::max() : started_ms+duration;
            batch.count=answer.addresses.size();
            std::copy(answer.addresses.begin(),answer.addresses.end(),batch.addresses.begin());
            return true;
        }
        // `accepted` is true only after all family consistency, cancellation,
        // and address-count checks have succeeded. It is one-shot.
        [[nodiscard]] auto finish(bool accepted,std::uint64_t now_ms) -> ReverseCommit {
            if (finished_) return ReverseCommit::invalid;
            finished_=true;
            if (!accepted) return ReverseCommit::empty;
            if (!valid_) return ReverseCommit::invalid;
            for (auto const& batch:batches_) if (batch.count && now_ms<batch.started) return ReverseCommit::invalid;
            bool published=false;
            for (auto const& batch:batches_) {
                if (!batch.count || batch.expires<=now_ms) continue;
                auto remaining=(batch.expires-now_ms)/1000;
                if (!remaining) continue;
                auto status=cache_.record(view_,query_.view(),std::span(batch.addresses.data(),batch.count),
                                          static_cast<std::uint32_t>(remaining),now_ms,token_);
                if (status==ReverseRecord::stale) return ReverseCommit::stale;
                if (status==ReverseRecord::unavailable) return ReverseCommit::unavailable;
                if (status==ReverseRecord::invalid) return ReverseCommit::invalid;
                published|=status==ReverseRecord::stored;
            }
            return published ? ReverseCommit::published : ReverseCommit::empty;
        }
    };
}
