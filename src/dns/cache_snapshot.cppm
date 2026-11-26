export module dns.cache_snapshot;
import std;
import dns.message;
export import dns.cache_types;

export {
// Immutable DNS snapshots. All writers serialize; each reader exclusively
// owns one synchronous guard.
namespace dns::detail {
#ifdef DNS_SEMANTIC_TEST_HOOK
namespace snapshot_test {
void after_advance_for_test();
void after_snapshot_load_for_test(void const* snapshot);
}
#endif
template<bool Ordered>
class BasicSnapshotState {
    using Key=dns::CacheKey;
    using Token=dns::CacheToken;
    using Error=dns::CacheError;
    using Answer=dns::AddressAnswer;
    using Negative=dns::NegativeKind;
    static constexpr std::size_t maximum=256,slots=Ordered ? maximum : 512;
    static constexpr std::uint32_t deleted_tag=2;
    struct Node {
        // Only the serialized writer touches refs. Separate its cache line from
        // the immutable data read through a protected snapshot.
        alignas(64) std::size_t refs=1;
        alignas(64) Key key;
        Answer answer;
        std::optional<Negative> negative;
        std::uint64_t expires,revision,order;
        std::size_t hash;
        Node(Key k,Answer a,std::optional<Negative> n,std::uint64_t e,std::uint64_t r,std::uint64_t o)
            : key(std::move(k)),answer(std::move(a)),negative(n),expires(e),revision(r),order(o),hash(Ordered ? 0 : SnapshotKeyHash{}(key)) {}
    };
    struct Snapshot {
        std::array<Node*,slots> values{};
        std::array<std::uint32_t,Ordered ? 0 : slots> tags{};
        std::size_t count=0,tombstones=0;
        std::uint64_t generation=1,now=0,next_order=0;
        bool initialized=false;
        Snapshot* next=nullptr;
    };
    // Reserve the bounded pool up front, but initialize a slot only when a
    // writer first needs it. Idle reader slots therefore do not touch pages.
    struct SnapshotPool {
        static_assert(std::is_nothrow_default_constructible_v<Snapshot>);
        std::allocator<Snapshot> allocator;
        Snapshot* storage;
        std::size_t capacity,used=0;
        explicit SnapshotPool(std::size_t count) : storage(allocator.allocate(count)),capacity(count) {}
        SnapshotPool(SnapshotPool const&)=delete;
        ~SnapshotPool() {
            for (std::size_t i=0;i<used;++i) std::destroy_at(storage+i);
            allocator.deallocate(storage,capacity);
        }
        auto create() noexcept -> Snapshot* {
            if (used==capacity) std::terminate();
            return std::construct_at(storage+used++);
        }
        auto operator[](std::size_t index) noexcept -> Snapshot& { return storage[index]; }
    };
    struct alignas(64) Hazard { std::atomic<Snapshot*> pointer=nullptr; std::atomic<bool> claimed=false; };
    struct Pending { Key key; std::uint64_t query; std::optional<std::uint64_t> refresh_revision; };
    std::size_t capacity_,reader_count_,pool_count_;
    std::uint64_t stale_window_ms_,next_query_=0;
    std::unique_ptr<Hazard[]> hazards_;
    SnapshotPool pool_;
    Snapshot* free_=nullptr;
    Snapshot* retired_=nullptr;
    std::atomic<Snapshot*> current_;
    mutable std::mutex mutex_;
    PendingIndex<Pending> pending_;
    std::size_t refresh_count_=0;

    static auto checked_readers(std::size_t readers) -> std::size_t {
        // Up to sixteen configured listeners with up to 256 workers each, plus
        // the separately driven UDP executor in the command process.
        if (readers>16*256+1) throw std::out_of_range("too many readers");
        return readers;
    }

    static auto same(Key const& a,Key const& b) noexcept -> bool { return SnapshotKeyEqual{}(a,b); }
    static auto less(Key const& a,Key const& b) noexcept -> bool {
        if (a.view!=b.view) return a.view<b.view;
        if (a.type!=b.type) return a.type<b.type;
        return a.name<b.name;
    }
    static auto lower_bound(Snapshot const& snapshot,Key const& key) noexcept -> std::size_t {
        std::size_t first=0,last=snapshot.count;
        while (first<last) {
            auto middle=first+(last-first)/2;
            if (less(snapshot.values[middle]->key,key)) first=middle+1; else last=middle;
        }
        return first;
    }
    static auto normalize(Key& key) -> bool {
        return (key.type==1 || key.type==28) && dns::canonicalize_name(key.name);
    }
    static auto valid_answer(Answer const& answer,std::uint16_t type) -> bool {
        if (answer.addresses.empty() || answer.addresses.size()>128 || answer.chain.size()>16 ||
            answer.canonical_name.size()>254 || !answer.ttl) return false;
        for (auto const& name:answer.chain) if (name.size()>254) return false;
        for (auto const& address:answer.addresses) if (address.size!=(type==1 ? 4 : 16)) return false;
        return true;
    }
    static auto tag(std::size_t hash) noexcept -> std::uint32_t {
        auto value=static_cast<std::uint64_t>(hash);
        return static_cast<std::uint32_t>(value^(value>>32)) | 1u;
    }
    static auto find(Snapshot const& snapshot,Key const& key) noexcept -> std::size_t {
        if constexpr (Ordered) {
            auto index=lower_bound(snapshot,key);
            return index<snapshot.count && same(snapshot.values[index]->key,key) ? index : slots;
        } else {
            auto hash=SnapshotKeyHash{}(key),start=hash%slots;
            auto wanted=tag(hash);
            for (std::size_t probe=0;probe<slots;++probe) {
                auto index=(start+probe)%slots;
                if (!snapshot.tags[index]) return slots;
                if (snapshot.tags[index]!=wanted) continue;
                auto* node=snapshot.values[index];
                if (node->hash==hash && same(node->key,key)) return index;
            }
            return slots;
        }
    }
    static auto drop(Node* node) noexcept -> void { if (--node->refs==0) delete node; }
    auto recycle(Snapshot* snapshot) noexcept -> void {
        for (auto& node:snapshot->values) if (node) { drop(node); node=nullptr; }
        snapshot->tags.fill(0);
        snapshot->count=0; snapshot->tombstones=0; snapshot->generation=1; snapshot->now=0; snapshot->next_order=0; snapshot->initialized=false;
        snapshot->next=free_; free_=snapshot;
    }
    auto collect() noexcept -> void {
        auto** link=&retired_;
        while (auto* snapshot=*link) {
            bool guarded=false;
            for (std::size_t i=0;i<reader_count_;++i)
                if (hazards_[i].pointer.load()==snapshot) { guarded=true; break; }
            if (guarded) link=&snapshot->next;
            else { *link=snapshot->next; recycle(snapshot); }
        }
    }
    auto acquire() noexcept -> Snapshot* {
        collect();
        // At most one current snapshot and reader_count_ retired snapshots are
        // protected. The pool has one further slot for the current writer.
        if (!free_) return pool_.create();
        auto* result=free_; free_=free_->next; result->next=nullptr; return result;
    }
    auto clone(Snapshot const& source) noexcept -> Snapshot* {
        auto* result=acquire();
        result->values=source.values;
        result->tags=source.tags;
        for (auto* node:result->values) if (node) ++node->refs;
        result->count=source.count; result->tombstones=source.tombstones; result->generation=source.generation; result->now=source.now;
        result->next_order=source.next_order; result->initialized=source.initialized;
        return result;
    }
    static auto erase_at(Snapshot& snapshot,std::size_t index) noexcept -> void {
        drop(snapshot.values[index]);
        if constexpr (Ordered) {
            std::move(snapshot.values.begin()+index+1,snapshot.values.begin()+snapshot.count,snapshot.values.begin()+index);
            snapshot.values[--snapshot.count]=nullptr;
        } else {
            snapshot.values[index]=nullptr;
            snapshot.tags[index]=deleted_tag; --snapshot.count; ++snapshot.tombstones;
        }
    }
    static auto compact(Snapshot& snapshot) noexcept -> void {
        // Only the unpublished writer-owned snapshot is changed. Keeping a
        // tombstone until compaction preserves colliding probe chains.
        if constexpr (!Ordered) {
            auto nodes=snapshot.values;
            snapshot.values.fill(nullptr); snapshot.tags.fill(0); snapshot.tombstones=0;
            for (auto* node:nodes) if (node) {
                auto start=node->hash%slots;
                for (std::size_t probe=0;probe<slots;++probe) {
                    auto index=(start+probe)%slots;
                    if (!snapshot.values[index]) {
                        snapshot.values[index]=node; snapshot.tags[index]=tag(node->hash); break;
                    }
                }
            }
        }
    }
    auto commit(Snapshot* replacement) noexcept -> void {
        if (replacement->tombstones>=128) compact(*replacement);
        auto* old=current_.exchange(replacement);
        old->next=retired_; retired_=old; collect();
    }
    struct Builder {
        BasicSnapshotState& owner;
        Snapshot* snapshot;
        Builder(BasicSnapshotState& owner_,Snapshot* snapshot_) : owner(owner_),snapshot(snapshot_) {}
        Builder(Builder const&)=delete;
        ~Builder() { if (snapshot) owner.recycle(snapshot); }
        auto publish() noexcept -> void { owner.commit(snapshot); snapshot=nullptr; }
    };
    auto ordered(std::uint64_t now,Snapshot const& snapshot) const noexcept -> std::uint64_t {
        return snapshot.initialized ? std::max(now,snapshot.now) : now;
    }
    auto advance(Snapshot& snapshot,std::uint64_t now) -> std::expected<void,Error> {
        if (snapshot.initialized && now<snapshot.now) return std::unexpected(Error::time_reversed);
        snapshot.now=now; snapshot.initialized=true;
        for (std::size_t i=0;i<slots;) {
            auto* node=snapshot.values[i];
            if (node && now>=node->expires && (node->negative || now-node->expires>=stale_window_ms_)) {
                erase_at(snapshot,i);
                if constexpr (Ordered) continue;
            }
            ++i;
        }
        return {};
    }
    auto refresh_current(Snapshot const& snapshot,Pending const& pending) const noexcept -> bool {
        if (!pending.refresh_revision) return true;
        auto index=find(snapshot,pending.key);
        return index!=slots && !snapshot.values[index]->negative && snapshot.values[index]->revision==*pending.refresh_revision;
    }
    static auto remove(Snapshot& snapshot,Key const& key) noexcept -> void {
        auto index=find(snapshot,key);
        if (index!=slots) erase_at(snapshot,index);
    }
    auto install(Snapshot& snapshot,Key key,Answer answer,std::optional<Negative> negative,
                 std::uint64_t expires,std::uint64_t revision) -> std::expected<void,Error> {
        if (!compact_key_storage(key)) return std::unexpected(Error::invalid_key);
        auto existing=find(snapshot,key);
        std::size_t victim=slots;
        std::uint64_t order;
        if (existing!=slots) order=snapshot.values[existing]->order;
        else if (snapshot.count==capacity_) {
            for (std::size_t i=0;i<slots;++i) if (auto* node=snapshot.values[i]; node &&
                (victim==slots || node->expires<snapshot.values[victim]->expires ||
                 (node->expires==snapshot.values[victim]->expires && node->order<snapshot.values[victim]->order))) victim=i;
            if (victim==slots) std::terminate();
            order=snapshot.values[victim]->order;
        } else {
            if (snapshot.next_order==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
            order=snapshot.next_order+1;
        }
        auto node=std::make_unique<Node>(std::move(key),std::move(answer),negative,expires,revision,order);
        if (existing!=slots) {
            drop(snapshot.values[existing]); snapshot.values[existing]=node.release();
        } else {
            if (victim!=slots) erase_at(snapshot,victim);
            else snapshot.next_order=order;
            if constexpr (Ordered) {
                auto index=lower_bound(snapshot,node->key);
                std::move_backward(snapshot.values.begin()+index,snapshot.values.begin()+snapshot.count,
                                   snapshot.values.begin()+snapshot.count+1);
                snapshot.values[index]=node.release(); ++snapshot.count;
            } else {
                auto start=node->hash%slots,index=slots;
                for (std::size_t probe=0;probe<slots;++probe) {
                    auto candidate=(start+probe)%slots;
                    if (!snapshot.values[candidate]) { index=candidate; break; }
                }
                if (index==slots) std::terminate();
                if (snapshot.tags[index]==deleted_tag) --snapshot.tombstones;
                snapshot.tags[index]=tag(node->hash); snapshot.values[index]=node.release(); ++snapshot.count;
            }
        }
        return {};
    }
public:
    class Reader {
        BasicSnapshotState* owner_;
        Hazard* hazard_;
        bool busy_=false;
        friend class BasicSnapshotState;
        Reader(BasicSnapshotState& owner,std::size_t index) : owner_(&owner),hazard_(&owner.hazards_[index]) {
            if (hazard_->claimed.exchange(true)) throw std::logic_error("reader already registered");
        }
        auto protect() -> Snapshot* {
            Snapshot* snapshot;
            do {
                snapshot=owner_->current_.load();
#ifdef DNS_SEMANTIC_TEST_HOOK
                snapshot_test::after_snapshot_load_for_test(snapshot);
#endif
                hazard_->pointer.store(snapshot);
            } while (snapshot!=owner_->current_.load());
            return snapshot;
        }
    public:
        auto validate(BasicSnapshotState const& state) const -> void {
            if (owner_!=&state) throw std::invalid_argument("reader belongs to another cache");
            if (busy_) throw std::logic_error("reader is already active");
        }
        Reader(Reader const&)=delete;
        auto operator=(Reader const&) -> Reader& = delete;
        Reader(Reader&& other) noexcept : owner_(other.owner_),hazard_(other.hazard_) {
            if (other.busy_) std::terminate();
            other.owner_=nullptr; other.hazard_=nullptr;
        }
        ~Reader() {
            if (owner_) {
                if (busy_ || hazard_->pointer.load()!=nullptr) std::terminate();
                hazard_->claimed.store(false);
            }
        }
    };
    explicit BasicSnapshotState(std::size_t capacity,std::uint64_t stale_window_ms,std::size_t readers)
        : capacity_(std::min<std::size_t>(capacity,maximum)),reader_count_(checked_readers(readers)),pool_count_(reader_count_+2),
          stale_window_ms_(stale_window_ms),hazards_(std::make_unique<Hazard[]>(reader_count_)),
          pool_(pool_count_),current_(pool_.create()) {}
    BasicSnapshotState(BasicSnapshotState const&)=delete;
    ~BasicSnapshotState() {
        // No reader may outlive this object, including a reader between calls.
        for (std::size_t i=0;i<reader_count_;++i) if (hazards_[i].claimed.load()) std::terminate();
        for (std::size_t i=0;i<pool_.used;++i)
            for (auto*& node:pool_[i].values) if (node) { drop(node); node=nullptr; }
    }
    [[nodiscard]] auto reader(std::size_t index) -> Reader {
        if (index>=reader_count_) throw std::out_of_range("reader index");
        return Reader(*this,index);
    }
    [[nodiscard]] auto size() const -> std::size_t { std::lock_guard lock(mutex_); return current_.load()->count; }

    template<class Hook>
    [[nodiscard]] auto lookup_with_hook(Key key,std::uint64_t now,Reader& reader,Hook&& hook)
        -> std::expected<std::optional<Answer>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        reader.validate(*this);
        reader.busy_=true;
        struct Release { Hazard& hazard; bool& busy; ~Release() { hazard.pointer.store(nullptr); busy=false; } } release{*reader.hazard_,reader.busy_};
        auto* snapshot=reader.protect();
        auto index=find(*snapshot,key);
        if (index==slots) return std::optional<Answer>{};
        auto* node=snapshot->values[index];
        hook();
        now=ordered(now,*snapshot);
        if (node->negative || now>=node->expires || (node->expires-now)/1000==0) return std::optional<Answer>{};
        auto result=node->answer; result.ttl=static_cast<std::uint32_t>((node->expires-now)/1000);
        return std::optional<Answer>{std::move(result)};
    }
    [[nodiscard]] auto lookup(Key key,std::uint64_t now,Reader& reader) -> std::expected<std::optional<Answer>,Error> {
        return lookup_with_hook(std::move(key),now,reader,[] {});
    }
    [[nodiscard]] auto lookup_negative(Key key,std::uint64_t now,Reader& reader) -> std::expected<std::optional<Negative>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        reader.validate(*this);
        reader.busy_=true;
        struct Release { Hazard& hazard; bool& busy; ~Release() { hazard.pointer.store(nullptr); busy=false; } } release{*reader.hazard_,reader.busy_};
        auto* snapshot=reader.protect();
        auto index=find(*snapshot,key);
        if (index==slots) return std::optional<Negative>{};
        auto* node=snapshot->values[index]; now=ordered(now,*snapshot);
        if (!node->negative || now>=node->expires || (node->expires-now)/1000==0) return std::optional<Negative>{};
        return node->negative;
    }
    [[nodiscard]] auto lookup_stale(Key key,std::uint64_t now) -> std::expected<std::optional<dns::StaleAddressAnswer>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_); auto* current=current_.load(); now=ordered(now,*current);
        Builder builder{*this,clone(*current)};
        if (auto result=advance(*builder.snapshot,now); !result) return std::unexpected(result.error());
        builder.publish(); current=current_.load();
        auto index=find(*current,key);
        if (index==slots) return std::optional<dns::StaleAddressAnswer>{};
        auto* node=current->values[index];
        if (node->negative || now<node->expires) return std::optional<dns::StaleAddressAnswer>{};
        auto age=now-node->expires;
        if (stale_window_ms_-age<1000) return std::optional<dns::StaleAddressAnswer>{};
        auto answer=node->answer; answer.ttl=1;
        return std::optional<dns::StaleAddressAnswer>{{std::move(answer),age}};
    }
    [[nodiscard]] auto begin_query(Key key) -> std::expected<Token,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        auto const hash=SnapshotKeyHash{}(key);
        std::lock_guard lock(mutex_);
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        if (!compact_key_storage(key)) return std::unexpected(Error::invalid_key);
        auto query=next_query_+1;
        pending_.emplace(query,hash,Pending{std::move(key),query,{}}); next_query_=query;
        return Token{current_.load()->generation,query};
    }
    [[nodiscard]] auto begin_refresh(Key key,std::uint64_t now,std::size_t maximum)
        -> std::expected<std::optional<Token>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        auto const hash=SnapshotKeyHash{}(key);
        std::lock_guard lock(mutex_); auto* current=current_.load(); now=ordered(now,*current);
        Builder builder{*this,clone(*current)};
        if (auto result=advance(*builder.snapshot,now); !result) return std::unexpected(result.error());
        builder.publish(); current=current_.load();
        auto index=find(*current,key);
        if (index==slots) return std::optional<Token>{};
        auto* node=current->values[index];
        if (node->negative || now<node->expires || stale_window_ms_-(now-node->expires)<1000) return std::optional<Token>{};
        if (pending_.has_key(hash,[&](Pending const& item) { return same(item.key,key); })) return std::optional<Token>{};
        if (refresh_count_>=maximum) return std::optional<Token>{};
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        if (!compact_key_storage(key)) return std::unexpected(Error::invalid_key);
        auto query=next_query_+1;
        pending_.emplace(query,hash,Pending{std::move(key),query,node->revision}); ++refresh_count_; next_query_=query;
        return std::optional<Token>{Token{current->generation,query}};
    }
    [[nodiscard]] auto cancel_query(Token token) -> std::expected<void,Error> {
        std::lock_guard lock(mutex_);
        if (token.generation!=current_.load()->generation) return std::unexpected(Error::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending) return std::unexpected(Error::stale_query);
        if (pending_.at(*pending).refresh_revision) --refresh_count_;
        pending_.erase(*pending); return {};
    }
    [[nodiscard]] auto publish(Key key,Answer answer,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (!valid_answer(answer,key.type)) return std::unexpected(Error::invalid_answer);
        auto const hash=SnapshotKeyHash{}(key);
        std::lock_guard lock(mutex_); auto* current=current_.load(); now=ordered(now,*current);
        if (current->initialized && now<current->now) return std::unexpected(Error::time_reversed);
        if (token.generation!=current->generation) return std::unexpected(Error::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending || !same(pending_.at(*pending).key,key)) return std::unexpected(Error::stale_query);
        if (!capacity_) return std::unexpected(Error::disabled);
        auto duration=std::uint64_t(*answer.ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(Error::invalid_answer);
        if (duration && !compact_answer_storage(answer)) return std::unexpected(Error::invalid_answer);
        Builder builder{*this,clone(*current)};
        if (auto result=advance(*builder.snapshot,now); !result) return result;
#ifdef DNS_SEMANTIC_TEST_HOOK
        snapshot_test::after_advance_for_test();
#endif
        if (!refresh_current(*builder.snapshot,pending_.at(*pending))) { builder.publish(); return std::unexpected(Error::stale_query); }
        if (!duration) remove(*builder.snapshot,key);
        else if (auto result=install(*builder.snapshot,key,std::move(answer),{},now+duration,token.query); !result) return result;
        pending_.erase_key_if(hash,[&](std::uint64_t q,Pending const& item) { return q<=token.query && same(item.key,key); },
            [this](Pending const& item) { if (item.refresh_revision) --refresh_count_; });
        builder.publish(); return {};
    }
    [[nodiscard]] auto publish_negative(Key key,Negative kind,std::uint32_t ttl,std::uint64_t now,Token token)
        -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        auto const hash=SnapshotKeyHash{}(key);
        std::lock_guard lock(mutex_); auto* current=current_.load(); now=ordered(now,*current);
        if (current->initialized && now<current->now) return std::unexpected(Error::time_reversed);
        if (token.generation!=current->generation) return std::unexpected(Error::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending || !same(pending_.at(*pending).key,key)) return std::unexpected(Error::stale_query);
        if (!capacity_) return std::unexpected(Error::disabled);
        auto duration=std::uint64_t(ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(Error::invalid_answer);
        Builder builder{*this,clone(*current)};
        if (auto result=advance(*builder.snapshot,now); !result) return result;
        if (!refresh_current(*builder.snapshot,pending_.at(*pending))) { builder.publish(); return std::unexpected(Error::stale_query); }
        if (!duration) remove(*builder.snapshot,key);
        else if (auto result=install(*builder.snapshot,key,{},kind,now+duration,token.query); !result) return result;
        pending_.erase_key_if(hash,[&](std::uint64_t q,Pending const& item) { return q<=token.query && same(item.key,key); },
            [this](Pending const& item) { if (item.refresh_revision) --refresh_count_; });
        builder.publish(); return {};
    }
    [[nodiscard]] auto invalidate(Key key,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        auto const hash=SnapshotKeyHash{}(key);
        std::lock_guard lock(mutex_); auto* current=current_.load(); now=ordered(now,*current);
        if (current->initialized && now<current->now) return std::unexpected(Error::time_reversed);
        if (token.generation!=current->generation) return std::unexpected(Error::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending || !same(pending_.at(*pending).key,key)) return std::unexpected(Error::stale_query);
        Builder builder{*this,clone(*current)};
        if (auto result=advance(*builder.snapshot,now); !result) return result;
        if (!refresh_current(*builder.snapshot,pending_.at(*pending))) { builder.publish(); return std::unexpected(Error::stale_query); }
        remove(*builder.snapshot,key);
        pending_.erase_key_if(hash,[&](std::uint64_t q,Pending const& item) { return q<=token.query && same(item.key,key); },
            [this](Pending const& item) { if (item.refresh_revision) --refresh_count_; });
        builder.publish(); return {};
    }
    [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<void,Error> {
        std::lock_guard lock(mutex_); auto* current=current_.load(); now=ordered(now,*current);
        if (current->initialized && now<current->now) return std::unexpected(Error::time_reversed);
        if (current->generation==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        Builder builder{*this,acquire()};
        builder.snapshot->generation=current->generation+1;
        builder.snapshot->now=now; builder.snapshot->initialized=true;
        pending_.clear(); refresh_count_=0; next_query_=0; builder.publish(); return {};
    }
#ifdef DNS_SEMANTIC_TEST_HOOK
    [[nodiscard]] auto current_for_test() const noexcept -> void const* { return current_.load(); }
    [[nodiscard]] auto tombstones_for_test() const -> std::size_t {
        std::lock_guard lock(mutex_); return current_.load()->tombstones;
    }
#endif
};
}
}
