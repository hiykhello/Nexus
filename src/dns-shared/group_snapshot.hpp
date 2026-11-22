// Group snapshot cache. Include after the DNS imports.
// Executor and task ownership are managed separately.
#pragma once

namespace dns_hp_experiment {
class GroupSnapshot {
public:
    struct BudgetExceeded {};
private:
    using Key=dns::CacheKey;
    using Answer=dns::AddressAnswer;
    using Negative=dns::NegativeKind;
    using Stale=dns::StaleAddressAnswer;
    using Token=dns::CacheToken;
    using Error=dns::CacheError;
    static constexpr std::size_t groups_max=17,page_size=32;
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
    // Isolated ceiling for this experiment, not a product default.
    static constexpr std::size_t entries_max=8192,pages_max=512;
#elif defined(DNS_GROUP_CAPACITY_1024_EXPERIMENT)
    static constexpr std::size_t entries_max=1024,pages_max=64;
#else
    static constexpr std::size_t entries_max=256,pages_max=16;
#endif
    // Counts requested snapshot storage, including retired versions and the
    // unpublished writer copy. Allocator overhead and caller buffers are not
    // represented; a process-wide RSS limit needs additional accounting.
    class Budget {
        std::size_t limit_,used_=0,peak_=0;
    public:
        class Lease {
            friend class Budget;
            Budget* owner_=nullptr; std::size_t bytes_=0;
            Lease(Budget& owner,std::size_t bytes) noexcept : owner_(&owner),bytes_(bytes) {}
        public:
            Lease(Lease const&)=delete;
            auto operator=(Lease const&) -> Lease& = delete;
            Lease(Lease&& other) noexcept : owner_(std::exchange(other.owner_,nullptr)),bytes_(other.bytes_) {}
            auto operator=(Lease&&)=delete;
            ~Lease() { if (owner_) owner_->used_-=bytes_; }
        };
        explicit Budget(std::size_t limit) : limit_(limit) {}
        auto reserve(std::size_t bytes) -> Lease {
            if (bytes>limit_-used_) throw BudgetExceeded{};
            used_+=bytes; peak_=std::max(peak_,used_); return Lease(*this,bytes);
        }
        [[nodiscard]] auto used() const noexcept -> std::size_t { return used_; }
        [[nodiscard]] auto peak() const noexcept -> std::size_t { return peak_; }
    };
    struct Node {
        Budget::Lease lease;
        alignas(64) std::size_t refs=1;
        alignas(64) Key key;
        Answer answer;
        std::optional<Negative> negative;
        std::uint64_t expires,discard,revision;
        inline static std::atomic<std::size_t> live=0,peak=0;
        Node(Budget::Lease lease_,Key key_,Answer answer_,std::optional<Negative> negative_,std::uint64_t expires_,
             std::uint64_t discard_,std::uint64_t revision_)
            : lease(std::move(lease_)),key(std::move(key_)),answer(std::move(answer_)),negative(negative_),expires(expires_),discard(discard_),revision(revision_) {
            auto count=live.fetch_add(1,std::memory_order_relaxed)+1;
            auto previous=peak.load(std::memory_order_relaxed);
            while (previous<count && !peak.compare_exchange_weak(previous,count,std::memory_order_relaxed)) {}
        }
        ~Node() { live.fetch_sub(1,std::memory_order_relaxed); }
    };
    struct Binding { Node* node=nullptr; std::uint64_t order=0; };
    struct Page {
        Budget::Lease lease;
        std::size_t refs=1,count=0;
        std::uint64_t min_expiry=std::numeric_limits<std::uint64_t>::max(),min_discard=std::numeric_limits<std::uint64_t>::max(),min_order=0;
        std::array<Binding,page_size> values{};
        explicit Page(Budget::Lease lease_) : lease(std::move(lease_)) {}
        Page(Budget::Lease lease_,Page const& other)
            : lease(std::move(lease_)),count(other.count),min_expiry(other.min_expiry),min_discard(other.min_discard),
              min_order(other.min_order),values(other.values) {}
    };
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
    // Allocate only the directory slots actually needed by an active group.
    // Both directories count against the budget while a replacement is built.
    class Directory {
        std::unique_ptr<Page*[]> pages_;
        std::optional<Budget::Lease> lease_;
        std::size_t size_=0;
    public:
        auto size() const noexcept -> std::size_t { return size_; }
        auto begin() noexcept -> Page** { return pages_.get(); }
        auto begin() const noexcept -> Page* const* { return pages_.get(); }
        auto operator[](std::size_t i) noexcept -> Page*& { return pages_[i]; }
        auto operator[](std::size_t i) const noexcept -> Page* { return pages_[i]; }
        auto grow(Budget& budget,std::size_t desired) -> void {
            if (desired<=size_) return;
            auto next=std::min(pages_max,std::max(desired,size_ ? size_*2 : std::size_t{1}));
            if (next<desired) std::terminate();
            auto lease=budget.reserve(next*sizeof(Page*));
            auto pages=std::make_unique<Page*[]>(next);
            if (size_) std::copy_n(pages_.get(),size_,pages.get());
            pages_=std::move(pages);
            lease_.reset(); lease_.emplace(std::move(lease)); size_=next;
        }
    };
#endif
    struct Index {
        Budget::Lease lease;
        std::size_t refs=1,count=0,entries=0;
        std::uint64_t next_order=0;
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
        Directory pages;
#else
        std::array<Page*,pages_max> pages{};
#endif
        explicit Index(Budget::Lease lease_) : lease(std::move(lease_)) {}
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
        Index(Budget::Lease lease_,Index const& other,Budget& budget)
            : lease(std::move(lease_)),count(other.count),entries(other.entries),next_order(other.next_order) {
            pages.grow(budget,other.pages.size());
            if (count) std::copy_n(other.pages.begin(),count,pages.begin());
        }
#else
        Index(Budget::Lease lease_,Index const& other)
            : lease(std::move(lease_)),count(other.count),entries(other.entries),next_order(other.next_order),pages(other.pages) {}
#endif
    };
    struct Root {
        std::array<Index*,groups_max> groups{};
        std::uint64_t generation=1,now=0;
        bool initialized=false;
        Root* next=nullptr;
    };
    struct RootPool {
        std::allocator<Root> allocator;
        Root* storage;
        std::size_t capacity,used=0;
        explicit RootPool(std::size_t count) : storage(allocator.allocate(count)),capacity(count) {}
        RootPool(RootPool const&)=delete;
        ~RootPool() {
            for (std::size_t i=0;i<used;++i) std::destroy_at(storage+i);
            allocator.deallocate(storage,capacity);
        }
        auto create() noexcept -> Root* {
            static_assert(std::is_nothrow_default_constructible_v<Root>);
            if (used==capacity) std::terminate();
            return std::construct_at(storage+used++);
        }
    };
    struct alignas(64) Hazard { std::atomic<Root*> pointer=nullptr; std::atomic<bool> claimed=false; };
    struct Refresh { std::size_t source; std::uint64_t revision; };
    struct Pending { std::size_t group; Key key; std::uint64_t query; std::optional<Refresh> refresh; };
    std::array<std::size_t,groups_max> capacities_{};
    std::size_t group_count_,reader_count_;
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
    std::size_t total_capacity_=0,base_share_=0;
#endif
    std::uint64_t stale_window_ms_;
    Budget budget_;
    Budget::Lease fixed_;
    bool fail_closed_;
    std::chrono::milliseconds recovery_delay_;
    std::chrono::steady_clock::time_point recovery_deadline_{};
    // Even values enable reads, odd values disable the cache. Each transition
    // changes the epoch so a reader spanning disable+clear cannot return an
    // old root after re-enabling.
    std::atomic<std::uint64_t> gate_=0;
    std::unique_ptr<Hazard[]> hazards_;
    RootPool pool_;
    Root* free_=nullptr;
    Root* retired_=nullptr;
    std::atomic<Root*> current_;
    std::mutex mutex_;
    std::vector<Pending> pending_;
    std::uint64_t next_query_=0;

    static auto checked_groups(std::span<std::size_t const> groups) -> std::size_t {
        if (groups.empty() || groups.size()>groups_max || std::ranges::any_of(groups,[](auto capacity) { return capacity>entries_max; }))
            throw std::invalid_argument("invalid group capacities");
        return groups.size();
    }
    static auto checked_readers(std::size_t readers) -> std::size_t {
        // Sixteen listeners with sixteen workers, plus SS UDP lookup and
        // the ordered UDP routing context on its separately driven executor.
        if (readers>16*16+2) throw std::out_of_range("too many readers");
        return readers;
    }
    auto disable_locked() noexcept -> void {
        auto state=gate_.load();
        if (!(state&1)) {
            gate_.store(state+1);
            recovery_deadline_=std::chrono::steady_clock::now()+recovery_delay_;
        }
        pending_.clear();
    }
    auto disable_after_allocation_failure(std::uint64_t epoch,std::optional<Token> token={},std::size_t group=0,
                                          std::uint64_t view=0,std::string_view name={},std::uint16_t type=0,
                                          std::uint64_t now=0) -> void {
        if (!fail_closed_) return;
        std::lock_guard lock(mutex_);
        // A concurrent clear already discarded the old state. A late or
        // superseded publication must not disable its replacement generation.
        if (gate_.load()!=epoch) return;
        if (token) {
            auto* current=current_.load();
            if (token->generation!=current->generation) return;
            auto pending=std::ranges::find(pending_,token->query,&Pending::query);
            if (pending==pending_.end() || pending->group!=group) return;
            if (name!="." && name.ends_with('.')) name.remove_suffix(1);
            if (pending->key.view!=view || pending->key.type!=type || pending->key.name.size()!=name.size()) return;
            for (std::size_t i=0;i<name.size();++i) {
                auto c=name[i]; if (c>='A' && c<='Z') c=static_cast<char>(c-'A'+'a');
                if (pending->key.name[i]!=c) return;
            }
            if (pending->refresh) {
                auto* binding=find(current->groups[pending->refresh->source],pending->key);
                now=current->initialized ? std::max(now,current->now) : now;
                if (!binding || binding->node->negative || binding->node->revision!=pending->refresh->revision ||
                    (now>=binding->node->expires && now-binding->node->expires>=stale_window_ms_)) return;
            }
        }
        disable_locked();
    }
    auto check_group(std::size_t group) const -> void {
        if (group>=group_count_) throw std::out_of_range("group index");
    }
    static auto same(Key const& a,Key const& b) noexcept -> bool {
        return a.view==b.view && a.type==b.type && a.name==b.name;
    }
    static auto less(Key const& a,Key const& b) noexcept -> bool {
        if (a.view!=b.view) return a.view<b.view;
        if (a.type!=b.type) return a.type<b.type;
        return a.name<b.name;
    }
    static auto normalize(Key& key) -> bool {
        return (key.type==1 || key.type==28) && dns::canonicalize_name(key.name);
    }
    static auto valid(Answer const& answer,std::uint16_t type) -> bool {
        if (answer.addresses.empty() || answer.addresses.size()>128 || answer.chain.size()>16 ||
            answer.canonical_name.size()>254 || !answer.ttl) return false;
        for (auto const& name:answer.chain) if (name.size()>254) return false;
        for (auto const& address:answer.addresses) if (address.size!=(type==1 ? 4 : 16)) return false;
        return true;
    }
    static auto node_charge(Key const& key,Answer const& answer) noexcept -> std::size_t {
        // Inputs have already been validated and compacted to their documented
        // bounds; the extra byte accounts for each possible string terminator.
        auto bytes=sizeof(Node)+key.name.capacity()+1+answer.canonical_name.capacity()+1+
                   answer.chain.capacity()*sizeof(std::string)+answer.addresses.capacity()*sizeof(dns::Address);
        for (auto const& name:answer.chain) bytes+=name.capacity()+1;
        return bytes;
    }
    static auto drop_node(Node* node) noexcept -> void { if (--node->refs==0) delete node; }
    static auto drop_page(Page* page) noexcept -> void {
        if (--page->refs) return;
        for (std::size_t i=0;i<page->count;++i) drop_node(page->values[i].node);
        delete page;
    }
    static auto drop_index(Index* index) noexcept -> void {
        if (--index->refs) return;
        for (std::size_t i=0;i<index->count;++i) drop_page(index->pages[i]);
        delete index;
    }
    static auto summarize(Page& page) noexcept -> void {
        page.min_expiry=std::numeric_limits<std::uint64_t>::max();
        page.min_discard=std::numeric_limits<std::uint64_t>::max(); page.min_order=0;
        for (std::size_t i=0;i<page.count;++i) {
            auto const& binding=page.values[i];
            page.min_discard=std::min(page.min_discard,binding.node->discard);
            if (!i || std::pair{binding.node->expires,binding.order}<std::pair{page.min_expiry,page.min_order}) {
                page.min_expiry=binding.node->expires; page.min_order=binding.order;
            }
        }
    }
    static auto page_index(Index const& index,Key const& key) noexcept -> std::size_t {
        std::size_t first=0,last=index.count;
        while (first<last) {
            auto middle=first+(last-first)/2;
            if (!less(key,index.pages[middle]->values[0].node->key)) first=middle+1; else last=middle;
        }
        return first ? first-1 : 0;
    }
    static auto lower(Page const& page,Key const& key) noexcept -> std::size_t {
        std::size_t first=0,last=page.count;
        while (first<last) {
            auto middle=first+(last-first)/2;
            if (less(page.values[middle].node->key,key)) first=middle+1; else last=middle;
        }
        return first;
    }
    static auto find(Index const* index,Key const& key) noexcept -> Binding const* {
        if (!index || !index->count) return nullptr;
        auto* page=index->pages[page_index(*index,key)]; auto position=lower(*page,key);
        return position<page->count && same(page->values[position].node->key,key) ? &page->values[position] : nullptr;
    }
    auto recycle(Root* root) noexcept -> void {
        for (auto& group:root->groups) if (group) { drop_index(group); group=nullptr; }
        root->generation=1; root->now=0; root->initialized=false;
        root->next=free_; free_=root;
    }
    auto collect() noexcept -> void {
        auto** link=&retired_;
        while (auto* root=*link) {
            bool guarded=false;
            for (std::size_t i=0;i<reader_count_;++i) if (hazards_[i].pointer.load()==root) { guarded=true; break; }
            if (guarded) link=&root->next;
            else { *link=root->next; recycle(root); }
        }
    }
    auto clone(Root const& source) noexcept -> Root* {
        collect();
        auto* root=free_;
        if (root) { free_=root->next; root->next=nullptr; } else root=pool_.create();
        root->generation=source.generation; root->now=source.now; root->initialized=source.initialized;
        for (std::size_t i=0;i<group_count_;++i) {
            root->groups[i]=source.groups[i]; if (root->groups[i]) ++root->groups[i]->refs;
        }
        return root;
    }
    auto commit(Root* root) noexcept -> void {
        auto* old=current_.exchange(root); old->next=retired_; retired_=old; collect();
    }
    struct Builder {
        GroupSnapshot& owner; Root* root;
        ~Builder() { if (root) owner.recycle(root); }
        auto publish() noexcept -> void { owner.commit(root); root=nullptr; }
    };
    auto writable_index(Root& root,std::size_t group) -> Index& {
        auto* original=root.groups[group];
        if (!original) { root.groups[group]=new Index(budget_.reserve(sizeof(Index))); return *root.groups[group]; }
        if (original->refs==1) return *original;
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
        auto copy=std::make_unique<Index>(budget_.reserve(sizeof(Index)),*original,budget_);
#else
        auto copy=std::make_unique<Index>(budget_.reserve(sizeof(Index)),*original);
#endif
        for (std::size_t i=0;i<copy->count;++i) ++copy->pages[i]->refs;
        root.groups[group]=copy.release(); drop_index(original);
        return *root.groups[group];
    }
    auto writable_page(Index& index,std::size_t position) -> Page& {
        auto* original=index.pages[position];
        if (original->refs==1) return *original;
        auto copy=std::make_unique<Page>(budget_.reserve(sizeof(Page)),*original);
        for (std::size_t i=0;i<copy->count;++i) ++copy->values[i].node->refs;
        index.pages[position]=copy.release(); drop_page(original);
        return *index.pages[position];
    }
    auto erase(Index& index,std::size_t page_index_,std::size_t position) -> void {
        auto& page=writable_page(index,page_index_);
        drop_node(page.values[position].node);
        std::move(page.values.begin()+position+1,page.values.begin()+page.count,page.values.begin()+position);
        page.values[--page.count]={}; --index.entries;
        if (page.count) { summarize(page); return; }
        drop_page(index.pages[page_index_]);
        std::move(index.pages.begin()+page_index_+1,index.pages.begin()+index.count,index.pages.begin()+page_index_);
        index.pages[--index.count]=nullptr;
    }
    auto remove(Index& index,Key const& key) -> void {
        if (!index.count) return;
        auto page_number=page_index(index,key); auto* page=index.pages[page_number]; auto position=lower(*page,key);
        if (position<page->count && same(page->values[position].node->key,key)) erase(index,page_number,position);
    }
    auto prune(Index& index,std::uint64_t now) -> void {
        for (std::size_t i=0;i<index.count;) {
            if (index.pages[i]->min_discard>now) { ++i; continue; }
            auto& page=writable_page(index,i); std::size_t out=0;
            for (std::size_t j=0;j<page.count;++j) {
                auto binding=page.values[j];
                if (binding.node->expires<=now && (binding.node->negative || now-binding.node->expires>=stale_window_ms_)) {
                    drop_node(binding.node); --index.entries;
                } else page.values[out++]=binding;
            }
            for (std::size_t j=out;j<page.count;++j) page.values[j]={};
            page.count=out;
            if (out) { summarize(page); ++i; }
            else {
                drop_page(index.pages[i]);
                std::move(index.pages.begin()+i+1,index.pages.begin()+index.count,index.pages.begin()+i);
                index.pages[--index.count]=nullptr;
            }
        }
    }
    auto insert(Index& index,Node* node,std::uint64_t order) -> void {
        if (!index.count) {
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
            index.pages.grow(budget_,1);
#endif
            auto page=std::make_unique<Page>(budget_.reserve(sizeof(Page))); ++node->refs;
            page->values[0]={node,order}; page->count=1; summarize(*page);
            index.pages[0]=page.release(); index.count=1; index.entries=1; return;
        }
        auto i=page_index(index,node->key); auto& page=writable_page(index,i); auto position=lower(page,node->key);
        if (position<page.count && same(page.values[position].node->key,node->key)) {
            ++node->refs; drop_node(page.values[position].node); page.values[position].node=node; summarize(page); return;
        }
        if (page.count==page_size) {
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
            index.pages.grow(budget_,index.count+1);
#endif
            if (index.count==index.pages.size()) std::terminate();
            auto right=std::make_unique<Page>(budget_.reserve(sizeof(Page))); right->count=page.count/2;
            for (std::size_t j=0;j<right->count;++j) {
                right->values[j]=page.values[page.count/2+j]; page.values[page.count/2+j]={};
            }
            page.count/=2; summarize(page); summarize(*right);
            std::move_backward(index.pages.begin()+i+1,index.pages.begin()+index.count,index.pages.begin()+index.count+1);
            index.pages[i+1]=right.release(); ++index.count;
            if (!less(node->key,index.pages[i+1]->values[0].node->key)) ++i;
        }
        auto& target=*index.pages[i]; position=lower(target,node->key);
        std::move_backward(target.values.begin()+position,target.values.begin()+target.count,target.values.begin()+target.count+1);
        ++node->refs; target.values[position]={node,order}; ++target.count; ++index.entries; summarize(target);
    }
    auto merge_sparse(Index& index) -> void {
        for (std::size_t i=0;i+1<index.count;) {
            auto* right=index.pages[i+1];
            if (index.pages[i]->count+right->count>page_size) { ++i; continue; }
            auto& left=writable_page(index,i);
            for (std::size_t j=0;j<right->count;++j) {
                ++right->values[j].node->refs; left.values[left.count++]=right->values[j];
            }
            summarize(left); drop_page(right);
            std::move(index.pages.begin()+i+2,index.pages.begin()+index.count,index.pages.begin()+i+1);
            index.pages[--index.count]=nullptr;
        }
    }
    auto evict(Index& index) -> std::uint64_t {
        std::size_t victim=0;
        for (std::size_t i=1;i<index.count;++i)
            if (std::pair{index.pages[i]->min_expiry,index.pages[i]->min_order}<
                std::pair{index.pages[victim]->min_expiry,index.pages[victim]->min_order}) victim=i;
        auto* page=index.pages[victim]; std::size_t position=0;
        while (page->values[position].node->expires!=page->min_expiry || page->values[position].order!=page->min_order) ++position;
        auto order=page->values[position].order; erase(index,victim,position); return order;
    }
    auto admit(Index& index,Node* node,std::size_t capacity) -> std::expected<void,Error> {
        std::uint64_t order=0;
        if (auto* existing=find(&index,node->key)) order=existing->order;
        else if (index.entries==capacity) order=evict(index);
        else {
            if (index.next_order==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
            order=++index.next_order;
        }
        insert(index,node,order); return {};
    }
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
    auto memberships(Root const& root) const noexcept -> std::size_t {
        std::size_t total=0;
        for (std::size_t i=0;i<group_count_;++i) if (root.groups[i]) total+=root.groups[i]->entries;
        return total;
    }
    auto admit_shared(Root& root,std::size_t group,Node* node,std::uint64_t now) -> std::expected<void,Error> {
        auto& own=*root.groups[group];
        if (find(&own,node->key)) return admit(own,node,total_capacity_);
        auto total=memberships(root);
        if (total==total_capacity_) {
            // Reclaim expired members before displacing a usable answer. Only
            // indexes containing expired entries require a copy.
            for (std::size_t i=0;i<group_count_;++i) if (i!=group && root.groups[i]) {
                auto* index=root.groups[i];
                bool expired=false;
                for (std::size_t p=0;p<index->count && !expired;++p) expired=index->pages[p]->min_discard<=now;
                if (expired) {
                    auto& writable=writable_index(root,i); prune(writable,now); merge_sparse(writable);
                }
            }
            total=memberships(root);
        }
        if (total==total_capacity_) {
            if (own.entries<base_share_) {
                std::size_t victim=group,largest=0;
                for (std::size_t i=0;i<group_count_;++i) {
                    auto* index=root.groups[i];
                    auto count=index ? index->entries : 0;
                    auto excess=count>base_share_ ? count-base_share_ : 0;
                    if (excess>largest) { largest=excess; victim=i; }
                }
                // With all memberships occupied and this group below its
                // share, another group must be borrowing at least one slot.
                if (!largest || victim==group) std::terminate();
                auto& lender=writable_index(root,victim); (void)evict(lender); merge_sparse(lender);
            } else {
                // Once the group has its share, keep other groups' members
                // intact and replace the group's own earliest expiry.
                return admit(own,node,own.entries);
            }
        }
        return admit(own,node,total_capacity_);
    }
#endif
    static auto fresh(Binding const* binding,std::uint64_t now) noexcept -> bool {
#ifdef DNS_GROUP_ALLOW_SUBSECOND_EXPERIMENT
        // Experiment only: preserve the actual expiry and return TTL 0 for
        // the last fractional second. The default keeps its existing policy.
        return binding && now<binding->node->expires;
#else
        return binding && now<binding->node->expires && (binding->node->expires-now)/1000;
#endif
    }
    auto stale(Binding const* binding,std::uint64_t now) const noexcept -> bool {
        if (!binding || binding->node->negative || now<binding->node->expires) return false;
        auto age=now-binding->node->expires;
        return age<stale_window_ms_ && stale_window_ms_-age>=1000;
    }
    static auto copy_answer(Node const& node,std::uint64_t now) -> Answer {
        auto answer=node.answer; answer.ttl=static_cast<std::uint32_t>((node.expires-now)/1000); return answer;
    }
    struct Adopted {
        std::optional<Answer> answer;
        std::optional<Negative> negative;
        std::optional<Stale> stale;
        std::uint64_t expires=0;
    };
    enum class AdoptKind { positive,negative,stale };
    auto adopt(std::size_t group,Key const& key,std::uint64_t now,AdoptKind kind,std::uint64_t epoch)
        -> std::expected<std::optional<Adopted>,Error> {
        std::lock_guard lock(mutex_); auto* current=current_.load();
        if ((epoch&1) || gate_.load()!=epoch) return std::optional<Adopted>{};
        try {
        now=current->initialized ? std::max(now,current->now) : now;
        // The slow path may observe a later time than a successful reader.
        // Publish that observation even on a miss so an older sample from a
        // different executor cannot make a stale or expired entry fresh again.
        if (!current->initialized || current->now<now) {
            Builder time_update{*this,clone(*current)};
            time_update.root->now=now; time_update.root->initialized=true;
            time_update.publish(); current=current_.load();
        }
        auto* own=find(current->groups[group],key);
        auto usable=[&](Binding const* binding) {
            return kind==AdoptKind::stale ? stale(binding,now) : fresh(binding,now);
        };
        auto capture=[&](Node const& node) {
            Adopted result;
            result.expires=node.expires;
            if (kind==AdoptKind::stale) {
                auto answer=node.answer; answer.ttl=1;
                result.stale=Stale{std::move(answer),now-node.expires};
            }
            else if (node.negative) result.negative=node.negative;
            else result.answer=copy_answer(node,now);
            return result;
        };
        if (usable(own)) return std::optional<Adopted>(capture(*own->node));
        Node* node=nullptr;
        for (std::size_t i=0;i<group_count_;++i) if (i!=group) {
            auto* candidate=find(current->groups[i],key);
            if (usable(candidate)) { node=candidate->node; break; }
        }
        if (!node) return std::optional<Adopted>{};
        // A safe shared answer is still usable if a new membership cannot be
        // admitted. In particular, the cache byte budget may be exhausted by
        // pinned history even though this answer itself remains valid.
        auto result=capture(*node);
        try {
            Builder builder{*this,clone(*current)}; builder.root->now=now; builder.root->initialized=true;
            auto& index=writable_index(*builder.root,group); prune(index,now);
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
            if (auto admitted=admit_shared(*builder.root,group,node,now); !admitted) return result;
#else
            if (auto admitted=admit(index,node,capacities_[group]); !admitted) return result;
#endif
            merge_sparse(index); builder.publish();
        } catch (BudgetExceeded const&) { return result; }
        return std::optional<Adopted>(std::move(result));
        } catch (BudgetExceeded const&) {
            // Failed admission changes no answer; this request can resolve via
            // the network without invalidating other groups' current values.
            return std::optional<Adopted>{};
        }
    }
    auto clear_locked(std::uint64_t now) -> std::expected<void,Error> {
        auto* current=current_.load();
        now=current->initialized ? std::max(now,current->now) : now;
        if (gate_.load()==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        if (current->generation==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        Builder builder{*this,clone(*current)};
        for (auto& index:builder.root->groups) if (index) { drop_index(index); index=nullptr; }
        builder.root->generation=current->generation+1; builder.root->now=now; builder.root->initialized=true;
        pending_.clear(); next_query_=0; builder.publish();
        auto state=gate_.load();
        if (state&1) gate_.store(state+1);
        else if (state<=std::numeric_limits<std::uint64_t>::max()-2) gate_.store(state+2);
        else gate_.store(std::numeric_limits<std::uint64_t>::max());
        return {};
    }
    auto recover_locked() -> void {
        if (!(gate_.load()&1) || !recovery_delay_.count() || std::chrono::steady_clock::now()<recovery_deadline_) return;
        // Avoid repeatedly rebuilding and exhausting the budget while any old
        // reader still pins a snapshot. Disabled reads cannot acquire new pins.
        for (std::size_t i=0;i<reader_count_;++i) if (hazards_[i].pointer.load()) return;
        auto* current=current_.load();
        (void)clear_locked(current->initialized ? current->now : 0);
    }
public:
    // The deadline is in the same monotonic millisecond epoch as the lookup.
    // It is needed when a cached result is handed to a suspended waiter.
    struct Fresh {
        std::optional<Answer> answer;
        std::optional<Negative> negative;
        std::uint64_t expires;
    };
    class Reader {
        friend class GroupSnapshot;
        GroupSnapshot* owner_; Hazard* hazard_; bool busy_=false;
        Reader(GroupSnapshot& owner,std::size_t index) : owner_(&owner),hazard_(&owner.hazards_[index]) {
            if (hazard_->claimed.exchange(true)) throw std::logic_error("reader already registered");
        }
        auto protect() -> Root* {
            Root* root;
            do { root=owner_->current_.load(); hazard_->pointer.store(root); } while (root!=owner_->current_.load());
            return root;
        }
    public:
        Reader(Reader const&)=delete;
        auto operator=(Reader const&) -> Reader& = delete;
        Reader(Reader&& other) noexcept : owner_(other.owner_),hazard_(other.hazard_) {
            if (other.busy_) std::terminate(); other.owner_=nullptr; other.hazard_=nullptr;
        }
        ~Reader() { if (owner_) { if (busy_ || hazard_->pointer.load()) std::terminate(); hazard_->claimed.store(false); } }
    };
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
    struct SharedCapacity { std::size_t memberships; };
    explicit GroupSnapshot(std::span<std::size_t const> capacities,SharedCapacity shared,std::size_t readers,
                           std::uint64_t stale_window_ms=0,
#else
    explicit GroupSnapshot(std::span<std::size_t const> capacities,std::size_t readers,std::uint64_t stale_window_ms=0,
#endif
                           std::size_t snapshot_budget=std::numeric_limits<std::size_t>::max(),std::uint64_t recovery_delay_ms=0)
        : group_count_(checked_groups(capacities)),reader_count_(checked_readers(readers)),stale_window_ms_(stale_window_ms),
          budget_(snapshot_budget),fixed_(budget_.reserve(sizeof(Hazard)*reader_count_+sizeof(Root)*(reader_count_+2))),
          fail_closed_(snapshot_budget!=std::numeric_limits<std::size_t>::max()),
          recovery_delay_(std::min<std::uint64_t>(recovery_delay_ms,30000)),
          hazards_(std::make_unique<Hazard[]>(reader_count_)),pool_(reader_count_+2),current_(pool_.create()) {
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
        if (std::ranges::any_of(capacities,[](auto enabled) { return enabled>1; }))
            throw std::invalid_argument("group must be enabled or disabled");
        auto enabled=static_cast<std::size_t>(std::ranges::count(capacities,std::size_t{1}));
        if (shared.memberships>entries_max || shared.memberships<enabled)
            throw std::invalid_argument("invalid shared capacity");
        total_capacity_=shared.memberships; base_share_=enabled ? shared.memberships/enabled : 0;
#endif
        std::ranges::copy(capacities,capacities_.begin());
    }
    GroupSnapshot(GroupSnapshot const&)=delete;
    ~GroupSnapshot() {
        for (std::size_t i=0;i<reader_count_;++i) if (hazards_[i].claimed.load()) std::terminate();
        for (std::size_t i=0;i<pool_.used;++i)
            for (auto* index:pool_.storage[i].groups) if (index) drop_index(index);
    }
    [[nodiscard]] auto reader(std::size_t index) -> Reader {
        if (index>=reader_count_) throw std::out_of_range("reader index"); return Reader(*this,index);
    }
    [[nodiscard]] static auto live_nodes() noexcept -> std::size_t { return Node::live.load(std::memory_order_relaxed); }
    [[nodiscard]] static auto peak_nodes() noexcept -> std::size_t { return Node::peak.load(std::memory_order_relaxed); }
    [[nodiscard]] auto fails_closed_on_allocation() const noexcept -> bool { return fail_closed_; }
    [[nodiscard]] auto supports_binding(std::size_t group,std::size_t first_reader,std::size_t readers) const noexcept -> bool {
        return group<group_count_ && first_reader<=reader_count_ && readers<=reader_count_-first_reader;
    }
    [[nodiscard]] auto charged_bytes() -> std::size_t { std::lock_guard lock(mutex_); return budget_.used(); }
    [[nodiscard]] auto peak_charged_bytes() -> std::size_t { std::lock_guard lock(mutex_); return budget_.peak(); }
    [[nodiscard]] auto size(std::size_t group) -> std::size_t {
        check_group(group); std::lock_guard lock(mutex_); auto* index=current_.load()->groups[group]; return index ? index->entries : 0;
    }
#ifdef DNS_GROUP_INSPECT_EXPERIMENT
    [[nodiscard]] auto page_count(std::size_t group) -> std::size_t {
        check_group(group); std::lock_guard lock(mutex_); auto* index=current_.load()->groups[group]; return index ? index->count : 0;
    }
    [[nodiscard]] auto contains_member(std::size_t group,Key const& key) -> bool {
        check_group(group); std::lock_guard lock(mutex_); return find(current_.load()->groups[group],key)!=nullptr;
    }
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
    [[nodiscard]] auto total_members() -> std::size_t {
        std::lock_guard lock(mutex_); return memberships(*current_.load());
    }
    [[nodiscard]] auto directory_slots(std::size_t group) -> std::size_t {
        check_group(group); std::lock_guard lock(mutex_); auto* index=current_.load()->groups[group];
        return index ? index->pages.size() : 0;
    }
#endif
#endif
private:
    [[nodiscard]] auto begin_query_owned(std::size_t group,Key key) -> std::expected<Token,Error> {
        check_group(group); if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_);
        if (gate_.load()&1) {
            recover_locked();
            if (gate_.load()&1) return std::unexpected(Error::disabled);
        }
        try {
        if (pending_.size()==4096) {
            if (fail_closed_) disable_locked(); return std::unexpected(Error::query_limit);
        }
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) {
            if (fail_closed_) disable_locked(); return std::unexpected(Error::generation_exhausted);
        }
        if (!dns::detail::compact_key_storage(key)) {
            if (fail_closed_) disable_locked(); return std::unexpected(Error::invalid_key);
        }
        auto query=next_query_+1; pending_.push_back({group,std::move(key),query,{}}); next_query_=query;
        return Token{current_.load()->generation,query};
        } catch (std::bad_alloc const&) {
            if (fail_closed_) disable_locked();
            throw;
        }
    }
public:
    // These entry points copy the caller's key inside the fail-closed boundary.
    // The string-view form also avoids constructing an owning key at the call
    // site. Inputs required by the network operation remain caller-owned.
    [[nodiscard]] auto begin_query(std::size_t group,std::uint64_t view,std::string_view name,std::uint16_t type)
        -> std::expected<Token,Error> {
        check_group(group);
        if (name.size()>254) return std::unexpected(Error::invalid_key);
        auto epoch=gate_.load();
        if (epoch&1) {
            if (!recovery_delay_.count()) return std::unexpected(Error::disabled);
            std::lock_guard lock(mutex_); recover_locked(); epoch=gate_.load();
            if (epoch&1) return std::unexpected(Error::disabled);
        }
        try { return begin_query_owned(group,Key{view,std::string(name),type}); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch); throw; }
    }
    [[nodiscard]] auto begin_query(std::size_t group,Key const& key) -> std::expected<Token,Error> {
        return begin_query(group,key.view,key.name,key.type);
    }
    [[nodiscard]] auto begin_query(std::size_t group,Key&& key) -> std::expected<Token,Error> {
        return begin_query_owned(group,std::move(key));
    }
    [[nodiscard]] auto begin_refresh(std::size_t group,Key key,std::uint64_t now,std::size_t maximum)
        -> std::expected<std::optional<Token>,Error> {
        check_group(group); if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_); auto* current=current_.load();
        if (gate_.load()&1) return std::unexpected(Error::disabled);
        now=current->initialized ? std::max(now,current->now) : now;
        if (!current->initialized || current->now<now) {
            Builder time_update{*this,clone(*current)};
            time_update.root->now=now; time_update.root->initialized=true;
            time_update.publish(); current=current_.load();
        }
        auto* binding=find(current->groups[group],key);
        std::size_t source=group;
        // A group may consume a shared stale answer without being able to
        // allocate its own membership. Keep the requester as token owner and
        // separately remember the source whose revision guards publication.
        if (binding && now<binding->node->expires) return std::optional<Token>{};
        if (!stale(binding,now)) {
            binding=nullptr;
            if (capacities_[group]) for (std::size_t i=0;i<group_count_;++i) if (i!=group) {
                auto* candidate=find(current->groups[i],key);
                if (stale(candidate,now)) { binding=candidate; source=i; break; }
            }
        }
        if (!binding) return std::optional<Token>{};
        if (std::ranges::any_of(pending_,[&](auto const& item) { return same(item.key,key); })) return std::optional<Token>{};
        auto refreshes=std::ranges::count_if(pending_,[](auto const& item) { return item.refresh.has_value(); });
        if (static_cast<std::size_t>(refreshes)>=maximum) return std::optional<Token>{};
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        if (!dns::detail::compact_key_storage(key)) return std::unexpected(Error::invalid_key);
        auto query=next_query_+1;
        pending_.push_back({group,std::move(key),query,Refresh{source,binding->node->revision}}); next_query_=query;
        return std::optional<Token>(Token{current->generation,query});
    }
    [[nodiscard]] auto cancel_query(Token token) -> std::expected<void,Error> {
        std::lock_guard lock(mutex_);
        if (token.generation!=current_.load()->generation) return std::unexpected(Error::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end()) return std::unexpected(Error::stale_query);
        pending_.erase(pending); return {};
    }
    template<bool from_acquisition=false>
    auto apply(std::size_t group,Key key,Answer answer,std::optional<Negative> negative,
               std::uint32_t ttl,std::uint64_t now,Token token,bool invalidate,
               std::conditional_t<from_acquisition,std::uint64_t,std::monostate> acquired={}) -> std::expected<void,Error> {
        check_group(group);
        std::lock_guard lock(mutex_); auto* current=current_.load();
        if (gate_.load()&1) return std::unexpected(Error::disabled);
        try {
        now=current->initialized ? std::max(now,current->now) : now;
        if (token.generation!=current->generation) return std::unexpected(Error::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || pending->group!=group || !same(pending->key,key))
            return std::unexpected(Error::stale_query);
        if (pending->refresh) {
            auto* binding=find(current->groups[pending->refresh->source],key);
            if (!binding || binding->node->negative || binding->node->revision!=pending->refresh->revision ||
                (now>=binding->node->expires && now-binding->node->expires>=stale_window_ms_))
                return std::unexpected(Error::stale_query);
        }
        if (!invalidate && !capacities_[group]) return std::unexpected(Error::disabled);
        auto duration=std::uint64_t(ttl)*1000;
        if constexpr (from_acquisition) {
            if (acquired>now || duration>std::numeric_limits<std::uint64_t>::max()-acquired) return std::unexpected(Error::invalid_answer);
            auto expiry=acquired+duration;
            duration=expiry>now ? expiry-now : 0;
        } else if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(Error::invalid_answer);
        // When a borrowed membership could not be admitted, publish the new
        // revision through its surviving source instead of demanding space for
        // another index. Other existing memberships are updated as usual.
        auto destination=pending->refresh ? pending->refresh->source : group;
        collect();
        auto drop_owned=[](Node* node) noexcept { if (node) drop_node(node); };
        std::unique_ptr<Node,decltype(drop_owned)> node(nullptr,drop_owned);
        if (!invalidate && duration) {
            // The node owns a distinct key; compact and account that copy,
            // rather than charging the capacity of a different string.
            Key stored_key=key;
            if (!dns::detail::compact_key_storage(stored_key)) return std::unexpected(Error::invalid_key);
            if (!negative && !dns::detail::compact_answer_storage(answer)) return std::unexpected(Error::invalid_answer);
            auto discard=now+duration;
            if (!negative) discard+=std::min(stale_window_ms_,std::numeric_limits<std::uint64_t>::max()-discard);
            auto charge=budget_.reserve(node_charge(stored_key,answer));
            node.reset(new Node(std::move(charge),std::move(stored_key),std::move(answer),negative,now+duration,discard,token.query));
        }
        Builder builder{*this,clone(*current)}; builder.root->now=now; builder.root->initialized=true;
        if (!node) {
            for (std::size_t i=0;i<group_count_;++i) if (find(builder.root->groups[i],key)) {
                auto& index=writable_index(*builder.root,i); remove(index,key); merge_sparse(index);
            }
        } else {
            auto& own=writable_index(*builder.root,destination); prune(own,now);
            for (std::size_t i=0;i<group_count_;++i) if (find(builder.root->groups[i],key)) {
                auto& index=writable_index(*builder.root,i);
                insert(index,node.get(),0);
            }
            if (!find(&own,key)) {
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
                if (auto result=admit_shared(*builder.root,destination,node.get(),now); !result) return result;
#else
                if (auto result=admit(own,node.get(),capacities_[destination]); !result) return result;
#endif
            }
            merge_sparse(own);
        }
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        builder.publish();
        return {};
        } catch (BudgetExceeded const&) {
            disable_locked(); return std::unexpected(Error::disabled);
        } catch (std::bad_alloc const&) {
            if (fail_closed_) disable_locked();
            throw;
        }
    }
    [[nodiscard]] auto publish(std::size_t group,Key key,Answer answer,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (!valid(answer,key.type)) return std::unexpected(Error::invalid_answer);
        auto ttl=*answer.ttl;
        return apply(group,std::move(key),std::move(answer),{},ttl,now,token,false);
    }
    [[nodiscard]] auto publish_negative(std::size_t group,Key key,Negative negative,std::uint32_t ttl,
                                         std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        return apply(group,std::move(key),{},negative,ttl,now,token,false);
    }
    // Experimental absolute acquisition time for delayed foreground writes.
    // It cannot extend the answer's TTL if lock acquisition is delayed.
    [[nodiscard]] auto publish_from(std::size_t group,Key key,Answer answer,std::uint64_t acquired,
                                    std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (!valid(answer,key.type)) return std::unexpected(Error::invalid_answer);
        auto ttl=*answer.ttl;
        return apply<true>(group,std::move(key),std::move(answer),{},ttl,now,token,false,acquired);
    }
    [[nodiscard]] auto publish_negative_from(std::size_t group,Key key,Negative negative,std::uint32_t ttl,
                                             std::uint64_t acquired,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        return apply<true>(group,std::move(key),{},negative,ttl,now,token,false,acquired);
    }
    [[nodiscard]] auto invalidate(std::size_t group,Key key,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        return apply(group,std::move(key),{}, {},0,now,token,true);
    }
    // Network callers already own their response. Constructing the cache key
    // here ensures allocation failure cannot leave an older value visible when
    // a definitive foreground result was not registered or published.
    [[nodiscard]] auto publish_view(std::size_t group,std::uint64_t view,std::string_view name,std::uint16_t type,
                                    Answer&& answer,std::uint64_t now,Token token) -> std::expected<void,Error> {
        check_group(group);
        if (name.size()>254) return std::unexpected(Error::invalid_key);
        auto epoch=gate_.load(); if (epoch&1) return std::unexpected(Error::disabled);
        try { return publish(group,Key{view,std::string(name),type},std::move(answer),now,token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch,token,group,view,name,type,now); throw; }
    }
    [[nodiscard]] auto publish_copy_view(std::size_t group,std::uint64_t view,std::string_view name,std::uint16_t type,
                                         Answer const& answer,std::uint64_t now,Token token) -> std::expected<void,Error> {
        check_group(group);
        if (name.size()>254) return std::unexpected(Error::invalid_key);
        auto epoch=gate_.load(); if (epoch&1) return std::unexpected(Error::disabled);
        try {
            Answer copy=answer;
            return publish_view(group,view,name,type,std::move(copy),now,token);
        } catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch,token,group,view,name,type,now); throw; }
    }
    [[nodiscard]] auto publish_copy_view_from(std::size_t group,std::uint64_t view,std::string_view name,std::uint16_t type,
                                              Answer const& answer,std::uint64_t acquired,std::uint64_t now,Token token)
        -> std::expected<void,Error> {
        check_group(group);
        if (name.size()>254) return std::unexpected(Error::invalid_key);
        auto epoch=gate_.load(); if (epoch&1) return std::unexpected(Error::disabled);
        try { return publish_from(group,Key{view,std::string(name),type},answer,acquired,now,token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch,token,group,view,name,type,now); throw; }
    }
    [[nodiscard]] auto publish_negative_view(std::size_t group,std::uint64_t view,std::string_view name,std::uint16_t type,
                                             Negative negative,std::uint32_t ttl,std::uint64_t now,Token token) -> std::expected<void,Error> {
        check_group(group);
        if (name.size()>254) return std::unexpected(Error::invalid_key);
        auto epoch=gate_.load(); if (epoch&1) return std::unexpected(Error::disabled);
        try { return publish_negative(group,Key{view,std::string(name),type},negative,ttl,now,token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch,token,group,view,name,type,now); throw; }
    }
    [[nodiscard]] auto publish_negative_view_from(std::size_t group,std::uint64_t view,std::string_view name,std::uint16_t type,
                                                   Negative negative,std::uint32_t ttl,std::uint64_t acquired,
                                                   std::uint64_t now,Token token) -> std::expected<void,Error> {
        check_group(group);
        if (name.size()>254) return std::unexpected(Error::invalid_key);
        auto epoch=gate_.load(); if (epoch&1) return std::unexpected(Error::disabled);
        try { return publish_negative_from(group,Key{view,std::string(name),type},negative,ttl,acquired,now,token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch,token,group,view,name,type,now); throw; }
    }
    [[nodiscard]] auto invalidate_view(std::size_t group,std::uint64_t view,std::string_view name,std::uint16_t type,
                                       std::uint64_t now,Token token) -> std::expected<void,Error> {
        check_group(group);
        if (name.size()>254) return std::unexpected(Error::invalid_key);
        auto epoch=gate_.load(); if (epoch&1) return std::unexpected(Error::disabled);
        try { return invalidate(group,Key{view,std::string(name),type},now,token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch,token,group,view,name,type,now); throw; }
    }
    [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<void,Error> {
        std::lock_guard lock(mutex_); return clear_locked(now);
    }
    template<class Hook>
    [[nodiscard]] auto lookup_with_hook(std::size_t group,Key key,std::uint64_t now,Reader& reader,Hook&& hook)
        -> std::expected<std::optional<Answer>,Error> {
        check_group(group); if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (reader.owner_!=this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        if (!capacities_[group]) return std::optional<Answer>{};
        auto epoch=gate_.load(); if (epoch&1) return std::optional<Answer>{};
        {
            reader.busy_=true;
            struct Guard { Reader& reader; ~Guard() { reader.hazard_->pointer.store(nullptr); reader.busy_=false; } } guard{reader};
            auto* root=reader.protect(); std::forward<Hook>(hook)();
            auto effective=root->initialized ? std::max(now,root->now) : now;
            auto* binding=find(root->groups[group],key);
            if (fresh(binding,effective)) {
                if (binding->node->negative) return std::optional<Answer>{};
                auto answer=copy_answer(*binding->node,effective);
                if (gate_.load()!=epoch) return std::optional<Answer>{};
                return std::optional<Answer>(std::move(answer));
            }
        }
        auto result=adopt(group,key,now,AdoptKind::positive,epoch);
        if (!result) return std::unexpected(result.error());
        return *result ? std::move((**result).answer) : std::optional<Answer>{};
    }
    [[nodiscard]] auto lookup(std::size_t group,Key key,std::uint64_t now,Reader& reader)
        -> std::expected<std::optional<Answer>,Error> {
        return lookup_with_hook(group,std::move(key),now,reader,[] {});
    }
    [[nodiscard]] auto lookup_fresh(std::size_t group,Key key,std::uint64_t now,Reader& reader)
        -> std::expected<std::optional<Fresh>,Error> {
        check_group(group); if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (reader.owner_!=this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        if (!capacities_[group]) return std::optional<Fresh>{};
        auto epoch=gate_.load(); if (epoch&1) return std::optional<Fresh>{};
        {
            reader.busy_=true;
            struct Guard { Reader& reader; ~Guard() { reader.hazard_->pointer.store(nullptr); reader.busy_=false; } } guard{reader};
            auto* root=reader.protect(); auto effective=root->initialized ? std::max(now,root->now) : now;
            auto* binding=find(root->groups[group],key);
            if (fresh(binding,effective)) {
                Fresh result{{},{},binding->node->expires};
                if (binding->node->negative) result.negative=binding->node->negative;
                else result.answer=copy_answer(*binding->node,effective);
                if (gate_.load()!=epoch) return std::optional<Fresh>{};
                return std::optional<Fresh>(std::move(result));
            }
        }
        auto adopted=adopt(group,key,now,AdoptKind::positive,epoch);
        if (!adopted) return std::unexpected(adopted.error());
        if (!*adopted) return std::optional<Fresh>{};
        return std::optional<Fresh>(Fresh{std::move((**adopted).answer),(**adopted).negative,(**adopted).expires});
    }
    [[nodiscard]] auto lookup_negative(std::size_t group,Key key,std::uint64_t now,Reader& reader)
        -> std::expected<std::optional<Negative>,Error> {
        check_group(group); if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (reader.owner_!=this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        if (!capacities_[group]) return std::optional<Negative>{};
        auto epoch=gate_.load(); if (epoch&1) return std::optional<Negative>{};
        {
            reader.busy_=true;
            struct Guard { Reader& reader; ~Guard() { reader.hazard_->pointer.store(nullptr); reader.busy_=false; } } guard{reader};
            auto* root=reader.protect(); auto effective=root->initialized ? std::max(now,root->now) : now;
            auto* binding=find(root->groups[group],key);
            if (fresh(binding,effective)) {
                auto result=binding->node->negative;
                return gate_.load()==epoch ? result : std::optional<Negative>{};
            }
        }
        auto result=adopt(group,key,now,AdoptKind::negative,epoch);
        if (!result) return std::unexpected(result.error());
        return *result ? (**result).negative : std::optional<Negative>{};
    }
    [[nodiscard]] auto lookup_stale(std::size_t group,Key key,std::uint64_t now,Reader& reader)
        -> std::expected<std::optional<Stale>,Error> {
        check_group(group); if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (reader.owner_!=this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        if (!capacities_[group]) return std::optional<Stale>{};
        auto epoch=gate_.load(); if (epoch&1) return std::optional<Stale>{};
        {
            reader.busy_=true;
            struct Guard { Reader& reader; ~Guard() { reader.hazard_->pointer.store(nullptr); reader.busy_=false; } } guard{reader};
            auto* root=reader.protect(); auto effective=root->initialized ? std::max(now,root->now) : now;
            auto* binding=find(root->groups[group],key);
            if (fresh(binding,effective)) return std::optional<Stale>{};
        }
        auto result=adopt(group,key,now,AdoptKind::stale,epoch);
        if (!result) return std::unexpected(result.error());
        return *result ? std::move((**result).stale) : std::optional<Stale>{};
    }
};
}
