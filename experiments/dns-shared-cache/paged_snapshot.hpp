// Experimental positive-only cache. It does not implement negative answers,
// stale refresh, clear or production lifecycle; it is not a replacement for
// AddressCache. Include after the DNS module imports.
#pragma once

namespace dns_hp_experiment {
class PagedSnapshotPrototype {
    using Key=dns::CacheKey;
    using Token=dns::CacheToken;
    using Error=dns::CacheError;
    using Answer=dns::AddressAnswer;
    static constexpr std::size_t maximum=512,page_size=32;
    // A published root has at most 31 pages: each adjacent pair contains at
    // least 33 nodes after merging. One insertion can split one further page.
    static constexpr std::size_t root_pages=2*(maximum/(page_size+1))+2;
    struct Node {
        alignas(64) std::size_t refs=1;
        alignas(64) Key key;
        Answer answer;
        std::uint64_t expires,order;
        inline static std::atomic<std::size_t> live=0,peak=0;
        Node(Key key_,Answer answer_,std::uint64_t expires_,std::uint64_t order_)
            : key(std::move(key_)),answer(std::move(answer_)),expires(expires_),order(order_) {
            auto count=live.fetch_add(1,std::memory_order_relaxed)+1;
            auto previous=peak.load(std::memory_order_relaxed);
            while (previous<count && !peak.compare_exchange_weak(previous,count,std::memory_order_relaxed)) {}
        }
        ~Node() { live.fetch_sub(1,std::memory_order_relaxed); }
    };
    struct Page {
        std::size_t refs=1,count=0;
        std::uint64_t min_expiry=std::numeric_limits<std::uint64_t>::max(),min_order=0;
        std::array<Node*,page_size> nodes{};
    };
    struct Root {
        std::array<Page*,root_pages> pages{};
        std::size_t count=0,entries=0;
        std::uint64_t now=0,next_order=0;
        bool initialized=false;
        Root* next=nullptr;
    };
    struct alignas(64) Hazard { std::atomic<Root*> pointer=nullptr; std::atomic<bool> claimed=false; };
    struct Pending { Key key; std::uint64_t query; };
    std::size_t capacity_,reader_count_;
    std::unique_ptr<Hazard[]> hazards_;
    std::unique_ptr<Root[]> pool_;
    Root* free_=nullptr;
    Root* retired_=nullptr;
    std::atomic<Root*> current_;
    std::mutex mutex_;
    std::vector<Pending> pending_;
    std::uint64_t next_query_=0;

    static auto checked_readers(std::size_t readers,std::uint64_t stale) -> std::size_t {
        if (stale || readers>257) throw std::invalid_argument("unsupported prototype configuration");
        return readers;
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
    static auto valid(Answer const& value,std::uint16_t type) -> bool {
        if (value.addresses.empty() || value.addresses.size()>128 || value.chain.size()>16 ||
            value.canonical_name.size()>254 || !value.ttl || !*value.ttl) return false;
        for (auto const& name:value.chain) if (name.size()>254) return false;
        for (auto const& address:value.addresses) if (address.size!=(type==1 ? 4 : 16)) return false;
        return true;
    }
    static auto drop_node(Node* node) noexcept -> void { if (--node->refs==0) delete node; }
    static auto drop_page(Page* page) noexcept -> void {
        if (--page->refs) return;
        for (std::size_t i=0;i<page->count;++i) drop_node(page->nodes[i]);
        delete page;
    }
    static auto summarize(Page& page) noexcept -> void {
        page.min_expiry=std::numeric_limits<std::uint64_t>::max(); page.min_order=0;
        for (std::size_t i=0;i<page.count;++i) {
            auto* node=page.nodes[i];
            if (!i || node->expires<page.min_expiry || (node->expires==page.min_expiry && node->order<page.min_order)) {
                page.min_expiry=node->expires; page.min_order=node->order;
            }
        }
    }
    static auto page_index(Root const& root,Key const& key) noexcept -> std::size_t {
        std::size_t first=0,last=root.count;
        while (first<last) {
            auto middle=first+(last-first)/2;
            if (!less(key,root.pages[middle]->nodes[0]->key)) first=middle+1; else last=middle;
        }
        return first ? first-1 : 0;
    }
    static auto lower(Page const& page,Key const& key) noexcept -> std::size_t {
        std::size_t first=0,last=page.count;
        while (first<last) {
            auto middle=first+(last-first)/2;
            if (less(page.nodes[middle]->key,key)) first=middle+1; else last=middle;
        }
        return first;
    }
    static auto find(Root const& root,Key const& key) noexcept -> Node* {
        if (!root.count) return nullptr;
        auto* page=root.pages[page_index(root,key)]; auto index=lower(*page,key);
        return index<page->count && same(page->nodes[index]->key,key) ? page->nodes[index] : nullptr;
    }
    auto recycle(Root* root) noexcept -> void {
        for (std::size_t i=0;i<root->count;++i) { drop_page(root->pages[i]); root->pages[i]=nullptr; }
        root->count=0; root->entries=0; root->now=0; root->next_order=0; root->initialized=false;
        root->next=free_; free_=root;
    }
    auto collect() noexcept -> void {
        auto** link=&retired_;
        while (auto* root=*link) {
            bool guarded=false;
            for (std::size_t i=0;i<reader_count_;++i)
                if (hazards_[i].pointer.load()==root) { guarded=true; break; }
            if (guarded) link=&root->next;
            else { *link=root->next; recycle(root); }
        }
    }
    auto clone(Root const& source) noexcept -> Root* {
        collect(); if (!free_) std::terminate();
        auto* root=free_; free_=free_->next; root->next=nullptr;
        root->count=source.count; root->entries=source.entries; root->now=source.now;
        root->next_order=source.next_order; root->initialized=source.initialized;
        for (std::size_t i=0;i<root->count;++i) { root->pages[i]=source.pages[i]; ++root->pages[i]->refs; }
        return root;
    }
    auto commit(Root* root) noexcept -> void {
        auto* old=current_.exchange(root); old->next=retired_; retired_=old; collect();
    }
    struct Builder {
        PagedSnapshotPrototype& owner; Root* root;
        ~Builder() { if (root) owner.recycle(root); }
        auto publish() noexcept -> void { owner.commit(root); root=nullptr; }
    };
    static auto writable(Root& root,std::size_t index) -> Page& {
        auto* original=root.pages[index];
        if (original->refs==1) return *original;
        auto copy=std::make_unique<Page>(*original); copy->refs=1;
        for (std::size_t i=0;i<copy->count;++i) ++copy->nodes[i]->refs;
        root.pages[index]=copy.release(); drop_page(original);
        return *root.pages[index];
    }
    static auto erase(Root& root,std::size_t page_index_,std::size_t node_index) -> void {
        auto& page=writable(root,page_index_);
        drop_node(page.nodes[node_index]);
        std::move(page.nodes.begin()+node_index+1,page.nodes.begin()+page.count,page.nodes.begin()+node_index);
        page.nodes[--page.count]=nullptr; --root.entries;
        if (page.count) { summarize(page); return; }
        drop_page(root.pages[page_index_]);
        std::move(root.pages.begin()+page_index_+1,root.pages.begin()+root.count,root.pages.begin()+page_index_);
        root.pages[--root.count]=nullptr;
    }
    static auto advance(Root& root,std::uint64_t now) -> void {
        root.now=now; root.initialized=true;
        for (std::size_t i=0;i<root.count;) {
            if (root.pages[i]->min_expiry>now) { ++i; continue; }
            auto& page=writable(root,i);
            std::size_t out=0;
            for (std::size_t j=0;j<page.count;++j) {
                auto* node=page.nodes[j];
                if (node->expires<=now) { drop_node(node); --root.entries; }
                else page.nodes[out++]=node;
            }
            for (std::size_t j=out;j<page.count;++j) page.nodes[j]=nullptr;
            page.count=out;
            if (out) { summarize(page); ++i; }
            else {
                drop_page(root.pages[i]);
                std::move(root.pages.begin()+i+1,root.pages.begin()+root.count,root.pages.begin()+i);
                root.pages[--root.count]=nullptr;
            }
        }
    }
    static auto insert(Root& root,std::unique_ptr<Node> node) -> void {
        if (!root.count) {
            auto page=std::make_unique<Page>(); page->nodes[0]=node.release(); page->count=1; summarize(*page);
            root.pages[0]=page.release(); root.count=1; root.entries=1; return;
        }
        auto index=page_index(root,node->key);
        auto& page=writable(root,index);
        auto position=lower(page,node->key);
        if (position<page.count && same(page.nodes[position]->key,node->key)) {
            drop_node(page.nodes[position]); page.nodes[position]=node.release(); summarize(page); return;
        }
        if (page.count==page_size) {
            if (root.count==root.pages.size()) std::terminate();
            auto right=std::make_unique<Page>();
            right->count=page.count/2;
            for (std::size_t i=0;i<right->count;++i) {
                right->nodes[i]=page.nodes[page.count/2+i]; page.nodes[page.count/2+i]=nullptr;
            }
            page.count/=2; summarize(page); summarize(*right);
            std::move_backward(root.pages.begin()+index+1,root.pages.begin()+root.count,root.pages.begin()+root.count+1);
            root.pages[index+1]=right.release(); ++root.count;
            if (!less(node->key,root.pages[index+1]->nodes[0]->key)) ++index;
        }
        auto& target=*root.pages[index]; position=lower(target,node->key);
        std::move_backward(target.nodes.begin()+position,target.nodes.begin()+target.count,target.nodes.begin()+target.count+1);
        target.nodes[position]=node.release(); ++target.count; ++root.entries; summarize(target);
    }
    static auto merge_sparse(Root& root) -> void {
        for (std::size_t i=0;i+1<root.count;) {
            auto* right=root.pages[i+1];
            if (root.pages[i]->count+right->count>page_size) { ++i; continue; }
            auto& left=writable(root,i);
            for (std::size_t j=0;j<right->count;++j) {
                ++right->nodes[j]->refs;
                left.nodes[left.count++]=right->nodes[j];
            }
            summarize(left); drop_page(right);
            std::move(root.pages.begin()+i+2,root.pages.begin()+root.count,root.pages.begin()+i+1);
            root.pages[--root.count]=nullptr;
        }
    }
public:
    class Reader {
        friend class PagedSnapshotPrototype;
        PagedSnapshotPrototype* owner_; Hazard* hazard_; bool busy_=false;
        Reader(PagedSnapshotPrototype& owner,std::size_t index) : owner_(&owner),hazard_(&owner.hazards_[index]) {
            if (hazard_->claimed.exchange(true)) throw std::logic_error("reader already registered");
        }
    public:
        Reader(Reader const&)=delete;
        auto operator=(Reader const&) -> Reader& = delete;
        Reader(Reader&& other) noexcept : owner_(other.owner_),hazard_(other.hazard_) {
            if (other.busy_) std::terminate(); other.owner_=nullptr; other.hazard_=nullptr;
        }
        ~Reader() {
            if (owner_) { if (busy_ || hazard_->pointer.load()) std::terminate(); hazard_->claimed.store(false); }
        }
    };
    explicit PagedSnapshotPrototype(std::size_t capacity,std::uint64_t stale,std::size_t readers)
        : capacity_(std::min(capacity,maximum)),reader_count_(checked_readers(readers,stale)),hazards_(std::make_unique<Hazard[]>(reader_count_)),
          pool_(std::make_unique<Root[]>(reader_count_+2)),current_(&pool_[0]) {
        for (std::size_t i=1;i<reader_count_+2;++i) { pool_[i].next=free_; free_=&pool_[i]; }
    }
    PagedSnapshotPrototype(PagedSnapshotPrototype const&)=delete;
    ~PagedSnapshotPrototype() {
        for (std::size_t i=0;i<reader_count_;++i) if (hazards_[i].claimed.load()) std::terminate();
        for (std::size_t i=0;i<reader_count_+2;++i)
            for (std::size_t j=0;j<pool_[i].count;++j) drop_page(pool_[i].pages[j]);
    }
    [[nodiscard]] auto reader(std::size_t index) -> Reader {
        if (index>=reader_count_) throw std::out_of_range("reader index");
        return Reader(*this,index);
    }
    [[nodiscard]] static auto live_nodes() noexcept -> std::size_t { return Node::live.load(std::memory_order_relaxed); }
    [[nodiscard]] static auto peak_nodes() noexcept -> std::size_t { return Node::peak.load(std::memory_order_relaxed); }
    struct Shape {
        std::size_t entries, pages, root_bytes, page_bytes, min_neighbor_sum;
    };
    // A writer-side diagnostic for this prototype, not a concurrent read API.
    [[nodiscard]] auto shape() -> Shape {
        std::lock_guard lock(mutex_);
        auto* root=current_.load();
        auto minimum=std::numeric_limits<std::size_t>::max();
        for (std::size_t i=1;i<root->count;++i)
            minimum=std::min(minimum,root->pages[i-1]->count+root->pages[i]->count);
        return {root->entries,root->count,sizeof(Root),sizeof(Page),minimum};
    }
    [[nodiscard]] auto begin_query(Key key) -> std::expected<Token,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_);
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        auto query=next_query_+1; pending_.push_back({std::move(key),query}); next_query_=query;
        return Token{1,query};
    }
    [[nodiscard]] auto publish(Key key,Answer answer,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (!valid(answer,key.type)) return std::unexpected(Error::invalid_answer);
        std::lock_guard lock(mutex_);
        auto* current=current_.load(); now=current->initialized ? std::max(now,current->now) : now;
        if (token.generation!=1) return std::unexpected(Error::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || !same(pending->key,key)) return std::unexpected(Error::stale_query);
        if (!capacity_) return std::unexpected(Error::disabled);
        auto duration=std::uint64_t(*answer.ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(Error::invalid_answer);
        Builder builder{*this,clone(*current)}; advance(*builder.root,now);
        auto* existing=find(*builder.root,key); std::uint64_t order=0;
        if (existing) order=existing->order;
        else if (builder.root->entries==capacity_) {
            std::size_t victim=0;
            for (std::size_t i=1;i<builder.root->count;++i)
                if (std::pair{builder.root->pages[i]->min_expiry,builder.root->pages[i]->min_order}<
                    std::pair{builder.root->pages[victim]->min_expiry,builder.root->pages[victim]->min_order}) victim=i;
            auto* page=builder.root->pages[victim]; std::size_t position=0;
            while (page->nodes[position]->expires!=page->min_expiry || page->nodes[position]->order!=page->min_order) ++position;
            order=page->nodes[position]->order; erase(*builder.root,victim,position);
        } else {
            if (builder.root->next_order==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
            order=++builder.root->next_order;
        }
        auto node=std::make_unique<Node>(key,std::move(answer),now+duration,order);
        insert(*builder.root,std::move(node)); merge_sparse(*builder.root); builder.publish();
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        return {};
    }
    template<class Hook>
    [[nodiscard]] auto lookup_with_hook(Key key,std::uint64_t now,Reader& reader,Hook&& hook) -> std::expected<std::optional<Answer>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (reader.owner_!=this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        reader.busy_=true;
        struct Guard { Reader& reader; ~Guard() { reader.hazard_->pointer.store(nullptr); reader.busy_=false; } } guard{reader};
        Root* root;
        do { root=current_.load(); reader.hazard_->pointer.store(root); } while (root!=current_.load());
        std::forward<Hook>(hook)();
        now=root->initialized ? std::max(now,root->now) : now;
        auto* node=find(*root,key);
        if (!node || now>=node->expires || (node->expires-now)/1000==0) return std::optional<Answer>{};
        auto answer=node->answer; answer.ttl=static_cast<std::uint32_t>((node->expires-now)/1000);
        return std::optional<Answer>(std::move(answer));
    }
    [[nodiscard]] auto lookup(Key key,std::uint64_t now,Reader& reader) -> std::expected<std::optional<Answer>,Error> {
        return lookup_with_hook(std::move(key),now,reader,[] {});
    }
};
}
