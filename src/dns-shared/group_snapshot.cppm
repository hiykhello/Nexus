// Group snapshot DNS cache module interface.
export module dns.group_snapshot;
import std;
import dns.cache;
import dns.message;

export namespace dns_hp_experiment {
    class GroupSnapshot {
    public:
        struct BudgetExceeded {};
    private:
        using Key = dns::CacheKey;
        using Answer = dns::AddressAnswer;
        using Negative = dns::NegativeKind;
        using Stale = dns::StaleAddressAnswer;
        using Token = dns::CacheToken;
        using Error = dns::CacheError;
        static constexpr std::size_t groups_max = 17, page_size = 32;
        static constexpr std::size_t entries_max = 8192, pages_max = 512;
        class Budget {
            std::size_t limit_, used_ = 0, peak_ = 0;
        public:
            class Lease {
                friend class Budget;
                Budget* owner_ = nullptr;
                std::size_t bytes_ = 0;
                Lease(Budget& owner, std::size_t bytes) noexcept : owner_(&owner), bytes_(bytes) {}
            public:
                Lease(Lease const&) = delete;
                auto operator=(Lease const&) -> Lease& = delete;
                Lease(Lease&& other) noexcept : owner_(std::exchange(other.owner_, nullptr)), bytes_(other.bytes_) {}
                auto operator=(Lease&&) = delete;
                ~Lease() { if (owner_) owner_->used_ -= bytes_; }
            };
            explicit Budget(std::size_t limit) : limit_(limit) {}
            auto reserve(std::size_t bytes) -> Lease {
                if (bytes > limit_ - used_) throw BudgetExceeded{};
                used_ += bytes;
                peak_ = std::max(peak_, used_);
                return Lease(*this, bytes);
            }
            [[nodiscard]] auto used() const noexcept -> std::size_t { return used_; }
            [[nodiscard]] auto peak() const noexcept -> std::size_t { return peak_; }
        };
        struct Node {
            Budget::Lease lease;
            alignas(64) std::size_t refs = 1;
            alignas(64) Key key;
            Answer answer;
            std::optional<Negative> negative;
            std::uint64_t expires, discard, revision;
            inline static std::atomic<std::size_t> live = 0, peak = 0;
            Node(Budget::Lease lease_, Key key_, Answer answer_, std::optional<Negative> negative_, std::uint64_t expires_,
                 std::uint64_t discard_, std::uint64_t revision_);
            ~Node();
        };
        struct Binding { Node* node = nullptr; std::uint64_t order = 0; };
        struct Page {
            Budget::Lease lease;
            std::size_t refs = 1, count = 0;
            std::uint64_t min_expiry = std::numeric_limits<std::uint64_t>::max();
            std::uint64_t min_discard = std::numeric_limits<std::uint64_t>::max();
            std::uint64_t min_order = 0;
            std::array<Binding, page_size> values{};
            explicit Page(Budget::Lease lease_) : lease(std::move(lease_)) {}
            Page(Budget::Lease lease_, Page const& other)
                : lease(std::move(lease_)), count(other.count), min_expiry(other.min_expiry),
                  min_discard(other.min_discard), min_order(other.min_order), values(other.values) {}
        };
        class Directory {
            std::unique_ptr<Page*[]> pages_;
            std::optional<Budget::Lease> lease_;
            std::size_t size_ = 0;
        public:
            auto size() const noexcept -> std::size_t { return size_; }
            auto begin() noexcept -> Page** { return pages_.get(); }
            auto begin() const noexcept -> Page* const* { return pages_.get(); }
            auto operator[](std::size_t i) noexcept -> Page*& { return pages_[i]; }
            auto operator[](std::size_t i) const noexcept -> Page* { return pages_[i]; }
            auto grow(Budget& budget, std::size_t desired) -> void;
        };
        struct Index {
            Budget::Lease lease;
            std::size_t refs = 1, count = 0, entries = 0;
            std::uint64_t next_order = 0;
            Directory pages;
            explicit Index(Budget::Lease lease_) : lease(std::move(lease_)) {}
            Index(Budget::Lease lease_, Index const& other, Budget& budget);
        };
        struct Root {
            std::array<Index*, groups_max> groups{};
            std::uint64_t generation = 1, now = 0;
            bool initialized = false;
            Root* next = nullptr;
        };
        struct RootPool {
            std::allocator<Root> allocator;
            Root* storage;
            std::size_t capacity, used = 0;
            explicit RootPool(std::size_t count) : storage(allocator.allocate(count)), capacity(count) {}
            RootPool(RootPool const&) = delete;
            ~RootPool();
            auto create() noexcept -> Root*;
        };
        struct alignas(64) Hazard { std::atomic<Root*> pointer = nullptr; std::atomic<bool> claimed = false; };
        struct Refresh { std::size_t source; std::uint64_t revision; };
        struct Pending { std::size_t group; Key key; std::uint64_t query; std::optional<Refresh> refresh; };
        struct Adopted {
            std::optional<Answer> answer;
            std::optional<Negative> negative;
            std::optional<Stale> stale;
            std::uint64_t expires = 0;
        };
        enum class AdoptKind { positive, negative, stale };

        std::array<std::size_t, groups_max> capacities_{};
        std::size_t group_count_, reader_count_;
        std::size_t total_capacity_ = 0, base_share_ = 0;
        std::uint64_t stale_window_ms_;
        Budget budget_;
        Budget::Lease fixed_;
        bool fail_closed_;
        std::chrono::milliseconds recovery_delay_;
        std::chrono::steady_clock::time_point recovery_deadline_{};
        std::atomic<std::uint64_t> gate_ = 0;
        std::unique_ptr<Hazard[]> hazards_;
        RootPool pool_;
        Root* free_ = nullptr;
        Root* retired_ = nullptr;
        std::atomic<Root*> current_;
        std::mutex mutex_;
        std::vector<Pending> pending_;
        std::uint64_t next_query_ = 0;

        static auto checked_groups(std::span<std::size_t const> groups) -> std::size_t;
        static auto checked_readers(std::size_t readers) -> std::size_t;
        auto disable_locked() noexcept -> void;
        auto disable_after_allocation_failure(std::uint64_t epoch, std::optional<Token> token = {},
            std::size_t group = 0, std::uint64_t view = 0, std::string_view name = {},
            std::uint16_t type = 0, std::uint64_t now = 0) -> void;
        auto check_group(std::size_t group) const -> void;
        static auto same(Key const& a, Key const& b) noexcept -> bool;
        static auto less(Key const& a, Key const& b) noexcept -> bool;
        static auto normalize(Key& key) -> bool;
        static auto valid(Answer const& answer, std::uint16_t type) -> bool;
        static auto node_charge(Key const& key, Answer const& answer) noexcept -> std::size_t;
        static auto drop_node(Node* node) noexcept -> void;
        static auto drop_page(Page* page) noexcept -> void;
        static auto drop_index(Index* index) noexcept -> void;
        static auto summarize(Page& page) noexcept -> void;
        static auto page_index(Index const& index, Key const& key) noexcept -> std::size_t;
        static auto lower(Page const& page, Key const& key) noexcept -> std::size_t;
        static auto find(Index const* index, Key const& key) noexcept -> Binding const*;
        auto recycle(Root* root) noexcept -> void;
        auto collect() noexcept -> void;
        auto clone(Root const& source) noexcept -> Root*;
        auto commit(Root* root) noexcept -> void;
        struct Builder {
            GroupSnapshot& owner;
            Root* root;
            ~Builder() { if (root) owner.recycle(root); }
            auto publish() noexcept -> void { owner.commit(root); root = nullptr; }
        };
        auto writable_index(Root& root, std::size_t group) -> Index&;
        auto writable_page(Index& index, std::size_t position) -> Page&;
        auto erase(Index& index, std::size_t page_index_, std::size_t position) -> void;
        auto remove(Index& index, Key const& key) -> void;
        auto prune(Index& index, std::uint64_t now) -> void;
        auto insert(Index& index, Node* node, std::uint64_t order) -> void;
        auto merge_sparse(Index& index) -> void;
        auto evict(Index& index) -> std::uint64_t;
        auto admit(Index& index, Node* node, std::size_t capacity) -> std::expected<void, Error>;
        auto memberships(Root const& root) const noexcept -> std::size_t;
        auto admit_shared(Root& root, std::size_t group, Node* node, std::uint64_t now) -> std::expected<void, Error>;
        static auto fresh(Binding const* binding, std::uint64_t now) noexcept -> bool;
        auto stale(Binding const* binding, std::uint64_t now) const noexcept -> bool;
        static auto copy_answer(Node const& node, std::uint64_t now) -> Answer;
        auto adopt(std::size_t group, Key const& key, std::uint64_t now, AdoptKind kind, std::uint64_t epoch)
            -> std::expected<std::optional<Adopted>, Error>;
        auto clear_locked(std::uint64_t now) -> std::expected<void, Error>;
        auto recover_locked() -> void;
        [[nodiscard]] auto begin_query_owned(std::size_t group, Key key) -> std::expected<Token, Error>;
        template<bool from_acquisition = false>
        auto apply(std::size_t group, Key key, Answer answer, std::optional<Negative> negative,
            std::uint32_t ttl, std::uint64_t now, Token token, bool invalidate,
            std::conditional_t<from_acquisition, std::uint64_t, std::monostate> acquired = {}) -> std::expected<void, Error>;

    public:
        struct Fresh {
            std::optional<Answer> answer;
            std::optional<Negative> negative;
            std::uint64_t expires;
        };
        class Reader {
            friend class GroupSnapshot;
            GroupSnapshot* owner_;
            Hazard* hazard_;
            bool busy_ = false;
            Reader(GroupSnapshot& owner, std::size_t index);
            auto protect() -> Root* {
                Root* root;
                do { root = owner_->current_.load(); hazard_->pointer.store(root); } while (root != owner_->current_.load());
                return root;
            }
        public:
            Reader(Reader const&) = delete;
            auto operator=(Reader const&) -> Reader& = delete;
            Reader(Reader&& other) noexcept : owner_(other.owner_), hazard_(other.hazard_) {
                if (other.busy_) std::terminate();
                other.owner_ = nullptr;
                other.hazard_ = nullptr;
            }
            ~Reader() {
                if (owner_) {
                    if (busy_ || hazard_->pointer.load()) std::terminate();
                    hazard_->claimed.store(false);
                }
            }
        };
        struct SharedCapacity { std::size_t memberships; };
        explicit GroupSnapshot(std::span<std::size_t const> capacities, SharedCapacity shared, std::size_t readers,
                               std::uint64_t stale_window_ms = 0,
                               std::size_t snapshot_budget = std::numeric_limits<std::size_t>::max(),
                               std::uint64_t recovery_delay_ms = 0);
        GroupSnapshot(GroupSnapshot const&) = delete;
        ~GroupSnapshot();

        [[nodiscard]] auto reader(std::size_t index) -> Reader;
        [[nodiscard]] static auto live_nodes() noexcept -> std::size_t { return Node::live.load(std::memory_order_relaxed); }
        [[nodiscard]] static auto peak_nodes() noexcept -> std::size_t { return Node::peak.load(std::memory_order_relaxed); }
        [[nodiscard]] auto fails_closed_on_allocation() const noexcept -> bool { return fail_closed_; }
        [[nodiscard]] auto supports_binding(std::size_t group, std::size_t first_reader, std::size_t readers) const noexcept -> bool {
            return group < group_count_ && first_reader <= reader_count_ && readers <= reader_count_ - first_reader;
        }
        [[nodiscard]] auto charged_bytes() -> std::size_t;
        [[nodiscard]] auto peak_charged_bytes() -> std::size_t;
        [[nodiscard]] auto size(std::size_t group) -> std::size_t;
#ifdef DNS_GROUP_INSPECT_EXPERIMENT
        [[nodiscard]] auto page_count(std::size_t group) -> std::size_t;
        [[nodiscard]] auto contains_member(std::size_t group, Key const& key) -> bool;
        [[nodiscard]] auto total_members() -> std::size_t;
        [[nodiscard]] auto directory_slots(std::size_t group) -> std::size_t;
#endif
        [[nodiscard]] auto begin_query(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type)
            -> std::expected<Token, Error>;
        [[nodiscard]] auto begin_query(std::size_t group, Key const& key) -> std::expected<Token, Error>;
        [[nodiscard]] auto begin_query(std::size_t group, Key&& key) -> std::expected<Token, Error>;
        [[nodiscard]] auto begin_refresh(std::size_t group, Key key, std::uint64_t now, std::size_t maximum)
            -> std::expected<std::optional<Token>, Error>;
        [[nodiscard]] auto cancel_query(Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish(std::size_t group, Key key, Answer answer, std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish_negative(std::size_t group, Key key, Negative negative, std::uint32_t ttl,
                                            std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish_from(std::size_t group, Key key, Answer answer, std::uint64_t acquired,
                                        std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish_negative_from(std::size_t group, Key key, Negative negative, std::uint32_t ttl,
                                                 std::uint64_t acquired, std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto invalidate(std::size_t group, Key key, std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                        Answer&& answer, std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish_copy_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                             Answer const& answer, std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish_copy_view_from(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                                  Answer const& answer, std::uint64_t acquired, std::uint64_t now, Token token)
            -> std::expected<void, Error>;
        [[nodiscard]] auto publish_negative_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                                 Negative negative, std::uint32_t ttl, std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto publish_negative_view_from(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                                      Negative negative, std::uint32_t ttl, std::uint64_t acquired,
                                                      std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto invalidate_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                           std::uint64_t now, Token token) -> std::expected<void, Error>;
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<void, Error>;
        template<class Hook>
        [[nodiscard]] auto lookup_with_hook(std::size_t group, Key key, std::uint64_t now, Reader& reader, Hook&& hook)
            -> std::expected<std::optional<Answer>, Error> {
            check_group(group);
            if (!normalize(key)) return std::unexpected(Error::invalid_key);
            if (reader.owner_ != this) throw std::invalid_argument("wrong cache");
            if (reader.busy_) throw std::logic_error("reader already active");
            if (!capacities_[group]) return std::optional<Answer>{};
            auto epoch = gate_.load();
            if (epoch & 1) return std::optional<Answer>{};
            {
                reader.busy_ = true;
                struct Guard { Reader& reader; ~Guard() { reader.hazard_->pointer.store(nullptr); reader.busy_ = false; } } guard{reader};
                auto* root = reader.protect();
                std::forward<Hook>(hook)();
                auto effective = root->initialized ? std::max(now, root->now) : now;
                auto* binding = find(root->groups[group], key);
                if (fresh(binding, effective)) {
                    if (binding->node->negative) return std::optional<Answer>{};
                    auto answer = copy_answer(*binding->node, effective);
                    if (gate_.load() != epoch) return std::optional<Answer>{};
                    return std::optional<Answer>(std::move(answer));
                }
                bool peer_hit = false;
                for (std::size_t i = 0; i < group_count_; ++i)
                    if (i != group && fresh(find(root->groups[i], key), effective)) { peer_hit = true; break; }
                if (!peer_hit && current_.load(std::memory_order_acquire) == root && gate_.load() == epoch)
                    return std::optional<Answer>{};
            }
            auto result = adopt(group, key, now, AdoptKind::positive, epoch);
            if (!result) return std::unexpected(result.error());
            return *result ? std::move((**result).answer) : std::optional<Answer>{};
        }
        [[nodiscard]] auto lookup(std::size_t group, Key key, std::uint64_t now, Reader& reader) -> std::expected<std::optional<Answer>, Error>;
        [[nodiscard]] auto lookup_fresh(std::size_t group, Key key, std::uint64_t now, Reader& reader) -> std::expected<std::optional<Fresh>, Error>;
        [[nodiscard]] auto lookup_negative(std::size_t group, Key key, std::uint64_t now, Reader& reader) -> std::expected<std::optional<Negative>, Error>;
        [[nodiscard]] auto lookup_stale(std::size_t group, Key key, std::uint64_t now, Reader& reader) -> std::expected<std::optional<Stale>, Error>;
    };
}
