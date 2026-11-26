// GroupSnapshot lifecycle, validation & reader lookup implementation.
module dns.group_snapshot;
import std;
import dns.cache;
import dns.message;

namespace dns_hp_experiment {
    GroupSnapshot::Node::Node(Budget::Lease lease_, Key key_, Answer answer_, std::optional<Negative> negative_,
        std::uint64_t expires_, std::uint64_t discard_, std::uint64_t revision_)
        : lease(std::move(lease_)), key(std::move(key_)), answer(std::move(answer_)), negative(negative_),
          expires(expires_), discard(discard_), revision(revision_) {
        auto count = live.fetch_add(1, std::memory_order_relaxed) + 1;
        auto previous = peak.load(std::memory_order_relaxed);
        while (previous < count && !peak.compare_exchange_weak(previous, count, std::memory_order_relaxed)) {}
    }
    GroupSnapshot::Node::~Node() { live.fetch_sub(1, std::memory_order_relaxed); }

    auto GroupSnapshot::Directory::grow(Budget& budget, std::size_t desired) -> void {
        if (desired <= size_) return;
        auto next = std::min(pages_max, std::max(desired, size_ ? size_ * 2 : std::size_t{1}));
        if (next < desired) std::terminate();
        auto lease = budget.reserve(next * sizeof(Page*));
        auto pages = std::make_unique<Page*[]>(next);
        if (size_) std::copy_n(pages_.get(), size_, pages.get());
        pages_ = std::move(pages);
        lease_.reset();
        lease_.emplace(std::move(lease));
        size_ = next;
    }

    GroupSnapshot::Index::Index(Budget::Lease lease_, Index const& other, Budget& budget)
        : lease(std::move(lease_)), count(other.count), entries(other.entries), next_order(other.next_order) {
        pages.grow(budget, other.pages.size());
        if (count) std::copy_n(other.pages.begin(), count, pages.begin());
    }

    GroupSnapshot::RootPool::~RootPool() {
        for (std::size_t i = 0; i < used; ++i) std::destroy_at(storage + i);
        allocator.deallocate(storage, capacity);
    }

    auto GroupSnapshot::RootPool::create() noexcept -> Root* {
        static_assert(std::is_nothrow_default_constructible_v<Root>);
        if (used == capacity) std::terminate();
        return std::construct_at(storage + used++);
    }

    GroupSnapshot::Reader::Reader(GroupSnapshot& owner, std::size_t index)
        : owner_(&owner), hazard_(&owner.hazards_[index]) {
        if (hazard_->claimed.exchange(true)) throw std::logic_error("reader already registered");
    }

    auto GroupSnapshot::checked_groups(std::span<std::size_t const> groups) -> std::size_t {
        if (groups.empty() || groups.size() > groups_max ||
            std::ranges::any_of(groups, [](auto capacity) { return capacity > entries_max; }))
            throw std::invalid_argument("invalid group capacities");
        return groups.size();
    }

    auto GroupSnapshot::checked_readers(std::size_t readers) -> std::size_t {
        // Up to sixteen listeners with up to 256 workers each, plus SS UDP lookup
        // and the ordered UDP routing context on its separately driven executor.
        if (readers > readers_max) throw std::out_of_range("too many readers");
        return readers;
    }

    auto GroupSnapshot::disable_locked() noexcept -> void {
        auto state = gate_.load(std::memory_order_relaxed);
        if (!(state & 1)) {
            gate_.store(state + 1, std::memory_order_release);
            recovery_deadline_ = std::chrono::steady_clock::now() + recovery_delay_;
        }
        pending_.clear();
    }

    auto GroupSnapshot::disable_after_allocation_failure(std::uint64_t epoch, std::optional<Token> token,
        std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type, std::uint64_t now) -> void {
        if (!fail_closed_) return;
        std::lock_guard lock(mutex_);
        if (gate_.load(std::memory_order_relaxed) != epoch) return;
        if (token) {
            auto* current = current_.load();
            if (token->generation != current->generation) return;
            auto pending = std::ranges::find(pending_, token->query, &Pending::query);
            if (pending == pending_.end() || pending->group != group) return;
            if (name != "." && name.ends_with('.')) name.remove_suffix(1);
            if (pending->key.view != view || pending->key.type != type || pending->key.name.size() != name.size()) return;
            for (std::size_t i = 0; i < name.size(); ++i) {
                auto c = name[i];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                if (pending->key.name[i] != c) return;
            }
            if (pending->refresh) {
                auto* binding = find(current->groups[pending->refresh->source], pending->key);
                now = current->initialized ? std::max(now, current->now) : now;
                if (!binding || binding->node->negative || binding->node->revision != pending->refresh->revision ||
                    (now >= binding->node->expires && now - binding->node->expires >= stale_window_ms_))
                    return;
            }
        }
        disable_locked();
    }

    auto GroupSnapshot::check_group(std::size_t group) const -> void {
        if (group >= group_count_) throw std::out_of_range("group index");
    }

    auto GroupSnapshot::same(Key const& a, Key const& b) noexcept -> bool {
        return a.view == b.view && a.type == b.type && a.name == b.name;
    }

    auto GroupSnapshot::less(Key const& a, Key const& b) noexcept -> bool {
        if (a.view != b.view) return a.view < b.view;
        if (a.type != b.type) return a.type < b.type;
        return a.name < b.name;
    }

    auto GroupSnapshot::normalize(Key& key) -> bool {
        return (key.type == 1 || key.type == 28) && dns::canonicalize_name(key.name);
    }

    auto GroupSnapshot::valid(Answer const& answer, std::uint16_t type) -> bool {
        if (answer.addresses.empty() || answer.addresses.size() > 128 || answer.chain.size() > 16 ||
            answer.canonical_name.size() > 254 || !answer.ttl)
            return false;
        for (auto const& name : answer.chain) if (name.size() > 254) return false;
        for (auto const& address : answer.addresses) if (address.size != (type == 1 ? 4 : 16)) return false;
        return true;
    }

    auto GroupSnapshot::fresh(Binding const* binding, std::uint64_t now) noexcept -> bool {
        return binding && now < binding->node->expires && (binding->node->expires - now) / 1000;
    }

    auto GroupSnapshot::stale(Binding const* binding, std::uint64_t now) const noexcept -> bool {
        if (!binding || binding->node->negative || now < binding->node->expires) return false;
        auto age = now - binding->node->expires;
        return age < stale_window_ms_ && stale_window_ms_ - age >= 1000;
    }

    auto GroupSnapshot::copy_answer(Node const& node, std::uint64_t now) -> Answer {
        auto answer = node.answer;
        answer.ttl = static_cast<std::uint32_t>((node.expires - now) / 1000);
        return answer;
    }

    GroupSnapshot::GroupSnapshot(std::span<std::size_t const> capacities, SharedCapacity shared, std::size_t readers,
                                 std::uint64_t stale_window_ms, std::size_t snapshot_budget, std::uint64_t recovery_delay_ms)
        : group_count_(checked_groups(capacities)), reader_count_(checked_readers(readers)), stale_window_ms_(stale_window_ms),
          budget_(snapshot_budget), fixed_(budget_.reserve(sizeof(Hazard) * reader_count_ + sizeof(Root) * (reader_count_ + 2))),
          fail_closed_(snapshot_budget != std::numeric_limits<std::size_t>::max()),
          recovery_delay_(std::min<std::uint64_t>(recovery_delay_ms, 30000)),
          hazards_(std::make_unique<Hazard[]>(reader_count_)), pool_(reader_count_ + 2), current_(pool_.create()) {
        if (std::ranges::any_of(capacities, [](auto enabled) { return enabled > 1; }))
            throw std::invalid_argument("group must be enabled or disabled");
        auto enabled = static_cast<std::size_t>(std::ranges::count(capacities, std::size_t{1}));
        if (shared.memberships > entries_max || shared.memberships < enabled)
            throw std::invalid_argument("invalid shared capacity");
        total_capacity_ = shared.memberships;
        base_share_ = enabled ? shared.memberships / enabled : 0;
        std::ranges::copy(capacities, capacities_.begin());
    }

    GroupSnapshot::~GroupSnapshot() {
        for (std::size_t i = 0; i < reader_count_; ++i) if (hazards_[i].claimed.load()) std::terminate();
        for (std::size_t i = 0; i < pool_.used; ++i)
            for (auto* index : pool_.storage[i].groups) if (index) drop_index(index);
    }

    auto GroupSnapshot::reader(std::size_t index) -> Reader {
        if (index >= reader_count_) throw std::out_of_range("reader index");
        return Reader(*this, index);
    }

    auto GroupSnapshot::charged_bytes() -> std::size_t { std::lock_guard lock(mutex_); return budget_.used(); }
    auto GroupSnapshot::peak_charged_bytes() -> std::size_t { std::lock_guard lock(mutex_); return budget_.peak(); }
    auto GroupSnapshot::size(std::size_t group) -> std::size_t {
        check_group(group);
        std::lock_guard lock(mutex_);
        auto* index = current_.load()->groups[group];
        return index ? index->entries : 0;
    }

#ifdef DNS_GROUP_INSPECT_EXPERIMENT
    auto GroupSnapshot::page_count(std::size_t group) -> std::size_t {
        check_group(group);
        std::lock_guard lock(mutex_);
        auto* index = current_.load()->groups[group];
        return index ? index->count : 0;
    }
    auto GroupSnapshot::contains_member(std::size_t group, Key const& key) -> bool {
        check_group(group);
        std::lock_guard lock(mutex_);
        return find(current_.load()->groups[group], key) != nullptr;
    }
    auto GroupSnapshot::total_members() -> std::size_t {
        std::lock_guard lock(mutex_);
        return memberships(*current_.load());
    }
    auto GroupSnapshot::directory_slots(std::size_t group) -> std::size_t {
        check_group(group);
        std::lock_guard lock(mutex_);
        auto* index = current_.load()->groups[group];
        return index ? index->pages.size() : 0;
    }
#endif

    namespace {
        // Zero-allocation canonicalization matching dns::canonicalize_name bit-for-bit.
        auto canonicalize_view(std::string_view src, std::array<char, 254>& scratch) noexcept
            -> std::optional<std::string_view> {
            if (src == ".") return src;
            if (src.ends_with('.')) src.remove_suffix(1);
            if (src.empty() || src.size() > 253) return std::nullopt;
            std::size_t label_len = 0, wire_size = 1;
            bool has_upper = false;
            for (unsigned char c : src) {
                if (c == '.') {
                    if (label_len == 0 || label_len > 63) return std::nullopt;
                    wire_size += label_len + 1;
                    if (wire_size > 255) return std::nullopt;
                    label_len = 0;
                } else {
                    if (c < 33 || c > 126 || c == '\\') return std::nullopt;
                    if (c >= 'A' && c <= 'Z') has_upper = true;
                    ++label_len;
                }
            }
            if (label_len == 0 || label_len > 63 || wire_size + label_len + 1 > 255) return std::nullopt;
            if (!has_upper) return src;
            for (std::size_t i = 0; i < src.size(); ++i) {
                auto c = src[i];
                scratch[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
            }
            return std::string_view(scratch.data(), src.size());
        }

        auto key_less(dns::CacheKey const& a, std::uint64_t b_view, std::uint16_t b_type, std::string_view b_name) noexcept -> bool {
            if (a.view != b_view) return a.view < b_view;
            if (a.type != b_type) return a.type < b_type;
            return std::string_view(a.name) < b_name;
        }
        auto view_less(std::uint64_t a_view, std::uint16_t a_type, std::string_view a_name, dns::CacheKey const& b) noexcept -> bool {
            if (a_view != b.view) return a_view < b.view;
            if (a_type != b.type) return a_type < b.type;
            return a_name < std::string_view(b.name);
        }
        auto key_same(dns::CacheKey const& a, std::uint64_t b_view, std::uint16_t b_type, std::string_view b_name) noexcept -> bool {
            return a.view == b_view && a.type == b_type && std::string_view(a.name) == b_name;
        }
    }

    auto GroupSnapshot::lookup(std::size_t group, Key key, std::uint64_t now, Reader& reader)
        -> std::expected<std::optional<Answer>, Error> {
        return lookup_with_hook(group, std::move(key), now, reader, [] {});
    }

    auto GroupSnapshot::lookup_fresh(std::size_t group, Key key, std::uint64_t now, Reader& reader)
        -> std::expected<std::optional<Fresh>, Error> {
        check_group(group);
        if (key.type != 1 && key.type != 28) return std::unexpected(Error::invalid_key);
        std::array<char, 254> scratch;
        auto norm = canonicalize_view(key.name, scratch);
        if (!norm) return std::unexpected(Error::invalid_key);
        if (reader.owner_ != this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        if (!capacities_[group]) return std::optional<Fresh>{};
        auto epoch = gate_.load(std::memory_order_acquire);
        if (epoch & 1) return std::optional<Fresh>{};
        auto find_sv = [&](Index const* index) noexcept -> Binding const* {
            if (!index || !index->count) return nullptr;
            std::size_t pf = 0, pl = index->count;
            while (pf < pl) {
                auto mid = pf + (pl - pf) / 2;
                if (!view_less(key.view, key.type, *norm, index->pages[mid]->values[0].node->key)) pf = mid + 1;
                else pl = mid;
            }
            auto* page = index->pages[pf ? pf - 1 : 0];
            std::size_t first = 0, last = page->count;
            while (first < last) {
                auto mid = first + (last - first) / 2;
                if (key_less(page->values[mid].node->key, key.view, key.type, *norm)) first = mid + 1;
                else last = mid;
            }
            return first < page->count && key_same(page->values[first].node->key, key.view, key.type, *norm)
                ? &page->values[first] : nullptr;
        };
        {
            reader.busy_ = true;
            struct Guard {
                Reader& reader;
                ~Guard() { reader.hazard_->pointer.store(nullptr, std::memory_order_release); reader.busy_ = false; }
            } guard{reader};
            auto* root = reader.protect();
            auto effective = root->initialized ? std::max(now, root->now) : now;
            auto* binding = find_sv(root->groups[group]);
            if (fresh(binding, effective)) {
                Fresh result{{}, {}, binding->node->expires};
                if (binding->node->negative) result.negative = binding->node->negative;
                else result.answer = copy_answer(*binding->node, effective);
                if (gate_.load(std::memory_order_acquire) != epoch) return std::optional<Fresh>{};
                return std::optional<Fresh>(std::move(result));
            }
            bool peer_hit = false;
            for (std::size_t i = 0; i < group_count_; ++i)
                if (i != group && fresh(find_sv(root->groups[i]), effective)) { peer_hit = true; break; }
            if (!peer_hit && current_.load(std::memory_order_acquire) == root && gate_.load(std::memory_order_acquire) == epoch)
                return std::optional<Fresh>{};
        }
        if (std::string_view(key.name) != *norm) key.name.assign(*norm);
        auto adopted = adopt(group, key, now, AdoptKind::positive, epoch);
        if (!adopted) return std::unexpected(adopted.error());
        if (!*adopted) return std::optional<Fresh>{};
        return std::optional<Fresh>(Fresh{std::move((**adopted).answer), (**adopted).negative, (**adopted).expires});
    }

    auto GroupSnapshot::lookup_negative(std::size_t group, Key key, std::uint64_t now, Reader& reader)
        -> std::expected<std::optional<Negative>, Error> {
        check_group(group);
        if (key.type != 1 && key.type != 28) return std::unexpected(Error::invalid_key);
        std::array<char, 254> scratch;
        auto norm = canonicalize_view(key.name, scratch);
        if (!norm) return std::unexpected(Error::invalid_key);
        if (reader.owner_ != this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        if (!capacities_[group]) return std::optional<Negative>{};
        auto epoch = gate_.load(std::memory_order_acquire);
        if (epoch & 1) return std::optional<Negative>{};
        auto find_sv = [&](Index const* index) noexcept -> Binding const* {
            if (!index || !index->count) return nullptr;
            std::size_t pf = 0, pl = index->count;
            while (pf < pl) {
                auto mid = pf + (pl - pf) / 2;
                if (!view_less(key.view, key.type, *norm, index->pages[mid]->values[0].node->key)) pf = mid + 1;
                else pl = mid;
            }
            auto* page = index->pages[pf ? pf - 1 : 0];
            std::size_t first = 0, last = page->count;
            while (first < last) {
                auto mid = first + (last - first) / 2;
                if (key_less(page->values[mid].node->key, key.view, key.type, *norm)) first = mid + 1;
                else last = mid;
            }
            return first < page->count && key_same(page->values[first].node->key, key.view, key.type, *norm)
                ? &page->values[first] : nullptr;
        };
        {
            reader.busy_ = true;
            struct Guard {
                Reader& reader;
                ~Guard() { reader.hazard_->pointer.store(nullptr, std::memory_order_release); reader.busy_ = false; }
            } guard{reader};
            auto* root = reader.protect();
            auto effective = root->initialized ? std::max(now, root->now) : now;
            auto* binding = find_sv(root->groups[group]);
            if (fresh(binding, effective)) {
                auto result = binding->node->negative;
                return gate_.load(std::memory_order_acquire) == epoch ? result : std::optional<Negative>{};
            }
            bool peer_hit = false;
            for (std::size_t i = 0; i < group_count_; ++i)
                if (i != group && fresh(find_sv(root->groups[i]), effective)) { peer_hit = true; break; }
            if (!peer_hit && current_.load(std::memory_order_acquire) == root && gate_.load(std::memory_order_acquire) == epoch)
                return std::optional<Negative>{};
        }
        if (std::string_view(key.name) != *norm) key.name.assign(*norm);
        auto result = adopt(group, key, now, AdoptKind::negative, epoch);
        if (!result) return std::unexpected(result.error());
        return *result ? (**result).negative : std::optional<Negative>{};
    }

    auto GroupSnapshot::lookup_stale(std::size_t group, Key key, std::uint64_t now, Reader& reader)
        -> std::expected<std::optional<Stale>, Error> {
        check_group(group);
        if (key.type != 1 && key.type != 28) return std::unexpected(Error::invalid_key);
        std::array<char, 254> scratch;
        auto norm = canonicalize_view(key.name, scratch);
        if (!norm) return std::unexpected(Error::invalid_key);
        if (reader.owner_ != this) throw std::invalid_argument("wrong cache");
        if (reader.busy_) throw std::logic_error("reader already active");
        if (!capacities_[group]) return std::optional<Stale>{};
        auto epoch = gate_.load(std::memory_order_acquire);
        if (epoch & 1) return std::optional<Stale>{};
        auto find_sv = [&](Index const* index) noexcept -> Binding const* {
            if (!index || !index->count) return nullptr;
            std::size_t pf = 0, pl = index->count;
            while (pf < pl) {
                auto mid = pf + (pl - pf) / 2;
                if (!view_less(key.view, key.type, *norm, index->pages[mid]->values[0].node->key)) pf = mid + 1;
                else pl = mid;
            }
            auto* page = index->pages[pf ? pf - 1 : 0];
            std::size_t first = 0, last = page->count;
            while (first < last) {
                auto mid = first + (last - first) / 2;
                if (key_less(page->values[mid].node->key, key.view, key.type, *norm)) first = mid + 1;
                else last = mid;
            }
            return first < page->count && key_same(page->values[first].node->key, key.view, key.type, *norm)
                ? &page->values[first] : nullptr;
        };
        {
            reader.busy_ = true;
            struct Guard {
                Reader& reader;
                ~Guard() { reader.hazard_->pointer.store(nullptr, std::memory_order_release); reader.busy_ = false; }
            } guard{reader};
            auto* root = reader.protect();
            auto effective = root->initialized ? std::max(now, root->now) : now;
            auto* binding = find_sv(root->groups[group]);
            if (fresh(binding, effective)) return std::optional<Stale>{};
            bool peer_hit = stale(binding, effective);
            for (std::size_t i = 0; !peer_hit && i < group_count_; ++i)
                if (i != group && stale(find_sv(root->groups[i]), effective)) peer_hit = true;
            if (!peer_hit && root->initialized && now <= root->now &&
                current_.load(std::memory_order_acquire) == root && gate_.load(std::memory_order_acquire) == epoch)
                return std::optional<Stale>{};
        }
        if (std::string_view(key.name) != *norm) key.name.assign(*norm);
        auto result = adopt(group, key, now, AdoptKind::stale, epoch);
        if (!result) return std::unexpected(result.error());
        return *result ? std::move((**result).stale) : std::optional<Stale>{};
    }
}
