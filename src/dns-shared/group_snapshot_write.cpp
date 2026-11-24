// GroupSnapshot COW page-tree & writer publication implementation.
module dns.group_snapshot;
import std;
import dns.cache;
import dns.message;

namespace dns_hp_experiment {
    auto GroupSnapshot::node_charge(Key const& key, Answer const& answer) noexcept -> std::size_t {
        auto bytes = sizeof(Node) + key.name.capacity() + 1 + answer.canonical_name.capacity() + 1 +
            answer.chain.capacity() * sizeof(std::string) + answer.addresses.capacity() * sizeof(dns::Address);
        for (auto const& name : answer.chain) bytes += name.capacity() + 1;
        return bytes;
    }
    auto GroupSnapshot::drop_node(Node* node) noexcept -> void { if (--node->refs == 0) delete node; }
    auto GroupSnapshot::drop_page(Page* page) noexcept -> void {
        if (--page->refs) return;
        for (std::size_t i = 0; i < page->count; ++i) drop_node(page->values[i].node);
        delete page;
    }
    auto GroupSnapshot::drop_index(Index* index) noexcept -> void {
        if (--index->refs) return;
        for (std::size_t i = 0; i < index->count; ++i) drop_page(index->pages[i]);
        delete index;
    }
    auto GroupSnapshot::summarize(Page& page) noexcept -> void {
        page.min_expiry = std::numeric_limits<std::uint64_t>::max();
        page.min_discard = std::numeric_limits<std::uint64_t>::max();
        page.min_order = 0;
        for (std::size_t i = 0; i < page.count; ++i) {
            auto const& binding = page.values[i];
            page.min_discard = std::min(page.min_discard, binding.node->discard);
            if (!i || std::pair{binding.node->expires, binding.order} < std::pair{page.min_expiry, page.min_order}) {
                page.min_expiry = binding.node->expires;
                page.min_order = binding.order;
            }
        }
    }
    auto GroupSnapshot::page_index(Index const& index, Key const& key) noexcept -> std::size_t {
        std::size_t first = 0, last = index.count;
        while (first < last) {
            auto middle = first + (last - first) / 2;
            if (!less(key, index.pages[middle]->values[0].node->key)) first = middle + 1;
            else last = middle;
        }
        return first ? first - 1 : 0;
    }
    auto GroupSnapshot::lower(Page const& page, Key const& key) noexcept -> std::size_t {
        std::size_t first = 0, last = page.count;
        while (first < last) {
            auto middle = first + (last - first) / 2;
            if (less(page.values[middle].node->key, key)) first = middle + 1;
            else last = middle;
        }
        return first;
    }
    auto GroupSnapshot::find(Index const* index, Key const& key) noexcept -> Binding const* {
        if (!index || !index->count) return nullptr;
        auto* page = index->pages[page_index(*index, key)];
        auto position = lower(*page, key);
        return position < page->count && same(page->values[position].node->key, key) ? &page->values[position] : nullptr;
    }
    auto GroupSnapshot::recycle(Root* root) noexcept -> void {
        for (auto& group : root->groups) if (group) { drop_index(group); group = nullptr; }
        root->generation = 1; root->now = 0; root->initialized = false;
        root->next = free_; free_ = root;
    }
    auto GroupSnapshot::collect() noexcept -> void {
        auto** link = &retired_;
        while (auto* root = *link) {
            bool guarded = false;
            for (std::size_t i = 0; i < reader_count_; ++i) if (hazards_[i].pointer.load() == root) { guarded = true; break; }
            if (guarded) link = &root->next;
            else { *link = root->next; recycle(root); }
        }
    }
    auto GroupSnapshot::clone(Root const& source) noexcept -> Root* {
        collect();
        auto* root = free_;
        if (root) { free_ = root->next; root->next = nullptr; } else root = pool_.create();
        root->generation = source.generation; root->now = source.now; root->initialized = source.initialized;
        for (std::size_t i = 0; i < group_count_; ++i) {
            root->groups[i] = source.groups[i];
            if (root->groups[i]) ++root->groups[i]->refs;
        }
        return root;
    }
    auto GroupSnapshot::commit(Root* root) noexcept -> void {
        auto* old = current_.exchange(root);
        old->next = retired_;
        retired_ = old;
        collect();
    }
    auto GroupSnapshot::writable_index(Root& root, std::size_t group) -> Index& {
        auto* original = root.groups[group];
        if (!original) { root.groups[group] = new Index(budget_.reserve(sizeof(Index))); return *root.groups[group]; }
        if (original->refs == 1) return *original;
        auto copy = std::make_unique<Index>(budget_.reserve(sizeof(Index)), *original, budget_);
        for (std::size_t i = 0; i < copy->count; ++i) ++copy->pages[i]->refs;
        root.groups[group] = copy.release();
        drop_index(original);
        return *root.groups[group];
    }
    auto GroupSnapshot::writable_page(Index& index, std::size_t position) -> Page& {
        auto* original = index.pages[position];
        if (original->refs == 1) return *original;
        auto copy = std::make_unique<Page>(budget_.reserve(sizeof(Page)), *original);
        for (std::size_t i = 0; i < copy->count; ++i) ++copy->values[i].node->refs;
        index.pages[position] = copy.release();
        drop_page(original);
        return *index.pages[position];
    }
    auto GroupSnapshot::erase(Index& index, std::size_t page_index_, std::size_t position) -> void {
        auto& page = writable_page(index, page_index_);
        drop_node(page.values[position].node);
        std::move(page.values.begin() + position + 1, page.values.begin() + page.count, page.values.begin() + position);
        page.values[--page.count] = {};
        --index.entries;
        if (page.count) { summarize(page); return; }
        drop_page(index.pages[page_index_]);
        std::move(index.pages.begin() + page_index_ + 1, index.pages.begin() + index.count, index.pages.begin() + page_index_);
        index.pages[--index.count] = nullptr;
    }
    auto GroupSnapshot::remove(Index& index, Key const& key) -> void {
        if (!index.count) return;
        auto page_number = page_index(index, key);
        auto* page = index.pages[page_number];
        auto position = lower(*page, key);
        if (position < page->count && same(page->values[position].node->key, key)) erase(index, page_number, position);
    }
    auto GroupSnapshot::prune(Index& index, std::uint64_t now) -> void {
        for (std::size_t i = 0; i < index.count;) {
            if (index.pages[i]->min_discard > now) { ++i; continue; }
            auto& page = writable_page(index, i);
            std::size_t out = 0;
            for (std::size_t j = 0; j < page.count; ++j) {
                auto binding = page.values[j];
                if (binding.node->expires <= now && (binding.node->negative || now - binding.node->expires >= stale_window_ms_)) {
                    drop_node(binding.node);
                    --index.entries;
                } else page.values[out++] = binding;
            }
            for (std::size_t j = out; j < page.count; ++j) page.values[j] = {};
            page.count = out;
            if (out) { summarize(page); ++i; }
            else {
                drop_page(index.pages[i]);
                std::move(index.pages.begin() + i + 1, index.pages.begin() + index.count, index.pages.begin() + i);
                index.pages[--index.count] = nullptr;
            }
        }
    }
    auto GroupSnapshot::insert(Index& index, Node* node, std::uint64_t order) -> void {
        if (!index.count) {
            index.pages.grow(budget_, 1);
            auto page = std::make_unique<Page>(budget_.reserve(sizeof(Page)));
            ++node->refs;
            page->values[0] = {node, order};
            page->count = 1;
            summarize(*page);
            index.pages[0] = page.release();
            index.count = 1;
            index.entries = 1;
            return;
        }
        auto i = page_index(index, node->key);
        auto& page = writable_page(index, i);
        auto position = lower(page, node->key);
        if (position < page.count && same(page.values[position].node->key, node->key)) {
            ++node->refs;
            drop_node(page.values[position].node);
            page.values[position].node = node;
            summarize(page);
            return;
        }
        if (page.count == page_size) {
            index.pages.grow(budget_, index.count + 1);
            if (index.count == index.pages.size()) std::terminate();
            auto right = std::make_unique<Page>(budget_.reserve(sizeof(Page)));
            right->count = page.count / 2;
            for (std::size_t j = 0; j < right->count; ++j) {
                right->values[j] = page.values[page.count / 2 + j];
                page.values[page.count / 2 + j] = {};
            }
            page.count /= 2;
            summarize(page);
            summarize(*right);
            std::move_backward(index.pages.begin() + i + 1, index.pages.begin() + index.count, index.pages.begin() + index.count + 1);
            index.pages[i + 1] = right.release();
            ++index.count;
            if (!less(node->key, index.pages[i + 1]->values[0].node->key)) ++i;
        }
        auto& target = *index.pages[i];
        position = lower(target, node->key);
        std::move_backward(target.values.begin() + position, target.values.begin() + target.count, target.values.begin() + target.count + 1);
        ++node->refs;
        target.values[position] = {node, order};
        ++target.count;
        ++index.entries;
        summarize(target);
    }
    auto GroupSnapshot::merge_sparse(Index& index) -> void {
        for (std::size_t i = 0; i + 1 < index.count;) {
            auto* right = index.pages[i + 1];
            if (index.pages[i]->count + right->count > page_size) { ++i; continue; }
            auto& left = writable_page(index, i);
            for (std::size_t j = 0; j < right->count; ++j) {
                ++right->values[j].node->refs;
                left.values[left.count++] = right->values[j];
            }
            summarize(left);
            drop_page(right);
            std::move(index.pages.begin() + i + 2, index.pages.begin() + index.count, index.pages.begin() + i + 1);
            index.pages[--index.count] = nullptr;
        }
    }
    auto GroupSnapshot::evict(Index& index) -> std::uint64_t {
        std::size_t victim = 0;
        for (std::size_t i = 1; i < index.count; ++i)
            if (std::pair{index.pages[i]->min_expiry, index.pages[i]->min_order} <
                std::pair{index.pages[victim]->min_expiry, index.pages[victim]->min_order}) victim = i;
        auto* page = index.pages[victim];
        std::size_t position = 0;
        while (page->values[position].node->expires != page->min_expiry ||
               page->values[position].order != page->min_order) ++position;
        auto order = page->values[position].order;
        erase(index, victim, position);
        return order;
    }
    auto GroupSnapshot::admit(Index& index, Node* node, std::size_t capacity) -> std::expected<void, Error> {
        std::uint64_t order = 0;
        if (auto* existing = find(&index, node->key)) order = existing->order;
        else if (index.entries == capacity) order = evict(index);
        else {
            if (index.next_order == std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
            order = ++index.next_order;
        }
        insert(index, node, order);
        return {};
    }
    auto GroupSnapshot::memberships(Root const& root) const noexcept -> std::size_t {
        std::size_t total = 0;
        for (std::size_t i = 0; i < group_count_; ++i) if (root.groups[i]) total += root.groups[i]->entries;
        return total;
    }
    auto GroupSnapshot::admit_shared(Root& root, std::size_t group, Node* node, std::uint64_t now) -> std::expected<void, Error> {
        auto& own = *root.groups[group];
        if (find(&own, node->key)) return admit(own, node, total_capacity_);
        auto total = memberships(root);
        if (total == total_capacity_) {
            for (std::size_t i = 0; i < group_count_; ++i) if (i != group && root.groups[i]) {
                auto* index = root.groups[i];
                bool expired = false;
                for (std::size_t p = 0; p < index->count && !expired; ++p) expired = index->pages[p]->min_discard <= now;
                if (expired) {
                    auto& writable = writable_index(root, i);
                    prune(writable, now);
                    merge_sparse(writable);
                }
            }
            total = memberships(root);
        }
        if (total == total_capacity_) {
            if (own.entries < base_share_) {
                std::size_t victim = group, largest = 0;
                for (std::size_t i = 0; i < group_count_; ++i) {
                    auto* index = root.groups[i];
                    auto count = index ? index->entries : 0;
                    auto excess = count > base_share_ ? count - base_share_ : 0;
                    if (excess > largest) { largest = excess; victim = i; }
                }
                if (!largest || victim == group) std::terminate();
                auto& lender = writable_index(root, victim);
                (void)evict(lender);
                merge_sparse(lender);
            } else {
                return admit(own, node, own.entries);
            }
        }
        return admit(own, node, total_capacity_);
    }
    auto GroupSnapshot::adopt(std::size_t group, Key const& key, std::uint64_t now, AdoptKind kind, std::uint64_t epoch)
        -> std::expected<std::optional<Adopted>, Error> {
        std::lock_guard lock(mutex_);
        auto* current = current_.load();
        if ((epoch & 1) || gate_.load() != epoch) return std::optional<Adopted>{};
        try {
            now = current->initialized ? std::max(now, current->now) : now;
            if (!current->initialized || current->now < now) {
                Builder time_update{*this, clone(*current)};
                time_update.root->now = now;
                time_update.root->initialized = true;
                time_update.publish();
                current = current_.load();
            }
            auto* own = find(current->groups[group], key);
            auto usable = [&](Binding const* binding) {
                return kind == AdoptKind::stale ? stale(binding, now) : fresh(binding, now);
            };
            auto capture = [&](Node const& node) {
                Adopted result;
                result.expires = node.expires;
                if (kind == AdoptKind::stale) {
                    auto answer = node.answer;
                    answer.ttl = 1;
                    result.stale = Stale{std::move(answer), now - node.expires};
                }
                else if (node.negative) result.negative = node.negative;
                else result.answer = copy_answer(node, now);
                return result;
            };
            if (usable(own)) return std::optional<Adopted>(capture(*own->node));
            Node* node = nullptr;
            for (std::size_t i = 0; i < group_count_; ++i) if (i != group) {
                auto* candidate = find(current->groups[i], key);
                if (usable(candidate)) { node = candidate->node; break; }
            }
            if (!node) return std::optional<Adopted>{};
            auto result = capture(*node);
            try {
                Builder builder{*this, clone(*current)};
                builder.root->now = now;
                builder.root->initialized = true;
                auto& index = writable_index(*builder.root, group);
                prune(index, now);
                if (auto admitted = admit_shared(*builder.root, group, node, now); !admitted) return result;
                merge_sparse(index);
                builder.publish();
            } catch (BudgetExceeded const&) { return result; }
            return std::optional<Adopted>(std::move(result));
        } catch (BudgetExceeded const&) { return std::optional<Adopted>{}; }
    }
}
