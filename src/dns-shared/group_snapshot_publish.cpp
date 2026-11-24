// GroupSnapshot query lifecycle, publication and clear implementation.
module dns.group_snapshot;
import std;
import dns.cache;
import dns.message;

namespace dns_hp_experiment {
    auto GroupSnapshot::clear_locked(std::uint64_t now) -> std::expected<void, Error> {
        auto* current = current_.load();
        now = current->initialized ? std::max(now, current->now) : now;
        if (gate_.load() == std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        if (current->generation == std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        Builder builder{*this, clone(*current)};
        for (auto& index : builder.root->groups) if (index) { drop_index(index); index = nullptr; }
        builder.root->generation = current->generation + 1;
        builder.root->now = now;
        builder.root->initialized = true;
        pending_.clear();
        next_query_ = 0;
        builder.publish();
        auto state = gate_.load();
        if (state & 1) gate_.store(state + 1);
        else if (state <= std::numeric_limits<std::uint64_t>::max() - 2) gate_.store(state + 2);
        else gate_.store(std::numeric_limits<std::uint64_t>::max());
        return {};
    }
    auto GroupSnapshot::recover_locked() -> void {
        if (!(gate_.load() & 1) || !recovery_delay_.count() || std::chrono::steady_clock::now() < recovery_deadline_) return;
        for (std::size_t i = 0; i < reader_count_; ++i) if (hazards_[i].pointer.load()) return;
        auto* current = current_.load();
        (void)clear_locked(current->initialized ? current->now : 0);
    }
    auto GroupSnapshot::begin_query_owned(std::size_t group, Key key) -> std::expected<Token, Error> {
        check_group(group);
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_);
        if (gate_.load() & 1) {
            recover_locked();
            if (gate_.load() & 1) return std::unexpected(Error::disabled);
        }
        try {
            if (pending_.size() == 4096) {
                if (fail_closed_) disable_locked();
                return std::unexpected(Error::query_limit);
            }
            if (next_query_ == std::numeric_limits<std::uint64_t>::max()) {
                if (fail_closed_) disable_locked();
                return std::unexpected(Error::generation_exhausted);
            }
            if (!dns::detail::compact_key_storage(key)) {
                if (fail_closed_) disable_locked();
                return std::unexpected(Error::invalid_key);
            }
            auto query = next_query_ + 1;
            pending_.push_back({group, std::move(key), query, {}});
            next_query_ = query;
            return Token{current_.load()->generation, query};
        } catch (std::bad_alloc const&) {
            if (fail_closed_) disable_locked();
            throw;
        }
    }
    auto GroupSnapshot::begin_query(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type)
        -> std::expected<Token, Error> {
        check_group(group);
        if (name.size() > 254) return std::unexpected(Error::invalid_key);
        auto epoch = gate_.load();
        if (epoch & 1) {
            if (!recovery_delay_.count()) return std::unexpected(Error::disabled);
            std::lock_guard lock(mutex_);
            recover_locked();
            epoch = gate_.load();
            if (epoch & 1) return std::unexpected(Error::disabled);
        }
        try { return begin_query_owned(group, Key{view, std::string(name), type}); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch); throw; }
    }
    auto GroupSnapshot::begin_query(std::size_t group, Key const& key) -> std::expected<Token, Error> {
        return begin_query(group, key.view, key.name, key.type);
    }
    auto GroupSnapshot::begin_query(std::size_t group, Key&& key) -> std::expected<Token, Error> {
        return begin_query_owned(group, std::move(key));
    }
    auto GroupSnapshot::begin_refresh(std::size_t group, Key key, std::uint64_t now, std::size_t maximum)
        -> std::expected<std::optional<Token>, Error> {
        check_group(group);
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_);
        auto* current = current_.load();
        if (gate_.load() & 1) return std::unexpected(Error::disabled);
        now = current->initialized ? std::max(now, current->now) : now;
        if (!current->initialized || current->now < now) {
            Builder time_update{*this, clone(*current)};
            time_update.root->now = now;
            time_update.root->initialized = true;
            time_update.publish();
            current = current_.load();
        }
        auto* binding = find(current->groups[group], key);
        std::size_t source = group;
        if (binding && now < binding->node->expires) return std::optional<Token>{};
        if (!stale(binding, now)) {
            binding = nullptr;
            if (capacities_[group]) for (std::size_t i = 0; i < group_count_; ++i) if (i != group) {
                auto* candidate = find(current->groups[i], key);
                if (stale(candidate, now)) { binding = candidate; source = i; break; }
            }
        }
        if (!binding) return std::optional<Token>{};
        if (std::ranges::any_of(pending_, [&](auto const& item) { return same(item.key, key); })) return std::optional<Token>{};
        auto refreshes = std::ranges::count_if(pending_, [](auto const& item) { return item.refresh.has_value(); });
        if (static_cast<std::size_t>(refreshes) >= maximum) return std::optional<Token>{};
        if (pending_.size() == 4096) return std::unexpected(Error::query_limit);
        if (next_query_ == std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        if (!dns::detail::compact_key_storage(key)) return std::unexpected(Error::invalid_key);
        auto query = next_query_ + 1;
        pending_.push_back({group, std::move(key), query, Refresh{source, binding->node->revision}});
        next_query_ = query;
        return std::optional<Token>(Token{current->generation, query});
    }
    auto GroupSnapshot::cancel_query(Token token) -> std::expected<void, Error> {
        std::lock_guard lock(mutex_);
        if (token.generation != current_.load()->generation) return std::unexpected(Error::stale_generation);
        auto pending = std::ranges::find(pending_, token.query, &Pending::query);
        if (pending == pending_.end()) return std::unexpected(Error::stale_query);
        pending_.erase(pending);
        return {};
    }
    template<bool from_acquisition>
    auto GroupSnapshot::apply(std::size_t group, Key key, Answer answer, std::optional<Negative> negative,
        std::uint32_t ttl, std::uint64_t now, Token token, bool invalidate,
        std::conditional_t<from_acquisition, std::uint64_t, std::monostate> acquired) -> std::expected<void, Error> {
        check_group(group);
        std::lock_guard lock(mutex_);
        auto* current = current_.load();
        if (gate_.load() & 1) return std::unexpected(Error::disabled);
        try {
            now = current->initialized ? std::max(now, current->now) : now;
            if (token.generation != current->generation) return std::unexpected(Error::stale_generation);
            auto pending = std::ranges::find(pending_, token.query, &Pending::query);
            if (pending == pending_.end() || pending->group != group || !same(pending->key, key))
                return std::unexpected(Error::stale_query);
            if (pending->refresh) {
                auto* binding = find(current->groups[pending->refresh->source], key);
                if (!binding || binding->node->negative || binding->node->revision != pending->refresh->revision ||
                    (now >= binding->node->expires && now - binding->node->expires >= stale_window_ms_))
                    return std::unexpected(Error::stale_query);
            }
            if (!invalidate && !capacities_[group]) return std::unexpected(Error::disabled);
            auto duration = std::uint64_t(ttl) * 1000;
            if constexpr (from_acquisition) {
                if (acquired > now || duration > std::numeric_limits<std::uint64_t>::max() - acquired)
                    return std::unexpected(Error::invalid_answer);
                auto expiry = acquired + duration;
                duration = expiry > now ? expiry - now : 0;
            } else if (duration > std::numeric_limits<std::uint64_t>::max() - now) return std::unexpected(Error::invalid_answer);
            auto destination = pending->refresh ? pending->refresh->source : group;
            collect();
            auto drop_owned = [](Node* node) noexcept { if (node) drop_node(node); };
            std::unique_ptr<Node, decltype(drop_owned)> node(nullptr, drop_owned);
            if (!invalidate && duration) {
                Key stored_key = key;
                if (!dns::detail::compact_key_storage(stored_key)) return std::unexpected(Error::invalid_key);
                if (!negative && !dns::detail::compact_answer_storage(answer)) return std::unexpected(Error::invalid_answer);
                auto discard = now + duration;
                if (!negative) discard += std::min(stale_window_ms_, std::numeric_limits<std::uint64_t>::max() - discard);
                auto charge = budget_.reserve(node_charge(stored_key, answer));
                node.reset(new Node(std::move(charge), std::move(stored_key), std::move(answer), negative, now + duration, discard, token.query));
            }
            Builder builder{*this, clone(*current)};
            builder.root->now = now;
            builder.root->initialized = true;
            if (!node) {
                for (std::size_t i = 0; i < group_count_; ++i) if (find(builder.root->groups[i], key)) {
                    auto& index = writable_index(*builder.root, i);
                    remove(index, key);
                    merge_sparse(index);
                }
            } else {
                auto& own = writable_index(*builder.root, destination);
                prune(own, now);
                for (std::size_t i = 0; i < group_count_; ++i) if (find(builder.root->groups[i], key)) {
                    auto& index = writable_index(*builder.root, i);
                    insert(index, node.get(), 0);
                }
                if (!find(&own, key)) {
                    if (auto result = admit_shared(*builder.root, destination, node.get(), now); !result) return result;
                }
                merge_sparse(own);
            }
            std::erase_if(pending_, [&](Pending const& item) { return item.query <= token.query && same(item.key, key); });
            builder.publish();
            return {};
        } catch (BudgetExceeded const&) {
            disable_locked();
            return std::unexpected(Error::disabled);
        } catch (std::bad_alloc const&) {
            if (fail_closed_) disable_locked();
            throw;
        }
    }
    auto GroupSnapshot::publish(std::size_t group, Key key, Answer answer, std::uint64_t now, Token token) -> std::expected<void, Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (!valid(answer, key.type)) return std::unexpected(Error::invalid_answer);
        auto ttl = *answer.ttl;
        return apply(group, std::move(key), std::move(answer), {}, ttl, now, token, false);
    }
    auto GroupSnapshot::publish_negative(std::size_t group, Key key, Negative negative, std::uint32_t ttl,
                                         std::uint64_t now, Token token) -> std::expected<void, Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        return apply(group, std::move(key), {}, negative, ttl, now, token, false);
    }
    auto GroupSnapshot::publish_from(std::size_t group, Key key, Answer answer, std::uint64_t acquired,
                                      std::uint64_t now, Token token) -> std::expected<void, Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (!valid(answer, key.type)) return std::unexpected(Error::invalid_answer);
        auto ttl = *answer.ttl;
        return apply<true>(group, std::move(key), std::move(answer), {}, ttl, now, token, false, acquired);
    }
    auto GroupSnapshot::publish_negative_from(std::size_t group, Key key, Negative negative, std::uint32_t ttl,
                                              std::uint64_t acquired, std::uint64_t now, Token token) -> std::expected<void, Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        return apply<true>(group, std::move(key), {}, negative, ttl, now, token, false, acquired);
    }
    auto GroupSnapshot::invalidate(std::size_t group, Key key, std::uint64_t now, Token token) -> std::expected<void, Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        return apply(group, std::move(key), {}, {}, 0, now, token, true);
    }
    auto GroupSnapshot::publish_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                     Answer&& answer, std::uint64_t now, Token token) -> std::expected<void, Error> {
        check_group(group);
        if (name.size() > 254) return std::unexpected(Error::invalid_key);
        auto epoch = gate_.load(); if (epoch & 1) return std::unexpected(Error::disabled);
        try { return publish(group, Key{view, std::string(name), type}, std::move(answer), now, token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch, token, group, view, name, type, now); throw; }
    }
    auto GroupSnapshot::publish_copy_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                          Answer const& answer, std::uint64_t now, Token token) -> std::expected<void, Error> {
        check_group(group);
        if (name.size() > 254) return std::unexpected(Error::invalid_key);
        auto epoch = gate_.load(); if (epoch & 1) return std::unexpected(Error::disabled);
        try { Answer copy = answer; return publish_view(group, view, name, type, std::move(copy), now, token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch, token, group, view, name, type, now); throw; }
    }
    auto GroupSnapshot::publish_copy_view_from(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                               Answer const& answer, std::uint64_t acquired, std::uint64_t now, Token token)
        -> std::expected<void, Error> {
        check_group(group);
        if (name.size() > 254) return std::unexpected(Error::invalid_key);
        auto epoch = gate_.load(); if (epoch & 1) return std::unexpected(Error::disabled);
        try { return publish_from(group, Key{view, std::string(name), type}, answer, acquired, now, token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch, token, group, view, name, type, now); throw; }
    }
    auto GroupSnapshot::publish_negative_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                              Negative negative, std::uint32_t ttl, std::uint64_t now, Token token) -> std::expected<void, Error> {
        check_group(group);
        if (name.size() > 254) return std::unexpected(Error::invalid_key);
        auto epoch = gate_.load(); if (epoch & 1) return std::unexpected(Error::disabled);
        try { return publish_negative(group, Key{view, std::string(name), type}, negative, ttl, now, token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch, token, group, view, name, type, now); throw; }
    }
    auto GroupSnapshot::publish_negative_view_from(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                                   Negative negative, std::uint32_t ttl, std::uint64_t acquired,
                                                   std::uint64_t now, Token token) -> std::expected<void, Error> {
        check_group(group);
        if (name.size() > 254) return std::unexpected(Error::invalid_key);
        auto epoch = gate_.load(); if (epoch & 1) return std::unexpected(Error::disabled);
        try { return publish_negative_from(group, Key{view, std::string(name), type}, negative, ttl, acquired, now, token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch, token, group, view, name, type, now); throw; }
    }
    auto GroupSnapshot::invalidate_view(std::size_t group, std::uint64_t view, std::string_view name, std::uint16_t type,
                                        std::uint64_t now, Token token) -> std::expected<void, Error> {
        check_group(group);
        if (name.size() > 254) return std::unexpected(Error::invalid_key);
        auto epoch = gate_.load(); if (epoch & 1) return std::unexpected(Error::disabled);
        try { return invalidate(group, Key{view, std::string(name), type}, now, token); }
        catch (std::bad_alloc const&) { disable_after_allocation_failure(epoch, token, group, view, name, type, now); throw; }
    }
    auto GroupSnapshot::clear(std::uint64_t now) -> std::expected<void, Error> {
        std::lock_guard lock(mutex_);
        return clear_locked(now);
    }
}
