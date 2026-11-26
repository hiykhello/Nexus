module udp;
import std;
import functional;
import utility;

namespace udp {
    namespace {
        auto next_pow2(std::size_t n) noexcept -> std::size_t {
            std::size_t p = 16;
            while (p < n) p <<= 1;
            return p;
        }
    }

    template <typename Endpoint>
    BasicFlowTable<Endpoint>::BasicFlowTable(Mapping mapping, Filtering filtering, Limits limits, RetirementHandler retirement)
        : mapping_(mapping), filtering_(filtering), limits_(limits), retirement_(retirement) {
        if (limits_.flows > 0 && limits_.flows <= kMaxFlows) {
            slots_.resize(limits_.flows);
            auto const bsz = next_pow2(limits_.flows * 2);
            local_mask_ = bsz - 1;
            local_buckets_.assign(bsz, LocalBucket{});
        }
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::hash_endpoint(Endpoint const& ep) noexcept -> std::size_t {
        std::uint64_t h = 14695981039346656037ull;
        auto mix = [&](std::uint64_t v) noexcept { h = (h ^ v) * 1099511628211ull; };
        if constexpr (sizeof(ep.address) == 4) {
            std::uint32_t a = 0;
            std::memcpy(&a, ep.address.data(), 4);
            mix(a);
        } else {
            std::uint64_t a0 = 0, a1 = 0;
            std::memcpy(&a0, ep.address.data(), 8);
            std::memcpy(&a1, ep.address.data() + 8, 8);
            mix(a0);
            mix(a1);
        }
        mix(ep.port);
        return static_cast<std::size_t>(h ^ (h >> 32));
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::lookup_slot(FlowId id) noexcept -> Flow* {
        auto idx = slot_index(id);
        if (idx >= slots_.size()) return nullptr;
        auto& slot = slots_[idx];
        return (slot.used && slot.id == id) ? &slot : nullptr;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::local_find_head(Endpoint const& local, std::size_t hash) const noexcept -> std::uint32_t {
        if (local_buckets_.empty() || !active_count_) return kNull;
        for (std::size_t pos = hash & local_mask_; ; pos = (pos + 1) & local_mask_) {
            auto const& b = local_buckets_[pos];
            if (b.head == kNull) return kNull;
            if (b.hash == hash && slots_[b.head].local == local) return b.head;
        }
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::local_insert(std::uint32_t idx) noexcept -> void {
        auto const h = slots_[idx].local_hash;
        auto const& local = slots_[idx].local;
        for (std::size_t pos = h & local_mask_; ; pos = (pos + 1) & local_mask_) {
            auto& b = local_buckets_[pos];
            if (b.head == kNull) {
                b = {idx, h};
                slots_[idx].local_next = kNull;
                return;
            }
            if (b.hash == h && slots_[b.head].local == local) {
                slots_[idx].local_next = b.head;
                b.head = idx;
                return;
            }
        }
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::local_erase(std::uint32_t idx) noexcept -> void {
        auto const h = slots_[idx].local_hash;
        auto const& local = slots_[idx].local;
        std::size_t pos = h & local_mask_;
        for (; ; pos = (pos + 1) & local_mask_) {
            auto const& b = local_buckets_[pos];
            if (b.head == kNull) return;
            if (b.hash == h && slots_[b.head].local == local) break;
        }
        if (local_buckets_[pos].head == idx) {
            auto nxt = slots_[idx].local_next;
            slots_[idx].local_next = kNull;
            if (nxt != kNull) { local_buckets_[pos].head = nxt; return; }
            std::size_t hole = pos;
            for (std::size_t scan = (hole + 1) & local_mask_; local_buckets_[scan].head != kNull; scan = (scan + 1) & local_mask_) {
                auto ideal = local_buckets_[scan].hash & local_mask_;
                if (((scan - ideal) & local_mask_) >= ((scan - hole) & local_mask_)) {
                    local_buckets_[hole] = local_buckets_[scan];
                    hole = scan;
                }
            }
            local_buckets_[hole] = {};
            return;
        }
        for (auto prev = local_buckets_[pos].head; prev != kNull; prev = slots_[prev].local_next) {
            if (slots_[prev].local_next == idx) {
                slots_[prev].local_next = slots_[idx].local_next;
                slots_[idx].local_next = kNull;
                return;
            }
        }
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::lru_unlink(std::uint32_t idx) noexcept -> void {
        auto p = slots_[idx].lru_prev, n = slots_[idx].lru_next;
        if (p != kNull) slots_[p].lru_next = n; else lru_head_ = n;
        if (n != kNull) slots_[n].lru_prev = p; else lru_tail_ = p;
        slots_[idx].lru_prev = slots_[idx].lru_next = kNull;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::lru_link_tail(std::uint32_t idx) noexcept -> void {
        slots_[idx].lru_prev = lru_tail_;
        slots_[idx].lru_next = kNull;
        if (lru_tail_ != kNull) slots_[lru_tail_].lru_next = idx; else lru_head_ = idx;
        lru_tail_ = idx;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::lru_touch(std::uint32_t idx) noexcept -> void {
        if (idx == lru_tail_) return;
        lru_unlink(idx);
        lru_link_tail(idx);
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::erase_slot(std::uint32_t idx) noexcept -> void {
        auto& flow = slots_[idx];
        if (flow.idle_override_ms) --custom_idle_count_;
        local_erase(idx);
        lru_unlink(idx);
        flow.id = 0;
        flow.used = false;
        flow.sent = false;
        flow.idle_override_ms = 0;
        flow.pending.reset();
        flow.inline_peers.clear();
        std::vector<Endpoint>{}.swap(flow.extra_peers);
        flow.next_free = free_head_;
        free_head_ = idx;
        --active_count_;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::advance(std::uint64_t now) -> std::expected<std::size_t, Error> {
        if (limits_.idle_ms == 0 || limits_.flows > kMaxFlows) return std::unexpected(Error::invalid_config);
        if (initialized_ && now < now_) return std::unexpected(Error::time_reversed);
        initialized_ = true;
        now_ = now;
        std::size_t removed = 0;
        if (custom_idle_count_ == 0) {
            while (lru_head_ != kNull && now - slots_[lru_head_].touched >= limits_.idle_ms) {
                auto cur = lru_head_;
                if (retirement_.notify) retirement_.notify(retirement_.context, slots_[cur].id);
                erase_slot(cur);
                ++removed;
            }
            return removed;
        }
        for (auto cur = lru_head_; cur != kNull; ) {
            auto nxt = slots_[cur].lru_next;
            auto idle = slots_[cur].idle_override_ms ? slots_[cur].idle_override_ms : limits_.idle_ms;
            if (now - slots_[cur].touched >= idle) {
                if (retirement_.notify) retirement_.notify(retirement_.context, slots_[cur].id);
                erase_slot(cur);
                ++removed;
            }
            cur = nxt;
        }
        return removed;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::set_flow_idle_ms(FlowId id, std::uint64_t idle_ms) noexcept -> bool {
        if (!idle_ms) return false;
        auto* flow = lookup_slot(id);
        if (!flow) return false;
        if (flow->idle_override_ms == 0) ++custom_idle_count_;
        flow->idle_override_ms = idle_ms;
        return true;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::compatible(Flow const& flow, Endpoint remote) const -> bool {
        if (mapping_ == Mapping::endpoint_independent) return true;
        if (flow.mapped_remote.address != remote.address) return false;
        return mapping_ == Mapping::address_dependent || flow.mapped_remote.port == remote.port;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::open(Endpoint local, Endpoint remote, std::uint64_t now) -> std::expected<FlowId, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto const h = hash_endpoint(local);
        for (auto cur = local_find_head(local, h); cur != kNull; cur = slots_[cur].local_next) {
            if (compatible(slots_[cur], remote)) return slots_[cur].id;
        }
        if (active_count_ >= limits_.flows) return std::unexpected(Error::capacity);
        if (next_gen_ > kMaxGen) return std::unexpected(Error::id_exhausted);
        std::uint32_t idx = 0;
        if (free_head_ != kNull) {
            idx = free_head_;
            free_head_ = slots_[idx].next_free;
            slots_[idx].next_free = kNull;
        } else {
            idx = next_alloc_++;
        }
        auto id = (next_gen_++ << kSlotBits) | idx;
        auto& flow = slots_[idx];
        flow.id = id;
        flow.local_hash = h;
        flow.local = local;
        flow.mapped_remote = remote;
        flow.touched = now;
        flow.idle_override_ms = 0;
        flow.sent = false;
        flow.pending.reset();
        flow.inline_peers.clear();
        flow.extra_peers.clear();
        flow.used = true;
        lru_link_tail(idx);
        local_insert(idx);
        ++active_count_;
        return id;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::open_send(Endpoint local, Endpoint remote, std::uint64_t now)
        -> std::expected<std::pair<FlowId, std::uint64_t>, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto previous = active_count_;
        auto id = open(local, remote, now);
        if (!id) return std::unexpected(id.error());
        bool created = active_count_ != previous;
        utility::scope_exit rollback([&] {
            if (created) (void)close(*id, now);
        });
        auto token = begin_send(*id, remote, now);
        if (!token) return std::unexpected(token.error());
        rollback.release();
        return std::pair{*id, *token};
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::begin_send(FlowId id, Endpoint remote, std::uint64_t now) -> std::expected<std::uint64_t, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto* flow = lookup_slot(id);
        if (!flow) return std::unexpected(Error::no_flow);
        if (!compatible(*flow, remote)) return std::unexpected(Error::remote_mismatch);
        if (flow->pending) return std::unexpected(Error::send_in_progress);
        auto key = remote;
        if (filtering_ == Filtering::address_dependent) key.port = 0;
        if (filtering_ != Filtering::endpoint_independent && !flow->has_peer(key)) {
            if (flow->peer_count() >= limits_.peers_per_flow) return std::unexpected(Error::peer_limit);
            flow->reserve_one_peer();
        }
        if (next_send_ == 0) return std::unexpected(Error::id_exhausted);
        auto token = next_send_++;
        flow->pending = std::pair{token, key};
        return token;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::finish_send(FlowId id, std::uint64_t token, bool success, std::uint64_t now) -> std::expected<void, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto* flow = lookup_slot(id);
        if (!flow || !flow->pending || flow->pending->first != token) return std::unexpected(Error::stale_send);
        auto key = flow->pending->second;
        flow->pending.reset();
        if (!success) return std::unexpected(Error::send_failed);
        if (filtering_ != Filtering::endpoint_independent && !flow->has_peer(key))
            flow->add_peer(key);
        flow->sent = true;
        flow->touched = now;
        lru_touch(slot_index(id));
        return {};
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::transmit(FlowId id, Endpoint remote, std::uint64_t now,
                             functional::function_ref<bool()> sender) -> std::expected<void, Error> {
        auto token = begin_send(id, remote, now);
        if (!token) return std::unexpected(token.error());
        utility::scope_exit rollback([&] { (void)finish_send(id, *token, false, now); });
        auto sent = sender();
        auto result = finish_send(id, *token, sent, now);
        rollback.release();
        return result;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::close(FlowId id, std::uint64_t now) -> std::expected<void, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto* flow = lookup_slot(id);
        if (!flow) return std::unexpected(Error::no_flow);
        if (retirement_.notify) retirement_.notify(retirement_.context, flow->id);
        erase_slot(slot_index(id));
        return {};
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::clear(std::uint64_t now) -> std::expected<std::size_t, Error> {
        auto expired = advance(now);
        if (!expired) return std::unexpected(expired.error());
        auto count = *expired + active_count_;
        while (lru_head_ != kNull) {
            auto cur = lru_head_;
            if (retirement_.notify) retirement_.notify(retirement_.context, slots_[cur].id);
            erase_slot(cur);
        }
        return count;
    }

    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::accept_reply(FlowId id, Endpoint remote, std::uint64_t now) -> std::expected<Endpoint, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto* flow = lookup_slot(id);
        if (!flow) return std::unexpected(Error::no_flow);
        auto key = remote;
        if (filtering_ == Filtering::address_dependent) key.port = 0;
        if (!flow->sent || (filtering_ != Filtering::endpoint_independent && !flow->has_peer(key)))
            return std::unexpected(Error::forbidden);
        flow->touched = now;
        lru_touch(slot_index(id));
        return flow->local;
    }

    template class BasicFlowTable<Endpoint4>;
    template class BasicFlowTable<Endpoint6>;
}
