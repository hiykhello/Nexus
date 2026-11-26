module tcp.table;
import std;

namespace tcp {
    namespace {
        constexpr std::size_t kMaxTableBufferCapacity = 4u * 1024u * 1024u;

        auto next_pow2(std::size_t n) noexcept -> std::size_t {
            std::size_t p = 16;
            while (p < n) p <<= 1;
            return p;
        }
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::BasicConnectionTable(
        std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge)
        : limit_(limit), hard_limit_(limit), buffer_capacity_(capacity), challenge_limits_(challenge) {
        slots_.resize(hard_limit_);
        auto const bsz = next_pow2(hard_limit_ * 2);
        bucket_mask_ = bsz - 1;
        buckets_.assign(bsz, kNull);
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::hash_tuple(TupleKey const& k) noexcept -> std::size_t {
        std::uint64_t h = 14695981039346656037ull;
        auto mix = [&](std::uint64_t v) noexcept { h = (h ^ v) * 1099511628211ull; };
        if constexpr (sizeof(Address) == 4) {
            std::uint32_t s = 0, d = 0;
            std::memcpy(&s, k.source.data(), 4);
            std::memcpy(&d, k.destination.data(), 4);
            mix(s);
            mix(d);
        } else {
            std::uint64_t s0 = 0, s1 = 0, d0 = 0, d1 = 0;
            std::memcpy(&s0, k.source.data(), 8);
            std::memcpy(&s1, k.source.data() + 8, 8);
            std::memcpy(&d0, k.destination.data(), 8);
            std::memcpy(&d1, k.destination.data() + 8, 8);
            mix(s0); mix(s1); mix(d0); mix(d1);
        }
        mix((std::uint64_t(k.source_port) << 16) | k.destination_port);
        return static_cast<std::size_t>(h ^ (h >> 32));
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::lookup_slot(ConnectionId id) noexcept -> Slot* {
        auto idx = slot_index(id);
        if (idx >= slots_.size()) return nullptr;
        auto& slot = slots_[idx];
        return (slot.used && slot.id == id) ? &slot : nullptr;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::lookup_slot(ConnectionId id) const noexcept -> Slot const* {
        auto idx = slot_index(id);
        if (idx >= slots_.size()) return nullptr;
        auto const& slot = slots_[idx];
        return (slot.used && slot.id == id) ? &slot : nullptr;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::bucket_find(
        TupleKey const& key, std::size_t hash) const noexcept -> std::uint32_t {
        if (buckets_.empty() || !active_count_) return kNull;
        for (std::size_t pos = hash & bucket_mask_; ; pos = (pos + 1) & bucket_mask_) {
            auto cur = buckets_[pos];
            if (cur == kNull) return kNull;
            if (slots_[cur].hash == hash && slots_[cur].key == key) return cur;
        }
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::bucket_insert(
        std::size_t hash, std::uint32_t idx) noexcept -> void {
        for (std::size_t pos = hash & bucket_mask_; ; pos = (pos + 1) & bucket_mask_) {
            if (buckets_[pos] == kNull) { buckets_[pos] = idx; return; }
        }
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::bucket_erase(std::uint32_t idx) noexcept -> void {
        std::size_t pos = slots_[idx].hash & bucket_mask_;
        for (; buckets_[pos] != idx; pos = (pos + 1) & bucket_mask_) {
            if (buckets_[pos] == kNull) return;
        }
        std::size_t hole = pos;
        for (std::size_t scan = (hole + 1) & bucket_mask_; buckets_[scan] != kNull; scan = (scan + 1) & bucket_mask_) {
            auto cur = buckets_[scan];
            auto ideal = slots_[cur].hash & bucket_mask_;
            if (((scan - ideal) & bucket_mask_) >= ((scan - hole) & bucket_mask_)) {
                buckets_[hole] = cur;
                hole = scan;
            }
        }
        buckets_[hole] = kNull;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::erase_slot(std::uint32_t idx) noexcept -> void {
        auto& slot = slots_[idx];
        bucket_erase(idx);
        auto p = slot.prev_active, n = slot.next_active;
        if (p != kNull) slots_[p].next_active = n; else active_head_ = n;
        if (n != kNull) slots_[n].prev_active = p; else active_tail_ = p;
        slot.prev_active = slot.next_active = kNull;
        slot.connection.reset();
        slot.id = 0;
        slot.used = false;
        slot.next_free = free_head_;
        free_head_ = idx;
        --active_count_;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::create(
        std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge)
        -> std::expected<BasicConnectionTable, TableError> {
        if (!limit || limit > kMaxCapacity || !capacity || capacity > kMaxTableBufferCapacity)
            return std::unexpected(TableError::invalid_capacity);
        if (!challenge.interval_ms) return std::unexpected(TableError::invalid_challenge_limit);
        return BasicConnectionTable(limit, capacity, challenge);
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::claim_challenge_ack(std::uint64_t now) noexcept -> bool {
        if (challenge_start_ && now < *challenge_start_) return false;
        if (!challenge_start_ || now - *challenge_start_ >= challenge_limits_.interval_ms) {
            challenge_start_ = now; challenge_count_ = 0;
        }
        if (challenge_count_ >= challenge_limits_.count) return false;
        ++challenge_count_; return true;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::stateless_reset_available(std::uint64_t now) const noexcept -> bool {
        if (reset_start_ && now < *reset_start_) return false;
        return challenge_limits_.count && (!reset_start_ || now - *reset_start_ >= challenge_limits_.interval_ms || reset_count_ < challenge_limits_.count);
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::claim_stateless_reset(std::uint64_t now) noexcept -> bool {
        if (reset_start_ && now < *reset_start_) return false;
        if (!reset_start_ || now - *reset_start_ >= challenge_limits_.interval_ms) {
            reset_start_ = now; reset_count_ = 0;
        }
        if (reset_count_ >= challenge_limits_.count) return false;
        ++reset_count_; return true;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::find(SegmentView segment) const noexcept -> std::optional<ConnectionId> {
        TupleKey key{segment.source, segment.destination, segment.source_port, segment.destination_port};
        auto idx = bucket_find(key, hash_tuple(key));
        return idx == kNull ? std::optional<ConnectionId>{} : slots_[idx].id;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::watch(SegmentView segment) -> std::shared_ptr<packet::TcpGeneration> {
        std::shared_ptr<packet::TcpGeneration> current;
        if (!watches_.empty()) {
            std::erase_if(watches_, [&](auto const& watch) {
                if (watch.token.expired()) return true;
                if (!current && watch.source == segment.source && watch.destination == segment.destination &&
                    watch.source_port == segment.source_port && watch.destination_port == segment.destination_port) {
                    auto token = watch.token.lock();
                    if (token && token->valid) current = std::move(token);
                }
                return false;
            });
            if (current) return current;
        }
        auto token = std::make_shared<packet::TcpGeneration>();
        watches_.push_back({segment.source, segment.destination, segment.source_port, segment.destination_port, token});
        return token;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::watched_generations() const noexcept -> std::size_t {
        return std::ranges::count_if(watches_, [](auto const& watch) { return !watch.token.expired(); });
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::open(
        SegmentView syn, std::uint32_t iss, std::uint64_t now) -> std::expected<ConnectionId, TableError> {
        TupleKey key{syn.source, syn.destination, syn.source_port, syn.destination_port};
        auto h = hash_tuple(key);
        if (bucket_find(key, h) != kNull) return std::unexpected(TableError::duplicate);
        if (active_count_ >= limit_) return std::unexpected(TableError::full);
        if (next_gen_ > kMaxGen) return std::unexpected(TableError::id_exhausted);
        auto connection = Connection::accept(syn, iss, buffer_capacity_, now);
        if (!connection) return std::unexpected(TableError::invalid_syn);
        std::uint32_t idx = 0;
        if (free_head_ != kNull) {
            idx = free_head_;
            free_head_ = slots_[idx].next_free;
            slots_[idx].next_free = kNull;
        } else {
            idx = next_alloc_++;
        }
        auto id = (next_gen_++ << kSlotBits) | idx;
        auto& slot = slots_[idx];
        slot.id = id;
        slot.hash = h;
        slot.key = key;
        slot.connection.emplace(std::move(*connection));
        slot.eof_observed = false;
        slot.reset_pending = false;
        slot.app_detached = false;
        slot.used = true;
        slot.prev_active = active_tail_;
        slot.next_active = kNull;
        if (active_tail_ != kNull) slots_[active_tail_].next_active = idx; else active_head_ = idx;
        active_tail_ = idx;
        bucket_insert(h, idx);
        ++active_count_;
        if (!watches_.empty()) {
            std::erase_if(watches_, [&](auto const& watch) {
                auto token = watch.token.lock();
                if (!token) return true;
                if (watch.source == syn.source && watch.destination == syn.destination &&
                    watch.source_port == syn.source_port && watch.destination_port == syn.destination_port) {
                    token->valid = false; return true;
                }
                return false;
            });
        }
        return id;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::get(ConnectionId id) noexcept -> Connection* {
        auto* s = lookup_slot(id);
        return s ? &*s->connection : nullptr;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::target(ConnectionId id) const noexcept -> std::optional<Target> {
        auto const* s = lookup_slot(id);
        if (!s) return {};
        return Target{s->key.destination, s->key.destination_port};
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::endpoints(ConnectionId id) const noexcept -> std::optional<Endpoints> {
        auto const* s = lookup_slot(id);
        if (!s) return {};
        return Endpoints{{s->key.source, s->key.source_port}, {s->key.destination, s->key.destination_port}};
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::next(ConnectionId after) const noexcept -> std::optional<ConnectionId> {
        if (!active_count_) return {};
        if (auto const* s = lookup_slot(after))
            return s->next_active != kNull ? slots_[s->next_active].id : slots_[active_head_].id;
        for (auto cur = active_head_; cur != kNull; cur = slots_[cur].next_active)
            if (slots_[cur].id > after) return slots_[cur].id;
        return slots_[active_head_].id;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::observe_eof(ConnectionId id) noexcept -> bool {
        auto* s = lookup_slot(id);
        if (!s || !s->connection->eof()) return false;
        s->eof_observed = true;
        return true;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::hold_reset(ConnectionId id, bool hold) noexcept -> bool {
        auto* s = lookup_slot(id);
        if (!s) return false;
        s->reset_pending = hold;
        return true;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::detach(ConnectionId id) noexcept -> bool {
        auto* s = lookup_slot(id);
        if (!s) return false;
        s->app_detached = true;
        s->connection->detach_reader();
        return true;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::is_detached(ConnectionId id) const noexcept -> bool {
        auto const* s = lookup_slot(id);
        return s && s->app_detached;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::reclaim(
        ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError> {
        auto* s = lookup_slot(id);
        if (!s) return std::unexpected(TableError::not_found);
        auto state = s->connection->state();
        bool ready = (state == ConnectionState::reset && !s->reset_pending) || state == ConnectionState::expired;
        if (state == ConnectionState::reset && s->reset_pending) return false;
        if (state == ConnectionState::handshake) {
            auto event = s->connection->poll(now);
            if (!event) return std::unexpected(TableError::time_reversed);
            ready = *event == HandshakeTimerEvent::expired;
        } else if (!ready) {
            auto result = s->connection->reclaimable(now);
            if (!result) return std::unexpected(TableError::time_reversed);
            ready = s->connection->state() == ConnectionState::expired || (*result && (s->eof_observed || s->app_detached));
        }
        if (ready) erase_slot(slot_index(id));
        return ready;
    }

    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    auto BasicConnectionTable<Connection, Address, SegmentView, Target, Endpoints>::abort(ConnectionId id) noexcept -> bool {
        if (!lookup_slot(id)) return false;
        erase_slot(slot_index(id));
        return true;
    }

    template class BasicConnectionTable<PassiveConnection, packet::Address4, packet::Tcp4View, Target4, Endpoints4>;
    template class BasicConnectionTable<PassiveConnection6, packet::Address6, packet::Tcp6View, Target6, Endpoints6>;
}
