module tcp.table;
import std;

namespace tcp {
    namespace {
        constexpr std::size_t kMaxTableBufferCapacity = 4u * 1024u * 1024u;
    }

    auto ConnectionTable::erase_entry(List::iterator it) noexcept -> void {
        by_id_.erase(it->id);
        by_tuple_.erase(TupleKey{it->source, it->destination, it->source_port, it->destination_port});
        entries_.erase(it);
    }
    auto ConnectionTable::create(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge) -> std::expected<ConnectionTable, TableError> {
        if (!limit || !capacity || capacity > kMaxTableBufferCapacity) return std::unexpected(TableError::invalid_capacity);
        if (!challenge.interval_ms) return std::unexpected(TableError::invalid_challenge_limit);
        return ConnectionTable(limit, capacity, challenge);
    }
    auto ConnectionTable::claim_challenge_ack(std::uint64_t now) noexcept -> bool {
        if (challenge_start_ && now < *challenge_start_) return false;
        if (!challenge_start_ || now - *challenge_start_ >= challenge_limits_.interval_ms) {
            challenge_start_ = now; challenge_count_ = 0;
        }
        if (challenge_count_ >= challenge_limits_.count) return false;
        ++challenge_count_; return true;
    }
    auto ConnectionTable::stateless_reset_available(std::uint64_t now) const noexcept -> bool {
        if (reset_start_ && now < *reset_start_) return false;
        return challenge_limits_.count && (!reset_start_ || now - *reset_start_ >= challenge_limits_.interval_ms || reset_count_ < challenge_limits_.count);
    }
    auto ConnectionTable::claim_stateless_reset(std::uint64_t now) noexcept -> bool {
        if (reset_start_ && now < *reset_start_) return false;
        if (!reset_start_ || now - *reset_start_ >= challenge_limits_.interval_ms) {
            reset_start_ = now; reset_count_ = 0;
        }
        if (reset_count_ >= challenge_limits_.count) return false;
        ++reset_count_; return true;
    }
    auto ConnectionTable::find(packet::Tcp4View segment) const noexcept -> std::optional<ConnectionId> {
        auto it = by_tuple_.find(TupleKey{segment.source, segment.destination, segment.source_port, segment.destination_port});
        return it == by_tuple_.end() ? std::optional<ConnectionId>{} : it->second->id;
    }
    auto ConnectionTable::watch(packet::Tcp4View segment) -> std::shared_ptr<packet::TcpGeneration> {
        std::shared_ptr<packet::TcpGeneration> current;
        std::erase_if(watches_,[&](auto const& watch) {
            if (watch.token.expired()) return true;
            if (!current && watch.source==segment.source && watch.destination==segment.destination &&
                watch.source_port==segment.source_port && watch.destination_port==segment.destination_port) {
                auto token=watch.token.lock();
                if (token && token->valid) current=std::move(token);
            }
            return false;
        });
        if (current) return current;
        auto token=std::make_shared<packet::TcpGeneration>();
        watches_.push_back({segment.source,segment.destination,segment.source_port,segment.destination_port,token});
        return token;
    }
    auto ConnectionTable::watched_generations() const noexcept -> std::size_t {
        return std::ranges::count_if(watches_,[](auto const& watch) { return !watch.token.expired(); });
    }
    auto ConnectionTable::open(packet::Tcp4View syn, std::uint32_t iss, std::uint64_t now)
        -> std::expected<ConnectionId, TableError> {
        if (find(syn)) return std::unexpected(TableError::duplicate);
        if (entries_.size() >= limit_) return std::unexpected(TableError::full);
        if (!next_id_) return std::unexpected(TableError::id_exhausted);
        auto connection = PassiveConnection::accept(syn, iss, buffer_capacity_, now);
        if (!connection) return std::unexpected(TableError::invalid_syn);
        auto id = next_id_;
        TupleKey key{syn.source, syn.destination, syn.source_port, syn.destination_port};
        entries_.push_back({id, syn.source, syn.destination, syn.source_port, syn.destination_port, std::move(*connection)});
        auto it = std::prev(entries_.end());
        try {
            by_id_.emplace(id, it);
            by_tuple_.emplace(key, it);
        } catch (...) {
            by_id_.erase(id);
            by_tuple_.erase(key);
            entries_.erase(it);
            throw;
        }
        std::erase_if(watches_,[&](auto const& watch) {
            auto token=watch.token.lock();
            if (!token) return true;
            if (watch.source==syn.source && watch.destination==syn.destination &&
                watch.source_port==syn.source_port && watch.destination_port==syn.destination_port) {
                token->valid=false; return true;
            }
            return false;
        });
        ++next_id_;
        return id;
    }
    auto ConnectionTable::get(ConnectionId id) noexcept -> PassiveConnection* {
        auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &it->second->connection;
    }
    auto ConnectionTable::target(ConnectionId id) const noexcept -> std::optional<Target4> {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) return {};
        return Target4{it->second->destination, it->second->destination_port};
    }
    auto ConnectionTable::endpoints(ConnectionId id) const noexcept -> std::optional<Endpoints4> {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) return {};
        return Endpoints4{{it->second->source, it->second->source_port}, {it->second->destination, it->second->destination_port}};
    }
    auto ConnectionTable::next(ConnectionId after) const noexcept -> std::optional<ConnectionId> {
        if (entries_.empty()) return {};
        if (auto it = by_id_.find(after); it != by_id_.end()) {
            auto nxt = std::next(it->second);
            return nxt != entries_.end() ? nxt->id : entries_.front().id;
        }
        for (auto const& entry : entries_) if (entry.id > after) return entry.id;
        return entries_.front().id;
    }
    auto ConnectionTable::observe_eof(ConnectionId id) noexcept -> bool {
        auto it = by_id_.find(id);
        if (it == by_id_.end() || !it->second->connection.eof()) return false;
        it->second->eof_observed = true;
        return true;
    }
    auto ConnectionTable::hold_reset(ConnectionId id, bool hold) noexcept -> bool {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) return false;
        it->second->reset_pending = hold;
        return true;
    }
    auto ConnectionTable::reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError> {
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return std::unexpected(TableError::not_found);
        auto it = found->second;
        auto state = it->connection.state();
        bool ready = (state == ConnectionState::reset && !it->reset_pending) || state == ConnectionState::expired;
        if (state == ConnectionState::reset && it->reset_pending) return false;
        if (state == ConnectionState::handshake) {
            auto event = it->connection.poll(now);
            if (!event) return std::unexpected(TableError::time_reversed);
            ready = *event == HandshakeTimerEvent::expired;
        } else if (!ready) {
            auto result = it->connection.reclaimable(now);
            if (!result) return std::unexpected(TableError::time_reversed);
            ready = *result && it->eof_observed;
        }
        if (ready) erase_entry(it);
        return ready;
    }
    auto ConnectionTable::abort(ConnectionId id) noexcept -> bool {
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return false;
        erase_entry(found->second);
        return true;
    }

    auto ConnectionTable6::erase_entry(List::iterator it) noexcept -> void {
        by_id_.erase(it->id);
        by_tuple_.erase(TupleKey{it->source, it->destination, it->source_port, it->destination_port});
        entries_.erase(it);
    }
    auto ConnectionTable6::create(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge) -> std::expected<ConnectionTable6, TableError> {
        if (!limit || !capacity || capacity > kMaxTableBufferCapacity) return std::unexpected(TableError::invalid_capacity);
        if (!challenge.interval_ms) return std::unexpected(TableError::invalid_challenge_limit);
        return ConnectionTable6(limit, capacity, challenge);
    }
    auto ConnectionTable6::claim_challenge_ack(std::uint64_t now) noexcept -> bool {
        if (challenge_start_ && now < *challenge_start_) return false;
        if (!challenge_start_ || now - *challenge_start_ >= challenge_limits_.interval_ms) {
            challenge_start_ = now; challenge_count_ = 0;
        }
        if (challenge_count_ >= challenge_limits_.count) return false;
        ++challenge_count_; return true;
    }
    auto ConnectionTable6::stateless_reset_available(std::uint64_t now) const noexcept -> bool {
        if (reset_start_ && now < *reset_start_) return false;
        return challenge_limits_.count && (!reset_start_ || now - *reset_start_ >= challenge_limits_.interval_ms || reset_count_ < challenge_limits_.count);
    }
    auto ConnectionTable6::claim_stateless_reset(std::uint64_t now) noexcept -> bool {
        if (reset_start_ && now < *reset_start_) return false;
        if (!reset_start_ || now - *reset_start_ >= challenge_limits_.interval_ms) {
            reset_start_ = now; reset_count_ = 0;
        }
        if (reset_count_ >= challenge_limits_.count) return false;
        ++reset_count_; return true;
    }
    auto ConnectionTable6::find(packet::Tcp6View segment) const noexcept -> std::optional<ConnectionId> {
        auto it = by_tuple_.find(TupleKey{segment.source, segment.destination, segment.source_port, segment.destination_port});
        return it == by_tuple_.end() ? std::optional<ConnectionId>{} : it->second->id;
    }
    auto ConnectionTable6::watch(packet::Tcp6View segment) -> std::shared_ptr<packet::TcpGeneration> {
        std::shared_ptr<packet::TcpGeneration> current;
        std::erase_if(watches_,[&](auto const& watch) {
            if (watch.token.expired()) return true;
            if (!current && watch.source==segment.source && watch.destination==segment.destination &&
                watch.source_port==segment.source_port && watch.destination_port==segment.destination_port) {
                auto token=watch.token.lock();
                if (token && token->valid) current=std::move(token);
            }
            return false;
        });
        if (current) return current;
        auto token=std::make_shared<packet::TcpGeneration>();
        watches_.push_back({segment.source,segment.destination,segment.source_port,segment.destination_port,token});
        return token;
    }
    auto ConnectionTable6::watched_generations() const noexcept -> std::size_t {
        return std::ranges::count_if(watches_,[](auto const& watch) { return !watch.token.expired(); });
    }
    auto ConnectionTable6::open(packet::Tcp6View syn, std::uint32_t iss, std::uint64_t now)
        -> std::expected<ConnectionId, TableError> {
        if (find(syn)) return std::unexpected(TableError::duplicate);
        if (entries_.size() >= limit_) return std::unexpected(TableError::full);
        if (!next_id_) return std::unexpected(TableError::id_exhausted);
        auto connection = PassiveConnection6::accept(syn, iss, buffer_capacity_, now);
        if (!connection) return std::unexpected(TableError::invalid_syn);
        auto id = next_id_;
        TupleKey key{syn.source, syn.destination, syn.source_port, syn.destination_port};
        entries_.push_back({id, syn.source, syn.destination, syn.source_port, syn.destination_port, std::move(*connection)});
        auto it = std::prev(entries_.end());
        try {
            by_id_.emplace(id, it);
            by_tuple_.emplace(key, it);
        } catch (...) {
            by_id_.erase(id);
            by_tuple_.erase(key);
            entries_.erase(it);
            throw;
        }
        std::erase_if(watches_,[&](auto const& watch) {
            auto token=watch.token.lock();
            if (!token) return true;
            if (watch.source==syn.source && watch.destination==syn.destination &&
                watch.source_port==syn.source_port && watch.destination_port==syn.destination_port) {
                token->valid=false; return true;
            }
            return false;
        });
        ++next_id_;
        return id;
    }
    auto ConnectionTable6::get(ConnectionId id) noexcept -> PassiveConnection6* {
        auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &it->second->connection;
    }
    auto ConnectionTable6::target(ConnectionId id) const noexcept -> std::optional<Target6> {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) return {};
        return Target6{it->second->destination, it->second->destination_port};
    }
    auto ConnectionTable6::endpoints(ConnectionId id) const noexcept -> std::optional<Endpoints6> {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) return {};
        return Endpoints6{{it->second->source, it->second->source_port}, {it->second->destination, it->second->destination_port}};
    }
    auto ConnectionTable6::next(ConnectionId after) const noexcept -> std::optional<ConnectionId> {
        if (entries_.empty()) return {};
        if (auto it = by_id_.find(after); it != by_id_.end()) {
            auto nxt = std::next(it->second);
            return nxt != entries_.end() ? nxt->id : entries_.front().id;
        }
        for (auto const& entry : entries_) if (entry.id > after) return entry.id;
        return entries_.front().id;
    }
    auto ConnectionTable6::observe_eof(ConnectionId id) noexcept -> bool {
        auto it = by_id_.find(id);
        if (it == by_id_.end() || !it->second->connection.eof()) return false;
        it->second->eof_observed = true;
        return true;
    }
    auto ConnectionTable6::hold_reset(ConnectionId id, bool hold) noexcept -> bool {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) return false;
        it->second->reset_pending = hold;
        return true;
    }
    auto ConnectionTable6::reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError> {
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return std::unexpected(TableError::not_found);
        auto it = found->second;
        auto state = it->connection.state();
        bool ready = (state == ConnectionState::reset && !it->reset_pending) || state == ConnectionState::expired;
        if (state == ConnectionState::reset && it->reset_pending) return false;
        if (state == ConnectionState::handshake) {
            auto event = it->connection.poll(now);
            if (!event) return std::unexpected(TableError::time_reversed);
            ready = *event == HandshakeTimerEvent::expired;
        } else if (!ready) {
            auto result = it->connection.reclaimable(now);
            if (!result) return std::unexpected(TableError::time_reversed);
            ready = *result && it->eof_observed;
        }
        if (ready) erase_entry(it);
        return ready;
    }
    auto ConnectionTable6::abort(ConnectionId id) noexcept -> bool {
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return false;
        erase_entry(found->second);
        return true;
    }
}
