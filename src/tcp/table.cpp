module nexus.tcp.table;
import std;

namespace nexus::tcp {
    auto ConnectionTable::create(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge) -> std::expected<ConnectionTable, TableError> {
        if (!limit || !capacity || capacity > 65535) return std::unexpected(TableError::invalid_capacity);
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
    auto ConnectionTable::find(packet::Tcp4View segment) const noexcept -> std::optional<ConnectionId> {
        for (auto const& entry : entries_)
            if (entry.source == segment.source && entry.destination == segment.destination &&
                entry.source_port == segment.source_port && entry.destination_port == segment.destination_port)
                return entry.id;
        return {};
    }
    auto ConnectionTable::open(packet::Tcp4View syn, std::uint32_t iss, std::uint64_t now)
        -> std::expected<ConnectionId, TableError> {
        if (find(syn)) return std::unexpected(TableError::duplicate);
        if (entries_.size() >= limit_) return std::unexpected(TableError::full);
        if (!next_id_) return std::unexpected(TableError::id_exhausted);
        auto connection = PassiveConnection::accept(syn, iss, buffer_capacity_, now);
        if (!connection) return std::unexpected(TableError::invalid_syn);
        auto id = next_id_;
        entries_.push_back({id, syn.source, syn.destination, syn.source_port, syn.destination_port, std::move(*connection)});
        ++next_id_;
        return id;
    }
    auto ConnectionTable::get(ConnectionId id) noexcept -> PassiveConnection* {
        for (auto& entry : entries_) if (entry.id == id) return &entry.connection;
        return nullptr;
    }
    auto ConnectionTable::target(ConnectionId id) const noexcept -> std::optional<Target4> {
        auto it = std::ranges::find(entries_, id, &Entry::id);
        if (it == entries_.end()) return {};
        return Target4{it->destination, it->destination_port};
    }
    auto ConnectionTable::next(ConnectionId after) const noexcept -> std::optional<ConnectionId> {
        for (auto const& entry : entries_) if (entry.id > after) return entry.id;
        if (!entries_.empty()) return entries_.front().id;
        return {};
    }
    auto ConnectionTable::observe_eof(ConnectionId id) noexcept -> bool {
        auto it = std::ranges::find(entries_, id, &Entry::id);
        if (it == entries_.end() || !it->connection.eof()) return false;
        it->eof_observed = true;
        return true;
    }
    auto ConnectionTable::hold_reset(ConnectionId id, bool hold) noexcept -> bool {
        auto it = std::ranges::find(entries_, id, &Entry::id);
        if (it == entries_.end()) return false;
        it->reset_pending = hold;
        return true;
    }
    auto ConnectionTable::reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError> {
        auto it = std::ranges::find(entries_, id, &Entry::id);
        if (it == entries_.end()) return std::unexpected(TableError::not_found);
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
        if (ready) entries_.erase(it);
        return ready;
    }
    auto ConnectionTable::abort(ConnectionId id) noexcept -> bool {
        auto it = std::ranges::find(entries_, id, &Entry::id);
        if (it == entries_.end()) return false;
        entries_.erase(it);
        return true;
    }
}
