module udp;
import std;
import nexus.compat;

namespace udp {
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::erase_flow(typename List::iterator it) noexcept -> void {
        by_id_.erase(it->id);
        if (auto lit = by_local_.find(it->local); lit != by_local_.end()) {
            std::erase(lit->second, it);
            if (lit->second.empty()) by_local_.erase(lit);
        }
        flows_.erase(it);
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::advance(std::uint64_t now) -> std::expected<std::size_t, Error> {
        if (limits_.idle_ms == 0) return std::unexpected(Error::invalid_config);
        if (initialized_ && now < now_) return std::unexpected(Error::time_reversed);
        initialized_ = true;
        now_ = now;
        std::size_t removed = 0;
        for (auto it = flows_.begin(); it != flows_.end(); ) {
            auto idle = it->idle_override_ms ? it->idle_override_ms : limits_.idle_ms;
            if (now - it->touched < idle) { ++it; continue; }
            auto cur = it++;
            if (retirement_.notify) retirement_.notify(retirement_.context, cur->id);
            erase_flow(cur);
            ++removed;
        }
        return removed;
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::set_flow_idle_ms(FlowId id, std::uint64_t idle_ms) noexcept -> bool {
        if (!idle_ms) return false;
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return false;
        found->second->idle_override_ms = idle_ms;
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
        if (auto lit = by_local_.find(local); lit != by_local_.end()) {
            for (auto it : lit->second) {
                if (compatible(*it, remote)) return it->id;
            }
        }
        if (flows_.size() >= limits_.flows) return std::unexpected(Error::capacity);
        if (next_id_ == 0) return std::unexpected(Error::id_exhausted);
        auto id = next_id_++;
        flows_.push_back(Flow{id, local, remote, now, false, {}, {}});
        auto it = std::prev(flows_.end());
        try {
            by_id_.emplace(id, it);
            by_local_[local].push_back(it);
        } catch (...) {
            erase_flow(it);
            throw;
        }
        return id;
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::open_send(Endpoint local, Endpoint remote, std::uint64_t now)
        -> std::expected<std::pair<FlowId, std::uint64_t>, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto previous = flows_.size();
        auto id = open(local, remote, now);
        if (!id) return std::unexpected(id.error());
        bool created = flows_.size() != previous;
        nexus::scope_exit rollback([&] {
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
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return std::unexpected(Error::no_flow);
        auto it = found->second;
        if (!compatible(*it, remote)) return std::unexpected(Error::remote_mismatch);
        if (it->pending) return std::unexpected(Error::send_in_progress);
        auto key = remote;
        if (filtering_ == Filtering::address_dependent) key.port = 0;
        if (filtering_ != Filtering::endpoint_independent && std::ranges::find(it->peers, key) == it->peers.end()) {
            if (it->peers.size() >= limits_.peers_per_flow) return std::unexpected(Error::peer_limit);
            it->peers.reserve(it->peers.size() + 1);
        }
        if (next_send_ == 0) return std::unexpected(Error::id_exhausted);
        auto token = next_send_++;
        it->pending = std::pair{token, key};
        return token;
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::finish_send(FlowId id, std::uint64_t token, bool success, std::uint64_t now) -> std::expected<void, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return std::unexpected(Error::stale_send);
        auto it = found->second;
        if (!it->pending || it->pending->first != token) return std::unexpected(Error::stale_send);
        auto key = it->pending->second;
        it->pending.reset();
        if (!success) return std::unexpected(Error::send_failed);
        if (filtering_ != Filtering::endpoint_independent && std::ranges::find(it->peers, key) == it->peers.end())
            it->peers.push_back(key);
        it->sent = true;
        it->touched = now;
        return {};
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::transmit(FlowId id, Endpoint remote, std::uint64_t now,
                             nexus::function_ref<bool()> sender) -> std::expected<void, Error> {
        auto token = begin_send(id, remote, now);
        if (!token) return std::unexpected(token.error());
        nexus::scope_exit rollback([&] { (void)finish_send(id, *token, false, now); });
        auto sent = sender();
        auto result = finish_send(id, *token, sent, now);
        rollback.release();
        return result;
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::close(FlowId id, std::uint64_t now) -> std::expected<void, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return std::unexpected(Error::no_flow);
        auto it = found->second;
        if (retirement_.notify) retirement_.notify(retirement_.context, it->id);
        erase_flow(it);
        return {};
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::clear(std::uint64_t now) -> std::expected<std::size_t, Error> {
        auto expired = advance(now);
        if (!expired) return std::unexpected(expired.error());
        auto count = *expired + flows_.size();
        if (retirement_.notify) {
            for (auto const& flow : flows_) retirement_.notify(retirement_.context, flow.id);
        }
        flows_.clear();
        by_id_.clear();
        by_local_.clear();
        return count;
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::accept_reply(FlowId id, Endpoint remote, std::uint64_t now) -> std::expected<Endpoint, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto found = by_id_.find(id);
        if (found == by_id_.end()) return std::unexpected(Error::no_flow);
        auto it = found->second;
        auto key = remote;
        if (filtering_ == Filtering::address_dependent) key.port = 0;
        if (!it->sent || (filtering_ != Filtering::endpoint_independent &&
                          std::ranges::find(it->peers, key) == it->peers.end())) return std::unexpected(Error::forbidden);
        it->touched = now;
        return it->local;
    }
    template class BasicFlowTable<Endpoint4>;
    template class BasicFlowTable<Endpoint6>;
}
