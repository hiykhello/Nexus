module;
#include <experimental/scope>
module nexus.udp;
import std;

namespace nexus::udp {
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::advance(std::uint64_t now) -> std::expected<std::size_t, Error> {
        if (limits_.idle_ms == 0) return std::unexpected(Error::invalid_config);
        if (initialized_ && now < now_) return std::unexpected(Error::time_reversed);
        initialized_ = true;
        now_ = now;
        return std::erase_if(flows_, [now, this](Flow const& flow) {
            if (now - flow.touched < limits_.idle_ms) return false;
            if (retirement_.notify) retirement_.notify(retirement_.context, flow.id);
            return true;
        });
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
        auto it = std::ranges::find_if(flows_, [&](Flow const& flow) { return flow.local == local && compatible(flow, remote); });
        if (it != flows_.end()) return it->id;
        if (flows_.size() >= limits_.flows) return std::unexpected(Error::capacity);
        if (next_id_ == 0) return std::unexpected(Error::id_exhausted);
        auto id = next_id_++;
        flows_.push_back(Flow{id, local, remote, now, false, {}, {}});
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
        std::experimental::scope_exit rollback([&] {
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
        auto it = std::ranges::find(flows_, id, &Flow::id);
        if (it == flows_.end()) return std::unexpected(Error::no_flow);
        if (!compatible(*it, remote)) return std::unexpected(Error::remote_mismatch);
        if (it->pending) return std::unexpected(Error::send_in_progress);
        auto key = remote;
        if (filtering_ == Filtering::address_dependent) key.port = 0;
        if (filtering_ != Filtering::endpoint_independent && std::ranges::find(it->peers, key) == it->peers.end()) {
            if (it->peers.size() >= limits_.peers_per_flow) return std::unexpected(Error::peer_limit);
            // Allocate before initiating external I/O; finish cannot fail allocation.
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
        auto it = std::ranges::find(flows_, id, &Flow::id);
        if (it == flows_.end() || !it->pending || it->pending->first != token) return std::unexpected(Error::stale_send);
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
                             std::function_ref<bool()> sender) -> std::expected<void, Error> {
        auto token = begin_send(id, remote, now);
        if (!token) return std::unexpected(token.error());
        std::experimental::scope_exit rollback([&] { (void)finish_send(id, *token, false, now); });
        auto sent = sender();
        auto result = finish_send(id, *token, sent, now);
        rollback.release();
        return result;
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::close(FlowId id, std::uint64_t now) -> std::expected<void, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto it = std::ranges::find(flows_, id, &Flow::id);
        if (it == flows_.end()) return std::unexpected(Error::no_flow);
        if (retirement_.notify) retirement_.notify(retirement_.context, it->id);
        flows_.erase(it);
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
        return count;
    }
    template <typename Endpoint>
    auto BasicFlowTable<Endpoint>::accept_reply(FlowId id, Endpoint remote, std::uint64_t now) -> std::expected<Endpoint, Error> {
        if (auto result = advance(now); !result) return std::unexpected(result.error());
        auto it = std::ranges::find(flows_, id, &Flow::id);
        if (it == flows_.end()) return std::unexpected(Error::no_flow);
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
