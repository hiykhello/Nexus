export module tailscale.snapshot;
import std;
import containers.inplace_vector;
import tailscale.control;
import tailscale.control_messages;

export namespace tailscale::snapshot {
    namespace cm=control_messages;
    enum class Error { inactive, stale, requires_full, duplicate, capacity, invalid };
    struct Peer {
        std::int64_t id=0,home_derp=0;
        control::NodePublic key;
        containers::inplace_vector<cm::Prefix,cm::max_prefixes> addresses,allowed_ips;
        containers::inplace_vector<cm::Endpoint,cm::max_endpoints> endpoints;
        bool machine_authorized=false,expired=false;
        std::optional<std::chrono::sys_seconds> not_after;
        std::optional<cm::DiscoKey> discovery;
    };
    // Caller-owned staging makes the temporary 64-peer capacity explicit and
    // keeps it off coroutine/native stacks. Do not share scratch concurrently.
    struct Scratch { containers::inplace_vector<Peer,cm::max_peers> peers; };
    // Non-installable peer projection. No JsonField or borrowed Map frame survives.
    // Caller must separately validate policy, TKA, identity and routes before use.
    class Snapshot {
        cm::DecodeOrigin origin_{};
        containers::inplace_vector<Peer,cm::max_peers> peers_;
        std::optional<Peer> self_;
        std::uint64_t last_frame_=0;
        std::int64_t self_id_=0;
        bool active_=false,seeded_=false,has_epoch_=false;
        static auto own(cm::PeerCandidate const& p) noexcept -> Peer {
            return {p.id,p.home_derp,p.key,p.addresses,p.allowed_ips,p.endpoints,p.machine_authorized,p.expired,p.not_after,p.discovery};
        }
        static auto valid(containers::inplace_vector<Peer,cm::max_peers> const& peers,control::NodePublic const& self,std::int64_t self_id) noexcept -> bool {
            for (std::size_t i=0;i<peers.size();++i) {
                if (peers[i].id<=0 || peers[i].id==self_id || peers[i].key==self) return false;
                for (std::size_t j=0;j<i;++j)
                    if (peers[i].id==peers[j].id || peers[i].key==peers[j].key) return false;
            }
            return true;
        }
    public:
        Snapshot()=default;
        Snapshot(Snapshot const&)=delete;
        auto operator=(Snapshot const&) -> Snapshot& = delete;
        // Begin invalidates the old stream immediately; its frames can no
        // longer mutate the state. An empty initial peer set must be explicit.
        auto begin(cm::DecodeOrigin origin) noexcept -> std::expected<void,Error> {
            if (active_) return std::unexpected(Error::invalid);
            if (!origin.connection_generation || !origin.stream_generation ||
                std::ranges::all_of(origin.local_node.view(),[](auto v){return v==0;})) return std::unexpected(Error::invalid);
            if (has_epoch_ && (origin.connection_generation<origin_.connection_generation ||
                (origin.connection_generation==origin_.connection_generation && origin.stream_generation<=origin_.stream_generation))) return std::unexpected(Error::stale);
            origin_=origin;peers_.clear();self_.reset();last_frame_=0;self_id_=0;active_=true;seeded_=false;has_epoch_=true;return {};
        }
        auto stop() noexcept -> void { peers_.clear();self_.reset();active_=seeded_=false; }
        // frame is the strictly increasing local receive ordinal assigned by
        // the single Map reader, not the optional server Seq checkpoint.
        // The first non-keepalive response must contain the decoded local node;
        // an empty or omitted Peers field initializes an empty projection.
        auto apply(cm::MapView const& view,std::uint64_t frame,Scratch& scratch) noexcept -> std::expected<void,Error> {
            if (!active_) return std::unexpected(Error::inactive);
            if (view.origin.local_node!=origin_.local_node || view.origin.connection_generation!=origin_.connection_generation || view.origin.stream_generation!=origin_.stream_generation) return std::unexpected(Error::stale);
            if (!frame || frame<=last_frame_) return std::unexpected(Error::stale);
            if (view.keep_alive && (view.self || view.mode!=cm::MapMode::unchanged || !view.peers.empty() || !view.changed.empty() || !view.removed.empty())) return std::unexpected(Error::invalid);
            if (!seeded_ && view.keep_alive) {last_frame_=frame;return {};}
            if (!seeded_ && (!view.self || view.self->id<=0 || view.self->key!=origin_.local_node || view.mode==cm::MapMode::delta)) return std::unexpected(Error::requires_full);
            if (seeded_ && view.self && (view.self->id!=self_id_ || view.self->key!=origin_.local_node)) return std::unexpected(Error::invalid);
            if ((view.mode==cm::MapMode::unchanged && (!view.peers.empty() || !view.changed.empty() || !view.removed.empty())) ||
                (view.mode==cm::MapMode::full && (view.peers.empty() || !view.changed.empty() || !view.removed.empty())) ||
                (view.mode==cm::MapMode::delta && (!view.peers.empty() || (view.changed.empty() && view.removed.empty())))) return std::unexpected(Error::invalid);
            auto self_id=seeded_ ? self_id_ : view.self->id;
            auto& next=scratch.peers;next=peers_;
            if (view.mode==cm::MapMode::full) {
                next.clear();
                for (auto const& p:view.peers) { if (next.size()==next.capacity()) return std::unexpected(Error::capacity); next.push_back(own(p)); }
            } else if (view.mode==cm::MapMode::delta) {
                for (auto id:view.removed) {
                    if (id<=0 || id==self_id) return std::unexpected(Error::invalid);
                    auto pos=std::ranges::find(next,id,&Peer::id);if (pos!=next.end()) next.erase(pos);
                }
                for (auto const& p:view.changed) {
                    auto pos=std::ranges::find(next,p.id,&Peer::id);
                    if (pos!=next.end()) *pos=own(p);
                    else {if (next.size()==next.capacity()) return std::unexpected(Error::capacity);next.push_back(own(p));}
                }
            }
            if (!valid(next,origin_.local_node,self_id)) return std::unexpected(Error::duplicate);
            peers_=std::move(next);
            if (view.self) self_=own(*view.self);
            self_id_=self_id;last_frame_=frame;seeded_=true;return {};
        }
        auto peers() const noexcept -> std::span<Peer const> {return {peers_.data(),peers_.size()};}
        auto self() const noexcept -> Peer const* {return self_ ? &*self_ : nullptr;}
        auto ready() const noexcept -> bool {return active_ && seeded_;}
    };
}
