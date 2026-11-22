export module wireguard.routing;
import std;

export namespace wireguard::routing {
    struct PeerHandle {
        std::uint16_t slot=0;
        std::uint64_t generation=0;
        auto operator==(PeerHandle const&) const -> bool = default;
    };
    struct Prefix {
        std::uint8_t family=0;
        std::array<std::uint8_t,16> address{};
        std::uint8_t bits=0;
        auto operator<=>(Prefix const&) const = default;
    };
    [[nodiscard]] inline auto valid_prefix(Prefix const& prefix) noexcept -> bool {
        auto bytes=prefix.family==4 ? 4u : prefix.family==6 ? 16u : 0u;
        if (!bytes || prefix.bits>bytes*8) return false;
        auto whole=prefix.bits/8,part=prefix.bits%8;
        if (part && (prefix.address[whole]&((1u<<(8-part))-1))) return false;
        auto first=whole+(part ? 1u : 0u);
        return std::ranges::all_of(std::span(prefix.address).subspan(first),[](auto c) { return c==0; });
    }
    [[nodiscard]] inline auto prefix_contains(Prefix const& prefix,std::uint8_t family,std::span<std::uint8_t const> address) noexcept -> bool {
        if (!valid_prefix(prefix) || prefix.family!=family || address.size()!=(family==4 ? 4u : 16u)) return false;
        auto whole=prefix.bits/8,part=prefix.bits%8;
        if (!std::ranges::equal(address.first(whole),std::span(prefix.address).first(whole))) return false;
        return !part || (address[whole]>>(8-part))==(prefix.address[whole]>>(8-part));
    }
    struct PeerGeneration { bool live=false; std::uint64_t generation=0; };
    struct OwnedPrefix { bool used=false; Prefix prefix{}; PeerHandle peer{}; };
    enum class RouteError { invalid_peer,stale_peer,invalid_prefix,full,not_owner };
    struct RouteStatus { std::size_t peers=0,prefixes=0; };
    namespace detail {
        inline auto valid(std::span<PeerGeneration const> peers,PeerHandle peer) noexcept -> bool {
            return peer.slot<peers.size() && peer.generation && peers[peer.slot].live && peers[peer.slot].generation==peer.generation;
        }
        inline auto lookup(std::span<OwnedPrefix const> prefixes,std::span<PeerGeneration const> peers,std::uint8_t family,std::span<std::uint8_t const> address) noexcept
            -> std::optional<PeerHandle> {
            if ((family!=4 && family!=6) || address.size()!=(family==4 ? 4u : 16u)) return {};
            OwnedPrefix const* best=nullptr;
            for (auto const& entry:prefixes) {
                if (!entry.used || !valid(peers,entry.peer) || (best && entry.prefix.bits<=best->prefix.bits) || !prefix_contains(entry.prefix,family,address)) continue;
                best=&entry;
            }
            return best ? std::optional(best->peer) : std::nullopt;
        }
    }
    template<std::size_t PeerCapacity=32,std::size_t PrefixCapacity=1024> class RouteTable;
    // This view borrows one table for a synchronous admission operation. It
    // must not be retained by Endpoint/tasks or across an executor suspension.
    class SourcePolicyView {
        template<std::size_t,std::size_t> friend class RouteTable;
        std::span<OwnedPrefix const> prefixes_;
        std::span<PeerGeneration const> peers_;
        std::optional<PeerHandle> peer_;
        SourcePolicyView(std::span<OwnedPrefix const> prefixes,std::span<PeerGeneration const> peers,PeerHandle peer) noexcept
            : prefixes_(prefixes),peers_(peers),peer_(peer) {}
    public:
        SourcePolicyView()=default;
        [[nodiscard]] auto enabled() const noexcept -> bool { return peer_.has_value(); }
        [[nodiscard]] auto current() const noexcept -> bool { return !peer_ || detail::valid(peers_,*peer_); }
        [[nodiscard]] auto matches_peer(PeerHandle peer) const noexcept -> bool { return peer_ && *peer_==peer && current(); }
        [[nodiscard]] auto permits(std::uint8_t family,std::span<std::uint8_t const> source) const noexcept -> bool {
            if (!peer_) return true;
            if (!current()) return false;
            auto winner=detail::lookup(prefixes_,peers_,family,source); return winner && *winner==*peer_;
        }
    };
    // One local identity/UDP port owns one table on its executor. Tombstones
    // remain after deletion; old handles cannot reactivate or clear a reused
    // peer slot. Exact-prefix reassignment does not retain an old-owner stack.
    template<std::size_t PeerCapacity,std::size_t PrefixCapacity> class RouteTable {
        static_assert(PeerCapacity>0 && PeerCapacity<=4096 && PrefixCapacity>0 && PrefixCapacity<=65536);
        std::array<PeerGeneration,PeerCapacity> peers_{};
        std::array<OwnedPrefix,PrefixCapacity> prefixes_{};
        std::size_t count_=0;
        auto erase_slot(std::uint16_t slot) noexcept -> void {
            for (auto& entry:prefixes_) if (entry.used && entry.peer.slot==slot) { entry={}; --count_; }
        }
    public:
        RouteTable()=default;
        RouteTable(RouteTable const&)=delete;
        auto operator=(RouteTable const&) -> RouteTable& = delete;
        RouteTable(RouteTable&&)=delete;
        auto operator=(RouteTable&&) -> RouteTable& = delete;
        [[nodiscard]] auto valid(PeerHandle peer) const noexcept -> bool { return detail::valid(peers_,peer); }
        [[nodiscard]] auto activate(PeerHandle peer) noexcept -> std::expected<void,RouteError> {
            if (peer.slot>=PeerCapacity || !peer.generation) return std::unexpected(RouteError::invalid_peer);
            auto& slot=peers_[peer.slot];
            if (peer.generation<slot.generation || (peer.generation==slot.generation && !slot.live)) return std::unexpected(RouteError::stale_peer);
            if (peer.generation==slot.generation) return {};
            erase_slot(peer.slot); slot={true,peer.generation}; return {};
        }
        [[nodiscard]] auto erase(PeerHandle peer) noexcept -> std::expected<void,RouteError> {
            if (!valid(peer)) return std::unexpected(RouteError::stale_peer);
            erase_slot(peer.slot); peers_[peer.slot].live=false; return {};
        }
        [[nodiscard]] auto assign(PeerHandle peer,Prefix const& prefix) noexcept -> std::expected<void,RouteError> {
            if (!valid(peer)) return std::unexpected(RouteError::stale_peer);
            if (!valid_prefix(prefix)) return std::unexpected(RouteError::invalid_prefix);
            OwnedPrefix* available=nullptr;
            for (auto& entry:prefixes_) {
                if (entry.used && entry.prefix==prefix) { entry.peer=peer; return {}; }
                if (!entry.used && !available) available=&entry;
            }
            if (!available) return std::unexpected(RouteError::full);
            *available=OwnedPrefix{true,prefix,peer}; ++count_; return {};
        }
        [[nodiscard]] auto unassign(PeerHandle peer,Prefix const& prefix) noexcept -> std::expected<void,RouteError> {
            if (!valid(peer)) return std::unexpected(RouteError::stale_peer);
            if (!valid_prefix(prefix)) return std::unexpected(RouteError::invalid_prefix);
            for (auto& entry:prefixes_) if (entry.used && entry.prefix==prefix) {
                if (entry.peer!=peer) return std::unexpected(RouteError::not_owner);
                entry={}; --count_; return {};
            }
            return {};
        }
        [[nodiscard]] auto lookup(std::uint8_t family,std::span<std::uint8_t const> address) const noexcept -> std::optional<PeerHandle> {
            return detail::lookup(prefixes_,peers_,family,address);
        }
        [[nodiscard]] auto view(PeerHandle peer) const noexcept -> SourcePolicyView { return SourcePolicyView(prefixes_,peers_,peer); }
        [[nodiscard]] auto status() const noexcept -> RouteStatus {
            RouteStatus result{0,count_}; for (auto const& peer:peers_) result.peers+=peer.live; return result;
        }
    };
}
