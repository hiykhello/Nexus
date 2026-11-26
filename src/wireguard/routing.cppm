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
        struct V4Entry {
            std::uint64_t generation=0;
            std::uint32_t network=0;
            std::uint32_t mask=0;
            std::uint16_t slot=0;
            std::uint8_t bits=0;
            [[nodiscard]] auto peer() const noexcept -> PeerHandle { return {slot,generation}; }
        };
        struct V6Entry {
            std::uint64_t hi=0;
            std::uint64_t lo=0;
            std::uint64_t generation=0;
            std::uint16_t slot=0;
            std::uint8_t bits=0;
            [[nodiscard]] auto peer() const noexcept -> PeerHandle { return {slot,generation}; }
        };
        [[nodiscard]] inline auto load_be32(std::span<std::uint8_t const> a) noexcept -> std::uint32_t {
            return (std::uint32_t{a[0]}<<24)|(std::uint32_t{a[1]}<<16)|(std::uint32_t{a[2]}<<8)|std::uint32_t{a[3]};
        }
        [[nodiscard]] inline auto load_be64(std::span<std::uint8_t const> a) noexcept -> std::uint64_t {
            return (std::uint64_t{a[0]}<<56)|(std::uint64_t{a[1]}<<48)|(std::uint64_t{a[2]}<<40)|(std::uint64_t{a[3]}<<32)|
                   (std::uint64_t{a[4]}<<24)|(std::uint64_t{a[5]}<<16)|(std::uint64_t{a[6]}<<8)|std::uint64_t{a[7]};
        }
        [[nodiscard]] constexpr auto v4_mask(std::uint8_t bits) noexcept -> std::uint32_t {
            return bits==0 ? std::uint32_t{0} : (~std::uint32_t{0}<<(32u-bits));
        }
        [[nodiscard]] constexpr auto v6_mask_hi(std::uint8_t bits) noexcept -> std::uint64_t {
            return bits==0 ? std::uint64_t{0} : (bits>=64 ? ~std::uint64_t{0} : (~std::uint64_t{0}<<(64u-bits)));
        }
        [[nodiscard]] constexpr auto v6_mask_lo(std::uint8_t bits) noexcept -> std::uint64_t {
            return bits<=64 ? std::uint64_t{0} : (~std::uint64_t{0}<<(128u-bits));
        }
        inline auto valid(std::span<PeerGeneration const> peers,PeerHandle peer) noexcept -> bool {
            return peer.slot<peers.size() && peer.generation && peers[peer.slot].live && peers[peer.slot].generation==peer.generation;
        }
        inline auto lookup(std::span<V4Entry const> v4,std::span<V6Entry const> v6,std::span<PeerGeneration const> peers,
            std::uint8_t family,std::span<std::uint8_t const> address) noexcept -> std::optional<PeerHandle> {
            if (family==4) {
                if (address.size()!=4) return {};
                auto const ip=load_be32(address);
                for (auto const& e:v4)
                    if ((ip&e.mask)==e.network && valid(peers,e.peer())) return e.peer();
                return {};
            }
            if (family==6) {
                if (address.size()!=16) return {};
                auto const hi=load_be64(address.first<8>()),lo=load_be64(address.subspan<8,8>());
                for (auto const& e:v6)
                    if (((hi&v6_mask_hi(e.bits))==e.hi) && ((lo&v6_mask_lo(e.bits))==e.lo) && valid(peers,e.peer()))
                        return e.peer();
                return {};
            }
            return {};
        }
    }
    template<std::size_t PeerCapacity=32,std::size_t PrefixCapacity=1024> class RouteTable;
    // This view borrows one table for a synchronous admission operation. It
    // must not be retained by Endpoint/tasks or across an executor suspension.
    class SourcePolicyView {
        template<std::size_t,std::size_t> friend class RouteTable;
        detail::V4Entry const* v4_=nullptr;
        std::size_t const* v4_count_=nullptr;
        detail::V6Entry const* v6_=nullptr;
        std::size_t const* v6_count_=nullptr;
        std::span<PeerGeneration const> peers_;
        std::optional<PeerHandle> peer_;
        SourcePolicyView(detail::V4Entry const* v4,std::size_t const* v4_count,
            detail::V6Entry const* v6,std::size_t const* v6_count,
            std::span<PeerGeneration const> peers,PeerHandle peer) noexcept
            : v4_(v4),v4_count_(v4_count),v6_(v6),v6_count_(v6_count),peers_(peers),peer_(peer) {}
    public:
        SourcePolicyView()=default;
        [[nodiscard]] auto enabled() const noexcept -> bool { return peer_.has_value(); }
        [[nodiscard]] auto current() const noexcept -> bool { return !peer_ || detail::valid(peers_,*peer_); }
        [[nodiscard]] auto matches_peer(PeerHandle peer) const noexcept -> bool { return peer_ && *peer_==peer && current(); }
        [[nodiscard]] auto permits(std::uint8_t family,std::span<std::uint8_t const> source) const noexcept -> bool {
            if (!peer_) return true;
            if (!current()) return false;
            auto winner=detail::lookup({v4_,*v4_count_},{v6_,*v6_count_},peers_,family,source);
            return winner && *winner==*peer_;
        }
    };
    // One local identity/UDP port owns one table on its executor. Tombstones
    // remain after deletion; old handles cannot reactivate or clear a reused
    // peer slot. Exact-prefix reassignment does not retain an old-owner stack.
    template<std::size_t PeerCapacity,std::size_t PrefixCapacity> class RouteTable {
        static_assert(PeerCapacity>0 && PeerCapacity<=4096 && PrefixCapacity>0 && PrefixCapacity<=65536);
        std::array<PeerGeneration,PeerCapacity> peers_{};
        std::array<detail::V4Entry,PrefixCapacity> v4_{};
        std::array<detail::V6Entry,PrefixCapacity> v6_{};
        std::size_t v4_count_=0,v6_count_=0;
        auto erase_slot(std::uint16_t slot) noexcept -> void {
            std::size_t w4=0;
            for (std::size_t r=0;r<v4_count_;++r) if (v4_[r].slot!=slot) v4_[w4++]=v4_[r];
            v4_count_=w4;
            std::size_t w6=0;
            for (std::size_t r=0;r<v6_count_;++r) if (v6_[r].slot!=slot) v6_[w6++]=v6_[r];
            v6_count_=w6;
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
            if (prefix.family==4) {
                auto const net=detail::load_be32(std::span(prefix.address).first<4>());
                std::size_t pos=v4_count_;
                for (std::size_t i=0;i<v4_count_;++i) {
                    if (v4_[i].bits<prefix.bits) { pos=i; break; }
                    if (v4_[i].bits==prefix.bits && v4_[i].network==net) {
                        v4_[i].slot=peer.slot; v4_[i].generation=peer.generation; return {};
                    }
                }
                if (v4_count_+v6_count_>=PrefixCapacity) return std::unexpected(RouteError::full);
                for (std::size_t i=v4_count_;i>pos;--i) v4_[i]=v4_[i-1];
                v4_[pos]=detail::V4Entry{peer.generation,net,detail::v4_mask(prefix.bits),peer.slot,prefix.bits};
                ++v4_count_;
                return {};
            }
            auto const hi=detail::load_be64(std::span(prefix.address).first<8>());
            auto const lo=detail::load_be64(std::span(prefix.address).subspan<8,8>());
            std::size_t pos=v6_count_;
            for (std::size_t i=0;i<v6_count_;++i) {
                if (v6_[i].bits<prefix.bits) { pos=i; break; }
                if (v6_[i].bits==prefix.bits && v6_[i].hi==hi && v6_[i].lo==lo) {
                    v6_[i].slot=peer.slot; v6_[i].generation=peer.generation; return {};
                }
            }
            if (v4_count_+v6_count_>=PrefixCapacity) return std::unexpected(RouteError::full);
            for (std::size_t i=v6_count_;i>pos;--i) v6_[i]=v6_[i-1];
            v6_[pos]=detail::V6Entry{hi,lo,peer.generation,peer.slot,prefix.bits};
            ++v6_count_;
            return {};
        }
        [[nodiscard]] auto unassign(PeerHandle peer,Prefix const& prefix) noexcept -> std::expected<void,RouteError> {
            if (!valid(peer)) return std::unexpected(RouteError::stale_peer);
            if (!valid_prefix(prefix)) return std::unexpected(RouteError::invalid_prefix);
            if (prefix.family==4) {
                auto const net=detail::load_be32(std::span(prefix.address).first<4>());
                for (std::size_t i=0;i<v4_count_;++i) {
                    if (v4_[i].bits<prefix.bits) break;
                    if (v4_[i].bits==prefix.bits && v4_[i].network==net) {
                        if (v4_[i].peer()!=peer) return std::unexpected(RouteError::not_owner);
                        for (std::size_t j=i+1;j<v4_count_;++j) v4_[j-1]=v4_[j];
                        --v4_count_;
                        return {};
                    }
                }
                return {};
            }
            auto const hi=detail::load_be64(std::span(prefix.address).first<8>());
            auto const lo=detail::load_be64(std::span(prefix.address).subspan<8,8>());
            for (std::size_t i=0;i<v6_count_;++i) {
                if (v6_[i].bits<prefix.bits) break;
                if (v6_[i].bits==prefix.bits && v6_[i].hi==hi && v6_[i].lo==lo) {
                    if (v6_[i].peer()!=peer) return std::unexpected(RouteError::not_owner);
                    for (std::size_t j=i+1;j<v6_count_;++j) v6_[j-1]=v6_[j];
                    --v6_count_;
                    return {};
                }
            }
            return {};
        }
        [[nodiscard]] auto lookup(std::uint8_t family,std::span<std::uint8_t const> address) const noexcept -> std::optional<PeerHandle> {
            return detail::lookup({v4_.data(),v4_count_},{v6_.data(),v6_count_},peers_,family,address);
        }
        [[nodiscard]] auto view(PeerHandle peer) const noexcept -> SourcePolicyView {
            return SourcePolicyView(v4_.data(),&v4_count_,v6_.data(),&v6_count_,peers_,peer);
        }
        [[nodiscard]] auto status() const noexcept -> RouteStatus {
            RouteStatus result{0,v4_count_+v6_count_}; for (auto const& peer:peers_) result.peers+=peer.live; return result;
        }
    };
}
