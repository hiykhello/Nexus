export module wireguard.registry;
import std;
import wireguard;
import wireguard.endpoint;
import wireguard.routing;

export namespace wireguard {
    using PeerHandle=routing::PeerHandle;
    enum class HostError { peers_full,stale_peer,exhausted,stale_attempt,index_conflict,indexes_full,
        reservation_exists,unreserved_index,invalid_snapshot,no_peer,initiation_peer_required,
        invalid_packet,source,queue_full,peer_queue_full,packet_too_large };
    struct HostFailure { HostError code; std::optional<Error> protocol; };
    struct IndexReservation {
        PeerHandle peer;
        std::uint64_t ticket,serial;
        std::uint32_t index;
    };
    struct ReceiverBinding {
        PeerHandle peer;
        std::uint32_t index;
        std::uint64_t ticket;
        auto operator==(ReceiverBinding const&) const -> bool = default;
    };
    struct RegistryStatus { std::size_t peers=0,indexes=0,reservations=0; };
    namespace host_detail {
        inline auto failure(HostError code,std::optional<Error> protocol={}) noexcept -> std::unexpected<HostFailure> { return std::unexpected(HostFailure{code,protocol}); }
    }
    // One receiver-index namespace for one local UDP port/executor. Handles
    // and reservations contain values only: this class never borrows a peer,
    // Endpoint, packet or task. Endpoint owners remain stable in the host.
    template<std::size_t PeerCapacity=32> class PeerRegistry {
        static_assert(PeerCapacity>0 && PeerCapacity<=4096);
        static constexpr auto indexes_per_peer=std::tuple_size_v<ReceiverIndexes>;
        static_assert(indexes_per_peer<=std::numeric_limits<std::uint8_t>::max());
        struct Peer { bool live=false; std::uint8_t active_indexes=0; std::uint64_t generation=0,latest=0; };
        struct Entry {
            bool used=false,reserved=false;
            ReceiverBinding binding{};
            std::uint64_t serial=0;
        };
        std::array<Peer,PeerCapacity> peers_{};
        std::array<Entry,PeerCapacity*indexes_per_peer> indexes_{};
        std::uint64_t reservation_serial_=0;
        auto peer_indexes(std::size_t slot) noexcept -> std::span<Entry,indexes_per_peer> {
            return std::span<Entry,indexes_per_peer>(indexes_.data()+slot*indexes_per_peer,indexes_per_peer);
        }
        auto peer_indexes(std::size_t slot) const noexcept -> std::span<Entry const,indexes_per_peer> {
            return std::span<Entry const,indexes_per_peer>(indexes_.data()+slot*indexes_per_peer,indexes_per_peer);
        }
        auto find(std::uint32_t value) noexcept -> Entry* {
            for (std::size_t p=0;p<PeerCapacity;++p) {
                if (!peers_[p].active_indexes) continue;
                for (auto& entry:peer_indexes(p)) if (entry.used && entry.binding.index==value) return &entry;
            }
            return nullptr;
        }
        auto find(std::uint32_t value) const noexcept -> Entry const* {
            for (std::size_t p=0;p<PeerCapacity;++p) {
                if (!peers_[p].active_indexes) continue;
                for (auto const& entry:peer_indexes(p)) if (entry.used && entry.binding.index==value) return &entry;
            }
            return nullptr;
        }
        static auto contains(ReceiverIndexes const& snapshot,ReceiverBinding binding) noexcept -> bool {
            return std::ranges::any_of(snapshot,[&](auto const& index) { return index.used && index.value==binding.index && index.ticket==binding.ticket; });
        }
    public:
        PeerRegistry()=default;
        PeerRegistry(PeerRegistry const&)=delete;
        auto operator=(PeerRegistry const&) -> PeerRegistry& = delete;
        PeerRegistry(PeerRegistry&&)=delete;
        auto operator=(PeerRegistry&&) -> PeerRegistry& = delete;
        [[nodiscard]] auto valid(PeerHandle peer) const noexcept -> bool {
            return peer.slot<PeerCapacity && peers_[peer.slot].live && peer.generation && peers_[peer.slot].generation==peer.generation;
        }
        [[nodiscard]] auto add() noexcept -> std::expected<PeerHandle,HostFailure> {
            for (std::size_t i=0;i<PeerCapacity;++i) {
                auto& peer=peers_[i];
                if (peer.live || peer.generation==std::numeric_limits<std::uint64_t>::max()) continue;
                peer.live=true; peer.active_indexes=0; ++peer.generation; peer.latest=0;
                return PeerHandle{static_cast<std::uint16_t>(i),peer.generation};
            }
            return host_detail::failure(HostError::peers_full);
        }
        [[nodiscard]] auto erase(PeerHandle peer) noexcept -> std::expected<void,HostFailure> {
            if (!valid(peer)) return host_detail::failure(HostError::stale_peer);
            for (auto& index:peer_indexes(peer.slot)) index={};
            peers_[peer.slot].active_indexes=0; peers_[peer.slot].live=false; peers_[peer.slot].latest=0; return {};
        }
        [[nodiscard]] auto latest(PeerHandle peer) const noexcept -> std::expected<std::uint64_t,HostFailure> {
            if (!valid(peer)) return host_detail::failure(HostError::stale_peer);
            return peers_[peer.slot].latest;
        }
        // Validate the complete snapshot before publishing/removing anything.
        // New receiver indexes must already have an exact global reservation.
        // In-progress reservations for this latest ticket survive an empty
        // snapshot while host entropy/preparation is outstanding.
        [[nodiscard]] auto sync(PeerHandle peer,ReceiverIndexes const& snapshot,std::uint64_t latest) noexcept -> std::expected<void,HostFailure> {
            if (!valid(peer)) return host_detail::failure(HostError::stale_peer);
            if (latest<peers_[peer.slot].latest) return host_detail::failure(HostError::stale_attempt);
            for (std::size_t i=0;i<snapshot.size();++i) {
                auto const& index=snapshot[i]; if (!index.used) continue;
                if (!index.ticket || index.ticket>latest) return host_detail::failure(HostError::invalid_snapshot);
                for (std::size_t j=0;j<i;++j) if (snapshot[j].used && snapshot[j].value==index.value) return host_detail::failure(HostError::invalid_snapshot);
                auto entry=find(index.value);
                if (!entry) return host_detail::failure(HostError::unreserved_index);
                if (entry->binding.peer!=peer) return host_detail::failure(HostError::index_conflict);
                if (entry->binding.ticket!=index.ticket || (entry->reserved && index.ticket!=latest)) return host_detail::failure(HostError::stale_attempt);
            }
            for (auto& entry:peer_indexes(peer.slot)) if (entry.used) {
                if (contains(snapshot,entry.binding)) entry.reserved=false;
                else if (!entry.reserved || entry.binding.ticket!=latest) { entry={}; --peers_[peer.slot].active_indexes; }
            }
            peers_[peer.slot].latest=latest; return {};
        }
        [[nodiscard]] auto sync(PeerHandle peer,Endpoint const& endpoint) noexcept -> std::expected<void,HostFailure> {
            return sync(peer,endpoint.receiver_indexes(),endpoint.latest_attempt());
        }
        [[nodiscard]] auto reserve(PeerHandle peer,std::uint64_t ticket,std::uint32_t seed,IndexMode mode=IndexMode::probe) noexcept
            -> std::expected<IndexReservation,HostFailure> {
            if (!valid(peer)) return host_detail::failure(HostError::stale_peer);
            if (!ticket || ticket!=peers_[peer.slot].latest) return host_detail::failure(HostError::stale_attempt);
            Entry* slot=nullptr;
            for (auto& entry:peer_indexes(peer.slot)) {
                if (entry.used) {
                    if (entry.reserved && entry.binding.ticket==ticket) return host_detail::failure(HostError::reservation_exists);
                } else if (!slot) slot=&entry;
            }
            if (!slot) return host_detail::failure(HostError::indexes_full);
            if (reservation_serial_==std::numeric_limits<std::uint64_t>::max()) return host_detail::failure(HostError::exhausted);
            auto probes=mode==IndexMode::exact ? std::size_t{1} : indexes_.size()+1;
            for (std::size_t probe=0;probe<probes;++probe) {
                auto value=seed+static_cast<std::uint32_t>(probe); if (find(value)) continue;
                auto serial=++reservation_serial_; *slot=Entry{true,true,{peer,value,ticket},serial};
                ++peers_[peer.slot].active_indexes;
                return IndexReservation{peer,ticket,serial,value};
            }
            return host_detail::failure(mode==IndexMode::exact ? HostError::index_conflict : HostError::indexes_full);
        }
        [[nodiscard]] auto valid(IndexReservation const& reservation) const noexcept -> bool {
            if (!valid(reservation.peer) || peers_[reservation.peer.slot].latest!=reservation.ticket) return false;
            for (auto const& entry:peer_indexes(reservation.peer.slot))
                if (entry.used && entry.binding.index==reservation.index)
                    return entry.reserved && entry.binding.peer==reservation.peer && entry.binding.ticket==reservation.ticket && entry.serial==reservation.serial;
            return false;
        }
        [[nodiscard]] auto release(IndexReservation const& reservation) noexcept -> std::expected<void,HostFailure> {
            if (!valid(reservation.peer) || peers_[reservation.peer.slot].latest!=reservation.ticket) return host_detail::failure(HostError::stale_attempt);
            for (auto& entry:peer_indexes(reservation.peer.slot)) {
                if (entry.used && entry.binding.index==reservation.index) {
                    if (!entry.reserved || entry.binding.peer!=reservation.peer || entry.binding.ticket!=reservation.ticket || entry.serial!=reservation.serial)
                        return host_detail::failure(HostError::stale_attempt);
                    entry={}; --peers_[reservation.peer.slot].active_indexes; return {};
                }
            }
            return host_detail::failure(HostError::stale_attempt);
        }
        [[nodiscard]] auto lookup(std::uint32_t index) const noexcept -> std::expected<ReceiverBinding,HostFailure> {
            auto entry=find(index);
            if (!entry || entry->reserved || !valid(entry->binding.peer)) return host_detail::failure(HostError::no_peer);
            return entry->binding;
        }
        [[nodiscard]] auto owns(ReceiverBinding const& binding) const noexcept -> bool {
            if (!valid(binding.peer)) return false;
            for (auto const& entry:peer_indexes(binding.peer.slot))
                if (entry.used && !entry.reserved && entry.binding==binding) return true;
            return false;
        }
        [[nodiscard]] auto classify(std::span<std::uint8_t const> wire) const noexcept -> std::expected<ReceiverBinding,HostFailure> {
            auto type=message_type(wire); if (!type) return host_detail::failure(HostError::invalid_packet,type.error());
            if (*type==MessageType::initiation) return host_detail::failure(HostError::initiation_peer_required);
            auto receiver=*type==MessageType::response ? load_le32(wire.subspan<8,4>()) : load_le32(wire.subspan<4,4>());
            return lookup(receiver);
        }
        [[nodiscard]] auto status() const noexcept -> RegistryStatus {
            RegistryStatus result;
            for (std::size_t p=0;p<PeerCapacity;++p) {
                result.peers+=peers_[p].live;
                if (!peers_[p].active_indexes) continue;
                for (auto const& entry:peer_indexes(p)) if (entry.used) { ++result.indexes; result.reservations+=entry.reserved; }
            }
            return result;
        }
    };
}
