export module wireguard.host;
import std;
import wireguard;
import wireguard.endpoint;
import wireguard.registry;

export namespace wireguard {
    template<std::size_t PacketBytes> struct CandidateDatagram {
        PeerHandle peer{};
        EndpointAddress source{};
        std::optional<ReceiverBinding> binding;
        std::uint64_t serial=0;
        std::array<std::uint8_t,PacketBytes> bytes{};
        std::size_t size=0;
        [[nodiscard]] auto wire() const noexcept -> std::span<std::uint8_t const> { return std::span(bytes).first(size); }
    };
    struct HostQueueStatus { std::size_t packets=0,bytes=0; };
    // Bounded ingress scheduling only; no peer pointers, socket/clock/RNG,
    // crypto, outgoing packet queue or relay loop. A receiver-index match is
    // an unauthenticated candidate. Only Endpoint::receive may deliver inner
    // bytes, confirm keys, validate allowed source or roam the endpoint.
    template<std::size_t PeerCapacity=32,std::size_t PacketCapacity=32,std::size_t PacketBytes=2048,std::size_t PeerPacketLimit=4>
    class PeerHost {
        static_assert(PacketCapacity>0 && PacketCapacity<=4096 && PacketBytes>=initiation_size && PacketBytes<=endpoint_max_outer_payload);
        static_assert(PeerPacketLimit>0 && PeerPacketLimit<=PacketCapacity);
        struct Slot { bool used=false; CandidateDatagram<PacketBytes> packet; };
        PeerRegistry<PeerCapacity> registry_;
        std::array<Slot,PacketCapacity> packets_{};
        HostQueueStatus queued_;
        std::uint64_t packet_serial_=0;
        std::size_t next_peer_=0;
        static auto valid_source(EndpointAddress const& source) noexcept -> bool {
            if (!source.port || (source.family!=4 && source.family!=6)) return false;
            auto size=source.family==4 ? 4u : 16u;
            if (std::ranges::all_of(std::span(source.address).first(size),[](auto c) { return c==0; })) return false;
            if (source.family==4) return std::ranges::all_of(std::span(source.address).subspan(4),[](auto c) { return c==0; });
            return !(std::ranges::all_of(std::span(source.address).first(10),[](auto c) { return c==0; }) && source.address[10]==255 && source.address[11]==255);
        }
        auto discard(Slot& slot) noexcept -> void { --queued_.packets; queued_.bytes-=slot.packet.size; slot={}; }
        auto prune() noexcept -> void {
            if (!queued_.packets) return;
            for (auto& slot:packets_) if (slot.used && !valid(slot.packet)) discard(slot);
        }
        auto enqueue(PeerHandle peer,std::optional<ReceiverBinding> binding,std::span<std::uint8_t const> wire,EndpointAddress source,bool allowed) noexcept
            -> std::expected<void,HostFailure> {
            if (!allowed || !valid_source(source)) return host_detail::failure(HostError::source);
            if (!registry_.valid(peer)) return host_detail::failure(HostError::stale_peer);
            if (wire.size()>PacketBytes) return host_detail::failure(HostError::packet_too_large);
            auto scan=[&] {
                std::size_t owned=0;
                Slot* free_slot=nullptr;
                for (auto& slot:packets_) {
                    if (slot.used) owned+=slot.packet.peer==peer;
                    else if (!free_slot) free_slot=&slot;
                }
                return std::pair{owned,free_slot};
            };
            auto [owned,slot]=scan();
            if (owned>=PeerPacketLimit || !slot) {
                prune();
                std::tie(owned,slot)=scan();
                if (owned>=PeerPacketLimit) return host_detail::failure(HostError::peer_queue_full);
                if (!slot) return host_detail::failure(HostError::queue_full);
            }
            if (packet_serial_==std::numeric_limits<std::uint64_t>::max()) return host_detail::failure(HostError::exhausted);
            slot->used=true; auto& packet=slot->packet;
            packet.peer=peer; packet.source=source; packet.binding=binding; packet.serial=++packet_serial_; packet.size=wire.size();
            std::ranges::copy(wire,packet.bytes.begin()); ++queued_.packets; queued_.bytes+=wire.size(); return {};
        }
    public:
        PeerHost()=default;
        PeerHost(PeerHost const&)=delete;
        auto operator=(PeerHost const&) -> PeerHost& = delete;
        PeerHost(PeerHost&&)=delete;
        auto operator=(PeerHost&&) -> PeerHost& = delete;
        [[nodiscard]] auto registry() noexcept -> PeerRegistry<PeerCapacity>& { return registry_; }
        [[nodiscard]] auto registry() const noexcept -> PeerRegistry<PeerCapacity> const& { return registry_; }
        [[nodiscard]] auto valid(CandidateDatagram<PacketBytes> const& packet) const noexcept -> bool {
            return registry_.valid(packet.peer) && (!packet.binding || (packet.binding->peer==packet.peer && registry_.owns(*packet.binding)));
        }
        [[nodiscard]] auto enqueue_indexed(std::span<std::uint8_t const> wire,EndpointAddress source,bool source_allowed) noexcept -> std::expected<void,HostFailure> {
            auto binding=registry_.classify(wire); if (!binding) return std::unexpected(binding.error());
            return enqueue(binding->peer,*binding,wire,source,source_allowed);
        }
        // Initiation has no receiver index. The upstream identity dispatcher
        // must resolve its encrypted static to this peer once. Never try every
        // registered Endpoint's DH/Noise parser in a receive hot path.
        [[nodiscard]] auto enqueue_initiation(PeerHandle peer,std::span<std::uint8_t const> wire,EndpointAddress source,bool source_allowed) noexcept -> std::expected<void,HostFailure> {
            auto type=message_type(wire); if (!type || *type!=MessageType::initiation) return host_detail::failure(HostError::invalid_packet,type ? Error::invalid_type : type.error());
            return enqueue(peer,{},wire,source,source_allowed);
        }
        [[nodiscard]] auto take() noexcept -> std::optional<CandidateDatagram<PacketBytes>> {
            if (!queued_.packets) return {};
            Slot* chosen=nullptr;
            std::size_t best_distance=PeerCapacity;
            for (auto& slot:packets_) {
                if (!slot.used) continue;
                if (!valid(slot.packet)) { discard(slot); continue; }
                auto peer=std::size_t{slot.packet.peer.slot};
                auto distance=peer>=next_peer_ ? peer-next_peer_ : PeerCapacity-next_peer_+peer;
                if (distance<best_distance || (distance==best_distance && slot.packet.serial<chosen->packet.serial)) {
                    best_distance=distance; chosen=&slot;
                }
            }
            if (!chosen) return {};
            auto result=chosen->packet; auto peer=std::size_t{result.peer.slot};
            discard(*chosen); next_peer_=(peer+1)%PeerCapacity; return result;
        }
        [[nodiscard]] auto queued_packets() const noexcept -> std::size_t { return queued_.packets; }
        [[nodiscard]] auto status() noexcept -> HostQueueStatus { prune(); return queued_; }
        auto clear() noexcept -> void { if (!queued_.packets) return; for (auto& slot:packets_) if (slot.used) discard(slot); }
    };
}
