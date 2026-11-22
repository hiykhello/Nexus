module packet;
import std;

namespace packet {
    namespace {
        auto index(Side side) noexcept -> std::size_t { return side == Side::first ? 0 : 1; }
    }
    auto MemoryLink::send(Side from, std::span<std::uint8_t const> packet, PacketKind kind, std::uint64_t flow_id, std::shared_ptr<TcpGeneration> generation) -> std::expected<void, DeviceError> {
        auto const sender = index(from), receiver = 1 - sender;
        if (queues_[sender].closed) return std::unexpected(DeviceError::closed);
        auto& queue = queues_[receiver];
        if (queue.closed) return std::unexpected(DeviceError::peer_closed);
        if (packet.empty()) return std::unexpected(DeviceError::empty_packet);
        if (packet.size() > limits_.packet_bytes || packet.size() > limits_.queue_bytes)
            return std::unexpected(DeviceError::packet_too_large);
        if (queue.packets.size() >= limits_.queue_packets || queue.bytes > limits_.queue_bytes ||
            packet.size() > limits_.queue_bytes - queue.bytes) return std::unexpected(DeviceError::queue_full);
        queue.packets.push_back(QueuedPacket{Bytes(packet.begin(), packet.end()),kind,flow_id,std::move(generation)});
        queue.bytes += packet.size();
        return {};
    }
    auto MemoryLink::send_packets(Side from,std::vector<Bytes> packets) -> std::expected<void,DeviceError> {
        auto sender=index(from),receiver=1-sender;
        if (queues_[sender].closed) return std::unexpected(DeviceError::closed);
        auto& queue=queues_[receiver];
        if (queue.closed) return std::unexpected(DeviceError::peer_closed);
        if (packets.size()>limits_.queue_packets-queue.packets.size())
            return std::unexpected(DeviceError::queue_full);
        auto available=limits_.queue_bytes-queue.bytes;
        for (auto const& packet:packets) {
            if (packet.empty()) return std::unexpected(DeviceError::empty_packet);
            if (packet.size()>limits_.packet_bytes || packet.size()>limits_.queue_bytes)
                return std::unexpected(DeviceError::packet_too_large);
            if (packet.size()>available) return std::unexpected(DeviceError::queue_full);
            available-=packet.size();
        }
        struct Rollback {
            Queue& queue;
            std::size_t previous;
            bool committed=false;
            ~Rollback(){if (!committed) while (queue.packets.size()>previous) queue.packets.pop_back();}
        } rollback{queue,queue.packets.size()};
        for (auto& packet:packets) queue.packets.push_back({std::move(packet)});
        queue.bytes=limits_.queue_bytes-available;
        rollback.committed=true;
        return {};
    }
    auto MemoryLink::receive(Side to) -> std::expected<std::optional<Bytes>, DeviceError> {
        auto packet=receive_packet(to);
        if (!packet) return std::unexpected(packet.error());
        if (!*packet) return std::optional<Bytes>{};
        return std::optional<Bytes>(std::move((**packet).bytes));
    }
    auto MemoryLink::receive_packet(Side to) -> std::expected<std::optional<QueuedPacket>, DeviceError> {
        auto const receiver = index(to), sender = 1 - receiver;
        auto& queue = queues_[receiver];
        if (queue.closed) return std::unexpected(DeviceError::closed);
        if (!queue.packets.empty()) {
            QueuedPacket packet = std::move(queue.packets.front());
            queue.packets.pop_front();
            queue.bytes -= packet.bytes.size();
            return std::optional<QueuedPacket>(std::move(packet));
        }
        if (queues_[sender].closed) return std::unexpected(DeviceError::peer_closed);
        return std::optional<QueuedPacket>{};
    }
    auto MemoryLink::close(Side side) noexcept -> void {
        auto& queue = queues_[index(side)];
        queue.closed = true;
        queue.packets.clear();
        queue.bytes = 0;
    }
}
