module nexus.packet;
import std;

namespace nexus::packet {
    namespace {
        auto index(Side side) noexcept -> std::size_t { return side == Side::first ? 0 : 1; }
    }
    auto MemoryLink::send(Side from, std::span<std::uint8_t const> packet) -> std::expected<void, DeviceError> {
        auto const sender = index(from), receiver = 1 - sender;
        if (queues_[sender].closed) return std::unexpected(DeviceError::closed);
        auto& queue = queues_[receiver];
        if (queue.closed) return std::unexpected(DeviceError::peer_closed);
        if (packet.empty()) return std::unexpected(DeviceError::empty_packet);
        if (packet.size() > limits_.packet_bytes || packet.size() > limits_.queue_bytes)
            return std::unexpected(DeviceError::packet_too_large);
        if (queue.packets.size() >= limits_.queue_packets || queue.bytes > limits_.queue_bytes ||
            packet.size() > limits_.queue_bytes - queue.bytes) return std::unexpected(DeviceError::queue_full);
        queue.packets.emplace_back(packet.begin(), packet.end());
        queue.bytes += packet.size();
        return {};
    }
    auto MemoryLink::receive(Side to) -> std::expected<std::optional<Bytes>, DeviceError> {
        auto const receiver = index(to), sender = 1 - receiver;
        auto& queue = queues_[receiver];
        if (queue.closed) return std::unexpected(DeviceError::closed);
        if (!queue.packets.empty()) {
            Bytes packet = std::move(queue.packets.front());
            queue.packets.pop_front();
            queue.bytes -= packet.size();
            return std::optional<Bytes>(std::move(packet));
        }
        if (queues_[sender].closed) return std::unexpected(DeviceError::peer_closed);
        return std::optional<Bytes>{};
    }
    auto MemoryLink::close(Side side) noexcept -> void {
        auto& queue = queues_[index(side)];
        queue.closed = true;
        queue.packets.clear();
        queue.bytes = 0;
    }
}
