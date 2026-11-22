export module wireguard.packet_link;
import std;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.port_types;

export namespace wireguard {
    // Borrows one stable Port on its executor. The descriptor pump owns only
    // its fixed pending packet; delivery goes directly to the port's queues.
    template<class Port> class PortPacketLink {
        Port* port_;
        Clock::time_point now_{};
    public:
        using Packet=typename Port::Packet;
        using Failure=PortFailure;
        explicit PortPacketLink(Port& port) noexcept : port_(&port) {}
        auto time(Clock::time_point now) noexcept -> void { now_=now; }
        [[nodiscard]] auto receive_packet() noexcept -> std::expected<std::optional<Packet>,Failure> {
            return port_->take_packet();
        }
        [[nodiscard]] auto send(std::span<std::uint8_t const> packet) -> std::expected<void,Failure> {
            auto accepted=port_->enqueue_ip(packet,now_);
            if (!accepted) return std::unexpected(accepted.error());
            return {};
        }
        [[nodiscard]] static auto packet_bytes(Packet const& packet) noexcept -> std::span<std::uint8_t const> { return packet.packet(); }
        [[nodiscard]] static auto retryable(Failure const& failure) noexcept -> bool {
            return failure.code==PortError::queue_full || failure.code==PortError::allocation ||
                (failure.code==PortError::endpoint && failure.endpoint && failure.endpoint->code==EndpointError::queue_full);
        }
        // Rechecked immediately before every write, including EAGAIN retries.
        [[nodiscard]] auto valid_output(Packet const& packet) const noexcept -> bool { return port_->valid_output(packet); }
    };
}
