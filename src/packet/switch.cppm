export module packet.mux;
export import packet;
import std;

export namespace packet {
    enum class SwitchReject { unsupported_packet };
    struct SwitchStep {
        bool input = false, input_delivered = false, input_backpressured = false;
        bool output_delivered = false, output_backpressured = false;
        std::optional<SwitchReject> rejected;
        std::optional<DeviceError> input_error, output_error;
    };
    // All links outlive the switch. Uses external second side and internal first sides.
    class MemorySwitch {
        MemoryLink& external_;
        MemoryLink& tcp_;
        MemoryLink& udp_;
        MemoryLink* tcp6_ = nullptr;
        bool udp_fragments_=false;
        std::optional<Bytes> input_;
        std::optional<QueuedPacket> output_;
        std::size_t input_route_ = 0, next_output_ = 0;
    public:
        MemorySwitch(MemoryLink& external, MemoryLink& tcp, MemoryLink& udp)
            : external_(external), tcp_(tcp), udp_(udp) {}
        MemorySwitch(MemoryLink& external, MemoryLink& tcp, MemoryLink& udp, MemoryLink& tcp6,bool udp_fragments=false)
            : external_(external), tcp_(tcp), udp_(udp), tcp6_(&tcp6), udp_fragments_(udp_fragments) {}
        MemorySwitch(MemorySwitch const&) = delete;
        auto operator=(MemorySwitch const&) -> MemorySwitch& = delete;
        [[nodiscard]] auto step() -> std::expected<SwitchStep, DeviceError>;
        // Discards packets held by the switch; link queues remain owned by their callers.
        auto discard() noexcept -> void { input_.reset(); output_.reset(); }
    };
}
