export module nexus.packet.mux;
export import nexus.packet;
import std;

export namespace nexus::packet {
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
        std::optional<Bytes> input_, output_;
        bool input_tcp_ = false, next_tcp_ = true;
    public:
        MemorySwitch(MemoryLink& external, MemoryLink& tcp, MemoryLink& udp)
            : external_(external), tcp_(tcp), udp_(udp) {}
        MemorySwitch(MemorySwitch const&) = delete;
        auto operator=(MemorySwitch const&) -> MemorySwitch& = delete;
        [[nodiscard]] auto step() -> std::expected<SwitchStep, DeviceError>;
        // Discards packets held by the switch; link queues remain owned by their callers.
        auto discard() noexcept -> void { input_.reset(); output_.reset(); }
    };
}
