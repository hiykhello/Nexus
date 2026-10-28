export module nexus.transport.memory;
export import nexus.packet.mux;
export import nexus.tcp.stack;
export import nexus.udp.engine;
import std;

export namespace nexus::transport {
    enum class MemoryClockError { time_reversed, stopped };
    using MemoryError = std::variant<MemoryClockError, packet::DeviceError, tcp::StackError, udp::EngineError>;
    struct MemoryStep {
        packet::SwitchStep device;
        tcp::StackStep tcp;
        udp::EngineStep udp;
    };
    // Single owner. The external link and TCP table outlive the engine.
    class MemoryEngine {
        packet::MemoryLink tcp_link_, udp_link_;
        std::uint64_t now_ = 0;
        bool initialized_ = false, stopped_ = false;
        packet::MemorySwitch device_;
        tcp::MemoryDirect4 tcp_;
        udp::MemoryEngine udp_;
    public:
        MemoryEngine(packet::MemoryLink& link, tcp::ConnectionTable& table, rules::Matcher policy,
                     std::size_t tcp_limit, udp::Mapping mapping, udp::Filtering filtering,
                     udp::Limits udp_limits = {}, std::size_t mtu = 1500,
                     packet::DeviceLimits internal_limits = {});
        ~MemoryEngine();
        // Terminal; closes owned outlets and discards internal queued packets.
        [[nodiscard]] auto stop(std::uint64_t now) -> std::expected<void, MemoryError>;
        MemoryEngine(MemoryEngine const&) = delete;
        auto operator=(MemoryEngine const&) -> MemoryEngine& = delete;
        // Single monotonic clock, milliseconds; ISS must be unpredictable for any new TCP SYN.
        [[nodiscard]] auto step(std::uint64_t now, std::uint32_t iss) -> std::expected<MemoryStep, MemoryError>;
    };
}
