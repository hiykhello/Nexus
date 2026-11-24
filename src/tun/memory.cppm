export module transport.memory;
export import packet.mux;
export import tcp.stack;
export import udp.engine;
import std;

export namespace transport {
    enum class MemoryClockError { time_reversed, stopped };
    using MemoryError = std::variant<MemoryClockError, packet::DeviceError, tcp::StackError, udp::EngineError>;
    struct MemoryStep {
        packet::SwitchStep device;
        tcp::StackStep tcp;
        udp::EngineStep udp;
        std::optional<tcp::StackStep> tcp6;
    };
    // Single owner. The external link and TCP table outlive the engine.
    class MemoryEngine {
        packet::MemoryLink tcp_link_, udp_link_, tcp6_link_;
        std::uint64_t now_ = 0;
        bool initialized_ = false, stopped_ = false;
        packet::MemorySwitch device_;
        tcp::MemoryDirect4 tcp_;
        udp::MemoryEngine udp_;
        tcp::ConnectionTable* table4_ = nullptr;
        tcp::ConnectionTable6* table6_ = nullptr;
        std::optional<tcp::MemoryDirect6> tcp6_;
        std::size_t flow_limit_ = 0, direct_limit_ = 0;
    public:
        MemoryEngine(packet::MemoryLink& link, tcp::ConnectionTable& table, rules::Matcher policy,
                     std::size_t tcp_limit, udp::Mapping mapping, udp::Filtering filtering,
                     udp::Limits udp_limits = {}, std::size_t mtu = 1500,
                     packet::DeviceLimits internal_limits = {}, std::optional<std::uint32_t> socket_mark = {});
        // The two tables are exclusively managed while this engine runs; limits are shared.
        MemoryEngine(packet::MemoryLink& link, tcp::ConnectionTable& table, tcp::ConnectionTable6& table6,
                     rules::Matcher policy, std::size_t flow_limit, std::size_t tcp_limit,
                     udp::Mapping mapping, udp::Filtering filtering, udp::Limits udp_limits = {},
                     std::size_t mtu = 1500, packet::DeviceLimits internal_limits = {},
                     std::optional<std::uint32_t> socket_mark = {});
        ~MemoryEngine();
        // Terminal; closes owned outlets and discards internal queued packets.
        [[nodiscard]] auto stop(std::uint64_t now) -> std::expected<void, MemoryError>;
        // Stateful reset IDs are unique for the lifetime of the supplied tables;
        // do not replace those tables while any output remains queued.
        // Output consumers must retain packet metadata and call this immediately
        // before delivery, including retries after backpressure. The engine and
        // its tables must outlive that check.
        [[nodiscard]] auto valid_output(packet::QueuedPacket const& packet) const noexcept -> bool;
        MemoryEngine(MemoryEngine const&) = delete;
        auto operator=(MemoryEngine const&) -> MemoryEngine& = delete;
        // Single monotonic clock, milliseconds; ISS must be unpredictable for any new TCP SYN.
        [[nodiscard]] auto step(std::uint64_t now, std::uint32_t iss) -> std::expected<MemoryStep, MemoryError>;
    };
}
