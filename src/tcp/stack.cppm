export module nexus.tcp.stack;
export import nexus.tcp.direct;
import std;

export namespace nexus::tcp {
    enum class StackStopped { stopped };
    using StackError = std::variant<EngineError, packet::DeviceError, DirectError, StackStopped>;
    struct StackStep {
        EngineStep input;
        std::optional<DirectFailure> start_error;
        std::optional<ReadResult> reset;
        DirectStep direct;
        ServiceResult service;
    };
    // Single owner; referenced table and link must outlive the stack.
    class MemoryDirect4 {
        ConnectionTable& table_;
        MemoryEngine engine_;
        Direct4 direct_;
        std::map<ConnectionId, bool> started_;
        std::set<ConnectionId> owned_;
        bool stopped_ = false;
    public:
        MemoryDirect4(packet::MemoryLink& link, ConnectionTable& table, rules::Matcher policy,
                      std::size_t direct_limit, std::size_t mtu = 1500);
        ~MemoryDirect4();
        // Terminal: close owned sockets and remove flows opened by this stack.
        auto stop() noexcept -> void;
        MemoryDirect4(MemoryDirect4 const&) = delete;
        auto operator=(MemoryDirect4 const&) -> MemoryDirect4& = delete;
        // Caller supplies a secure ISS when a SYN may be consumed and a monotonic millisecond clock.
        [[nodiscard]] auto step(std::uint64_t now, std::uint32_t iss) -> std::expected<StackStep, StackError>;
    };
}
