export module tcp.stack;
export import tcp.direct;
import std;

export namespace tcp {
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
                      std::size_t direct_limit, std::size_t mtu = 1500,
                      std::optional<std::uint32_t> socket_mark = {});
        ~MemoryDirect4();
        // Terminal: close owned sockets and remove flows opened by this stack.
        auto stop() noexcept -> void;
        MemoryDirect4(MemoryDirect4 const&) = delete;
        auto operator=(MemoryDirect4 const&) -> MemoryDirect4& = delete;
        [[nodiscard]] auto direct_size() const noexcept -> std::size_t { return direct_.size(); }
        auto direct_limit(std::size_t limit) noexcept -> void { direct_.admission_limit(limit); }
        // Caller supplies a secure ISS when a SYN may be consumed and a monotonic millisecond clock.
        [[nodiscard]] auto step(std::uint64_t now, std::uint32_t iss) -> std::expected<StackStep, StackError>;
    };
    // Single owner; referenced table and link must outlive the stack.
    class MemoryDirect6 {
        ConnectionTable6& table_;
        MemoryEngine6 engine_;
        Direct6 direct_;
        std::map<ConnectionId, bool> started_;
        std::set<ConnectionId> owned_;
        bool stopped_ = false;
    public:
        MemoryDirect6(packet::MemoryLink& link, ConnectionTable6& table, rules::Matcher policy,
                      std::size_t direct_limit, std::size_t mtu = 1500,
                      std::optional<std::uint32_t> socket_mark = {});
        ~MemoryDirect6();
        // Terminal: close owned sockets and remove flows opened by this stack.
        auto stop() noexcept -> void;
        MemoryDirect6(MemoryDirect6 const&) = delete;
        auto operator=(MemoryDirect6 const&) -> MemoryDirect6& = delete;
        [[nodiscard]] auto direct_size() const noexcept -> std::size_t { return direct_.size(); }
        auto direct_limit(std::size_t limit) noexcept -> void { direct_.admission_limit(limit); }
        // Caller supplies a secure ISS when a SYN may be consumed and a monotonic millisecond clock.
        [[nodiscard]] auto step(std::uint64_t now, std::uint32_t iss) -> std::expected<StackStep, StackError>;
    };
}
