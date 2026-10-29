export module nexus.udp.engine;
export import nexus.udp.direct;
import nexus.rules;
import std;

export namespace nexus::udp {
    struct EngineStep {
        bool input = false;
        bool delivered = false;
        bool backpressured = false;
        bool input_allocation_failed = false;
        bool input_backpressured = false;
        bool ipv4_allocation_failed = false, ipv6_allocation_failed = false;
        std::size_t expired = 0;
        std::optional<DirectError> rejected;
        std::optional<DirectError> ipv4_error;
        std::optional<DirectError> ipv6_error;
        std::optional<packet::DeviceError> output_error;
    };
    using EngineError = std::variant<packet::DeviceError, DirectError, Error>;
    // Single owner; the link must outlive the engine. The engine uses its
    // second side. step processes at most one input and holds at most 128 replies.
    // A transient send error retains one input for retry; later inputs wait.
    class MemoryEngine {
        packet::MemoryLink& link_;
        Direct4 ipv4_;
        Direct6 ipv6_;
        std::optional<packet::Bytes> incoming_;
        std::array<packet::Bytes, 128> pending_;
        std::size_t pending_begin_ = 0, pending_end_ = 0;
        bool initialized_ = false;
        std::uint64_t last_time_ = 0;
    public:
        MemoryEngine(packet::MemoryLink& link, rules::Matcher policy, Mapping mapping, Filtering filtering,
                     Limits limits = {}, std::size_t mtu = 1500,
                     std::optional<std::uint32_t> socket_mark = {});
        ~MemoryEngine();
        MemoryEngine(MemoryEngine const&) = delete;
        auto operator=(MemoryEngine const&) -> MemoryEngine& = delete;
        [[nodiscard]] auto step(std::uint64_t now) -> std::expected<EngineStep, EngineError>;
        [[nodiscard]] auto stop(std::uint64_t now) -> std::expected<void, Error>;
    };
}
