export module nexus.tcp.engine;
export import nexus.tcp.dispatch;
import std;

export namespace nexus::tcp {
    enum class EngineError { time_reversed, unknown_flow, invalid_mtu };
    struct EngineStep {
        bool input = false, delivered = false, backpressured = false, stale_reply = false;
        std::optional<ConnectionId> id;
        bool opened = false;
        std::optional<ConnectionError> input_error;
        std::optional<DispatchFailure> rejected;
        std::optional<packet::DeviceError> output_error;
    };
    struct TransmitResult {
        std::size_t bytes = 0;
        bool backpressured = false, delivered = false;
        std::optional<ConnectionError> connection_error;
        std::optional<packet::DeviceError> output_error;
    };
    struct ReadResult {
        std::size_t bytes = 0;
        bool eof = false;
        std::optional<ConnectionError> connection_error;
        EngineStep notification;
    };
    enum class ServiceAction { none, syn_ack, retransmit, probe, fin, fin_retry, data, reclaimed };
    struct ServiceResult {
        std::optional<ConnectionId> id;
        ServiceAction action = ServiceAction::none;
        TransmitResult output;
        std::optional<TableError> table_error;
    };
    // Single owner. The table and link must outlive the engine; uses the second side.
    class MemoryEngine {
        packet::MemoryLink& link_;
        ConnectionTable& table_;
        rules::Matcher policy_;
        std::optional<packet::Bytes> incoming_;
        std::uint32_t incoming_iss_ = 0;
        std::optional<packet::Bytes> pending_;
        std::optional<ConnectionId> pending_id_;
        bool pending_reset_ = false;
        std::size_t mtu_;
        std::uint64_t now_ = 0;
        bool initialized_ = false;
        ConnectionId cursor_ = 0;
        enum class Action { data, retransmit, probe, fin, fin_retry };
        auto flush(EngineStep& report) -> void;
        auto emit(PassiveConnection& flow, SendSlice const& slice, std::uint64_t now, Action action)
            -> std::expected<TransmitResult, EngineError>;
    public:
        MemoryEngine(packet::MemoryLink& link, ConnectionTable& table, std::size_t mtu = 1500)
            : link_(link), table_(table), mtu_(mtu) {}
        MemoryEngine(packet::MemoryLink& link, ConnectionTable& table, rules::Matcher policy, std::size_t mtu = 1500)
            : link_(link), table_(table), policy_(std::move(policy)), mtu_(mtu) {}
        ~MemoryEngine();
        MemoryEngine(MemoryEngine const&) = delete;
        auto operator=(MemoryEngine const&) -> MemoryEngine& = delete;
        // ISS is used only if this step opens a flow; caller supplies a secure value.
        // An input retained after an exception keeps the ISS from its original step.
        [[nodiscard]] auto step(std::uint64_t now, std::uint32_t iss)
            -> std::expected<EngineStep, std::variant<EngineError, packet::DeviceError>>;
        [[nodiscard]] auto transmit(ConnectionId id, std::uint64_t now)
            -> std::expected<TransmitResult, EngineError>;
        [[nodiscard]] auto retransmit(ConnectionId id, std::uint64_t now)
            -> std::expected<TransmitResult, EngineError>;
        [[nodiscard]] auto probe(ConnectionId id, std::uint64_t now)
            -> std::expected<TransmitResult, EngineError>;
        [[nodiscard]] auto send_fin(ConnectionId id, std::uint64_t now, bool retry = false)
            -> std::expected<TransmitResult, EngineError>;
        // Advances at most one connection and emits at most one packet.
        [[nodiscard]] auto service(std::uint64_t now) -> std::expected<ServiceResult, EngineError>;
        [[nodiscard]] auto read(ConnectionId id, std::span<std::uint8_t> output, std::uint64_t now, bool observe_eof = true)
            -> std::expected<ReadResult, EngineError>;
        // Abort an established flow and queue a RST; retry if another response is pending.
        [[nodiscard]] auto reset(ConnectionId id, std::uint64_t now) -> std::expected<ReadResult, EngineError>;
    };
}
